#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in bounded observations/decoder for one update in a copied 587-package root."""
import argparse
import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('_scaled_' + name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


bound, roots, archives, space, supervision = map(load, ('bound_update','full_root','archive_stream','capacity','supervision'))
KEYS = {'schema_version','purpose','before_lock_sha256','after_lock_sha256','limits','capacity','platform_mode'}
LIMITS = {'root_nodes','root_bytes','file_bytes','package_files','archive_bytes','archive_total_bytes',
          'decoded_bytes','archive_members','window_bytes','seconds'}
CAPACITY = {'root_reserve_bytes','root_reserve_inodes','workspace_future_bytes','workspace_future_inodes'}


def configuration(path, pin):
    raw = bound.client.read_path(path, 65536)
    bound.need(hashlib.sha256(raw).hexdigest() == pin, 'scale configuration changed')
    value = bound.client.decode(raw)
    bound.need(type(value) is dict and set(value) == KEYS and value['schema_version'] == 1
        and type(value['schema_version']) is int and value['purpose'] == 'disposable-bound-update-scale',
        'explicit scaled disposable configuration required')
    bound.need(value['platform_mode'] in ('apple','generic-development'), 'explicit platform mode required')
    for key in ('before_lock_sha256','after_lock_sha256'):
        bound.need(type(value[key]) is str and bound.client.HEX.fullmatch(value[key]), 'exact inventory digest required')
    bound.need(type(value['limits']) is dict and set(value['limits']) == LIMITS
        and type(value['capacity']) is dict and set(value['capacity']) == CAPACITY, 'exact finite scale budgets required')
    for key, number in value['limits'].items():
        bound.need(type(number) is int and 0 < number <= 64*1024**3, 'positive finite scale limit required')
    limits = value['limits']
    bound.need(limits['root_nodes'] <= 4000000 and limits['archive_members'] <= 1000000
        and limits['package_files'] <= 1000000 and limits['seconds'] <= 3600
        and limits['file_bytes'] <= limits['root_bytes'] and limits['archive_bytes'] <= limits['archive_total_bytes']
        and 1024 <= limits['window_bytes'] <= 1024**3, 'unsupported scale ceilings')
    for number in value['capacity'].values():
        bound.need(type(number) is int and 0 < number <= 64*1024**3, 'explicit finite future capacity budget required')
    return value


def inventory_sha(inventory):
    return hashlib.sha256(''.join(f'{name} {version}\n' for name,version in sorted(inventory.items())).encode()).hexdigest()


class Runtime:
    def __init__(self, args, config):
        self.args, self.config, self.root = args, config, Path(args.root)
        self.policy_module = load('generic_policy' if config['platform_mode']=='generic-development' else 'platform_policy')
        limits = config['limits']; self.deadline = time.monotonic()+limits['seconds']
        self.root_limits = roots.Limits(deadline=self.deadline,max_packages=587,max_nodes=limits['root_nodes'],
            max_bytes=limits['root_bytes'],max_file_bytes=limits['file_bytes'],max_package_files=limits['package_files'])
        self.archive_limits = archives.Limits(compressed_bytes=limits['archive_bytes'],
            total_compressed_bytes=limits['archive_total_bytes'],decoded_bytes=limits['decoded_bytes'],
            members=limits['archive_members'],file_bytes=limits['file_bytes'],window_bytes=limits['window_bytes'],deadline=self.deadline)
        self.Alpm = functools.partial(roots.Alpm,limits=self.root_limits)
        self.Ptr = roots.installer.Ptr
        self.MAX_PACKAGES, self.MAX_INPUTS, self.MAX_ARCHIVE = 1, limits['archive_total_bytes'], limits['archive_bytes']
        self.footprints, self.demands = [], None

    def package_map(self, value): return roots.package_map(value,limits=self.root_limits)

    def check_inventory(self, actual, expected, label):
        roots.inventory_exact(actual,expected,limits=self.root_limits)

    def tree(self, root):
        observation = roots.observe(root,limits=self.root_limits)
        self.footprints.append(observation['footprint'])
        bound.need(observation['eligible'], 'unsupported root observation: '+','.join(observation['unsupported_counts']))
        roots.require_eligible(observation)
        return observation['nodes']

    def node(self, path): return roots.node(self.root,Path(path).relative_to(self.root).as_posix(),limits=self.root_limits)

    def archive_payload(self, path, accounting):
        return archives.archive_payload(path,self.archive_limits,accounting)

    def projected_paths(self, seed, payload): return roots.projected_paths(seed,payload,limits=self.root_limits)

    def selection(self, snapshot, before, desired):
        bound.need(len(before) == 587 and inventory_sha(before) == self.config['before_lock_sha256'],
                   'actual baseline differs from exact 587-package lock')
        bound.need(len(desired) == 1 and set(desired) <= set(before), 'one existing changed package required')
        bound.need(all(before[name] != version for name,version in desired.items()), 'changed archive required')
        after = dict(before,**desired)
        bound.need(inventory_sha(after) == self.config['after_lock_sha256'], 'expected post-update lock differs')

    def observed_after(self, after):
        bound.need(len(after) == 587 and inventory_sha(after) == self.config['after_lock_sha256'],
                   'actual post-update lock differs')

    def authorize(self, policy, settings, snapshot, before, after, before_files, after_files, **kwargs):
        self.package_map(before); self.package_map(after)
        policy_module = self.policy_module
        if self.config['platform_mode']=='generic-development':
            bound.need(policy['before_lock_sha256']==self.config['before_lock_sha256']
                and policy['after_lock_sha256']==self.config['after_lock_sha256'],'generic policy/configuration locks differ')
            return policy_module.authorize(policy,settings,snapshot,before,after,before_files,after_files,**kwargs)
        names = policy_module.protected_names(policy)
        bound.need(names <= before.keys() and names <= after.keys(), 'actual protected platform packages absent')
        # The unchanged Apple evaluator receives the complete protected view;
        # the full inventory was independently bounded and matched above.
        return policy_module.authorize(policy,settings,snapshot,
            {name:before[name] for name in names},{name:after[name] for name in names},before_files,after_files,**kwargs)

    def capacity(self, root, work, projected, payload, old_payload):
        budget = self.config['capacity']; footprint = self.footprints[-1]
        parents = {parent.as_posix() for path in payload for parent in Path(path).parents if str(parent) != '.'}
        self.demands = [dict(path=str(root),bytes=sum(row.get('bytes',0) for row in payload.values())
            + sum(row.get('bytes',0) for row in old_payload.values()) + footprint['database_bytes']
            + budget['root_reserve_bytes'],inodes=len(payload)+len(parents)+footprint['database_files']
            + len(old_payload)+budget['root_reserve_inodes']),
            dict(path=str(work),bytes=budget['workspace_future_bytes'],inodes=budget['workspace_future_inodes'])]
        return space.check(self.demands)

    def precommit(self):
        self.root_limits.tick()
        configuration(self.args.scale,self.args.scale_sha256)
        bound.need(self.demands is not None,'capacity check missing')
        space.check(self.demands)


def apply(args):
    delegated, result = False, None
    try:
        bound.guard(Path(args.root),Path(args.workspace))
        config = configuration(args.scale,args.scale_sha256)
        runtime = Runtime(args,config)
        if args.measure_only:
            value = roots.observe(Path(args.root),limits=runtime.root_limits)
            return dict(status='MEASURED' if value['complete'] else 'INCOMPLETE',footprint=value['footprint'],
                unsupported_counts=value['unsupported_counts'],unsupported_examples=value['unsupported'],
                eligible=value['eligible'],scope='copied-root-filesystem-only',
                packages_committed=False,checkpoint_changed=False,hardware='NOT RUN')
        bound.need(all(getattr(args,name,None) for name in ('settings','settings_sha256','policy','policy_sha256',
            'bundle','metadata','signature','public_keyring','state_dir')), 'explicit release and platform configuration required')
        delegated = True
        result = bound.apply(args,adapter=runtime)
        result.update(root_footprints=runtime.footprints,capacity_scope='future demand; already allocated snapshots excluded',
                      auxiliary_execution='REFUSED_IF_PRESENT',full587_composition='NOT ESTABLISHED',
                      platform_mode=config['platform_mode'],apple_acceptance='NOT ESTABLISHED')
        return result
    except BaseException as error:
        failure = dict(result) if type(result) is dict else {}
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            failure.setdefault(field,'UNKNOWN' if delegated else False)
        failure.update(status='FAIL',phase='scale-reporting' if delegated else 'scale-configuration',
                       error_type=type(error).__name__,error=str(error)[:256])
        return failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root','workspace','scale','scale-sha256'):
        parser.add_argument('--'+name,required=True)
    for name in ('settings','settings-sha256','policy','policy-sha256','bundle','metadata','signature','public-keyring','state-dir'):
        parser.add_argument('--'+name)
    parser.add_argument('--operation',default='repository-update')
    parser.add_argument('--measure-only',action='store_true')
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.worker:
        result=apply(args)
    else:
        bound.guard(Path(args.root),Path(args.workspace))
        config=configuration(args.scale,args.scale_sha256)
        row=supervision.run([sys.executable,'-B',str(Path(__file__).resolve()),*sys.argv[1:],'--worker'],
            env=dict(os.environ),cwd=args.workspace,timeout=config['limits']['seconds'],output_limit=1024**2)
        if row['termination'] is None and row['returncode'] in (0,1):
            result=bound.client.decode(row['stdout'])
        else:
            result=dict(status='FAIL',phase='worker',termination=row['termination'],returncode=row['returncode'],
                commit_started='UNKNOWN',packages_committed='UNKNOWN',checkpoint_changed='UNKNOWN',
                recovery='dispose owned container/root; no lock-file removal or rollback attempted')
    print(json.dumps(result,sort_keys=True))
    return int(result['status'] not in ('PASS','MEASURED'))


if __name__=='__main__': raise SystemExit(main())
