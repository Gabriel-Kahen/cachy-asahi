#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in held auxiliary candidate, only for the real setup3-to-setup4 upgrade."""
from pathlib import Path

import aux_checkpoint as aux
import full_root as roots
import internal_runtime as strict
import scale_update as scale

SETUP = 'cachy-asahi-apps'
SETUP_ARCHIVE = '319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
FILES = {'usr/bin/cachy-asahi-apps', 'usr/lib/cachy-asahi-apps/apps.py', 'usr/lib/cachy-asahi-apps/helper-pins.json', 'usr/lib/cachy-asahi-apps/inventory.py', 'usr/share/doc/cachy-asahi-apps/README.md', 'usr/share/doc/cachy-asahi-apps/source-provenance.json', 'usr/share/licenses/cachy-asahi-apps/LICENSE', 'usr/share/licenses/cachy-asahi-apps/NOTICE'}


def apps6_selection_guard(snapshot,before,desired,config,*,need,inventory_sha):
    # bound_update calls selection only inside snapshot.authenticated's context.
    need(type(before) is dict and len(before)==607 and inventory_sha(before)=='72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4','exact-apps604-before-lock')
    need(config['before_lock_sha256']=='72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4' and config['after_lock_sha256']=='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5','exact-apps604-scale-locks')
    need(before.get('cachy-asahi-apps')=='0.1.0-6' and desired=={'cachy-asahi-apps':'0.1.0-16'} and before.get('cachy-asahi-setup')=='0.1.0-6','exact-apps5-to6-transition')
    after=dict(before,**desired)
    other=lambda rows:{n:v for n,v in rows.items() if n!='cachy-asahi-apps'}
    need(len(other(before))==606 and other(before)==other(after) and inventory_sha(after)=='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5','exact-apps604-after-lock-and-other603')
    rows=snapshot['release']['packages']
    need(type(rows) is list and len(rows)==1 and rows[0]['name']=='cachy-asahi-apps' and rows[0]['version']=='0.1.0-16' and rows[0]['sha256']=='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af','exact-apps6-authenticated-archive')


def apps6_postcommit_compare(before,after,comparator,*,committed,selected,config,need,compare):
    # The exact selected Apps files are below this one non-recursive ldconfig
    # scan entry. Keep inode, mode, owner, links, size and all other rows exact;
    # only this directory's mtime/ctime may reflect those selected replacements.
    if not committed:return compare(before,after,comparator,committed=False)
    need(selected is True and config['before_lock_sha256']=='72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4' and config['after_lock_sha256']=='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5','apps604-selected-postcommit-only')
    name='usr/lib/cachy-asahi-apps';old,new=before['scan'].get(name),after['scan'].get(name)
    need(type(old) is dict and type(new) is dict and set(old)==set(new)=={'node','identity'},'apps-directory-scan-row')
    need(old['node']==new['node'] and set(old['node'])=={'type','mode','uid','gid'} and old['node']['type']=='directory' and old['node']['mode']==0o755,'apps-directory-node-metadata')
    a,b=old['identity'],new['identity'];need(type(a) is tuple and type(b) is tuple and len(a)==len(b)==9 and all(type(v) is int for v in (*a,*b)) and a[:7]==b[:7],'apps-directory-inode-links-size-metadata')
    left=dict(before,scan=dict(before['scan']));right=dict(after,scan=dict(after['scan']))
    left['scan'][name]=dict(old,identity=a[:7]);right['scan'][name]=dict(new,identity=b[:7])
    result=compare(left,right,comparator,committed=True)
    return dict(result,selected_scan_directory=dict(path=name,projection='DIRECTORY_MTIME_CTIME_ONLY',inode_links_size_metadata='UNCHANGED',before_times=a[7:],after_times=b[7:]))


class Runtime(strict.Runtime):
    def __init__(self,args,config,*,comparator_path):
        super().__init__(args,config)
        self.comparator = aux.load_comparator(comparator_path,self.root_limits)
        self.aux_before = self.aux_precommit = None
        self.auxiliary_checks = []

    def view(self,observation):
        # A private validator view only: the exact helper remains in every raw
        # baseline/projected/live map. No copied file is removed or stubbed.
        aux.need(observation['complete'] is True and observation['unsupported_counts']=={'auxiliary-present':3}, 'strict-auxiliary-only-observation')
        nodes = {k:v for k,v in observation['nodes'].items() if k != aux.HELPER_NODE}
        return dict(observation,nodes=nodes,eligible=True,unsupported_counts={})

    def retained(self,nodes):
        result = super().retained(nodes)
        if getattr(self,'commit_ready',False) and aux.AUX_CACHE in result:
            result[aux.AUX_CACHE] = {k:v for k,v in result[aux.AUX_CACHE].items() if k != 'sha256'}
        return result

    def tree(self,root):
        aux.need(Path(root)==self.root,'selected-root')
        observation = roots.observe(root,limits=self.root_limits,hardlinks='generic-development-internal')
        aux.need(observation['complete'] is True and observation['unsupported_counts']=={'auxiliary-present':3}, 'strict-auxiliary-only-observation')
        state = aux.checkpoint(root,observation,self.root_limits)
        joined = aux.live_keys(state,self.comparator)
        view = self.view(observation); roots.require_eligible(view)
        nodes = observation['nodes']; self.footprints.append(observation['footprint'])
        if self.baseline is None:
            self.baseline,self.aux_before = observation,state
            self.auxiliary_checks.append(dict(checkpoint='observe-before',live_cache_keys=joined))
        else:
            committed = getattr(self,'commit_ready',False)
            previous = self.aux_precommit if committed else self.aux_before
            aux.need(previous is not None,'precommit-checkpoint-required')
            check = apps6_postcommit_compare(previous,state,self.comparator,committed=committed,selected=getattr(self,"apps6_auxiliary_selected",False),config=self.config,need=aux.need,compare=aux.compare)
            roots.check_hardlink_preservation(self.view(self.baseline),view,protected_paths=(),limits=self.root_limits)
            expected = self.projected if committed else self.baseline['nodes']
            aux.need(self.retained(nodes)==self.retained(expected),'unrelated-root-content-changed')
            if not committed: aux.need(nodes==self.baseline['nodes'],'root-changed-before-commit')
            if committed: self.auxiliary_checks.append(dict(checkpoint='observe-after',live_cache_keys=joined,**check))
        self.observation = observation
        return nodes

    def selection(self,snapshot,before,desired):
        apps6_selection_guard(snapshot,before,desired,self.config,need=aux.need,inventory_sha=scale.inventory_sha)
        super().selection(snapshot,before,desired)
        self.apps6_auxiliary_selected = True

    def projected_paths(self,seed,payload):
        aux.need(self.baseline is not None and seed==self.baseline['nodes'],'observed-seed')
        aux.need({name for name,node in payload.items() if node['type']!='directory'}==FILES
                 and all(node['type'] in ('file','directory') for node in payload.values()),'exact-eight-apps6-files')
        ancestors = {parent.as_posix() for name in FILES for parent in Path(name).parents if parent.as_posix()!='.'}
        for name,node in payload.items():
            aux.need(name in FILES or name in ancestors and node['type']=='directory','setup-payload-path')
            if node['type']=='directory' and name in seed:
                aux.need(seed[name]==node,'setup-parent-metadata')
            aux.need(name not in self.aux_before['closure'] or node['type']=='directory' and seed.get(name)==node,'payload-touches-auxiliary-closure')
        aux.need(self.old_paths<=payload.keys(),'selected-payload-removal-unsupported')
        projected = roots.projected_internal_hardlinks(self.view(self.baseline),payload,
            selected_old_paths=self.old_paths,removed_paths=(),protected_paths=(),limits=self.root_limits)
        projected[aux.HELPER_NODE] = seed[aux.HELPER_NODE]
        self.projected = projected
        return projected

    def precommit(self):
        # Keep the strict Runtime unchanged; set its commit flag only after this
        # last live closure read and the inherited configuration/capacity checks.
        scale.Runtime.precommit(self)
        aux.need(self.projected is not None,'complete-projected-root')
        state = aux.checkpoint(self.root,self.observation,self.root_limits)
        joined = aux.live_keys(state,self.comparator)
        check = aux.compare(self.aux_before,state,self.comparator,committed=False)
        self.aux_precommit = state
        self.auxiliary_checks.append(dict(checkpoint='precommit',live_cache_keys=joined,**check))
        self.commit_ready = True


def apply(args,*,comparator_path):
    delegated,result = False,None
    try:
        scale.bound.guard(Path(args.root),Path(args.workspace))
        config = scale.configuration(args.scale,args.scale_sha256)
        runtime = Runtime(args,config,comparator_path=comparator_path)
        delegated = True
        result = scale.bound.apply(args,adapter=runtime)
        result.update(scope='opt-in-setup-auxiliary-disposable-root',auxiliary_checks=runtime.auxiliary_checks,
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED',apple_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
        return result
    except BaseException as error:
        failure = dict(result) if type(result) is dict else {}
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            failure.setdefault(field,'UNKNOWN' if delegated else False)
        failure.update(status='FAIL',phase='auxiliary-runtime',error_type=type(error).__name__,error=str(error)[:256],
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED')
        return failure
