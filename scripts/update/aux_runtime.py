#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in held auxiliary candidate, only for the real setup3-to-setup4 upgrade."""
from pathlib import Path

import aux_checkpoint as aux
import full_root as roots
import internal_runtime as strict
import scale_update as scale

SETUP = 'cachy-asahi-setup'
SETUP_ARCHIVE = 'c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
FILES = {'usr/bin/cachy-asahi-setup','usr/bin/cachy-asahi-repository',
         'usr/share/doc/'+SETUP+'/README.md','usr/share/doc/'+SETUP+'/repository-enrollment.md',
         'usr/share/licenses/'+SETUP+'/NOTICE','usr/share/licenses/'+SETUP+'/LICENSE'}


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
            check = aux.compare(previous,state,self.comparator,committed=committed)
            roots.check_hardlink_preservation(self.view(self.baseline),view,protected_paths=(),limits=self.root_limits)
            expected = self.projected if committed else self.baseline['nodes']
            aux.need(self.retained(nodes)==self.retained(expected),'unrelated-root-content-changed')
            if not committed: aux.need(nodes==self.baseline['nodes'],'root-changed-before-commit')
            if committed: self.auxiliary_checks.append(dict(checkpoint='observe-after',live_cache_keys=joined,**check))
        self.observation = observation
        return nodes

    def selection(self,snapshot,before,desired):
        aux.need(before.get(SETUP)=='0.1.0-3' and desired=={SETUP:'0.1.0-4'},'exact-setup-transition')
        rows = snapshot['release']['packages']
        aux.need(len(rows)==1 and rows[0]['name']==SETUP and rows[0]['version']=='0.1.0-4'
                 and rows[0]['sha256']==SETUP_ARCHIVE,'exact-setup-archive')
        super().selection(snapshot,before,desired)

    def projected_paths(self,seed,payload):
        aux.need(self.baseline is not None and seed==self.baseline['nodes'],'observed-seed')
        aux.need({name for name,node in payload.items() if node['type']!='directory'}==FILES
                 and all(node['type'] in ('file','directory') for node in payload.values()),'exact-six-setup-files')
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
