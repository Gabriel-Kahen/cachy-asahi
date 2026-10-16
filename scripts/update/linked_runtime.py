#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Setup-only auxiliary adapter connected to finite frozen link identities."""
from pathlib import Path

import aux_checkpoint as aux
import aux_runtime
import full_root as roots
import root_link_selection as links
import scale_update as scale


class Runtime(aux_runtime.Runtime):
    def view(self,observation): return links.view(observation,self.root_limits)

    def resolve_nodes(self,nodes,path):
        return links.protection_endpoint(nodes,path,self.root_limits)

    def tree(self,root):
        aux.need(Path(root)==self.root,'selected-root')
        observation=roots.observe(root,limits=self.root_limits,hardlinks='generic-development-internal')
        links.check(observation,self.root_limits)
        state=aux.checkpoint(root,observation,self.root_limits)
        joined=aux.live_keys(state,self.comparator)
        view=self.view(observation); roots.require_eligible(view)
        nodes=observation['nodes']; self.footprints.append(observation['footprint'])
        if self.baseline is None:
            self.baseline,self.aux_before=observation,state
            self.auxiliary_checks.append(dict(checkpoint='observe-before',live_cache_keys=joined))
        else:
            committed=getattr(self,'commit_ready',False)
            previous=self.aux_precommit if committed else self.aux_before
            aux.need(previous is not None,'precommit-checkpoint-required')
            check=aux.compare(previous,state,self.comparator,committed=committed)
            roots.check_hardlink_preservation(self.view(self.baseline),view,protected_paths=(),limits=self.root_limits)
            expected=self.projected if committed else self.baseline['nodes']
            aux.need(self.retained(nodes)==self.retained(expected),'unrelated-root-content-changed')
            if not committed: aux.need(nodes==self.baseline['nodes'],'root-changed-before-commit')
            if committed: self.auxiliary_checks.append(dict(checkpoint='observe-after',live_cache_keys=joined,**check))
        self.observation=observation
        return nodes

    def projected_paths(self,seed,payload):
        projected=super().projected_paths(seed,payload)
        self.projected=links.restore_literals(projected,seed)
        return self.projected


def apply(args,*,comparator_path):
    delegated,result=False,None
    try:
        scale.bound.guard(Path(args.root),Path(args.workspace))
        config=scale.configuration(args.scale,args.scale_sha256)
        runtime=Runtime(args,config,comparator_path=comparator_path)
        delegated=True
        result=scale.bound.apply(args,adapter=runtime)
        result.update(scope='opt-in-setup-selected-links-disposable-root',auxiliary_checks=runtime.auxiliary_checks,
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED',apple_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
        return result
    except BaseException as error:
        failure=dict(result) if type(result) is dict else {}
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            failure.setdefault(field,'UNKNOWN' if delegated else False)
        failure.update(status='FAIL',phase='selected-link-runtime',error_type=type(error).__name__,error=str(error)[:256],
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED')
        return failure
