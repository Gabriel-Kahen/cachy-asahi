#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Setup-only auxiliary adapter connected to finite frozen link identities."""
from pathlib import Path

import aux_checkpoint as aux
import aux_runtime
import full_root as roots
import root_link_selection as links
import scale_update as scale


def apps_scan_difference(before,after,raw_before,raw_after):
    import hashlib,json
    def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    def summary(mapping,name):
        if name not in mapping:return {'present':False}
        row=mapping[name];data=encoded(row)
        if len(data)>16384:raise ValueError('bounded scan row')
        out={'present':True,'row_type':type(row).__name__,'row_bytes':len(data),'row_sha256':hashlib.sha256(data).hexdigest()}
        if type(row) is not dict:
            if row is None or type(row) in (bool,int) or type(row) is str and len(row)<=128:out['scalar']=row
            return out
        out['row_keys']=sorted(str(k)[:128] for k in row)[:16];node=row.get('node')
        if type(node) is dict:
            out['node']={k:v for k,v in node.items() if k in ('type','mode','uid','gid','bytes','sha256') and (type(v) in (int,bool) or type(v) is str and len(v)<=128)}
            if type(node.get('target')) is str:out['node']['target_sha256']=hashlib.sha256(node['target'].encode()).hexdigest()
        identity=row.get('identity')
        if type(identity) in (list,tuple) and len(identity)<=9 and all(type(v)is int for v in identity):out['identity']=list(identity)
        return out
    old,new=before['scan'],after['scan']
    if type(old)is not dict or type(new)is not dict or len(old)>8192 or len(new)>8192:raise ValueError('bounded scan maps')
    names=sorted(set(old)|set(new));path=next((n for n in names if n not in old or n not in new or old[n]!=new[n]),None)
    if path is None:raise ValueError('no original scan difference')
    if type(path)is not str or not 0<len(path)<=1024 or not path.isprintable() or path.startswith('/') or any(p in ('','.','..') for p in path.split('/')):raise ValueError('bounded scan path')
    category,field='ROW_SHAPE_OR_SCALAR','row'
    if path not in new:category,field='MISSING_NODE','row.presence'
    elif path not in old:category,field='EXTRA_NODE','row.presence'
    elif type(old[path])is dict and type(new[path])is dict:
        a,b=old[path],new[path]
        if set(a)!=set(b):category,field='ROW_FIELDS','row.keys'
        elif a.get('node')!=b.get('node'):
            category,field='NODE_METADATA_OR_SHAPE','node'
            if type(a.get('node'))is dict and type(b.get('node'))is dict:
                key=next(k for k in sorted(set(a['node'])|set(b['node'])) if k not in a['node'] or k not in b['node'] or a['node'][k]!=b['node'][k]);field='node.'+str(key)[:128];category='NODE_HASH_OR_LINK' if key in ('sha256','target') else 'NODE_METADATA_OR_SHAPE'
        elif a.get('identity')!=b.get('identity'):
            category,field='INODE_IDENTITY','identity'
            aa,bb=a.get('identity'),b.get('identity');labels=('device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')
            if type(aa)in(list,tuple) and type(bb)in(list,tuple) and len(aa)==len(bb)<=9:field='identity.'+labels[next(i for i in range(len(aa)) if aa[i]!=bb[i])]
    value={'schema_version':1,'status':'BOUNDED_SCAN_DIFFERENCE_DIAGNOSTIC_ONLY','acceptance_authority':False,'path':path,'category':category,'field':field,'before_scan_entries':len(old),'after_scan_entries':len(new),'before':summary(raw_before['scan'],path),'after':summary(raw_after['scan'],path),'comparison_view':'EXISTING_EXACT_APPS_PARENT_TIME_PROJECTION','original_failure':'aux-checkpoint-scan-changed'}
    if len(encoded(value))>8192:raise ValueError('bounded scan diagnostic')
    return value


def apps6_linked_compare(runtime,before,after,*,committed):
    def compare(left,right,comparator,*,committed):
        try:return aux.compare(left,right,comparator,committed=committed)
        except ValueError as error:
            if str(error)=='aux-checkpoint-scan-changed':
                try:
                    try:value=apps_scan_difference(left,right,before,after)
                    except Exception as diagnostic_error:value={'status':'SCAN_DIAGNOSTIC_UNAVAILABLE','error_type':type(diagnostic_error).__name__,'acceptance_authority':False}
                    runtime.auxiliary_checks.append({'checkpoint':'scan-comparison-failure','diagnostic':value})
                except Exception:pass # Original refusal always wins over diagnostic failure.
            raise
    return aux_runtime.apps6_postcommit_compare(before,after,runtime.comparator,committed=committed,selected=getattr(runtime,'apps6_auxiliary_selected',False),config=runtime.config,need=aux.need,compare=compare)


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
            check=apps6_linked_compare(self,previous,state,committed=committed)
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
            selected_link_variant=links.variant_report(runtime.baseline['nodes'] if runtime.baseline is not None else None),
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED',apple_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
        return result
    except BaseException as error:
        failure=dict(result) if type(result) is dict else {}
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            failure.setdefault(field,'UNKNOWN' if delegated else False)
        failure.update(status='FAIL',phase='selected-link-runtime',error_type=type(error).__name__,error=str(error)[:256],
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED')
        return failure
