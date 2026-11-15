# SPDX-License-Identifier: MIT
"""One exact namespace diagnostic's DATA joins; import has no actor authority."""
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

SOURCE = '69455e13bc99a2b2b6c2aca11f69d581769ae500'
REF = 'codex/native-build-namespace-observable-v1-20261114'
TREE = '0850f8b2d8e3098a4e65f6cda6ba44698d3381a0'
PARENT = '6b5b5a8f20ad2698c2d7f14a8f59c9b0ad5da165'
MAP = 'bf6d956b671b4c3df38aa579277319c1f4030a9e5efd14778fd9db528072a726'
PROFILE = '6c1592dc2cb9d9e2dca0f01f02ebaaae6b1e1936daf6307d05d7536da262a0e5'
OPERATION = 'native-build-namespace-preflight-v1'
GROUP = 'native-arm-build'
READER = dict(path='native/build_tools_reader_v2.py',bytes=106215,
              sha256='3426a340d1cd95a88280e84c8eee3debcba638abdb84d72dc5f46d05b22511cb')
HELPER = dict(path='native/image_lifecycle.py',bytes=12996,
              sha256='db316b70634018f4c85c179cabc4abfe28143dd3d863011b18367a050f8e5340',
              oid='6c9d339c9a40275447f4781ca578ad9aad9206dc')
STEP = 'Check observable namespace source controls without actors'


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def publication(value, raw_commit, rows):
    need(type(value)is dict and value.get('status')=='PUBLISHED_SOURCE_200_BODY_QUALIFIED_ACTORS_NOT_ADMITTED' and
         (value.get('source'),value.get('ref'),value.get('tree'),value.get('parents'))==(SOURCE,'refs/heads/'+REF,TREE,[PARENT]) and
         value.get('count')==200 and value.get('factory_Main_proof')is value.get('resource_authority')is None and
         value.get('Native_POSTs')==value.get('Original_GETs')==value.get('Reader_calls')==value.get('Source_execution')==0 and
         value.get('release_accepted')is False, 'exact Root observable publication DATA only')
    need(oid('commit',raw_commit)==SOURCE and pin(raw_commit)==value.get('raw'), 'exact raw observable Source commit')
    need(value['files']=={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode=r['mode'],blob=r['oid'])for n,r in rows.items()},'entire Root-published Source200 rows')
    header=raw_commit.split(b'\n\n',1)[0].splitlines()
    need([r[5:].decode() for r in header if r.startswith(b'tree ')]==[TREE] and
         [r[7:].decode() for r in header if r.startswith(b'parent ')]==[PARENT], 'genuine sole Source6b parent and exact tree')
    need(type(rows) is dict and len(rows)==200 and 'native/source-map.json' in rows, 'complete physical Source200')
    for name,row in rows.items():
        path=Path(name)
        need(type(name) is str and path.as_posix()==name and not path.is_absolute() and '..' not in path.parts and
             type(row) is dict and set(row)=={'bytes','sha256','mode','oid'} and row['mode'] in ('100644','100755') and
             type(row['bytes']) is int and 0<row['bytes']<=32*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256']) and
             re.fullmatch('[0-9a-f]{40}',row['oid']), 'typed bounded closed Source row')
    for item in (READER,HELPER):
        row=rows[item['path']]
        need(all(row[k]==item[k] for k in item if k!='path'), 'exact qualified Reader/helper body and blob')
    return value


def factory(value):
    need(type(value) is dict and value.get('schema')==1 and value.get('issuer')=='Root' and
         value.get('status')=='ROOT_BOUND_NAMESPACE_OBSERVABLE_FACTORY_CI_MAIN' and value.get('approved') is True and
         value.get('reviewed_factory')=='d6b86264d2fb6243e0ccde4a95e2a7f50804420e' and value.get('pull_request')==437 and
         value.get('baseline_main')=='208bd08d7f14c76468ff4c8fb18c357f37120070', 'PR437 genuine factory CI/Main binding pending; HOLD before role entry')
    for key in ('factory_Main','factory_head'):
        need(type(value.get(key)) is str and re.fullmatch('[0-9a-f]{40}',value[key]), 'actual factory/Main identity required')
    need(type(value.get('expected_CI_checks')) is int and 1<=value['expected_CI_checks']<=256,
         'Root binds exact complete final CI count, never infer it from earlier heads')
    for key in ('factory_merge','factory_CI'):
        row=value.get(key)
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['path']) is str and
             Path(row['path']).is_absolute() and type(row['bytes']) is int and 0<row['bytes']<=4*1024**2 and
             re.fullmatch('[0-9a-f]{64}',row['sha256']), 'independently pinned Root merge/complete CI DATA')
    return value


def factory_proofs(binding, merge, ci):
    factory(binding)
    need(merge.get('main')==binding['factory_Main'] and merge.get('tested_head')==binding['factory_head'] and
         merge.get('merge_PUTs')==1 and merge.get('all_unlisted_objects_modes_preserved') is True and
         merge.get('inverse_restores_actual_premerge_main') is True, 'genuine one-merge and exact correction inverse proof')
    need(type(merge.get('premerge_main')) is str and re.fullmatch('[0-9a-f]{40}',merge['premerge_main']) and
         type(merge.get('reviewed_changes')) is dict and 9<=len(merge['reviewed_changes'])<=256 and
         type(merge.get('correction_paths')) is list and len(set(merge['correction_paths']))==9,
         'complete reviewed integration batch and explicit correction subset; never claim nine-only merge')
    need(ci.get('head')==binding['factory_head'] and type(ci.get('checks')) is int and ci['checks']==ci.get('jobs')==binding['expected_CI_checks'] and
         ci.get('check_job_bijection') is True and ci.get('failures')==[] and ci.get('nonterminal')==[],
         'full completed CI/check-job bijection; no rollup-name-only qualification')
    jobs=ci.get('feature_jobs')
    need(type(jobs) is list and len(jobs)==2 and
         sorted(j.get('name','') for j in jobs)==['Image lifecycle source controls (3.12)','Image lifecycle source controls (3.14)'],
         'both actual hosted Python3.12/3.14 factory jobs required')
    for job in jobs:
        need(job.get('status')=='completed' and job.get('conclusion')=='success' and
             job.get('head_sha')==binding['factory_head'] and
             all(type(job.get(k)) is int and job[k]>0 for k in ('id','run_id','run_attempt')),
             'actual successful factory job/source/run/attempt identity')
        steps=[s for s in job.get('steps',[]) if s.get('name')==STEP]
        need(len(steps)==1 and steps[0].get('status')=='completed' and steps[0].get('conclusion')=='success',
             'exact observable50-control step in each real Python job')
    need(len({j['id'] for j in jobs})==2 and len({(j['run_id'],j['run_attempt']) for j in jobs})==1,
         'distinct Python jobs in the same actual source-controls run/attempt')
    return binding


def batch(merge, before, after, body):
    """Independently join every reviewed addition/removal/change and its inverse."""
    changed={n for n in set(before)|set(after) if before.get(n)!=after.get(n)}
    need(changed==set(merge['reviewed_changes']), 'every changed/addition/removal path explicitly reviewed, all others held')
    inverse=dict(after)
    for index,(name,change) in enumerate(merge['reviewed_changes'].items()):
        path=Path(name);need(path.as_posix()==name and not path.is_absolute() and '..' not in path.parts and
             type(change) is dict and set(change)=={'before','after'}, 'closed reviewed batch path/change')
        for side,actual in [('before',before),('after',after)]:
            row=change[side]
            if row is None:need(name not in actual, 'truthful reviewed addition/removal')
            else:
                need(type(row) is dict and set(row)=={'bytes','sha256','mode','oid'} and
                     row['mode'] in ('100644','100755') and actual.get(name)==dict(mode=row['mode'],blob=row['oid']),
                     'reviewed batch actual mode/blob')
                raw=body(side,index,name)
                need(pin(raw)=={k:row[k] for k in ('bytes','sha256')} and oid('blob',raw)==row['oid'], 'every changed batch body independently joined')
        if name in before:inverse[name]=before[name]
        else:inverse.pop(name,None)
    need(inverse==before, 'complete actual premerge tracked tree restored by batch inverse')
    return changed


def qualify(namespace):
    """Root runtime only: callback-owned Git; no code from Source/capsule imported."""
    o=SimpleNamespace(**namespace);facts=o.obj(o.T/'facts.json')
    binding=factory(facts.get('factory_binding'))
    p=o.obj(o.T/'source-publication.ACTUAL.json');rows=o.obj(o.T/'source-full200.json');raw=o.U.read(o.T/'publication/source.raw')
    publication(p,raw,rows)
    need(o.obj(o.PUB/'publication.json')==p and o.SOURCE_ROOT is not None, 'unmodified Root publication and explicit genuine physical Source root')
    auth={n:{k:r[k] for k in ('bytes','sha256')} for n,r in rows.items()};modes={n:int(r['mode'],8)&511 for n,r in rows.items()}
    need(o.C.closed_source_declared(o.U,o.SOURCE_ROOT,auth,modes)==TREE, 'all200 actual Source bodies/modes/tree before ingress')
    need(o.entries(o.git('source-full-map','ls-tree','-r','-z','--full-tree',SOURCE))=={n:dict(mode=r['mode'],blob=r['oid']) for n,r in rows.items()}, 'actual full200 Git body/mode/blob map')
    need(o.git('source-raw','cat-file','commit',SOURCE)==raw, 'genuine raw Source Git object')
    parent_raw=o.git('parent-raw','cat-file','commit',PARENT)
    need(oid('commit',parent_raw)==PARENT and parent_raw==o.U.read(o.T/'publication/parent.raw'), 'actual Source6b complete raw parent')
    need(o.git('source-local','rev-parse','refs/heads/'+REF).decode().strip()==SOURCE and
         o.git('source-remote','ls-remote','--heads','origin','refs/heads/'+REF).decode().split()==[SOURCE,'refs/heads/'+REF], 'fresh actual source/ref unchanged')
    wf=o.rowread(o.SOURCE_ROOT/o.WF,rows[o.WF])
    need(wf==o.rowread(o.SOURCE_ROOT/'.github/workflows/native-arm-developer-workflows.yml',rows['.github/workflows/native-arm-developer-workflows.yml']) and
         b'group: native-arm-build\n  cancel-in-progress: false\n  queue: max' in wf and b'runs-on: ubuntu-24.04-arm' in wf and
         b'options: [native-build-namespace-preflight-v1]' in wf, 'exact held ARM/group/operation workflow aliases')
    contract=o.obj(o.SOURCE_ROOT/'native/build-tools-contract-v2.json')
    need(contract.get('operation')==OPERATION and contract.get('baseline_packages')==349 and
         contract.get('resource_class')=='HEAVY_NON_KERNEL' and contract.get('concurrency_group')==GROUP and
         contract.get('cases')==['bwrap-user-mount-net','unshare-mapped-root'] and
         contract.get('bounds')==dict(command_seconds=20,total_seconds=60,command_bytes=65536,command_rows=2,consumer_cpus=2,consumer_memory=4294967296,consumer_pids=256),
         'source-authoritative finite diagnostic only; no package/install or policy scope')
    mapping=o.obj(o.SOURCE_ROOT/'native/source-map.json')
    need(pin(o.U.read(o.SOURCE_ROOT/'native/source-map.json'))['sha256']==MAP and mapping.get('actual')==dict(source=None,ref=None,run=None) and
         mapping.get('namespace_preflight_operation')==OPERATION and mapping.get('namespace_build_log_visibility')=='UNQUIET_TOOLS_IIDFILE_V1' and mapping['files']=={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode=int(r['mode'],8)&511) for n,r in rows.items() if n!='native/source-map.json'}, 'complete199 nonrecursive NULL-actual source map')
    profile=o.obj(o.T/'source-profile.json');parent_rows=o.obj(o.T/'parent-full200.json')
    source_delta(profile,parent_rows,rows)
    need(pin(o.U.read(o.T/'source-profile.json'))['sha256']==PROFILE, 'exact reviewed observable source profile')
    need(o.entries(o.git('parent-full-map','ls-tree','-r','-z','--full-tree',PARENT))=={n:dict(mode=r['mode'],blob=r['oid'])for n,r in parent_rows.items()}, 'actual complete parent6b Git map')
    def proof(row):
        body=o.U.read(Path(row['path']));need(pin(body)=={k:row[k] for k in ('bytes','sha256')}, 'Root external factory proof pin');return o.U.obj(body)
    merge=proof(binding['factory_merge']);factory_proofs(binding,merge,proof(binding['factory_CI']))
    live=o.main_guard();o.git('factory-ancestor','merge-base','--is-ancestor',binding['factory_Main'],live)
    o.git('factory-head-ancestor','merge-base','--is-ancestor',binding['factory_head'],binding['factory_Main'])
    o.git('baseline-main-ancestor','merge-base','--is-ancestor',binding['baseline_main'],binding['factory_Main'])
    table=o.entries(o.git('current-main-full-map','ls-tree','-r','-z','--full-tree',live));factory_rows=o.obj(o.T/'factory-files.json')
    need(len(factory_rows)==9, 'exact9 reviewed image producer correction leaves')
    need(set(merge['correction_paths'])==set(factory_rows), 'exact correction subset within full reviewed merge')
    before=o.entries(o.git('premerge-full-map','ls-tree','-r','-z','--full-tree',merge['premerge_main']))
    after=o.entries(o.git('merged-full-map','ls-tree','-r','-z','--full-tree',binding['factory_Main']))
    def batch_body(side,index,name):
        revision=merge['premerge_main'] if side=='before' else binding['factory_Main']
        return o.git('batch-'+side+'-'+str(index),'show',revision+':'+name)
    changed=batch(merge,before,after,batch_body)
    merged_raw=o.git('merged-raw','cat-file','commit',binding['factory_Main'])
    parents=[r[7:].decode() for r in merged_raw.split(b'\n\n',1)[0].splitlines() if r.startswith(b'parent ')]
    need(oid('commit',merged_raw)==binding['factory_Main'] and parents==[merge['premerge_main'],binding['factory_head']], 'genuine reviewed two-parent PR merge; no fabricated inverse basis')
    for index,(name,row) in enumerate(factory_rows.items()):
        body=o.git('factory-'+str(index),'show',live+':'+name)
        need(table[name]==dict(mode=row['mode'],blob=row['oid']) and pin(body)=={k:row[k] for k in ('bytes','sha256')}, 'all correction bodies/modes/blobs retained in live Main')
    o.save(o.OUT/'source-qualification.json',dict(status='EXACT_NAMESPACE_OBSERVABLE_PUBLISHED_SOURCE200_AND_MERGED_FACTORY',source=SOURCE,ref=REF,tree=TREE,parent=PARENT,map_sha256=MAP,main=live,factory_batch_changed=len(changed),factory_correction_subset=9,reader={k:READER[k] for k in ('bytes','sha256')},reader_executed=False,acceptance=False))
    return live


def source_delta(profile,before,after):
    need(profile.get('parent')==PARENT and profile.get('prospective_tree')==TREE and profile.get('source_files')==200 and
         profile.get('unchanged_files')==196 and profile.get('actual')==dict(source=None,ref=None,run=None,job=None,artifact=None) and
         profile.get('visibility')=='UNQUIET_TOOLS_IIDFILE_V1' and profile.get('acceptance')is False, 'exact source-only observable profile')
    expected={'native/owner.py','native/image_lifecycle.py','native/build_tools_reader_v2.py','native/source-map.json'}
    need(len(before)==len(after)==200 and set(before)==set(after) and
         {n for n in before if before[n]!=after[n]}==expected==set(profile['changes']), 'only exact four leaves differ;196 bodies/modes/blobs held')
    inverse=dict(after)
    for name,change in profile['changes'].items():
        for side,rows in [('before',before),('after',after)]:
            row=change[side];actual=rows[name]
            need(actual==dict(bytes=row['bytes'],sha256=row['sha256'],mode='100755'if row['mode']==0o755 else'100644',oid=row['oid']), 'complete before/after observable leaf pin')
        inverse[name]=before[name]
    need(inverse==before, 'four-leaf inverse restores complete published parent')


def dispatch_view(value):
    need(value.get('source')==SOURCE and value.get('ref')=='refs/heads/'+REF,
         'only exact actual Root observable source/ref projection')
    return dict(source=SOURCE,ref=REF)
