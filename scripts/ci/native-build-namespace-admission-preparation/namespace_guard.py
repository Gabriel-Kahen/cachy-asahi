# SPDX-License-Identifier: MIT
"""One exact namespace diagnostic's DATA joins; import has no actor authority."""
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

SOURCE = '6b5b5a8f20ad2698c2d7f14a8f59c9b0ad5da165'
REF = 'codex/native-build-namespace-preflight-v2-20261114'
TREE = 'a825d475d248f2254070d256d23780c4ef2d0f4b'
PARENT = '97a44c4c7cb206704bf76e9fd1f1afb2266278c2'
MAP = '7474683e198759876dcee6b31a036473f2129da351fce3bcc8e37770b4a70f79'
PROFILE = '8c0dc91cbd97dcfda1353dcafa1da1f08f250e3c690a97e08f657431f29e7472'
OPERATION = 'native-build-namespace-preflight-v1'
GROUP = 'native-arm-build'
READER = dict(path='native/build_tools_reader_v2.py',bytes=100346,
              sha256='2292e492bf33fea2d079525165293e47e2d817deed71495a3b80d3090a406aa5')
HELPER = dict(path='native/image_lifecycle.py',bytes=13034,
              sha256='805fabc496f10b67425cc69bdf7793d0e703dae1fab2407d8596391c9e9c5f2b',
              oid='5ff9656200fc88681567be84b2efa0e91c23803d')
STEP = 'Check image lifecycle producer and Reader DATA without actors'


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def publication(value, raw_commit, rows):
    need(type(value) is dict and value.get('status')=='PUBLIC_SOURCE_DATA_ONLY_NOT_NATIVE_ADMISSION' and
         (value.get('source'),value.get('ref'),value.get('tree'),value.get('parent'),value.get('map_sha256'),value.get('profile_sha256')) ==
         (SOURCE,REF,TREE,PARENT,MAP,PROFILE) and value.get('files')==200 and
         value.get('fresh_bare_verified') is True and value.get('remote_ref_verified') is True and
         value.get('native_run') is value.get('job') is value.get('artifact') is None and
         value.get('actual_reader_calls')==0 and value.get('supersedes_ineligible_source')=='b659e3049d11ff160494dfc2d8881830c9aae7ac',
         'exact corrected Root Source DATA publication, never old b659 or native admission')
    need(oid('commit',raw_commit)==SOURCE and pin(raw_commit)['sha256']==value['raw_commit_sha256'], 'exact Root raw Source commit')
    header=raw_commit.split(b'\n\n',1)[0].splitlines()
    need([r[5:].decode() for r in header if r.startswith(b'tree ')]==[TREE] and
         [r[7:].decode() for r in header if r.startswith(b'parent ')]==[PARENT], 'genuine sole Source97 parent and exact tree')
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
         value.get('status')=='ROOT_BOUND_NAMESPACE_FACTORY_CI_MAIN' and value.get('approved') is True and
         value.get('reviewed_correction')=='8d4ec359bf05dda455eb772077b4edf37de53002' and value.get('pull_request')==433 and
         value.get('baseline_main')=='295d838936371ce7376fc5b71c47232b155bd0b3', 'PR433 genuine factory CI/Main binding pending; HOLD before role entry')
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
         type(merge.get('reviewed_changes')) is dict and 11<=len(merge['reviewed_changes'])<=256 and
         type(merge.get('correction_paths')) is list and len(set(merge['correction_paths']))==11,
         'complete reviewed integration batch and explicit correction subset; never claim eleven-only merge')
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
             'exact source lifecycle53-control step in each real Python job')
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
    need(oid('commit',parent_raw)==PARENT and parent_raw==o.U.read(o.T/'publication/parent.raw'), 'actual Source97 complete raw parent')
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
         mapping.get('namespace_preflight_operation')==OPERATION and mapping['files']=={n:dict(bytes=r['bytes'],sha256=r['sha256'],mode=int(r['mode'],8)&511) for n,r in rows.items() if n!='native/source-map.json'}, 'complete199 nonrecursive NULL-actual source map')
    def proof(row):
        body=o.U.read(Path(row['path']));need(pin(body)=={k:row[k] for k in ('bytes','sha256')}, 'Root external factory proof pin');return o.U.obj(body)
    merge=proof(binding['factory_merge']);factory_proofs(binding,merge,proof(binding['factory_CI']))
    live=o.main_guard();o.git('factory-ancestor','merge-base','--is-ancestor',binding['factory_Main'],live)
    o.git('factory-head-ancestor','merge-base','--is-ancestor',binding['factory_head'],binding['factory_Main'])
    o.git('baseline-main-ancestor','merge-base','--is-ancestor',binding['baseline_main'],binding['factory_Main'])
    table=o.entries(o.git('current-main-full-map','ls-tree','-r','-z','--full-tree',live));factory_rows=o.obj(o.T/'factory-files.json')
    need(len(factory_rows)==11, 'exact11 reviewed image producer correction leaves')
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
    o.save(o.OUT/'source-qualification.json',dict(status='EXACT_NAMESPACE_PREFLIGHT_PUBLISHED_SOURCE200_AND_MERGED_FACTORY',source=SOURCE,ref=REF,tree=TREE,parent=PARENT,map_sha256=MAP,main=live,factory_batch_changed=len(changed),factory_correction_subset=11,reader={k:READER[k] for k in ('bytes','sha256')},reader_executed=False,acceptance=False))
    return live
