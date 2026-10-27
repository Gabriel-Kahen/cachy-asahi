#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One bounded complete retained DATA fetch outside executable source; no retries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C
sys.path.insert(0,str(C.HERE.parents[2]/C.DATA))
import reserved_process as R
SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
TREE='e21f947bac3afdfbd67e4e65c8234b35ae42b00f'
PROFILE='scripts/ci/setup6-retained-helpers/carrier-profile.json'
PROFILE_SHA='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
BUDGETS=(10,400,10,45,10)
NAME='fish-done-retained574'
CAP=2*1024**2

def plan(carrier):
    git=['/usr/bin/git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true',
         '-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always']
    return [[*git,'init','--template=',str(carrier)],
        [*git,'-C',str(carrier),'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60',
         'fetch','--depth=1','--no-tags','--no-recurse-submodules',
         'https://github.com/Gabriel-Kahen/cachy-asahi.git',SOURCE],
        [*git,'-C',str(carrier),'rev-parse','--verify','FETCH_HEAD'],
        [*git,'-C',str(carrier),'checkout','--detach',SOURCE],
        [*git,'-C',str(carrier),'rev-parse','--verify','HEAD']]

def profile(root):
    raw=C.read(root/PROFILE);value=json.loads(raw)
    C.need(C.pin(raw)['sha256']==PROFILE_SHA and value['source']==SOURCE and
           len(value['files'])==1154 and sum(r['bytes'] for r in value['files'].values())==1046432165,
           'original complete1154 retained DATA profile required')
    return value

def execute(root,carrier,proof_path,output):
    started=time.monotonic();deadline=started+480
    root,carrier,output=map(C.safe,(root,carrier,output))
    proof=json.loads(C.read(proof_path));C.verify(root,proof['manifest_sha256']);profile(root)
    temp=C.safe(Path(os.environ['RUNNER_TEMP']))
    C.need(carrier==temp/NAME and output==temp/'done-transport' and
           not carrier.is_relative_to(root) and not root.is_relative_to(carrier) and
           not output.is_relative_to(root) and not root.is_relative_to(output) and
           not os.path.lexists(carrier) and not os.path.lexists(output),
           'fresh fixed outside-source retained DATA and transport output required')
    C.need(temp.stat().st_uid==os.getuid() and not temp.stat().st_mode&0o022,
           'owned non-writable-by-others runner temporary directory required')
    C.need(proof['status']=='SOURCE_PROOF_PASS' and proof['source_sha']==proof['workflow_sha']==
           os.environ['SOURCE_SHA']==os.environ['GITHUB_SHA']==os.environ['GITHUB_WORKFLOW_SHA'] and
           proof['run_id']==os.environ['GITHUB_RUN_ID'] and proof['run_attempt']==os.environ['GITHUB_RUN_ATTEMPT'],
           'exact current source/workflow/run proof required')
    output.mkdir(mode=0o700);(output/'home').mkdir(mode=0o700)
    report=dict(status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',proof=proof,carrier_source=SOURCE,
        carrier_path=str(carrier),source_root=str(root),runner_temp=str(temp),profile_sha256=PROFILE_SHA,
        expected_files=1154,expected_bytes=1046432165,budget_seconds=480,fetch_budget_seconds=400,
        retry=False,partial_data_retained=True,native='NOT_RUN',acceptance=False)
    rows=[]
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',HOME=str(output/'home'),
        GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='https')
    try:
        carrier.mkdir(mode=0o700)
        for index,(argv,budget) in enumerate(zip(plan(carrier),BUDGETS),1):
            remaining=deadline-time.monotonic();C.need(remaining>0,'transport total deadline expired')
            row=dict(index=index,argv=argv,budget_seconds=budget);rows.append(row)
            with (output/f'command-{index}.stdout').open('xb') as out,(output/f'command-{index}.stderr').open('xb') as err:
                receipt=R.run(argv,min(budget,remaining),cwd=output,env=env,stdout=out,stderr=err,
                              term_seconds=3,kill_seconds=2)
            # Host init may finish adopting/reaping a completed git helper. No
            # numeric group operation follows the supervisor's actual leader reap.
            end=min(deadline,time.monotonic()+2)
            while receipt['ownership']=='REAPED' and receipt['retirement']=='PRESENT' and time.monotonic()<end:
                time.sleep(.02);R.refresh(receipt)
            row['supervision']=receipt
            for suffix in ('stdout','stderr'):
                raw=C.read(output/f'command-{index}.{suffix}',CAP);row[suffix]=C.pin(raw)
            C.save(output/'commands.json',rows);R.assert_verified(receipt)
            if index in (3,5):
                C.need(C.read(output/f'command-{index}.stdout',CAP)==(SOURCE+'\n').encode(),
                       'exact fetched/checked-out retained commit required')
        C.need(time.monotonic()<=deadline,'transport total deadline expired')
        report.update(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY',carrier_head=SOURCE)
    except BaseException as error:
        report.update(error_type=type(error).__name__,error=str(error)[:2048])
        raise
    finally:
        C.save(output/'commands.json',rows)
        report['elapsed_seconds']=time.monotonic()-started
        C.save(output/'report.json',report)
    return report

def validate(directory,root,proof,prepared=None):
    """Pure offline original-byte DATA gate; no carrier bodies or actors execute."""
    profile(root)
    report=json.loads(C.read(directory/'report.json'));rows=json.loads(C.read(directory/'commands.json'))
    carrier=Path(report['carrier_path']);temp=Path(report['runner_temp']);source=Path(report['source_root'])
    C.need(temp.is_absolute() and '..' not in temp.parts and carrier==temp/NAME and
           source.is_absolute() and '..' not in source.parts and not carrier.is_relative_to(source) and
           not source.is_relative_to(carrier),'recorded external retained DATA placement required')
    C.need(report['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY' and report['proof']==proof and
           report['carrier_source']==report['carrier_head']==SOURCE and report['profile_sha256']==PROFILE_SHA and
           report['expected_files']==1154 and report['expected_bytes']==1046432165 and report['budget_seconds']==480 and
           report['fetch_budget_seconds']==400 and 0<=report['elapsed_seconds']<=480 and report['retry'] is False and
           report['partial_data_retained'] is True and report['native']=='NOT_RUN' and report['acceptance'] is False,
           'same-owner exact full retained DATA transport proof required')
    C.need(type(rows) is list and len(rows)==5,'five one-fetch transport commands required')
    expected={'report.json','commands.json'}
    for index,(row,argv,budget) in enumerate(zip(rows,plan(carrier),BUDGETS),1):
        C.need(row['index']==index and row['argv']==argv and row['budget_seconds']==budget,
               'original exact one-fetch transport plan required')
        R.assert_verified(row['supervision'])
        for suffix in ('stdout','stderr'):
            name=f'command-{index}.{suffix}';expected.add(name)
            C.need(C.pin(C.read(directory/name,CAP))==row[suffix],'original transport stream/hash differs')
    C.need(set(C.files(directory))==expected,'whole retained transport stream namespace differs')
    C.need(all(C.read(directory/f'command-{i}.stdout',CAP)==(SOURCE+'\n').encode() for i in (3,5)),
           'raw fetched/HEAD commit outputs differ')
    if prepared is not None:
        value=prepared['packages'];identity=value['carrier'];cache=value['receipt']['cache']
        packages=json.loads(C.read(root/'scripts/ci/maintained-desktop574-inputs.json'))['packages']
        expected={}
        for row in packages:
            expected[row['filename']]=dict(bytes=row['size'],sha256=row['sha256'])
            expected[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
        C.need(prepared['status']=='PASS_RETAINED1148_AND_FIVE_ORIGINAL_NONPACKAGE_DATA' and
               prepared['actual'] is value['actual'] is None and len(prepared['nonpackages'])==5 and
               value['mode']=='desktop574' and value['source']==identity['source']==SOURCE and
               identity['tree']==TREE and identity['files']==identity['blob_joins']==1154 and
               cache['added']==len(expected)==1148 and cache['before_files']=={} and cache['after_files']==expected and
               value['receipt']['actual_authority'] is False and
               cache['all_previous_inode_metadata_bytes_unchanged'] is True,
               'original complete1154 Git/blob and1148 cache preparation required after DATA transport')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','carrier','proof','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(execute(*(getattr(args,n).absolute() for n in ('source','carrier','proof','output'))),indent=2))
