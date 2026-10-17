#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only subject and600s supervisor for the separate diagnostic route."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guest as G
import observer_progress as P
C=G.C
STATUS='SOURCE_OBSERVER_RETURNED_DIAGNOSTIC_ONLY'
FORBIDDEN='FORBIDDEN_DIAGNOSTIC_ONLY_NO_LIFECYCLE_ACCEPTANCE'
MARKER='caa_gnu_source_observer_only=1'

def child():
    """One original source-before snapshot, including its complete capability map."""
    selection=C.decode(C.read('/installed16k/selection.json'));nonce=selection['nonce']
    C.need(re.fullmatch('[0-9a-f]{32}',nonce) and os.getpid()!=1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==selection['kernel']['release'],'fixed actual16K source child required')
    markers=Path('/proc/cmdline').read_text().split()
    C.need(MARKER in markers and 'caa_gnu_installed16k=1' in markers,'dedicated source-only guest marker required')
    C.need(selection.get('diagnostic_route')=='SOURCE_OBSERVATION_ONLY_600S_NO_ACCEPTANCE','explicit diagnostic selection required')
    profile=C.read('/installed16k/container16k.py');C.need(C.sha(profile)==selection['adapter_sha256'],'exact generated snapshot subject required')
    import sandbox
    isolation=sandbox.apply();C.save('/out/isolation.json',isolation)
    os.environ.update(CACHY_GNU_PROVIDER_LIFECYCLE='1',INPUT_INDEX_SHA256=selection['input_index_sha256'],OUTPUT_UID='0',OUTPUT_GID='0',PYTHONDONTWRITEBYTECODE='1')
    record=G.install_progress(observer=P)
    native=C.load('guest_worker','/installed16k/container16k.py');native.guard()
    index,_,_,_=native.C.configuration(Path('/inputs'),selection['input_index_sha256']);api=native.C.helpers(Path('/source'))
    api['capability_index']=index;api['capability_checks']={}
    C.need(not any(Path('/work').iterdir()),'source-only diagnostic requires empty work root')
    # Original snapshot() owns full node/hash/hardlink/capability checks, 600s
    # cooperative deadline, serialization and existing snapshot/evidence caps.
    # No main/run_case, ALPM transaction, copy, runtime or reduced payload route.
    value=native.snapshot(api,Path('/held'),'pristine-source-before')
    digest=hashlib.sha256(json.dumps(value['nodes'],sort_keys=True).encode()).hexdigest()
    C.need(digest==index['source_nodes_sha256']==selection['source_nodes_sha256'],'complete source node map equality')
    check=api['capability_checks']['pristine-source-before']
    C.need(check['sha256']==index['source_capabilities_sha256']==selection['capabilities_sha256'],'complete original capability equality')
    C.need(not any(Path('/work').iterdir()),'source-only diagnostic created work root')
    record('worker','leave')
    result=dict(status=STATUS,acceptance=FORBIDDEN,source_sha=selection['source_sha'],nonce=nonce,page_size=16384,source_nodes_sha256=digest,capabilities_sha256=check['sha256'],complete=value['complete'],nodes=len(value['nodes']),snapshot=C.row('/out/pristine-source-before-root.json.gz'),ALPM='NOT_RUN',normal_lifecycle='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
    C.save('/out/result.json',result)
    print('GNU_SOURCE_OBSERVER_ONLY '+nonce+' '+json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)

def supervise(runtime,selection,nonce):
    """Finite existing process-group supervisor; no timeout-as-success path."""
    stop=threading.Event()
    def poll():
        last=0
        while not stop.wait(.25):
            try:
                info=G.PROGRESS.lstat();C.need(G.stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and G.stat.S_IMODE(info.st_mode)==0o600,'owned progress reader')
                value=G.progress_value(C.read(G.PROGRESS,65536),selection);row=value['records'][-1]
                if row['sequence']>last:
                    last=row['sequence'];print('GNU_INSTALLED16K_PROGRESS '+nonce+' '+json.dumps(dict(source_sha=selection['source_sha'],acceptance=FORBIDDEN,**row),sort_keys=True,separators=(',',':')),flush=True)
            except Exception:pass
    thread=threading.Thread(target=poll,name='bounded-source-only-progress',daemon=True);thread.start()
    try:
        return runtime.run_command(['/usr/bin/python3','-I','-B','/installed16k/source_diagnostic.py','child'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1'),600,512*1024)
    finally:stop.set();thread.join(timeout=1)

if __name__=='__main__':
    C.need(sys.argv[1:]==['child'],'source-only child entry required')
    child()
