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
STATUS='FIRST_NORMAL_SOURCE_OBSERVER_RETURNED_DIAGNOSTIC_ONLY'
FORBIDDEN='FORBIDDEN_DIAGNOSTIC_ONLY_NO_LIFECYCLE_ACCEPTANCE'
MARKER='caa_gnu_source_observer_only=1'

class FirstObserverComplete(BaseException):
    """Explicit diagnostic stop; the original normal program records FAIL."""

def intercept(C,selection):
    state=dict(observations=0,completed=None,normal_failure=None)
    original_load=C.load
    def load(name,path):
        module=original_load(name,path)
        if name=='guest_worker' and str(path)=='/installed16k/container16k.py':
            helpers=module.C.helpers
            def selected_helpers(*args,**kwargs):
                api=helpers(*args,**kwargs);roots=api['roots'];observe=roots.observe
                def first(root,**options):
                    C.need(state['observations']==0 and Path(root)==Path('/held'),'exact first held-source observer only')
                    state['observations']+=1
                    value=observe(root,**options)
                    digest=C.sha(json.dumps(value['nodes'],sort_keys=True).encode())
                    C.need(value['complete'] is True and digest==selection['source_nodes_sha256'],'complete first original source map equality')
                    state['completed']=dict(complete=True,nodes=len(value['nodes']),source_nodes_sha256=digest)
                    raise FirstObserverComplete('DIAGNOSTIC_STOP_AFTER_FIRST_OBSERVER_BEFORE_CAPABILITIES')
                api['roots']=G.types.SimpleNamespace(**dict(vars(roots),observe=first));return api
            module.C.helpers=selected_helpers
            main=module.main
            def stopped_main():
                code=main()
                if state['completed'] is not None:
                    report=C.decode(C.read('/out/result.json',65536))
                    C.need(code==1 and report['status']=='FAIL' and report['error_type']=='FirstObserverComplete' and report['error']=='DIAGNOSTIC_STOP_AFTER_FIRST_OBSERVER_BEFORE_CAPABILITIES','original normal program must refuse diagnostic interruption')
                    state['normal_failure']=dict(exit_code=code,status=report['status'],error_type=report['error_type'],error=report['error'])
                    raise FirstObserverComplete('DIAGNOSTIC_STOP_AFTER_FIRST_OBSERVER_BEFORE_CAPABILITIES')
                return code
            module.main=stopped_main
        return module
    C.load=load;return state

def child():
    """Exact normal worker/main/security/setup, stopped after its first observer."""
    selection=C.decode(C.read('/installed16k/selection.json'));nonce=selection['nonce']
    C.need(selection.get('diagnostic_route')=='FIRST_NORMAL_SOURCE_OBSERVER_ONLY_600S_NO_ACCEPTANCE' and MARKER in Path('/proc/cmdline').read_text().split(),'dedicated first-observer diagnostic selection/marker')
    G.install_progress();state=intercept(C,selection)
    try:G.worker()
    except FirstObserverComplete:
        C.need(state['observations']==1 and state['completed'] is not None and state['normal_failure'] is not None,'one complete original first observer and normal refusal required')
    else:raise ValueError('normal worker returned without explicit diagnostic stop')
    C.need(not any(Path('/work').iterdir()),'first-observer diagnostic must stop before clone')
    result=dict(status=STATUS,acceptance=FORBIDDEN,source_sha=selection['source_sha'],nonce=nonce,page_size=16384,**state['completed'],capabilities='NOT_RUN_STOPPED_BEFORE_CAPABILITY_OBSERVER',stop='AFTER_FIRST_ROOTS_OBSERVE_BEFORE_CAPS_CLONE_ALPM',normal_subject='UNCHANGED_NORMAL_G_WORKER_MAIN',normal_failure=state['normal_failure'],ALPM='NOT_RUN',normal_lifecycle='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
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
