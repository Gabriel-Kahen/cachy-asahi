#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One separately leased native574 -> independent Welcome5/DNS GUI continuation."""
import argparse,fcntl,json,os,platform,signal,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import candidates as C
import prepare
import invocation as I

def execute(source,base,assets,out,selected,context=None):
    C.selection(source)
    C.need(selected in ('minimal','overlay')and platform.system()=='Linux'and platform.machine()=='aarch64'and os.getuid()==os.geteuid()>0 and
        not any(k.startswith('DOCKER_')for k in os.environ),'explicit profile/ordinary native ARM/local daemon required')
    for path in (source,base,assets,out):C.need(path.is_absolute()and not any(p.is_symlink()for p in (path,*path.parents)),'ordinary explicit path required')
    C.need(not out.exists()and not any(out.is_relative_to(p)or p.is_relative_to(out)for p in (source,base,assets)),'fresh disjoint output required')
    C.need(type(context)is dict and set(context)=={'argv','proof','source_proof','source_manifest'}and context['proof'].get('profile')==selected and context['proof'].get('source_path')==str(source)and context['proof'].get('runtime_path')==str(out),'authenticated actual wrapper context required')
    original=C.read(base/'report.json');C.need(original.get('status')=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and original.get('image')==(base/'image-id').read_text().strip(),'actual owned producer required')
    out.mkdir(mode=0o700);lease=os.open(out/'runtime.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_CLOEXEC,0o600);fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
    common=C.load('held_GUI_bounded_process',source/'scripts/virtual/common.py')
    active=None;started=False;retired=False;absent=False;code=None
    def interrupted(*_):raise TimeoutError('owned profile cancellation/deadline')
    previous={s:signal.signal(s,interrupted)for s in (signal.SIGTERM,signal.SIGINT)}
    try:
        runner=prepare.prepare(source,assets,out/'runner',selected)
        I.write(out/'profile-invocation.json',context['argv'],context['proof'],context['source_proof'],context['source_manifest'],I.pin(runner/'runner-proof.json'))
        env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(out/'home'));(out/'home').mkdir(mode=0o700)
        started=True
        active=common.LoggedProcess([sys.executable,'-B',str(runner/'desktop574_runtime.py'),'--source',str(source),'--base-dir',str(base),'--output',str(out/'runtime')],out/'runtime-child.log',env=env,limit=16*1024**2)
        active.process.wait(timeout=2200);code=active.process.returncode;active.finish();retired=True
        C.need(code==0,'actual original runtime failed; original logs retained')
        result=C.read(out/'runtime/runtime.json');C.need(result.get('status')=='PASS_INSTALLED_WELCOME_SINGLE_PROFILE_GUI_METADATA','actual original runner status differs')
        old=list(sys.path);sys.path.insert(0,str(runner))
        try:
            validator=C.load('welcome5_actual_generated_contract',runner/'contract.py')
            proof=validator.verify_result(result['events'],C.read(runner/'candidate-lock.json'))
        finally:sys.path[:]=old
        C.need(result.get('gui_contract')==proof,'actual complete13-view replay differs')
        (out/'result.json').write_text(json.dumps(dict(status='PASS_WELCOME5_DNS_GUI_METADATA_PIXELS_PENDING_REVIEW',profile=selected,gui=proof,physical_input='NOT_RUN',hardware='NOT_RUN',current606='NOT_RUN'),sort_keys=True,indent=2)+'\n')
        return 0
    finally:
        for s in previous:signal.signal(s,signal.SIG_IGN)
        try:
            if active is not None:
                if active.process.poll()is None:
                    try:os.killpg(active.process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:active.process.wait(timeout=450)
                    except subprocess.TimeoutExpired:
                        os.killpg(active.process.pid,signal.SIGKILL);active.process.wait(timeout=5)
                active.finish();code=active.process.returncode;retired=True
                try:os.killpg(active.process.pid,0)
                except ProcessLookupError:absent=True
            if not started:retired=absent=True
        finally:
            (out/'runtime-terminal.json').write_text(json.dumps(dict(schema_version=1,profile=selected,child_started=started,reaped=retired,group_absent=absent,returncode=code),sort_keys=True)+'\n')
            os.close(lease)
            for s,old in previous.items():signal.signal(s,old)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','base','assets','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--profile',required=True,choices=('minimal','overlay'))
    a=p.parse_args();p.error('invoke job.py run with the authenticated source proof; direct runtime invocation is unsupported')
