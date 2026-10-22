#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run one ready source-bound GUI mode/profile in disposable native CI only."""
import argparse,fcntl,json,os,platform,re,signal,sys
from pathlib import Path
import factory as F
import context606 as C

def cleanup(value):
    rows=value['cleanup'];C.need(type(rows)is list and len(rows)==15 and all(r.get('exit',0)==0 and'error'not in r for r in rows)and sum(r.get('guest_disk_removed')is True for r in rows)==1 and value['base_reference_cleanup']['ok']is True,'all original14 guards plus one new owned controller-image removal')
    identities={value['runtime_image'],value['controller_image']};C.need(len(identities)==2 and value['base_image']not in identities and all(re.fullmatch('sha256:[a-f0-9]{64}',v)for v in identities),'two exact new owned image identities')
    removed={r['action'].removeprefix('remove-image:')for r in rows if r.get('action','').startswith('remove-image:')};C.need(removed==identities,'both exact owned images retired')
    return dict(status='PASS_NEW15_RUNTIME_CLEANUP_REQUIRES_ORIGINAL_PRODUCER_RETIREMENT',images=sorted(identities),producer='BORROWED_NOT_REMOVED')

def run(source,runner,base,out,selected,mode):
    source,runner,base,out=(Path(p).absolute()for p in(source,runner,base,out));F.source(source);proof=C.authorize_runner(runner)
    C.need(proof['profile']==selected and proof['mode']==mode,'exact source-bound independent profile/page mode')
    C.need(platform.system()=='Linux'and platform.machine()=='aarch64'and os.getuid()==os.geteuid()>0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('RUNNER_ARCH')=='ARM64','explicit adopted native disposable CI only')
    C.need(not out.exists()and out.parent.is_dir()and not any(p.is_symlink()for p in(out,*out.parents)),'fresh owned controller output')
    C.need(json.loads(C.read(base/'report.json'))['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION','successful original owned574 producer still required')
    out.mkdir(mode=0o700);(out/'home').mkdir(mode=0o700);fd=os.open(out/'runtime.lease',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    common=F.load('_current606_original_process',source/'scripts/virtual/common.py');child=None;code=None;absent=False;natural=False
    def stop(*_):raise TimeoutError('owned GUI controller interrupted')
    previous={s:signal.signal(s,stop)for s in(signal.SIGTERM,signal.SIGINT)}
    try:
        env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(out/'home'),LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC')
        argv=[sys.executable,'-B',str(runner/'desktop574_runtime.py'),'--source',str(source),'--base-dir',str(base),'--output',str(out/'runtime')]
        child=common.LoggedProcess(argv,out/'runtime-child.log',env=env,limit=16*1024**2);child.process.wait(timeout=2200);code=child.process.returncode;child.finish();natural=True
        try:os.killpg(child.process.pid,0)
        except ProcessLookupError:absent=True
        C.need(absent,'owned controller group must retire before success')
        C.need(code==0,'new source-owned GUI runtime must naturally succeed')
        value=json.loads(C.read(out/'runtime/runtime.json',16*1024**2));C.need(value['status']=='PASS_CURRENT606_WELCOME8_'+mode.upper()+'_GUI_METADATA'and value['runtime_package_count']==606 and value['guest_packages']==606 and value['controller_packages']==590,'exact current606 guest,590 controller and selected page result')
        old=sys.path[:];sys.path.insert(0,str(runner))
        try:contract=F.load('_current606_actual_complete_contract',runner/'contract.py');joined=contract.verify_result(value['events'],json.loads(C.read(runner/'candidate-lock.json')))
        finally:sys.path[:]=old
        C.need(joined==value['gui_contract'],'whole actual thirteen-view/Doctor2/DNS/606 preservation replay')
        result=dict(status='PASS_ONE_CURRENT606_WELCOME8_GUI_PROFILE_PENDING_ROOT',profile=selected,mode=mode,GUI=joined,cleanup=cleanup(value),producer_cleanup='NOT_ATTEMPTED_ORIGINAL_ORDERED_CLEANUP_STILL_REQUIRED',source_proof=F.pin(C.read(runner/'current606-proof.json',16*1024**2)),Root_acceptance='NOT_ISSUED',hardware='NOT_RUN',performance='NOT_CLAIMED',release='NOT_ADMITTED');(out/'result.json').write_bytes(C.enc(result));return result
    finally:
        for s in previous:signal.signal(s,signal.SIG_IGN)
        try:
            if child is not None:
                if child.process.poll()is None:
                    try:os.killpg(child.process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:child.process.wait(timeout=450)
                    except __import__('subprocess').TimeoutExpired:os.killpg(child.process.pid,signal.SIGKILL);child.process.wait(timeout=5)
                child.finish();code=child.process.returncode
                try:os.killpg(child.process.pid,0)
                except ProcessLookupError:absent=True
            else:absent=True
        finally:
            (out/'runtime-terminal.json').write_bytes(C.enc(dict(schema_version=1,profile=selected,mode=mode,child_started=child is not None,reaped=child is None or child.process.poll()is not None,group_absent=absent,natural_exit=natural,returncode=code)))
            os.close(fd)
            for s,old in previous.items():signal.signal(s,old)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in('source','runner','base','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--profile',choices=('minimal','overlay'),required=True);p.add_argument('--mode',choices=('generic4k','generic16k'),required=True);a=p.parse_args();print(json.dumps(run(a.source,a.runner,a.base,a.output,a.profile,a.mode),sort_keys=True))


def retirement(value):
    """Positive cleanup is unchanged; failure retirement is a separate predicate."""
    if value.get('status','').startswith('PASS_'):return cleanup(value)
    return F.load('_source_owned_failed_GUI_retirement',Path(__file__).resolve().parent/'failure_cleanup.py').retired(value)
