#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite producer/profile owner and capped original export; no implicit GUI admission."""
import argparse,fcntl,json,os,re,shutil,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import candidates as C
import assets
import run
import invocation
HERE=Path(__file__).resolve().parent
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing')
SUCCESS='PASS_WELCOME5_DNS_SINGLE_PROFILE_METADATA_PIXELS_PENDING_ROOT_REVIEW'

def save(path,value):
    path=Path(path);temp=path.with_suffix('.partial')
    with temp.open('x')as stream:json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    temp.replace(path)
def manifest(source):
    C.verify_source(source);return C.read(HERE/'source-manifest.json')
def prove(source,profile,environment,runtime=None):
    policy=C.selection(source);C.need(profile in ('minimal','overlay'),'one independent profile required')
    C.need(runtime is not None,'explicit proof-bound runtime path required')
    runtime=invocation.absolute(str(runtime));C.need(runtime.name=='welcome5-runtime','fixed runtime path required')
    old=C.load('held_native_source_proof',source/'scripts/ci/welcome-native/ci/caller.py')
    value=old.prove(source,manifest(source),environment)
    value.update(profile=profile,manifest_sha256=C.digest(HERE/'source-manifest.json'),scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',source_path=str(source),runtime_path=str(runtime),carrier_source=policy['inputs']['welcome5']['carrier_source'])
    value['renewal_source']=C.load('welcome5_gui_renewal_proof',HERE/'renewal.py').selection(source)['carrier_source']
    return value

def binding(source,profile,proof):
    manifest(source);C.selection(source)
    C.need(proof.get('source_path')==str(source)and str(invocation.absolute(proof['runtime_path']))==proof['runtime_path'],'proof-bound actual source/runtime path differs')
    C.need(proof.get('status')=='SOURCE_PROOF_PASS'and proof.get('profile')==profile and proof.get('manifest_sha256')==C.digest(HERE/'source-manifest.json')and
        re.fullmatch('[0-9a-f]{16}',proof.get('job_token')or'')and proof.get('scope')=='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE','source/profile/owner proof differs')

def cleanup(source,profile,proof,base,runtime,out):
    binding(source,profile,proof);C.need(proof['runtime_path']==str(runtime),'actual cleanup runtime differs from proof');value=dict(status='FAIL',runtime='UNKNOWN',producer='NOT_RETIRED')
    try:
        if runtime.exists():
            lease=os.open(runtime/'runtime.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
                terminal=C.read(runtime/'runtime-terminal.json');C.need(terminal.get('reaped')is True and terminal.get('group_absent')is True,'runtime child/group not retired; producer preserved')
                if terminal.get('child_started')is True:
                    gui=C.read(runtime/'runtime/runtime.json');validate_cleanup(gui);value['runtime']=gui['cleanup']
                else:value['runtime']='NO_VM_ACTOR_STARTED'
            finally:os.close(lease)
        else:value['runtime']='NOT_STARTED'
        if (base/'report.json').exists():
            import subprocess
            done=subprocess.run([sys.executable,'-I','-B',str(source/'scripts/ci/maintained_desktop574.py'),'cleanup','--inputs',str(source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(base),'--job-token',proof['job_token']],capture_output=True,timeout=240)
            C.need(done.returncode==0 and len(done.stdout)+len(done.stderr)<=1024**2,'original producer cleanup failed')
            original=C.read(base/'report.json');value['producer']=original['owned_cleanup'];C.need(value['producer']['status']=='PASS','producer absence not verified')
        else:value['producer']='NOT_STARTED'
        value['status']='PASS_RUNTIME_RETIRED_BEFORE_ORIGINAL_PRODUCER'
    except Exception as error:value.update(error_type=type(error).__name__,error=str(error)[:512])
    save(out,value);return value

def validate_cleanup(gui):
    rows=gui.get('cleanup');C.need(type(rows)is list and len(rows)==14 and all(r.get('exit',0)==0 and 'error'not in r for r in rows)and
        sum(r.get('guest_disk_removed')is True for r in rows)==1 and gui.get('base_reference_cleanup',{}).get('ok')is True,'all original14 VM/image/workspace cleanup guards required')

def retain(source,profile,proof_path,base,runtime,cleanup_path,out):
    C.need(not out.exists(),'fresh export required');out.mkdir(mode=0o700)
    value=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],total_bytes=0,profile=profile,scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',GUI='NOT_ACCEPTED',hardware='NOT_RUN',current606='NOT_RUN',visual_review='NOT_RUN')
    def copy(path,name,cap,required=True):
        if not required and not path.exists():return
        try:
            info=C.regular(path,cap);C.need(value['total_bytes']+info.st_size<=512*1024**2,'original total export limit')
            target=out/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            value['files'][name]=dict(bytes=info.st_size,sha256=C.digest(target));value['total_bytes']+=info.st_size
        except Exception as error:value['errors'].append(name+': '+str(error)[:256])
    copy(proof_path,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)
    for name in ('report.json','installed-packages.lock'):copy(base/name,'base/'+name,1024**2)
    for name in ('result.json','runtime-terminal.json','profile-invocation.json'):copy(runtime/name,name,2*1024**2)
    copy(runtime/'runtime-child.log','runtime-child.log',16*1024**2,False)
    gui=runtime/'runtime';runner=runtime/'runner'
    for name,cap in (('runtime.json',16*1024**2),('guest.log',8*1024**2),('events.log',8*1024**2),('configuration.log',16*1024**2),('package-build.log',16*1024**2),('base-reference.log',16*1024**2),('runtime-image.log',16*1024**2),('fixture.log',16*1024**2),('config/desktop/desktop.json',2*1024**2),('package/provenance.json',2*1024**2),('package/validation.json',2*1024**2),('package/expected-packages.lock',256*1024)):
        copy(gui/name,'gui/'+name,cap,required=name in ('runtime.json','guest.log','events.log'))
    for i in range(24):copy(gui/('config/desktop/command-'+str(i)+'.txt'),'gui/config/desktop/command-'+str(i)+'.txt',1024**2,False)
    for view in VIEWS:copy(gui/'frames'/(profile+'-'+view+'.ppm'),'frames/'+profile+'-'+view+'.ppm',8*1024**2)
    if runner.is_dir():
        for path in sorted(runner.iterdir()):
            if path.is_file():copy(path,'generated/'+path.name,2*1024**2)
        products=runner/'candidates'
        if products.is_dir():
            for path in sorted(products.iterdir()):copy(path,'inputs/'+path.name,8*1024**2)
    for path in HERE.iterdir():
        if path.is_file():copy(path,'source/'+path.name,2*1024**2)
    try:
        proof=C.read(proof_path);binding(source,profile,proof);ordered=C.read(cleanup_path);original=C.read(base/'report.json');gui_result=C.read(gui/'runtime.json');result=C.read(runtime/'result.json')
        C.need(ordered['status']=='PASS_RUNTIME_RETIRED_BEFORE_ORIGINAL_PRODUCER'and ordered['producer']==original['owned_cleanup']and
            original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and original['ownership']['token']==proof['job_token']and
            original['owned_cleanup']['status']=='PASS'and original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True)and original['owned_cleanup']['probe']['absence_verified']is True,'original producer source/ownership/cleanup required')
        validate_cleanup(gui_result)
        C.need(proof['runtime_path']==str(runtime),'actual retained runtime path differs')
        invocation.validate(C.read(runtime/'profile-invocation.json'),proof,invocation.pin(proof_path),invocation.pin(HERE/'source-manifest.json'),invocation.pin(runner/'runner-proof.json'))
        C.need(result['status']=='PASS_WELCOME5_DNS_GUI_METADATA_PIXELS_PENDING_REVIEW'and gui_result['status']=='PASS_INSTALLED_WELCOME_SINGLE_PROFILE_GUI_METADATA'and
            gui_result['runtime_package_count']==595 and gui_result['configuration']=='desktop-container-verifier-pass'and gui_result['base_image']==original['image'],'actual GUI composition/result differs')
        # Import only our source-regenerated trusted runner, never retained export code.
        old=list(sys.path);sys.path.insert(0,str(runner))
        try:
            validator=C.load('source_regenerated_GUI_export_contract',runner/'contract.py');verified=validator.verify_result(gui_result['events'],C.read(runner/'candidate-lock.json'))
        finally:sys.path[:]=old
        C.need(verified==gui_result['gui_contract']==result['gui'],'complete original+DNS semantic replay differs')
        image=C.load('held_PPM_checks',source/'scripts/ci/desktop574_runtime.py')
        expected={profile+'-'+v for v in VIEWS};C.need(set(gui_result['frames'])==expected,'exact13 original capture rows required')
        for name in expected:C.need(image.ppm(out/'frames'/(name+'.ppm'))==gui_result['frames'][name],'complete original PPM identity differs')
        C.need(not value['errors'],'closed export incomplete');value.update(status=SUCCESS,GUI='NATIVE_METADATA_PASS_PIXELS_PENDING_REVIEW',contract=verified)
    except Exception as error:value['errors'].append(str(error)[:512])
    save(out/'retention.json',value);return value

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','inputs','run','cleanup','retain'));p.add_argument('--profile',choices=('minimal','overlay'),required=True)
    for name in ('source','proof','base','runtime','assets','public','carrier','renewal','cleanup','output'):p.add_argument('--'+name,type=Path)
    a=p.parse_args();source=a.source.absolute()
    if a.phase=='proof':
        value=prove(source,a.profile,os.environ,a.runtime.absolute()if a.runtime is not None else None);save(a.proof,value)
        with open(os.environ['GITHUB_OUTPUT'],'a')as stream:stream.write('job_token='+value['job_token']+'\ncarrier_source='+value['carrier_source']+'\nrenewal_source='+value['renewal_source']+'\n')
    else:
        proof=C.read(a.proof);binding(source,a.profile,proof)
        if a.phase=='inputs':value=assets.prepare(source,a.public.absolute(),a.carrier.absolute(),a.output.absolute(),a.renewal.absolute());save(a.output/'provenance.json',value)
        elif a.phase=='run':
            C.need(proof['runtime_path']==str(a.runtime.absolute()),'actual run runtime differs from source proof')
            return run.execute(source,a.base.absolute(),a.assets.absolute(),a.runtime.absolute(),a.profile,
                dict(argv=list(sys.argv[1:]),proof=proof,source_proof=invocation.pin(a.proof),source_manifest=invocation.pin(HERE/'source-manifest.json')))
        elif a.phase=='cleanup':
            C.need(proof['runtime_path']==str(a.runtime.absolute()),'actual cleanup runtime differs from source proof')
            value=cleanup(source,a.profile,proof,a.base.absolute(),a.runtime.absolute(),a.output.absolute())
        else:value=retain(source,a.profile,a.proof,a.base.absolute(),a.runtime.absolute(),a.cleanup,a.output.absolute())
    print(json.dumps(value,sort_keys=True,indent=2));return int(value['status']not in ('SOURCE_PROOF_PASS','PREPARED_PUBLIC_NATIVE_INPUTS_ONLY','PASS_RUNTIME_RETIRED_BEFORE_ORIGINAL_PRODUCER',SUCCESS))
if __name__=='__main__':raise SystemExit(main())
