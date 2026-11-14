#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit ordinary-user launcher for this finite, offline TEST lifecycle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
BASE='cachy-asahi-nm-source-final:20261114'
BASE_ID='sha256:7052baf57a6eec068371ffdb2f9670ef69bd5ce11ee3ba67f705b724dc8a53d5'
NAMES={'networkmanager','libnm','nm-cloud-setup','networkmanager-docs'}


def sha(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def inputs(directory):
    validation=json.loads((REPO/'packages/port/networkmanager-source-candidate/validation.json').read_text())
    rows=validation['host_archive_facts'];assert {r['pkgname']for r in rows}==NAMES and len(rows)==4
    for row in rows:
        ref=row['archive'];assert Path(ref['name']).name==ref['name']
        p=directory/ref['name'];assert p.is_file()and not p.is_symlink()
        assert p.stat().st_size==ref['bytes']and sha(p)==ref['sha256'],ref['name']
    return [row['archive']for row in rows]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-disposable-x86-TEST-journey',action='store_true')
    p.add_argument('--archives',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if not args.allow_disposable_x86_TEST_journey:p.error('explicit TEST-only opt-in required')
    if not __debug__:p.error('optimized Python refused; assertions are acceptance checks')
    if os.geteuid()==0:p.error('ordinary host user required; never sudo')
    refs=inputs(args.archives.resolve(strict=True));out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    report={'schema_version':1,'status':'HOLD','base_image_id':BASE_ID,'host_installs':False,'source_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),'native_ARM':'NOT RUN','M2':'NOT RUN','release_acceptance':'HOLD'}
    nonce=secrets.token_hex(8);tag='cachy-asahi-nm-journey:'+nonce;container='cachy-asahi-nm-journey-'+nonce;created=False
    def command(name,argv,timeout=60):
        with (out/(name+'.log')).open('wb')as log:
            result=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        assert result.returncode==0,(name,result.returncode)
    try:
        observed=json.loads(subprocess.check_output(['docker','image','inspect',BASE],text=True))[0]
        assert observed['Id']==BASE_ID,'exact retained prerequisite image required; no pull/install fallback'
        with tempfile.TemporaryDirectory(prefix='cachy-asahi-nm-journey-')as temporary:
            context=Path(temporary);data=context/'input';data.mkdir()
            for ref in refs:shutil.copyfile(args.archives/ref['name'],data/ref['name'])
            for source in [HERE/'journey.py',REPO/'scripts/integration/repository.py']:shutil.copyfile(source,data/source.name)
            report['source_pins']={s.name:sha(s)for s in [HERE/'journey.py',HERE/'run.py',REPO/'scripts/integration/repository.py']}
            (data/'contract.json').write_text(json.dumps({'archives':refs,'source_commit':report['source_commit'],'source_pins':report['source_pins']},indent=2)+'\n')
            dockerfile='\n'.join(['FROM '+BASE,'USER 0:0','COPY input/ /opt/nm-journey-input/','RUN find /opt/nm-journey-input -type f -exec chmod 0444 {} + && chmod 0555 /opt/nm-journey-input && install -d -m700 /scratch /test-home /out','ENV CACHY_ASAHI_NM_TEST_CONTAINER=1','ENTRYPOINT ["/usr/bin/python3","-I","-B","/opt/nm-journey-input/journey.py","--allow-disposable-x86-TEST-journey"]',''])
            (context/'Dockerfile').write_text(dockerfile)
            command('image-build',['docker','build','--network=none','--pull=false','--tag',tag,str(context)],180)
            after=json.loads(subprocess.check_output(['docker','image','inspect',BASE],text=True))[0]
            built=json.loads(subprocess.check_output(['docker','image','inspect',tag],text=True))[0]
            assert after['Id']==BASE_ID and built['RootFS']['Layers'][:len(observed['RootFS']['Layers'])]==observed['RootFS']['Layers']
        command('create',['docker','create','--name',container,'--init','--network=none','--cap-drop=ALL',
                *[v for cap in ['CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID','SYS_CHROOT']for v in ['--cap-add',cap]],
                '--security-opt=no-new-privileges','--cpus=2','--memory=4g','--pids-limit=256',tag]);created=True
        observed=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
        assert observed['Mounts']==[] and observed['HostConfig']['NetworkMode']=='none'
        assert observed['HostConfig']['Privileged']is False
        hc=observed['HostConfig'];assert hc['NanoCpus']==2_000_000_000 and hc['Memory']==4*1024**3 and hc['PidsLimit']==256
        report['runtime']={key:hc[key]for key in ['NetworkMode','NanoCpus','Memory','PidsLimit','Privileged','SecurityOpt','CapAdd','CapDrop','Devices']}
        report['caller_mounts']=observed['Mounts']
        report['container_id']=observed['Id'];report['journey_image_id']=observed['Image']
        try:command('journey',['docker','start','--attach',container],520)
        finally:
            command('export-public-report',['docker','cp',container+':/out',str(out/'guest')])
            if (out/'guest/report.json').exists():report['guest']=json.loads((out/'guest/report.json').read_text())
        state=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]['State']
        assert state['ExitCode']==0 and not state['OOMKilled'],state
        assert report['guest']['status']=='PASS_X86_TEST_REPOSITORY_LIFECYCLE_ONLY'
        assert report['guest']['test_private_state_removed']is True
        report['status']='PASS_X86_TEST_REPOSITORY_LIFECYCLE_ONLY'
    except BaseException as error:
        report['failure']={'category':type(error).__name__,'message':str(error)[:2048]}
    finally:
        if created:
            cleanup=subprocess.run(['docker','rm','--force',container],capture_output=True,timeout=30)
            report['owned_container_removed']=cleanup.returncode==0
            if cleanup.returncode:report['status']='HOLD_CONTAINER_CLEANUP_FAILURE'
        cleanup_image=subprocess.run(['docker','image','rm',tag],capture_output=True,timeout=30)
        report['owned_image_tag_removed']=cleanup_image.returncode==0
        if created and cleanup_image.returncode:report['status']='HOLD_IMAGE_CLEANUP_FAILURE'
        (out/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'report':str(out/'report.json'),'failure':report.get('failure')}))
    return 0 if report['status']=='PASS_X86_TEST_REPOSITORY_LIFECYCLE_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())
