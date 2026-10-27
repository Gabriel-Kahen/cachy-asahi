#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One registered consumer using held Welcome Docker policy and Setup8 ownership."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C


def execute(root,base,output,proof_path):
    C.need(os.getuid()==os.geteuid()>0 and platform.machine()=='aarch64' and not any(n.startswith('DOCKER_') for n in os.environ),'ordinary local native ARM runner required')
    proof=json.loads(C.read(proof_path));m=C.verify(root,proof['manifest_sha256'])
    C.need(not output.exists() and not output.is_relative_to(root) and not output.is_relative_to(base),'fresh separate consumer output required')
    before=json.loads(C.read(base/'report.json'));image=C.read(base/'image-id').decode().strip()
    C.need(before['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and before['image']==image and re.fullmatch('sha256:[0-9a-f]{64}',image),'fresh owned original574 image required')
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',HOME=str(base/'home'),TZ='UTC')
    def capture(argv):
        r=subprocess.run(argv,env=env,capture_output=True,timeout=30);C.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<1024**2,'bounded local daemon observation failed');return r.stdout.decode().strip()
    C.need(capture(['/usr/bin/docker','context','show'])=='default' and json.loads(capture(['/usr/bin/docker','context','inspect','default']))[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock' and capture(['/usr/bin/docker','info','--format','{{.Architecture}}']) in ('aarch64','arm64') and capture(['/usr/bin/docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',image])=='linux/arm64','local native daemon/image required')
    wanted=''.join(r['name']+' '+r['version']+'\n' for r in sorted(json.loads(C.read(root/'scripts/ci/maintained-desktop574-inputs.json'))['packages'],key=lambda r:r['name']))
    C.need(C.read(base/'installed-packages.lock').decode()==wanted,'exact574 installed lock differs')
    output.mkdir(mode=0o755);lease=os.open(output/'consumer.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
    name='cachy-asahi-product-lifecycle-'+os.urandom(16).hex()
    argv,label=C.held_docker(root,image,name,output)
    # Accepted helper emits 'docker'; bind it to the same observed local client.
    argv[0]='/usr/bin/docker'
    argv += ['--label='+label+'='+proof['consumer_token'],'--env=CACHY_SETUP8_REAL_SHELL_CONTAINER=1',
        '--mount','type=bind,src='+str(root)+',dst=/source,readonly',
        '--entrypoint=/usr/bin/python3',image,'-I','-B','/source/scripts/ci/setup8-real-shells-native/container.py',
        '--source','/source','--output','/out/native','--context-sha256',m['held_context_sha256']]
    C.save(output/'owner.json',dict(schema_version=1,token=proof['consumer_token'],image=image,label=label,containers=[name]))
    C.save(output/'command.json',dict(argv=argv,timeout_seconds=2100,resources=dict(memory='3g',cpus=4,pids=256,tmpfs='/tmp:rw,nosuid,nodev,exec,size=2g'),readonly_mounts=['/source'],writable_mounts=['/out'],actors=1,actual=None))
    status='FAIL'
    try:
        with (output/'lifecycle.stdout').open('wb') as stdout,(output/'lifecycle.stderr').open('wb') as stderr:
            r=subprocess.run(argv,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=2050)
        C.need(r.returncode==0,'native shell consumer failed')
        result=json.loads(C.read(output/'native/native-report.json'));validate(result)
        status='PASS_FINITE_NATIVE_REAL_SHELLS_PENDING_ORDERED_RETIREMENT'
    finally:
        C.save(output/'report.json',dict(status=status,image=image,ownership_token=proof['consumer_token'],base_lock_sha256=C.digest(base/'installed-packages.lock'),actual=None,physical_M2='NOT_RUN',release='NOT_ADMITTED'))
        os.close(lease)
    return 0


def validate(value):
    C.need(value['status']=='PASS_FINITE_NATIVE_SETUP8_REAL_SHELL_COMPOSITION' and value['machine']=='aarch64' and value['actual_page_size']>0 and len(value['builds'])==8,'native finite result/builds differ')
    C.need([r['phase'] for r in value['events']]==['install','repeat-install','remove','reinstall','final-remove'],'five actual nine-package ALPM transitions required')
    report=value['trial'];C.need(report['status']=='PASS_SETUP8_REAL_SHELL_COMPOSITION' and report['package_installation']=='NATIVE_ALPM_INSTALLED' and len(report['cases'])==14 and set(report['cases'].values())=={'PASS'} and len(report['cli_observations'])==60 and len(report['probes'])==19 and report['actual_sigkill_returncode']==-9,'actual ordinary full14/60/19 shell observations required')
    C.need(sum(p.get('startup_file_automatically_loaded',False) for p in report['probes'])==12 and all(p['status']=='PASS' for p in report['probes']) and value['reinstall']['status']=='PASS_SETUP8_REAL_SHELL_REINSTALL' and value['protected_configuration_preserved'] is True,'shell startup/preservation/reinstall differs')
    C.need(value['physical_M2']=='NOT_RUN' and value['release']=='NOT_ADMITTED' and value['trust']=='UNSIGNED_LOCAL_TEST_PACKAGES','native development scope differs')


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('source','base','output','proof'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();raise SystemExit(execute(*(C.safe(getattr(a,n).absolute()) for n in ('source','base','output','proof'))))
