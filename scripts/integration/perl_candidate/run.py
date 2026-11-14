#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy pinned inputs into owned offline containers; never mount caller paths."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('existing_lifecycle',ROOT/'scripts/integration/lifecycle.py')
PROCESS=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(PROCESS)
need=PROCESS.require
BASE='sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145'
PINS={'candidate.pkg.tar.zst':'c4924603c063963ad92e1935e2f9637d3a7e21cd0e944635a450abe966d4a944',
      'old.pkg.tar.zst':'6f563b2dc3c3fb9c2d3ce5d3c3d304c6cfff29dffc75ef7ce50a2b7ce513e371',
      'db5.3.pkg.tar.zst':'abac3474e766fa8a36fcae945f5e8c8e818665fc41a56daff92db81cd176d389',
      'db5.3.pkg.tar.zst.sig':'6d924ad6b7de7e882484cd7478956df824fcd88612c70ce48a90a5c8eafba499',
      'core.db':'aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae'}


def pin(path):
    body=path.read_bytes();return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())


def validate_inspection(row,image):
    config=row['HostConfig']
    need(row['Image']==image and row['Mounts']==[] and not row['Config'].get('Volumes'), 'exact image without caller mounts/volumes required')
    need(row['Config']['User']=='0:0', 'container root identity required')
    need(config['NetworkMode']=='none' and not config['Privileged'], 'offline unprivileged container required')
    need(config['Binds'] in (None,[]) and config['Devices'] in (None,[]), 'caller binds/devices refused')
    need(config['NanoCpus']==2000000000 and config['Memory']==4294967296 and config['PidsLimit']==256, 'exact resources required')
    need(set(config['CapDrop'])=={'ALL'} and set(config['CapAdd'])=={'CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_SETGID','CAP_SETUID','CAP_SYS_CHROOT'}, 'exact capability mask required')
    need(config['SecurityOpt']==['no-new-privileges'], 'NNP required')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True);parser.add_argument('--old',type=Path,required=True)
    parser.add_argument('--prerequisites',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();output=args.output.resolve();output.mkdir(exist_ok=False)
    context=output/'context';(context/'inputs').mkdir(parents=True);(context/'support').mkdir();(context/'smoke').mkdir()
    report={'base_image':BASE,'commands':[],'containers':[],'cleanup':[],'status':'RUNNING'}
    def command(argv,timeout=30,allowed=(0,)):
        result=PROCESS.bounded_process(argv,timeout=timeout,stdout_limit=2*1024**2,stderr_limit=256*1024)
        report['commands'].append(dict(argv=list(map(str,argv)),**{k:v.decode(errors='replace') if isinstance(v,bytes) else v for k,v in result.items()}))
        (output/'host.json').write_text(json.dumps(report,indent=2)+'\n')
        if result['reason']!='exit' or result['returncode'] not in allowed:raise RuntimeError('command failed: '+str(argv))
        return result['stdout'].decode().strip()
    prerequisite=args.prerequisites.resolve()
    mapping={'candidate.pkg.tar.zst':args.candidate.resolve(),'old.pkg.tar.zst':args.old.resolve(),
        'db5.3.pkg.tar.zst':prerequisite/'db5.3-5.3.28-7-x86_64.pkg.tar.zst',
        'db5.3.pkg.tar.zst.sig':prerequisite/'db5.3-5.3.28-7-x86_64.pkg.tar.zst.sig','core.db':prerequisite/'core-20261108.db'}
    for name,path in mapping.items():
        need(path.is_file() and not path.is_symlink() and pin(path)['sha256']==PINS[name],name)
        shutil.copyfile(path,context/'inputs'/name)
    support={'lifecycle.py':'scripts/integration/lifecycle.py','repository.py':'scripts/integration/repository.py',
        'virtual_common.py':'scripts/virtual/common.py','glibc_abi.py':'scripts/ci/glibc-owned-rebuild/abi.py'}
    for name,path in support.items():shutil.copyfile(ROOT/path,context/'support'/name)
    for name in ['test_staged_commands.py','stage_commands.py','check_config.pl','provides.txt']:
        shutil.copyfile(ROOT/'packages/port/perl5423-source-candidate'/name,context/'smoke'/name)
    shutil.copyfile(Path(__file__).with_name('container.py'),context/'container.py')
    manifest={'inputs':{n:pin(context/'inputs'/n) for n in mapping},'support':{n:pin(context/'support'/n) for n in support},
              'prerequisite':json.loads((prerequisite/'prerequisite.json').read_bytes())}
    (context/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    owned=[];prepared_image=None
    def create(image,prepare=False):
        argv=['docker','create','--user','0:0','--network','none','--cpus','2','--memory','4g','--pids-limit','256',
            '--cap-drop','ALL','--security-opt','no-new-privileges']
        for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID','SYS_CHROOT'):argv+=['--cap-add',cap]
        # The fixed inert PID1 keeps the daemon-owned rootfs mounted while
        # copying inputs/output; stopped-rootfs docker cp has returned EBUSY.
        argv+=['--env','CACHY_ASAHI_PERL_TEST=1','--entrypoint','/usr/bin/sleep',image,'300']
        ident=command(argv);owned.append(ident);report['containers'].append(ident)
        row=json.loads(command(['docker','inspect',ident]))[0];validate_inspection(row,image)
        (output/(('prepare' if prepare else 'runtime')+'-inspection.json')).write_text(json.dumps(row,indent=2)+'\n')
        command(['docker','start',ident])
        return ident
    try:
        before=json.loads(command(['docker','image','inspect',BASE]))[0]
        need(before['Id']==BASE and not before['Config'].get('Volumes'), 'pinned mount-free base required')
        container=create(BASE,True)
        command(['docker','cp',str(context),container+':/opt/perl-candidate'])
        command(['docker','exec',container,'/usr/bin/python3','-I','-B','/opt/perl-candidate/container.py','--prepare'],timeout=180,allowed=(0,1))
        command(['docker','cp',container+':/tmp/perl-result',str(output/'prepare')])
        need(json.loads((output/'prepare/result.json').read_bytes())['status']=='PASS_FROZEN_SIGNED_PREREQUISITE', 'prerequisite preparation failed')
        prepared_image=command(['docker','commit',container])
        runtime=create(prepared_image)
        command(['docker','exec',runtime,'/usr/bin/python3','-I','-B','/opt/perl-candidate/container.py'],timeout=180,allowed=(0,1))
        command(['docker','cp',runtime+':/tmp/perl-result',str(output/'runtime')])
        result=json.loads((output/'runtime/result.json').read_bytes())
        report.update(status=result['status'],prepared_image=prepared_image)
        need(result['status']=='PASS_TEST_SIGNED_X86_64_ALPM_COMPONENT',result.get('failure'))
    except BaseException as error:
        report.update(status='FAIL',failure=type(error).__name__+': '+str(error))
        raise
    finally:
        active_error=sys.exc_info()[0] is not None
        cleanup_failed=False
        for ident in reversed(owned):
            try:
                command(['docker','rm','--force',ident])
                need(command(['docker','container','ls','--all','--quiet','--no-trunc','--filter','id='+ident])=='', 'owned container remains')
                report['cleanup'].append(dict(container=ident,removed=True,absence_verified=True))
            except BaseException as error:
                cleanup_failed=True;report['cleanup'].append(dict(container=ident,removed=False,error=str(error)))
        if prepared_image:
            try:
                command(['docker','image','rm',prepared_image])
                need(json.loads(command(['docker','image','inspect',prepared_image],allowed=(1,)))==[], 'owned image remains')
                report['prepared_image_removed']=True
            except BaseException:cleanup_failed=True;report['prepared_image_removed']=False
        if cleanup_failed:report['status']='FAIL_OWNED_CLEANUP_NOT_ESTABLISHED'
        (output/'host.json').write_text(json.dumps(report,indent=2)+'\n')
        if cleanup_failed and not active_error:raise RuntimeError('owned cleanup not established')


if __name__=='__main__':main()
