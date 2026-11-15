#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run one pinned offline host-x86 Docker TEST lifecycle; never install on host."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = load('candidate_preparation',HERE/'prepare.py')
L = load('candidate_unchanged_supervision',HERE.parent/'lifecycle.py')
C = load('candidate_host_controls',HERE/'controls.py')
CAPS = ['CHOWN','DAC_OVERRIDE','FOWNER','KILL','SETGID','SETUID']
OWNER_LABEL = 'org.cachy-asahi.handoff-test.owner'


def retain_command(record,row,save,cleanup=False):
    record['commands'].append(row)
    try:
        save()
    except OSError as error:
        if not cleanup:
            raise
        record.setdefault('cleanup_evidence_errors',[]).append(dict(type=type(error).__name__,errno=error.errno))


def cleanup_owned(command,identity,cid=None):
    """Independent cleanup budget; recover only our exact labeled/mounted create."""
    deadline = time.monotonic()+45
    def call(label,argv):
        return command(label,argv,seconds=10,deadline=deadline)
    query = ['docker','ps','-a','--no-trunc','--filter','name=^/'+identity['name']+'$','--format','{{.ID}}']
    found = call('find-only-owned-name',query).decode().splitlines()
    assert len(found) <= 1 and all(re.fullmatch('[0-9a-f]{64}',value) for value in found),'ambiguous owned container identity'
    result = dict(container_removed=False,cleanup_budget_seconds=45,owned_name=identity['name'])
    if found:
        recovered = found[0]
        assert cid is None or recovered == cid,'owned ID/name changed'
        if identity['cidfile'].exists():
            assert identity['cidfile'].read_text().strip() == recovered,'owned cidfile differs'
        row = json.loads(call('recover-owned-container-identity',['docker','container','inspect',recovered]))[0]
        assert row['Name'] == '/'+identity['name'] and row['Image'] == identity['image'],'owned name/image differs'
        assert row['Config'].get('Labels',{}).get(OWNER_LABEL) == identity['nonce'],'owned label differs'
        assert row['Config']['Cmd'] == identity['argv'] and row['Config']['Entrypoint'] == ['/usr/bin/python3'],'owned actor differs'
        assert {(m['Source'],m['Destination'],m['RW']) for m in row['Mounts']} == identity['mounts'],'owned mounts differ'
        assert len(row['Mounts']) == 3 and all(m['Type'] == 'bind' for m in row['Mounts']),'owned mount type differs'
        call('remove-only-owned-container',['docker','rm','-f',recovered])
        result.update(container_id=recovered,recovered_after_client_failure=cid is None)
    assert call('verify-owned-container-absent',query) == b'','owned container remains'
    result['container_removed'] = True
    return result


def run(artifact,output):
    assert output.is_absolute() and output.resolve() == output and not output.exists()
    output.mkdir(mode=0o700)
    nonce = secrets.token_hex(16)
    record = dict(status='RUNNING',scope='host-x86_64-private-container-TEST-only',image_id=P.IMAGE,
                  nonce=nonce,commands=[],cleanup=dict(container_removed=False),native_arm='NOT RUN',M2='NOT RUN')
    cid = None
    identity = None
    end = time.monotonic()+600
    def save():
        (output/'host-report.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    def command(label,argv,seconds=30,expected=0,deadline=None):
        cutoff = end if deadline is None else deadline
        assert time.monotonic() < cutoff,'host/cleanup deadline'
        result = L.bounded_process(argv,timeout=min(seconds,cutoff-time.monotonic()),stdout_limit=2*1024**2,
            stderr_limit=1024**2,env=dict(os.environ,LC_ALL='C'))
        row = {key:(value.decode('utf-8','replace') if isinstance(value,bytes) else value) for key,value in result.items()}
        row.update(label=label,argv=list(map(str,argv)))
        retain_command(record,row,save,cleanup=deadline is not None)
        assert result['reason'] == 'exit' and result['returncode'] == expected and result['cleanup'].get('reaped') and not result['cleanup'].get('errors'),label+': '+row['stderr'][-2000:]
        return result['stdout']
    try:
        docker_context = json.loads(command('local-docker-context',['docker','context','inspect']))
        endpoint = docker_context[0]['Endpoints']['docker']['Host']
        assert endpoint.startswith('unix://') and not os.environ.get('DOCKER_HOST'),'local Unix Docker endpoint required'
        daemon = json.loads(command('daemon-platform',['docker','info','--format','{{json .}}']))
        assert daemon['OSType'] == 'linux' and daemon['Architecture'] == 'x86_64'
        image = json.loads(command('pinned-image',['docker','image','inspect',P.IMAGE]))[0]
        assert image['Id'] == P.IMAGE and image['Os'] == 'linux' and image['Architecture'] == 'amd64'
        assert not image['Config'].get('Volumes'),'image-defined mounts refused'
        prepared = output/'prepared'
        result = json.loads(command('prepare-genuine-TEST-inputs',['/usr/bin/python3','-I','-B',str(HERE/'prepare.py'),
            '--artifact',str(artifact),'--output',str(prepared),'--nonce',nonce],seconds=180))
        assert result['private_signing_home_removed'] and result['producer_sources_removed']
        contract = C.validate_contract(json.loads((prepared/'inputs/contract.json').read_bytes()))
        evidence = output/'guest'
        evidence.mkdir(mode=0o700)
        name = 'cachy-asahi-handoff-test-'+nonce
        cidfile = output/'container-id'
        create = ['docker','create','--name',name,'--cidfile',str(cidfile),'--label',OWNER_LABEL+'='+nonce,
                  '--pull=never','--network','none','--ipc','private','--cgroupns','private',
                  '--user','0:0','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','2g','--cpus','2',
                  '--pids-limit','128','--restart','no','--stop-timeout','5',
                  '--tmpfs','/tmp:rw,nosuid,nodev,size=512m,mode=1777',
                  '--env','CACHY_ASAHI_DISPOSABLE_LIFECYCLE='+nonce,'--env','CACHY_ASAHI_IMAGE_ID='+P.IMAGE]
        for cap in CAPS:
            create += ['--cap-add',cap]
        for source,target,readonly in ((prepared/'inputs','/inputs',True),(prepared/'runner','/runner',True),(evidence,'/out',False)):
            assert not any(char in str(source) for char in ',\n\r'), 'unsafe Docker mount source'
            create += ['--mount','type=bind,source='+str(source)+',target='+target+',bind-propagation=rprivate'+(',readonly' if readonly else '')]
        argv = ['-I','-B','/runner/guest.py','--contract-sha256',result['contract_sha256']]
        create += ['--entrypoint','/usr/bin/python3',P.IMAGE,*argv]
        identity = dict(name=name,nonce=nonce,image=P.IMAGE,cidfile=cidfile,argv=argv,mounts={
            (str(prepared/'inputs'),'/inputs',False),(str(prepared/'runner'),'/runner',False),(str(evidence),'/out',True)})
        record['creation_attempted'] = name
        save()
        raw_cid = command('create-owned-container',create).decode().strip()
        assert re.fullmatch('[0-9a-f]{64}',raw_cid),'exact container ID required'
        cid = raw_cid
        container = json.loads(command('inspect-owned-container',['docker','container','inspect',cid]))[0]
        cfg,host = container['Config'],container['HostConfig']
        assert container['Id'] == cid and container['Name'] == '/'+name and container['Image'] == P.IMAGE
        assert cfg['User'] == '0:0' and cfg['Entrypoint'] == ['/usr/bin/python3'] and cfg['Cmd'] == argv
        assert host['NetworkMode'] == 'none' and host['IpcMode'] == 'private' and host['CgroupnsMode'] == 'private'
        assert host['Privileged'] is False and host['ReadonlyRootfs'] is False and host['CapDrop'] == ['ALL']
        normalized_caps = [cap.removeprefix('CAP_') for cap in host['CapAdd']]
        assert set(normalized_caps) == set(CAPS) and len(normalized_caps) == len(CAPS), 'unexpected Docker capabilities'
        assert not host.get('Devices') and not host.get('DeviceRequests') and not host.get('Binds')
        assert host['SecurityOpt'] in (['no-new-privileges'],['no-new-privileges=true'])
        assert host['Memory'] == 2*1024**3 and host['NanoCpus'] == 2*10**9 and host['PidsLimit'] == 128
        assert host['Tmpfs'] == {'/tmp':'rw,nosuid,nodev,size=512m,mode=1777'}
        assert host['AutoRemove'] is False and host['RestartPolicy']['Name'] == 'no'
        mounts = container['Mounts']
        assert len(mounts) == 3 and all(row['Type'] == 'bind' and row['Propagation'] == 'rprivate' for row in mounts)
        assert {(row['Source'],row['Destination'],row['RW']) for row in mounts} == {
            (str(prepared/'inputs'),'/inputs',False),(str(prepared/'runner'),'/runner',False),(str(evidence),'/out',True)}
        record.update(contract_sha256=result['contract_sha256'],preparation=result,container_id=cid,
                      package_sha256=contract['package']['sha256'],source_files=contract['source_files'])
        save()
        command('actual-installed-lifecycle',['docker','start','--attach',cid],seconds=330)
        terminal = json.loads(command('terminal-container-state',['docker','container','inspect',cid]))[0]['State']
        assert terminal['Running'] is False and terminal['ExitCode'] == 0 and terminal['OOMKilled'] is False
        report = json.loads((evidence/'report.json').read_bytes())
        assert report['status'] == 'PASS_HOST_X86_INSTALLED_LIFECYCLE_ONLY'
        assert report['package_transactions'] == 3 and len(report['payloads']['installed-exact39']) == 39
        assert all(row['status'] == 'PASS' for row in report['checks'])
        assert report['inventories']['baseline'] == report['inventories']['removed']
        record.update(status=report['status'],guest_check_count=len(report['checks']),
                      guest_command_count=len(report['commands']),package_transactions=3,
                      inventory_counts={key:len(rows) for key,rows in report['inventories'].items()})
    except BaseException as error:
        record.update(status='FAIL',error=str(error))
        raise
    finally:
        if identity is not None:
            try:
                record['cleanup'] = cleanup_owned(command,identity,cid)
            except BaseException as error:
                record.update(status='FAIL',cleanup_error=str(error))
        if record.get('cleanup_evidence_errors'):
            record['status'] = 'FAIL_EVIDENCE_IO'
        try:
            save()
        except OSError as error:
            record.update(status='FAIL_EVIDENCE_IO',final_evidence_error=dict(type=type(error).__name__,errno=error.errno))
            print('Container cleanup completed/assessed; evidence write failed: '+type(error).__name__,file=sys.stderr)
    assert record['cleanup']['container_removed']
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = run(args.artifact.resolve(),args.output)
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result['status'] == 'PASS_HOST_X86_INSTALLED_LIFECYCLE_ONLY' else 1)
