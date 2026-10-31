# SPDX-License-Identifier: MIT
"""Fabricated positive lifecycle DATA only; never a native result or actor."""
import base64
import gzip
import os
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
OLD=Path(os.environ['IMAGE_TOOLS_NATIVE_SOURCE']).resolve()
FIXTURES=HERE/'fixtures'
FIXTURE_PINS={'native-root.ext4.gz':(16988,'a27c4a93d355dc676092906fffb1cb236725cd4bf10f48aaf4efe3a223029946'),'inventory.json':(2535,'6e1e13193d1b1f444ebe6d785b2922eb56ba539ccd21f0fab1d8ac3828bb3e6a'),'fsck.log':(287,'f63edc02dc242a3399eb42270700dd501dc9ab6f6aa6d25e9477258c6c044621')}
def fixture_bytes(name):
    raw=(FIXTURES/name).read_bytes();expected=FIXTURE_PINS[name]
    assert len(raw)==expected[0] and hashlib.sha256(raw).hexdigest()==expected[1],name
    if name=='native-root.ext4.gz':
        raw=gzip.decompress(raw)
        assert len(raw)==16777216 and hashlib.sha256(raw).hexdigest()=='e020c3958a838df27ab72528bce57d97aea988ad10b1cec5dd633d59d9ebf4a2'
    return raw
PREFIX='journey/image-alpm-v1/'
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def fixture(R):
    contract_raw=(OLD/'native/image-contract-v1.json').read_bytes();contract=json.loads(contract_raw)
    base=(OLD/'native/expected349.lock').read_bytes();version='0.1.0-1';fixed=Path(contract['invocation']['source']).parent
    private=Path('/tmp/image-tools-test-SYNTHETIC');config=str(private/'pacman.conf');trust=private/'trust';data={};commands=[]
    state=dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[])
    def command(step,argv,raw=b'SYNTHETIC command DATA only\n',expected=0):
        row=dict(step=step,argv=list(map(str,argv)),cwd=str(private),expected=expected,success=True,
            log='%03d-%s.log'%(len(commands),step),log_pin=pin(raw),supervision=dict(state,exit=1 if expected=='nonzero' else expected))
        commands.append(row);data[PREFIX+row['log']]=raw;return row
    report=dict(schema_version=1,operation=R.OPERATION,status=R.PASS,source_map_sha256='a'*64,version=version,first_failure=None,
        contract=pin(contract_raw),stages=['build-a','build-b','compare','sign','install','commands-system','commands-moved','remove','restore','cleanup'],
        commands=commands,builds={},inventory={},payloads={},signatures={},business={},signature_policy=dict(SigLevel='Required',LocalFileSigLevel='Required'),
        payload_absent=True,private_roots_absent=True,exports_preserved=True,exports_before=dict(files=1,**pin(b'SYNTHETIC user evidence')),
        cleanup=dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[]))
    report['exports_after']=dict(report['exports_before']);snapshot=dict(files=1,**pin(b'SYNTHETIC restored system state'))
    report['restore']={name:dict(before=snapshot,after=snapshot,unchanged=True) for name in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')}
    def inventory(key,current):
        body=b''.join(sorted(base.splitlines(keepends=True)+([] if current is None else [('cachy-asahi-image-tools '+current+'\n').encode()])))
        command(key+'-inventory',['/usr/bin/pacman','-Q'],body);report['inventory'][key]=dict(**pin(body),count=349 if current is None else 350,version=current)
    inventory('baseline',None);reasons={'explicit':b'SYNTHETIC-explicit\n','dependencies':b'SYNTHETIC-dependency\n'}
    report['install_reasons_before']={k:pin(raw) for k,raw in reasons.items()};report['install_reasons_after']=dict(report['install_reasons_before'])
    for key,raw in reasons.items():command('baseline-reasons-'+key,['/usr/bin/pacman','-Qqe' if key=='explicit' else '-Qqd'],raw)
    archive_pin=pin(b'SYNTHETIC native package archive bytes NOT BUILT');buildinfo=('format = 2\npkgname = cachy-asahi-image-tools\npkgver = '+version+'\npkgarch = any\npkgbuild_sha256sum = '+contract['recipe']['source_files']['PKGBUILD']['sha256']+'\n'+''.join('installed = '+row+'\n' for row in contract['buildinfo_installed']))
    comparison=dict(status='PASS_EXACT_NATIVE_BUILD_PAIR',archive=archive_pin,builds={},payload_files=66,base_inventory_count=349,source_map_sha256='a'*64,
        equality=dict(archive=True,payload=True,pkginfo=True,buildinfo=True,mtree=True),buildinfo_text=buildinfo)
    report['comparison']=comparison
    for i,label in enumerate(('a','b')):
        raw=b'Starting check()\n'+b''.join(('Ran '+str(n)+' tests in 0.01s\n\nOK\n').encode() for n in (29,4,35,13))
        command('build-'+label,['/usr/bin/runuser','-u','alarm','--','/usr/bin/makepkg','--cleanbuild','--nodeps','--config',contract['invocation']['source']+'/'+contract['makepkg_config']['path']],raw)
        report['builds'][label]=dict(check_invoked=True,check_tests=81,check_policy='POSITIVE_CHECK_NO_NOCHECK',recipe_sha256=contract['recipe']['source_files']['PKGBUILD']['sha256'],build_directory=dict(identity=dict(device=1,inode=i+1)),archive=dict(filename=contract['recipe']['archive'],**archive_pin))
        comparison['builds'][label]=dict(archive=archive_pin)
    signer='A'*40;status='[GNUPG:] VALIDSIG '+signer+' 2026-10-28 1700000000 0 4 0 22 10 00 '+signer+'\n[GNUPG:] TRUST_ULTIMATE\n';report['fingerprint']=signer
    for label in ('a','b'):
        command('verify-'+label,['/usr/bin/gpg','--homedir',trust,'--status-fd=1','--verify','SYNTHETIC.sig','SYNTHETIC.pkg'],status.encode())
        signature=b'SYNTHETIC detached signature DATA NOT CRYPTOGRAPHY';report['signatures'][label]=dict(status=status,signature=dict(**pin(signature),base64=base64.b64encode(signature).decode()))
    config_raw=('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n').encode()
    command('required-signature-config',['/usr/bin/cat',config],config_raw);report['signature_config']=pin(config_raw)
    command('install',['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-U',fixed/'build-inputs/a'/contract['recipe']['archive']]);inventory('installed',version)
    payload=contract['recipe']['payload_files'];report['payloads']['installed']=dict(version=version,count=66,verified=True,stale_absent=True,files={name:{k:row[k] for k in ('bytes','sha256','mode')} for name,row in payload.items()})
    for name in payload:command('owner-cachy-asahi-image-tools',['/usr/bin/pacman','--config',config,'-Qoq','/'+name],b'cachy-asahi-image-tools\n')
    image=fixture_bytes('native-root.ext4.gz');inventory_raw=fixture_bytes('inventory.json');fsck=fixture_bytes('fsck.log')
    for name,raw,key in [('native-root.ext4',image,'native_image'),('native-inventory.json',inventory_raw,'native_inventory'),('native-fsck.log',fsck,'native_fsck')]:data[PREFIX+name]=raw;report[key]=pin(raw)
    image_row=dict(**pin(image),uuid='725346d2-f127-47bc-b464-9dd46155e8d6',hash_seed='725346d2-f127-47bc-b464-9dd46155e8d6')
    controls=[('plan',0),('assemble',0),('verify',0),('resume',0),('existing-output-refusal',1),('wrong-receipt-refusal',1),('unsigned-kind-refusal',1),('input-pin-refusal',1),('genuine-signature-refusal',1),('incomplete-resume-refusal',1)]
    for label in ('system','moved'):
        diagnostic='diagnostics/'+label+'/';records=[];receipt='c'*64
        for index,(name,expected) in enumerate(controls,1):
            stem='%02d-%s'%(index,name);records.append(dict(name=name,expected_exit=expected,actual_exit=expected,log=stem))
            raw=encoded(dict(status='VERIFIED_COMPLETED_PRISTINE_PAYLOAD_IMAGE',actors_rerun=False,receipt_sha256=receipt)) if name in ('verify','resume') else b'{}\n'
            data[PREFIX+diagnostic+'control-commands/'+stem+'.log']=raw
            data[PREFIX+diagnostic+'control-commands/'+stem+'.json']=encoded(dict(supervision=dict(state,exit=expected),**pin(raw)))
        profiles={}
        for filename,key in [('tool_pins.json','tools'),('metadata_pins.json','metadata')]:
            raw=encoded(dict(schema_version=2,python=dict(version=[3,14,8])));data[PREFIX+diagnostic+'good-inputs/'+filename]=raw;profiles[key]=pin(raw)
        encoded_result=dict(status='HOST_ROOTLESS_EXT4_BUILT_AND_READ_BACK',image=image_row,host=dict(machine='aarch64'),calls=[dict(exit_code=0)])
        data[PREFIX+diagnostic+'assembled/pipeline/encoded/result.json']=encoded(encoded_result)
        report['business'][label]=dict(status='PASS_NATIVE_INSTALLED_SYNTHETIC_IMAGE_CONTROLS',native_architecture='aarch64',native_page_bytes=4096,frozen_harness_native_boundary='NOT_RUN',no_actor_verify_resume=True,positive_artifacts_preserved=True,payload_nodes=8,source_harness=dict(sha256=R.PRODUCERS['native/image_synthetic_v1.py']),commands=records,receipt_sha256=receipt,native_tool_profiles=profiles,image=image_row)
        command(label+'-synthetic',['/usr/bin/runuser','-u','alarm','--','/usr/bin/python3',contract['synthetic_harness']['path']])
    command('remove',['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-R','cachy-asahi-image-tools']);inventory('removed',None)
    for key,raw in reasons.items():command('restored-reasons-'+key,['/usr/bin/pacman','-Qqe' if key=='explicit' else '-Qqd'],raw)
    # Synthetic records for the strict TEST-home cleanup reader; never actors.
    for home in ('signing','trust'):
        command('retire-'+home,['/usr/bin/gpgconf','--homedir',private/home,'--kill','all'],b'',expected=0)
        commands[-1]['channels']='stdout+stderr combined in pipe order'
        command('no-autostart-'+home,['/usr/bin/gpg-connect-agent','--homedir',private/home,'--no-autostart','/bye'],
                b'gpg-connect-agent: no gpg-agent running in this session\n',expected=0)
        commands[-1]['channels']='stdout+stderr combined in pipe order'
    report['diagnostic_files']={name[len(PREFIX):]:pin(raw) for name,raw in data.items() if name.startswith(PREFIX+'diagnostics/')}
    guest=dict(status=R.PASS,operation=R.OPERATION,source_map_sha256='a'*64,architecture='aarch64',page_size=4096,packages=pin(base),physical_M2='NOT_RUN',native_16K='NOT_QUALIFIED',system_install='IMAGE_STAGE_ALPM_ONLY',release='NOT_ADMITTED',image_alpm=report)
    data[PREFIX+'result.json']=encoded(report);data[PREFIX+'commands.json']=encoded(commands);data['journey/result.json']=encoded(guest)
    binding=dict(source='1'*40,ref='refs/heads/codex/SYNTHETIC-image-positive',run='42',attempt=1);binding['token']=hashlib.sha256((binding['source']+':'+binding['ref']+':'+binding['run']).encode()).hexdigest()[:24]
    data['receipt.json']=encoded(dict(schema=1,binding=binding,source_map_sha256='a'*64,status=R.PASS))
    data['cleanup.json']=encoded(dict(status='PASS_EXACT_OWNED_RESOURCES_RETIRED'))
    return data,guest,binding
