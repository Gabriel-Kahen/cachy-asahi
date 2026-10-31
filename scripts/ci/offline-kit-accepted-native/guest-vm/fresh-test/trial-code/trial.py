#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite TEST signing/transport trial. Uses pinned accepted native data; finite disposable installation is separate."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time

SHORT=os.environ.get('ACCEPTED_TOOL','')
if SHORT not in ('maintenance','diagnostics'): raise ValueError('finite accepted tool selector')
PACKAGE='cachy-asahi-maintenance' if SHORT=='maintenance' else 'cachy-asahi-session-diagnostics'
VERSION='0.1.0-2' if SHORT=='maintenance' else '0.1.0-3'
NAMESPACE='dev.offline-accepted-'+SHORT
RUNTIME=('scripts/release/offline_kit.py','scripts/client/client.py','scripts/release/source_delivery.py')

def need(ok,why):
    if not ok: raise ValueError(why)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(encoded(value));path.chmod(0o600)
def load(path): return json.loads(path.read_bytes())
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value);return value

def command(argv,*,env=None,log=None,allowed=(0,)):
    result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=90,env=env)
    need(len(result.stdout)+len(result.stderr)<=16*1024**2,'bounded real trial command output')
    if log:
        save(log,dict(argv=list(map(str,argv)),exit=result.returncode,stdout=result.stdout.decode(errors='replace'),
                      stderr=result.stderr.decode(errors='replace')))
    need(result.returncode in allowed,'real trial command failed: '+str(argv[0])+': '+result.stderr.decode(errors='replace')[-2000:])
    return result

def sections(raw):
    result={}
    for part in raw.decode().strip().split('\n\n'):
        lines=part.splitlines()
        if lines and lines[0].startswith('%'):result[lines[0].strip('%')]=lines[1:]
    return result

def base_inventory():
    rows=[]
    for path in sorted(Path('/var/lib/pacman/local').glob('*/desc')):
        values=sections(path.read_bytes()); files=sections(path.with_name('files').read_bytes())
        rows.append(dict(name=values['NAME'][0],version=values['VERSION'][0],arch=values['ARCH'][0],
            depend=values.get('DEPENDS',[]),provides=values.get('PROVIDES',[]),conflict=values.get('CONFLICTS',[]),
            files=[name for name in files.get('FILES',[]) if not name.endswith('/')]))
    need(len(rows)==574,'actual signed image must contain accepted574 ALPM records')
    observed=''.join(sorted(row['name']+' '+row['version']+'\n' for row in rows))
    need(observed==Path('/trial/packages.lock').read_text(),'actual ALPM database equals accepted574 lock')
    return dict(schema_version=1,snapshot_id='accepted574-native-trial',target_arch='aarch64',
                kind='complete-target-transaction',packages=rows)

def refresh_receipt(path,k):
    value=load(path/'kit.json');files,links=k.inventory(path);files.pop('kit.json')
    value.update(files=files,symlinks=links);(path/'kit.json').chmod(0o600);save(path/'kit.json',value)
    return sha((path/'kit.json').read_bytes())

def produce():
    root=Path('/trial');out=root/'public';out.mkdir(mode=0o700)
    public=out/'transport';public.mkdir(mode=0o700);trust=out/'trust';trust.mkdir(mode=0o700)
    producer=root/'producer';producer.mkdir(mode=0o700);inputs=producer/'inputs';inputs.mkdir(mode=0o700)
    storage=producer/'repository';storage.mkdir(mode=0o700)
    home=root/'signing';home.mkdir(mode=0o700);env=dict(os.environ,GNUPGHOME=str(home))
    r=module(Path('/feature/scripts/release/release.py'),'selected_release')
    k=module(Path('/feature/scripts/release/offline_kit.py'),'selected_kit')
    adapter=module(Path('/feature/scripts/release/recipe_source_delivery.py'),'selected_recipe_delivery')
    log=out/'producer-logs';log.mkdir()
    try:
        command(['gpg','--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key',
            'TEST ONLY native offline kit <offline-native@invalid>','ed25519','sign','1d'],env=env,log=log/'key-generation.json')
        listing=command(['gpg','--batch','--with-colons','--list-keys'],env=env).stdout.decode()
        key=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        carrier=Path('/accepted'); accepted=carrier/'current'; history=carrier/'history'
        F=module(Path(__file__).with_name('fresh_profile.py'),'fresh_root_test_profile')
        fresh=F.validate_phase(carrier,os.environ['FRESH_TEST_PROFILE_SHA256'],int(time.time()),18610)
        profile=fresh['profile']; fresh_key=profile['authority']['key']
        marker=load(accepted/'FILES.json')
        need({p.name for p in accepted.iterdir()}==set(marker['files'])|{'FILES.json'},'closed fresh TEST current23')
        for name,row in marker['files'].items():
            body=(accepted/name).read_bytes()
            need(len(body)==row['bytes'] and sha(body)==row['sha256'],'exact current DATA pin')
        original=load(history/(SHORT+'.provenance.json'))
        archive=accepted/original['native_archive'];raw=archive.read_bytes();digest=sha(raw)
        need(original['package']==PACKAGE and original['version']==VERSION and
             original['native_archive_pin']==dict(bytes=len(raw),sha256=digest),'unchanged historical native archive')
        public_home=producer/'root-test-public-trust';public_home.mkdir(mode=0o700)
        public_env=dict(env,GNUPGHOME=str(public_home));public_key=producer/'root-test-public.gpg'
        command(['gpg','--batch','--yes','--dearmor','--output',public_key,
                 accepted/original['TEST_public_key']],env=public_env,log=log/'root-test-key-dearmor.json')
        verified=command(['gpgv','--homedir',public_home,'--status-fd=1','--keyring',public_key,
                          accepted/original['TEST_signature'],archive],env=public_env,log=log/'root-test-signature.json')
        F.check_gpgv_status(verified.stdout,fresh_key,int(time.time()))
        save(inputs/'fresh-root-test-signature-verification.json',dict(
            status='PASS_FRESH_ROOT_LOCAL_TEST_SIGNATURE_OF_UNCHANGED_NATIVE_ARCHIVE',
            archive_sha256=digest,signer=fresh_key['fingerprint'],profile_sha256=fresh['profile_pin']['sha256'],
            historical_native_provenance_sha256=sha((history/(SHORT+'.provenance.json')).read_bytes()),
            fresh_native_build=False,original_native_signature=False,production_trust='NOT_ADMITTED'))
        for name in (original['TEST_signature'],original['TEST_public_key'],SHORT+'.TEST-original-status.txt'):
            shutil.copyfile(accepted/name,inputs/('root-test-'+name))
        for name in (original['TEST_signature'],original['TEST_public_key'],SHORT+'.TEST-original-status.txt',SHORT+'.provenance.json'):
            shutil.copyfile(history/name,inputs/('historical-'+name))
        shutil.copyfile(carrier/'profile.json',inputs/'root-test-profile.json')
        shutil.copyfile(archive,inputs/archive.name)
        actual=original
        identity=load(root/'identity.json');source_sha=identity['identity']['source_sha']
        observed=command(['pacman','-Q']).stdout.decode()
        need(''.join(sorted(observed.splitlines(keepends=True)))==Path('/trial/packages.lock').read_text(),'running signed574 image inventory')
        base=base_inventory();save(inputs/'base.json',base)
        save(inputs/'accepted-native-component.json',actual)
        save(inputs/'integration.lock.json',dict(schema_version=1,purpose='TEST_NATIVE_TRIAL_ONLY',identity=identity,
             base_sha256=sha(encoded(base)),packages_lock_sha256=sha(Path('/trial/packages.lock').read_bytes()),
             accepted_native_component_sha256=sha(encoded(actual)),
             accepted574=True,installation_authorized=False))
        review=inputs/'source-review.txt'
        review.write_text('DEVELOPMENT TEST source transport only. Original project MIT recipe and notices.\n'
            'No source completeness, legal release review, stable distribution, installation or M2 acceptance.\n')
        packed=producer/'recipe-source'
        source_raw=(accepted/(SHORT+'.source.tar')).read_bytes()
        need(dict(bytes=len(source_raw),sha256=sha(source_raw))==original['source_bundle_pin'],'exact accepted fullsource tar')
        saved,bodies=adapter.unpacked(source_raw,sha(source_raw))
        need(len(bodies)==(20 if SHORT=='maintenance' else 12) and
             adapter.bind_archive(archive,PACKAGE,bodies,adapter.metadata(bodies['.SRCINFO']))==saved['archive_binding'],
             'actual native archive and fullsource metadata/payload/license closure')
        recipe=producer/'recipe';recipe.mkdir(mode=0o700)
        for name,body in bodies.items():
            path=recipe/name;path.write_bytes(body);path.chmod(0o644)
        pack=adapter.pack(recipe,PACKAGE,original['source'],packed,archive,review,
                          'DEVELOPMENT_TEST_SOURCE_ASSOCIATION_NOT_RELEASE_ACCEPTANCE',False)
        need((packed/'source.tar').read_bytes()==source_raw,'byte-identical accepted source tar after repack')
        save(out/'source-pack.json',pack)
        # Retain the adapter's exact source files and declared index as publisher inputs.
        source_index=load(packed/'source-delivery.json')
        for path in packed.iterdir():shutil.copyfile(path,inputs/path.name)
        package=dict(name=PACKAGE,version=VERSION,arch='any')
        recipe_hash=sha(bodies['PKGBUILD'])
        record=dict(schema_version=1,artifact_sha256=digest,package=package,source_commit=source_sha,
             recipe_sha256=recipe_hash,recipe_source_commit=original['source'],licenses=['MIT'],
             sources=[dict(url='context-source:'+source_sha+'/packages/tools/'+PACKAGE,sha256=recipe_hash)],
             build=dict(execution='native',architecture='aarch64',environment='historical-native-component:'+original['source'],
                        snapshot_id=base['snapshot_id'],authority='HISTORICAL_NATIVE_ARCHIVE_BUILD_RECORD'),
             fresh_native_build=False,fresh_signature_authority='ROOT_LOCAL_TEST_ONLY',
             actual_native_build_record='evidence/accepted-native-component.json',
             acceptance='TEST_COMPONENT_ONLY_NO_INSTALL_OR_HARDWARE_ACCEPTANCE')
        save(inputs/'provenance.json',record)
        shutil.copyfile('/feature/LICENSE',inputs/'LICENSE.project')
        def ref(name):return dict(path=name,sha256=sha((inputs/name).read_bytes()))
        python=next(row['version'] for row in base['packages'] if row['name']=='python')
        spec=dict(schema_version=1,release_id='offline-native-test-1',synthetic=False,target_arch='aarch64',
             repo_name='offline-native-test',source_commit=source_sha,
             base=dict(ref('base.json'),snapshot_id=base['snapshot_id']),
             packages=[dict(artifact=ref(archive.name),provenance=ref('provenance.json'))],
             policy=dict(supported_models=['m2-air-13'],selected_packages=[PACKAGE],protected_packages=['glibc'],
                 coordinated_sets=[dict(name='native-builder-python',versions={'python':python})]),
             model_field_is_schema_reservation_only=True,hardware_validation='NOT_RUN',
             project_license=dict(ref('LICENSE.project'),spdx='MIT'),
             evidence=[dict(ref(name),id=name) for name in ('integration.lock.json','accepted-native-component.json','fresh-root-test-signature-verification.json','root-test-profile.json',*('root-test-'+n for n in (original['TEST_signature'],original['TEST_public_key'],SHORT+'.TEST-original-status.txt')),*('historical-'+n for n in (original['TEST_signature'],original['TEST_public_key'],SHORT+'.TEST-original-status.txt',SHORT+'.provenance.json')))],
             source_delivery=dict(schema_version=1,index=dict(ref('source-delivery.json'),id='source-delivery.json')))
        save(inputs/'spec.json',spec)
        staged=r.stage(argparse.Namespace(spec=str(inputs/'spec.json')),storage,key,r.gpg_env(home,storage))
        save(out/'staging.json',staged)
        bundle=Path(staged['path']);state=producer/'state';state.mkdir(mode=0o700)
        public_key=producer/'public.gpg';public_key.write_bytes(command(['gpg','--batch','--export',key],env=env).stdout)
        now=datetime.now(timezone.utc);metadata=producer/'development.json'
        k.c.build(argparse.Namespace(bundle=str(bundle),output=str(metadata),namespace=NAMESPACE,signer=key,
            sequence=1,issued_utc=k.c.utc(now-timedelta(minutes=1)),expires_utc=k.c.utc(now+timedelta(hours=4))))
        r.sign(metadata,key,env)
        args=argparse.Namespace(bundle=str(bundle),metadata=str(metadata),signature=str(metadata)+'.sig',
            public_keyring=str(public_key),namespace=NAMESPACE,signer=key,minimum_sequence=1,state_dir=str(state),
            lock_evidence='integration.lock.json',output=str(public/'good'))
        assembled=k.assemble(args);save(out/'assembly.json',assembled)
        pins=dict(schema=1,signer=key,namespace=NAMESPACE,minimum_sequence=1,
                  receiver_sha256=assembled['receiver_sha256'],kit_sha256={'good':assembled['kit_sha256']},
                  package=dict(package,sha256=digest),producer_paths_removed=False)
        good=public/'good'
        for label in ('tampered','expired','wrong-key','bootstrap-tampered'):
            target=public/label;shutil.copytree(good,target,symlinks=True)
            if label=='tampered':
                path=target/'release/repo'/archive.name;path.chmod(0o600);path.write_bytes(b'TEST isolated tampered package')
            elif label=='expired':
                path=target/'development.json';value=load(path)
                value.update(issued_utc=k.c.utc(now-timedelta(hours=2)),expires_utc=k.c.utc(now-timedelta(hours=1)))
                path.chmod(0o600);save(path,value);Path(str(path)+'.sig').unlink();r.sign(path,key,env)
            elif label=='wrong-key':
                command(['gpg','--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key',
                    'TEST ONLY wrong root <wrong-root@invalid>','ed25519','sign','1d'],env=env,log=log/'wrong-key-generation.json')
                listing=command(['gpg','--batch','--with-colons','--list-keys'],env=env).stdout.decode()
                other=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:') and line.split(':')[9]!=key)
                path=target/'public.gpg';path.chmod(0o600)
                path.write_bytes(command(['gpg','--batch','--export',other],env=env).stdout)
            else:
                path=target/RUNTIME[0];path.chmod(0o600);path.write_bytes(path.read_bytes()+b'\nraise RuntimeError("untrusted code ran")\n')
            pins['kit_sha256'][label]=refresh_receipt(target,k)
        # A real signed higher sequence drives the receiver's persistent rollback checkpoint.
        high=trust/'higher.json'
        k.c.build(argparse.Namespace(bundle=str(bundle),output=str(high),namespace=NAMESPACE,signer=key,sequence=2,
            issued_utc=k.c.utc(now-timedelta(seconds=30)),expires_utc=k.c.utc(now+timedelta(hours=4))))
        r.sign(high,key,env)
        # Trusted proposal code is outside transport; context source map binds it before actors.
        shutil.copyfile(Path(__file__).with_name('plan_bridge.py'),trust/'plan_bridge.py')
        pins['plan_bridge_sha256']=sha((trust/'plan_bridge.py').read_bytes())
        pins['higher_sha256']=sha(high.read_bytes());pins['higher_signature_sha256']=sha(Path(str(high)+'.sig').read_bytes())
        pins['producer_paths_removed']=True
        save(trust/'pins.json',pins)
        # A regular archive preserves internal db aliases through artifact upload.
        with tarfile.open(out/'transport.tar.gz','w:gz',dereference=False) as transport:
            transport.add(public,arcname='transport')
        save(out/'producer.json',dict(status='PASS_HISTORICAL_NATIVE_ARCHIVE_FRESH_ROOT_TEST_SIGNATURE_AND_TEST_KIT_ASSEMBLY',
            recipe_sha256=recipe_hash,package=dict(package,sha256=digest),source_delivery='CHECKED_DECLARED_ASSOCIATIONS',
            model_schema_reservation='m2-air-13 IS NOT HARDWARE SUPPORT OR EXECUTION',installed='NOT_RUN'))
    finally:
        try:
            command(['gpgconf','--homedir',home,'--kill','all'],env=env,log=log/'key-agent-cleanup.json')
        finally:
            shutil.rmtree(home);shutil.rmtree(producer)
    need(not home.exists() and not producer.exists(),'actual producer inputs and TEST private key removed')
    save(out/'producer-path-absence.json',dict(producer_absent=True,signing_home_absent=True))

def bootstrap(kit,pins):
    for name,pin in pins['receiver_sha256'].items():
        path=kit/name
        need(not path.is_symlink() and sha(path.read_bytes())==pin,'external bootstrap code pin refused: '+name)

def receive():
    result=Path('/result');logs=result/'logs';logs.mkdir(mode=0o700)
    pins=load(Path('/trusted/pins.json'))
    need(pins['producer_paths_removed'] and all(not Path(p).exists() for p in
        ('/producer','/trial','/build-one','/build-two','/feature','/recipe','/signing','/accepted')),
         'receiver cannot access producer inputs, checkout, recipes, build roots or signing home')
    good=Path('/media/good');bootstrap(good,pins)
    plan_path=Path('/trusted/plan_bridge.py')
    need(sha(plan_path.read_bytes())==pins['plan_bridge_sha256'],'external proposal code pin')
    k=module(good/RUNTIME[0],'relocated_trusted_kit');p=module(plan_path,'trusted_plan_proposal')
    state=result/'state';state.mkdir(mode=0o700)
    before=k.inventory(good)
    def args(kit=good,**changes):
        row=dict(kit=str(kit),kit_sha256=pins['kit_sha256'][kit.name],namespace=pins['namespace'],
            signer=pins['signer'],minimum_sequence=1,state_dir=str(state))
        row.update(changes);return argparse.Namespace(**row)
    def inspect_cli(label,expected):
        kit=Path('/media')/label;bootstrap(kit,pins)
        cmd=[sys.executable,'-I','-B',kit/RUNTIME[0],'inspect','--kit',kit,
            '--kit-sha256',pins['kit_sha256'][label],'--namespace',pins['namespace'],'--signer',pins['signer'],
            '--minimum-sequence','1','--state-dir',state]
        row=command(cmd,log=logs/(label+'.json'),allowed=(expected,))
        return json.loads(row.stdout) if expected==0 else row.stderr.decode()
    inspected=inspect_cli('good',0)
    need(inspected['source_delivery']=='CHECKED_DECLARED_ASSOCIATIONS' and not inspected['source_delivery_gap']
         and not inspected['packages_installed'] and not inspected['state_changed'],'real relocated verification only')
    client_args=k.arguments(good,args())
    verified=k.c.verify(client_args);save(result/'client-verify.json',verified)
    planned=p.plan(args(),api=k);save(result/'client-plan.json',planned)
    need(planned['status']=='BLOCKED_ENGINE_COMPATIBILITY' and not planned['transaction_authorized']
         and planned['candidate_contract']['candidates'][0]['package']==pins['package'],'concrete source-bound candidate plan')
    remove=p.plan(args(operation='remove',before={PACKAGE:pins['package']['version']}),api=k)
    save(result/'hypothetical-remove-plan.json',remove)
    need(not remove['packages_removed'] and remove['candidate_contract']['after']=={},'hypothetical removal is not execution')
    lookup=argparse.Namespace(**{**vars(client_args),'package':PACKAGE,'version':pins['package']['version'],
                               'arch':'any','artifact_sha256':pins['package']['sha256'],'output':str(result/'source-export')})
    save(result/'source-lookup-export.json',k.c.sources(lookup))
    refusals={}
    for label,reason in (('tampered','release payload checksum mismatch'),('expired','expired'),('wrong-key','signer')):
        message=inspect_cli(label,1)
        # Full concrete diagnostics are retained. Authentication refusal is required;
        # exact GPG wording varies with the accepted574 version.
        need(message.strip(),'concrete refusal diagnostic required');refusals[label]=message
        need(list(state.iterdir())==[],'failed isolated cases must not create checkpoint')
    try:bootstrap(Path('/media/bootstrap-tampered'),pins)
    except ValueError as error:refusals['bootstrap-tampered']=str(error)
    else:raise ValueError('changed transferred receiver code was admitted')
    for label,changes in (('wrong-namespace',dict(namespace='dev.wrong-root')),('floor',dict(minimum_sequence=2)),
                          ('wrong-signer',dict(signer='F'*40))):
        try:k.inspect(args(**changes))
        except (k.c.Error,ValueError,OSError,subprocess.SubprocessError) as error:refusals[label]=type(error).__name__+': '+str(error)
        else:raise ValueError('external trust refusal missing: '+label)
        need(list(state.iterdir())==[],'external refusal preserved fresh state')
    higher=Path('/trusted/higher.json');higher_sig=Path('/trusted/higher.json.sig')
    need(sha(higher.read_bytes())==pins['higher_sha256'] and sha(higher_sig.read_bytes())==pins['higher_signature_sha256'],
         'independent higher envelope pins')
    advance=argparse.Namespace(**{**vars(client_args),'metadata':str(higher),'signature':str(higher_sig),'apply':True})
    checkpoint=k.c.verify(advance);save(result/'higher-real-checkpoint.json',checkpoint)
    need(checkpoint['sequence']==2 and checkpoint['state_changed'],'real authenticated higher checkpoint')
    checkpoint_path=state/k.c.CHECKPOINT;held=checkpoint_path.read_bytes()
    try:k.inspect(args())
    except (k.c.Error,ValueError,OSError,subprocess.SubprocessError) as error:refusals['rollback']=type(error).__name__+': '+str(error)
    else:raise ValueError('lower sequence replay admitted')
    need(checkpoint_path.read_bytes()==held,'rollback refusal preserves exact checkpoint bytes')
    need(k.inventory(good)==before,'all receiver cases preserve original transport bytes and aliases')
    save(result/'refusals.json',refusals)
    save(result/'receiver.json',dict(status='PASS_RELOCATED_NATIVE_DEVELOPMENT_VERIFY_AND_PROPOSED_PLAN',
        source_delivery=inspected['source_delivery'],refusal_cases=sorted(refusals),
        source_exported=True,original_transport_unchanged=True,actual_higher_checkpoint=True,
        packages_installed=False,packages_removed=False,transaction_authorized=False,
        installation='NOT_RUN_MISSING_SUPPORTED_CANDIDATE_PROFILE',hardware='NOT_RUN',release='NOT_ADMITTED'))

def candidate():
    raw=Path('/inputs/candidate-selection.json').read_bytes();selection=json.loads(raw)
    need(sha(raw)==os.environ['CANDIDATE_SELECTION_SHA'],'external candidate selection SHA')
    source=Path('/source/candidate_lifecycle.py')
    need(sha(source.read_bytes())==selection['sources']['candidate_lifecycle.py']['sha256'],
         'independently selected lifecycle code hash')
    lifecycle=module(source,'actual_candidate_lifecycle');trust=selection['kit']
    report=lifecycle.run(argparse.Namespace(execute=True,source_root='/source',
        selection='/inputs/candidate-selection.json',selection_sha256=sha(raw),
        kit=trust['path'],kit_sha256=trust['kit_sha256'],signer=trust['signer'],namespace=trust['namespace'],
        minimum_sequence=trust['minimum_sequence'],state_dir=trust['state_dir']))
    need(report['status']=='PASS_FINITE_REAL_CANDIDATE_DISPOSABLE_ALPM_LIFECYCLE','actual candidate lifecycle complete')

if __name__=='__main__':
    need(platform.machine() in ('aarch64','arm64') and os.getuid()==os.geteuid()!=0,'non-root native ARM trial only')
    need(len(sys.argv)==2 and sys.argv[1] in ('produce','receive','candidate'),'fixed finite trial phase')
    Path(os.environ['HOME']).mkdir(mode=0o700,exist_ok=True)
    globals()[sys.argv[1]]()
