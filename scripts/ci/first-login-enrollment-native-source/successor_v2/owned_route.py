# SPDX-License-Identifier: MIT
"""Finite current-three registration for an existing qualified owned session.

No supervisor, builder, signer or bootstrap is implemented here. Root's new
owner successor supplies its existing bounded Commands and signed-image session.
Frozen v1 has no such registration hook and is deliberately not called.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent
OPERATION = 'first-login-enrollment-ui-current-v2'
PASS = 'PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY'
STAGES = ('backend', 'ui', 'lifecycle')
COUNTS = dict(backend=350, ui=374, lifecycle=372)
NATIVE_SHA = 'cde384acd8574ddfcb07f7316ad4d24349f5b958ac6b2cea48a3a6aff480c827'
PROJECT = {'cachy-asahi-setup':'0.3.0-1', 'cachy-asahi-repository-enrollment':'0.4.0-1',
           'cachy-asahi-first-login':'0.1.0-3', 'cachy-asahi-first-login-ui':'0.2.0-2'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, maximum=4*1024**2):
    path=Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary absolute DATA path')
    info=path.stat()
    need(path.is_file() and info.st_nlink == 1 and 0 <= info.st_size <= maximum, 'bounded single-link DATA file')
    raw=path.read_bytes();after=path.stat()
    need(len(raw)==info.st_size and (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'DATA changed while reading')
    return raw


def reference(row, maximum=4*1024**2):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}, 'exact whole-file reference; NULL is unready')
    raw=read(row['path'],maximum)
    need(pin(raw)=={k:row[k] for k in ('bytes','sha256')}, 'whole reference changed')
    return raw


def native():
    # Maintained implementation code, never loaded from a produced artifact.
    raw=read(HERE/'native.py',65536)
    need(pin(raw)['sha256']==NATIVE_SHA,'whole maintained current adapter code pin')
    spec=importlib.util.spec_from_file_location('current_owned_native',HERE/'native.py')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
    exec(compile(raw,str(HERE/'native.py'),'exec'),module.__dict__)
    return module


def natural(row):
    need(row['reaped'] is True and row['ownership']=='REAPED' and row['group_census']=='EMPTY_TWICE' and
         row['output_complete'] is True and row['timeout'] is False and row['signals']==[] and
         row['error'] is None and type(row['exit']) is int and row['exit']==0, 'natural owned command retirement required')


def signature(row, archive, signature_file, now, N):
    """Join an authentic retained Root decision; current GPG belongs to owner."""
    need(type(row) is dict and set(row)=={'Root_decision','Root_verification'},
         'retained Root decision and verification references required')
    decision=json.loads(reference(row['Root_decision']));proof_raw=reference(row['Root_verification'])
    proof=json.loads(proof_raw);package=decision['archive']
    need(decision['schema']==1 and decision['issuer']=='Root' and decision['accepted'] is True and
         decision['holds_preserved'] is True and decision['trust_scope']=='TEST_ONLY' and
         package['arch']=='any' and package['package'] in PROJECT and package['version']==PROJECT[package['package']] and
         decision['status']==('ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY' if package['package']=='cachy-asahi-setup'
                             else 'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY'),
         'Root package-specific private TEST decision, no runtime admission')
    archive_pin=pin(reference(archive,16*1024**2));signature_pin=pin(reference(signature_file))
    need({k:package[k] for k in ('bytes','sha256')}==archive_pin and decision['signature']==signature_pin and
         decision['signature_file']==signature_file['path'] and decision['verification_proof_sha256']==pin(proof_raw)['sha256'],
         'Root decision exact archive/signature/verification join')
    key=decision['public_test_key'];fingerprint=key['fingerprint']
    need(proof['schema']==1 and proof['Root_issuer']=='Root' and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and
         proof['verified'] is True and proof['trust_scope']=='TEST_ONLY' and proof['archive']==archive_pin and
         proof['signature']==signature_pin and proof['public_test_key']==key and key['trust_scope']=='TEST_ONLY' and
         re.fullmatch('[0-9A-F]{40}',fingerprint or ''), 'same Root-verified public TEST primary and bytes')
    public_key=dict(path=decision['public_test_key_file'],**{k:key[k] for k in ('bytes','sha256')})
    reference(public_key,65536)
    verified=datetime.datetime.fromisoformat(proof['actual_verified_utc'])
    issued=datetime.datetime.fromisoformat(decision['issued_at'])
    need(verified.tzinfo is not None and issued.tzinfo is not None and verified.timestamp()<=issued.timestamp()<=now,
         'historical Root verification/decision ordering; not a fresh Root observation')
    return dict(kind='ROOT_RETAINED_TEST_SIGNATURE_DECISION',archive=archive,signature=signature_file,
                public_key=public_key,fingerprint=fingerprint,Root_decision=row['Root_decision'],
                Root_verification=row['Root_verification'],trust_scope='TEST_ONLY')


def stage_signatures(session, inputs, grant, stage, N):
    """Require actual supervised current-owner GPG before native stage work."""
    verify=getattr(session,'verify_signatures',None)
    need(callable(verify),'qualified owner must verify current stage signatures')
    keys=('setup8','first_login_backend') if stage=='ui' else ('setup8',);selections={}
    for key in keys:
        value=inputs[key];selected=signature(value['current_TEST_signature_verification'],value['archive'],value['signature'],time.time(),N)
        need(grant['owner']['test_fingerprint']==selected['fingerprint'] and grant['owner']['test_public_key']==selected['public_key'],
             'same separately Root-selected current owner TEST key policy')
        selections[key]=selected
    receipt=verify(inputs)
    need(type(receipt) is dict and receipt.get('status')=='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION' and
         receipt.get('operation')==OPERATION and receipt.get('stage')==stage and receipt.get('binding')==grant['binding'] and
         receipt.get('scope')=='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION' and
         type(receipt.get('verified')) is dict and set(receipt['verified'])==set(keys),
         'complete delegated actual owner signature receipt; no fresh Root claim')
    for key in keys:
        selected=selections[key]
        row=receipt['verified'][key];command=row['command'];status=row['status_text']
        need(type(status) is str and 0<len(status.encode())<=1024**2 and
             row['archive']=={k:selected['archive'][k] for k in ('bytes','sha256')} and
             row['signature']=={k:selected['signature'][k] for k in ('bytes','sha256')} and
             row['public_test_key']=={k:selected['public_key'][k] for k in ('bytes','sha256')} and
             row['fingerprint']==selected['fingerprint'],'current verification exact Root-selected bytes/key')
        argv=command['argv'];need(type(argv) is list and len(argv)==11,'exact current owner GPG vector')
        home=Path(argv[2]);need(home.is_absolute() and home.name=='trust' and home.parent.parent==Path('/tmp') and
             re.fullmatch('build-tools-test-[A-Za-z0-9_+-]+',home.parent.name) and
             argv==['/usr/bin/gpg','--homedir',str(home),'--batch','--no-auto-key-retrieve','--auto-key-locate','clear',
                    '--status-fd=1','--verify',selected['signature']['path'],selected['archive']['path']] and
             command['step']=='owner-current-signature-'+key and type(command['expected']) is int and command['expected']==0 and command['success'] is True and
             command['log_pin']==pin(status.encode()),'exact offline actual-owner signature command/status receipt')
        natural(command['supervision']);N.strict_signature(status,selected['fingerprint'])
    return receipt


def image_packages(stage, packages):
    need(stage in STAGES and type(packages) is dict and len(packages)==COUNTS[stage], 'typed exact stage image inventory')
    present=set(packages)&set(PROJECT)
    expected={'cachy-asahi-setup'} if stage=='backend' else ({'cachy-asahi-setup','cachy-asahi-first-login'} if stage=='ui' else set())
    need(present==expected and all(packages[n]==PROJECT[n] for n in present),
         'exact stage dependencies; lifecycle must start project-free372, never UI374')


def admission(value, inputs, source, profile, stage, now):
    N=native();N.policy(profile)
    need(profile==json.loads((HERE/'profile.json').read_bytes()),'whole maintained current-three profile')
    need(profile==json.loads((HERE/'profile.json').read_bytes()), 'whole maintained current-three profile, no substituted payloads')
    need(stage in STAGES and value['schema']==1 and value['operation']==OPERATION and value['stage']==stage and
         value['issuer']=='Root' and value['approved'] is True, 'distinct Root current-stage admission required')
    need(value['profile_pin']==pin((HERE/'profile.json').read_bytes()) and value['inputs_pin']==pin(encoded(inputs)),
         'complete current profile/inputs admission')
    need(value['binding']['source_lock']==pin(read(Path(source)/'source.lock.json')) and
         inputs['source']==value['binding'], 'same published current Source binding')
    binding=value['binding']
    need(re.fullmatch('[0-9a-f]{40}',binding.get('source') or '') and
         re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',binding.get('ref') or '') and
         all(type(binding.get(k)) is str and re.fullmatch('[1-9][0-9]*',binding[k]) for k in ('run','job')) and
         type(binding.get('attempt')) is int and binding['attempt']==1, 'actual exact Source/run/job/attempt tuple')
    need(inputs['Root_admission']==value['selector'] and inputs['matching_Reader']==value['matching_Reader'] and
         type(value['matching_Reader']) is dict and value['matching_Reader']['selector'] and
         value['matching_Reader'].get('operation')==OPERATION and
         re.fullmatch('[0-9a-f]{64}',value['matching_Reader']['sha256']), 'new actual Reader/owner selectors; no v1 reuse')
    need(type(value['issued_at_unix']) in (int,float) and type(value['expires_at_unix']) in (int,float) and
         value['issued_at_unix'] <= now <= value['expires_at_unix'] <= value['issued_at_unix']+300,
         'fresh current operation/resource admission')
    cap=inputs['Root_capacity']
    need(all(type(cap.get(k)) is int for k in ('build_seconds','builder_cpus','builder_memory_bytes','builder_pids','total_seconds','command_rows')) and
         cap==value['resources'] and 2 <= cap['build_seconds'] <= 180 and cap['builder_cpus']==4 and
         cap['builder_memory_bytes']==4*1024**3 and cap['builder_pids']==512 and
         2 <= cap['total_seconds'] <= 1800 and 1 <= cap['command_rows'] <= 512,
         'explicit new finite policy; old consumer admission is insufficient')
    image=value['images'][stage]
    need(re.fullmatch('sha256:[0-9a-f]{64}',image['id']) and type(image['packages']) is dict and
         len(image['packages'])==COUNTS[stage], 'typed exact stage image/inventory')
    lock=reference(image['inventory_pin']).decode('ascii')
    rows=lock.splitlines();need(len(rows)==len(image['packages']) and
        lock==''.join(n+' '+v+'\n' for n,v in sorted(image['packages'].items())), 'complete exact image inventory bytes')
    proof=json.loads(reference(image['Root_qualification']))
    need(proof['issuer']=='Root' and proof['status']=='ROOT_REVIEWED_CURRENT_ONBOARDING_IMAGE_V2' and
         proof['operation']==OPERATION and proof['stage']==stage and proof['binding']==value['binding'] and
         proof['image']==image['id'] and proof['inventory_pin']==image['inventory_pin'] and
         proof['observed_architecture']=='aarch64' and proof['owned_runner'] is True and
         proof['image_build_policy_admitted'] is True, 'independently bound actual native image/namespace proof')
    need(inputs['image_namespace_qualification']==image['Root_qualification'], 'same new namespace qualification')
    reference(value['runtime'])
    need(proof['runtime']==value['runtime'],'same separately Root-selected whole runtime input')
    image_packages(stage,image['packages'])
    if stage in ('backend','ui'):
        prefix='ui_' if stage=='ui' else ''
        inventory=inputs[prefix+'builder_inventory']
        need(inputs[prefix+'builder_image']==image['id'] and inventory['packages']==image['packages'] and
             {k:inventory[k] for k in ('path','bytes','sha256')}==image['inventory_pin'],
             'generic builder must select the exact independently qualified stage image/inventory')
    signature(inputs['setup8']['current_TEST_signature_verification'],inputs['setup8']['archive'],inputs['setup8']['signature'],now,N)
    need(pin(reference(inputs['setup8']['archive'],16*1024**2))==profile['setup8']['archive_pin'], 'authentic accepted Setup8 bytes')
    if stage=='ui':
        backend=inputs['first_login_backend'];pair=json.loads(reference(backend['native_pair']))
        need(pair['issuer']=='Root' and pair['status']=='ROOT_REVIEWED_CURRENT_FIRST_LOGIN_PAIR_V2' and
             pair['binding']==value['binding'] and pair['name']=='cachy-asahi-first-login' and
             pair['version']=='0.1.0-3' and pair['archive']==pin(reference(backend['archive'],16*1024**2)),
             'genuine reviewed current CLI03 pair, not an old backend or arbitrary populated object')
        signature(backend['current_TEST_signature_verification'],backend['archive'],backend['signature'],now,N)
    if stage in ('ui','lifecycle'):
        official=inputs['official_ui_dependencies']
        need(official['required']==['gtk4','python-gobject'] and {'gtk4','python-gobject'}<=set(image['packages']),
             'actual official GTK4/python-gobject dependencies required')
        catalog=reference(official['exact_closure']);archives=reference(official['archive_signature_inputs'])
        verified=json.loads(reference(official['verification']))
        need(verified['issuer']=='Root' and verified['status']=='ROOT_REVIEWED_OFFICIAL_ONBOARDING_CLOSURE_V2' and
             verified['catalog']==pin(catalog) and verified['archive_signature_inputs']==pin(archives) and
             verified['base_packages']==349 and verified['qualified_packages']==372 and verified['selected_packages']==23,
             'same independently signed official transitive closure; no worker fetch or guessed provider')
    return N,image


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def command_callback(commands, maximum, row_cap):
    """Adapt the existing Commands.run API; retain its original supervision rows."""
    need(2 <= commands.timeout <= maximum and commands.max_output <= 1024**2, 'existing owned Commands bounds')
    def run(step, argv):
        before=len(commands.records);need(before < row_cap, 'finite current command row cap')
        raw=commands.run(step,list(map(str,argv)),commands.output.parent,0)
        need(type(raw) is bytes and len(commands.records)==before+1, 'one actual owned command receipt')
        row=commands.records[-1];natural(row['supervision'])
        need(row['step']==step and row['argv']==list(map(str,argv)) and row['expected']==0 and
             row['success'] is True and row['log_pin']==pin(raw), 'exact complete owned command/log receipt')
        return raw
    return run


class ObservedTools:
    """Retain raw installed-file observations in addition to held local checks."""
    def __init__(self, held):
        self.held=held
    def __getattr__(self, name):
        return getattr(self.held,name)
    def check_payload(self, recipe, run, pacman, label):
        result=self.held.check_payload(recipe,run,pacman,label)
        for i,(name,row) in enumerate(sorted(recipe['payload_files'].items())):
            path='/'+name
            raw=run(label+'-stat-'+str(i),['/usr/bin/stat','-c','%u:%g:%a:%s:%h:%F','--',path])
            need(raw==('0:0:%o:%d:1:regular file\n'%(row['mode'],row['bytes'])).encode(),
                 'retained installed regular-file identity/mode/size')
            raw=run(label+'-sha256-'+str(i),['/usr/bin/sha256sum','--',path])
            need(raw==(row['sha256']+'  '+path+'\n').encode(),'retained installed whole-file bytes')
        return result


def signed_domain(session):
    need(os.getpid()>1 and os.getppid()==1 and os.getuid()==os.geteuid()==0 and
         os.uname().machine=='aarch64' and session.facts.get('execution_domain')=='OWNED_SIGNED_IMAGE_LOCAL',
         'lifecycle Python/helpers/state checks must be local inside the owned native signed-image actor')


def run_registered(*, stage, source, profile, inputs, grant, output, open_session, now=None):
    """Executable staged route; owner context retains all cleanup authority.

    open_session is the new owner's narrow hook over its qualified bootstrap,
    existing Commands and signed-image callbacks. Frozen v1 has no such hook.
    """
    output=Path(output);source=Path(source);now=time.time() if now is None else now
    N,image=admission(grant,inputs,source,profile,stage,now)
    need(grant['source_root']==str(source) and grant['output']==str(output), 'exact Root-bound current source/output operands')
    need(output.is_absolute() and source.is_absolute() and not output.exists() and output!=source and
         output not in source.parents and source not in output.parents and
         not any(p.is_symlink() for p in (output,*output.parents,source,*source.parents)), 'fresh disjoint nonaliased output')
    output.mkdir(mode=0o700)
    report=dict(schema=1,operation=OPERATION,stage=stage,status='HOLD',binding=grant['binding'],
                profile_pin=grant['profile_pin'],inputs_pin=grant['inputs_pin'],source_lock=grant['binding']['source_lock'],
                commands=[],Root_acceptance=None,native16K='UNQUALIFIED',M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
    session=None;primary=None
    try:
        # The qualified owner, not this adapter, opens namespaces, owns waits,
        # establishes TEST trust and restores state on success or exception.
        with open_session(grant,source,output) as session:
            facts=session.facts
            facts=session.facts
            need(facts['operation']==OPERATION and facts['stage']==stage and facts['binding']==grant['binding'] and
                 facts['image']==image['id'] and facts['architecture']=='aarch64' and facts['page_size'] in (4096,16384),
                 'same actual qualified owner session')
            need(facts.get('operation')==OPERATION and facts.get('stage')==stage and
                 facts.get('binding')==grant['binding'] and facts.get('image')==image['id'] and
                 facts.get('architecture')=='aarch64' and facts.get('page_size') in (4096,16384),
                 'actual owner facts must join this current stage and qualified image')
            need(Path(session.commands.output)==output/'commands' and
                 1 < session.commands.deadline-time.monotonic() <= inputs['Root_capacity']['total_seconds'],
                 'existing owned runner must use the fresh command directory and admitted total deadline')
            report['owner_facts']=facts
            report['stage_signature_verification']=stage_signatures(session,inputs,grant,stage,N)
            run=command_callback(session.commands,inputs['Root_capacity']['build_seconds'],inputs['Root_capacity']['command_rows'])
            if stage in ('backend','ui'):
                report['builds']=N.build_pairs(run,session.tools,source,profile,inputs,stage,output/'builds')
                report['artifacts']={}
                for kind in (('ui',) if stage=='ui' else ('enrollment','first-login')):
                    pins={label:session.tools.pin(output/'builds'/(kind+'-'+label)/'artifacts'/profile['packages'][kind]['archive'])
                          for label in ('a','b')}
                    need(pins['a']==pins['b'],'whole actual compressed pair bytes must match')
                    report['artifacts'][kind]=pins
            else:
                signed_domain(session)
                report['protected_before']=session.protected_before
                need(set(grant['signed'])=={'setup8',*N.KINDS},'four exact current signed inputs before retention')
                report['signed']=grant['signed']
                # Retain only public signed package DATA/configuration, never
                # ephemeral keys/homes. Original actor-local argv stay intact.
                retained=output/'signed';retained.mkdir(mode=0o700)
                for key,row in grant['signed'].items():
                    for field,destination in (('archive','archive'),('signature','signature')):
                        raw=session.tools.ordinary(Path(row[field]),16*1024**2)
                        need(pin(raw)==row[field+'_pin'],'signed DATA changed before retention')
                        (retained/(key+'.'+destination)).write_bytes(raw)
                config=session.tools.ordinary(Path(session.pacman[1]),65536)
                (output/'signature-config.txt').write_bytes(config)
                report['signature_config_pin']=pin(config)
                def signed_run(step,argv):
                    raw=run(step,argv)
                    if step=='current-baseline':
                        need(b''.join(sorted(raw.splitlines(keepends=True)))==reference(image['inventory_pin']),
                             'actual lifecycle baseline must be the qualified project-free372 image')
                    return raw
                report['lifecycle']=N.lifecycle(signed_run,ObservedTools(session.tools),profile,grant['signed'],session.pacman,
                                                session.verifier,session.fingerprint,session.verify_state)
                report['protected_after']=session.protected_after()
                need(report['protected_before']==report['protected_after'],'all protected baseline state restored')
            report['commands']=list(session.commands.records)
        report['owner_cleanup']=session.cleanup
        if stage=='lifecycle':
            need(session.cleanup==dict(status='PENDING_OUTER_CONTAINER_RETIREMENT',operation=OPERATION,stage=stage,
                 binding=grant['binding'],natural_retirement=True,owned_container_absence_verified=False,protected_state_unchanged=True),
                 'local lifecycle cleanup must defer actual container absence to outer owner')
            report['status']='PENDING_OUTER_CURRENT_STAGE_RETIREMENT'
            return report
        need(session.cleanup==dict(status='PASS_OWNED_CURRENT_STAGE_RETIREMENT',operation=OPERATION,stage=stage,
             binding=grant['binding'],natural_retirement=True,owned_container_absence_verified=True,protected_state_unchanged=True),
             'complete original owner cleanup required')
        report['status']=PASS
    except BaseException as error:
        primary=error;report['failure']=dict(type=type(error).__name__,message=str(error)[:2048])
        if error.__context__ is not None:
            report['prior_failure']=dict(type=type(error.__context__).__name__,message=str(error.__context__)[:2048])
        if session is not None:
            report['commands']=list(session.commands.records);report['owner_cleanup']=getattr(session,'cleanup',None)
        raise
    finally:
        try:(output/'route.json').write_bytes(encoded(report))
        except BaseException:
            if primary is None:raise
    return report


def register(operations):
    need(type(operations) is dict and OPERATION not in operations, 'one new operation; never relabel v1')
    operations[OPERATION]=run_registered
    return operations


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('admission','inputs','source','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--admission-sha256',required=True);parser.add_argument('--execute',action='store_true')
    args=parser.parse_args();need(args.execute and sys.flags.isolated and sys.dont_write_bytecode and __debug__,
                                 'Root-only explicit isolated unoptimized current operation entry')
    body=read(args.admission);need(pin(body)['sha256']==args.admission_sha256,'external Root admission SHA')
    grant=json.loads(body);inputs=json.loads(read(args.inputs));profile=json.loads((HERE/'profile.json').read_bytes())
    # A new separately reviewed owner successor must expose exactly this hook.
    # Loading the frozen two-package owner or guessing callbacks is forbidden.
    admission(grant,inputs,args.source,profile,grant['stage'],time.time())
    need(grant['source_root']==str(args.source) and grant['output']==str(args.output), 'exact Root-bound entry operands before provider import')
    owner=grant['owner'];raw=reference(owner['code'],128*1024)
    need(owner['api']=='CURRENT_ONBOARDING_OWNED_CALLBACKS_V2','new qualified owner callback API')
    spec=importlib.util.spec_from_file_location('root_current_owned_provider',owner['code']['path'])
    provider=importlib.util.module_from_spec(spec);sys.modules[spec.name]=provider
    exec(compile(raw,owner['code']['path'],'exec'),provider.__dict__)
    need(callable(getattr(provider,'open_current_session',None)), 'new owner successor must expose open_current_session; frozen v1 is unsupported')
    registry=register({})
    result=registry[OPERATION](stage=grant['stage'],source=args.source,profile=profile,inputs=inputs,grant=grant,
                              output=args.output,open_session=provider.open_current_session)
    print(json.dumps(dict(status=result['status'],operation=OPERATION,stage=grant['stage'])))


if __name__=='__main__':main()
