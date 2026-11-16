# SPDX-License-Identifier: MIT
"""Delegated private stage adapter; imports no owner and creates no authority."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time

OP='first-login-enrollment-ui-current-v2'
ISSUER='DELEGATED_CURRENT_OWNER_V3'
STAGES=('backend','ui','lifecycle')
NATIVE_PIN=dict(bytes=13703,sha256='cde384acd8574ddfcb07f7316ad4d24349f5b958ac6b2cea48a3a6aff480c827')
PROFILE_PIN=dict(bytes=21679,sha256='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171')
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
KINDS=('enrollment','first-login','ui')
PROJECT={'cachy-asahi-setup':'0.3.0-1','cachy-asahi-repository-enrollment':'0.4.0-1',
         'cachy-asahi-first-login':'0.1.0-3','cachy-asahi-first-login-ui':'0.2.0-2'}


def need(ok,why):
    if not ok:raise ValueError(why)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    need(type(raw) is bytes and 0<len(raw)<=1024**2,'bounded complete delegation/command JSON')
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
    encoded(value);need(type(value) is dict,'JSON object');return value


def final(value):
    need(all(value.get(k)==v and type(value.get(k)) is type(v) for k,v in FINAL.items()),'no delegated final acceptance')


def absolute(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),
         'ordinary absolute nonaliased stage path')
    return path


def image_packages(stage,image):
    need(type(image) is dict and re.fullmatch('sha256:[0-9a-f]{64}',image.get('id') or '') and
         type(image.get('packages')) is dict and len(image['packages'])==dict(backend=350,ui=374,lifecycle=372)[stage],
         'exact provisional immutable image and inventory count')
    present=set(image['packages'])&set(PROJECT)
    expected={'cachy-asahi-setup'} if stage=='backend' else {'cachy-asahi-setup','cachy-asahi-first-login'} if stage=='ui' else set()
    need(present==expected and all(image['packages'][n]==PROJECT[n] for n in present),'exact stage dependency membership')


def private_build_plan(source,profile,plan,image,stage,output):
    """New delegated operands; never call the frozen Root-gated build_vectors."""
    need(stage in ('backend','ui') and set(plan)=={'source_date_epoch','capacity','builder_inventory'},'private build plan only')
    c=plan['capacity'];need(set(c)=={'build_seconds','builder_cpus','builder_memory_bytes','builder_pids'} and
         all(type(v) is int for v in c.values()) and 2<=c['build_seconds']<=180 and
         (c['builder_cpus'],c['builder_memory_bytes'],c['builder_pids'])==(4,4*1024**3,512),'fixed private generic builder resources')
    epoch=plan['source_date_epoch'];need(type(epoch) is int and epoch>=0,'private stable source epoch')
    inventory=plan['builder_inventory'];need(set(inventory)=={'path','bytes','sha256','packages'} and
         inventory['packages']==image['packages'] and type(inventory['bytes']) is int and inventory['bytes']>0 and
         re.fullmatch('[0-9a-f]{64}',inventory['sha256'] or ''),'whole private builder inventory')
    absolute(inventory['path']);image_packages(stage,image)
    required={'python','gnupg','pacman','coreutils','libarchive','bubblewrap','util-linux','fish','zsh'}
    if stage=='ui':required|={'gtk4','python-gobject'}
    need(required<=set(image['packages']),'all offline builder dependencies preinstalled')
    source,output=absolute(source),absolute(output);rows=[]
    need(source!=output and source not in output.parents and output not in source.parents,'separate source and builds')
    for kind in (('ui',) if stage=='ui' else ('enrollment','first-login')):
        recipe=source/profile['packages'][kind]['path']
        for label in ('a','b'):
            rows.append(dict(kind=kind,label=label,recipe=str(recipe),output=str(output/(kind+'-'+label)),
                source_date_epoch=epoch,capacity=dict(c),builder_inventory=inventory,image=image['id']))
    return rows


def natural(row):
    need(row['reaped'] is True and row['ownership']=='REAPED' and row['group_census']=='EMPTY_TWICE' and
         row['output_complete'] is True and row['timeout'] is False and row['signals']==[] and row['error'] is None and
         type(row['exit']) is int and row['exit']==0,'natural delegated command retirement')


def run_callback(session,cap):
    def run(step,argv):
        before=len(session.records);need(before<cap['command_rows'],'private command row cap')
        raw=session.run(step,argv);need(type(raw) is bytes and len(raw)<=1024**2 and len(session.records)==before+1,'one real bounded command receipt')
        row=session.records[-1]
        need(row['step']==step and row['argv']==argv and type(row['expected']) is int and row['expected']==0 and
             row['success'] is True and row['log_pin']==pin(raw),'actual delegated command/whole output join')
        natural(row['supervision'])
        if 'seconds' in row['supervision']:
            seconds=row['supervision']['seconds'];need(type(seconds) in (int,float) and math.isfinite(seconds) and
                0<=seconds<cap['max_command_seconds'],'bounded actual command duration')
        return raw
    return run


def build_pairs(session,source,profile,stage,output,capability):
    pairs={};artifacts={}
    plan=private_build_plan(source,profile,session.build_inputs,session.image,stage,output)
    for kind in (('ui',) if stage=='ui' else ('enrollment','first-login')):
        for intent in (row for row in plan if row['kind']==kind):
            before=len(session.records);observed=session.build(kind,intent['label'])
            need(type(observed) is dict and observed['status']=='built-package-static-pass' and
                 before<len(session.records)<=capability['command_rows'],'actual private build DATA and owned command receipts')
            for row in session.records[before:]:
                need(row['success'] is True and type(row['expected']) is int and row['expected']==0,'successful actual build command')
                natural(row['supervision'])
            session.native.check_log(session.tools.ordinary(Path(intent['output'])/'build.log',1024**2),kind,profile)
        before=len(session.records);raw=session.compare(kind)
        need(type(raw) is bytes and len(raw)<=1024**2 and len(session.records)==before+1<=capability['command_rows'],'one actual held comparison command receipt')
        row=session.records[-1];natural(row['supervision'])
        need(row['argv']==['/usr/bin/python3','-I','-B',str(source/'scripts/build/compare.py'),
             str(output/(kind+'-a')),str(output/(kind+'-b')),'--require-bytes'] and row['success'] is True and
             type(row['expected']) is int and row['expected']==0 and row['log_pin']==pin(raw),'actual held comparison argv/output')
        comparison=decode(raw);archive=profile['packages'][kind]['archive']
        need(comparison['status']=='contents-reproduced' and comparison['errors']==[] and comparison['packages']=={
            archive:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)},'complete actual private pair comparison')
        pins={label:session.tools.pin(output/(kind+'-'+label)/'artifacts'/archive) for label in ('a','b')}
        need(pins['a']==pins['b'],'actual complete compressed pair equality');pairs[kind]=comparison;artifacts[kind]=pins
    return dict(pairs=pairs,artifacts=artifacts)


def signed_domain():
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.getpid()>1 and os.getppid()==1,
         'lifecycle Python must be local root native direct child, never a remote callback')


def run_registered(*,stage,source,profile,inputs,delegation_raw,delegation_sha256,context,image,executor,output,open_session):
    """Execute only the delegated owner's supplied bounded session callbacks."""
    d=decode(delegation_raw);need(pin(delegation_raw)['sha256']==delegation_sha256 and delegation_raw==encoded(d),'exact external canonical delegation')
    need(stage in STAGES and type(d['schema']) is int and (d['schema'],d['kind']) in (
         (3,'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'),
         (4,'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4')) and
         d['issuer']=='Root' and d['approved'] is True and d['stage']==stage and d['scope']=='CURRENT_PRIVATE_STAGE_ONLY','distinct Root private stage delegation')
    final(d);final(context)
    source,output=absolute(source),absolute(output);b=context['binding']
    need((context['schema'],context['kind'],context['issuer']) in (
         (3,'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V3','DELEGATED_CONTEXT_PROGRAM_V3'),
         (4,'DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4','DELEGATED_CONTEXT_PROGRAM_V4')) and type(context['schema']) is int and context['schema']==d['schema'] and
         context['operation']==OP and context['stage']==stage and context['source_root']==str(source) and
         context['delegation_pin']==pin(delegation_raw) and context['nonce']==d['nonce'] and re.fullmatch('[0-9a-f]{64}',d['nonce']), 'same genuine delegated context observations')
    need(set(b)=={'source','ref','run','job','attempt','source_lock'} and all(b[k]==d['binding'][k] for k in ('source','ref','attempt','source_lock')) and
         all(type(b[k]) is str and re.fullmatch('[1-9][0-9]*',b[k]) for k in ('run','job')) and
         d['binding']['run'] is d['binding']['job'] is None,'observed run/job, never preissued Root observations')
    need(image['status']=='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY' and image['operation']==OP and image['stage']==stage and
         image['binding']==b and image['owner_executor_facts']['nonce']==d['nonce'] and image['delegation_pin']==pin(delegation_raw) and
         image['Root_final_acceptance'] is None and image['independent_image_qualification'] is None and image.get('issuer')!='Root',
         'same delegated provisional image observations, no independent image qualification')
    observed_image=dict(id=image['image_id'],packages=image['packages'],inventory_pin=image['inventory_pin'])
    image_packages(stage,observed_image);need(pin(encoded(profile))==PROFILE_PIN,'whole frozen current recipe profile')
    c=d['capability'];need(c['operation']==OP and c['stage']==stage and all(type(c[k]) is int and c[k]>0 for k in
         ('max_command_seconds','total_seconds','builder_cpus','builder_memory_bytes','builder_pids','command_rows')) and
         2<=c['max_command_seconds']<=min(180,c['total_seconds']) and c['command_rows']<=512 and
         (c['builder_cpus'],c['builder_memory_bytes'],c['builder_pids'])==(4,4*1024**3,512),'finite delegated stage capability')
    need(not output.exists() and output!=source and source not in output.parents and output not in source.parents,'fresh disjoint private output')
    output.mkdir(mode=0o700);report=dict(schema=4,kind='DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4',issuer=ISSUER,operation=OP,
        stage=stage,binding=b,nonce=d['nonce'],delegation_pin=pin(delegation_raw),context_pin=pin(encoded(context)),
        image_pin=pin(encoded(image)),image=observed_image,status='HOLD_DELEGATED_CURRENT_STAGE',commands=[],**FINAL)
    session=None;primary=None
    try:
        with open_session(delegation_raw=delegation_raw,delegation_sha256=delegation_sha256,context=context,image_report=image,
                          executor=executor,source_root=source,output=output,inputs=inputs) as session:
            f=session.facts
            need(f['operation']==OP and f['stage']==stage and f['binding']==b and f['nonce']==d['nonce'] and
                 f['delegation_pin']==pin(delegation_raw) and f['image']==observed_image['id'] and f['architecture']=='aarch64' and
                 type(f['page_size']) is int and f['page_size'] in (4096,16384),'same actual delegated owner session')
            need(f.get('context_pin')==pin(encoded(context)) and
                 f.get('context_program_pin')=={k:d['programs']['context'][k] for k in ('bytes','sha256')} and
                 f.get('context_issuer')==context['issuer'] and f.get('context_kind')==context['kind'],
                 'selected context provider validated the exact whole observation and program')
            need(session.native_pin==NATIVE_PIN and session.profile==profile and session.image==observed_image,'whole unmodified held native/helper/profile/image selection')
            report['owner_facts']=f;run=run_callback(session,c)
            if stage in ('backend','ui'):
                private=session.build_inputs['capacity']
                need(private['build_seconds']<=c['max_command_seconds'] and private['builder_cpus']==c['builder_cpus'] and
                     private['builder_memory_bytes']==c['builder_memory_bytes'] and private['builder_pids']==c['builder_pids'],'private plan within actual delegation')
                report['builds']=build_pairs(session,source,profile,stage,output/'builds',c)
            else:
                signed_domain();report['protected_before']=session.protected_before;report['signed']=session.signed
                need(set(session.signed)=={'setup8',*KINDS},'exact four current private signed inputs')
                retained=output/'signed';retained.mkdir(mode=0o700)
                for key,row in session.signed.items():
                    for field in ('archive','signature'):
                        raw=session.tools.ordinary(Path(row[field]),16*1024**2)
                        need(pin(raw)==row[field+'_pin'],'actual private signed material unchanged');(retained/(key+'.'+field)).write_bytes(raw)
                config=session.tools.ordinary(Path(session.pacman[1]),65536);(output/'signature-config.txt').write_bytes(config)
                report['signature_config_pin']=pin(config)
                report['lifecycle']=session.native.lifecycle(run,session.tools,profile,session.signed,session.pacman,
                    session.verifier,session.fingerprint,session.verify_state)
                report['protected_after']=session.protected_after()
                need(bool(report['protected_before']) and report['protected_before']==report['protected_after'],'actual protected local baseline restored')
        report['commands']=list(session.records)
        expected=dict(status='PENDING_OUTER_CONTAINER_RETIREMENT' if stage=='lifecycle' else 'PASS_DELEGATED_CURRENT_STAGE_RETIREMENT',
            operation=OP,stage=stage,binding=b,nonce=d['nonce'],natural_retirement=True,
            owned_container_absence_verified=stage!='lifecycle',protected_state_unchanged=True,**FINAL)
        report['owner_cleanup']=session.cleanup;need(session.cleanup==expected and
            all(type(session.cleanup[k]) is type(v) for k,v in expected.items()),'exact observed delegated cleanup, local lifecycle cannot assert absence')
        report['body_status']='PROVISIONAL_CURRENT_'+stage.upper()+'_DATA_ONLY'
        report['status']='PENDING_OUTER_CURRENT_STAGE_RETIREMENT' if stage=='lifecycle' else report['body_status']
    except BaseException as error:
        primary=error;report['failure']=dict(type=type(error).__name__,message=str(error)[:2048])
        if session is not None:report['commands']=list(session.records);report['owner_cleanup']=getattr(session,'cleanup',None)
        raise
    finally:
        try:
            raw=encoded(report);need(len(raw)<=4*1024**2,'finite delegated stage report')
            with (output/'route.json').open('xb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw)
        except BaseException:
            if primary is None:raise
    return report


if __name__=='__main__':raise SystemExit('Internal delegated owner adapter only; no standalone actor or authority')
