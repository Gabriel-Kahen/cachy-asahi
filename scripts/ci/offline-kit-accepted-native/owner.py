#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed accepted native DATA kit owner. Only explicit native execution admits actors."""
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,stat,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LANE='scripts/ci/offline-kit-accepted-native'
MAP=LANE+'/source-map.json'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-offline-kit-accepted.yml')
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
COMMON_BYTES=(HERE/'owner_common.py').read_bytes()
if hashlib.sha256(COMMON_BYTES).hexdigest()!='785e4d7a1ebc77220ae7bbdacab3bae42bc7581d0ebcb7e6e109bcb4e4e44bf8':raise ValueError('pinned owner primitives')
spec=importlib.util.spec_from_file_location('_closed_owner_common',HERE/'owner_common.py');C=importlib.util.module_from_spec(spec);exec(compile(COMMON_BYTES,str(HERE/'owner_common.py'),'exec'),C.__dict__)
need,sha,read,load,save,fresh=C.need,C.sha,C.read,C.load,C.save,C.fresh

def source(root,pin):
    root=C.safe_path(root);raw=read(root/MAP)
    need(re.fullmatch('[0-9a-f]{64}',pin or '') and sha(raw)==pin,'complete source map pin')
    value=json.loads(raw);need(value['schema']==1 and value['actual'] is None,'source-only exact namespace')
    expected=set(value['files'])|{MAP,*ALIASES};seen=set();dirs=set()
    for folder,children,files in os.walk(root,followlinks=False):
        folder=Path(folder)
        for n in tuple(children):
            p=folder/n;need(not p.is_symlink(),'source directory symlink')
            if folder==root and n in ('.git','retained-public-inputs','retained-native-tools'):children.remove(n)
            else:dirs.add(p.relative_to(root).as_posix())
        for n in files:seen.add((folder/n).relative_to(root).as_posix())
    need(seen==expected and dirs=={p.as_posix() for n in expected for p in Path(n).parents if p!=Path('.')},'closed source namespace')
    for name,row in value['files'].items():
        p=Path(name);need(not p.is_absolute() and '..' not in p.parts,'source map path')
        raw=read(root/name)
        need(dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE((root/name).stat().st_mode))==row,'exact source: '+name)
    template=read(root/LANE/'workflow.yml.in').decode()
    rendered=template.replace('@MAP_SHA@',pin).replace('@OWNER_SHA@',value['files'][LANE+'/owner.py']['sha256']).encode()
    need(all(read(root/n)==rendered and stat.S_IMODE((root/n).stat().st_mode)==0o644 for n in ALIASES),'identical exact workflow aliases')
    need(stat.S_IMODE((root/MAP).stat().st_mode)==0o644,'fixed map mode')
    need(sha(read(root/LANE/'expected-packages.lock'))==LOCK,'accepted574 exact lock')
    pins=load(root/LANE/'feature-files.json')
    need(pins['scripts/release/release.py']['mode']==0o755,'reviewed release.py executable correction')
    for name,row in pins.items():need(value['files'][LANE+'/feature/'+name]==row,'whole feature closure')
    return value

def identity(env=None):
    e=os.environ if env is None else env;s=e.get('SOURCE_SHA','')
    need(re.fullmatch('[0-9a-f]{40}',s) and e.get('GITHUB_SHA')==e.get('GITHUB_WORKFLOW_SHA')==s,'exact workflow/product/input SHA')
    need(e.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and
         e.get('GITHUB_RUN_ATTEMPT')=='1' and re.fullmatch('[1-9][0-9]*',e.get('GITHUB_RUN_ID','')),'manual first attempt identity')
    need(any(e.get('GITHUB_WORKFLOW_REF','').startswith(e['GITHUB_REPOSITORY']+'/'+p+'@') for p in ALIASES),'registered workflow identity')
    token=sha((s+':'+e['GITHUB_RUN_ID']+':1:accepted-tools').encode())[:16]
    return dict(source_sha=s,feature_code_sha=s,run_id=e['GITHUB_RUN_ID'],token=token,
                consumer='offline-kit-accepted-'+token)

def binding(args,execute=False):
    manifest=source(ROOT,args.manifest_sha256);own=identity();tmp=C.safe_path(os.environ['RUNNER_TEMP'])
    need(Path(args.work)==tmp/'offline-kit-accepted-work' and not tmp.is_relative_to(ROOT) and not ROOT.is_relative_to(tmp),'fixed disjoint runtime path')
    if execute:
        need(args.execute and platform.system()=='Linux' and platform.machine() in ('aarch64','arm64') and os.getuid()==os.geteuid()!=0 and
             os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64','explicit ordinary native ARM actor')
        need(not any(k.startswith(('DOCKER_','LD_','CACHY_OLD_FOUR_','CACHY_RETAINED_')) for k in os.environ),'private/loader actor environment refused')
    return manifest,own,tmp

def proof(args):
    manifest,own,tmp=binding(args);work=fresh(args.work);work.chmod(0o700)
    save(work/'source-proof.json',dict(status='PASS_PRESECRET_COMPLETE_ACCEPTED_TOOLS_SOURCE',identity=own,map_sha256=args.manifest_sha256,files=len(manifest['files'])+3,native='NOT_RUN'))
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('job_token='+own['token']+'\n')

def admitted(args):
    manifest,own,tmp=binding(args,True)
    held=load(Path(args.work)/'source-proof.json')
    need(held['identity']==own and held['map_sha256']==args.manifest_sha256,'same presecret proof')
    return manifest,own,tmp

CARRIER_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
CARRIER_TREE='e21f947bac3afdfbd67e4e65c8234b35ae42b00f'
CARRIER_PROFILE='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
NATIVE_WORK_PATHS=('bootstrap-actors','bootstrap.json','kit-actors','maintenance','diagnostics',
    'kit-results.json','accepted-carrier','accepted-carrier.json','cleanup-actors')
NATIVE_BASE_PATHS=('report.json','image-id','probe-cid')


def transport(args):
    """One complete exact fetch directly outside the executable source; DATA only."""
    _,own,tmp=admitted(args);work=Path(args.work);carrier=C.safe_path(tmp/'offline-kit-retained574')
    need(not os.path.lexists(carrier) and not carrier.is_relative_to(ROOT) and not ROOT.is_relative_to(carrier),
         'fresh outside-source retained DATA path required')
    need(carrier.parent.stat().st_uid==os.getuid() and not carrier.parent.stat().st_mode&0o022,
         'owned external retained DATA parent required')
    receipt=work/'input-transport-owner.json';need(not os.path.lexists(receipt),'one-shot transport receipt required')
    raw=read(ROOT/'scripts/ci/retained-build-inputs/carrier-profile.json');profile=json.loads(raw)
    need(sha(raw)==CARRIER_PROFILE and profile['source']==CARRIER_SOURCE and len(profile['files'])==1154
         and sum(row['bytes'] for row in profile['files'].values())==1046432165,'full original retained profile required')
    report=dict(status='STARTED_RETAINED_INPUT_TRANSPORT_DATA',identity=own,carrier_path=str(carrier),
        carrier_source=CARRIER_SOURCE,profile_sha256=CARRIER_PROFILE,expected_carrier_files=1154,
        expected_carrier_bytes=1046432165,budget_seconds=480,retry=False,partial_data_retained=True,
        native='NOT_RUN',acceptance=False,authentication='ORIGINAL_COMPLETE_PREPARE_AND_NATIVE_SIGNATURE_AUDIT_STILL_REQUIRED')
    save(receipt,report)
    try:
        actor=C.Actors(work/'input-transport-actors',480);fresh(carrier).chmod(0o700)
        git=['git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true',
             '-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always']
        actor.run([*git,'init','--template=',str(carrier)],timeout=10)
        actor.run([*git,'-C',str(carrier),'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60',
            'fetch','--depth=1','--no-tags','--no-recurse-submodules',
            'https://github.com/Gabriel-Kahen/cachy-asahi.git',CARRIER_SOURCE],timeout=400)
        fetched=actor.run([*git,'-C',str(carrier),'rev-parse','--verify','FETCH_HEAD'],timeout=10)
        need(fetched==CARRIER_SOURCE,'exact fetched retained commit required')
        actor.run([*git,'-C',str(carrier),'checkout','--detach',CARRIER_SOURCE],timeout=45)
        head=actor.run([*git,'-C',str(carrier),'rev-parse','--verify','HEAD'],timeout=10)
        need(head==CARRIER_SOURCE,'exact retained DATA HEAD required')
        report.update(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY',carrier_head=head)
    except(Exception,KeyboardInterrupt)as error:
        report.update(status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',error=type(error).__name__+': '+str(error)[:2048]);raise
    finally:save(receipt,report)


def transport_receipt(work,own,tmp):
    transferred=load(work/'input-transport-owner.json')
    need(transferred['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY' and transferred['identity']==own
         and transferred['carrier_path']==str(tmp/'offline-kit-retained574')
         and transferred['carrier_source']==transferred['carrier_head']==CARRIER_SOURCE
         and transferred['profile_sha256']==CARRIER_PROFILE and transferred['expected_carrier_files']==1154
         and transferred['expected_carrier_bytes']==1046432165 and transferred['budget_seconds']==480
         and transferred['retry']is False and transferred['partial_data_retained']is True
         and transferred['native']=='NOT_RUN' and transferred['acceptance']is False
         and transferred['authentication']=='ORIGINAL_COMPLETE_PREPARE_AND_NATIVE_SIGNATURE_AUDIT_STILL_REQUIRED',
         'same-owner full exact retained transport DATA required')
    need(read(work/'phase-logs/transport.exit-code')==b'0\n','successful raw transport phase required')
    read(work/'phase-logs/transport.stdout');read(work/'phase-logs/transport.stderr')
    return transferred


def prepared_receipt(base,transferred):
    prepared=load(base/'offline-kit-retained574-inputs.json');joined=prepared['carrier']
    need(prepared['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'
         and joined['status']=='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY'
         and prepared['source']==joined['source']==transferred['carrier_source']==CARRIER_SOURCE
         and joined['ref']=='codex/native574-complete-retained-inputs-v1' and joined['tree']==CARRIER_TREE
         and type(joined['files'])is type(joined['blob_joins'])is int and joined['files']==joined['blob_joins']==1154
         and prepared['mode']=='desktop574' and prepared['actual']is None
         and prepared['receipt']['actual_authority']is False
         and prepared['receipt']['cache']['all_previous_inode_metadata_bytes_unchanged']is True,
         'unchanged full1154 Git/blob preparation and cache preservation required')
    return prepared


def transport_failed_cleanup(work,own,tmp):
    receipt=work/'input-transport-owner.json'
    native=any(os.path.lexists(work/n)for n in NATIVE_WORK_PATHS) or any(
        os.path.lexists(tmp/'desktop574'/n)for n in NATIVE_BASE_PATHS)
    target=work/'ordered-cleanup.json'
    if not os.path.lexists(receipt):
        if native:return False
        code_path=work/'phase-logs/transport.exit-code';code=None
        if os.path.lexists(code_path):
            raw=read(code_path);need(re.fullmatch(rb'[1-9][0-9]*\n',raw) and int(raw)<=255,
                 'missing transport receipt cannot accompany a successful raw phase')
            code=int(raw)
        need(not os.path.lexists(target),'fresh pre-native diagnostic required')
        save(target,dict(status='INPUT_TRANSPORT_NOT_ESTABLISHED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY',identity=own,
            transport_receipt_sha256=None,transport_phase_exit=code,partial_carrier_path=str(tmp/'offline-kit-retained574'),
            carrier_ownership='UNKNOWN_OR_NOT_ESTABLISHED',partial_data_preserved=True,native='NOT_RUN',
            native_cleanup='NOT_ESTABLISHED',acceptance=False,
            transport_process_scope='NO_LIVE_RECHECK_OR_NATIVE_ABSENCE_CREDIT'))
        return True
    transferred=load(receipt)
    if transferred.get('status')=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY':
        if native:return False
        transport_receipt(work,own,tmp)
        need(not os.path.lexists(target),'fresh pre-native DATA diagnostic required')
        save(target,dict(status='INPUT_TRANSPORT_COMPLETED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY',identity=own,
            transport_receipt_sha256=sha(read(receipt)),transport_phase_exit=0,
            partial_carrier_path=str(tmp/'offline-kit-retained574'),partial_data_preserved=True,
            native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False,
            transport_process_scope='NO_LIVE_RECHECK_OR_NATIVE_ABSENCE_CREDIT'))
        return True
    need(transferred.get('status')in('STARTED_RETAINED_INPUT_TRANSPORT_DATA','FAIL_RETAINED_INPUT_TRANSPORT_DATA'),
         'known input transport status required before cleanup')
    need(not native,'native evidence prohibits passive failed-transport diagnostic')
    need(transferred['identity']==own and transferred['carrier_path']==str(tmp/'offline-kit-retained574')
         and transferred['carrier_source']==CARRIER_SOURCE and transferred['acceptance']is False,
         'same-owner external failed transport required')
    code=read(work/'phase-logs/transport.exit-code');need(re.fullmatch(rb'[1-9][0-9]*\n',code) and int(code)<=255,
         'failed raw transport status required for diagnostic')
    read(work/'phase-logs/transport.stdout');read(work/'phase-logs/transport.stderr')
    need(not os.path.lexists(target),'fresh transport diagnostic required')
    save(target,dict(status='INPUT_TRANSPORT_FAILED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY',identity=own,
        transport_receipt_sha256=sha(read(receipt)),partial_carrier_path=str(tmp/'offline-kit-retained574'),
        partial_data_preserved=True,native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False,
        transport_process_scope='CONSULT_RETAINED_ACTOR_RECEIPTS_NO_LIVE_RECHECK_OR_NATIVE_ABSENCE_CREDIT'))
    return True


def bootstrap(args):
    _,own,tmp=admitted(args);work=Path(args.work);base=tmp/'desktop574'
    transferred=transport_receipt(work,own,tmp)
    p=C.module(HERE/'prefill574.py','exact574_data_prefill')
    deadline=time.monotonic()+2290
    p.prefill(ROOT,tmp/'offline-kit-retained574',base,deadline)
    prepared_receipt(base,transferred)
    producer=C.module(ROOT/'scripts/ci/maintained_desktop574.py','exact574_core')
    inputs=load(ROOT/'scripts/ci/maintained-desktop574-inputs.json')
    package_names={row['filename'] for row in inputs['packages']}
    package_names |= {n+'.sig' for n in package_names}
    for row in producer.plan(inputs,base/'context'):
        if row['filename'] not in package_names:continue
        raw=read(row['target'],max(row['size'],16*1024**2))
        need(len(raw)==row['size'] and sha(raw)==row['sha256'],'all1148 retained package/signature inputs complete before core')
    actor=C.Actors(work/'bootstrap-actors',max(1,int(deadline-time.monotonic())))
    actor.run([sys.executable,'-I','-B',ROOT/'scripts/ci/maintained_desktop574.py','build','--inputs',
               ROOT/'scripts/ci/maintained-desktop574-inputs.json','--output',base,'--job-token',own['token']],timeout=max(1,int(deadline-time.monotonic())))
    result=load(base/'report.json');need(result['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and sha(read(base/'installed-packages.lock'))==LOCK,'actual accepted574 producer inventory')
    save(work/'bootstrap.json',dict(status='PASS_ACTUAL_FRESH_ACCEPTED574_PRODUCER',identity=own,image=result['image']))

def accepted_carrier(directory,output):
    """External published carrier supplies DATA only, exactly equal to closed pins."""
    need(sha(read(directory/'FILES.json'))=='90debc7e293cfa34cda36f5ea1b8b968c43942134e4d40253963c3568e1c35cb','published carrier inventory pin')
    expected={p.name:read(p) for p in (HERE/'accepted').iterdir()}
    need({p.name for p in directory.iterdir() if p.name!='.git'}==set(expected),'published carrier exact23 leaf namespace')
    fresh(output)
    for name,raw in expected.items():
        need(read(directory/name)==raw,'published carrier body differs: '+name)
        path=output/name;path.write_bytes(raw);path.chmod(0o644)
    need(sum(len(b) for b in expected.values())==453417,'published carrier exact byte count')
    return dict(source='08638af367190fb437c04c5f460703388dc19c78',tree='88a82a9217c5078d6987e04ccc17a439e8192a9f',
        ref='codex/native-tools-accepted-source-inputs-v1',files=23,bytes=453417,
        inventory_sha256='90debc7e293cfa34cda36f5ea1b8b968c43942134e4d40253963c3568e1c35cb',actual_authority=False)

def run(args):
    manifest,own,tmp=admitted(args);work=Path(args.work);base=load(work/'bootstrap.json')
    need(base['identity']==own and base['status']=='PASS_ACTUAL_FRESH_ACCEPTED574_PRODUCER','same actual574 producer')
    core=C.module(ROOT/'scripts/ci/maintained_desktop574.py','selected574_image')
    need(core.inspect_image(base['image'],own['token'])['Id']==base['image'],'owned immutable574 image')
    actor=C.Actors(work/'kit-actors',4500);results={}
    data=work/'accepted-carrier'
    carrier=accepted_carrier(ROOT/'retained-native-tools',data)
    save(work/'accepted-carrier.json',carrier)
    for short in ('maintenance','diagnostics'):
        current=fresh(work/short);current.chmod(0o700)
        trial=fresh(current/'trial');trial.chmod(0o700)
        save(trial/'identity.json',dict(identity=own,image=base['image'],packages_sha256=LOCK,accepted_carrier=carrier))
        shutil.copyfile(HERE/'expected-packages.lock',trial/'packages.lock')
        selected=dict(own,accepted_tool=short)
        mounts=[('/feature',str(HERE/'feature'),False),('/trial-code',str(HERE/'trial-code'),False),
                ('/accepted',str(data),False),('/trial',str(trial),True)]
        C.trial_actor(actor,selected,base['image'],current,'produce',mounts)
        need(not (trial/'producer').exists() and not (trial/'signing').exists(),'actual producer/key absence before receiver')
        public=trial/'public';receiver=fresh(current/'receiver');receiver.chmod(0o700)
        C.trial_actor(actor,selected,base['image'],current,'receive',[
            ('/trial-code',str(HERE/'trial-code'),False),('/media',str(public/'transport'),False),('/trusted',str(public/'trust'),False),('/result',str(receiver),True)])
        received=load(receiver/'receiver.json')
        need(received['status']=='PASS_RELOCATED_NATIVE_DEVELOPMENT_VERIFY_AND_PROPOSED_PLAN' and received['packages_installed'] is False,'real offline receiver refusal/source export result')
        closed=HERE/'candidate-source'
        selector=C.module(HERE/'select_candidate.py','exact_candidate_selector')
        selection=selector.make(closed,public/'transport',public/'trust',own,base['image'])
        inputs=fresh(current/'candidate-inputs');save(inputs/'candidate-selection.json',selection)
        output=fresh(current/'candidate-output');output.chmod(0o700);(output/'client-state').mkdir(mode=0o700)
        selected.update(candidate_nonce=selection['nonce'],candidate_selection_sha=sha(read(inputs/'candidate-selection.json')))
        C.trial_actor(actor,selected,base['image'],current,'candidate',[
            ('/trial-code',str(HERE/'trial-code'),False),('/source',str(closed),False),('/inputs',str(inputs),False),
            ('/builder-packages.lock',str(HERE/'expected-packages.lock'),False),('/media',str(public/'transport'),False),('/out',str(output),True)])
        actual=load(output/'candidate-lifecycle.json')
        need(actual['status']=='PASS_FINITE_REAL_CANDIDATE_DISPOSABLE_ALPM_LIFECYCLE' and actual['original574_database_restored'] is True and
             len(actual['events'])==5 and len(actual['offline_authentication_refusal_recovery'])==3,'actual finite lifecycle and recovery')
        results[short]=dict(receiver=received,lifecycle=actual,producer=load(public/'producer.json'))
        save(work/'kit-results.json',dict(status='PARTIAL',identity=own,packages=results))
    save(work/'kit-results.json',dict(status='PASS_TWO_ACTUAL_ACCEPTED_TOOLS_KITS_PENDING_CLEANUP',identity=own,packages=results,full_base_payload_installed=False,hardware='NOT_RUN',release='NOT_ADMITTED'))

def same_consumer_inspection(saved,current):
    """Only Docker's observed false/null OOM default may change across stop."""
    if type(saved) is not dict or type(current) is not dict:
        return False
    for name in ('Id','Name','Image'):
        if type(saved.get(name)) is not str or saved[name]!=current.get(name):
            return False
    if any(type(row.get(name)) is not dict for row in (saved,current) for name in ('Config','HostConfig')):
        return False
    hosts=[]
    for row in (saved,current):
        host=dict(row['HostConfig'])
        if 'OomKillDisable' not in host or not (host['OomKillDisable'] is False or host['OomKillDisable'] is None):
            return False
        host['OomKillDisable']=False
        hosts.append(host)
    before,after=(saved['Config'],hosts[0]),(current['Config'],hosts[1])
    try:
        return before==after and json.dumps(before,sort_keys=True,allow_nan=False)==json.dumps(after,sort_keys=True,allow_nan=False)
    except (TypeError,ValueError):
        return False

def cleanup(args):
    _,own,tmp=admitted(args);work=Path(args.work)
    if transport_failed_cleanup(work,own,tmp):return
    actor=C.Actors(work/'cleanup-actors',300);removed=[]
    ids=actor.docker('ps','-aq','--no-trunc','--filter','label='+C.LABEL+'='+own['token']).split()
    base=load(work/'bootstrap.json') if (work/'bootstrap.json').exists() else None
    for cid in ids:
        row=json.loads(actor.docker('inspect',cid))[0]
        need(base is not None and row['Name']=='/'+own['consumer'] and row['Image']==base['image'] and
             row['Config']['Labels'].get(C.LABEL)==own['token'],'same owned consumer only')
        matches=[load(p) for p in work.glob('*/trial-*-inspection.json') if load(p)['Id']==cid]
        need(len(matches)==1 and same_consumer_inspection(matches[0],row),'owned finite consumer inspection receipt')
        actor.docker('rm','-f',cid);removed.append(cid)
    need(not actor.docker('ps','-aq','--no-trunc','--filter','label='+C.LABEL+'='+own['token']) and
         not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+own['consumer']+'$'),'all kit consumers absent before574 image retirement')
    core_report=tmp/'desktop574/report.json'
    if os.path.lexists(core_report):
        load(core_report)  # Ordinary original ownership DATA is required before its cleanup actor.
        actor.run([sys.executable,'-I','-B',ROOT/'scripts/ci/maintained_desktop574.py','cleanup','--inputs',ROOT/'scripts/ci/maintained-desktop574-inputs.json','--output',tmp/'desktop574','--job-token',own['token']],timeout=180)
        result=load(core_report);need(result['owned_cleanup']['status']=='PASS','original574 strict ownership cleanup')
    else:raise ValueError('missing original producer ownership report cannot establish native cleanup')
    save(work/'ordered-cleanup.json',dict(status='PASS_CONSUMERS_ABSENT_THEN_ORIGINAL574_RETIRED',identity=own,removed=removed))

PUBLIC_FILE_LIMIT=16*1024**2
PUBLIC_TOTAL_LIMIT=128*1024**2
PUBLIC_RESULT_RESERVE=2*1024**2
PUBLIC_FILE_COUNT=2048
RETENTION_STEPS=('install','reinstall','remove','reinstall-after-remove','final-remove')


def public_names(manifest):
    """Finite public metadata/media names; raw installed trees have no role here."""
    names=set(('source-proof.json','bootstrap.json','accepted-carrier.json','input-transport-owner.json',
               'ordered-cleanup.json','kit-results.json'))
    for root in ('bootstrap-actors','cleanup-actors','kit-actors','input-transport-actors'):
        names.add(root+'/actors.json')
        names.update(root+f'/{i:04d}.log' for i in range(100))
    names.update('phase-logs/transport.'+suffix for suffix in ('stdout','stderr','exit-code'))
    accepted=LANE+'/accepted/'
    names.update('accepted-carrier/'+n[len(accepted):] for n in manifest['files'] if n.startswith(accepted))
    for short,package,version,prefix in (
            ('maintenance','cachy-asahi-maintenance','0.1.0-2','maintenance'),
            ('diagnostics','cachy-asahi-session-diagnostics','0.1.0-3','session')):
        names.add(short+'/candidate-inputs/candidate-selection.json')
        for phase in ('produce','receive','candidate'):
            names.update(short+'/trial-'+phase+'-'+suffix+'.json' for suffix in ('inspection','stopped','absence'))
        receiver=short+'/receiver/'
        names.update(receiver+n+'.json' for n in ('client-verify','client-plan','higher-real-checkpoint',
            'hypothetical-remove-plan','receiver','refusals','source-lookup-export'))
        names.add(receiver+'state/checkpoint.json')
        names.update(receiver+'logs/'+label+'.json' for label in ('good','expired','tampered','wrong-key'))
        names.update(receiver+'source-export/'+package+'-'+suffix for suffix in
            ('LICENSE','NOTICE','PKGBUILD','existing-review','source-map.json','source.tar'))
        names.add(receiver+'source-export/source-delivery-receipt.json')
        names.update(short+'/trial/'+n for n in ('identity.json','packages.lock'))
        public=short+'/trial/public/'
        names.update(public+n for n in ('assembly.json','producer-path-absence.json','producer.json','source-pack.json','staging.json','transport.tar.gz'))
        names.update(public+'producer-logs/'+n+'.json' for n in
            ('key-agent-cleanup','key-generation','original-key-dearmor','original-signature','wrong-key-generation'))
        names.update(public+'trust/'+n for n in ('higher.json','higher.json.sig','pins.json','plan_bridge.py'))
        release=('base.json','release.json','release.json.sig','spec.json','project-license.txt',
            'provenance/'+package+'.json','repo/'+package+'-'+version+'-any.pkg.tar.xz',
            'repo/'+package+'-'+version+'-any.pkg.tar.xz.sig',
            'repo/offline-native-test.db.tar.gz','repo/offline-native-test.db.tar.gz.sig',
            'repo/offline-native-test.files.tar.gz','repo/offline-native-test.files.tar.gz.sig')
        evidence=('accepted-native-component.json','integration.lock.json','original-signature-verification.json','source-delivery.json')
        evidence+=tuple(package+'-'+suffix for suffix in ('LICENSE','NOTICE','PKGBUILD','source-map.json','existing-review','source.tar'))
        evidence+=('original-'+package+'-'+version+'-any.pkg.tar.xz.sig',)
        evidence+=tuple('original-'+short+'.'+suffix for suffix in ('TEST-original-status.txt','TEST-public.asc','provenance.json'))
        for label in ('good','expired','tampered','wrong-key','bootstrap-tampered'):
            root=public+'transport/'+label+'/'
            names.update(root+n for n in ('development.json','development.json.sig','kit.json','public.gpg','receiver-license.txt',
                'scripts/client/client.py','scripts/release/offline_kit.py','scripts/release/source_delivery.py'))
            names.update(root+'release/'+n for n in release)
            names.update(root+'release/evidence/'+n for n in evidence)
        output=short+'/candidate-output/'
        names.update(output+n for n in ('candidate-lifecycle.json','candidate-exports.tar.gz','candidate-partial.tar.gz',
            'candidate-partial.json','candidate-retention.json','offline-refusal-recovery.json','client-state/checkpoint.json'))
        for step in RETENTION_STEPS:
            phase=output+'phase-'+prefix+'-'+step+'/'
            names.update(phase+n for n in ('contract.json','worker-command.json','supervisor-logs/worker.log'))
            names.update(phase+'workspace/evidence/'+n for n in ('result.json','authentication-command.json','supervisor-command.log',
                'alpm.log','candidate-packages.lock','installed-packages.lock'))
    return names


def public_aliases():
    aliases={}
    for short in ('maintenance','diagnostics'):
        for label in ('good','expired','tampered','wrong-key','bootstrap-tampered'):
            for suffix in ('db','files'):
                for signature in ('','.sig'):
                    root=short+'/trial/public/transport/'+label+'/release/repo/'
                    aliases[root+'offline-native-test.'+suffix+signature]='offline-native-test.'+suffix+'.tar.gz'+signature
    return aliases


def portable_public(name):
    return type(name) is str and len(name)<=256 and all(
        part not in ('','.','..') and re.fullmatch('[A-Za-z0-9@+_.-]+',part) for part in name.split('/'))


def private_retention(parts):
    return any(part in ('producer','signing','original-trust','system-snapshot') or
               part.startswith('.local-transaction-') for part in parts) or any(
               parts[i:i+2]==('workspace','system') for i in range(len(parts)-1))


def partial_retention(current,own):
    """Retain only a validated DATA capsule; never expose its raw source trees."""
    output=current/'candidate-output'
    if not os.path.lexists(output):return None
    C.safe_path(output);need(output.is_dir(),'ordinary candidate output required')
    report=output/'candidate-lifecycle.json';full=output/'candidate-exports.tar.gz'
    if os.path.lexists(report) and os.path.lexists(full):
        value=load(report)
        if value.get('status')=='PASS_FINITE_REAL_CANDIDATE_DISPOSABLE_ALPM_LIFECYCLE':
            need(sha(read(full))==value['export_capsule_sha256'],'held successful export capsule pin')
            need(not any(os.path.lexists(output/n) for n in ('candidate-partial.tar.gz','candidate-partial.json')),
                 'unexpected partial pair beside successful export quarantined')
            return None
    partial=output/'candidate-partial.tar.gz';metadata=output/'candidate-partial.json'
    roots=[output/('phase-'+prefix+'-'+step)/'workspace'/role for prefix in ('maintenance','session')
        for step in RETENTION_STEPS for role in ('system','evidence/system-snapshot')]
    if not any(os.path.lexists(p) for p in (*roots,partial,metadata)):return None
    selected=read(current/'candidate-inputs/candidate-selection.json');selection=json.loads(selected)
    need(selection['source_commit']==own['source_sha'] and selection['feature_code_sha']==own['feature_code_sha'],
         'partial DATA selected source context')
    context=dict(source_commit=own['source_sha'],feature_code_sha=own['feature_code_sha'],
        selection_sha256=sha(selected),package=selection['candidate']['package'])
    helper=C.module(HERE/'candidate-source/candidate_lifecycle.py','retained_partial_data_helper')
    if not os.path.lexists(partial) and not os.path.lexists(metadata):helper.retain_partial(output,context)
    need(os.path.lexists(partial) and os.path.lexists(metadata),'complete partial capsule/manifest pair required')
    marker=read(metadata,2*1024**2);capsule=read(partial)
    need(helper.verify_partial(output,context)==json.loads(marker),'verified partial manifest changed')
    need(read(metadata,2*1024**2)==marker and read(partial)==capsule,'verified partial pair changed')
    return dict(status='VERIFIED_PARTIAL_DATA_ONLY',acceptance=False,manifest_bytes=len(marker),capsule_bytes=len(capsule),
        manifest_sha256=sha(marker),capsule_sha256=sha(capsule))


def retain(args):
    manifest,own,tmp=binding(args);work=Path(args.work);out=fresh(tmp/'offline-kit-accepted-public')
    total=0;files={};attempted=set();errors=[];error_count=0;partial={};eligible=False
    def failed(stage,name,error):
        nonlocal error_count
        error_count+=1
        if len(errors)<64:errors.append(dict(stage=stage,path=str(name)[:256],error_type=type(error).__name__,error=str(error)[:384]))
    def emit(path,name,expected=None):
        nonlocal total
        dst=None;attempted.add(name)
        try:
            need(portable_public(name),'nonportable public path refused')
            need(len(files)<PUBLIC_FILE_COUNT and name not in files,'bounded unique public file set')
            raw=read(path,PUBLIC_FILE_LIMIT)
            if expected is not None:
                need(len(raw)==expected['bytes'] and sha(raw)==expected['sha256'],'source/evidence body pin differs')
                if 'mode' in expected:need(stat.S_IMODE(path.stat().st_mode)==expected['mode'],'source mode differs')
            need(total+len(raw)<=PUBLIC_TOTAL_LIMIT-PUBLIC_RESULT_RESERVE,'bounded public bytes with result reserve')
            dst=out/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw)
            files[name]=dict(bytes=len(raw),sha256=sha(raw));total+=len(raw)
        except Exception as error:
            if dst is not None:
                try:dst.unlink(missing_ok=True)
                except OSError as cleanup_error:failed('partial-copy-cleanup',name,cleanup_error)
            failed('copy',name,error)
    try:
        # Source and concrete raw actor/worker evidence precede optional media/capsules.
        for name,row in manifest['files'].items():emit(ROOT/name,'source/'+name,row)
        try:
            map_raw=read(ROOT/MAP);emit(ROOT/MAP,'source/'+MAP,dict(bytes=len(map_raw),sha256=args.manifest_sha256,mode=0o644))
        except Exception as error:failed('source-map',MAP,error)
        try:
            template=read(ROOT/LANE/'workflow.yml.in').decode()
            rendered=template.replace('@MAP_SHA@',args.manifest_sha256).replace('@OWNER_SHA@',manifest['files'][LANE+'/owner.py']['sha256']).encode()
            for name in ALIASES:emit(ROOT/name,'source/'+name,dict(bytes=len(rendered),sha256=sha(rendered),mode=0o644))
        except Exception as error:failed('source-aliases','workflows',error)
        C.safe_path(work);work_info=work.lstat()
        need(stat.S_ISDIR(work_info.st_mode) and work_info.st_uid==os.getuid() and not work_info.st_mode&0o022,
             'ordinary owned private work root required')
        allowed=public_names(manifest);aliases=public_aliases()
        critical=lambda n:n.parts[0] in ('bootstrap-actors','cleanup-actors','kit-actors','input-transport-actors','phase-logs') or 'supervisor-logs' in n.parts or n.name=='worker-command.json' or ('evidence' in n.parts and n.name in ('result.json','supervisor-command.log'))
        critical_paths=[Path(n) for n in allowed if critical(Path(n)) and os.path.lexists(work/n)]
        kit_logs=[p for p in critical_paths if p.parts[0]=='kit-actors' and p.stem.isdecimal()]
        latest=max(kit_logs,key=lambda p:int(p.stem)) if kit_logs else None
        def priority(path):
            return (0 if path.name=='actors.json' else 1 if path==latest else
                2 if path.parts[0] not in ('bootstrap-actors','cleanup-actors','kit-actors','input-transport-actors','phase-logs') else 3,path.as_posix())
        for rel in sorted(critical_paths,key=priority):emit(work/rel,rel.as_posix())
        for short in ('maintenance','diagnostics'):
            try:
                value=partial_retention(work/short,own)
                if value is not None:partial[short]=value
            except Exception as error:failed('partial-capsule',short,error)
        directories={str(p) for n in allowed|set(aliases) for p in Path(n).parents if p!=Path('.')}
        paths=[];nodes=0;pending=[work]
        while pending:
            folder=pending.pop();entries=[]
            try:
                with os.scandir(folder) as stream:
                    for entry in stream:
                        nodes+=1;need(nodes<=20000,'bounded public namespace scan exceeded');entries.append(entry)
            except OSError as error:failed('walk',folder.relative_to(work),error);continue
            for entry in sorted(entries,key=lambda e:e.name):
                path=Path(entry.path);rel=path.relative_to(work)
                if private_retention(rel.parts):continue
                if entry.is_dir(follow_symlinks=False):
                    if not portable_public(rel.as_posix()) or rel.as_posix() not in directories:
                        failed('namespace',rel,ValueError('unlisted/nonordinary public directory refused'))
                    else:pending.append(path)
                    continue
                if path.is_symlink() and aliases.get(rel.as_posix())==os.readlink(path):continue
                if rel.as_posix() not in allowed or not portable_public(rel.as_posix()):
                    failed('namespace',rel,ValueError('unlisted/nonportable public file refused'));continue
                paths.append(rel)
        accepted=LANE+'/accepted/'
        for rel in paths:
            name=rel.as_posix()
            if name in attempted:continue
            expected=manifest['files'].get(accepted+name[len('accepted-carrier/'):]) if name.startswith('accepted-carrier/') else None
            if len(rel.parts)==3 and rel.parts[1]=='candidate-output' and rel.name in ('candidate-partial.tar.gz','candidate-partial.json'):
                verified=partial.get(rel.parts[0])
                if not verified or verified['status']!='VERIFIED_PARTIAL_DATA_ONLY':continue
                kind='capsule' if rel.name.endswith('.tar.gz') else 'manifest'
                expected=dict(bytes=verified[kind+'_bytes'],sha256=verified[kind+'_sha256'])
            emit(work/rel,name,expected)
        for short in tuple(partial):
            pair=[short+'/candidate-output/'+n for n in ('candidate-partial.json','candidate-partial.tar.gz')]
            if not all(n in files for n in pair):
                for name in pair:
                    if name in files:
                        try:(out/name).unlink();total-=files.pop(name)['bytes']
                        except OSError as error:failed('partial-copy-cleanup',name,error)
                partial.pop(short);failed('partial-capsule',short,ValueError('incomplete copied partial pair quarantined'))
        for name in ('report.json','installed-packages.lock','offline-kit-retained574-inputs.json'):
            path=tmp/'desktop574'/name
            if os.path.lexists(path):emit(path,'producer574/'+name)
        complete=(work/'kit-results.json').exists() and (work/'ordered-cleanup.json').exists()
        result=load(work/'kit-results.json') if complete else {}
        if complete and result.get('status')=='PASS_TWO_ACTUAL_ACCEPTED_TOOLS_KITS_PENDING_CLEANUP':
            transferred=transport_receipt(work,own,tmp);prepared_receipt(tmp/'desktop574',transferred)
        eligible=complete and load(work/'ordered-cleanup.json')['status']=='PASS_CONSUMERS_ABSENT_THEN_ORIGINAL574_RETIRED' and result.get('status')=='PASS_TWO_ACTUAL_ACCEPTED_TOOLS_KITS_PENDING_CLEANUP'
    except Exception as error:failed('retain','public',error)
    status='PASS_NATIVE_TWO_ACCEPTED_TOOLS_OFFLINE_KIT_FINITE_ALPM_ONLY' if eligible and not error_count else 'INCOMPLETE_OR_FAILED'
    record=dict(status=status,identity=own,files=files,bytes=total,retention_complete=not error_count,
        retention_errors=errors,retention_error_count=error_count,partial_capsules=partial,
        export_trees='candidate-exports.tar.gz holds successful five-phase snapshots; candidate-partial.tar.gz holds only observed failed-run DATA; raw system trees never copied',
        private_paths='producer/signing/original-trust/.local-transaction-* and all raw workspace/system/system-snapshot paths excluded',
        full_base_payload_installed=False,hardware='NOT_RUN',release='NOT_ADMITTED')
    if status=='INCOMPLETE_OR_FAILED':record.update(acceptance=False,native='NOT_ADMITTED')
    need(len((json.dumps(record,indent=2,sort_keys=True)+'\n').encode())<=PUBLIC_RESULT_RESERVE,'bounded reserved public result')
    save(out/'result.json',record)
    need(not error_count,'public retention incomplete; see retained result.json')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('proof','transport','bootstrap','run','cleanup','retain'))
    p.add_argument('--manifest-sha256',required=True);p.add_argument('--work',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    globals()[a.command](a)
if __name__=='__main__':main()
