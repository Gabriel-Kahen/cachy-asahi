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
            if folder==root and n in ('.git','retained-public-inputs','retained574','retained-native-tools'):children.remove(n)
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

def bootstrap(args):
    _,own,tmp=admitted(args);work=Path(args.work);base=tmp/'desktop574'
    p=C.module(HERE/'prefill574.py','exact574_data_prefill')
    deadline=time.monotonic()+2290
    p.prefill(ROOT,ROOT/'retained574',base,deadline)
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

def cleanup(args):
    _,own,tmp=admitted(args);work=Path(args.work);actor=C.Actors(work/'cleanup-actors',300);removed=[]
    ids=actor.docker('ps','-aq','--no-trunc','--filter','label='+C.LABEL+'='+own['token']).split()
    base=load(work/'bootstrap.json') if (work/'bootstrap.json').exists() else None
    for cid in ids:
        row=json.loads(actor.docker('inspect',cid))[0]
        need(base is not None and row['Name']=='/'+own['consumer'] and row['Image']==base['image'] and
             row['Config']['Labels'].get(C.LABEL)==own['token'],'same owned consumer only')
        matches=[load(p) for p in work.glob('*/trial-*-inspection.json') if load(p)['Id']==cid]
        need(len(matches)==1 and matches[0]['Config']==row['Config'] and matches[0]['HostConfig']==row['HostConfig'],'owned finite consumer inspection receipt')
        actor.docker('rm','-f',cid);removed.append(cid)
    need(not actor.docker('ps','-aq','--no-trunc','--filter','label='+C.LABEL+'='+own['token']) and
         not actor.docker('ps','-aq','--no-trunc','--filter','name=^/'+own['consumer']+'$'),'all kit consumers absent before574 image retirement')
    core_report=tmp/'desktop574/report.json'
    if core_report.exists():
        actor.run([sys.executable,'-I','-B',ROOT/'scripts/ci/maintained_desktop574.py','cleanup','--inputs',ROOT/'scripts/ci/maintained-desktop574-inputs.json','--output',tmp/'desktop574','--job-token',own['token']],timeout=180)
        result=load(core_report);need(result['owned_cleanup']['status']=='PASS','original574 strict ownership cleanup')
    else:need(base is None,'missing original producer receipt')
    save(work/'ordered-cleanup.json',dict(status='PASS_CONSUMERS_ABSENT_THEN_ORIGINAL574_RETIRED',identity=own,removed=removed))

def retain(args):
    _,own,tmp=binding(args);work=Path(args.work);out=fresh(tmp/'offline-kit-accepted-public');total=0;files={}
    for path in sorted(work.rglob('*')):
        if not path.is_file() or path.is_symlink():continue
        rel=path.relative_to(work)
        if any(p in ('producer','signing','original-trust') for p in rel.parts):continue
        if 'system-snapshot' in rel.parts:continue
        if 'workspace' in rel.parts and 'system' in rel.parts and (work/rel.parts[0]/'candidate-output/candidate-exports.tar.gz').is_file():continue
        if any(part.startswith('.local-transaction-') for part in rel.parts):continue
        raw=read(path);total+=len(raw);need(total<=128*1024**2,'bounded public evidence no silent dropping')
        dst=out/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw);files[str(rel)]=dict(bytes=len(raw),sha256=sha(raw))
    for path in (tmp/'desktop574/report.json',tmp/'desktop574/installed-packages.lock',tmp/'desktop574/offline-kit-retained574-inputs.json'):
        if path.exists():
            raw=read(path);total+=len(raw);need(total<=128*1024**2,'bounded original574 evidence')
            name='producer574/'+path.name;dst=out/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw);files[name]=dict(bytes=len(raw),sha256=sha(raw))
    manifest=source(ROOT,args.manifest_sha256)
    for name in (*manifest['files'],MAP,*ALIASES):
        raw=read(ROOT/name);total+=len(raw);need(total<=128*1024**2,'bounded complete source evidence')
        dst=out/'source'/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw);files['source/'+name]=dict(bytes=len(raw),sha256=sha(raw))
    complete=(work/'kit-results.json').exists() and (work/'ordered-cleanup.json').exists()
    result=load(work/'kit-results.json') if complete else {}
    status='PASS_NATIVE_TWO_ACCEPTED_TOOLS_OFFLINE_KIT_FINITE_ALPM_ONLY' if complete and load(work/'ordered-cleanup.json')['status']=='PASS_CONSUMERS_ABSENT_THEN_ORIGINAL574_RETIRED' and result.get('status')=='PASS_TWO_ACTUAL_ACCEPTED_TOOLS_KITS_PENDING_CLEANUP' else 'INCOMPLETE_OR_FAILED'
    save(out/'result.json',dict(status=status,identity=own,files=files,bytes=total,export_trees='candidate-exports.tar.gz preserves all five post-commit snapshots and aliases per package; repeated working seeds omitted when capsule exists',private_paths='producer/signing/original-trust never exported',full_base_payload_installed=False,hardware='NOT_RUN',release='NOT_ADMITTED'))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('proof','bootstrap','run','cleanup','retain'))
    p.add_argument('--manifest-sha256',required=True);p.add_argument('--work',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    globals()[a.command](a)
if __name__=='__main__':main()
