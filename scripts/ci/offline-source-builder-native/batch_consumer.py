# SPDX-License-Identifier: MIT
"""Finite real CLI consumer; actor execution requires the parent's admitted owner.

This module supplies no builder adapter, guessed provider, source acquisition,
package installation, publication, or source-pin exception.
"""
import fcntl
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading

INTERFACE='offline-build-v2'
KIND='PINNED_OCI_BUILD_V2_OFFLINE_SOURCES'
FEATURE='53a76b00df09ce8072c65d967e3346e799a679b0'
NAMES=('cachy-asahi-zlib-baseline','cachy-asahi-zlib-lto')
DOCKER=('/usr/bin/docker','--host=unix:///var/run/docker.sock')


def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def fresh_bytes(path,raw):
    with Path(path).open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def save(path,value):
    fresh_bytes(path,encoded(value))


def feature_guard(args,O,own):
    need(own.get('feature_code_sha')==args.feature_code_sha==FEATURE,'exact selected v2 batch feature revision required')
    feature=Path(O.feature_root())
    O.feature_files(feature)
    return feature


def provider_command(source,work,image,own,owner,label):
    command=[*DOCKER,'run','--rm','--name',owner['name'],'--label',label+'='+owner['token'],
        '--label',own['label']+'='+own['token'],'--pull=never','--platform=linux/arm64','--network=none',
        '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit','128',
        '--memory','1g','--cpus','1','--user',f'{os.getuid()}:{os.getgid()}',
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=64m',
        '--env','CACHY_BATCH_ALPM_CAPTURE=1','--env','CACHY_BATCH_IMAGE='+image]
    for root in owner['mount_roots']:
        command+=['--mount','type=bind,src='+root+',dst='+root+',readonly']
    return command+['--entrypoint','/usr/bin/python3',image,'-I','-B',
        str(source/'scripts/ci/offline-source-builder-native/capture_installed.py'),
        '--request',str(work/'installed-provider-capture-request.json')]


def actor_capture(O,actor,root,helper):
    """Wrap the fixed separate-stream helper in the owner's child-group supervisor."""
    def capture(argv,seconds):
        index=len(actor.rows);request=root/f'{index:04d}.request.json';output=root/f'{index:04d}'
        save(request,dict(argv=list(argv),timeout=seconds))
        actor.run([sys.executable,'-I','-B',str(helper),'--request',str(request),'--output',str(output)],timeout=seconds+5)
        receipt=O.load(output/'receipt.json')
        need(type(receipt.get('schema_version'))is int and receipt['schema_version']==1 and receipt['argv']==list(argv)
             and type(receipt.get('returncode'))is int,'observed CLI capture identity differs')
        streams={name:O.read(output/name) for name in('stdout','stderr')}
        need(receipt['streams']=={n:dict(bytes=len(raw),sha256=O.sha(raw))for n,raw in streams.items()},'capture stream receipt differs')
        return subprocess.CompletedProcess(argv,receipt['returncode'],streams['stdout'],streams['stderr'])
    return capture


def planner_capture(actor):
    def capture(argv,timeout=20):
        value=actor.run(argv,timeout=timeout,allowed=(0,1))
        code=actor.rows[-1]['exit']
        return subprocess.CompletedProcess(argv,code,value.encode(),b'')
    return capture


def provider_capture(args,O,own,feature,image,G,T,actor,command_root):
    source,work=Path(args.source_root),Path(args.work)
    request=G.provider_request(source,image)
    save(work/'installed-provider-capture-request.json',request)
    token=os.urandom(16).hex()
    owner=dict(name='offline-batch-plan-'+token,token=token,image=image,mount_roots=[str(source),str(work)],
        purpose='readonly-installed-provider-capture',identity=own)
    save(command_root/'provider-owner.json',owner)
    supplied=dict(own,label=O.LABEL)
    command=provider_command(source,work,image,supplied,owner,T.LABEL)
    save(command_root/'provider-command.json',dict(argv=command,owner=owner))
    log=Path(actor.directory)/'installed-provider-capture.log'
    try:
        actor.run(command,log=log,timeout=100)
        raw=O.read(log)
        need(len(raw)<=4*1024**2,'installed provider stdout bound')
        parsed=json.loads(raw)
        need(type(parsed)is dict and parsed.get('status')=='CAPTURED_INSTALLED_ALPM_SELECTIONS_ONLY','actual provider capture did not complete')
        # Actors.run supervises a merged stdout/stderr stream. The qualified
        # collector writes this canonical JSON once on success, with no other
        # output. Never pass extra merged bytes off as its exact stdout.
        need(raw==G.encoded(parsed),'provider merged stream differs from exact canonical collector stdout')
        save(work/'installed-provider-capture-origin.json',dict(schema_version=1,
            status='SUPERVISED_MERGED_STREAM_EQUALS_CANONICAL_COLLECTOR_STDOUT',
            supervised_log_path=str(log),supervised_log_sha256=O.sha(raw),
            stream_origin='owner.Actors.run merges stdout and stderr',separate_streams_captured=False,
            acceptance_rule='Exact byte equality with batch_graph.encoded(parsed collector JSON); any extra bytes are refused'))
        fresh_bytes(work/'installed-provider-capture.json',raw)
        save(work/'installed-provider-capture-result.json',dict(schema_version=1,status='ACTUAL_OWNED_CONTAINER_STDOUT_CAPTURED',
            image=image,inventory_sha256=G.LOCK_SHA,returncode=0,stdout_sha256=O.sha(raw),
            collector_sha256=O.sha(O.read(source/G.LANE/'capture_installed.py')),
            retained_reader_sha256=O.sha(O.read(source/G.LANE/'retained-orphans-reader')),
            request_sha256=O.sha(O.read(work/'installed-provider-capture-request.json')),
            source_map_sha256=O.sha(O.read(source/G.LANE/'source-map.json'))))
    finally:
        save(command_root/'provider-retired.json',T.retire(owner,capture=planner_capture(actor)))
    return owner


def runtime_value(args,O,own,selections,retained_root=None):
    """Replay ten supplied observations, optionally from final retained bytes."""
    module=O.module(Path(O.HERE)/'runtime_proof.py','_installed341_runtime_join')
    source,work=Path(args.source_root),Path(args.work)
    inputs={}
    for name in module.MEMBERS:
        relative=('scripts/ci/offline-source-builder-native/source-map.json' if name=='source-map.json' else name)
        source_input=name in('source-map.json','scripts/ci/inputs.lock.json')
        path=(Path(retained_root)/('source/'+relative if source_input else relative) if retained_root is not None
              else source/relative if source_input else work/relative)
        inputs[name]=O.read(path)
    return module.prove(own,inputs,selections)


def verify_retained_runtime(args,O,own,expected,public):
    origin=O.load(Path(public)/'installed-provider-capture-origin.json')
    expected_log=Path(args.work)/'batch-graph-actors/installed-provider-capture.log'
    need(origin['supervised_log_path']==str(expected_log),'collector supervised log owner path differs')
    need(O.read(Path(public)/'batch-graph-actors/installed-provider-capture.log')==O.read(Path(public)/'installed-provider-capture.json'),
         'retained supervised collector log differs from capture bytes')
    selections=O.load(Path(public)/'batch-graph/graph-review.json')['provider_selections']
    replay=runtime_value(args,O,own,selections,retained_root=public)
    need(encoded(replay)==encoded(expected),'retained runtime originals differ from qualified proof')
    need(O.sha(O.read(Path(public)/'installed-provider-runtime-proof.json'))==O.sha(encoded(expected)),
         'retained runtime proof body differs')
    return replay


def runtime_join(args,O,own,selected):
    """Join actual post-producer observations; never require a future image proof."""
    value=runtime_value(args,O,own,selected['review']['provider_selections'])
    need(value['status']=='PASS_OWNED_IMAGE_AND_INSTALLED341_RUNTIME_JOINS'
         and value['identity']==own and value['source_pin_acceptance']=='NOT_ESTABLISHED'
         and value['recipe_buildinfo_holds_unchanged']is True,'runtime image/ALPM join scope differs')
    path=Path(args.work)/'installed-provider-runtime-proof.json';save(path,value)
    return dict(path=str(path),sha256=O.sha(O.read(path)),status=value['status'])


def cli(feature,action,selected,planner,planner_sha):
    command=[sys.executable,'-B',str(feature/'scripts/maintenance/build_batch_v2.py'),action,
        '--builder-interface',INTERFACE]
    for key in('input','config','sources'):
        command+=['--'+key,selected[key+'_path'],'--'+key+'-sha256',selected[key+'_sha']]
    return command+['--planner',str(planner),'--planner-sha256',planner_sha]


def check_state(value,counts,status):
    need(value.get('kind')==KIND and value.get('status')==status and set(value['packages'])==set(NAMES),'actual native v2 checkpoint differs')
    need([len(value['packages'][n]['attempts'])for n in NAMES]==counts,'finite native attempt count differs')


def candidate_spec(O,work,selected):
    return dict(schema_version=1,purpose='local-build-output-candidate',synthetic=False,
        input=dict(path=selected['input_path'],sha256=selected['input_sha']),
        batches=[dict(id=n,path=str(work/('batch-'+n)),admission_sha256=O.sha(O.read(work/('batch-'+n)/'admission.json')),
            state_sha256=O.sha(O.read(work/('batch-'+n)/'state.json')))for n in('a','b')],
        pairs=[dict(package=n,first='a',second='b')for n in NAMES])


def run(args,O):
    _,own=O.admitted(args)
    work=Path(args.work);feature=feature_guard(args,O,own);here=Path(O.HERE)
    need(not(work/'batches-owner.json').exists(),'fresh finite batch phase required')
    base=O.load(work/'bootstrap-owner.json')
    need(base.get('status')=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP' and base['identity']==own,
         'qualified same-owner original341 image required')
    image=base['image'];need(type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'immutable producer image required')
    G=O.module(here/'batch_graph.py','_batch_graph_consumer')
    T=O.module(here/'planner_transport.py','_batch_planner_consumer')
    observer=O.module(here/'observe_batch.py','_batch_observer_consumer')
    report=dict(status='FAIL',identity=own,image=image,builder_interface=INTERFACE,builds='NOT_RUN',
        installed='NOT_RUN',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED')
    stop=threading.Event();watcher=None;observed=[];failure=None;before=None
    try:
        graph_actor=O.Actors(work/'batch-graph-actors',360)
        need(graph_actor.run(['docker','context','show'],timeout=10)=='default','default local Docker context required')
        context=json.loads(graph_actor.docker('context','inspect','default',timeout=10))[0]
        need(context['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local default Docker endpoint required')
        details=json.loads(graph_actor.docker('image','inspect',image,timeout=10))[0]
        need(O.require_image(details,own)==image,'same owned immutable native image required')
        save(work/'current-image-inspect.json',details)
        O.seed_source_cache(feature,work)
        before=O.cache_snapshot(work/'source-cache');save(work/'source-cache-before.json',before)
        command_root=O.fresh(work/'batch-capture-commands')
        provider_capture(args,O,own,feature,image,G,T,graph_actor,command_root)
        selected=G.prepare(args.source_root,feature,work,image,args.cache)
        report['graph_review']=selected['review']
        report['runtime_proof']=runtime_join(args,O,own,selected)
        if selected['review']['status']!='INPUTS_READY_FOR_PLANNER_REVIEW':
            report.update(status='INPUT_HOLD_SOURCE_OR_DEPENDENCY_METADATA',builds='NOT_RUN')
            raise ValueError('original341 graph source/dependency/provider input holds remain')
        need(not selected['review']['recipe_pins_unknown'] and not selected['review']['candidate_provider_ambiguities']
             and not selected['review']['unavailable_named_inputs'],'graph diagnostics cannot hide input holds')
        graph_root=work/'batch-graph';planner=here/'planner_transport.py';planner_sha=O.sha(O.read(planner))
        save(graph_root/'runtime-binding.json',dict(source_root=str(args.source_root),work=str(work),cache=str(args.cache),
            public=str(args.public),proof=str(args.proof),identity=own,manifest_sha256=args.manifest_sha256,
            input_sha256=selected['input_sha'],image=image))
        plan_log=Path(graph_actor.directory)/'admission.log'
        graph_actor.run(cli(feature,'plan',selected,planner,planner_sha),log=plan_log,timeout=150)
        admission_raw=O.read(plan_log);admit=json.loads(admission_raw)
        need(admit.get('builder_interface')==INTERFACE and admit.get('input_sha256')==selected['input_sha']
             and admit.get('sources_sha256')==selected['sources_sha'] and set(admit['tasks'])==set(NAMES)
             and not admit['global_holds'] and len(admit['groups'])==2 and all(not g['held'] for g in admit['groups']),
             'actual native v2 admission is incomplete/held')
        fresh_bytes(graph_root/'admission.json',admission_raw);admission_sha=O.sha(admission_raw)
        report.update(admission_sha256=admission_sha,input_sha256=selected['input_sha'],builds='ACTUAL_V2_CLI_ATTEMPTS_STARTED')
        batch_actor=O.Actors(work/'batch-actors',1950)
        observation_actor=O.Actors(work/'batch-observation-actors',1950)
        capture=actor_capture(O,observation_actor,command_root,here/'capture_command.py')
        def observe():
            try:observed.append(observer.observe(feature,work,image,stop,capture,timeout=1800))
            except (Exception,KeyboardInterrupt)as error:
                observed.append(dict(status='FAIL_OBSERVER_EXCEPTION',error=type(error).__name__+': '+str(error)))
        watcher=threading.Thread(target=observe,name='finite-native-batch-observer');watcher.start()
        common=cli(feature,'execute',selected,planner,planner_sha)+['--admission-sha256',admission_sha]
        batch_actor.run(common+['--output',str(work/'batch-a')],timeout=660,allowed=(1,))
        first_raw=O.read(work/'batch-a/state.json');first=json.loads(first_raw)
        check_state(first,[1,1],'INCOMPLETE')
        need(first['packages'][NAMES[0]]['status']=='FAILED' and first['packages'][NAMES[1]]['status']=='SUCCESS'
             and first['packages'][NAMES[0]]['attempts'][0]['exit_code']==1,'controlled failure did not preserve independent LTO success')
        need(O.read(work/'batch-a/admission.json')==admission_raw,'first batch admission changed')
        fault=O.load(work/'batch-observations/fault.json')
        need(fault['status']=='ACTUAL_OWNED_RUNNING_CONTAINER_KILL_RETURNED','actual first-baseline fault was not observed')
        fresh_bytes(work/'failure-state.json',first_raw)
        batch_actor.run(common+['--output',str(work/'batch-a'),'--resume','--retry',NAMES[0]],timeout=660)
        final_a_raw=O.read(work/'batch-a/state.json');a=json.loads(final_a_raw)
        check_state(a,[2,1],'COMPLETE')
        need(a['packages'][NAMES[1]]==first['packages'][NAMES[1]]
             and a['packages'][NAMES[0]]['attempts'][0]==first['packages'][NAMES[0]]['attempts'][0],
             'resume reran independent work or overwrote the failure')
        fresh_bytes(work/'batch-a-final-state.json',final_a_raw)
        batch_actor.run(common+['--output',str(work/'batch-b')],timeout=660)
        final_b_raw=O.read(work/'batch-b/state.json');b=json.loads(final_b_raw)
        check_state(b,[1,1],'COMPLETE');fresh_bytes(work/'batch-b-final-state.json',final_b_raw)
        need(O.read(work/'batch-a/admission.json')==O.read(work/'batch-b/admission.json')==admission_raw,
             'independent batches must retain the same admitted sources/inputs')
        stop.set();watcher.join(timeout=25)
        need(not watcher.is_alive() and len(observed)==1 and observed[0]['status']=='PASS_FIVE_ACTUAL_RUNNING_V2_ATTEMPTS_ONE_OWNED_KILL',
             'all five actual v2 running-container observations required')
        names=[]
        for batch,state in (('batch-a',a),('batch-b',b)):
            for package,row in state['packages'].items():
                for index,attempt in enumerate(row['attempts'],1):
                    need(attempt['output']==f'{package}/attempt-{index:03d}/build','finite owned attempt path differs')
                    record=O.load(work/batch/attempt['output']/'provenance.json')
                    need(record['image']==record['image_id']==image and record['mode']=='native','actual attempt image/native identity differs')
                    name=record['clean_environment_id'];need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',name),'owned build name differs')
                    names.append(name)
                    if(batch,package,index)==('batch-a',NAMES[0],1):
                        need(record['status']=='failed' and type(record['exit_code'])is int and record['exit_code']==137
                             and name==fault['name'],'actual kill did not cause genuine baseline container failure')
                    else:need(record['status']=='built-package-static-pass' and type(record['exit_code'])is int and record['exit_code']==0,
                              'all four successful actual builders required')
        need(len(names)==len(set(names))==5 and set(names)=={r['name']for r in observed[0]['observations'].values()},
             'five observed clean containers must exactly match the actual attempts')
        report['all_container_names']=names
        spec=candidate_spec(O,work,selected);spec_path=graph_root/'output-spec.json';save(spec_path,spec)
        manifests=O.fresh(work/'candidate-manifests')
        response=batch_actor.run([sys.executable,'-B',str(feature/'scripts/maintenance/build_outputs_v2.py'),'candidate',
            '--builder-interface',INTERFACE,'--spec',str(spec_path),'--spec-sha256',O.sha(O.read(spec_path)),
            '--output',str(manifests)],timeout=210)
        result=json.loads(response);candidate_path=Path(result['path'])
        need(candidate_path.parent==manifests and re.fullmatch(r'[0-9a-f]{64}\.json',candidate_path.name)
             and result['sha256']==O.sha(O.read(candidate_path))==candidate_path.stem,'content-addressed candidate output binding differs')
        candidate=O.load(candidate_path)
        need(result['status']==candidate['status']=='LOCAL_BUILD_OUTPUT_CANDIDATE' and candidate['synthetic']is False
             and candidate['builder_interface']==INTERFACE and candidate['batch_task_coverage']=='COMPLETE'
             and {p['name']for p in candidate['packages']}==set(NAMES) and all(p['bytes_equal']is True for p in candidate['packages']),
             'actual output admission and both independent byte pairs required')
        need(all(candidate.get(k)is False for k in('authenticated','signed','staged','published','full_overlay_accepted'))
             and candidate.get('installed')==candidate.get('hardware_status')=='NOT RUN','output candidate scope was elevated')
        rebuilds=[r['clean_environment_id']for p in candidate['packages']for r in p['rebuilds']]
        need(all(len(p['rebuilds'])==2 for p in candidate['packages'])and len(rebuilds)==len(set(rebuilds))==4
             and set(rebuilds)==set(names)-{fault['name']},'output admission must bind exactly the four successful clean executions')
        O.feature_files(feature)
        report.update(status='PASS_TWO_NATIVE_V2_BATCHES_REAL_FAILURE_RESUME_AND_OUTPUT_ADMISSION',
            builds='FOUR_SUCCESSFUL_CLEAN_BUILDS_ONE_CONTROLLED_FAILURE',output_candidate=dict(path=str(candidate_path),sha256=result['sha256']),
            observation_status=observed[0]['status'])
    except (Exception,KeyboardInterrupt)as error:
        failure=error;report['error']=type(error).__name__+': '+str(error)[:4096]
    finally:
        stop.set()
        if watcher is not None:
            watcher.join(timeout=25)
            report['observer_joined']=not watcher.is_alive()
            if watcher.is_alive():
                failure=failure or ValueError('observer did not retire within its bounded capture interval')
                report.update(status='FAIL',observer_error='observer remains alive')
        if observed:report['observer_result']=observed[0]
        if before is not None:
            try:
                after=O.cache_snapshot(work/'source-cache');save(work/'source-cache-after.json',after)
                need(before==after,'offline source cache changed during actual batch execution')
                report['source_cache_unchanged']=True
            except Exception as error:
                failure=failure or error;report.update(status='FAIL',cache_error=str(error))
        O.save(work/'batches-owner.json',report)
    if failure is not None:raise failure
    return report


def cleanup(args,O,own):
    """Retire recorded attempt/planner consumers before producer image removal."""
    _,current=O.admitted(args);need(current==own,'cleanup owner identity changed')
    work=Path(args.work);feature=feature_guard(args,O,own);here=Path(O.HERE)
    observer=O.module(here/'observe_batch.py','_batch_cleanup_observer')
    transport=O.module(here/'planner_transport.py','_batch_cleanup_transport')
    v2=O.module(feature/'scripts/maintenance/build_batch_v2.py','_batch_cleanup_v2')
    actor=O.Actors(work/'batch-cleanup-actors',300)
    report=dict(status='FAIL',identity=own,observed_absent=[],removed_build_containers=[],planners=[])
    try:
        base=O.load(work/'bootstrap-owner.json')
        need(base['identity']==own and base['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP','same owned producer required for consumer cleanup')
        image=base['image'];entry_sha=O.sha(O.read(feature/'scripts/build/container-entry-v2.sh'))
        capture=planner_capture(actor)
        with ExitStack()as leases:
            for batch in('batch-a','batch-b'):
                root=work/batch
                if not(root.exists()or root.is_symlink()):continue
                need(root.is_dir()and not root.is_symlink(),'ordinary owned batch root required')
                lock=root/'.lock';O.read(lock)
                stream=leases.enter_context(lock.open('rb'))
                fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                for package in root.iterdir():
                    need(not package.is_symlink(),'batch cleanup alias refused')
                    if not package.is_dir():continue
                    need(package.name in NAMES,'unrecorded batch package namespace')
                    allowed={'attempt-001','attempt-002'}if batch=='batch-a'and package.name==NAMES[0]else{'attempt-001'}
                    need(all(p.is_dir()and not p.is_symlink()and p.name in allowed for p in package.iterdir()),'unrecorded attempt namespace')
            names=set()
            for batch,package,index in observer.ATTEMPTS:
                output=work/batch/package/f'attempt-{index:03d}'/'build';path=output/'provenance.json'
                if not(path.exists()or path.is_symlink()):continue
                record=O.load(path)
                if record.get('clean_environment_id')is None:
                    need(record.get('status')in('preflight-failed','failed'),'missing owned container identity')
                    continue
                admission=O.load(work/batch/'admission.json')
                runtime=O.load(work/'batch-graph/runtime-binding.json')
                need(runtime['identity']==own and runtime['image']==image and admission['builder_interface']==INTERFACE
                     and admission['input_sha256']==runtime['input_sha256']==O.sha(O.read(work/'batch-graph/input.json')),
                     'cleanup admission/source/owner binding differs')
                need(set(admission['tasks'])==set(NAMES),'finite cleanup task set required')
                task=admission['tasks'][package]
                need(task['image']==image and record.get('status')in('building','failed','built-package-static-pass'),
                     'owned v2 attempt provenance required')
                # Normalize status only for this common ownership predicate;
                # the unchanged record remains a terminal/partial attempt.
                name=observer.check_provenance(dict(record,status='building'),feature,output,image,entry_sha)
                need(name not in names,'duplicate owned build cleanup identity');names.add(name)
                v2.verify_material(task,output)
                ids=actor.run([*DOCKER,'ps','-aq','--no-trunc','--filter','name=^/'+name+'$'],timeout=10).split()
                need(len(ids)<=1 and all(re.fullmatch('[0-9a-f]{64}',p)for p in ids),'ambiguous owned build lookup')
                if ids:
                    retire_build(actor,observer,feature,output,image,name,ids[0],report)
                need(not actor.run([*DOCKER,'ps','-aq','--no-trunc','--filter','name=^/'+name+'$'],timeout=10),
                     'owned build name remains')
                if ids:
                    need(not actor.run([*DOCKER,'ps','-aq','--no-trunc','--filter','id='+ids[0]],timeout=10),'owned build CID remains')
                report['observed_absent'].append(name)
            retire_planners(args,O,own,feature,work,image,transport,capture,report)
        if(work/'batches-owner.json').exists():
            batch=O.load(work/'batches-owner.json')
            need(batch['identity']==own,'batch cleanup report identity differs')
            if batch['status']=='PASS_TWO_NATIVE_V2_BATCHES_REAL_FAILURE_RESUME_AND_OUTPUT_ADMISSION':
                need(set(report['observed_absent'])==set(batch['all_container_names'])and len(names)==5,
                     'all five actual build absences required before producer cleanup')
        report['status']='PASS_ACTUAL_BUILD_CONSUMERS_ABSENT_BEFORE_IMAGE'
    except (Exception,KeyboardInterrupt)as error:
        report['error']=type(error).__name__+': '+str(error)[:4096]
        raise
    finally:
        O.save(work/'pair-cleanup-owner.json',report)
    return report


def retire_build(actor,observer,feature,output,image,name,cid,report):
    rows=json.loads(actor.run([*DOCKER,'container','inspect',name],timeout=10))
    need(type(rows)is list and len(rows)==1,'single owned build inspection required')
    row=rows[0];binds=[p for p in row['Mounts']if p.get('Type')=='bind']
    other=all(p.get('Type')=='bind'or(p.get('Type')=='tmpfs'and p.get('Destination')=='/tmp'and p.get('RW')is True)for p in row['Mounts'])
    need(row['Id']==cid and row['Name']=='/'+name and row['Image']==row['Config']['Image']==image
         and row['Config']['User']==f'{os.getuid()}:{os.getgid()}'and len(binds)==5
         and all(type(p.get('RW'))is bool for p in binds)
         and {(p['Source'],p['Destination'],p['RW'])for p in binds}==observer.mounts(feature,output)and other,
         'live build cleanup image/user/mount ownership differs')
    actor.run([*DOCKER,'rm','-f',cid],timeout=15);report['removed_build_containers'].append(cid)


def retire_planners(args,O,own,feature,work,image,transport,capture,report):
    owners=[];capture_owner=work/'batch-capture-commands/provider-owner.json'
    if capture_owner.exists()or capture_owner.is_symlink():owners.append(capture_owner)
    owners+=sorted((work/'batch-graph').glob('planner-owner-*.json'))
    owner_names=set()
    for path in owners:
        owner=O.load(path)
        expected_roots=[str(args.source_root),str(work)]if path==capture_owner else[str(feature),str(work)]
        need(owner.get('identity')==own and owner['image']==image and owner['mount_roots']==expected_roots
             and owner['purpose']==('readonly-installed-provider-capture'if path==capture_owner else'readonly-native-planner')
             and owner['name']not in owner_names,'readonly consumer cleanup source/image/identity differs')
        owner_names.add(owner['name']);report['planners'].append(transport.retire(owner,capture=capture))
