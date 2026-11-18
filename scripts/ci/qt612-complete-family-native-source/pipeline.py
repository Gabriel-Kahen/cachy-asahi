# SPDX-License-Identifier: MIT
"""One Root-owned serial component pair per stage; no default actor or grant."""
import importlib.util
import os
from pathlib import Path
import re
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pipeline_common',HERE/'common.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
M,P,need=C.M,C.P,C.need
DESKTOP_CONSUMER='desktop_consumer'
PAIR_ONLY_STATUS='PASS_QT612_FAMILY_COMPONENT_PAIR_ONLY'
BUILD_SECONDS,COMPARE_SECONDS,QUALIFY_SECONDS,LIFECYCLE_SECONDS=6900,120,1200,1800
STAGE_SECONDS,CLEANUP_SECONDS=18000,90
POLICY=dict(builder_memory_bytes=4*1024**3,builder_swap_extra_bytes=0,builder_cpus=1,builder_pids=512,
            builder_tmpfs_bytes=4*1024**3,qualifier_memory_bytes=2*1024**3,qualifier_cpus=1,
            controller_memory_bytes=512*1024**2,stage_seconds=STAGE_SECONDS,cleanup_seconds=CLEANUP_SECONDS,
            baseline_authentication='Separate Root-selected complete procedure; no embedded160-second GPG cap',
            baseline_authentication_timeout=None,capacity_sufficient=None,Root_acceptance=None)


def family_plan(lock,*,complete,consumer_selected=False):
    rows=[]
    for i,key in enumerate(C.ORDER):
        row=lock['components'][key]
        rows.append(dict(component=key,recipe_commit=row['commit'],package=row['package'],filename=row['filename'],
            direct_providers=row['predecessors'],installed_previous_providers=list(C.ORDER[:i]),
            expected_inventory_count=356+i,final_installed_count=357+i,
            clean_attempts=2,parallel_builds=1,normal_signature_policy='Required TrustedOnly',
            normal_dependency_check='Unchanged pacman -T and makepkg dependency/check phases',
            build_timeout_seconds=BUILD_SECONDS,comparison_timeout_seconds=COMPARE_SECONDS,
            qualification_timeout_seconds=QUALIFY_SECONDS,lifecycle_timeout_seconds=LIFECYCLE_SECONDS,
            stage_timeout_seconds=STAGE_SECONDS,Root_binding=None,actual_image=None))
    return dict(schema=1,kind='QT612_COMPLETE_FAMILY_ORDERED_STAGE_PLAN_V1',order=list(C.ORDER),stages=rows,
        input_plan_complete=complete,baseline=349,required_additions=7,prepared_baseline=356 if complete else None,
        final_package_count=361 if complete else None,policy=POLICY,
        desktop_consumer=dict(source_commit=lock['consumer']['commit'],selected=consumer_selected,
                              requires_all_providers=True,expected_inventory_count=361,Root_binding=None),
        family_is_one_job=False,require_new_Root_stage_binding_each=True,
        Wayland_notice_path_reconciliation=dict(frozen_interface='usr/share/licenses/cachy-asahi-qt612-gui-source-reference/source',
            selected_provider='usr/share/licenses/cachy-asahi-qt612-gui-server-source-reference/source',
            rule='Preserve frozen interface; select server provider explicitly; protocol input pins unchanged'),
        transport='Frozen75ce F69 exact14/128MiB route is not this tuple; independent family transport binding UNISSUED',
        Root_acceptance=None,actor_enabled=False)


def inventory_pin(path,expected_count,*,expected_raw=None):
    observed={};raw=M.stream(path,None,observed,collect=True,cap=1024**2)
    lines=raw.decode('ascii').splitlines(keepends=True)
    need(len(lines)==expected_count and lines==sorted(lines) and raw.endswith(b'\n')
         and all(re.fullmatch('[a-z0-9][a-z0-9+_.-]* [^\\s]+\n',line) for line in lines)
         and len({x.split(' ',1)[0] for x in lines})==len(lines),'EXACT_SORTED_STAGE_INVENTORY')
    need(not any(x.startswith(('qt6-base ','qt6-shadertools ','qt6-svg ','qt6-declarative ','qt6-wayland ')) for x in lines),
         'NO_OFFICIAL_HOST_QT_PACKAGE_FALLBACK')
    need(expected_raw is None or raw==expected_raw,'EXACT_STAGE_INVENTORY_CLOSURE')
    return C.pin(raw)


def expected_inventory(root,mapping,component):
    """Derive the whole stage inventory from the immutable baseline and earlier providers."""
    root=M.ordinary(root)
    baseline=mapping['files']['expected356.lock']
    raw=M.stream(root/'expected356.lock',{k:baseline[k] for k in ('bytes','sha256')},{},collect=True)
    packages=dict(line.split(' ',1) for line in raw.decode('ascii').splitlines())
    need(len(packages)==356,'EXACT_BASE356_INVENTORY')
    providers=C.load_lock()['components']
    for key in prior_components(component):
        row=providers[key]; name=row['package']
        need(name not in packages,'DISTINCT_QT_PROVIDER_IDENTITY')
        packages[name]='6.12.0-1'
    return ''.join(f'{name} {version}\n' for name,version in sorted(packages.items())).encode()


def prior_components(component):
    return C.ORDER if component==DESKTOP_CONSUMER else C.ORDER[:C.ORDER.index(component)]


def builder_image_plan(*,source,source_map_sha256,component,baseline_image,previous,uid,gid):
    """Prepare a normal signed image transaction from the authenticated 349 image.

    The caller selects and authenticates prior pair receipts and detached
    signatures. This adapter reopens their whole bytes and checks package
    identity before emitting the seven additions and ordered Qt providers.
    """
    mapping=C.read_source(source,source_map_sha256)
    need(mapping['input_plan_complete'] is True and
         (component in C.ORDER or component==DESKTOP_CONSUMER and mapping.get('desktop_consumer')),
         'COMPLETE_FAMILY_IMAGE_INPUTS')
    root=M.ordinary(source);observed={}
    items=mapping['files']['family-inputs.DATA.json']
    inputs=M.load(root/'family-inputs.DATA.json',{k:items[k] for k in ('bytes','sha256')},observed)
    dependency_lock=P.selected(C.PARENT/'dependency-candidates.lock.json',P.DEPENDENCIES,observed)
    base=P.validate_base_provider(inputs['base_provider'],dependency_lock,observed)
    dependencies=inputs['dependencies']
    plan=P.dependency_image_plan(baseline_image,base,dependencies,builder_uid=uid,builder_gid=gid)
    assets={}
    for row in dependencies['packages'].values():
        name=row['filename']
        assets[name]=row['archive'];assets[name+'.sig']=row['signature']
        for ref in (row['archive'],row['signature']):P.reference(ref,observed)
    prior=prior_components(component)
    need(type(previous)is dict and set(previous)==set(prior),'EXACT_PREVIOUS_PROVIDER_SET')
    lock=C.load_lock()
    paths=[]
    for key in prior:
        row=lock['components'][key]; selected=previous[key]; name=row['filename']
        need(set(selected)=={'qualification','archive','signature'},'EXACT_PROVIDER_CARRYOVER_REFS')
        receipt=M.decode(P.reference(selected['qualification'],observed,collect=True))
        need(receipt.get('status')=='PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY'
             and receipt.get('component')==key and receipt.get('filename')==name
             and receipt.get('recipe_commit')==row['commit'] and receipt.get('source_map_sha256')==source_map_sha256,
             'MATCHING_SELECTED_PRIOR_PAIR')
        expected={field:selected['archive'][field] for field in ('bytes','sha256')}
        need(len(receipt['observations'])==2 and all(x['archive']==expected for x in receipt['observations']),
             'SAME_QUALIFIED_PROVIDER_ARCHIVE')
        need(Path(selected['archive']['path']).name==name and Path(selected['signature']['path']).name==name+'.sig',
             'EXACT_PROVIDER_ARCHIVE_SIGNATURE_NAMES')
        need(0<selected['signature']['bytes']<=1024**2,'FINITE_PROVIDER_SIGNATURE')
        P.reference(selected['archive'],observed,cap=512*1024**2);P.reference(selected['signature'],observed,cap=1024**2)
        metadata=P.pkginfo(selected['archive']['path'])
        need(metadata.get('pkgname')==[row['package']] and metadata.get('pkgver')==['6.12.0-1']
             and metadata.get('arch')==['aarch64'],'EXACT_PRIOR_PROVIDER_PACKAGE_IDENTITY')
        assets[name]=selected['archive'];assets[name+'.sig']=selected['signature']
        paths.append('/qt612-deps/'+name)
    # Install in dependency order against this one image. No repository sync
    # or network input is part of the reviewed transaction.
    seam=' && pacman -Q | LC_ALL=C sort > /qt612.actual.lock'
    need(plan['dockerfile'].count(seam)==1,'EXACT_PINNED_IMAGE_COMMAND_SEAM')
    extra=''.join(' && pacman --config /qt612.pacman.conf -U --noconfirm --noscriptlet '+p for p in paths)
    plan['dockerfile']=plan['dockerfile'].replace(seam,extra+seam)
    inventory=expected_inventory(root,mapping,component)
    M.unchanged(observed)
    return dict(plan,component=component,signed_context=assets,
                expected_inventory=inventory.decode('ascii'),inventory_pin=C.pin(inventory),
                expected_packages=356+len(prior),pair_evidence_is_authentication=False)


def stage_commands(*,source,source_map_sha256,component,output,image,inventory,cache,nonce):
    mapping=C.read_source(source,source_map_sha256);need(component in C.ORDER,'EXACT_FAMILY_COMPONENT')
    need(mapping['input_plan_complete'] is True,'COMPLETE_SIGNED_INPUT_PLAN_REQUIRED')
    need(re.fullmatch('sha256:[0-9a-f]{64}',image or '') and re.fullmatch('[0-9a-f]{32}',nonce or ''),'ACTUAL_IMMUTABLE_IMAGE_NONCE_SELECTION')
    root,out,cache=map(M.ordinary,(source,output,cache));inventory=M.ordinary(inventory)
    need(not any(',' in str(p) or '\n' in str(p) for p in (root,out,cache,inventory)),'SAFE_MOUNT_OPERANDS')
    pin=inventory_pin(inventory,356+C.ORDER.index(component),expected_raw=expected_inventory(root,mapping,component))
    plan_name='materials/'+component+'/plan.json'
    plan_path=root/plan_name
    plan_sha=mapping['files'][plan_name]['sha256']
    common=['--image',image,'--mode','native','--network','none','--source-date-epoch','1792021458',
        '--timeout',str(BUILD_SECONDS),'--expected-packages',str(inventory),'--reviewed-inputs',str(root/'reviewed'/(component+'.json')),
        '--source-plan',str(plan_path),'--source-plan-sha256',plan_sha,
        '--source-catalog',str(root/'materials'/component/'catalog.json'),'--source-cache',str(cache)]
    program=root/'runtime'/component/'scripts/build/build_family.py'
    return dict(component=component,source_map_sha256=source_map_sha256,image=image,nonce=nonce,inventory_pin=pin,cache=str(cache),
        inventory_path=str(inventory),entry_pin={k:mapping['files']['runtime/'+component+'/scripts/build/container-entry-v2.sh'][k] for k in ('bytes','sha256')},
        source_date_epoch=1792021458,builds=[dict(attempt=str(i),argv=['/usr/bin/python3','-I','-B',str(program),str(root/'recipes'/component),*common,'--output',str(out/('build-'+str(i)))],
            env=dict(CACHY_QT612_REFERENCE_NONCE=nonce,CACHY_QT612_REFERENCE_ATTEMPT=str(i))) for i in (1,2)],
        compare=['/usr/bin/python3','-I','-B',str(root/'runtime'/component/'scripts/build/compare_v2.py'),str(out/'build-1'),str(out/'build-2'),'--require-bytes'],
        serial=True,Root_binding=None,actor_enabled=False)


def require_actual_family(component,*,source=None,source_map_sha256=None,actor_argv=None):
    """Binding consistency only; actual Root supervisor authenticates authority."""
    need(os.getuid()==os.geteuid()>0 and os.uname().machine in ('aarch64','arm64'),'ACTUAL_ORDINARY_NATIVE_ARM_REQUIRED')
    need(component in C.ORDER or (component==DESKTOP_CONSUMER and actor_argv is None),'EXACT_FAMILY_COMPONENT')
    source=source or os.environ.get('QT612_FAMILY_SOURCE_ROOT')
    source_map_sha256=source_map_sha256 or os.environ.get('QT612_FAMILY_SOURCE_MAP_SHA256')
    need(source is not None,'ROOT_FAMILY_SOURCE_UNBOUND')
    mapping=C.read_source(source,source_map_sha256)
    need(mapping['input_plan_complete'] is True,'COMPLETE_SIGNED_INPUT_PLAN_REQUIRED')
    gate=P.module('actor_gate')
    binding=gate.read_selected(os.environ.get('QT612_FAMILY_BINDING_PATH'),os.environ.get('QT612_FAMILY_BINDING_SHA256'))
    keys={'kind','issued_by','accepted','source','ref','run','job','attempt','source_map_sha256','component','nonce',
          'image','inventory_pin','created_utc','expires_utc','policy','Root_supervisor_authentication_required'}
    need(set(binding)==keys and binding['kind']=='ROOT_QT612_COMPLETE_FAMILY_STAGE_BINDING_V1'
         and binding['issued_by']=='Root' and binding['accepted'] is True
         and binding['Root_supervisor_authentication_required'] is True,'ROOT_FAMILY_BINDING_UNISSUED')
    now=int(time.time())
    need(type(binding['created_utc']) is int and type(binding['expires_utc']) is int
         and binding['created_utc']<=now<binding['expires_utc']
         and 0<binding['expires_utc']-binding['created_utc']<=STAGE_SECONDS,'FRESH_COMPONENT_STAGE_WINDOW')
    need(binding['policy']==POLICY and binding['source_map_sha256']==source_map_sha256
         and binding['component']==component and re.fullmatch('[0-9a-f]{32}',binding['nonce'] or '')
         and re.fullmatch('sha256:[0-9a-f]{64}',binding['image'] or ''),'SAME_EXACT_STAGE_SOURCE_POLICY')
    need(os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'
         and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
         and re.fullmatch('[0-9a-f]{40}',binding['source'] or '')
         and binding['source']==os.environ.get('GITHUB_SHA') and binding['ref']==os.environ.get('GITHUB_REF')
         and binding['ref'].startswith('refs/heads/')
         and binding['attempt']==os.environ.get('GITHUB_RUN_ATTEMPT')=='1'
         and binding['run']==os.environ.get('GITHUB_RUN_ID') and re.fullmatch('[1-9][0-9]{0,19}',binding['run'] or '')
         and re.fullmatch('[1-9][0-9]{0,19}',binding['job'] or ''),'ACTUAL_ROOT_STAGE_DISPATCH_CONTEXT')
    if actor_argv is not None:
        need(os.environ.get('CACHY_QT612_REFERENCE_NONCE')==binding['nonce']
             and os.environ.get('CACHY_QT612_REFERENCE_ATTEMPT') in ('1','2'),'SAME_ACTUAL_COMPONENT_ATTEMPT_NONCE')
        root=M.ordinary(source);args=actor_argv
        need(args and args[0]==str(root/'recipes'/component),'SAME_ACTUAL_COMPONENT_RECIPE')
        values={'--image':binding['image'],'--mode':'native','--network':'none','--timeout':str(BUILD_SECONDS),
                '--source-date-epoch':'1792021458','--reviewed-inputs':str(root/'reviewed'/(component+'.json')),
                '--source-plan':str(root/'materials'/component/'plan.json'),
                '--source-plan-sha256':mapping['files']['materials/'+component+'/plan.json']['sha256'],
                '--source-catalog':str(root/'materials'/component/'catalog.json')}
        for key,value in values.items():
            need(args.count(key)==1 and args.index(key)+1<len(args) and args[args.index(key)+1]==value,'SAME_ACTUAL_BUILDER_ARG_'+key)
        need(args.count('--expected-packages')==1,'SELECTED_ACTUAL_INVENTORY')
        path=args[args.index('--expected-packages')+1]
        need(inventory_pin(M.ordinary(path),356+C.ORDER.index(component),
                           expected_raw=expected_inventory(root,mapping,component))==binding['inventory_pin'],
             'SAME_ACTUAL_STAGE_INVENTORY')
    return binding


def binding_template():
    return dict(kind='ROOT_QT612_COMPLETE_FAMILY_STAGE_BINDING_V1',issued_by=None,accepted=False,
        **dict.fromkeys(('source','ref','run','job','attempt','source_map_sha256','component','nonce','image','inventory_pin','created_utc','expires_utc')),
        policy=POLICY,Root_supervisor_authentication_required=True)


def retain_failure(*,root,destination,phase,primary,component):
    root=M.ordinary(root);writer=M.Writer(destination);observed={};files={};total=0
    try:
        allowed=['comparison.json','qualification.json','qualification.rawlog','lifecycle.json','lifecycle.rawlog']
        filename=C.load_lock()['components'][component]['filename'].removesuffix('.pkg.tar.xz')+'-check.log'
        for attempt in ('build-1','build-2'):
            allowed += [attempt+'/'+p for p in ('build.log','provenance.json','validation.json','artifacts/'+filename,
                'artifacts/family-stage.json','artifacts/family-configuration.json','artifacts/family-notices.json',
                'artifacts/family-dependencies.missing','artifacts/family-shader-smoke.json')]
        for name in allowed:
            p=root/name
            if not p.exists():continue
            sink=C.F.HashSink();M.stream(p,None,observed,cap=8*1024**2,target=sink)
            pin=sink.result();total+=pin['bytes'];need(total<=32*1024**2,'FINITE_WHOLE_FAILURE_EXPORT')
            files[name]=writer.put(name,source=p,expected=pin,observed=observed,cap=8*1024**2)
        result=dict(status='HOLD_QT612_FAMILY_STAGE',component=component,phase=phase,primary=primary,
            complete=True,files=files,scope='All available allowlisted whole evidence only',Root_acceptance=None)
        writer.put('failure-receipt.json',raw=C.encoded(result));M.unchanged(observed);return result
    finally:writer.close()


def qualification_request(plan, *, source, source_map_sha256, output, work):
    out=M.ordinary(output)
    return dict(schema=1,kind='QT612_FAMILY_PAIR_QUALIFICATION_REQUEST_V1',
        source=str(M.ordinary(source)),source_map_sha256=source_map_sha256,component=plan['component'],
        first=str(out/'build-1'),second=str(out/'build-2'),comparison=str(out/'comparison.json'),
        expected={k:plan[k] for k in ('image','inventory_pin','entry_pin','nonce','source_date_epoch','inventory_path')},
        work=str(M.ordinary(work)))


def _drive_stage(plan,executor,*,source,source_map_sha256,output,work,failure_output,pair_only=False):
    """Explicit owned-callback protocol; MODEL tests do not enter the public actor gate."""
    need(type(pair_only) is bool,'EXPLICIT_FAMILY_STAGE_MODE')
    need(getattr(executor,'API',None)=='ROOT_QT612_COMPLETE_FAMILY_OWNED_EXECUTOR_V1','ROOT_OWNED_FAMILY_EXECUTOR_REQUIRED')
    callbacks=('require_domain','require_signed_inventory','require_no_containers','run','require_absent_twice','qualify')
    if not pair_only: callbacks+=('lifecycle',)
    need(all(callable(getattr(executor,n,None)) for n in callbacks),'COMPLETE_OWNED_STAGE_CALLBACKS')
    phase='PREPARE';key=plan['component'];deadline=time.monotonic()+STAGE_SECONDS-CLEANUP_SECONDS
    def budget(seconds):need(time.monotonic()+seconds<=deadline,'REMAINING_STAGE_WALL_BUDGET')
    try:
        executor.require_domain(POLICY)
        # Authentication of the complete baseline/providers is a separate actual
        # Root procedure. This callback must read back its real completed result.
        executor.require_signed_inventory(component=key,image=plan['image'],inventory_pin=plan['inventory_pin'],
            previous_providers=list(C.ORDER[:C.ORDER.index(key)]),signature_policy='Required TrustedOnly')
        for row in plan['builds']:
            phase='BUILD_'+row['attempt'];budget(BUILD_SECONDS);executor.require_no_containers()
            receipt=executor.run(row['argv'],BUILD_SECONDS,env=row['env'])
            need(type(receipt)is dict and receipt.get('exit')==0 and all(receipt.get(k)is True for k in ('natural','reaped','output_complete')),'NATURAL_COMPLETE_COMPONENT_BUILD')
            executor.require_absent_twice('cachy-qt612-family-'+plan['nonce']+'-'+key+'-'+row['attempt'])
        phase='COMPARE';budget(COMPARE_SECONDS)
        receipt=executor.run(plan['compare'],COMPARE_SECONDS,env={},stdout=str(M.ordinary(output)/'comparison.json'))
        need(receipt.get('exit')==0 and all(receipt.get(k)is True for k in ('natural','reaped','output_complete')),'NATURAL_STRICT_COMPONENT_COMPARE')
        executor.require_no_containers();phase='QUALIFY';budget(QUALIFY_SECONDS)
        request=qualification_request(plan,source=source,source_map_sha256=source_map_sha256,output=output,work=work)
        request_raw=C.encoded(request)
        request_dir=M.Writer(M.ordinary(output)/'qualifier-input')
        try:
            request_dir.put('request.json',raw=request_raw)
        finally:
            request_dir.close()
        request_path=M.ordinary(output)/'qualifier-input/request.json'
        qualify_argv=['/usr/bin/python3','-I','-B',str(HERE/'qualify.py'),'--request',str(request_path),
                      '--request-sha256',C.pin(request_raw)['sha256']]
        worker=executor.qualify(argv=qualify_argv,timeout=QUALIFY_SECONDS,
            memory_bytes=POLICY['qualifier_memory_bytes'],cpus=1,output_json=str(M.ordinary(output)/'qualification.json'))
        need(type(worker)is dict and worker.get('exit')==0
             and all(worker.get(k)is True for k in ('natural','reaped','output_complete')),'NATURAL_REAPED_PASSIVE_QUALIFIER')
        qualified=worker['result']
        row=C.load_lock()['components'][key]
        need(worker.get('result_pin')==C.pin(C.encoded(qualified)),'WHOLE_QUALIFIER_RESULT_PIN')
        retained={}
        receipt_root=M.ordinary(output)
        M.stream(receipt_root/'qualification.json',worker['result_pin'],retained)
        need(qualified.get('status')=='PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY'
             and qualified.get('component')==key and qualified.get('source_map_sha256')==source_map_sha256
             and qualified.get('image')==plan['image'] and qualified.get('inventory_pin')==plan['inventory_pin']
             and qualified.get('filename')==row['filename'] and qualified.get('recipe_commit')==row['commit']
             and qualified.get('nonce')==plan['nonce'] and qualified.get('entry_pin')==plan['entry_pin']
             and qualified.get('source_date_epoch')==plan['source_date_epoch']
             and set(qualified.get('provenance_pins',{}))=={'build-1','build-2'}
             and qualified.get('native_acceptance') is None,'EXACT_COMPONENT_BYTE_QUALIFICATION')
        for attempt,pin in qualified['provenance_pins'].items():
            M.stream(receipt_root/attempt/'provenance.json',pin,retained)
        observations=qualified['observations']
        need(len(observations)==2 and observations[0]['archive']==observations[1]['archive'],
             'SAME_CURRENT_ARCHIVE_IN_BOTH_QUALIFIED_ATTEMPTS')
        archive_pin=observations[0]['archive']
        for attempt in ('build-1','build-2'):
            M.stream(receipt_root/attempt/'artifacts'/row['filename'],archive_pin,retained,cap=512*1024**2)
        if pair_only:
            executor.require_no_containers()
            M.unchanged(retained)
            return dict(status=PAIR_ONLY_STATUS,component=key,qualification=qualified,lifecycle=None,
                        lifecycle_status='NOT_RUN',Root_acceptance=None,native_acceptance=None)
        phase='LIFECYCLE';budget(LIFECYCLE_SECONDS)
        lifecycle_module=C.local('lifecycle')
        inventory=M.stream(M.ordinary(plan['inventory_path']),plan['inventory_pin'],{},collect=True)
        lifecycle_plan=lifecycle_module.command_plan(row,inventory,worker['result_pin'],archive_pin)
        need(sum(x['seconds'] for x in lifecycle_plan['steps'])<LIFECYCLE_SECONDS,'FINITE_LIFECYCLE_COMMAND_BUDGET')
        lifecycle=executor.lifecycle(component=key,qualified=qualified,plan=lifecycle_plan,
            timeout=LIFECYCLE_SECONDS,output_json=str(M.ordinary(output)/'lifecycle.json'))
        lifecycle_module.validate_receipt(lifecycle_plan,lifecycle,canonical_pin=lambda obj:C.pin(C.encoded(obj)))
        M.stream(receipt_root/'lifecycle.json',C.pin(C.encoded(lifecycle)),retained,cap=32*1024**2)
        executor.require_no_containers()
        M.unchanged(retained)
        return dict(status='PASS_COMPONENT_CALLBACK_AND_BYTE_JOINS_ONLY',component=key,qualification=qualified,
                    lifecycle=lifecycle,Root_acceptance=None,native_acceptance=None)
    except BaseException as error:
        primary=P.failure_capsule(error)
        try:retained=retain_failure(root=output,destination=failure_output,phase=phase,primary=primary,component=key)
        except BaseException as secondary:retained=dict(complete=False,retention_error=P.failure_capsule(secondary))
        raise P.ProducerHold(phase,primary,retained) from None


def check_stage_workspace(*, source, inventory, cache, output, work, failure_output):
    """Reject filesystem collisions before the first owned executor callback."""
    source, inventory, cache, output, work, failure_output = map(
        M.ordinary, (source, inventory, cache, output, work, failure_output))
    output_parent = next((parent for parent in output.parents if parent.exists()), None)
    need(output_parent is not None and output_parent.is_dir() and (not output.exists() or output.is_dir()),
         'FAMILY_STAGE_OUTPUT_DIRECTORY')
    slots = tuple(output / name for name in (
        'build-1', 'build-2', 'comparison.json', 'qualifier-input',
        'qualification.json', 'qualification.rawlog', 'lifecycle.json', 'lifecycle.rawlog'))
    need(not any(path.exists() or path.is_symlink() for path in slots),
         'FRESH_FAMILY_STAGE_OUTPUTS')
    need(not work.exists() and (work.parent.is_dir() or work.parent == output),
         'FRESH_FAMILY_QUALIFIER_WORK')
    # Failure retention must be possible even if the first build creates nothing.
    need(not failure_output.exists() and failure_output.parent.is_dir(),
         'FRESH_FAMILY_FAILURE_OUTPUT')
    reads = (source, inventory, cache)
    writes = (*slots, work, failure_output)
    for index, path in enumerate(writes):
        need(all(not path.is_relative_to(other) and not other.is_relative_to(path)
                 for other in (*reads, *writes[:index])),
             'DISJOINT_FAMILY_STAGE_WRITE_PATHS')


def run_stage(plan,executor,*,source,source_map_sha256,output,work,failure_output,pair_only=False):
    check_stage_workspace(source=source, inventory=plan['inventory_path'], cache=plan['cache'],
                          output=output, work=work, failure_output=failure_output)
    binding=require_actual_family(plan['component'],source=source,source_map_sha256=source_map_sha256)
    need(plan['image']==binding['image'] and plan['nonce']==binding['nonce']
         and plan['inventory_pin']==binding['inventory_pin'],'SAME_ACTUAL_STAGE_BINDING')
    canonical=stage_commands(source=source,source_map_sha256=source_map_sha256,component=plan['component'],
        output=output,image=binding['image'],inventory=plan['inventory_path'],cache=plan['cache'],nonce=binding['nonce'])
    need(C.encoded(plan)==C.encoded(canonical),'EXACT_REDERIVED_STAGE_COMMANDS')
    need(callable(getattr(executor,'authenticate_Root_stage_binding',None)),'ACTUAL_ROOT_AUTHORITY_CALLBACK_REQUIRED')
    mapping=C.read_source(source,source_map_sha256)
    for name in ('pipeline.py','qualify.py','lifecycle.py'):
        row=mapping['files']['scripts/ci/qt612-complete-family-native-source/'+name]
        M.stream(HERE/name,{k:row[k] for k in ('bytes','sha256')},{},mode=0o644)
    executor.authenticate_Root_stage_binding(binding)
    return _drive_stage(plan,executor,source=source,source_map_sha256=source_map_sha256,
                        output=output,work=work,failure_output=failure_output,pair_only=pair_only)
