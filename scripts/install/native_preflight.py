#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preflight-only consumer of the live captured native development owner."""
import ast
import builtins
import contextlib
import hashlib
import importlib
import json
import marshal
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

HANDOFF = 'scripts/ci/development/repository_handoff.py'
# Root must rebind after any separately reviewed issuer change.
ISSUER_SHA = '1329653ab38468b92c08abe9426a176509b5586fab3a07a1e9432c90cb704219'
RECEIVER = 'scripts/install/native_arm_trial.py'
RECEIVER_SHA = '597f244bbd957cfc63b4635aa769f589e78d082aac71e153240a0797a806cc97'
PROFILE_SHA = 'db58bda8102ce098eded530f0920c21c1f09cb7a6cfb1d03ab84f0dfbf63d3f7'
OWN = 'scripts/install/native_preflight.py'
SOURCE_PATHS = ('scripts/install/local_transaction.py', 'scripts/install/test_local_transaction.py',
                RECEIVER, 'scripts/install/test_native_arm_trial.py', 'scripts/port/kernel-native-job/runtime.py')
CONFIG = {'ArgsEscaped':False, 'Cmd':[], 'Entrypoint':[],
          'Env':['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
          'ExposedPorts':None, 'Healthcheck':None, 'Labels':{}, 'Shell':[], 'StopSignal':None,
          'User':'alarm', 'Volumes':None, 'WorkingDir':'/tmp'}

# Moby 28.0.4 container.Config JSON omitempty fields, constrained to CONFIG.
OPTIONAL_CONFIG = ('ArgsEscaped','ExposedPorts','Healthcheck','Shell','StopSignal')


def need(value, code):
    if not value: raise ValueError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return (json.dumps(value, sort_keys=True, allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'JSON_DUPLICATE'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'JSON_NONFINITE'))


def tick(end):
    need(type(end) in (int,float) and math.isfinite(end) and time.monotonic() < end, 'DEADLINE')


def namespace(module, raw, pin):
    """Compare actual captured functions, defaults, constants and imports to source."""
    need(type(module) is types.ModuleType and sha(raw) == pin, 'ISSUER_PIN')
    expected = types.ModuleType(module.__name__); expected.__file__ = module.__file__
    exec(compile(raw,module.__file__,'exec'),expected.__dict__)
    def code_bytes(code):
        # Format 2 avoids active-frame sharing; tags preserve slice/tuple distinctions.
        def constant(value):
            kind=type(value)
            if kind is types.CodeType: return ('code',code_bytes(value))
            if kind is tuple: return ('tuple',tuple(constant(item) for item in value))
            if kind is frozenset: return ('frozenset',frozenset(constant(item) for item in value))
            if kind is slice: return ('slice',constant(value.start),constant(value.stop),constant(value.step))
            need(any(kind is builtin for builtin in
                     (type(None),type(Ellipsis),bool,int,float,complex,str,bytes)), 'ISSUER_CODE')
            return ('literal',value)
        need(type(code) is types.CodeType,'ISSUER_CODE')
        return marshal.dumps(code.replace(co_consts=tuple(constant(item) for item in code.co_consts)),2)
    def function(value, original):
        need(type(value) is types.FunctionType and type(original) is types.FunctionType, 'ISSUER_CODE')
        if hasattr(original,'__wrapped__'):
            need(value.__code__ is original.__code__ and value.__globals__ is vars(contextlib) and
                 value.__closure__ is not None and len(value.__closure__)==1 and
                 value.__closure__[0].cell_contents is getattr(value,'__wrapped__',None), 'ISSUER_WRAPPER')
            value=value.__wrapped__; original=original.__wrapped__
        need(value.__globals__ is vars(module) and code_bytes(value.__code__)==code_bytes(original.__code__) and
             value.__defaults__ == original.__defaults__ and value.__kwdefaults__ == original.__kwdefaults__ and
             value.__closure__ is None, 'ISSUER_CODE')
    for node in ast.parse(raw).body:
        if isinstance(node,ast.FunctionDef): function(vars(module).get(node.name),vars(expected)[node.name])
        elif isinstance(node,ast.ClassDef):
            cls=vars(module).get(node.name); original=vars(expected)[node.name]
            need(type(cls) is type and cls.__module__==module.__name__ and cls.__name__==node.name and
                 set(vars(cls))==set(vars(original)), 'ISSUER_CLASS')
            for member in node.body:
                if isinstance(member,ast.FunctionDef):
                    value=vars(cls).get(member.name); reference=vars(original)[member.name]
                    if isinstance(reference,(staticmethod,classmethod)):
                        need(type(value) is type(reference), 'ISSUER_CODE'); value=value.__func__; reference=reference.__func__
                    function(value,reference)
        elif isinstance(node,(ast.Assign,ast.AnnAssign)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                names=[target.id] if isinstance(target,ast.Name) else [n.id for n in target.elts] if isinstance(target,ast.Tuple) else []
                for name in names: need(vars(module).get(name)==vars(expected)[name], 'ISSUER_CONSTANT')
        elif isinstance(node,(ast.Import,ast.ImportFrom)):
            for alias in node.names:
                name=alias.asname or alias.name
                need(vars(module).get(name) is vars(expected)[name], 'ISSUER_IMPORT')
    language=vars(module).get('__builtins__')
    need(type(language) is dict and set(language)==set(vars(builtins)), 'ISSUER_BUILTINS')
    for name,value in vars(builtins).items():
        if name=='__import__' and language[name] is not value:
            # Sources.module's captured importer is authenticated by Sources.graph_namespace.
            need(pin != ISSUER_SHA and type(language[name]) is types.FunctionType,'ISSUER_BUILTINS')
        else: need(language[name] is value,'ISSUER_BUILTINS')


def issuer(module, raw): namespace(module,raw,ISSUER_SHA)


def live(session, controller, end):
    """No receipt, caller-created namespace or object can substitute for this owner."""
    tick(end)
    module = sys.modules.get('development_repository_handoff')
    need(type(module) is types.ModuleType and type(type(session)) is type and
         type(session) is vars(module).get('Session'), 'LIVE_OWNER_REQUIRED')
    def plain(value):
        descriptor=vars(type(value)).get('__dict__')
        need(type(descriptor) is types.GetSetDescriptorType and descriptor.__objclass__ is type(value),
             'LIVE_OWNER_REQUIRED')
        state=descriptor.__get__(value,type(value))
        need(type(state) is dict and all(type(key) is str for key in state),'LIVE_OWNER_REQUIRED')
        return state
    sources=plain(session).get('sources')
    need(type(type(sources)) is type and type(sources) is vars(module).get('Sources'),'LIVE_OWNER_REQUIRED')
    raw=plain(sources).get('raw')
    need(type(raw) is dict and all(type(key) is str for key in raw) and
         all(name in raw and type(raw[name]) is bytes for name in (HANDOFF,OWN,RECEIVER)), 'REGISTRATION_REQUIRED')
    issuer(module,raw[HANDOFF])
    methods=vars(type(sources))
    state=methods['class_state'](sources,session,HANDOFF,module)
    source_state=methods['class_state'](sources,sources,HANDOFF,module)
    need(type(state) is dict and type(source_state) is dict and
         all(type(key) is str for key in state) and all(type(key) is str for key in source_state) and
         state.get('sources') is sources,'LIVE_OWNER_REQUIRED')
    grant=source_state.get('grant')
    need(type(grant) is dict and all(type(key) is str for key in grant),'REGISTRATION_REQUIRED')
    rows=grant.get('source_files')
    need(type(rows) is dict and all(type(key) is str for key in rows) and type(rows.get(OWN)) is dict and
         all(type(key) is str for key in rows[OWN]) and type(rows[OWN].get('sha256')) is str,'REGISTRATION_REQUIRED')
    own_module = sys.modules.get(__name__)
    need(type(own_module) is types.ModuleType and own_module.__dict__ is globals(), 'BRIDGE_NAMESPACE')
    methods['graph_namespace'](sources,own_module,OWN,{OWN:own_module},{},{})
    namespace(own_module,raw[OWN],rows[OWN]['sha256'])
    graph=methods['source_graph'](sources,session); selected=state.get('source_graph'); composition=state.get('composition')
    need(type(composition) is str and composition=='installer-preflight-maintained-v1' and type(selected) is dict and
         all(type(key) is str for key in selected) and set(selected)=={
             'entry','runtime','collector','phase','original','original_aliases','native_preflight'} and
         selected['native_preflight'] is own_module and type(graph) is dict and
         all(type(key) is str for key in graph) and graph.get(OWN) is own_module, 'LIVE_GRAPH_REQUIRED')
    methods['guard'](sources,end,state.get('cancelled'))
    context = vars(type(session))['original_context'](session,deadline=end,controller=controller)
    need(state['result']['initial_exit_code'] is None and state['controller'] is controller and
         controller.cancelled is False and not context['original']['integration'].CANCEL_REQUESTED,
         'LIVE_OWNER_REQUIRED')
    # original_context permits a post-return inspection too; this consumer does not.
    frame, run_frame, observed = state['native_consumer_observation']
    active = []; current = sys._getframe()
    for _ in range(64):
        active.append(current)
        if current.f_back is None: break
        current = current.f_back
    need(observed is controller and frame in active and run_frame in active, 'ACTIVE_NATIVE_OWNER_REQUIRED')
    need(sha(sources.raw[RECEIVER]) == RECEIVER_SHA, 'RECEIVER_PIN')
    for name in (OWN,*SOURCE_PATHS):
        need(name in sources.raw and name in sources.grant['source_files'], 'REGISTRATION_REQUIRED')
    tick(end); return context


def image_handoff(observed, controller, receiver, inputs_raw, packages_raw):
    need(type(observed) is list and len(observed)==1 and type(observed[0]) is dict, 'IMAGE_INSPECT')
    image = observed[0]
    need(image.get('Id') == controller.image and image.get('Architecture') == 'arm64' and
         image.get('Os') == 'linux' and sha(inputs_raw) == receiver.INPUTS_SHA and
         sha(packages_raw) == receiver.BASE_SHA, 'IMAGE_BINDING')
    full_config = image.get('Config'); need(type(full_config) is dict, 'IMAGE_CONFIG')
    # Preserve the sparse raw policy projection; defaults affect validation only.
    missing = [key+':UNKNOWN' for key in CONFIG if key not in OPTIONAL_CONFIG and key not in full_config]
    need(not missing, 'IMAGE_CONFIG '+','.join(missing))
    config = {key:full_config[key] for key in CONFIG if key in full_config}
    canonical = {key:config.get(key) for key in CONFIG}
    # Only reviewed absent/null defaults normalize; present wrong values fail.
    for key in ('Cmd','Entrypoint','Shell'):
        if canonical[key] is None: canonical[key] = []
    if canonical['ArgsEscaped'] is None: canonical['ArgsEscaped'] = False
    if canonical.get('Entrypoint') == ['']: canonical['Entrypoint'] = []
    if canonical.get('Labels') is None: canonical['Labels'] = {}
    changed=[key+':'+type_label(canonical[key]) for key in CONFIG
             if canonical[key]!=CONFIG[key] or key=='ArgsEscaped' and type(canonical[key]) is not bool]
    need(not changed, 'IMAGE_CONFIG '+','.join(changed))
    return dict(source_commit=controller.commit,image_id=controller.image,inputs_sha256=receiver.INPUTS_SHA,
                packages_lock_sha256=receiver.BASE_SHA,architecture='arm64',os='linux',Config=config)


def selection(sources, controller, receiver, handoff, nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE')
    need(sha(receiver.PROFILE_BYTES) == PROFILE_SHA, 'PROFILE_PIN')
    value = dict(schema_version=1,purpose='maintained-native-arm-synthetic-installer-v1',phase='preflight',
        source_commit=controller.commit,sources={name:{'size':len(sources.raw[name]),'sha256':sha(sources.raw[name])}
        for name in SOURCE_PATHS},tool_profile_sha256=PROFILE_SHA,native_inputs_sha256=receiver.INPUTS_SHA,
        builder_packages_sha256=receiver.BASE_SHA,image_id=controller.image,
        image_config_sha256=sha(encoded(handoff['Config'])),native_handoff_sha256=sha(encoded(handoff)),nonce=nonce)
    receiver.validate_selection(value); return value


def type_label(value):
    kind=type(value)
    for builtin,label in ((type(None),'NoneType'),(bool,'bool'),(int,'int'),(float,'float'),
                          (str,'str'),(list,'list'),(dict,'dict')):
        if kind is builtin: return label
    return 'UNKNOWN'


def container_environment(config, trial):
    """Require each exact Env entry once, allowing only its documented reordering."""
    env = config.get('Env')
    expected = CONFIG['Env']+['CACHY_ASAHI_INSTALL_NONCE='+trial['nonce'],
        'CACHY_ASAHI_INSTALL_IMAGE='+trial['image_id']]
    if not (type(env) is list and len(env)==len(expected) and
            all(type(entry) is str for entry in env) and sorted(env)==sorted(expected)):field = 'ENV_EQUALITY'
    elif config.get('Volumes'):field = 'VOLUMES_FALSEY'
    elif config.get('Healthcheck'):field = 'HEALTHCHECK_FALSEY'
    else:field = None
    try:need(field is None, 'CONTAINER_ENV')
    except ValueError as error:
        try:
            state = BaseException.__dict__['__dict__'].__get__(error,type(error))
            state['native_preflight_container_field'] = field
        except BaseException as secondary:retain_failure(error, secondary)
        raise


def container_binding(rows, cid, name, trial, source, inputs, output):
    need(type(rows) is list and len(rows)==1 and type(rows[0]) is dict, 'CONTAINER_INSPECT')
    row=rows[0]; config=row.get('Config',{}); host=row.get('HostConfig',{})
    need(type(config) is dict and type(host) is dict and all(type(key) is str for key in host), 'CONTAINER_INSPECT_SHAPE')
    # Inspect resolved defaults; never infer a private namespace from missing data.
    for key, expected in (('PidMode',''),('IpcMode','private'),('UTSMode',''),('UsernsMode',''),('AutoRemove',False)):
        observed=host.get(key)
        need(key in host and type(observed) is type(expected) and observed==expected,
             'CONTAINER_POLICY '+key+':'+(type_label(observed) if key in host else 'missing'))
    restart=host.get('RestartPolicy')
    need(type(restart) is dict and all(type(key) is str for key in restart) and
         set(restart)=={'Name','MaximumRetryCount'} and
         type(restart['Name']) is str and restart['Name']=='no' and
         type(restart['MaximumRetryCount']) is int and restart['MaximumRetryCount']==0,
         'CONTAINER_POLICY RestartPolicy:'+ (type_label(restart) if 'RestartPolicy' in host else 'missing'))
    need(row.get('Id')==cid and row.get('Name')=='/'+name and row.get('Image')==trial['image_id'] and
         config.get('User')==f'{os.getuid()}:{os.getgid()}' and config.get('Entrypoint')==['/usr/bin/python3'] and
         config.get('Cmd')==['-I','-B','/source/scripts/install/native_arm_trial.py','--selection','/inputs/trial.json',
                            '--selection-sha256',sha(encoded(trial))], 'CONTAINER_BINDING')
    container_environment(config, trial)
    need(host.get('NetworkMode')=='none' and host.get('CgroupnsMode')=='private' and
         host.get('Privileged') is False and host.get('ReadonlyRootfs') is True and host.get('CapDrop')==['ALL'] and
         not host.get('CapAdd') and not host.get('Devices') and not host.get('DeviceRequests') and
         host.get('Memory')==2*1024**3 and host.get('NanoCpus')==2*10**9 and host.get('PidsLimit')==128 and
         host.get('SecurityOpt') in (['no-new-privileges'],['no-new-privileges=true']), 'CONTAINER_POLICY')
    need(host.get('Tmpfs')=={'/tmp':'rw,nosuid,nodev,exec,size=512m,mode=1777'}, 'CONTAINER_TMPFS')
    mounts=row.get('Mounts'); need(type(mounts) is list and len(mounts)==3, 'CONTAINER_MOUNTS')
    expected={(str(source),'/source',False),(str(inputs),'/inputs',False),(str(output),'/out',True)}
    need(all(type(m) is dict and m.get('Type')=='bind' and type(m.get('RW')) is bool and
             m.get('Propagation')=='rprivate' for m in mounts) and
         {(m.get('Source'),m.get('Destination'),m.get('RW')) for m in mounts}==expected, 'CONTAINER_MOUNTS')


def receiver_public_record(record, public_sha256):
    """Closed receiver.public schema and canonical-byte binding; no acceptance grant."""
    keys=('schema_version','status','phase','barrier','ABI','matrix','tests','failures','errors','skips','termination','owned_child_cleanup','first_failure')
    if (type(record) is not dict or not all(type(key) is str for key in record) or set(record)!=set(keys) or
            type(public_sha256) is not str or len(public_sha256)!=64):return None
    if not all(type(record[key]) is str for key in ('status','phase','barrier','ABI','matrix','owned_child_cleanup','first_failure')):return None
    if not (type(record['schema_version']) is int and record['schema_version']==1 and
            record['status'] in ('REFUSED','FAIL','PASS_NATIVE_PREFLIGHT_ONLY','PASS_NATIVE_FIXTURE_ONLY') and
            record['phase'] in ('inputs','preflight','ABI','matrix','complete') and
            all(record[key] in ('NOT_RUN','PASS') for key in ('barrier','ABI','matrix')) and
            record['first_failure'] in ('NONE','INPUT_REFUSED','BARRIER_FAILED','ABI_FAILED','MATRIX_FAILED','CANCELLED','SOURCE_DRIFT','CHILD_CLEANUP','IO_OR_TOOL_FAILED','PUBLICATION_FAILED','INTERNAL') and
            record['owned_child_cleanup'] in ('UNKNOWN','NOT_STARTED','PASS','FAIL') and type(record['termination']) is bool and
            all(type(record[key]) is int and 0<=record[key]<=26 for key in ('tests','failures','errors','skips'))):return None
    if record['status']=='PASS_NATIVE_PREFLIGHT_ONLY' and not (record['phase']=='complete' and record['barrier']=='PASS' and record['ABI']==record['matrix']=='NOT_RUN' and record['tests']==1 and record['owned_child_cleanup']=='PASS' and record['first_failure']=='NONE' and not any(record[key] for key in ('failures','errors','skips','termination'))):return None
    if record['status']=='PASS_NATIVE_FIXTURE_ONLY' and not (record['phase']=='complete' and record['barrier']==record['ABI']==record['matrix']=='PASS' and record['tests']==26 and record['owned_child_cleanup']=='PASS' and record['first_failure']=='NONE' and not any(record[key] for key in ('failures','errors','skips','termination'))):return None
    value={key:record[key] for key in keys}
    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
    if len(raw)>4096 or hashlib.sha256(raw).hexdigest()!=public_sha256:return None
    return value


def receiver_acceptance_fact(result, record, cleanup):
    """Three closed acceptance booleans; no raw child result or diagnostics."""
    if not all(type(value) is dict and all(type(key) is str for key in value)
               for value in (result,record,cleanup)): return None
    code=result.get('exit_code')
    if not all(type(record.get(key)) is str for key in ('status','phase','ABI','matrix')):return None
    remove=cleanup.get('remove_exit');absent=cleanup.get('absent')
    return {'start_success':type(code) is int and code==0,
            'receiver_preflight_only':record['status']=='PASS_NATIVE_PREFLIGHT_ONLY' and
                record['phase']=='complete' and record['ABI']==record['matrix']=='NOT_RUN',
            'native_cleanup_pass':set(cleanup)=={'remove_exit','absent'} and
                type(remove) is int and remove==0 and type(absent) is bool and absent is True}


def accept(result, public_raw, private_raw, receiver, cleanup, end):
    tick(end)
    record = strict(public_raw)
    need(receiver.public(record) == public_raw and strict(private_raw) == record, 'RECEIVER_RESULT')
    try:
        need(type(result['exit_code']) is int and result['exit_code'] == 0 and record['status'] == 'PASS_NATIVE_PREFLIGHT_ONLY' and
             record['phase'] == 'complete' and record['ABI'] == record['matrix'] == 'NOT_RUN' and
             type(cleanup) is dict and cleanup == {'remove_exit':0,'absent':True} and
             type(cleanup['remove_exit']) is int and type(cleanup['absent']) is bool, 'P0_REFUSED')
    except ValueError as error:
        try:
            detail=receiver_acceptance_fact(result,record,cleanup)
            if detail is not None:
                detail.update(receiver_public=dict(record),receiver_public_sha256=sha(public_raw))
                state=BaseException.__dict__['__dict__'].__get__(error,type(error))
                state['native_preflight_receiver_accept']=detail
        except BaseException as secondary:retain_failure(error,secondary)
        raise
    return record


def retain_failure(first, secondary):
    """Keep an established first cause, including falsey errors and controls."""
    if first is None:first = secondary
    if first is not secondary:
        prior = first.__cause__
        if prior is not secondary:
            first.__cause__ = secondary if prior is None else BaseExceptionGroup(
                'native preflight secondary failure', [prior, secondary])
    if not isinstance(secondary, Exception):
        state = BaseException.__dict__['__dict__'].__get__(first, type(first))
        state['native_preflight_cancelled'] = True
    return first


RUN_DIAGNOSTIC_STAGES = ('ENTRY', 'LIVE_OWNER', 'ACTOR_CONTRACT', 'NATIVE_HOST', 'OUTPUT_BOUNDARY', 'RECEIVER_NAMESPACE', 'OUTPUT_CREATE', 'NONCE', 'TRANSPORT_CREATE', 'TRANSPORT_GUARD', 'DAEMON_INFO', 'IMAGE_INSPECT', 'IMAGE_HANDOFF', 'TRIAL_SELECTION', 'TRIAL_WRITE', 'CONTAINER_CREATE', 'CONTAINER_ID', 'CONTAINER_INSPECT', 'CONTAINER_BINDING', 'CONTAINER_START', 'CONTAINER_REMOVE', 'CONTAINER_ABSENCE', 'TRANSPORT_CLOSE', 'RECEIVER_ACCEPT', 'FINAL_LIVE', 'RETURN')
RUN_DIAGNOSTIC_PREDICATES = ('ACTIVE_NATIVE_OWNER_REQUIRED', 'ACTOR_CONTRACT', 'BRIDGE_NAMESPACE', 'COMMAND_CLEANUP', 'COMMAND_COUNT', 'CONTAINER_BINDING', 'CONTAINER_CREATE', 'CONTAINER_ENV', 'CONTAINER_ID', 'CONTAINER_INSPECT', 'CONTAINER_INSPECT_SHAPE', 'CONTAINER_MOUNTS', 'CONTAINER_NAME', 'CONTAINER_POLICY', 'CONTAINER_TMPFS', 'DEADLINE', 'IMAGE_BINDING', 'IMAGE_CONFIG', 'IMAGE_INSPECT', 'ISSUER_BUILTINS', 'ISSUER_CLASS', 'ISSUER_CODE', 'ISSUER_CONSTANT', 'ISSUER_IMPORT', 'ISSUER_PIN', 'ISSUER_WRAPPER', 'JSON_DUPLICATE', 'JSON_NONFINITE', 'LIVE_GRAPH_REQUIRED', 'LIVE_OWNER_REQUIRED', 'NATIVE_LOCAL_DAEMON', 'NATIVE_ORDINARY_HOST', 'NONCE', 'OUTPUT_BOUNDARY', 'P0_REFUSED', 'PROFILE_PIN', 'RECEIVER_PIN', 'RECEIVER_RESULT', 'REGISTRATION_REQUIRED')


def run_failure_fact(error, stage):
    """Closed existing exception facts only; preserve the exception and validators."""
    need(type(stage) is str and stage in RUN_DIAGNOSTIC_STAGES, 'DIAGNOSTIC_STAGE')
    predicate = 'OTHER'; image_config = None
    if type(error) is ValueError and type(error.args) is tuple and len(error.args) == 1 and type(error.args[0]) is str:
        value = error.args[0]
        if value in RUN_DIAGNOSTIC_PREDICATES:predicate = value
        elif value.startswith('IMAGE_CONFIG '):predicate = 'IMAGE_CONFIG'
        elif value.startswith('CONTAINER_POLICY '):predicate = 'CONTAINER_POLICY'
        if stage == 'CONTAINER_BINDING' and predicate == 'CONTAINER_ENV':
            state = BaseException.__dict__['__dict__'].__get__(error,type(error))
            field = state.get('native_preflight_container_field')
            if type(field) is str and field in ('ENV_EQUALITY','VOLUMES_FALSEY','HEALTHCHECK_FALSEY'):
                predicate = 'CONTAINER_ENV_'+field
        if stage == 'IMAGE_HANDOFF' and predicate == 'IMAGE_CONFIG':
            image_config = {'boundary':'UNKNOWN','fields':[]}
            if value == 'IMAGE_CONFIG':
                image_config['boundary'] = 'CONFIG_TYPE'
            elif len(value) <= 512:
                parts = [part.split(':') for part in value[len('IMAGE_CONFIG '):].split(',')]
                kinds = ('NoneType','bool','int','float','str','list','dict','UNKNOWN')
                if (1 <= len(parts) <= len(CONFIG) and all(len(part) == 2 and part[0] in CONFIG and part[1] in kinds for part in parts)):
                    names = [part[0] for part in parts]
                    if len(set(names)) == len(names) and tuple(names) == tuple(name for name in CONFIG if name in names):
                        image_config = {'boundary':'POLICY_FIELDS','fields':[{'name':name,'kind':kind} for name,kind in parts]}
    if stage=='RECEIVER_ACCEPT' and predicate=='P0_REFUSED':
        state=BaseException.__dict__['__dict__'].__get__(error,type(error))
        detail=state.get('native_preflight_receiver_accept')
        keys=('start_success','receiver_preflight_only','native_cleanup_pass')
        if (type(detail) is dict and all(type(key) is str for key in detail) and set(detail) in (set(keys),set(keys)|{'receiver_public','receiver_public_sha256'}) and
                all(type(detail[key]) is bool for key in keys) and not all(detail[key] for key in keys)):
            projected={key:detail[key] for key in keys}
            if 'receiver_public' in detail:
                public=receiver_public_record(detail['receiver_public'],detail['receiver_public_sha256'])
                if public is None or detail['receiver_preflight_only'] is not (public['status']=='PASS_NATIVE_PREFLIGHT_ONLY' and public['phase']=='complete' and public['ABI']==public['matrix']=='NOT_RUN'):
                    return {'schema_version':2,'stage':stage,'predicate':predicate,'image_config':image_config}
                projected.update(receiver_public=public,receiver_public_sha256=detail['receiver_public_sha256'])
            return {'schema_version':4 if 'receiver_public' in projected else 3,'stage':stage,'predicate':predicate,'image_config':None,
                    'receiver_accept':projected}
    return {'schema_version':2,'stage':stage,'predicate':predicate,'image_config':image_config}


def run(session, controller, output, *, deadline, nonce, runtime_contract):
    """Root-wired in-process bridge; construction/registration grants no execution."""
    stage = 'ENTRY'; failure_stage = None
    try:
        started = time.monotonic(); tick(deadline); end = min(deadline,started+60)
        stage = 'LIVE_OWNER'
        context = live(session,controller,end); sources = session.sources
        stage = 'ACTOR_CONTRACT'
        need(type(runtime_contract) is dict and set(runtime_contract)=={'cli_sha256','endpoint_identity','env'} and
             sha((json.dumps(runtime_contract,sort_keys=True,indent=2)+'\n').encode()) == sources.grant['actor_contract_sha256'],
             'ACTOR_CONTRACT')
        stage = 'NATIVE_HOST'
        need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and
             os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'NATIVE_ORDINARY_HOST')
        stage = 'OUTPUT_BOUNDARY'
        output = Path(output)
        need(output.is_absolute() and '..' not in output.parts and not output.exists() and
             all(stat.S_ISDIR(p.lstat().st_mode) for p in output.parents) and
             not any(output.is_relative_to(p) or p.is_relative_to(output) for p in
                     (sources.root,context['root'],Path(controller.native_out))), 'OUTPUT_BOUNDARY')
        stage = 'RECEIVER_NAMESPACE'
        receiver = sources.module('native_install_receiver',RECEIVER)
        # Authenticate loaded code and immutable global facts through captured Sources.
        sources.graph_namespace(receiver,RECEIVER,{RECEIVER:receiver},{},{})
        namespace(receiver,sources.raw[RECEIVER],RECEIVER_SHA)
        transport = session.source_graph['runtime']['transport']
        stage = 'OUTPUT_CREATE'
        output.mkdir(mode=0o700); inputs=output/'inputs'; inputs.mkdir(mode=0o700)
        child=output/'child'; child.mkdir(mode=0o700)
        stage = 'NONCE'
        need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE')
        name='cachy-asahi-install-'+nonce; cli=None; cid=None; cleanup={'remove_exit':None,'absent':False}
        result=None; failure=None; report=None; command_rows=[]
        def guard(): live(session,controller,end); cli._preflight()
        def command(args, cutoff):
            tick(cutoff); live(session,controller,cutoff); cli._preflight()
            value, observation = transport.supervise(['/proc/self/fd/'+str(cli.fd),*args],env=cli.env,
                deadline=cutoff,limit=1024**2,pass_fds=(cli.fd,),preflight=cli._preflight)
            need(observation['direct_child_reaped'] is True and observation['group_disposal_requested'] is True and
                 observation['forced_teardown'] is False and observation['cancelled'] is False, 'COMMAND_CLEANUP')
            need(len(command_rows)<8,'COMMAND_COUNT')
            path=output/('docker-'+str(len(command_rows))+'.json');command_rows.append(path)
            with path.open('xb') as stream:
                stream.write(encoded({'argv':args,'result':{'exit_code':value['exit_code'],
                             'stdout':value['stdout'].decode('utf-8','replace'),'stderr':value['stderr'].decode('utf-8','replace')},
                             'observation':observation}))
            path.chmod(0o600)
            return value
        try:
            stage = 'TRANSPORT_CREATE'
            cli=transport.DockerTransport(**runtime_contract,create_validator=lambda _:None)
            stage = 'TRANSPORT_GUARD'
            guard()
            stage = 'DAEMON_INFO'
            info=command(['info','--format','{{json .}}'],end-10)
            daemon=strict(info['stdout']); need(info['exit_code']==0 and daemon.get('Architecture') in ('aarch64','arm64') and
                                               daemon.get('OSType')=='linux','NATIVE_LOCAL_DAEMON')
            stage = 'IMAGE_INSPECT'
            inspected=command(['image','inspect',controller.image],end-10)
            need(inspected['exit_code']==0,'IMAGE_INSPECT')
            stage = 'IMAGE_HANDOFF'
            raw,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(Path(controller.native_out)/'inputs.lock.json',end)
            packages,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(Path(controller.native_out)/'packages.lock',end)
            image=image_handoff(strict(inspected['stdout']),controller,receiver,raw,packages)
            stage = 'TRIAL_SELECTION'
            trial=selection(sources,controller,receiver,image,nonce)
            stage = 'TRIAL_WRITE'
            for path,data in ((inputs/'image.json',encoded(image)),(inputs/'trial.json',encoded(trial))):
                with path.open('xb') as stream: stream.write(data)
                path.chmod(0o600)
            stage = 'CONTAINER_CREATE'
            guard(); args=receiver.docker_command(trial,sources.root,inputs,child)
            need(args[3]==name,'CONTAINER_NAME')
            args[1]='create'; args[2:2]=['--cidfile',str(output/'container-id')]
            created=command(args[1:],end-10)
            need(created['exit_code']==0,'CONTAINER_CREATE')
            stage = 'CONTAINER_ID'
            cid_raw,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(output/'container-id',end,limit=128)
            candidate=cid_raw.decode('ascii').strip()
            need(re.fullmatch('[0-9a-f]{64}',candidate) and created['stdout'].strip()==candidate.encode(), 'CONTAINER_ID')
            cid=candidate
            stage = 'CONTAINER_INSPECT'
            inspected=command(['container','inspect',candidate],end-10)
            need(inspected['exit_code']==0,'CONTAINER_INSPECT')
            stage = 'CONTAINER_BINDING'
            container_binding(strict(inspected['stdout']),candidate,name,trial,sources.root,inputs,child)
            cid=candidate
            stage = 'CONTAINER_START'
            result=command(['start','--attach',cid],end-10)
        except BaseException as error:
            failure_stage = stage
            failure=retain_failure(None,error)
        finally:
            if cli is not None:
                if cid is not None:
                    try:
                        stage = 'CONTAINER_REMOVE'
                        removed=command(['rm','-f',cid],end-5); cleanup['remove_exit']=removed['exit_code']
                        stage = 'CONTAINER_ABSENCE'
                        remaining=command(['container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}'],end)
                        cleanup['absent']=remaining['exit_code']==0 and remaining['stdout']==b''
                    except BaseException as error:
                        if failure is None:failure_stage = stage
                        failure=retain_failure(failure,error)
                stage = 'TRANSPORT_CLOSE'
                try: cli.close()
                except BaseException as error:
                    if failure is None:failure_stage = stage
                    failure=retain_failure(failure,error)
        if failure is None:
            stage = 'RECEIVER_ACCEPT'
            raw,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(child/'result.json',end,limit=4096)
            report=accept(result,result['stdout'],raw,receiver,cleanup,end)
            stage = 'FINAL_LIVE'
            live(session,controller,end)
        if failure is not None: raise failure
        stage = 'RETURN'
        return {'status':'PASS','stage':'native-install-preflight','receiver':report,'cleanup':cleanup,
                'elapsed_seconds':time.monotonic()-started,'ABI':'NOT RUN','native_matrix':'NOT RUN',
                'hardware_validation':'NOT RUN','selected_for_release':False,'public':[]}
    except BaseException as error:
        try:
            fact = run_failure_fact(error, failure_stage if failure_stage is not None else stage)
            state = BaseException.__dict__['__dict__'].__get__(error,type(error))
            state['native_preflight_run_fact'] = fact
        except BaseException as secondary:
            retain_failure(error, secondary)
            state = BaseException.__dict__['__dict__'].__get__(error,type(error))
            state['native_preflight_run_fact_failed'] = True
        raise
