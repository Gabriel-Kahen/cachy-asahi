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
ISSUER_SHA = 'fea5348a93631157fa394ee12b9666ec54e2b667f5fc8f535a9aba9d634162db'
RECEIVER = 'scripts/install/native_arm_trial.py'
RECEIVER_SHA = '90aaedaad6ea79c1c9a172d12c7e8383c4375aa8f75ec81558dbcad26077a77d'
PROFILE_SHA = 'b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8'
OWN = 'scripts/install/native_preflight.py'
SOURCE_PATHS = ('scripts/install/local_transaction.py', 'scripts/install/test_local_transaction.py',
                RECEIVER, 'scripts/install/test_native_arm_trial.py', 'scripts/port/kernel-native-job/runtime.py')
CONFIG = {'ArgsEscaped':False, 'Cmd':[], 'Entrypoint':[],
          'Env':['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
          'ExposedPorts':None, 'Healthcheck':None, 'Labels':{}, 'Shell':[], 'StopSignal':None,
          'User':'alarm', 'Volumes':None, 'WorkingDir':'/tmp'}


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
    need(type(composition) is str and composition=='installer-preflight' and type(selected) is dict and
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
    if state.get('p0_scope') is not None:
        current = vars(type(session))['p0_context'](session)
        selected = vars(module)['validate_input_successor'](current['input_successor'])
        need(selected == grant['input_successor'] and
             current['source_view_inputs_sha256'] == selected['historical_inputs_sha256'] and
             type(current['inputs_raw']) is bytes and len(current['inputs_raw']) == selected['inputs_bytes'] and
             sha(current['inputs_raw']) == selected['inputs_sha256'] and
             type(current['packages_raw']) is bytes and len(current['packages_raw']) == selected['packages_bytes'] and
             sha(current['packages_raw']) == selected['packages_sha256'], 'INPUT_SUCCESSOR')
        context = {**context, 'input_successor': selected, 'inputs_raw': current['inputs_raw'],
                   'packages_raw': current['packages_raw'],
                   'source_view_inputs_sha256': current['source_view_inputs_sha256']}
    tick(end); return context


def image_handoff(observed, controller, receiver, inputs_raw, packages_raw, *, input_successor=None):
    inputs_sha, packages_sha = receiver.input_selection(input_successor)
    if input_successor is not None:
        input_successor = receiver.validate_input_successor(input_successor)
        need(type(inputs_raw) is bytes and len(inputs_raw) == input_successor['inputs_bytes'] and
             type(packages_raw) is bytes and len(packages_raw) == input_successor['packages_bytes'], 'INPUT_SUCCESSOR')
    need(type(observed) is list and len(observed)==1 and type(observed[0]) is dict, 'IMAGE_INSPECT')
    image = observed[0]
    need(image.get('Id') == controller.image and image.get('Architecture') == 'arm64' and
         image.get('Os') == 'linux' and sha(inputs_raw) == inputs_sha and
         sha(packages_raw) == packages_sha, 'IMAGE_BINDING')
    full_config = image.get('Config'); need(type(full_config) is dict, 'IMAGE_CONFIG')
    # Project execution policy, normalizing only absent/empty execution defaults.
    config = {key:full_config.get(key) for key in CONFIG}
    for key in ('Cmd', 'Entrypoint', 'Shell'):
        if config[key] is None: config[key] = []
    if config['ArgsEscaped'] is None: config['ArgsEscaped'] = False
    canonical = dict(config)
    if canonical.get('Entrypoint') == ['']: canonical['Entrypoint'] = []
    if canonical.get('Labels') is None: canonical['Labels'] = {}
    changed=[key+':'+type_label(canonical[key]) for key in CONFIG
             if (key in ('Cmd', 'Entrypoint', 'Shell') and type(canonical[key]) is not list) or
             (key=='ArgsEscaped' and type(canonical[key]) is not bool) or canonical[key]!=CONFIG[key]]
    need(not changed, 'IMAGE_CONFIG '+','.join(changed))
    value = dict(source_commit=controller.commit,image_id=controller.image,inputs_sha256=inputs_sha,
                 packages_lock_sha256=packages_sha,architecture='arm64',os='linux',Config=config)
    if input_successor is not None:
        value.update(input_successor=input_successor, tool_profile_lineage=receiver.TOOL_PROFILE_LINEAGE)
    return value


def selection(sources, controller, receiver, handoff, nonce, *, input_successor=None):
    inputs_sha, packages_sha = receiver.input_selection(input_successor)
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE')
    need(sha(receiver.PROFILE_BYTES) == PROFILE_SHA, 'PROFILE_PIN')
    value = dict(schema_version=1,purpose='native-arm-synthetic-installer',phase='preflight',
        source_commit=controller.commit,sources={name:{'size':len(sources.raw[name]),'sha256':sha(sources.raw[name])}
        for name in SOURCE_PATHS},tool_profile_sha256=PROFILE_SHA,native_inputs_sha256=inputs_sha,
        builder_packages_sha256=packages_sha,image_id=controller.image,
        image_config_sha256=sha(encoded(handoff['Config'])),native_handoff_sha256=sha(encoded(handoff)),nonce=nonce)
    if input_successor is not None:
        selected = receiver.validate_input_successor(input_successor)
        receiver.validate_input_successor(handoff.get('input_successor'))
        need(handoff.get('input_successor') == selected and
             type(handoff.get('tool_profile_lineage')) is str and
             handoff.get('tool_profile_lineage') == receiver.TOOL_PROFILE_LINEAGE and
             handoff.get('inputs_sha256') == inputs_sha and
             handoff.get('packages_lock_sha256') == packages_sha, 'INPUT_SUCCESSOR')
        value.update(input_successor=selected, tool_profile_lineage=receiver.TOOL_PROFILE_LINEAGE)
    receiver.validate_selection(value); return value


def type_label(value):
    kind=type(value)
    for builtin,label in ((type(None),'NoneType'),(bool,'bool'),(int,'int'),(float,'float'),
                          (str,'str'),(list,'list'),(dict,'dict')):
        if kind is builtin: return label
    return 'UNKNOWN'


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
         row.get('AppArmorProfile')==dev_apparmor_name() and config.get('User')==f'{os.getuid()}:{os.getgid()}' and config.get('Entrypoint')==['/usr/bin/python3'] and
         config.get('Cmd')==['-I','-B','/source/scripts/install/native_arm_trial.py','--selection','/inputs/trial.json',
                            '--selection-sha256',sha(encoded(trial))], 'CONTAINER_BINDING')
    need(environment_matches(config.get('Env'),CONFIG['Env']+['CACHY_ASAHI_INSTALL_NONCE='+trial['nonce'],
         'CACHY_ASAHI_INSTALL_IMAGE='+trial['image_id']]) and not config.get('Volumes') and
         not config.get('Healthcheck'), 'CONTAINER_ENV')
    need(host.get('NetworkMode')=='none' and host.get('CgroupnsMode')=='private' and
         host.get('Privileged') is False and host.get('ReadonlyRootfs') is True and host.get('CapDrop')==['ALL'] and
         not host.get('CapAdd') and not host.get('Devices') and not host.get('DeviceRequests') and
         host.get('Memory')==2*1024**3 and host.get('NanoCpus')==2*10**9 and host.get('PidsLimit')==128 and
         dev_security_options(host.get('SecurityOpt')), 'CONTAINER_POLICY')
    need(host.get('Tmpfs')=={'/tmp':'rw,nosuid,nodev,exec,size=512m,mode=1777'}, 'CONTAINER_TMPFS')
    mounts=row.get('Mounts'); need(type(mounts) is list and len(mounts)==3, 'CONTAINER_MOUNTS')
    expected={(str(source),'/source',False),(str(inputs),'/inputs',False),(str(output),'/out',True)}
    need(all(type(m) is dict and m.get('Type')=='bind' and type(m.get('RW')) is bool and
             m.get('Propagation')=='rprivate' for m in mounts) and
         {(m.get('Source'),m.get('Destination'),m.get('RW')) for m in mounts}==expected, 'CONTAINER_MOUNTS')


def accept(result, public_raw, private_raw, receiver, cleanup, end, *, input_successor=None):
    tick(end)
    record = strict(public_raw)
    need(receiver.public(record) == public_raw and strict(private_raw) == record, 'RECEIVER_RESULT')
    if input_successor is not None:
        selected = receiver.validate_input_successor(input_successor)
        need(record.get('input_successor') == selected and
             record.get('tool_profile_lineage') == receiver.TOOL_PROFILE_LINEAGE, 'INPUT_SUCCESSOR')
    else:
        need('input_successor' not in record and 'tool_profile_lineage' not in record, 'INPUT_SUCCESSOR')
    need_preflight_result(type(result['exit_code']) is int and result['exit_code'] == 0 and record['status'] == 'PASS_NATIVE_PREFLIGHT_ONLY' and
         record['phase'] == 'complete' and record['ABI'] == record['matrix'] == 'NOT_RUN' and
         type(cleanup) is dict and cleanup == {'remove_exit':0,'absent':True} and
         type(cleanup['remove_exit']) is int and type(cleanup['absent']) is bool, 'P0_REFUSED', record, receiver)
    return record


def run(session, controller, output, *, deadline, nonce, runtime_contract):
    """Root-wired in-process bridge; construction/registration grants no execution."""
    started = time.monotonic(); tick(deadline); end = min(deadline,started+60)
    context = live(session,controller,end); sources = session.sources
    need(type(runtime_contract) is dict and set(runtime_contract)=={'cli_sha256','endpoint_identity','env'} and
         sha((json.dumps(runtime_contract,sort_keys=True,indent=2)+'\n').encode()) == sources.grant['actor_contract_sha256'],
         'ACTOR_CONTRACT')
    need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and
         os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'NATIVE_ORDINARY_HOST')
    output = Path(output)
    need(output.is_absolute() and '..' not in output.parts and not output.exists() and
         all(stat.S_ISDIR(p.lstat().st_mode) for p in output.parents) and
         not any(output.is_relative_to(p) or p.is_relative_to(output) for p in
                 (sources.root,context['root'],Path(controller.native_out))), 'OUTPUT_BOUNDARY')
    receiver = sources.module('native_install_receiver',RECEIVER)
    # Authenticate loaded code and immutable global facts through captured Sources.
    sources.graph_namespace(receiver,RECEIVER,{RECEIVER:receiver},{},{})
    namespace(receiver,sources.raw[RECEIVER],RECEIVER_SHA)
    transport = session.source_graph['runtime']['transport']
    output.mkdir(mode=0o700); inputs=output/'inputs'; inputs.mkdir(mode=0o700)
    child=output/'child'; child.mkdir(mode=0o700)
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'NONCE')
    name='cachy-asahi-install-'+nonce; cli=None; cid=None; cleanup={'remove_exit':None,'absent':False}
    result=None; failure=None; report=None; command_rows=[]; cancelled=False; cleanup_uncertain=False
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
        cli=transport.DockerTransport(**runtime_contract,create_validator=lambda _:None)
        guard()
        info=command(['info','--format','{{json .}}'],end-10)
        daemon=strict(info['stdout']); need(info['exit_code']==0 and daemon.get('Architecture') in ('aarch64','arm64') and
                                           daemon.get('OSType')=='linux','NATIVE_LOCAL_DAEMON')
        inspected=command(['image','inspect',controller.image],end-10)
        need(inspected['exit_code']==0,'IMAGE_INSPECT')
        raw,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(Path(controller.native_out)/'inputs.lock.json',end)
        packages,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(Path(controller.native_out)/'packages.lock',end)
        input_successor = context.get('input_successor')
        if input_successor is not None:
            need(raw == context['inputs_raw'] and packages == context['packages_raw'], 'INPUT_SUCCESSOR')
        image=image_handoff(strict(inspected['stdout']),controller,receiver,raw,packages,
                            input_successor=input_successor)
        trial=selection(sources,controller,receiver,image,nonce,input_successor=input_successor)
        for path,data in ((inputs/'image.json',encoded(image)),(inputs/'trial.json',encoded(trial)),(inputs/'dev-seccomp.json',receiver.DEV_SECCOMP_BYTES)):
            with path.open('xb') as stream: stream.write(data)
            path.chmod(0o600)
        guard(); args=receiver.docker_command(trial,sources.root,inputs,child)
        need(args[3]==name,'CONTAINER_NAME')
        args[1]='create'; args[2:2]=['--cidfile',str(output/'container-id')]
        created=command(args[1:],end-10)
        need(created['exit_code']==0,'CONTAINER_CREATE')
        cid_raw,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(output/'container-id',end,limit=128)
        candidate=cid_raw.decode('ascii').strip()
        need(re.fullmatch('[0-9a-f]{64}',candidate) and created['stdout'].strip()==candidate.encode(), 'CONTAINER_ID')
        cid=candidate
        inspected=command(['container','inspect',candidate],end-10)
        need(inspected['exit_code']==0,'CONTAINER_INSPECT')
        container_binding(strict(inspected['stdout']),candidate,name,trial,sources.root,inputs,child)
        cid=candidate
        result=command(['start','--attach',cid],end-10)
    except BaseException as error:
        failure=error
        cancelled=isinstance(error,KeyboardInterrupt)
    finally:
        if cli is not None:
            if cid is not None:
                try:
                    removed=command(['rm','-f',cid],end-5); cleanup['remove_exit']=removed['exit_code']
                    remaining=command(['container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}'],end)
                    cleanup['absent']=remaining['exit_code']==0 and remaining['stdout']==b''
                except BaseException as error:
                    cancelled |= isinstance(error,KeyboardInterrupt)
                    cleanup_uncertain=True
                    if failure is None:failure=error
            try: cli.close()
            except BaseException as error:
                cancelled |= isinstance(error,KeyboardInterrupt)
                cleanup_uncertain=True
                if failure is None:failure=error
    if failure is None:
        raw,_,_=session.sources.module('_preflight_issuer',HANDOFF).read(child/'result.json',end,limit=4096)
        report=accept(result,result['stdout'],raw,receiver,cleanup,end,input_successor=context.get('input_successor'))
        live(session,controller,end)
    if failure is not None:
        BaseException.__setattr__(failure,'native_preflight_cancelled',cancelled)
        BaseException.__setattr__(failure,'native_preflight_cleanup_uncertain',cleanup_uncertain)
        raise failure
    value = {'status':'PASS','stage':'native-install-preflight','receiver':report,'cleanup':cleanup,
             'elapsed_seconds':time.monotonic()-started,'ABI':'NOT RUN','native_matrix':'NOT RUN',
             'hardware_validation':'NOT RUN','selected_for_release':False,'public':[]}
    if context.get('input_successor') is not None:
        value.update(input_successor=receiver.validate_input_successor(context['input_successor']),
                     tool_profile_lineage=receiver.TOOL_PROFILE_LINEAGE)
    return value


def environment_matches(observed, expected):
    """Unique exact entries; image/CLI environment merging may reorder them."""
    return (type(observed) is list and len(observed) == len(expected) and
            all(type(value) is str for value in observed) and set(observed) == set(expected))


def need_preflight_result(value, code, record, receiver):
    """Best-effort existing public fields only; original refusal remains primary."""
    try:
        need(value, code)
    except BaseException as first:
        try:
            keys = ('schema_version','status','phase','barrier','ABI','matrix','tests',
                    'failures','errors','skips','termination','owned_child_cleanup','first_failure')
            sys.stderr.buffer.write(receiver.public({key: record[key] for key in keys}))
            sys.stderr.buffer.flush()
        except BaseException as error:
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                try:
                    BaseException.__setattr__(first, 'native_preflight_cancelled', True)
                    BaseException.__setattr__(first, 'native_preflight_cleanup_uncertain', True)
                except BaseException:
                    pass
        raise


def dev_security_options(value):
    """Exact Docker CLI compacted policy; no arbitrary custom/unconfined policy."""
    return (type(value) is list and len(value) == 3 and
            value[0] in ('no-new-privileges', 'no-new-privileges=true') and
            type(value[1]) is str and value[1].startswith('seccomp=') and
            value[2] == 'apparmor=' + dev_apparmor_name() and
            sha(value[1][8:].encode()) == 'd0996a8cdf2c8ed29a69dbcdea8c1b2ad905d2e820518c974af2baa555c7c9ad')


def dev_apparmor_name():
    """Unique DEV job identity; arbitrary host profile selectors are refused."""
    parts = (os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_RUN_ATTEMPT'))
    if not all(type(v) is str and 0 < len(v) <= 20 and all('0' <= c <= '9' for c in v) for v in parts):
        raise ValueError('CONTAINER_POLICY')
    return 'cachy-asahi-p0-dev-' + '-'.join(parts)
