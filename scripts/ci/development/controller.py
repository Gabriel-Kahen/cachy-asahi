#!/usr/bin/env python3
"""One finite native development job; local image consumers precede cleanup."""
import argparse
import ast
import base64
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import tarfile
import types

import packet
from common import command, digest, read_json, read_regular, require, save

ROOT = Path(__file__).resolve().parents[3]
STAGES = ('ksm', 'arm-c01-base', 'client', 'virtual')
PUBLIC_SELECTORS = {
    'ksm': {'adapter-status', 'recovery-status', 'public', 'public-material'},
    'arm-c01-base': {'adapter-status', 'recovery-status', 'public', 'owner/public', 'owner/public-status', 'owner/public-artifacts'},
    'client': {'adapter-status', 'owner-public'},
    'virtual': {'adapter-status', *('virtual-public/' + name for name in
                 ('result', 'events', 'minimal-frame', 'overlay-frame', 'qemu', 'tooling-launch',
                  'verify-launch', 'prepare-launch', 'runtime-launch', 'launcher'))},
}
CANCELLED = False
POLICY = None
CLOCK_ISSUER_SHA256 = '9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581'  # Independently reviewed pre-checkout issuer body.
VIRTUAL_NAMES = ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c',
                 'image_decode_probe.c', 'image_decode_report.py', 'controller.py',
                 'audit_tooling.py', 'tooling.lock.json', 'tooling-audit.json')
INSTALLER_PATH = 'scripts/install/native_preflight.py'
INSTALLER_NAME = 'native_install_preflight'
ZSH_NAMES = {'zsh_addon':'development_zsh_addon', 'zsh_session':'development_zsh_session'}


def finite(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except (OverflowError,TypeError,ValueError):return False


def within(deadline):
    require(finite(deadline) and time.monotonic() < deadline,
            'development-deadline-exceeded')


def private_input(path, pin, environment, limit):
    """Capture externally pinned private bootstrap bytes once, before interpretation."""
    path = Path(path).absolute()
    require(os.environ.get(environment + '_PATH') == str(path) and os.environ.get(environment + '_SHA256') == pin and
            type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) and '..' not in path.parts and
            not path.is_relative_to(ROOT) and all(not item.is_symlink() for item in path.parents),
            'bootstrap-input-binding-refused')
    node = lambda value:(value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                         value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and
            parent.st_uid == os.geteuid(), 'bootstrap-input-parent-refused')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600 and
            before.st_nlink == 1 and before.st_uid == os.geteuid() and 0 < before.st_size <= limit,
            'bootstrap-input-file-refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd);require(node(opened) == node(before), 'bootstrap-input-replaced')
        chunks = [];size = 0
        while True:
            raw = os.read(fd, min(65536, limit + 1 - size))
            if not raw:break
            chunks.append(raw);size += len(raw);require(size <= limit, 'bootstrap-input-bound-exceeded')
        require(node(os.fstat(fd)) == node(before), 'bootstrap-input-replaced')
        raw = b''.join(chunks)
    finally:os.close(fd)
    after = path.parent.lstat()
    require(node(path.lstat()) == node(before) and
            (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid) ==
            (parent.st_dev, parent.st_ino, parent.st_mode, parent.st_uid, parent.st_gid) and
            len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == pin, 'bootstrap-input-replaced')
    return raw


def clock_domain():
    info = time.get_clock_info('monotonic')
    require(info.monotonic and not info.adjustable and type(info.resolution) is float and
            0 < info.resolution <= 1 and 'CLOCK_MONOTONIC' in info.implementation, 'clock-domain-refused')
    with open('/proc/sys/kernel/random/boot_id', 'rb') as stream:boot = stream.read(128).strip().decode('ascii')
    require(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot), 'clock-domain-refused')
    before = os.stat('/proc/self/ns/time');fd = os.open('/proc/self/ns/time', os.O_RDONLY | os.O_CLOEXEC)
    try:opened = os.fstat(fd)
    finally:os.close(fd)
    after = os.stat('/proc/self/ns/time')
    require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino) == (after.st_dev, after.st_ino),
            'clock-domain-refused')
    with open('/proc/self/timens_offsets', 'rb') as stream:offsets = stream.read(1024)
    require(len(offsets) < 1024 and {tuple(line.split()) for line in offsets.splitlines()} ==
            {(b'monotonic', b'0', b'0'), (b'boottime', b'0', b'0')}, 'clock-domain-refused')
    return {'clock_id':'CLOCK_MONOTONIC', 'boot_id':boot,
            'time_namespace_device':opened.st_dev, 'time_namespace_inode':opened.st_ino}


def workflow_clock(raw, *, entry, controller_entry=None):
    value = packet.decode(raw)
    keys = {'schema_version', 'purpose', 'source_commit', 'run_id', 'run_attempt', 'nonce',
            'issued_monotonic', 'deadline_monotonic', 'allowance_seconds', 'clock_domain',
            'issuer_source_sha256', 'issuer_workflow_commit'}
    require(type(value) is dict and set(value) == keys and type(value['schema_version']) is int and
            value['schema_version'] == 1 and value['purpose'] == 'development-workflow-clock' and
            type(value['allowance_seconds']) is int and value['allowance_seconds'] == 10800 and
            type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}', value['nonce']), 'workflow-clock-refused')
    require(type(CLOCK_ISSUER_SHA256) is str and re.fullmatch('[0-9a-f]{64}', CLOCK_ISSUER_SHA256) and
            value['issuer_source_sha256'] == CLOCK_ISSUER_SHA256, 'clock-issuer-not-registered')
    for field, env, expression in (('source_commit','GITHUB_SHA','[0-9a-f]{40}'),
            ('run_id','GITHUB_RUN_ID','[1-9][0-9]{0,19}'), ('run_attempt','GITHUB_RUN_ATTEMPT','[1-9][0-9]{0,9}'),
            ('issuer_workflow_commit','GITHUB_WORKFLOW_SHA','[0-9a-f]{40}')):
        require(type(value[field]) is str and re.fullmatch(expression, value[field]) and value[field] == os.environ.get(env),
                'workflow-clock-binding-refused')
    require(value['issuer_workflow_commit'] == value['source_commit'], 'workflow-clock-binding-refused')
    domain = value['clock_domain']
    require(type(domain) is dict and set(domain) == {'clock_id','boot_id','time_namespace_device','time_namespace_inode'} and
            type(domain['time_namespace_device']) is int and domain['time_namespace_device'] >= 0 and
            type(domain['time_namespace_inode']) is int and domain['time_namespace_inode'] > 0 and
            domain == clock_domain(), 'clock-domain-refused')
    issued, end = value['issued_monotonic'], value['deadline_monotonic']
    require(all(finite(item) and item > 0 for item in (entry, issued, end)) and
            float(end) == float(issued) + 10800 and issued <= entry <= time.monotonic() < end and
            0 <= time.monotonic() - issued < 10800, 'workflow-clock-time-refused')
    if controller_entry is not None:
        require(type(controller_entry) is float and finite(controller_entry) and
                issued <= controller_entry <= entry, 'controller-entry-refused')
    cutoff = min(end - 120, (entry if controller_entry is None else controller_entry) + 10080);within(cutoff)
    return cutoff, end


def original_argv(output, cache, pins):
    view = output / 'repository-handoff/original-view'
    result = ['integration']
    for flag, name in (('inputs','inputs.lock.json'), ('recipes','recipes.lock.json'), ('integration','integration.lock.json')):
        result.extend(('--' + flag, str(view / 'scripts/ci' / name), '--' + flag + '-sha256', pins['scripts/ci/' + name]))
    result.extend(('--cache',str(cache),'--output',str(output/'native'),'--integration-output',str(output/'integration')))
    return result


def composed_mode(source_packet, composition):
    require(type(composition) is str and composition in packet.COMPOSED_MODES and
            type(source_packet) is dict and type(source_packet.get('schema_version')) is int and
            source_packet['schema_version'] == 2 and type(source_packet.get('composition')) is str and
            source_packet['composition'] == composition, 'composed-packet-contract-refused')
    return composition


def composed_sources(root, source_packet, grant_raw, grant_pin, runtime_raw, output, cache, deadline, *, composition=packet.COMPOSITION):
    """Authenticate exact packet and explicit per-run contracts before allocation."""
    within(deadline)
    composed_mode(source_packet,composition)
    grant = packet.decode(grant_raw);runtime = packet.decode(runtime_raw)
    require(type(grant) is dict and grant.get('source_files') == source_packet['source_files'] and
            grant.get('policy_path') == packet.GENERIC_POLICY and grant.get('license_path') == 'LICENSE' and
            type(runtime) is dict and set(runtime) == {'cli_sha256','endpoint_identity','env'}, 'composed-grant-refused')
    handoff_path = 'scripts/ci/development/repository_handoff.py'
    raw, row = packet.read(root / handoff_path)
    require(row == source_packet['source_files'][handoff_path], 'composed-source-drift')
    name = 'development_repository_handoff'
    require(name not in sys.modules, 'composed-module-collision')
    module = types.ModuleType(name);module.__file__ = str(root / handoff_path)
    sys.modules[name] = module
    try:
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        sources = module.preflight(root,grant_raw,grant_pin,deadline=deadline)
        selected = Development.consume_zsh if composition == packet.ZSH_COMPOSITION else Development.consume
        require(grant['callbacks']['existing_consumers'] == {'path':'scripts/ci/development/controller.py',
                'module':__name__,'qualname':'Development.' + selected.__name__}, 'composed-callback-refused')
        # Authenticate all actual class methods before creating any output.
        sources.callback('existing_consumers',selected.__get__(object.__new__(Development)),deadline)
        argv = original_argv(output,cache,source_packet['metadata_pins'])
        session = module.Session(sources,output/'repository-handoff',job_deadline=deadline,cancelled=cancelled,composition=composition)
        session.view_plan(argv)
        require(module.digest(module.encoded({'argv':argv,'output':str(session.output)})) == grant['initial_invocation_sha256'] and
                module.digest(module.encoded(runtime)) == grant['actor_contract_sha256'], 'composed-grant-refused')
        for env,key in (('GITHUB_SHA','source_commit'),('GITHUB_RUN_ID','run_id'),('GITHUB_RUN_ATTEMPT','run_attempt')):
            require(os.environ.get(env) == grant[key], 'composed-grant-refused')
        authority_name = 'development_repository_authority'
        require(authority_name not in sys.modules and all(grant['callbacks'][role] ==
                {'path':'scripts/ci/development/repository_authority.py','module':authority_name,
                 'qualname':'RootCallbacks.' + role} for role in ('public_receiver','authority_provider')),
                'composed-callback-refused')
        authority = sources.module(authority_name,'scripts/ci/development/repository_authority.py')
        sys.modules[authority_name] = authority
        try:
            callbacks = authority.RootCallbacks(root,grant_raw,grant_pin,runtime_raw,session.output,
                                               deadline=deadline,session=session)
            sources.callback('public_receiver',callbacks.public_receiver,deadline)
            sources.callback('authority_provider',callbacks.authority_provider,deadline)
            sources.guard(deadline)
        except BaseException:
            sys.modules.pop(authority_name,None);raise
        return session, callbacks, runtime, argv
    except BaseException:
        sys.modules.pop(name,None);raise


def broad_source_guard(session, modules, deadline):
    """Validate explicit parent dependencies; an ambient module label is insufficient."""
    sources = session.sources;sources.guard(deadline)
    cache = {}
    for path,module in modules.items():
        require(type(module) is types.ModuleType and module.__file__ == str(sources.root/path) and
                sys.modules.get(module.__name__) is module,'broad-source-module-refused')
        sources.graph_namespace(module,path,modules,{},cache)
        literals = {}
        def literal(node):
            if isinstance(node,ast.Name) and node.id in literals:return literals[node.id]
            if isinstance(node,ast.Dict):return {literal(key):literal(value) for key,value in zip(node.keys,node.values)}
            if isinstance(node,(ast.List,ast.Tuple,ast.Set)):
                values = [literal(item) for item in node.elts]
                return values if isinstance(node,ast.List) else tuple(values) if isinstance(node,ast.Tuple) else set(values)
            if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Add,ast.Sub,ast.Mult,ast.Pow,ast.BitOr)):
                left,right = literal(node.left),literal(node.right)
                if isinstance(node.op,ast.Add):return left+right
                if isinstance(node.op,ast.Sub):return left-right
                if isinstance(node.op,ast.Mult):return left*right
                if isinstance(node.op,ast.BitOr):return left|right
                require(type(right) is int and 0 <= right <= 32,'broad-source-literal-refused');return left**right
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='re' and node.func.attr=='compile':
                require(len(node.args)==1 and not node.keywords,'broad-source-literal-refused');return re.compile(literal(node.args[0]))
            return ast.literal_eval(node)
        for node in ast.parse(sources.raw[path]).body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                try:expected = literal(node.value)
                except (ValueError,TypeError,KeyError):continue  # Runtime objects are code/identity-bound below.
                key = node.targets[0].id;literals[key] = expected
                require(type(module.__dict__.get(key)) is type(expected) and module.__dict__[key] == expected,
                        'broad-source-literal-refused')
    return sources.graph_identity(tuple(modules.values()))


def interrupt(*_):
    global CANCELLED
    CANCELLED = True
    raise KeyboardInterrupt()


def load_native(root):
    sys.path.insert(0, str(root / 'scripts/ci'))
    spec = importlib.util.spec_from_file_location('development_native_arm', root / 'scripts/ci/native_arm.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cancelled(controller=None):
    integration = sys.modules.get('integration')
    return CANCELLED or bool(controller and controller.cancelled) or bool(integration and integration.CANCEL_REQUESTED)


def run_client(controller, root, output, cache, *, deadline=None):
    from common import base_prerequisite
    report = {'status': 'NOT RUN', 'prerequisite': {}, 'public': []}
    options = {} if deadline is None else {'deadline':deadline}
    if deadline is not None:within(deadline)
    output.mkdir(mode=0o700)
    public = output / 'adapter-status'; public.mkdir()
    try:
        prerequisite = base_prerequisite(controller, **options)
        report['prerequisite'] = prerequisite
        report['status'] = 'FAIL'
        stage = root / 'scripts/client/stage.py'
        args = [sys.executable, '-B', str(stage), 'run', '--image', prerequisite['image_id'],
                '--bootstrap', str(controller.native_out / 'bootstrap.json'),
                '--bootstrap-sha256', digest(controller.native_out / 'bootstrap.json', **options),
                '--packages', prerequisite['packages_lock'], '--packages-sha256', prerequisite['packages_sha256'],
                '--source', str(root), '--stage-sha256', digest(stage, **options), '--guard-sha256', digest(root / 'scripts/ci/source_suites.py', **options),
                '--output', str(output / 'owner-public')]
        code = command(args, output / 'private-driver.log', 420, **({'deadline':deadline} if deadline is not None else {}))
        owner = read_json(output / 'owner-public/receipt.json', **options)
        require(code == 0 and owner.get('status') == 'PASS' and owner.get('native_client_tests') == 'PASS' and
                owner.get('container_cleanup') == owner.get('controller_tmp_removed') == 'PASS' and
                owner.get('image_id') == controller.image and owner.get('packages_sha256') == prerequisite['packages_sha256'],
                'native-client-acceptance-failed')
        report['status'] = 'PASS'
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['error_code'] = 'client-prerequisite-refused' if report['status'] == 'NOT RUN' else 'client-stage-failed'
        report['error_type'] = type(error).__name__
    finally:
        if cancelled(controller):
            report['status'] = 'FAIL'; report['error_code'] = 'cancelled'
        if (output / 'owner-public/receipt.json').is_file():
            report['public'].append(str((output / 'owner-public').absolute()))
        report['public'].append(str(public.absolute()))
        save(public / 'result.json', {key: value for key, value in report.items() if key != 'public'}, **options)
    return report


class Development:
    def __init__(self, root, output, cache, source_packet, *, deadline=None, composition=packet.COMPOSITION,
                 clock_nonce=None, runtime_contract=None):
        self.root, self.output, self.cache, self.packet = root, output, cache, source_packet
        self.deadline = deadline
        self.repository_capture = None
        self.publication_deadline = None
        self.repository_session = None
        self.composition, self.clock_nonce, self.runtime_contract = composition, clock_nonce, runtime_contract
        self.native_preflight_module = None
        self.report = {'schema_version': 1, 'purpose': 'same-job-native-development', 'status': 'FAIL',
                       'development_only': True, 'selected_for_release': False, 'hardware_validation': 'NOT RUN',
                       'performance_acceptance': 'NOT RUN', 'production_trust': 'NOT RUN',
                       'source_commit': os.environ.get('GITHUB_SHA'), 'initial_integration': 'NOT RUN',
                       'publication': 'NOT RUN', 'stages': {name: {'status': 'NOT RUN', 'prerequisite': 'initial-build-not-completed'}
                                                     for name in STAGES}}
        self.public = []
        self.callback_entered = False
        if composition == packet.ZSH_COMPOSITION:
            self.report['stages']['zsh-addon'] = {'status':'NOT RUN','prerequisite':'initial-build-not-completed'}
        (output / 'development-summary').mkdir()
        self.persist()

    def persist(self):
        try:
            save(self.output / 'result.json', self.report)
            save(self.output / 'development-summary/result.json', self.report)
        except BaseException:
            self.report.update(status='FAIL', error_code='durable-status-persistence-failed')
            print(json.dumps({'purpose': 'same-job-native-development', 'status': 'FAIL',
                              'error_code': 'durable-status-persistence-failed'}, sort_keys=True))
            raise

    def persist_installer(self):
        """Retain the first exception while still recording failed terminal persistence."""
        first, code = sys.exception(), self.report.get('error_code')
        try:self.persist()
        except BaseException as error:
            self.report.update(status='FAIL',status_persistence='FAIL')
            if code is not None:self.report['error_code'] = code
            else:self.report.setdefault('error_code','durable-status-persistence-failed')
            if isinstance(error,KeyboardInterrupt):self.report['cancelled'] = True
            stage = self.report['stages'].get('native-install-preflight')
            if stage is not None:stage.update(status='FAIL',status_persistence='FAIL')
            if first is None:raise

    def persist_zsh(self):
        """New-mode terminal writes preserve the established cause and report code."""
        first, code = sys.exception(), self.report.get('error_code')
        try:self.persist()
        except BaseException as error:
            self.report.update(status='FAIL',status_persistence='FAIL')
            if code is not None:self.report['error_code'] = code
            else:self.report.setdefault('error_code','durable-status-persistence-failed')
            if isinstance(error,KeyboardInterrupt):self.report['cancelled'] = True
            stage = self.report['stages'].get('zsh-addon')
            if stage is not None:stage.update(status='FAIL',status_persistence='FAIL')
            if first is None:raise

    def consume(self, controller):
        if self.deadline is None:signal.setitimer(signal.ITIMER_REAL, 0)
        else:
            within(self.deadline)
            signal.setitimer(signal.ITIMER_REAL, self.deadline - time.monotonic())
        require(type(self.composition) is str and self.composition in packet.COMPOSED_MODES, 'composed-packet-contract-refused')
        if self.deadline is not None and self.packet.get('schema_version') == 2:
            composed_mode(self.packet,self.composition)
        if self.composition == packet.INSTALLER_COMPOSITION:
            return self.consume_installer(controller)
        from base_stages import run_arm, run_ksm
        from virtual_stage import run_virtual
        bound_modules = None
        if self.deadline is not None:
            require(self.repository_session is not None,'composed-session-refused')
            self.repository_session.original_context(deadline=self.deadline,controller=controller)
            bound_modules = {'scripts/ci/development/'+name+'.py':sys.modules[name]
                             for name in ('common','packet','base_stages','virtual_stage')}
            bound_modules['scripts/ci/development/controller.py'] = sys.modules[__name__]
            observation = broad_source_guard(self.repository_session,bound_modules,self.deadline)
        self.callback_entered = True
        virtual_names = VIRTUAL_NAMES
        source_map = self.packet.get('source_files', {})
        if all('scripts/virtual/' + name in source_map for name in virtual_names):
            controller.virtual_packet_sha256 = {name: source_map['scripts/virtual/' + name]['sha256'] for name in virtual_names}
        # The initial image is still owned by Controller. It removes it only
        # after this callback returns, including after failed consumers.
        for name, action in (('ksm', run_ksm), ('arm-c01-base', run_arm), ('client', run_client), ('virtual', run_virtual)):
            if cancelled(controller):
                raise KeyboardInterrupt()
            output = self.output / name
            try:
                if self.deadline is not None:within(self.deadline)
                if bound_modules is not None:
                    require(broad_source_guard(self.repository_session,bound_modules,self.deadline) == observation,
                            'broad-source-identity-drift')
                kwargs = {'deadline':self.deadline} if self.deadline is not None else {}
                value = action(controller, self.root, output, **kwargs) if name == 'ksm' else action(controller, self.root, output, self.cache, **kwargs)
                if self.deadline is not None:within(self.deadline)
                if bound_modules is not None:
                    require(broad_source_guard(self.repository_session,bound_modules,self.deadline) == observation,
                            'broad-source-identity-drift')
                    self.repository_session.original_context(deadline=self.deadline,controller=controller)
                require(value.get('status') in ('PASS', 'FAIL', 'NOT RUN', 'CAPTURED_REQUIRES_VISUAL_REVIEW'), 'invalid-stage-status')
                require(name == 'virtual' or value['status'] != 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'invalid-review-stage')
                if name == 'virtual' and value['status'] == 'PASS' and value.get('owner_status') == 'CAPTURED_REQUIRES_VISUAL_REVIEW':
                    value = dict(value, status='CAPTURED_REQUIRES_VISUAL_REVIEW', execution_status='PASS')
                for directory in value.get('public', []):
                    path = Path(directory).absolute()
                    require('..' not in path.parts and output.absolute() in path.parents and
                            path.relative_to(output.absolute()).as_posix() in PUBLIC_SELECTORS[name], 'stage-public-path-refused')
                    self.public.append(path)
                self.report['stages'][name] = {key: item for key, item in value.items() if key != 'public'}
            except KeyboardInterrupt:
                self.report['stages'][name] = {'status': 'FAIL', 'error_code': 'cancelled'}
                self.recover_public(name, output)
                raise
            except Exception as error:
                self.report['stages'][name] = {'status': 'FAIL', 'error_code': 'adapter-failed', 'error_type': type(error).__name__}
                self.recover_public(name, output)
            finally:
                self.persist()
        # Do not turn the original four-package summary into a new predicate.
        # Development failures stay authoritative in our separate aggregate.

    def zsh_module(self, controller):
        """Select only the captured pair from the same actual suspended Session."""
        composed_mode(self.packet,self.composition);within(self.deadline)
        require(self.composition == packet.ZSH_COMPOSITION,'zsh-composition-refused')
        session = self.repository_session; owner = sys.modules.get('development_repository_handoff')
        require(type(owner) is types.ModuleType and type(session) is owner.Session and
                type(session.sources) is owner.Sources and session.composition == self.composition and
                session.job_deadline == self.deadline and session.controller is controller,
                'zsh-session-refused')
        session.sources.class_state(session,'scripts/ci/development/repository_handoff.py',owner)
        session.sources.guard(self.deadline)
        session.original_context(deadline=self.deadline,controller=controller)
        graph = session.source_graph.get('zsh')
        require(type(graph) is dict and set(graph) == set(ZSH_NAMES),'zsh-graph-refused')
        for role, name in ZSH_NAMES.items():
            module = graph[role]; path = 'scripts/ci/development/' + role + '.py'
            require(type(module) is types.ModuleType and module.__name__ == name and
                    module.__file__ == str(self.root/path) and sys.modules.get(name) is module and
                    path in session.sources.raw,'zsh-graph-refused')
        module = graph['zsh_session'];callback = module.__dict__.get('run_zsh')
        require(type(callback) is types.FunctionType and callback.__module__ == ZSH_NAMES['zsh_session'] and
                callback.__qualname__ == 'run_zsh' and callback.__globals__ is module.__dict__, 'zsh-callback-refused')
        require(type(self.runtime_contract) is dict and set(self.runtime_contract) == {'cli_sha256','endpoint_identity','env'} and
                hashlib.sha256((json.dumps(self.runtime_contract,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()).hexdigest() ==
                session.sources.grant['actor_contract_sha256'],'zsh-runtime-refused')
        return module

    def consume_zsh(self, controller):
        """Zsh precedes the existing consumers under the retained original job clock."""
        output = self.output/'zsh-addon'
        completed = False
        try:
            if cancelled(controller):raise KeyboardInterrupt()
            module = self.zsh_module(controller);self.callback_entered = True
            runtime_raw = (json.dumps(self.runtime_contract,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
            value = module.run_zsh(controller,self.root,output,self.cache,
                session=self.repository_session,actor_contract_raw=runtime_raw)
            within(self.deadline)
            require(self.zsh_module(controller) is module,'zsh-graph-refused')
            require(type(value) is dict and value.get('stage') == 'zsh-addon' and value.get('status') == 'PASS' and
                    value.get('provisional') is True and value.get('hardware_status') == value.get('installation') == 'NOT RUN' and
                    value.get('selected_for_release') is False and type(value.get('cleanup')) is dict and
                    value['cleanup'].get('status') == 'PASS' and type(value.get('public')) is list and
                    len(value['public']) == 2,'zsh-result-refused')
            selected = [Path(name).absolute() for name in value['public']]
            require(set(selected) == {output/'adapter-status',output/'public'} and len(set(selected)) == 2,
                    'zsh-public-path-refused')
            self.report['stages']['zsh-addon'] = {key:item for key,item in value.items() if key != 'public'}
            self.public.extend(selected)
            completed = True
            self.consume(controller)
        except BaseException as error:
            if not completed:
                self.report['stages']['zsh-addon'] = {'status':'FAIL','error_code':'cancelled' if isinstance(error,KeyboardInterrupt)
                    else 'zsh-stage-failed','error_type':type(error).__name__}
            self.report['status'] = 'FAIL'
            if isinstance(error,KeyboardInterrupt):self.report['cancelled'] = True
            self.report.setdefault('error_code','composed-consumer-failed' if completed else 'zsh-stage-failed')
            raise
        finally:
            first, code = sys.exception(), self.report.get('error_code')
            try:self.persist()
            except BaseException:
                self.report.update(status='FAIL',status_persistence='FAIL')
                if code is not None:self.report['error_code'] = code
                if first is None:raise

    def installer_module(self, controller):
        """Use the same captured SDK classes/graph; the bridge checks actual active frames."""
        composed_mode(self.packet,self.composition);within(self.deadline)
        session = self.repository_session; owner = sys.modules.get('development_repository_handoff')
        require(type(owner) is types.ModuleType and type(session) is owner.Session and
                type(session.sources) is owner.Sources and type(session.composition) is str and
                session.composition == self.composition and session.job_deadline == self.deadline and
                session.controller is controller and type(session.native_consumer_observation) is tuple and
                len(session.native_consumer_observation) == 3 and session.native_consumer_observation[2] is controller and
                session.result['initial_exit_code'] is None, 'installer-owner-refused')
        sources = session.sources
        sources.class_state(session,'scripts/ci/development/repository_handoff.py',owner)
        sources.class_state(sources,'scripts/ci/development/repository_handoff.py',owner)
        sources.guard(self.deadline)
        session.original_context(deadline=self.deadline,controller=controller)
        graph = sources.source_graph(session)
        require(type(graph) is dict and all(type(name) is str for name in graph) and INSTALLER_PATH in graph and
                type(session.source_graph) is dict and session.source_graph.get('native_preflight') is graph[INSTALLER_PATH],
                'installer-graph-refused')
        module = graph[INSTALLER_PATH]
        require(type(module) is types.ModuleType and type(module.__name__) is str and module.__name__ == INSTALLER_NAME and
                type(module.__dict__.get('OWN')) is str and module.OWN == INSTALLER_PATH and
                type(module.__file__) is str and module.__file__ == str(self.root/INSTALLER_PATH) and
                sys.modules.get(INSTALLER_NAME) is module, 'installer-graph-refused')
        callback = module.__dict__.get('run')
        require(type(callback) is types.FunctionType and type(callback.__module__) is str and
                callback.__module__ == INSTALLER_NAME and type(callback.__qualname__) is str and
                callback.__qualname__ == 'run' and callback.__globals__ is module.__dict__, 'installer-callback-refused')
        require(INSTALLER_PATH in sources.raw and INSTALLER_PATH in sources.grant['source_files'] and
                type(module.__dict__.get('ISSUER_SHA')) is str and module.ISSUER_SHA ==
                hashlib.sha256(sources.raw['scripts/ci/development/repository_handoff.py']).hexdigest(), 'installer-issuer-refused')
        sources.graph_namespace(module,INSTALLER_PATH,graph,{}, {})
        module.namespace(module,sources.raw[INSTALLER_PATH],sources.grant['source_files'][INSTALLER_PATH]['sha256'])
        require(type(self.clock_nonce) is str and re.fullmatch('[0-9a-f]{32}',self.clock_nonce) and
                type(self.runtime_contract) is dict and set(self.runtime_contract) == {'cli_sha256','endpoint_identity','env'} and
                hashlib.sha256((json.dumps(self.runtime_contract,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()).hexdigest() ==
                sources.grant['actor_contract_sha256'], 'installer-runtime-refused')
        within(self.deadline)
        if self.native_preflight_module is not None:
            require(self.native_preflight_module is module,'installer-graph-refused')
        self.native_preflight_module = module
        return module

    def persist_p0(self):
        """Retain first failure and propagate only exact terminal persistence facts."""
        first = sys.exception()
        try:self.persist_installer()
        except BaseException as error:
            target = first if first is not None else error
            if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(target,'native_preflight_cancelled',True)
            BaseException.__setattr__(target,'native_preflight_cleanup_uncertain',True)
            if first is None:raise
        finally:
            if first is not None:
                if self.report.get('cancelled') is True:BaseException.__setattr__(first,'native_preflight_cancelled',True)
                if self.report.get('status_persistence') == 'FAIL':BaseException.__setattr__(first,'native_preflight_cleanup_uncertain',True)

    def consume_p0(self, controller):
        """Registered P0 entry while the actual original main/run frames live."""
        session = self.repository_session
        owner = sys.modules.get('development_repository_handoff')
        require(type(owner) is types.ModuleType and type(session) is owner.Session,'installer-owner-refused')
        context = owner.Session.p0_context(session);end = context['end']
        bridge = self.installer_module(controller)
        module = session.p0_entry_module;path = 'scripts/install/p0_entry.py'
        require(type(module) is types.ModuleType and module.__name__ == 'native_install_p0_entry' and
                module.__file__ == str(self.root/path) and sys.modules.get(module.__name__) is module,
                'installer-graph-refused')
        session.sources.graph_namespace(module,path,{path:module},{},{})
        bridge.namespace(module,session.sources.raw[path],session.sources.grant['source_files'][path]['sha256'])
        try:
            if cancelled(controller):raise KeyboardInterrupt()
            self.callback_entered = True
            value = module.run(session,controller,self.output/'native-install-preflight',token=session,
                stage='installer-P0',entry=context['entry'],deadline=end,nonce=self.clock_nonce,
                runtime_contract=self.runtime_contract,preflight_raw=session.sources.raw[INSTALLER_PATH])
            within(end);owner.Session.p0_context(session)
            require(type(value) is dict and set(value) == {'schema_version','status','stage','receiver','cleanup','ABI','matrix','hardware_validation','input_successor'} and
                    value['schema_version'] == 1 and type(value['schema_version']) is int and
                    value['status'] == 'PASS_P0_ONLY' and value['stage'] == 'installer-P0' and
                    value['ABI'] == value['matrix'] == value['hardware_validation'] == 'NOT_RUN' and
                    owner.validate_input_successor(value['input_successor']) == context['input_successor'],'installer-result-refused')
            self.report['stages']['native-install-preflight'] = dict(value)
            return value
        except BaseException as error:
            interrupted = isinstance(error,KeyboardInterrupt) or cancelled(controller);uncertain = False
            try:
                markers = BaseException.__getattribute__(error,'__dict__')
                if type(markers) is dict:
                    interrupted |= markers.get('native_preflight_cancelled') is True
                    uncertain = markers.get('native_preflight_cleanup_uncertain') is True
            except BaseException as metadata_error:
                interrupted |= isinstance(metadata_error,KeyboardInterrupt);uncertain = True
            self.report['stages']['native-install-preflight'] = {'status':'FAIL','error_code':'cancelled' if interrupted else
                'installer-preflight-failed','scope':'preflight-only','cleanup_uncertain':uncertain}
            self.report['status'] = 'FAIL'
            if interrupted:self.report['cancelled'] = True
            self.report.setdefault('error_code','installer-preflight-cancelled' if interrupted else 'installer-preflight-failed')
            raise
        finally:self.persist_p0()

    def run_p0(self, session, runtime_contract, argv, *, entry, image, inputs_raw, packages_raw):
        """Root's explicit independent callable; old run_composed is unchanged."""
        composed_mode(self.packet,self.composition)
        module = sys.modules.get('development_repository_handoff')
        require(type(module) is types.ModuleType and type(session) is module.Session and
                type(session.sources) is module.Sources,'composed-session-refused')
        require(self.composition == packet.INSTALLER_COMPOSITION and
                session.composition == self.composition and session.job_deadline == self.deadline and
                session.sources.root == self.root and session.sources.grant['source_files'] == self.packet['source_files'] and
                runtime_contract == self.runtime_contract,'composed-session-refused')
        session.sources.class_state(session,'scripts/ci/development/repository_handoff.py',module)
        session.sources.class_state(session.sources,'scripts/ci/development/repository_handoff.py',module)
        session.sources.guard(self.deadline)
        self.repository_session = session
        return session.execute_p0(argv,self.consume_p0,runtime_contract,entry=entry,image=image,inputs_raw=inputs_raw,packages_raw=packages_raw)

    def consume_installer(self, controller):
        """P0 is a limited result; unrelated broad roles remain NOT RUN."""
        self.report['execution_scope'] = 'native-install-preflight-only'
        self.report['stages']['native-install-preflight'] = {'status':'NOT RUN','scope':'preflight-only'}
        try:
            if cancelled(controller):raise KeyboardInterrupt()
            module = self.installer_module(controller)
            self.callback_entered = True
            value = module.run(self.repository_session,controller,self.output/'native-install-preflight',
                deadline=self.deadline,nonce=self.clock_nonce,runtime_contract=self.runtime_contract)
            within(self.deadline)
            require(self.installer_module(controller) is module,'installer-graph-refused')
            require(type(value) is dict and set(value) == {'status','stage','receiver','cleanup','elapsed_seconds',
                    'ABI','native_matrix','hardware_validation','selected_for_release','public'} and value['status'] == 'PASS' and
                    value['stage'] == 'native-install-preflight' and value['ABI'] == value['native_matrix'] ==
                    value['hardware_validation'] == 'NOT RUN' and value['selected_for_release'] is False and
                    type(value['public']) is list and not value['public'] and finite(value['elapsed_seconds']) and
                    value['elapsed_seconds'] >= 0 and type(value['cleanup']) is dict and
                    value['cleanup'] == {'remove_exit':0,'absent':True} and type(value['cleanup']['remove_exit']) is int and
                    type(value['cleanup']['absent']) is bool and type(value['receiver']) is dict and
                    value['receiver'].get('status') == 'PASS_NATIVE_PREFLIGHT_ONLY' and value['receiver'].get('phase') == 'complete' and
                    value['receiver'].get('ABI') == value['receiver'].get('matrix') == 'NOT_RUN', 'installer-result-refused')
            self.report['stages']['native-install-preflight'] = {
                **{key:item for key,item in value.items() if key != 'public'},'scope':'preflight-only'}
        except BaseException as error:
            interrupted = isinstance(error,KeyboardInterrupt) or cancelled(controller)
            uncertain = False
            try:
                markers = BaseException.__getattribute__(error,'__dict__')
                if type(markers) is dict:
                    interrupted |= markers.get('native_preflight_cancelled') is True
                    uncertain = markers.get('native_preflight_cleanup_uncertain') is True
            except BaseException as metadata_error:
                interrupted |= isinstance(metadata_error,KeyboardInterrupt)
                uncertain = True
            self.report['stages']['native-install-preflight'] = {'status':'FAIL','error_code':'cancelled' if interrupted else
                'installer-preflight-failed','error_type':type(error).__name__,'scope':'preflight-only'}
            if uncertain:self.report['stages']['native-install-preflight']['cleanup_uncertain'] = True
            self.report['status'] = 'FAIL'
            if interrupted:self.report['cancelled'] = True
            self.report.setdefault('error_code','installer-preflight-cancelled' if interrupted else 'installer-preflight-failed')
            raise
        finally:self.persist_installer()

    def recover_public(self, name, output):
        """Use adapter selectors, never a raw workspace walk after cancellation."""
        try:
            if self.deadline is not None:within(self.deadline)
            if name == 'virtual':
                from virtual_stage import public_paths
                paths = public_paths(output)
            elif name in ('ksm', 'arm-c01-base'):
                from base_stages import recovery_public
                kwargs = {'deadline':self.deadline} if self.deadline is not None else {}
                paths = recovery_public(name, output, **kwargs)
            else:
                paths = []
                for directory in ('adapter-status', 'owner-public'):
                    if self.deadline is not None:within(self.deadline)
                    path = output / directory
                    selected = path.is_dir()
                    if self.deadline is not None:within(self.deadline)
                    if selected:paths.append(path)
            if self.deadline is not None:within(self.deadline)
            for value in paths:
                if self.deadline is not None:within(self.deadline)
                path = Path(value).absolute()
                require('..' not in path.parts and output.absolute() in path.parents and
                        path.relative_to(output.absolute()).as_posix() in PUBLIC_SELECTORS[name], 'stage-public-path-refused')
                if self.deadline is not None:within(self.deadline)
                if path not in self.public:
                    self.public.append(path)
                if self.deadline is not None:within(self.deadline)
            if self.deadline is not None:within(self.deadline)
        except KeyboardInterrupt:
            self.report['stages'][name]['failure_retention'] = 'FAIL'
            raise
        except Exception:
            self.report['stages'][name]['failure_retention'] = 'FAIL'

    def run(self, native, argv):
        try:
            code = native.main(argv, integration_consumers=self.consume)
            self.report['initial_exit_code'] = code
        except KeyboardInterrupt:
            self.report['cancelled'] = True
        except Exception as error:
            self.report.update(error_code='initial-execution-failed', error_type=type(error).__name__)
        finally:
            try:
                initial = read_json(self.output / 'integration/result.json')
                self.report['initial_integration'] = 'PASS' if self.report.get('initial_exit_code') == 0 and initial.get('status') == 'PASS' else 'FAIL'
                self.report['initial_cleanup'] = initial.get('owned_image_cleanup', {'status': 'NOT RUN'})
            except (OSError, ValueError):
                self.report['initial_integration'] = 'FAIL'
            self.report['callback_entered'] = self.callback_entered
            self.report['cancelled'] = self.report.get('cancelled', False) or cancelled()
            self.persist()
        return self.report

    def run_composed(self, session, callbacks, runtime_contract, argv):
        """The held Session alone owns the actual original view and sole producer."""
        composed_mode(self.packet,self.composition)
        require(type(session.composition) is str and session.composition == self.composition and
                self.deadline is not None and session.job_deadline == self.deadline and
                session.output == self.output/'repository-handoff', 'composed-session-refused')
        try:
            within(self.deadline)
            module = sys.modules.get('development_repository_handoff')
            require(type(module) is types.ModuleType and type(session) is module.Session and
                    type(session.sources) is module.Sources and session.sources.root == self.root and
                    session.sources.grant['source_files'] == self.packet['source_files'], 'composed-session-refused')
            session.sources.class_state(session,'scripts/ci/development/repository_handoff.py',module)
            session.sources.class_state(session.sources,'scripts/ci/development/repository_handoff.py',module)
            session.sources.guard(self.deadline)
            self.repository_session = session
            if self.composition == packet.INSTALLER_COMPOSITION:
                require(type(runtime_contract) is dict and runtime_contract == self.runtime_contract, 'installer-runtime-refused')
            selected = self.consume_zsh if self.composition == packet.ZSH_COMPOSITION else self.consume
            value = session.execute(argv, {'existing_consumers':selected,
                    'public_receiver':callbacks.public_receiver,'authority_provider':callbacks.authority_provider}, runtime_contract)
            session.sources.class_state(session,'scripts/ci/development/repository_handoff.py',module)
            session.sources.guard(self.deadline)
            require(type(value) is dict and set(value) == set(session.result) | {'public','phase_public'} and
                    {key:item for key,item in value.items() if key not in ('public','phase_public')} == session.result,
                    'composed-result-refused')
            status = module.status_projection(session.result)
            self.report['repository_handoff'] = status
            phase = value['phase_public']
            if status['status'] == 'PASS':
                require(type(phase) is dict and set(phase) == {'descriptor_bytes','sha256'} and
                        type(phase['descriptor_bytes']) is bytes and phase['descriptor_bytes'] == session.phase_export_raw and
                        phase['sha256'] == session.phase_export_sha256 == hashlib.sha256(phase['descriptor_bytes']).hexdigest(),
                        'composed-phase-descriptor-refused')
                self.repository_capture = (session,module.encoded(status),phase['descriptor_bytes'],phase['sha256'])
            else:require(phase is None, 'composed-phase-descriptor-refused')
            self.report['initial_exit_code'] = value['initial_exit_code']
            self.report['cancelled'] = value['cancelled']
            for name in value['public']:
                path = Path(name).absolute()
                require(path.parent == session.output and path.name in ('status','phase-public'), 'stage-public-path-refused')
                if path.name == 'phase-public':
                    require(self.repository_capture is not None,'composed-phase-descriptor-refused')
                else:self.public.append(path)
        except KeyboardInterrupt:
            self.report.update(cancelled=True,error_code=self.report.get('error_code','composed-execution-cancelled'))
        except Exception as error:
            if 'error_code' not in self.report:
                self.report.update(error_code='composed-execution-failed',error_type=type(error).__name__)
        finally:
            try:
                initial = read_json(self.output/'integration/result.json')
                self.report['initial_integration'] = 'PASS' if type(self.report.get('initial_exit_code')) is int and self.report['initial_exit_code'] == 0 and initial.get('status') == 'PASS' else 'FAIL'
                self.report['initial_cleanup'] = initial.get('owned_image_cleanup',{'status':'NOT RUN'})
            except (OSError,ValueError):self.report['initial_integration'] = 'FAIL'
            self.report['repository_handoff'] = self.report.get('repository_handoff',{'status':'FAIL','cleanup':'UNVERIFIED'})
            self.report['repository_publication'] = self.report.get('repository_publication','NOT RUN')
            self.report['callback_entered'] = self.callback_entered
            self.report['cancelled'] = self.report.get('cancelled',False) or cancelled()
            if self.composition == packet.INSTALLER_COMPOSITION:self.persist_installer()
            elif self.composition == packet.ZSH_COMPOSITION:self.persist_zsh()
            else:self.persist()
        return self.report


def public_policy():
    global POLICY
    if POLICY is None:
        path = ROOT / 'scripts/ci/integration_export.py'
        require(digest(path) == '1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c', 'public-policy-source-drift')
        spec = importlib.util.spec_from_file_location('development_public_policy', path)
        POLICY = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(POLICY)
    return POLICY


def public_tree(root, opaque_approved=None):
    require('..' not in root.parts and root.is_dir() and not root.is_symlink() and
            all(stat.S_ISDIR(path.lstat().st_mode) for path in root.parents), 'public-directory-required')
    count, size = 0, 0
    policy = public_policy()
    opaque_approved = opaque_approved or {}
    for path in root.rglob('*'):
        info = path.lstat()
        require(not path.is_symlink(), 'public-symlink-refused')
        require(not any(policy.SENSITIVE_PATH.search(part) for part in path.relative_to(root).parts), 'public-sensitive-path-refused')
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'public-regular-file-required')
        count += 1; size += info.st_size
        require(count <= 4096 and size <= 16 * 1024**2, 'public-bundle-bound-exceeded')
        relative = path.relative_to(root).as_posix()
        source = False
        if root.name == 'public-material' and relative.startswith('source/'):
            name = relative.removeprefix('source/')
            source = name in packet.KSM_FILES
            require(source and digest(path) == read_json(ROOT / 'manifests/reviewed/ksmctl.json').get(name), 'public-gpl-source-binding-refused')
        binary = (root.name == 'public-material' and re.fullmatch(r'attempt-[12]/cachy-asahi-ksmctl-0\.1\.0-1-any\.pkg\.tar\.(xz|zst|gz)', relative)) or (
            root.name == 'public-artifacts' and relative == 'development-ARM-C01-outputs.tar.gz') or (
            root.name in ('minimal-frame', 'overlay-frame') and relative == root.name.removesuffix('-frame') + '.ppm')
        if relative in opaque_approved:
            row = opaque_approved[relative]
            require(row['bytes'] == info.st_size and row['sha256'] == digest(path), 'public-material-binding-refused')
            binary = True
        require(source or binary or path.suffix in policy.SUFFIXES, 'public-file-selector-refused')
        if source or path.suffix in policy.SUFFIXES or (relative in opaque_approved and path.suffix == '.conf'):
            text = read_regular(path, policy.FILE_LIMIT).decode('utf-8')
            require(not policy.PRIVATE_CONTENT.search(text) and
                    all(ord(char) >= 32 or char in '\n\r\t' for char in text), 'public-text-policy-refused')
        else:
            require(not re.search(rb'-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:[A-Z0-9 ]* )?PRIVATE KEY)-----',
                                  read_regular(path, 8 * 1024**2)), 'public-private-armor-refused')
    require(count > 0, 'empty-public-bundle')


PHASE_RESULT_KEYS = frozenset(('schema_version purpose status development_only selected_for_release '
    'original_B_continuity stable_promotion production_trust published_endpoint hardware_validation installation '
    'native_build repository_authority_sha256 software_environment blockers cleanup phase_receipt_sha256 '
    'phase_request_sha256 original_crypto_verification current_A_authorization repository_input_acceptance '
    'commands tool_sha256 signer namespace lineage release_sha256 release_semantics client_cases '
    'new_signature_and_database_sha256 source_sha256 metadata_sha256 public_files').split())
PHASE_LINEAGE_KEYS = frozenset(('schema_version purpose development_only original_B_continuity '
    'repository_authority_sha256 metadata_sha256 repository_source_commit archive_role input_lineage '
    'original_signer_roles original_crypto_verification phase_receipt_sha256 phase_request_sha256 '
    'current_A_authorization archives').split())
TEST_GENERATE = ['--batch','--no-options','--pinentry-mode','loopback','--passphrase','',
    '--quick-generate-key','TEST ONLY separate repository-client restage <restage@test.invalid>','ed25519','sign','1d']


def phase_filename(name, originals):
    if name in ('result.json','public-key.gpg','bundle/base.json','bundle/spec.json','bundle/release.json',
                'bundle/release.json.sig','bundle/project-license.txt','bundle/evidence/lineage.json'):return True
    if re.fullmatch(r'logs/[0-9]{3}\.(?:stdout|stderr)|envelope-(?:1|2|altered)\.json(?:\.sig)?',name):return True
    if name in {'bundle/provenance/'+package+'.json' for package in originals}:return True
    if re.fullmatch(r'bundle/repo/test-restage\.(?:db|files)(?:\.tar\.gz)?(?:\.sig)?',name):return True
    return any(re.fullmatch(re.escape('bundle/repo/'+package)+r'-[A-Za-z0-9.+_:-]+-any\.pkg\.tar\.(?:xz|zst|gz)(?:\.sig)?',name)
               for package in originals)


def phase_json_privacy(value, *, semantic=None, generation=(), deadline=None):
    """Closed semantic exceptions never change the generic credential regex."""
    policy = public_policy();count = 0
    semantic = {} if semantic is None else semantic
    require(type(semantic) is dict,'phase-json-privacy-refused')
    credentials = re.compile(r'(?:^|[_-])(?:authorization|password|passwd|passphrase|secret|private[_-]?key|token|api[_-]?key|access_token|refresh_token|client_secret)(?:$|[_-])',re.I)
    def visit(item,path=(),depth=0):
        nonlocal count
        count += 1;require(count <= 2000000 and depth <= 32,'phase-json-bound-refused')
        if deadline is not None and count % 256 == 1:within(deadline)
        if type(item) is dict:
            for key,child in item.items():
                require(type(key) is str and len(key) <= 512,'phase-json-type-refused')
                slot = path+(key,)
                if key in ('current_A_authorization','snapshot_authorization','terminal_authorization'):
                    require(slot in semantic and child == semantic[slot] and type(child) is str and
                            child in ('REVOKED','SNAPSHOT_ONLY','VALID_AT_OBSERVATION'),'phase-json-privacy-refused')
                else:require(not credentials.search(key) and not policy.PRIVATE_CONTENT.search(key),'phase-json-privacy-refused')
                visit(child,slot,depth+1)
        elif type(item) is list:
            for index,child in enumerate(item):visit(child,path+(index,),depth+1)
        elif type(item) is str:
            require(len(item) <= 4096 and all(ord(char) >= 32 or char in '\n\r\t' for char in item),'phase-json-text-refused')
            if path in generation:require(item == '--passphrase','phase-json-privacy-refused')
            else:require(not policy.PRIVATE_CONTENT.search(item),'phase-json-privacy-refused')
        else:require(item is None or type(item) in (int,bool),'phase-json-type-refused')
    visit(value)


def phase_result(value, files, descriptor, modules, *, deadline=None):
    """Structure/privacy only; actual input/crypto acceptance belongs to Session."""
    adapter, gate = modules['adapter'], modules['gate']
    sha = lambda value:type(value) is str and re.fullmatch('[0-9a-f]{64}',value)
    require(type(value) is dict and set(value) == PHASE_RESULT_KEYS and type(value['schema_version']) is int and
            value['schema_version'] == 2 and value['purpose'] == 'phase-aware-separate-test-restage' and
            value['status'] == value['repository_input_acceptance'] == value['release_semantics'] == 'PASS' and
            value['development_only'] is True and value['selected_for_release'] is value['original_B_continuity'] is False and
            value['blockers'] == [] and type(value['blockers']) is list and
            all(value[key] == 'NOT RUN' for key in ('stable_promotion','production_trust','published_endpoint',
                'hardware_validation','installation','native_build')) and
            value['current_A_authorization'] == 'REVOKED' and
            value['original_crypto_verification'] == 'independent-public-key-phase-verification', 'phase-result-refused')
    require(type(value['cleanup']) is dict and value['cleanup'] == {'status':'PASS','private_state_absent':True,
            'signer_agent_stop':'PASS'} and type(value['cleanup']['private_state_absent']) is bool and
            all(sha(value[key]) for key in ('repository_authority_sha256','metadata_sha256','phase_receipt_sha256',
                                         'phase_request_sha256','release_sha256')), 'phase-result-refused')
    require(type(value['signer']) is str and re.fullmatch('[0-9A-F]{40}',value['signer']) and
            value['namespace'] == 'test-restage.'+value['repository_authority_sha256'][:16] and
            type(value['source_sha256']) is dict and value['source_sha256'] == adapter.SOURCES and
            type(value['tool_sha256']) is dict and set(value['tool_sha256']) == set(adapter.TOOLS) and
            all(sha(item) for item in value['tool_sha256'].values()), 'phase-result-refused')
    require(type(value['software_environment']) is dict and set(value['software_environment']) == {'architecture','page_size','execution'} and
            value['software_environment']['architecture'] == 'aarch64' and type(value['software_environment']['page_size']) is int and
            value['software_environment']['page_size'] > 0 and value['software_environment']['execution'] == 'local-bounded-private-processes',
            'phase-result-refused')
    require(value['public_files'] == {name:row for name,row in descriptor['public_files'].items() if name != 'result.json'},
            'phase-public-map-refused')
    lineage = adapter.decode(files['bundle/evidence/lineage.json'])
    require(type(lineage) is dict and set(lineage) == PHASE_LINEAGE_KEYS and value['lineage'] == lineage and
            type(lineage['schema_version']) is int and lineage['schema_version'] == 2 and
            lineage['purpose'] == 'phase-aware-separate-test-signer-restaging' and lineage['development_only'] is True and
            lineage['original_B_continuity'] is False and lineage['current_A_authorization'] == 'REVOKED' and
            all(lineage[key] == value[key] for key in ('repository_authority_sha256','metadata_sha256','original_crypto_verification',
                                                       'phase_receipt_sha256','phase_request_sha256')) and
            type(lineage['repository_source_commit']) is str and re.fullmatch('[0-9a-f]{40}',lineage['repository_source_commit']) and
            type(lineage['archives']) is list and len(lineage['archives']) == 4 and
            {row.get('name') for row in lineage['archives'] if type(row) is dict} == adapter.ORIGINALS,
            'phase-lineage-refused')
    input_rows = lineage['input_lineage']
    require(type(input_rows) is list and len(input_rows) == 15 and type(lineage['original_signer_roles']) is dict and
            set(lineage['original_signer_roles']) == {'signer-A','signer-B','verifier'} and
            lineage['archive_role'] in ('baseline','updated'), 'phase-lineage-refused')
    roles = lineage['original_signer_roles']
    for role,row in roles.items():
        require(type(row) is dict and set(row) == {'fingerprint','certificate','certificate_sha256'} and
                type(row['fingerprint']) is str and re.fullmatch('[0-9A-F]{40}',row['fingerprint']) and
                sha(row['certificate_sha256']), 'phase-lineage-refused')
        gate.relative(row['certificate'])
    require(len({row['fingerprint'] for row in roles.values()}) == 3 and
            sum(row.get('signer') == 'signer-A' for row in input_rows if type(row) is dict) == 7 and
            sum(row.get('signer') == 'signer-B' for row in input_rows if type(row) is dict) == 8,
            'phase-lineage-refused')
    for row in lineage['archives']:
        require(type(row) is dict and set(row) == {'name','filename','sha256','version','original_signer','original_signature_sha256'} and
                type(row['name']) is str and row['name'] in adapter.ORIGINALS and type(row['filename']) is str and
                type(row['version']) is str and 0 < len(row['version']) <= 128 and
                re.fullmatch(re.escape(row['name']+'-'+row['version'])+r'-any\.pkg\.tar\.(xz|zst|gz)',row['filename']) and
                sha(row['sha256']) and sha(row['original_signature_sha256']) and
                row['original_signer'] == roles['signer-A' if lineage['archive_role'] == 'baseline' else 'signer-B']['fingerprint'] and
                descriptor['public_files'].get('bundle/repo/'+row['filename'],{}).get('sha256') == row['sha256'],
                'phase-lineage-refused')
    row_keys = {'path','signature','signer','data_sha256','signature_sha256','fingerprint','certificate_sha256',
                'snapshot_integrity','snapshot_authorization','terminal_authorization'}
    semantic = {('current_A_authorization',):'REVOKED'}
    for number,row in enumerate(input_rows):
        require(type(row) is dict and set(row) == row_keys and row['signer'] in ('signer-A','signer-B') and
                row['snapshot_integrity'] == 'VALID' and row['snapshot_authorization'] == 'SNAPSHOT_ONLY' and
                row['terminal_authorization'] == ('REVOKED' if row['signer'] == 'signer-A' else 'VALID_AT_OBSERVATION') and
                type(row['fingerprint']) is str and re.fullmatch('[0-9A-F]{40}',row['fingerprint']) and
                row['fingerprint'] == lineage['original_signer_roles'][row['signer']].get('fingerprint') and
                row['certificate_sha256'] == lineage['original_signer_roles'][row['signer']].get('certificate_sha256') and
                all(sha(row[key]) for key in ('data_sha256','signature_sha256','certificate_sha256')),
                'phase-lineage-refused')
        gate.relative(row['path']);gate.relative(row['signature'])
        semantic[('input_lineage',number,'snapshot_authorization')] = 'SNAPSHOT_ONLY'
        semantic[('input_lineage',number,'terminal_authorization')] = row['terminal_authorization']
    phase_json_privacy(lineage,semantic=semantic,deadline=deadline)
    commands = value['commands'];require(type(commands) is list and 0 < len(commands) <= 256,'phase-command-refused')
    exceptions = []
    for number,row in enumerate(commands):
        require(type(row) is dict and set(row) == {'argv','exit_code','expected','stdout','stdout_sha256','stderr','stderr_sha256'} and
                type(row['argv']) is list and 0 < len(row['argv']) <= 64 and
                all(type(arg) is str and len(arg) <= 4096 and '\0' not in arg for arg in row['argv']) and
                type(row['exit_code']) is int and (type(row['expected']) is int and row['expected'] == row['exit_code'] == 0 or
                type(row['expected']) is str and row['expected'] == 'nonzero' and row['exit_code'] != 0), 'phase-command-refused')
        executable = Path(row['argv'][0]);family = executable.name
        require(executable.is_absolute() and executable.parent in (Path('/usr/bin'),Path('/bin')) and
                (family in adapter.TOOLS or re.fullmatch(r'python3\.[0-9]+',family)),'phase-command-refused')
        if '--passphrase' in row['argv']:
            require(family == 'gpg' and row['argv'][1:] == TEST_GENERATE,'phase-command-refused')
            exceptions.append(('commands',number,'argv',5))
        for stream in ('stdout','stderr'):
            require(row[stream] == f'logs/{number:03d}.{stream}' and row[stream] in files and
                    sha(row[stream+'_sha256']) and adapter.digest(files[row[stream]]) == row[stream+'_sha256'],
                    'phase-command-log-refused')
    phase_json_privacy(value,semantic={('current_A_authorization',):'REVOKED',
        **{('lineage',)+slot:expected for slot,expected in semantic.items()}},generation=tuple(exceptions),deadline=deadline)
    expected_cases = ('cold-readonly','apply-1','repeat-readonly','apply-2','signed-rollback-rejected',
                      'signed-same-sequence-change-rejected','wrong-namespace-rejected')
    require(type(value['client_cases']) is list and len(value['client_cases']) == 7 and
            tuple(row.get('name') for row in value['client_cases'] if type(row) is dict) == expected_cases and
            all(set(row) == {'name','result','expected_rejection','checkpoint_before','checkpoint_after','command_record'} and
                row['result'] == 'PASS' and type(row['command_record']) is int and 0 <= row['command_record'] < len(commands) and
                all(row[key] is None or sha(row[key]) for key in ('checkpoint_before','checkpoint_after'))
                for row in value['client_cases']), 'phase-client-result-refused')
    rejections = (None,None,None,None,'metadata sequence rollback',
                  'same sequence has altered metadata bytes','metadata namespace/signer differs from external pin')
    checkpoints = None
    for number,row in enumerate(value['client_cases']):
        before,after = row['checkpoint_before'],row['checkpoint_after']
        require(row['expected_rejection'] == rejections[number] and
                (before is None if number == 0 else before == checkpoints) and
                (after is not None and after != before if number in (1,3) else after == before) and
                commands[row['command_record']]['expected'] == ('nonzero' if number >= 4 else 0),
                'phase-client-result-refused')
        checkpoints = after
    for name in files:
        gate.relative(name)
    require(adapter.digest(files['bundle/release.json']) == value['release_sha256'] and
            value['new_signature_and_database_sha256'] == {Path(name).name:row['sha256']
                for name,row in descriptor['public_files'].items() if name.startswith('bundle/repo/') and
                ('.pkg.tar.' not in name or name.endswith('.sig'))}, 'phase-result-refused')
    return value


def phase_capture(development, deadline):
    require(development.repository_capture is not None,'phase-return-authority-required')
    session,status_raw,descriptor_raw,descriptor_sha = development.repository_capture
    module = sys.modules.get('development_repository_handoff')
    require(type(module) is types.ModuleType and type(session) is module.Session and
            type(session.sources) is module.Sources and session.sources.root == development.root and
            session.sources.grant['source_files'] == development.packet['source_files'], 'phase-return-authority-required')
    session.sources.class_state(session,'scripts/ci/development/repository_handoff.py',module)
    session.sources.class_state(session.sources,'scripts/ci/development/repository_handoff.py',module)
    session.sources.guard(deadline)
    observation = session.native_consumer_observation
    require(session.used is True and type(observation) is tuple and len(observation) == 3 and
            type(observation[0]) is types.FrameType and type(observation[1]) is types.FrameType and
            observation[2] is session.controller and session.original_scope is None,
            'phase-return-authority-required')
    native_frame, run_frame, controller = observation
    original = session.source_graph['original'];caller = native_frame.f_back
    require(native_frame.f_code is original['native_arm'].main.__code__ and
            native_frame.f_globals is original['native_arm'].__dict__ and
            run_frame.f_code is original['integration'].Controller.run.__code__ and
            run_frame.f_globals is original['integration'].__dict__ and
            type(controller) is original['integration'].Controller and
            native_frame.f_locals.get('controller') is controller and run_frame.f_locals.get('self') is controller and
            type(caller) is types.FrameType and caller.f_code is module.Session.execute.__code__ and
            caller.f_globals is module.__dict__ and caller.f_locals.get('self') is session and
            type(caller.f_locals.get('code')) is int and caller.f_locals['code'] == 0,
            'phase-return-authority-required')
    status = module.status_projection(module.decode(status_raw))
    require(module.encoded(status) == status_raw and status == session.result == development.report['repository_handoff'] and
            status['status'] == status['cleanup'] == status['input_acceptance'] == status['restage'] == 'PASS' and
            status['initial_exit_code'] == 0 and status['cancelled'] is False and status['error_code'] is None and
            status['execution_grant_sha256'] == session.sources.grant_pin and all(status[key] == session.sources.grant[key]
                for key in ('source_commit','run_id','run_attempt','actor_contract_sha256','initial_invocation_sha256')) and
            development.report['initial_integration'] == development.report['initial_cleanup'].get('status') == 'PASS' and
            not cancelled(), 'phase-return-authority-required')
    require(type(descriptor_raw) is bytes and 0 < len(descriptor_raw) <= packet.FILE_LIMIT and
            module.digest(descriptor_raw) == descriptor_sha == session.phase_export_sha256 and
            descriptor_raw == session.phase_export_raw, 'phase-descriptor-refused')
    descriptor = module.decode(descriptor_raw)
    require(set(descriptor) == {'path','receipt_sha256','receipt_bytes','public_files'} and
            module.encoded(descriptor) == descriptor_raw and descriptor['path'] == str(development.output/'repository-handoff/phase-public') and
            type(descriptor['receipt_bytes']) is int and 0 < descriptor['receipt_bytes'] <= packet.FILE_LIMIT and
            type(descriptor['receipt_sha256']) is str and re.fullmatch('[0-9a-f]{64}',descriptor['receipt_sha256']) and
            type(descriptor['public_files']) is dict and 0 < len(descriptor['public_files']) <= 513,
            'phase-descriptor-refused')
    modules = session.source_graph['phase'];gate, adapter = modules['gate'],modules['adapter']
    for key in ('gate','adapter'):
        path = 'scripts/port/repository-client-phase-stage/'+key+'.py'
        require(modules[key].__file__ == str(development.root/path),'phase-module-refused')
        for function in modules[key].__dict__.values():
            if isinstance(function,types.FunctionType):session.sources.global_function(function)
    return phase_files(Path(descriptor['path']),descriptor,modules,deadline)


def phase_files(root, descriptor, modules, deadline):
    """Bounded immutable byte custody; this helper alone confers no Session authority."""
    gate,adapter = modules['gate'],modules['adapter']
    gate.tree(root,descriptor['public_files'])
    root_node = root.lstat();files = {};total = 0
    directories = {root,*[root/parent for name in descriptor['public_files'] for parent in Path(name).parents]}
    directory_nodes = {}
    for directory in directories:
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o700,'phase-public-type-refused')
        directory_nodes[directory] = (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    for name,row in descriptor['public_files'].items():
        within(deadline);gate.relative(name)
        require(type(row) is dict and set(row) == {'sha256','bytes'} and type(row['bytes']) is int and
                0 <= row['bytes'] <= packet.FILE_LIMIT and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) and
                phase_filename(name,adapter.ORIGINALS), 'phase-public-map-refused')
        info = (root/name).lstat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o644,'phase-public-type-refused')
        raw = read_regular(root/name,packet.FILE_LIMIT,deadline=deadline)
        require(len(raw) == row['bytes'] and adapter.digest(raw) == row['sha256'],'phase-public-bytes-refused')
        total += len(raw);require(total <= packet.TOTAL_LIMIT,'phase-public-bound-refused');files[name] = raw
    require(root.lstat() == root_node and 'result.json' in files and
            descriptor['public_files']['result.json'] == {'bytes':descriptor['receipt_bytes'],'sha256':descriptor['receipt_sha256']},
            'phase-public-custody-refused')
    gate.tree(root,descriptor['public_files'])
    for directory,before in directory_nodes.items():
        info = directory.lstat()
        require(before == (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid),'phase-public-custody-refused')
    value = phase_result(adapter.decode(files['result.json']),files,descriptor,modules,deadline=deadline)
    require(files['result.json'] == adapter.encoded(value) and files['bundle/evidence/lineage.json'] == adapter.encoded(value['lineage']),
            'phase-result-canonical-required')
    policy = public_policy()
    for name,raw in files.items():
        within(deadline)
        if name in ('result.json','bundle/evidence/lineage.json'):continue  # Strict typed validation above.
        if name.endswith('.json'):phase_json_privacy(adapter.decode(raw),deadline=deadline)
        elif name.startswith('logs/') or name.endswith('.txt'):
            text = raw.decode('utf-8');require(not policy.PRIVATE_CONTENT.search(text) and
                all(ord(char) >= 32 or char in '\n\r\t' for char in text),'phase-public-privacy-refused')
        else:require(not re.search(rb'-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:[A-Z0-9 ]* )?PRIVATE KEY)-----|\((?:protected-|shadowed-)?private-key',raw),
                     'phase-public-privacy-refused')
    within(deadline)
    return files


def phase_bundle(files, deadline):
    """Publish exactly the captured validated bytes; no mutable path reread."""
    target = io.BytesIO()
    with tarfile.open(fileobj=target,mode='w:gz') as archive:
        for name,raw in sorted(files.items()):
            within(deadline);info = tarfile.TarInfo('phase-public/'+name)
            info.size = len(raw);info.mode = 0o644;info.uid = info.gid = info.mtime = 0
            archive.addfile(info,io.BytesIO(raw))
            require(target.tell() <= packet.FILE_LIMIT,'compressed-bundle-bound-exceeded')
    within(deadline);raw = target.getvalue()
    require(len(raw) <= packet.FILE_LIMIT,'compressed-bundle-bound-exceeded')
    return raw


def publish(development, bundle, emit=print):
    """Only existing producers' explicit public selectors reach workflow logs."""
    report = development.report
    roots = list(development.public)
    native = development.output / 'native'
    if native.is_dir():
        roots.append(native)
    initial = development.output / 'integration/public'
    if initial.is_dir():
        roots.extend(initial / name for name in ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites', 'summary')
                     if (initial / name).is_dir())
        try:
            initial_status = read_json(development.output / 'integration/result.json')
        except (OSError, ValueError):
            initial_status = {}
        for directory, stage in (('fixture-archives', 'fixtures'), ('signer-public-artifacts', 'signer'), ('repository-public-artifacts', 'repository')):
            path = initial / directory
            if path.exists() or initial_status.get('stages', {}).get(stage, {}).get('status') == 'PASS':
                roots.append(path)
    records = []
    if development.packet.get('schema_version') == 2:
        try:
            require(development.publication_deadline is not None,'publication-deadline-required')
            data = phase_bundle(phase_capture(development,development.publication_deadline),development.publication_deadline)
            pin = hashlib.sha256(data).hexdigest();name = 'development-repository-handoff-phase-public'
            emit(f'CACHY_ASAHI_EVIDENCE_BEGIN {name} sha256={pin} bytes={len(data)}')
            emit(base64.encodebytes(data).decode(),end='')
            emit(f'CACHY_ASAHI_EVIDENCE_END {name}')
            records.append({'name':name,'archive_root':'phase-public','sha256':pin,'bytes':len(data),'status':'PASS'})
            report['repository_publication'] = 'PASS'
        except Exception as error:
            development.repository_capture = None
            report['repository_publication'] = 'FAIL'
            records.append({'name':'development-repository-handoff-phase-public','status':'FAIL',
                            'error_code':'bounded-phase-publication-failed','error_type':type(error).__name__})
    for root in roots:
        try:
            # The original bootstrap exporter alone has the preexisting
            # context/GPG exclusion; new stages must supply explicit trees.
            if root != native:
                if root.parent == initial and root.name in ('fixture-archives', 'signer-public-artifacts', 'repository-public-artifacts'):
                    from initial_artifacts import receive
                    received = receive(ROOT, development.output / 'integration', root)
                    public_tree(root, {**received['opaque_approved'], **received['text_approved']})
                else:
                    public_tree(root)
            data = bundle(root)
            require(len(data) <= 8 * 1024**2, 'compressed-bundle-bound-exceeded')
            name = 'development-' + root.relative_to(development.output).as_posix().replace('/', '-')
            pin = hashlib.sha256(data).hexdigest()
            emit(f'CACHY_ASAHI_EVIDENCE_BEGIN {name} sha256={pin} bytes={len(data)}')
            emit(base64.encodebytes(data).decode(), end='')
            emit(f'CACHY_ASAHI_EVIDENCE_END {name}')
            records.append({'name': name, 'archive_root': root.name, 'sha256': pin, 'bytes': len(data), 'status': 'PASS'})
        except Exception as error:
            records.append({'name': 'development-' + root.relative_to(development.output).as_posix().replace('/', '-'),
                            'status': 'FAIL', 'error_code': 'bounded-publication-failed', 'error_type': type(error).__name__})
    report['bundles'] = records
    report['publication'] = 'PASS' if records and all(row['status'] == 'PASS' for row in records) else 'FAIL'
    stages = report['stages']
    required = (report.get('initial_integration') == 'PASS' and report.get('initial_cleanup', {}).get('status') == 'PASS'
                and not report.get('cancelled') and report['publication'] == 'PASS')
    if development.packet.get('schema_version') == 2:
        repository = report.get('repository_handoff',{})
        required = required and repository.get('status') == repository.get('cleanup') == repository.get('restage') == repository.get('input_acceptance') == 'PASS' and report.get('repository_publication') == 'PASS'
    required = required and all(stages[name]['status'] == 'PASS' for name in STAGES[:-1])
    if development.composition == packet.ZSH_COMPOSITION:
        required = required and stages.get('zsh-addon',{}).get('status') == 'PASS'
    if development.composition == packet.INSTALLER_COMPOSITION:required = False
    virtual = stages['virtual']['status']
    report['status'] = ('CAPTURED_REQUIRES_VISUAL_REVIEW' if virtual == 'CAPTURED_REQUIRES_VISUAL_REVIEW' else 'PASS') if required and virtual in ('PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW') else 'FAIL'
    save(development.output / 'result.json', report)
    summary = development.output / 'development-summary'; summary.mkdir(exist_ok=True)
    save(summary / 'result.json', report)
    try:
        public_tree(summary)
        data = bundle(summary); pin = hashlib.sha256(data).hexdigest()
        emit(f'CACHY_ASAHI_EVIDENCE_BEGIN development-observed-summary sha256={pin} bytes={len(data)}')
        emit(base64.encodebytes(data).decode(), end='')
        emit('CACHY_ASAHI_EVIDENCE_END development-observed-summary')
    except Exception:
        report.update(status='FAIL', publication='FAIL', error_code='final-summary-publication-failed')
        save(development.output / 'result.json', report)
        save(summary / 'result.json', report)
    emit(json.dumps(report, sort_keys=True))
    return report['status'] in ('PASS', 'CAPTURED_REQUIRES_VISUAL_REVIEW')


def close_boundary(development, previous, timer):
    """Own pending delivery until cancellation has a durable terminal receipt."""
    global CANCELLED
    def remember(*_):
        global CANCELLED
        CANCELLED = True
    failed = False
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, set(previous))
    # Previous default handlers cannot resume before pending delivery is
    # observed and recorded. The closing handlers only remember signals.
    for sig in previous:
        try:
            signal.signal(sig, remember)
        except KeyboardInterrupt:
            CANCELLED = failed = True
        except Exception:
            failed = True
    try:
        signal.setitimer(signal.ITIMER_REAL, *timer)
    except KeyboardInterrupt:
        CANCELLED = failed = True
    except Exception:
        failed = True
    if signal.sigpending() & set(previous):
        CANCELLED = True
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    except KeyboardInterrupt:
        CANCELLED = failed = True
    except Exception:
        failed = True
    def record_failure():
        if development is None:
            print(json.dumps({'purpose':'same-job-native-development','status':'FAIL','execution':'NOT RUN',
                'error_code':'composed-boundary-finalization-failed','cancelled':CANCELLED},sort_keys=True))
            return
        development.report.update(status='FAIL', cancelled=CANCELLED)
        if 'error_code' not in development.report:development.report['error_code'] = 'terminal-finalization-failed'
        development.repository_capture = None
        if development.composition == packet.INSTALLER_COMPOSITION:development.persist_installer()
        elif development.composition == packet.ZSH_COMPOSITION:development.persist_zsh()
        else:development.persist()
        print(json.dumps(development.report, sort_keys=True))
    if failed or CANCELLED:
        record_failure()
    for sig, handler in previous.items():
        try:
            signal.signal(sig, handler)
        except KeyboardInterrupt:
            CANCELLED = failed = True
        except Exception:
            failed = True
    if failed or CANCELLED:
        record_failure()
    return failed or CANCELLED


def retire_installer_module(session, development):
    """Retire only the exact Session graph member; leave foreign registry entries intact."""
    if session is None:return True
    composition = getattr(session,'composition',None)
    require(type(composition) is str and composition in packet.COMPOSED_MODES, 'installer-retirement-refused')
    if composition != packet.INSTALLER_COMPOSITION:return True
    owner = sys.modules.get('development_repository_handoff')
    require(type(owner) is types.ModuleType and type(session) is owner.Session and
            type(session.sources) is owner.Sources and type(session.source_graph) is dict, 'installer-retirement-refused')
    module = session.source_graph.get('native_preflight')
    if module is None:
        # Registration may roll back the graph while retaining a foreign registry entry.
        return sys.modules.get(INSTALLER_NAME) is None and (development is None or development.native_preflight_module is None)
    require(type(module) is types.ModuleType and type(module.__name__) is str and module.__name__ == INSTALLER_NAME and
            type(module.__dict__.get('OWN')) is str and module.OWN == INSTALLER_PATH and
            type(module.__file__) is str and module.__file__ == str(session.sources.root/INSTALLER_PATH) and
            (development is None or development.native_preflight_module is None or development.native_preflight_module is module),
            'installer-retirement-refused')
    registered = sys.modules.get(INSTALLER_NAME)
    if registered is module:del sys.modules[INSTALLER_NAME]
    elif registered is not None:return False
    return True


def retire_zsh_modules(session):
    """Retain unresolved helper custody; retire only this exact Session's healthy pair."""
    if session is None:return True
    composition = getattr(session,'composition',None)
    require(type(composition) is str and composition in packet.COMPOSED_MODES,'zsh-retirement-refused')
    if composition != packet.ZSH_COMPOSITION:return True
    owner = sys.modules.get('development_repository_handoff')
    require(type(owner) is types.ModuleType and type(session) is owner.Session and
            type(session.sources) is owner.Sources,'zsh-retirement-refused')
    session.sources.class_state(session,'scripts/ci/development/repository_handoff.py',owner)
    return session.retire_zsh()


def composed_main(args, pins, *, entry):
    """Root bootstrap inputs are mandatory; construction/preflight never starts actors."""
    global CANCELLED
    require(all(getattr(args,name,None) is not None for name in ('clock','clock_sha256','execution_grant',
            'execution_grant_sha256','runtime_contract','runtime_contract_sha256')), 'composed-bootstrap-required')
    composition = getattr(args,'composition',packet.COMPOSITION)
    require(type(composition) is str and composition in packet.COMPOSED_MODES, 'composed-packet-contract-refused')
    clock_raw = private_input(args.clock,args.clock_sha256,'DEVELOPMENT_CLOCK',16*1024)
    deadline, workflow_end = workflow_clock(clock_raw,entry=entry,
        controller_entry=getattr(args,'controller_entry_monotonic',None))
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    require(previous_timer == (0.0,0.0),'active-enclosing-timer-refused')
    previous = {sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
    development = session = None
    try:
        for sig in previous:signal.signal(sig,interrupt)
        within(deadline);signal.setitimer(signal.ITIMER_REAL,deadline-time.monotonic())
        source_packet = packet.preflight_composed(ROOT,args.packet,args.development_sha256,os.environ.get('GITHUB_SHA',''),composition=composition)
        composed_mode(source_packet,composition)
        within(deadline)
        require(all(source_packet['metadata_pins'].get(name) == pin for name,pin in pins.items()), 'runtime-metadata-pins-drift')
        if args.check_only:
            print('composed development source packet verified; execution NOT RUN')
            return 0
        grant_raw = private_input(args.execution_grant,args.execution_grant_sha256,'DEVELOPMENT_EXECUTION_GRANT',packet.FILE_LIMIT)
        within(deadline)
        runtime_raw = private_input(args.runtime_contract,args.runtime_contract_sha256,'DEVELOPMENT_RUNTIME_CONTRACT',16*1024)
        within(deadline)
        output, cache = args.output.absolute(), args.cache.absolute()
        require('..' not in output.parts and '..' not in cache.parts and
                all(not p.is_symlink() for p in (cache,*cache.parents,*output.parents)) and
                not output.exists() and not output.is_symlink(), 'fresh-output-required')
        require(not any(a.is_relative_to(b) for a,b in ((output,ROOT),(cache,ROOT),(output,cache),(cache,output))),
                'disjoint-output-cache-required')
        require(Path.cwd().resolve() == ROOT, 'authenticated-checkout-cwd-required')
        session, callbacks, runtime, argv = composed_sources(ROOT,source_packet,grant_raw,args.execution_grant_sha256,
                                                            runtime_raw,output,cache,deadline,composition=composition)
        within(deadline)
        output.mkdir(mode=0o700);cache.mkdir(mode=0o700,exist_ok=True)
        development = Development(ROOT,output,cache,source_packet,deadline=deadline,composition=composition,
            clock_nonce=packet.decode(clock_raw)['nonce'],runtime_contract=runtime)
        development.report.update(source_packet_sha256=args.development_sha256,composition=composition,
                                  execution_grant_sha256=args.execution_grant_sha256)
        development.run_composed(session,callbacks,runtime,argv)
        publication_end = min(workflow_end,time.monotonic()+120)
        development.publication_deadline = publication_end
        within(publication_end);signal.setitimer(signal.ITIMER_REAL,publication_end-time.monotonic())
        evidence = session.sources.module('development_log_evidence','scripts/ci/log_evidence.py')
        code = 0 if publish(development,evidence.bundle) else 1
        within(publication_end)
        return code
    except BaseException:
        if development is not None:
            development.report.update(status='FAIL',publication='FAIL')
            if CANCELLED:development.report['cancelled'] = True
            if 'error_code' not in development.report:development.report['error_code'] = 'composed-boundary-failed'
            if composition == packet.INSTALLER_COMPOSITION:development.persist_installer()
            elif composition == packet.ZSH_COMPOSITION:development.persist_zsh()
            else:development.persist()
        else:
            print(json.dumps({'purpose':'same-job-native-development','status':'FAIL','execution':'NOT RUN',
                              'error_code':'composed-bootstrap-refused'},sort_keys=True))
        raise
    finally:
        retirement_failed = False
        first = sys.exception()
        try:
            retirement_failed = not retire_installer_module(session,development)
            if composition == packet.ZSH_COMPOSITION:
                retirement_failed = not retire_zsh_modules(session) or retirement_failed
        except BaseException as error:
            retirement_failed = True
            if isinstance(error,KeyboardInterrupt):
                CANCELLED = True
        if retirement_failed and development is not None:
            key = 'zsh_retirement' if composition == packet.ZSH_COMPOSITION else 'native_preflight_retirement'
            code = 'zsh-retirement-failed' if composition == packet.ZSH_COMPOSITION else 'installer-retirement-failed'
            development.report.update(status='FAIL',**{key:'FAIL'})
            development.report.setdefault('error_code',code)
            development.repository_capture = None
            try:
                if composition == packet.INSTALLER_COMPOSITION:development.persist_installer()
                elif composition == packet.ZSH_COMPOSITION:development.persist_zsh()
                else:development.persist()
            except BaseException:
                if first is None:raise
        try:
            try:closing_failed = close_boundary(development,previous,previous_timer)
            except BaseException as error:
                if composition == packet.COMPOSITION or first is None:raise
                closing_failed = True
                if isinstance(error,KeyboardInterrupt):CANCELLED = True
                if development is not None:
                    development.report.update(status='FAIL',terminal_finalization='FAIL')
                    development.report.setdefault('error_code','terminal-finalization-failed')
                    development.repository_capture = None
            if closing_failed or retirement_failed:
                # A finally exception overrides a provisional successful return.
                if first is None or composition == packet.COMPOSITION:raise ValueError('composed-finalization-failed')
        finally:
            if session is not None:
                for name in ('development_repository_authority','development_repository_handoff'):
                    sys.modules.pop(name,None)


def main(argv=None):
    entry = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs-sha256', 'recipes-sha256', 'integration-sha256', 'development-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--packet', type=Path, default=ROOT / 'scripts/ci/development/packet.lock.json')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--composition',choices=packet.COMPOSED_MODES)
    parser.add_argument('--controller-entry-monotonic',type=float)
    for name in ('clock','execution-grant','runtime-contract'):
        parser.add_argument('--'+name,type=Path)
        parser.add_argument('--'+name+'-sha256')
    args = parser.parse_args(argv)
    pins = {'scripts/ci/inputs.lock.json': args.inputs_sha256, 'scripts/ci/recipes.lock.json': args.recipes_sha256,
            'scripts/ci/integration.lock.json': args.integration_sha256}
    if args.composition is not None:return composed_main(args,pins,entry=entry)
    require(args.controller_entry_monotonic is None, 'controller-entry-requires-composition')
    try:
        source_packet = packet.preflight(ROOT, args.packet, args.development_sha256, os.environ.get('GITHUB_SHA', ''))
        require(all(source_packet['metadata_pins'].get(name) == pin for name, pin in pins.items()), 'runtime-metadata-pins-drift')
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'purpose': 'same-job-native-development', 'status': 'FAIL', 'source_preflight': 'FAIL',
                          'execution': 'NOT RUN', 'error_code': 'reviewed-source-packet-refused'}, sort_keys=True))
        raise
    if args.check_only:
        print('development source packet verified; execution NOT RUN')
        return 0
    output, cache = args.output.absolute(), args.cache.absolute()
    require('..' not in output.parts and '..' not in cache.parts and not cache.is_symlink() and
            not any(p.is_symlink() for p in cache.parents), 'safe-output-cache-required')
    require(not output.exists() and not output.is_symlink() and not any(p.is_symlink() for p in output.parents), 'fresh-output-required')
    require(ROOT not in output.parents and ROOT not in cache.parents and output not in cache.parents and cache not in output.parents and output != cache,
            'disjoint-output-cache-required')
    output.mkdir(mode=0o700)
    cache.mkdir(mode=0o700, exist_ok=True)
    development = Development(ROOT, output, cache, source_packet)
    development.report['source_packet_sha256'] = args.development_sha256
    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    code = 1
    finalization_failed = False
    try:
        native = load_native(ROOT)
        native_args = ['integration', '--inputs-sha256', args.inputs_sha256, '--recipes-sha256', args.recipes_sha256,
                       '--integration-sha256', args.integration_sha256, '--integration-output', str(output / 'integration'),
                       '--cache', str(cache), '--output', str(output / 'native')]
        signal.setitimer(signal.ITIMER_REAL, 3000)
        development.run(native, native_args)
        signal.setitimer(signal.ITIMER_REAL, 0)
        from log_evidence import bundle
        try:
            code = 0 if publish(development, bundle) else 1
        except KeyboardInterrupt:
            development.report.update(status='FAIL', cancelled=True, publication='FAIL', error_code='publication-cancelled')
            with_signal = {sig: signal.signal(sig, signal.SIG_IGN) for sig in previous}
            try:
                development.persist()
                print(json.dumps(development.report, sort_keys=True))
            finally:
                for sig, handler in with_signal.items():
                    signal.signal(sig, handler)
            code = 1
    finally:
        finalization_failed = close_boundary(development, previous, previous_timer)
    return 1 if finalization_failed else code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, KeyboardInterrupt):
        print('FAIL: development boundary/source refusal', file=sys.stderr)
        sys.exit(1)
