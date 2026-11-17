# SPDX-License-Identifier: MIT
"""Bounded v19 runtime bridge over immutable project TEST admission14dd.

All input references and the external Root decision are fixed by CONFIG_PIN.
Import enters no role. Public gpgv is possible only through the caller's existing
owned/supervised call function; no default subprocess or image executor exists.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import types

CONFIG_PIN=None
CONFIG = 'hosted/project-test-provider.json'
INTERFACE = 'scripts/ci/rust199-source-reference-native/project_test_provider_v1/admission.py'
INTERFACE_PIN = dict(bytes=22931, sha256='5fa246f5b23152aeb2833ebb1f33e30d94149ee71796c1b85366c037a1e1b9f9')
PATHS = dict(policy='project-test/provider-policy.json', decision='project-test/Root-provider-decision.json')


def need(value, why):
    if not value:
        raise ValueError('project-provider bridge: ' + why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate DATA key'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite DATA'))


def read(path, cap, tick=lambda: None):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute DATA')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap, 'bounded single-link DATA')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            tick(); raw = stream.read(cap + 1); tick()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = lambda row: tuple(getattr(row, name) for name in fields)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'stable complete DATA')
        return raw
    finally:
        os.close(fd)


def interface(root):
    path = Path(root) / INTERFACE; raw = read(path, 128 * 1024)
    need(pin(raw) == INTERFACE_PIN, 'immutable embedded project interface14dd')
    A = types.ModuleType('v19_project_admission14dd'); A.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), A.__dict__)
    return A


def binding(root, A, tick):
    need(CONFIG_PIN is not None, 'UNBOUND Root policy/decision configuration')
    A.D.descriptor(CONFIG_PIN, A.D.MIB)
    raw = read(Path(root) / CONFIG, A.D.MIB, tick)
    need(pin(raw) == CONFIG_PIN, 'exact constructor-selected provider config')
    value = A.decode(raw)
    need(raw == A.encode(value) and set(value) == {'schema', 'kind', 'policy', 'decision'}
         and type(value['schema']) is int and value['schema'] == 19
         and value['kind'] == 'RUST19_PROJECT_TEST_PROVIDER_BINDING_V1', 'canonical finite provider config')
    for name, path in PATHS.items():
        A.reference(value[name], A.D.MIB)
        need(value[name]['path'] == path, 'fixed separate project policy/Root-decision path')
    return value


def policy(root, *, now=None, tick=lambda: None):
    root = Path(root); A = interface(root); selected = binding(root, A, tick)
    p = A.read_ref(root, selected['policy'], A.D.MIB, tick)
    decision = A.read_ref(root, selected['decision'], A.D.MIB, tick)
    state = A.admit(root, p, selected['policy']['sha256'], decision, selected['decision']['sha256'], now=now, tick=tick)
    state['bridge_config'] = dict(pin=CONFIG_PIN, references=selected)
    checked(state, root, now=now, tick=tick)
    return state


def checked(state, root=None, *, now=None, tick=lambda: None):
    """Re-read exact selections and expiry at every runtime boundary."""
    need(type(state) is dict and isinstance(state.get('source_root'), Path), 'explicit admitted selection state')
    source = state['source_root']; need(root is None or Path(root) == source, 'same exact Source root')
    A = interface(source); selected = binding(source, A, tick)
    need(state.get('bridge_config') == dict(pin=CONFIG_PIN, references=selected), 'same full binding selection')
    p = A.validate_policy(state['policy'])
    raw = A.read_ref(source, selected['policy'], A.D.MIB, tick)
    need(raw == A.encode(p) and state['policy_pin'] == pin(raw), 'same whole immutable policy')
    raw_decision = A.read_ref(source, selected['decision'], A.D.MIB, tick)
    need(state['Root_decision_pin'] == pin(raw_decision) and raw_decision == A.encode(state['Root_decision']), 'same complete Root decision')
    A.root_decision(raw_decision, selected['decision']['sha256'], p, pin(raw), int(time.time()) if now is None else now)
    need(state['expected_inventory'] == A.D.expected_inventory(source, p), 'same full baseline plus additions inventory')
    return A


def gpgv_receipt(state, receipt, A, now):
    p = state['policy']; rows = receipt.get('gpgv_evidence'); scope = receipt.get('gpgv_context')
    need(type(scope) is dict and set(scope) == {'source_root', 'context_root', 'output_root'}
         and scope['source_root'] == str(state['source_root']), 'same explicit project verification DATA roots')
    for key in ('context_root', 'output_root'):
        value = scope[key]
        need(type(value) is str and 0 < len(value) <= 4096 and not any(ord(c) < 32 for c in value), 'bounded public verification path')
        path = Path(value)
        need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents))
             and not path.is_relative_to(state['source_root']), 'separate ordinary public verification path')
    need(type(rows) is dict and set(rows) == {row['name'] for row in p['packages']}, 'complete two-provider public gpgv evidence')
    for package in p['packages']:
        row = rows[package['name']]
        source = str(state['source_root'] / 'build-dependencies' / package['filename'])
        argv = ['/usr/bin/gpgv', '--homedir', str(Path(scope['output_root']) / 'project-test-verification'),
                '--keyring', str(Path(scope['context_root']) / 'project-test-dependencies/public-test.gpg'), '--status-fd', '1', source + '.sig', source]
        need(type(row) is dict and set(row) == {'argv', 'returncode', 'status', 'status_base64'}
             and type(row['returncode']) is int and row['returncode'] == 0 and row['argv'] == argv
             and type(row['status_base64']) is str and 0 < len(row['status_base64']) <= 87384, 'whole successful scoped gpgv receipt')
        raw = base64.b64decode(row['status_base64'], validate=True)
        need(len(raw) <= 65536 and pin(raw) == row['status'] == receipt['verified_signatures'][package['name']]['gpgv_status'], 'whole retained gpgv status')
        A.signature_status(raw, p, now)


def prepare_context(source_root, context, output, selection, call, tick=lambda: None, *, now=None):
    A = checked(selection, source_root, now=now, tick=tick); evidence = {}
    expected = {str(Path(source_root) / 'build-dependencies' / row['filename']): row['name'] for row in selection['policy']['packages']}
    def supervised(argv, timeout):
        need(type(argv) is list and len(argv) == 9 and argv[:1] == ['/usr/bin/gpgv'] and timeout == 30
             and argv[-1] in expected and argv[-2] == argv[-1] + '.sig'
             and argv[1:3] == ['--homedir', str(Path(output) / 'project-test-verification')]
             and argv[3:7] == ['--keyring', str(Path(context) / 'project-test-dependencies/public-test.gpg'), '--status-fd', '1'], 'only exact supervised project TEST gpgv')
        checked(selection, source_root, now=now, tick=tick)
        result = call(argv, timeout=timeout); tick()
        need(type(result.returncode) is int and result.returncode == 0 and type(result.stdout) is bytes and len(result.stdout) <= 65536, 'bounded successful public verification')
        name = expected[argv[-1]]; need(name not in evidence, 'one signature observation per selected provider')
        evidence[name] = dict(argv=argv, returncode=0, status=pin(result.stdout), status_base64=base64.b64encode(result.stdout).decode('ascii'))
        return result
    receipt = A.prepare_context(selection, context, output, supervised, now=now, tick=tick)
    receipt = dict(receipt, gpgv_evidence=evidence, gpgv_context=dict(source_root=str(source_root), context_root=str(context), output_root=str(output)))
    A = checked(selection, source_root, now=now, tick=tick)
    gpgv_receipt(selection, receipt, A, int(time.time()) if now is None else now)
    path = Path(output) / 'build-dependency-audit.json'
    with path.open('xb') as stream: stream.write(encode(receipt))
    need(read(path, A.D.MIB, tick) == encode(receipt), 'whole persisted scoped TEST verification audit')
    return receipt


def extend_dockerfile(original, selection, verified_context, *, now=None):
    A = checked(selection, now=now); gpgv_receipt(selection, verified_context, A, int(time.time()) if now is None else now)
    result = A.image_dockerfile(selection, original, verified_context, now=now)
    checked(selection, now=now)
    return result


def observe(image_root, source_root, selection, tick=lambda: None, *, image_id, native=False, now=None):
    A = checked(selection, source_root, now=now, tick=tick)
    result = A.module(A.HERE / 'image.py').observe(image_root, source_root, selection['policy'], image_id=image_id, tick=tick, native=native, D=A.D)
    checked(selection, source_root, now=now, tick=tick)
    return result


def validate_observation(value, source_root, selection, expected=None, *, image_id, native=True, tick=lambda: None, now=None):
    A = checked(selection, source_root, now=now, tick=tick)
    result = A.module(A.HERE / 'image.py').validate_observation(value, source_root, selection['policy'], image_id=image_id, expected=expected, native=native, D=A.D)
    checked(selection, source_root, now=now, tick=tick)
    return result
