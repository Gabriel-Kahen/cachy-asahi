# SPDX-License-Identifier: MIT
"""Versioned Qt3 stage borrowing the exact maintained image execution machinery.

Only two build_stage AST seams differ: the explicit Root public-trust scope,
and passive zstd PKGINFO reading. Admission, Build, DRIVER and cleanup retain
their reviewed implementations and real kernel/custody checks.
"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import time

HERE = Path(__file__).resolve().parent
OPERATION = 'bankstown-qt3-native-private-test-v1'
TRUST_SCOPE = 'BANKSTOWN_QT3_IMAGE_INPUT_TRUST_ONLY'
COMMAND_ROWS = 512
SIGNATURE_ROWS = 385
RESERVED_CONTROL_ROWS = 96
HELD_IMAGE_PIN = dict(bytes=55783, sha256='f4e590532d7f6115f830215810f9dee5f2a1eb714351a9a7e572d22c5a255f90')


def need(value, code):
    if not value:
        raise ValueError(code)


def pin(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def local(name):
    path = HERE / (name + '.py')
    spec = importlib.util.spec_from_file_location('bankstown_qt3_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BoundedReader:
    """Finite decompressed DATA reads; never extract or invoke a decompressor."""
    def __init__(self, stream, deadline, cap=2 * 1024**3):
        self.stream, self.deadline, self.cap, self.count = stream, deadline, cap, 0

    def read(self, size=-1):
        need(time.monotonic() < self.deadline, 'METADATA_DEADLINE')
        size = min(1024**2, self.cap + 1 - self.count) if size < 0 else min(size, self.cap + 1 - self.count)
        need(size > 0, 'METADATA_EXPANDED_BYTE_BOUND')
        body = self.stream.read(size)
        self.count += len(body)
        need(self.count <= self.cap, 'METADATA_EXPANDED_BYTE_BOUND')
        return body


def zstd_package_metadata(path, metadata_parser, *, deadline, opener=None):
    """Use Python3.14's decoder and the actual maintained metadata predicate."""
    if opener is None:
        try:
            from compression import zstd
        except ImportError:
            raise ValueError('PYTHON314_ZSTD_DATA_READER_REQUIRED') from None
        opener = zstd.open
    found, total = [], 0
    with opener(path, 'rb') as raw:
        bounded = BoundedReader(raw, deadline)
        with tarfile.open(fileobj=bounded, mode='r|') as archive:
            for count, member in enumerate(archive, 1):
                need(time.monotonic() < deadline and count <= 100000
                     and 0 <= member.size <= 2 * 1024**3, 'PACKAGE_METADATA_MEMBER_BOUND')
                total += member.size
                need(total <= 2 * 1024**3, 'PACKAGE_METADATA_LOGICAL_BOUND')
                if member.name.removeprefix('./') == '.PKGINFO':
                    need(member.isfile() and member.size <= 256 * 1024, 'BOUNDED_ACTUAL_PKGINFO')
                    with archive.extractfile(member) as stream:
                        body = stream.read(member.size + 1)
                    need(len(body) == member.size, 'TRUNCATED_ACTUAL_PKGINFO')
                    found.append(metadata_parser(body))
    need(len(found) == 1, 'ONE_ACTUAL_PKGINFO')
    return found[0]


def projected_stage(module, body):
    """Compile only the whole-pinned stage, refusing any unreviewed seam shape."""
    need(pin(body) == HELD_IMAGE_PIN, 'EXACT_HELD_IMAGE_PROGRAM')
    tree = ast.parse(body)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'build_stage']
    need(len(functions) == 1, 'ONE_HELD_BUILD_STAGE')
    function = functions[0]
    scope_count = metadata_count = 0
    for node in ast.walk(function):
        if isinstance(node, ast.Constant) and node.value == 'CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY':
            node.value = TRUST_SCOPE
            scope_count += 1
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'md':
            expected = "T._metadata(b.run('pkginfo-%03d' % i, ['/usr/bin/bsdtar', '-xOf', row['archive']['path'], '.PKGINFO'], 60)) if magic == b'\\x28\\xb5\\x2f\\xfd' else package_metadata(row['archive']['path'])"
            need(ast.dump(node.value) == ast.dump(ast.parse(expected, mode='eval').body), 'EXACT_HELD_METADATA_SEAM')
            node.value = ast.parse("package_metadata(row['archive']['path'])", mode='eval').body
            metadata_count += 1
    need(scope_count == metadata_count == 1, 'TWO_EXACT_REVIEWED_STAGE_SEAMS')
    projected = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = module.__dict__
    exec(compile(projected, str(HERE / 'image.py') + ':reviewed-stage', 'exec'), namespace)
    return namespace['build_stage']


def bind_inputs(I, C, request, stage, source, H, d, c, *, verify_archives=True):
    """Root pin and fixed stage selection; the actor always verifies all bodies."""
    need(stage == c['stage'] == 'qt3' and d['capability']['operation'] == OPERATION, 'FIXED_QT3_STAGE')
    need(d['inputs_pin'] == I.pin(I.encoded(request)), 'ROOT_SELECTED_INPUT_REQUEST_PIN')
    need(d['capability']['command_rows'] == COMMAND_ROWS
         and SIGNATURE_ROWS + RESERVED_CONTROL_ROWS <= COMMAND_ROWS, 'FINITE512_ROW_BUDGET')
    plan = I.plan_inputs(source_root=source, source_rows=C.source_rows(d, source),
                         request=request, verify_archives=verify_archives)
    need(len(plan['base_rows']) == 257 and len(plan['additions']) == 128, 'EXACT385_SIGNED_OPERANDS')
    return plan


def build_qt3_image(*, delegation_raw, delegation_sha256, context, source_root,
                   inputs, executor, output, context_program=None):
    """Return raw provisional image DATA; only Root can qualify the handoff.

    Actual admission, controller/executor facts, normal signed ALPM and every
    natural retirement remain mandatory. No executor or image is synthesized.
    """
    need(type(delegation_raw) is bytes and 0 < len(delegation_raw) <= 2 * 1024**2
         and pin(delegation_raw)['sha256'] == delegation_sha256, 'EXTERNAL_ROOT_DELEGATION_PIN')
    preview = json.loads(delegation_raw)
    need(type(preview) is dict and preview.get('kind') == 'ROOT_DELEGATED_BANKSTOWN_QT3_PRIVATE_TEST_V1'
         and preview.get('issuer') == 'Root' and preview.get('approved') is True,
         'GENUINE_EXTERNAL_ROOT_QT3_SELECTION')
    C = context_program or local('context')
    # Authenticate the complete Source/dependency map before importing its
    # passive input implementation. The unchanged image admission below also
    # rechecks the actual native kernel domains, not merely these DATA joins.
    admitted_d, _, _ = C.admit(delegation_raw, delegation_sha256, context, source_root, executor)
    source_rows = C.source_rows(admitted_d, source_root)
    dependency = source_rows['scripts/ci/bankstown-qt3-native-source/inputs.py']
    need(pin(C.read(HERE / 'inputs.py', 128 * 1024)[0]) == {k: dependency[k] for k in ('bytes', 'sha256')},
         'ACTUAL_SOURCE_INPUT_IMPLEMENTATION_PIN')
    I = local('inputs')
    M = I.held(source_root, 'image_current_v3.py')  # Separate module globals only.
    original_admit = M.admit
    M.context_contract = C.context_contract
    M.OP, M.COUNTS, M.__file__ = OPERATION, {'qt3': 477}, str(HERE / 'image.py')
    need(M.admit is original_admit, 'UNCHANGED_ACTUAL_IMAGE_ADMISSION')
    plans = []

    def selected(request, stage, source, H, d, c):
        plan = bind_inputs(I, C, request, stage, source, H, d, c)
        plans.append(plan)
        return plan['base'], plan['base_rows'], plan['additions'], plan['baseline'], plan['expected']

    # The original function verifies the Root/program/code/policy bindings and
    # actual kernel owner+daemon observations before this selection is called.
    M.selected_inputs = selected
    original_package_metadata = M.package_metadata
    deadline = None
    parsers = []

    def metadata(path):
        need(deadline is not None, 'ACTUAL_ADMISSION_BEFORE_METADATA')
        with Path(path).open('rb') as stream:
            magic = stream.read(4)
        if magic == b'\x28\xb5\x2f\xfd':
            if not parsers:
                parsers.append(M.tools(Path(source_root))._metadata)
            return zstd_package_metadata(path, parsers[0], deadline=deadline)
        need(time.monotonic() < deadline, 'METADATA_DEADLINE')
        return original_package_metadata(path)

    M.package_metadata = metadata
    body = I.read_code(Path(source_root) / I.NATIVE / 'image_current_v3.py', HELD_IMAGE_PIN)
    stage = projected_stage(M, body)
    # The unchanged admission still runs inside stage; this wrapper only clips
    # passive reads to its same finite original work deadline after admission.
    def admit(*args, **kwargs):
        nonlocal deadline
        admitted = original_admit(*args, **kwargs)
        d = admitted[0]
        deadline = time.monotonic() + d['capability']['total_seconds'] - 90
        return admitted

    M.admit = admit
    report = stage(delegation_raw=delegation_raw, delegation_sha256=delegation_sha256,
        context=context, source_root=source_root, inputs=inputs, executor=executor,
        output=output, context_program=C)
    need(len(plans) == 1 and report['packages'] == plans[0]['expected']
         and report['status'] == 'PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY', 'ACTUAL477_STAGE_RESULT')
    report['kind'] = 'BANKSTOWN_QT3_IMAGE_DATA_V1'
    report['catalog_pin'] = {k: plans[0]['catalog'][k] for k in ('bytes', 'sha256')}
    report['input_request_pin'] = plans[0]['request_pin']
    report['execution_projection'] = dict(trust_scope=TRUST_SCOPE,
        metadata='PASSIVE_PYTHON314_ZSTD_WITH_HELD_METADATA_PREDICATE',
        held_image_program=I.HELD['image_current_v3.py'][1], command_rows_cap=COMMAND_ROWS,
        signed_operands=SIGNATURE_ROWS, reserved_control_rows=RESERVED_CONTROL_ROWS)
    (Path(output) / 'image-provisional.json').write_bytes(M.encoded(report))
    return report
