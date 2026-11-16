# SPDX-License-Identifier: MIT
"""Finite audio Source constructor; it creates DATA, never a Root grant."""
import importlib.util
import stat
import types
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
FAMILY = 'scripts/ci/bankstown-qt3-native-source/'
RUNTIME = ('context.py', 'controller.py', 'inputs.py', 'image.py', 'handoff.py',
           'handoff.schema.json', 'materialize.py', 'owner.py', 'policy.PROPOSAL.json')
HELD = 'scripts/ci/first-login-enrollment-native-source/payload/native/'
REQUIRED = {FAMILY + n for n in RUNTIME} | {HELD + n for n in (
    'delegated_context_v3.py', 'owned_executor_current_v3.py', 'base_inputs_current_v3.py',
    'inputs_current_v3.py', 'image_current_v3.py', 'build_tools_tools_v2.py')} | {
    'scripts/virtual/owned_process.py', 'scripts/ci/bankstown-qt3-native-profile-v1/profile.py',
    'scripts/port/bankstown-qt3-native-v1/admission.py',
    'scripts/port/bankstown-qt3-native-v1/profile.py',
    'scripts/port/bankstown-qt3-native-v1/builder.py',
    'scripts/port/bankstown-qt3-native-v1/entry.sh',
    'inputs/stages/baseline349.expected.lock'}


def local(name):
    spec = importlib.util.spec_from_file_location('bankstown_source_prepare_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = local('handoff')


def required_members(file_rows):
    """Use the frozen admission program's real closure, without issuing a trial."""
    key = 'scripts/port/bankstown-qt3-native-v1/admission.py'
    H.need(key in file_rows, 'FROZEN_ADMISSION_SOURCE_REQUIRED')
    row = file_rows[key]
    expected = dict(bytes=8276, sha256='6408b84bdf54e604ae6d734dedbbc5b179a7d2ded7c68abfa8451e8b7a16cf02')
    H.need({k: row[k] for k in ('bytes', 'sha256')} == expected, 'FROZEN_ADMISSION_SOURCE_PIN')
    raw = H.verify_reference({k: row[k] for k in ('path', 'bytes', 'sha256')}, cap=128 * 1024, body=True)
    admission = types.ModuleType('bankstown_qt3_source_frozen_requirements')
    exec(compile(raw, row['path'], 'exec'), admission.__dict__)
    required = REQUIRED | set(admission.REQUIRED_MATERIALS)
    required |= {'scripts/ci/bankstown-qt3-native-profile-v1/' + name for name in
                 ('passive.py', 'inventory.py', 'receipt.py', 'expected349.lock')}
    required.add('scripts/ci/first-login-enrollment-native-source/profile.json')
    parent_member = 'scripts/port/arm-rust-toolchain-inputs/qtbase-successor/parent-binding.json'
    H.need(parent_member in file_rows, 'FROZEN_PARENT_SOURCE_REQUIRED')
    parent_ref = {k: file_rows[parent_member][k] for k in ('path', 'bytes', 'sha256')}
    H.need({k: parent_ref[k] for k in ('bytes', 'sha256')} ==
           dict(bytes=3972, sha256='ae78fac40449df9da2d055a39ef8431339813f3fbba9c9569c8bcd23a09b87ed'), 'FROZEN_PARENT_SOURCE_PIN')
    parent = H.decoded(H.verify_reference(parent_ref, cap=128 * 1024, body=True))
    required |= {'scripts/port/arm-rust-toolchain-inputs/' + member for member in parent['files']}
    return required


def member(value):
    H.need(type(value) is str and 0 < len(value) <= 240 and '\\' not in value, 'SOURCE_MEMBER')
    path = PurePosixPath(value)
    H.need(not path.is_absolute() and str(path) == value and len(path.parts) <= 16
           and not any(p in ('.', '..', '.git', 'work', '__pycache__') for p in path.parts)
           and all(all(c.isascii() and (c.isalnum() or c in '._+-') for c in p) for p in path.parts),
           'CLOSED_AUDIO_SOURCE_MEMBER')
    return value


def prepare_source(*, file_rows, file_rows_sha256, output):
    """Copy exactly the externally selected finite map, then emit two map aliases.

    Each row is {path,bytes,sha256,mode}, where mode selects output permissions.
    Code, policy, catalog and prospective
    inventory operands must be explicitly selected; archives for the477 provider
    stay external. The returned map pin is DATA for a later genuine Root grant.
    """
    H.need(type(file_rows) is dict and REQUIRED <= set(file_rows) and len(file_rows) + 2 <= 256,
           'COMPLETE_FINITE_AUDIO_SOURCE_SELECTION')
    H.need(H.pin(H.encoded(file_rows))['sha256'] == file_rows_sha256, 'EXTERNAL_SOURCE_ROWS_PIN')
    H.need(required_members(file_rows) <= set(file_rows), 'COMPLETE_FROZEN_AND_AUDIO_SOURCE_CLOSURE')
    out = H.ordinary(str(output))
    H.need(not out.exists(), 'FRESH_AUDIO_SOURCE_OUTPUT')
    H.need('source-map.json' not in file_rows and 'source.lock.json' not in file_rows, 'SOURCE_MAPS_ARE_OUTPUTS')
    for name in file_rows:
        member(name)
        H.need(not any(str(parent) in file_rows for parent in PurePosixPath(name).parents
                       if str(parent) != '.'), 'SOURCE_FILE_DIRECTORY_COLLISION')
    total, rows, bodies = 0, {}, {}
    for name, row in sorted(file_rows.items()):
        member(name)
        H.need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode'}
               and type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'EXACT_SOURCE_INPUT_ROW')
        path = H.ordinary(row['path'])
        H.need(not path.is_relative_to(out) and not out.is_relative_to(path), 'DISJOINT_SOURCE_OPERAND')
        body = H.verify_reference({k: row[k] for k in ('path', 'bytes', 'sha256')}, cap=64 * 1024**2, body=True)
        total += len(body)
        H.need(total <= 128 * 1024**2, 'SOURCE_TOTAL_BYTE_BOUND')
        rows[name] = dict(H.pin(body), mode=row['mode'])
        bodies[name] = body
    raw = H.encoded(dict(schema=1, kind='BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1',
        operation='bankstown-qt3-native-private-test-v1', files=rows,
        actual=dict(source=None, ref=None, run=None, job=None, image=None, profile=None,
                    executor=None, Root_final_acceptance=None)))
    H.need(total + 2 * len(raw) <= 128 * 1024**2, 'SOURCE_WITH_MAPS_BYTE_BOUND')
    out.mkdir(mode=0o755)
    identity = (out.stat().st_dev, out.stat().st_ino)
    try:
        for name, body in bodies.items():
            target = out / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(body)
            target.chmod(rows[name]['mode'])
        for name in ('source-map.json', 'source.lock.json'):
            target = out / name
            with target.open('xb') as stream:
                stream.write(raw)
            target.chmod(0o644)
    except BaseException as original:
        try:
            # Retire only this fresh inode and the finite namespace we created.
            H.need((out.stat().st_dev, out.stat().st_ino) == identity, 'SOURCE_OUTPUT_OWNERSHIP_LOST')
            allowed = set(rows) | {'source-map.json', 'source.lock.json'}
            directories = {str(parent) for n in allowed for parent in PurePosixPath(n).parents if str(parent) != '.'}
            paths = list(out.rglob('*'))
            for path in paths:
                relative, row = str(path.relative_to(out)), path.lstat()
                H.need((stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and relative in allowed)
                       or (stat.S_ISDIR(row.st_mode) and relative in directories), 'SOURCE_CLEANUP_FOREIGN_ENTRY')
            for path in sorted(paths, key=lambda p: len(p.parts), reverse=True):
                path.rmdir() if path.is_dir() else path.unlink()
            out.rmdir()
        except BaseException as cleanup:
            original.add_note('Source cleanup held: ' + str(cleanup))
        raise
    return dict(schema=1, kind='BANKSTOWN_QT3_PREPARED_SOURCE_DATA_V1',
                root=str(out), source_lock=H.pin(raw), files=len(rows), bytes=total + 2 * len(raw),
                actual_selectors=None, Root_final_acceptance=None, native_credit=False)
