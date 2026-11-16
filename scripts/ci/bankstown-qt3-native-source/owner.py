# SPDX-License-Identifier: MIT
"""One audio image -> external Root selection -> profile -> build lifetime."""
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import time
import types

HERE = Path(__file__).resolve().parent
PROFILE_MEMBER = 'scripts/ci/bankstown-qt3-native-profile-v1/profile.py'
BUILDER_MEMBER = 'scripts/port/bankstown-qt3-native-v1/builder.py'
BUILDER_PIN = dict(bytes=26504, sha256='6d5c19922091163ab612ceeceb96deef034e3274b80e2d17aa36704c87e30366')
DOCKER_BEFORE = b"argv = ['/usr/bin/docker', '--host', self.endpoint] + args"
DOCKER_AFTER = b"argv = ['/usr/bin/docker', '--host=' + self.endpoint] + args"


def local(name):
    spec = importlib.util.spec_from_file_location('bankstown_qt3_owner_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = local('handoff')


def projected_builder(source_root):
    """One invertible literal Source adaptation, with original receipts intact."""
    path = H.ordinary(str(Path(source_root) / BUILDER_MEMBER))
    raw = H.verify_reference(dict(path=str(path), **BUILDER_PIN), cap=128 * 1024, body=True)
    H.need(raw.count(DOCKER_BEFORE) == 1 and DOCKER_AFTER not in raw, 'EXACT_DOCKER_ARGV_SEAM')
    adapted = raw.replace(DOCKER_BEFORE, DOCKER_AFTER)
    H.need(adapted.replace(DOCKER_AFTER, DOCKER_BEFORE) == raw, 'INVERTIBLE_BUILDER_ADAPTATION')
    module = types.ModuleType('bankstown_qt3_literal_host_builder')
    module.__file__ = str(path)
    exec(compile(adapted, str(path), 'exec'), module.__dict__)
    return module, dict(original=H.pin(raw), projected=H.pin(adapted),
                        seam='one Docker --host=<endpoint> argument; no receipt rewriting')


def root_directory(directory, *, source_root, work):
    path = H.ordinary(str(directory))
    H.need(path.is_dir() and path != Path('/'), 'PREEXISTING_ROOT_SELECTION_DIRECTORY')
    for parent in (path, *path.parents):
        row = parent.lstat()
        H.need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
               'ROOT_CONTROLLED_SELECTION_DIRECTORY_CHAIN')
    for excluded in (Path(source_root), Path(work)):
        H.need(not path.is_relative_to(excluded) and not excluded.is_relative_to(path),
               'ROOT_SELECTION_DISJOINT_FROM_OWNER_WRITES')
    return path


def root_file(path, cap=2 * 1024**2):
    path = H.ordinary(str(path))
    before = path.lstat()
    H.need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
           and not before.st_mode & 0o022 and 0 < before.st_size <= cap, 'ROOT_DELIVERED_ORDINARY_SELECTION')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = bytearray()
        while part := os.read(fd, min(1024**2, cap + 1 - len(raw))):
            raw.extend(part)
            H.need(len(raw) <= cap, 'ROOT_SELECTION_BYTE_BOUND')
        H.need(len(raw) == before.st_size and H.identity(before) == H.identity(os.fstat(fd))
               == H.identity(path.lstat()), 'ROOT_SELECTION_CHANGED')
        return bytes(raw)
    finally:
        os.close(fd)


def await_selection(*, phase, delegation, image_raw, executor, source_root, work, expected=None):
    """External Root delivers two separate selections; this code never approves."""
    H.need(phase in ('admission', 'profile'), 'FIXED_ROOT_SELECTION_PHASE')
    selected = delegation['root_selection']
    directory = root_directory(selected['directory'], source_root=source_root, work=work)
    image = H.decoded(image_raw)
    path = directory / (image['nonce'] + '.' + phase + '.json')
    until = min(executor.deadline - 90, time.monotonic() + selected['wait_seconds'])
    while not path.exists():
        executor.live()
        H.need(time.monotonic() < until and time.time() < delegation['expires_epoch'], 'EXTERNAL_ROOT_SELECTION_NOT_DELIVERED_IN_TIME')
        time.sleep(min(.25, max(.001, until - time.monotonic())))
    executor.live()
    H.need(time.monotonic() < until, 'EXTERNAL_ROOT_SELECTION_DEADLINE')
    raw = root_file(path)
    value = H.decoded(raw)
    keys = {'schema', 'kind', 'issuer', 'approved', 'nonce', 'image_receipt_pin', 'issued_at', 'expires_at'}
    keys |= {'admission'} if phase == 'admission' else {'profile', 'profile_receipt'}
    H.need(type(value) is dict and set(value) == keys and type(value['schema']) is int
           and value['schema'] == 1 and value['kind'] == 'ROOT_DELIVERED_BANKSTOWN_QT3_' + phase.upper() + '_SELECTION_V1'
           and value['issuer'] == 'Root' and value['approved'] is True
           and value['nonce'] == image['nonce'] and value['image_receipt_pin'] == H.pin(image_raw),
           'EXACT_EXTERNALLY_DELIVERED_ROOT_SELECTION')
    now = time.time()
    H.need(type(value['issued_at']) is int and type(value['expires_at']) is int
           and 0 <= value['issued_at'] <= now < value['expires_at'] <= delegation['expires_epoch'],
           'FRESH_ROOT_SELECTION')
    for role in (('admission',) if phase == 'admission' else ('profile', 'profile_receipt')):
        reference = value[role]
        H.need(type(reference) is dict and set(reference) == {'path', 'bytes', 'sha256'}, 'ROOT_SELECTED_WHOLE_REFERENCE')
        if phase == 'admission':
            H.need(Path(reference['path']).parent == directory, 'ROOT_ADMISSION_SAME_CUSTODY_DIRECTORY')
            body = root_file(reference['path'])
            H.need(H.pin(body) == {k: reference[k] for k in ('bytes', 'sha256')}, 'ROOT_ADMISSION_PIN_DIFFERS')
        else:
            H.need(reference == expected[role], 'ROOT_PROFILE_SELECTION_DIFFERS')
            H.verify_reference(reference, cap=2 * 1024**2, deadline=until)
    return value


def load_profile(source_root, delegation):
    descriptor = delegation['programs']['profile']
    H.need(descriptor['member'] == PROFILE_MEMBER, 'FIXED_PASSIVE_PROFILE_PROGRAM')
    path = Path(source_root) / PROFILE_MEMBER
    H.verify_reference(dict(path=str(path), **{k: descriptor[k] for k in ('bytes', 'sha256')}), cap=128 * 1024)
    spec = importlib.util.spec_from_file_location('bankstown_qt3_selected_passive_profile', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    H.need(callable(module.export) and callable(module.verify), 'MAINTAINED_PROFILE_EXPORT_VERIFY_API')
    return module


def retain(source, destination):
    H.ordinary(str(source))
    H.need(source.is_file() and not source.is_symlink() and source.stat().st_size <= 64 * 1024**2,
           'BOUNDED_PUBLIC_CALLBACK_OUTPUT')
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def retained_call(call, pairs):
    """Retain first-failure DATA without replacing the producer's exception."""
    try:
        value = call()
    except BaseException as original:
        for source, destination in pairs:
            try:
                if source.exists():
                    retain(source, destination)
            except BaseException as error:
                original.add_note('Public DATA retention held: ' + type(error).__name__)
        raise
    for source, destination in pairs:
        if source.exists():
            retain(source, destination)
    return value


def run_owned_current_v3(*, delegation_raw, delegation_sha256, context, source_root,
                         inputs, executor, output, public_output):
    C, I, F = local('context'), local('image'), local('materialize')
    d = C.validate_delegation(delegation_raw, delegation_sha256)
    C.validate_context(d, context)
    C.source(d, source_root)
    H.need(d['inputs_pin'] == H.pin(H.encoded(inputs)), 'ROOT_SELECTED_AUDIO_REQUEST')
    executor.live()
    out, public = H.ordinary(str(output)), H.ordinary(str(public_output))
    H.need(out.is_dir() and not public.exists() and not public.is_relative_to(source_root), 'OWNED_FRESH_PUBLIC_OUTPUT')
    public.mkdir(mode=0o700)
    policy = C.decode(C.read(Path(source_root) / d['policy']['member'])[0])
    profile = load_profile(source_root, d)
    image_report = retained_call(lambda: I.build_qt3_image(delegation_raw=delegation_raw,
        delegation_sha256=delegation_sha256, context=context, source_root=source_root,
        inputs=inputs, executor=executor, output=out / 'image', context_program=C),
        [(out / 'image' / 'image-provisional.json', public / 'image' / 'image-provisional.json')])
    executor.live()
    image, image_path = F.materialize_image(source_root=source_root, image_report=image_report,
        delegation=d, context=context, policy=policy, catalog_reference=inputs['catalog'],
        executor=executor, output=out / 'filesystem')
    image_raw = image_path.read_bytes()
    retain(image_path, public / 'image-receipt.json')
    admission_selection = await_selection(phase='admission', delegation=d, image_raw=image_raw,
        executor=executor, source_root=source_root, work=out.parent)
    admission_ref = admission_selection['admission']
    arguments = dict(image_receipt_path=image_path, image_receipt_sha256=H.pin(image_raw)['sha256'],
        admission_path=Path(admission_ref['path']), admission_sha256=admission_ref['sha256'],
        catalog_path=Path(inputs['catalog']['path']), source_root=Path(source_root), executor=executor)
    profile_path, profile_receipt = out / 'native-profile.json', out / 'profile-receipt.json'
    profile_result = profile.export(profile_path=profile_path, output_receipt_path=profile_receipt, **arguments)
    retain(profile_path, public / 'native-profile.json')
    retain(profile_receipt, public / 'profile-receipt.json')
    expected = dict(profile=F.file_reference(profile_path, cap=2 * 1024**2, deadline=executor.deadline),
        profile_receipt=F.file_reference(profile_receipt, cap=2 * 1024**2, deadline=executor.deadline))
    profile_selection = await_selection(phase='profile', delegation=d, image_raw=image_raw,
        executor=executor, source_root=source_root, work=out.parent, expected=expected)
    profile.verify(profile_path=profile_path, profile_sha256=profile_selection['profile']['sha256'],
        output_receipt_path=profile_receipt, output_receipt_sha256=profile_selection['profile_receipt']['sha256'],
        **arguments)
    executor.live()
    admission_raw = root_file(admission_ref['path'])
    H.need(H.pin(admission_raw) == {k: admission_ref[k] for k in ('bytes', 'sha256')}, 'ROOT_TRIAL_CHANGED')
    builder, projection = projected_builder(source_root)
    trial = builder.load(Path(source_root) / 'scripts/port/bankstown-qt3-native-v1/admission.py',
                         'bankstown_qt3_selected_trial').validate_trial(
                             admission_raw, admission_ref['sha256'], now=time.time())
    H.need(time.monotonic() + trial['resources']['wall_seconds'] + 90 < executor.deadline,
           'REMAINING_OWNED_LIFETIME_MUST_COVER_PRIVATE_BUILD_AND_RETIREMENT')
    result = retained_call(lambda: builder.build_private_test(admission_raw=admission_raw,
        admission_sha256=admission_ref['sha256'], profile_path=profile_path,
        profile_sha256=profile_selection['profile']['sha256'], executor=executor,
        source_root=Path(source_root), output=out / 'build'),
        [(out / 'build' / relative, public / 'build' / relative) for relative in
         ('result.json', 'cleanup-HOLD.json', 'commands/commands.json')])
    executor.live()
    for folder, names in ((out / 'image', ('image-provisional.json',)),
                          (out / 'filesystem', ('view-DATA.json',)),
                          (out / 'build', ('result.json',))):
        for filename in names:
            retain(folder / filename, public / folder.name / filename)
    for artifact in (out / 'build' / 'artifacts').iterdir():
        if '.pkg.tar.' in artifact.name and not artifact.name.endswith('.sig'):
            retain(artifact, public / 'artifacts' / artifact.name)
    report = dict(schema=1, kind='BANKSTOWN_QT3_OWNED_PIPELINE_DATA_V1', completed=True,
        binding=context['binding'], nonce=context['nonce'], image_receipt=H.pin(image_raw),
        profile_receipt=H.pin(profile_receipt.read_bytes()), profile=profile_result['profile'],
        builder_projection=projection, private_build_status=result['status'],
        image_lifetime='EPHEMERAL_SAME_OWNED_DAEMON_UNTIL_CONTROLLER_RETIREMENT',
        legal='HELD', key_freshness='HELD', **H.FINAL)
    (public / 'pipeline-DATA.json').write_bytes(H.encoded(report))
    return report
