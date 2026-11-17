# SPDX-License-Identifier: MIT
"""Finite native-build receipt joins; no actor, signature or Root authority.

The caller authenticates the complete external Root selection and verifies its
project TEST signature/archive first. This validator requires retained original
build evidence, not a status-only native assertion. MODEL controls grant no
native credit. row.native has exactly builds[2] and comparison whole references.
"""
import hashlib
from pathlib import Path, PurePosixPath
import re
import types

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'successor_v18/payload/hosted/build_dependencies.py'
raw = BASE.read_bytes()
if len(raw) != 20374 or hashlib.sha256(raw).hexdigest() != 'ba8aaf5b89c5fa318ce1595bbb486edec270b8e0f4ea71975c42a0f70046e882':
    raise ValueError('immutable official predecessor helper changed')
D = types.ModuleType('project_native_frozen_v18'); D.__file__ = str(BASE)
exec(compile(raw, str(BASE), 'exec'), D.__dict__)
ENTRY = {'89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24',
         '9be3db97efde70536a81d1c97f9ac69893a6004ab403566f8453704a2a189d2a'}
REQUIRED = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
            'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
            'artifacts/makepkg.conf', 'artifacts/pacman.conf'}


def need(value, why):
    D.need(value, 'project native evidence: ' + why)


def reference(root, row, tick):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'whole relative receipt reference')
    D.relative(row['path']); wanted = {k: row[k] for k in ('bytes', 'sha256')}
    D.descriptor(wanted, D.MIB)
    raw = D.read(root / row['path'], D.MIB, tick)
    need(D.pin(raw) == wanted, 'whole original receipt bytes')
    return D.decode(raw)


def command(record):
    argv = record.get('command')
    need(type(argv) is list and 20 < len(argv) <= 256 and all(type(v) is str and 0 < len(v) <= 4096 for v in argv), 'finite original build argv')
    need(argv[:2] in (['docker', 'run'], ['/usr/bin/docker', 'run'])
         and argv[-3:] == ['/bin/bash', record['image_id'], '/builder-entry.sh'], 'normal immutable-image builder entry')
    for key, value in (('--platform', 'linux/arm64'), ('--network', 'none'), ('--pull=never', None),
                       ('--cap-drop=ALL', None), ('--security-opt=no-new-privileges', None), ('--read-only', None),
                       ('--pids-limit', '512'), ('--memory', '4g'), ('--memory-swap', '4g'), ('--cpus', '4'),
                       ('--name', record['clean_environment_id']), ('--rm', None), ('--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g')):
        need(argv.count(key) == 1 and (value is None or argv[argv.index(key) + 1] == value), 'unchanged finite native resource/isolation flags')
    need(argv.count('--entrypoint') == 1 and argv[argv.index('--entrypoint') + 1] == '/bin/bash'
         and argv.count('--user') == 1, 'explicit ordinary native user and entry')
    user = argv[argv.index('--user') + 1]
    need(re.fullmatch('[1-9][0-9]*:[0-9]+', user) is not None
         and not any(any(flag in arg for flag in ('--nodeps', '--ignorearch', '--skippgpcheck', '--skipinteg')) for arg in argv)
         and record.get('entry_script_sha256') in ENTRY, 'normal dependency checks and fixed reviewed entry script')
    # Refuse extra Docker switches rather than letting a later override undo
    # the retained ordinary network/capability/mount/environment contract.
    flags = {'--rm', '--pull=never', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only'}
    pairs = {'--name', '--platform', '--user', '--pids-limit', '--memory', '--memory-swap',
             '--cpus', '--network', '--tmpfs', '--entrypoint'}
    env, mounts, labels = {}, {}, set()
    index = 2
    while index < len(argv) - 2:
        option = argv[index]; index += 1
        if option in flags: continue
        need(option in pairs | {'--env', '--mount', '--label'} and index < len(argv) - 2, 'only reviewed native Docker options')
        value = argv[index]; index += 1
        if option == '--env':
            key, separator, item = value.partition('=')
            need(separator and key not in env, 'unique original builder environment'); env[key] = item
        if option == '--mount':
            parts = value.split(','); fields = {}
            for part in parts:
                key, separator, item = part.partition('=')
                need(key not in fields, 'unique mount fields'); fields[key] = item if separator else True
            destination = fields.get('dst')
            need(destination in {'/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'} and destination not in mounts
                 and fields.get('type') == 'bind' and type(fields.get('src')) is str and fields['src'].startswith('/')
                 and '..' not in Path(fields['src']).parts
                 and set(fields) == ({'type', 'src', 'dst'} if destination == '/out' else {'type', 'src', 'dst', 'readonly'})
                 and (destination == '/out' or fields['readonly'] is True), 'four exact ordinary builder mounts')
            mounts[destination] = fields
        if option == '--label':
            need(re.fullmatch(r'org\.cachy-asahi\.(?:llhttp|libgit2)-reference\.nonce=[0-9a-f]{32}', value)
                 and value not in labels, 'only owned native provider nonce label'); labels.add(value)
    need(index == len(argv) - 2 and env == {'CACHY_ASAHI_CONTAINER': '1', 'SOURCE_DATE_EPOCH': str(record['source_date_epoch'])}
         and set(mounts) == {'/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'}, 'complete original environment and mount contract')


def build(root, row, evidence, tick):
    need(type(evidence) is dict and set(evidence) == {'provenance', 'validation'}, 'original build reference pair')
    record = reference(root, evidence['provenance'], tick); report = reference(root, evidence['validation'], tick)
    folder = PurePosixPath(evidence['provenance']['path']).parent
    need(evidence['provenance']['path'].endswith('/provenance.json')
         and evidence['validation']['path'] == str(folder / 'validation.json'), 'same original build directory')
    need(record.get('status') == 'built-package-static-pass' and type(record.get('exit_code')) is int and record['exit_code'] == 0
         and record.get('mode') == 'native' and record.get('builder_host_arch') in ('aarch64', 'arm64')
         and record.get('network') == 'none' and type(record.get('image_id')) is str
         and re.fullmatch('sha256:[0-9a-f]{64}', record['image_id']) and record.get('image') == record['image_id']
         and type(record.get('source_date_epoch')) is int and record['source_date_epoch'] >= 0
         and type(record.get('clean_environment_id')) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}', record['clean_environment_id']), 'successful recorded native build, not host/emulation/status-only evidence')
    command(record)
    hashes = record.get('files'); need(type(hashes) is dict and REQUIRED <= set(hashes) and len(hashes) <= 1024, 'complete retained environment/inventory/validation evidence')
    files = {}; total = 0
    for name, digest in hashes.items():
        D.relative(name); need(D.sha(digest), 'whole evidence file hash'); raw = D.read(root / folder / name, D.INPUT_CAP, tick)
        need(D.pin(raw)['sha256'] == digest, 'retained file differs'); total += len(raw)
        need(total <= 128 * D.MIB, 'complete retained build byte bound'); files[name] = raw
    need(hashes['validation.json'] == evidence['validation']['sha256'], 'validation reference joins provenance')
    lock = files['expected-packages.lock']; inventory = D.inventory(lock)
    need(inventory and len(inventory) <= 600 and files['artifacts/packages.lock'] == lock
         and D.pin(lock)['sha256'] == record.get('expected_packages_sha256'), 'complete actual inventory equals complete selected image inventory')
    need(re.match(rb'Linux[^\n]*\baarch64\b', files['artifacts/environment.txt']) is not None, 'retained native uname identity')
    p = row['license_provenance']; prefix = PurePosixPath(p['pkgbuild']['path']).parent
    expected_inputs = {}
    for name, wanted in p['recipe_files'].items():
        D.relative(name); D.descriptor(wanted)
        relative = str(PurePosixPath(name).relative_to(prefix)); D.relative(relative)
        need(relative not in expected_inputs, 'unique full recipe-root snapshot')
        actual = D.read(root / folder / 'inputs' / relative, D.INPUT_CAP, tick)
        need(D.pin(actual) == wanted, 'whole retained recipe snapshot bytes')
        expected_inputs[relative] = wanted['sha256']
    need(record.get('recipe_inputs') == expected_inputs and expected_inputs.get('PKGBUILD') == p['pkgbuild']['sha256'], 'complete recipe inputs exactly match Root-selected project snapshot')
    snapshot = set(); inputs = root / folder / 'inputs'
    for index, path in enumerate(inputs.rglob('*')):
        need(index < 2048 and not path.is_symlink() and (path.is_file() or path.is_dir()), 'bounded ordinary complete recipe namespace')
        if path.is_file(): snapshot.add(str(path.relative_to(inputs)))
    need(snapshot == set(expected_inputs), 'no unlisted recipe snapshot operands')
    filename = row['filename']; need(record.get('artifacts') == {filename: row['archive']['sha256']}
         and D.pin(files.get('artifacts/' + filename, b'')) == row['archive'], 'same whole accepted package archive in each native build')
    need({p.name for p in (root / folder / 'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')} == {filename}, 'no unexpected native package artifacts')
    need(type(report.get('errors')) is list and report['errors'] == [] and type(report.get('artifacts')) is list and len(report['artifacts']) == 1, 'one original successful static package report')
    artifact = report['artifacts'][0]
    need(artifact.get('artifact') == filename and artifact.get('sha256') == row['archive']['sha256'] and artifact.get('errors') == [], 'same original archive report')
    metadata = artifact.get('metadata', {}); info = metadata.get('.PKGINFO', {}); buildinfo = metadata.get('.BUILDINFO', {})
    need(all(info.get(k, []) == value for k, value in row['metadata'].items())
         and buildinfo.get('pkgname') == [row['name']] and buildinfo.get('pkgver') == [row['version']]
         and buildinfo.get('format') == ['2'] and buildinfo.get('pkgarch') == ['aarch64'] and buildinfo.get('pkgbuild_sha256sum') == [p['pkgbuild']['sha256']], 'native static metadata and unchanged recipe/BUILDINFO correspondence')
    members = artifact.get('members', {}); regular = {n for n, item in row['providers'].items() if item['kind'] == 'file'}
    need(set(artifact.get('elf', {})) == regular and all(item.get('machine') == 183 and item.get('errors') == [] for item in artifact['elf'].values()), 'complete declared AArch64 provider validation')
    for name, wanted in row['providers'].items():
        item = members.get(name, {})
        actual = dict(kind='file', mode=item.get('mode'), bytes=item.get('size'), sha256=item.get('sha256')) if item.get('type') == '0' else dict(kind='symlink', mode=item.get('mode'), target=item.get('link')) if item.get('type') == '2' else None
        need(actual == wanted, 'every provider mode/hash/alias agrees with native package report')
    return record, artifact, D.pin(lock)


def validate(root, row, tick=lambda: None):
    """Return DATA joins only; the caller supplies genuine Root/TEST admission."""
    root = Path(root); evidence = row['native']
    need(type(evidence) is dict and set(evidence) == {'builds', 'comparison'}
         and type(evidence['builds']) is list and len(evidence['builds']) == 2, 'two complete distinct native build references')
    left, a, inventory = build(root, row, evidence['builds'][0], tick)
    right, b, other = build(root, row, evidence['builds'][1], tick)
    need(evidence['builds'][0]['provenance']['path'] != evidence['builds'][1]['provenance']['path']
         and left['clean_environment_id'] != right['clean_environment_id'], 'two distinct actual clean native runs')
    for key in ('image', 'image_id', 'mode', 'source_date_epoch', 'recipe_inputs', 'recipe_metadata', 'expected_packages_sha256', 'entry_script_sha256'):
        need(key in left and left[key] == right.get(key), 'identical native pair source/image/environment contract')
    need(inventory == other and a['members'] == b['members'] and a['metadata'] == b['metadata'], 'complete provider/payload/metadata native pair identity')
    comparison = reference(root, evidence['comparison'], tick)
    need(comparison.get('status') == 'contents-reproduced' and comparison.get('errors') == []
         and set(comparison.get('packages', {})) == {row['filename']}, 'original strict one-package comparison')
    flags = comparison['packages'][row['filename']]
    need(set(flags) == {'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'} and all(v is True for v in flags.values()), 'strict clean pair includes archive/BUILDINFO byte identity')
    return dict(kind='PROJECT_TEST_NATIVE_PAIR_DATA_V1', image=left['image_id'], inventory=inventory,
                builds=evidence['builds'], comparison=evidence['comparison'], archive=row['archive'],
                clean_environment_ids=[left['clean_environment_id'], right['clean_environment_id']],
                native_acceptance=False, Root_acceptance=None)
