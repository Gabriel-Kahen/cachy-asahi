# SPDX-License-Identifier: MIT
"""Current-byte Qt family pair qualification; no launcher, signing or acceptance."""
import argparse
import builtins
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import types

HERE = Path(__file__).resolve().parent
COMPONENTS = ('gui_server', 'shadertools', 'svg', 'declarative', 'wayland')
JSON_CAP, FILE_CAP, ARCHIVE_CAP = 32*1024**2, 128*1024**2, 512*1024**2
PAYLOAD_CAP, NODE_CAP = 1024**3, 65536
NORMAL_PACKAGE_TOTAL = 512*1024**2
REQUEST_KIND = 'QT612_FAMILY_PAIR_QUALIFICATION_REQUEST_V1'
REQUEST_CAP = 65536
METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
_PASSIVE = 0


def need(value, reason):
    if not value:
        raise ValueError(reason)


def _local(name):
    spec = importlib.util.spec_from_file_location('qt612_family_'+name, HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def _audit(event, args):
    if _PASSIVE:
        need(not event.startswith(('subprocess.', 'socket.', 'ctypes.')) and event not in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'), 'QUALIFIER_PASSIVE_CODE_NO_ACTORS')


sys.addaudithook(_audit)


@contextmanager
def passive():
    global _PASSIVE
    _PASSIVE += 1
    try:
        yield
    finally:
        _PASSIVE -= 1


def validate_records(first, second, comparison, *, row, expected, recipe_inputs):
    """Pure MODEL seam. Record assertions alone do not establish actual execution."""
    need(type(expected) is dict and set(expected) == {'image', 'inventory_pin', 'entry_pin', 'nonce',
         'source_date_epoch', 'inventory_path'}, 'EXACT_FAMILY_PAIR_EXPECTATION')
    need(re.fullmatch('sha256:[0-9a-f]{64}', expected['image'] or '')
         and re.fullmatch('[0-9a-f]{32}', expected['nonce'] or '')
         and type(expected['source_date_epoch']) is int and expected['source_date_epoch'] >= 0,
         'IMMUTABLE_FAMILY_PAIR_EXPECTATION')
    for key in ('inventory_pin', 'entry_pin'):
        pin = expected[key]
        need(type(pin) is dict and set(pin) == {'bytes', 'sha256'} and type(pin['bytes']) is int
             and pin['bytes'] > 0 and re.fullmatch('[0-9a-f]{64}', pin['sha256']), 'EXTERNAL_FAMILY_INPUT_PIN')
    filename = row['filename']
    need(type(comparison) is dict and set(comparison) == {'status', 'errors', 'packages', 'hardware_status', 'independence_limit'}
         and comparison['status'] == 'contents-reproduced' and comparison['errors'] == []
         and comparison['hardware_status'] == 'NOT RUN'
         and comparison['independence_limit'] == 'Distinct recorded container runs; independent machine execution is not attested.'
         and set(comparison['packages']) == {filename}, 'NORMAL_FAMILY_STRICT_COMPARISON')
    flags = comparison['packages'][filename]
    need(type(flags) is dict and set(flags) == {'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'}
         and all(value is True for value in flags.values()), 'FOUR_WAY_STRICT_FAMILY_PAIR_EQUALITY')
    component = row['component']
    for number, record in enumerate((first, second), 1):
        need(record['status'] == 'built-package-static-pass' and type(record['exit_code']) is int
             and record['exit_code'] == 0 and record['mode'] == 'native' and record['network'] == 'none'
             and record['builder_host_arch'] in ('aarch64', 'arm64')
             and record['image'] == record['image_id'] == expected['image']
             and record['expected_packages_sha256'] == expected['inventory_pin']['sha256']
             and record['entry_script_sha256'] == expected['entry_pin']['sha256']
             and type(record['source_date_epoch']) is int and record['source_date_epoch'] == expected['source_date_epoch']
             and record['recipe_inputs'] == recipe_inputs and record['recipe_metadata'] == row['metadata']
             and record['clean_environment_id'] == 'cachy-qt612-family-'+expected['nonce']+'-'+component+'-'+str(number)
             and type(record['source_material']) is dict and bool(record['source_material'])
             and set(record['artifacts']) == {filename}
             and re.fullmatch('[0-9a-f]{64}', record['artifacts'][filename]), 'EXACT_FAMILY_NATIVE_BUILD_RECORD')
    need(first['source_material'] == second['source_material'] and first['artifacts'] == second['artifacts'],
         'SAME_SOURCE_MATERIAL_AND_ARCHIVE_PAIR')
    return filename


def validate_package(actual, row, recipe_inputs):
    """Exact normal package identity and dependency fields, including virtuals."""
    metadata = row['metadata']
    info = actual['metadata']['.PKGINFO']
    name = [row['package']]
    version = metadata['pkgver'][0]+'-'+metadata['pkgrel'][0]
    if metadata.get('epoch', ['0']) != ['0']:
        version = metadata['epoch'][0]+':'+version
    need(info.get('pkgname') == name and info.get('pkgver') == [version] and info.get('arch') == ['aarch64'],
         'EXACT_FAMILY_PACKAGE_IDENTITY')
    need(info.get('pkgbase') == metadata.get('pkgbase', name), 'EXACT_FAMILY_PACKAGE_FIELD_pkgbase')
    for package_key, source_key in (('depend', 'depends'), ('makedepend', 'makedepends'),
            ('checkdepend', 'checkdepends'), ('optdepend', 'optdepends'), ('provides', 'provides'),
            ('conflict', 'conflicts'), ('replaces', 'replaces'), ('backup', 'backup'), ('license', 'license')):
        # The maintained normal builder compares these as exact multisets.
        need(sorted(info.get(package_key, [])) == sorted(metadata.get(source_key, [])),
             'EXACT_FAMILY_PACKAGE_FIELD_'+package_key)
    need(not metadata.get('install') and not info.get('install') and METADATA <= set(actual['files'])
         and all(name in METADATA or name == 'usr' or name.startswith('usr/') for name in actual['members'])
         and not any(name.startswith(('usr/share/libalpm/hooks/', 'usr/lib/systemd/')) for name in actual['members']),
         'FAMILY_NO_INSTALL_SCRIPT_HOOK_OR_FOREIGN_ROOT')
    need(sum(member['size'] for member in actual['members'].values()) <= NORMAL_PACKAGE_TOTAL,
         'NORMAL_PACKAGE_EXPANDED_BYTE_CAP')
    build = actual['metadata']['.BUILDINFO']
    need(build.get('format') == ['2'] and build.get('pkgname') == name and build.get('pkgver') == [version]
         and build.get('pkgarch') == ['aarch64'] and build.get('pkgbuild_sha256sum') == [recipe_inputs['PKGBUILD']],
         'ACTUAL_PROJECTED_FAMILY_BUILDINFO')


def validate_validation(actual, report, *, row, recipe_inputs, c):
    """Match the actual current normal package() report, including its status."""
    need(type(report) is dict and set(report) == {'artifact', 'sha256', 'metadata', 'members', 'elf',
         'errors', 'review', 'status'} and report['status'] == 'artifact-static-pass' and report['errors'] == []
         and type(report['review']) is list and all(type(value) is str for value in report['review'])
         and report['artifact'] == row['filename'] and report['sha256'] == actual['archive']['sha256']
         and c.encoded(report['members']) == c.encoded(actual['members'])
         and c.encoded(report['elf']) == c.encoded(actual['geometry'])
         and c.encoded(report['metadata']) == c.encoded(actual['metadata']), 'ACTUAL_NORMAL_PACKAGE_VALIDATION_SCHEMA')
    validate_package(actual, row, recipe_inputs)


def _parent_fd(root, name):
    fd = os.dup(root)
    try:
        for part in PurePosixPath(name).parent.parts:
            if part == '.':
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def extract_payload(path, actual, destination, *, c, observed):
    """Re-read the qualified archive into a fresh private, fd-anchored stage."""
    m, f = c.M, c.F
    destination = m.ordinary(destination)
    need(not destination.exists(), 'FRESH_PRIVATE_FAMILY_STAGE')
    payload = {name: row for name, row in actual['members'].items() if name not in METADATA}
    need(0 < len(payload) <= NODE_CAP and sum(r['bytes'] for n, r in actual['files'].items() if n not in METADATA) <= PAYLOAD_CAP,
         'FINITE_FAMILY_STAGE_PAYLOAD')
    os.mkdir(destination, 0o700)
    root = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in sorted(actual['directories'], key=lambda n: (n.count('/'), n)):
            f.safe_name(name)
            parent = _parent_fd(root, name)
            try:
                os.mkdir(PurePosixPath(name).name, 0o700, dir_fd=parent)
            finally:
                os.close(parent)
        fd = os.open(m.ordinary(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as raw:
            before = os.fstat(raw.fileno())
            need(m.identity(before) == observed[str(path)], 'SAME_QUALIFIED_ARCHIVE_FOR_EXTRACTION')
            reader = f.XZReader(raw)
            seen = set()
            class BoundedInfo(tarfile.TarInfo):
                count = 0
                @classmethod
                def frombuf(cls, buf, encoding, errors):
                    item = super().frombuf(buf, encoding, errors)
                    cls.count += 1
                    need(cls.count <= 100000 and 0 <= item.size <= FILE_CAP, 'BOUNDED_SECOND_TAR_HEADER')
                    if item.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                        need(item.size <= 1024**2, 'BOUNDED_SECOND_TAR_EXTENSION')
                    return item
            with tarfile.open(fileobj=reader, mode='r|', tarinfo=BoundedInfo) as archive:
                for item in archive:
                    if item.name in ('.', './'):
                        need(item.isdir(), 'ORDINARY_FAMILY_ARCHIVE_ROOT')
                        continue
                    name = f.safe_name(item.name)
                    need(name not in seen and len(seen) < NODE_CAP and name in actual['members'], 'EXACT_SECOND_ARCHIVE_NAMESPACE')
                    seen.add(name)
                    row = actual['members'][name]
                    need((item.type.decode('ascii'), item.mode, item.uid, item.gid, item.size, item.mtime, item.linkname)
                         == tuple(row[k] for k in ('type', 'mode', 'uid', 'gid', 'size', 'mtime', 'link')),
                         'SAME_SECOND_ARCHIVE_HEADER')
                    if item.isfile():
                        digest, size = hashlib.sha256(), 0
                        parent, target = None, None
                        if name not in METADATA:
                            parent = _parent_fd(root, name)
                            target = os.open(PurePosixPath(name).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             item.mode, dir_fd=parent)
                        try:
                            with archive.extractfile(item) as stream:
                                while block := stream.read(1024**2):
                                    size += len(block)
                                    need(size <= item.size <= FILE_CAP, 'BOUNDED_SECOND_ARCHIVE_MEMBER')
                                    digest.update(block)
                                    if target is not None:
                                        remaining = memoryview(block)
                                        while remaining:
                                            wrote = os.write(target, remaining)
                                            need(wrote > 0, 'COMPLETE_PRIVATE_STAGE_WRITE')
                                            remaining = remaining[wrote:]
                            need(size == item.size and digest.hexdigest() == row['sha256'], 'EXACT_SECOND_ARCHIVE_MEMBER_BYTES')
                            if target is not None:
                                os.fchmod(target, item.mode)
                        finally:
                            if target is not None:
                                os.close(target)
                            if parent is not None:
                                os.close(parent)
            while reader.read(65536):
                pass
            need(seen == set(actual['members']) and reader.decoder.eof
                 and m.identity(before) == m.identity(os.fstat(raw.fileno())) == m.identity(path.lstat()),
                 'COMPLETE_STABLE_SECOND_ARCHIVE')
        for name, row in actual['symlinks'].items():
            parent = _parent_fd(root, name)
            try:
                os.symlink(row['target'], PurePosixPath(name).name, dir_fd=parent)
            finally:
                os.close(parent)
        for name, mode in sorted(actual['directories'].items(), key=lambda r: -r[0].count('/')):
            parent = _parent_fd(root, name)
            try:
                child = os.open(PurePosixPath(name).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    os.fchmod(child, mode)
                finally:
                    os.close(child)
            finally:
                os.close(parent)
    finally:
        os.close(root)
    return destination


def snapshot(root, *, c):
    root = c.M.ordinary(root)
    rows, pending = {}, [root]
    while pending:
        for path in pending.pop().iterdir():
            name = path.relative_to(root).as_posix()
            c.F.safe_name(name)
            info = path.lstat()
            need(len(rows) < NODE_CAP and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)),
                 'FINITE_PRIVATE_STAGE_SNAPSHOT')
            rows[name] = c.M.identity(info)
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
    return rows



def verify_extraction(root, actual, *, c, observed):
    rows = snapshot(root, c=c)
    need(set(rows) == set(actual['members'])-METADATA, 'EXACT_EXTRACTED_PAYLOAD_NAMESPACE')
    for name, descriptor in actual['files'].items():
        if name not in METADATA:
            c.M.stream(root/name, {k: descriptor[k] for k in ('bytes', 'sha256')}, observed,
                       cap=FILE_CAP, mode=descriptor['mode'])
    for name, descriptor in actual['symlinks'].items():
        path = root/name
        need(path.is_symlink() and str(path.readlink()) == descriptor['target']
             and stat.S_IMODE(path.lstat().st_mode) == descriptor['mode'], 'EXACT_EXTRACTED_PAYLOAD_LINK')
    for name, mode in actual['directories'].items():
        info = (root/name).lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode, 'EXACT_EXTRACTED_PAYLOAD_DIRECTORY')
    return rows


def require_snapshot(root, before, *, c):
    need(snapshot(root, c=c) == before, 'PRIVATE_STAGE_OR_PROOF_CHANGED_DURING_REPLAY')


def _component_source(source, mapping, component, row, *, c, observed):
    prefix = 'recipes/'+component+'/'
    rows = {name[len(prefix):]: descriptor for name, descriptor in mapping['files'].items() if name.startswith(prefix)}
    contract_name = 'contracts/'+component+'/BUILD-CONTRACT.json'
    contract_descriptor = mapping['files'][contract_name]
    need(contract_descriptor == row['contracts']['BUILD-CONTRACT.json'], 'EXACT_FROZEN_COMPONENT_CONTRACT')
    need(set(rows) == set(row['recipe_inputs']) | {'family-contract.json'}, 'EXACT_COMPONENT_SOURCE_RECIPE_NAMES')
    raw, hashes = {}, {}
    for name, descriptor in rows.items():
        c.M.member(name)
        need(descriptor['mode'] == 0o644, 'ORDINARY_COMPONENT_RECIPE_MODE')
        if name not in ('PKGBUILD', 'family-contract.json'):
            need(descriptor == row['recipe_inputs'][name], 'UNCHANGED_FROZEN_COMPONENT_HELPER')
        raw[name] = c.M.stream(source/prefix/name, {k: descriptor[k] for k in ('bytes', 'sha256')}, observed,
                               collect=True, mode=0o644, cap=FILE_CAP)
        hashes[name] = descriptor['sha256']
    original = c.M.stream(source/'inverse'/component/'PKGBUILD', {k: row['recipe_inputs']['PKGBUILD'][k]
                         for k in ('bytes', 'sha256')}, observed, collect=True, mode=0o644)
    need(raw['PKGBUILD'] == c.project_pkgbuild(original, component), 'EXACT_FAMILY_CHECK_MARKER_PROJECTION')
    contract_raw = c.M.stream(source/contract_name, {k: contract_descriptor[k] for k in ('bytes', 'sha256')},
                             observed, collect=True, mode=0o644)
    need(raw['family-contract.json'] == contract_raw, 'EXACT_FAMILY_CONTRACT_ALIAS')
    return raw, hashes, c.M.decode(contract_raw)


def _checker_modules(raw, root, *, component, row):
    """Local source/elf imports resolve only to held, already-pin-verified bytes."""
    modules = {}
    ordinary_import = builtins.__import__
    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in ('source', 'elf'):
            return load(name)
        return ordinary_import(name, globals, locals, fromlist, level)
    def load(name):
        filename = name+'.py'
        need(name in ('source', 'elf', 'check_stage', 'reflection') and filename in raw, 'PINNED_LOCAL_STAGE_IMPORT')
        if name not in modules:
            value = types.ModuleType('qt612_family_'+component+'_'+name)
            value.__file__ = str(root/filename)
            value.__dict__['__builtins__'] = dict(vars(builtins), __import__=local_import)
            modules[name] = value
            with passive():
                exec(compile(raw[filename], value.__file__, 'exec'), value.__dict__)
        return modules[name]
    source_module = load('source')
    need(source_module.PACKAGE == row['package'], 'EXACT_PINNED_STAGE_PACKAGE')
    return load, source_module


def _notice_receipt(actual, row, raw, *, component, c):
    policy = c.M.decode(raw['source-notices.json'])
    need(set(policy) == {'schema_version', 'source_notices'} and policy['schema_version'] == 1
         and type(policy['source_notices']) is dict and 0 < len(policy['source_notices']) <= 512, 'FIXED_COMPONENT_NOTICE_POLICY')
    prefix = 'usr/share/licenses/'+row['package']+'/source/'
    found = {name[len(prefix):]: descriptor for name, descriptor in actual['files'].items() if name.startswith(prefix)}
    need({name: descriptor['sha256'] for name, descriptor in found.items()} == policy['source_notices']
         and not any(name.startswith(prefix) for name in actual['symlinks']), 'WHOLE_COMPONENT_ARCHIVE_NOTICE_BYTES')
    count, total = len(found), sum(r['bytes'] for r in found.values())
    if component == 'shadertools':
        vendors = c.M.decode(raw['vendored-inputs.lock.json'])['files']
        return dict(status='SOURCE_NOTICES_AND_VENDORS_VERIFIED', notices=count,
                    vendors=dict(files=len(vendors), bytes=sum(r['bytes'] for r in vendors.values())))
    if component == 'declarative':
        return dict(status='SOURCE_NOTICES_VERIFIED', notices=count)
    return dict(status='PASS_QT612_SOURCE_NOTICES_ONLY', notices=count, bytes=total)




def require_serial_cache(raw):
    """Check the real cache, including the type and duplicate-key boundary."""
    need(type(raw) is bytes, 'REAL_SERIAL_AUTOGEN_CACHE_BYTES')
    rows = [line for line in raw.splitlines()
            if re.match(rb'^[ \t]*"?CMAKE_AUTOGEN_PARALLEL"?:', line)]
    need(rows == [b'CMAKE_AUTOGEN_PARALLEL:STRING=1'], 'EXACT_ONE_SERIAL_AUTOGEN_CACHE_SETTING')


def finalize_result(result, *, expected, provenance_raw, observed, c):
    """Keep original record bytes and all observed operands bound through return."""
    need(type(provenance_raw) is list and len(provenance_raw) == 2
         and all(type(raw) is bytes and 0 < len(raw) <= JSON_CAP for raw in provenance_raw),
         'TWO_WHOLE_ORIGINAL_PROVENANCE_RECORDS')
    result = dict(result, nonce=expected['nonce'], entry_pin=dict(expected['entry_pin']),
        source_date_epoch=expected['source_date_epoch'], provenance_pins={
            'build-'+str(number): c.pin(raw) for number, raw in enumerate(provenance_raw, 1)})
    c.M.unchanged(observed)
    return result


def source_material_binding(source, mapping, component, row, recipe_inputs, *, c, observed):
    """Reconstruct the maintained offline source receipt from selected Source bytes."""
    prefix = 'materials/'+component+'/'
    def selected(name):
        path = prefix+name
        descriptor = mapping['files'][path]
        return c.M.stream(source/path, {k:descriptor[k] for k in ('bytes','sha256')}, observed,
                          collect=True, mode=0o644)
    plan_raw, catalog_raw = selected('plan.json'), selected('catalog.json')
    plan, catalog = c.M.decode(plan_raw), c.M.decode(catalog_raw)
    catalog_sha = c.pin(catalog_raw)['sha256']
    need(plan['catalog_sha256'] == catalog_sha and plan['recipe_inputs'] == recipe_inputs
         and len(catalog['sources']) == len(plan['sources']) == 1, 'EXACT_FAMILY_OFFLINE_PLAN_CATALOG')
    item = catalog['sources'][0]
    archive = row['archive']
    need(item['revision'] == row['upstream_revision'] and item['url'] == archive['url']
         and plan['sources'] == [dict(source=archive['url'], id=component, revision=item['revision'])]
         and item['material'] == dict(id=component, path=archive['filename'], bytes=archive['bytes'],sha256=archive['sha256']),
         'EXACT_REVIEWED_FAMILY_UPSTREAM_ARCHIVE')
    result = dict(schema_version=1,purpose='offline-build-sources',plan_sha256=c.pin(plan_raw)['sha256'],
                  catalog_sha256=catalog_sha,recipe_inputs=recipe_inputs,
                  sources=[dict(filename=archive['filename'],source=archive['url'],record=item)],
                  legal_acceptance=False,source_completeness_accepted=False)
    files = {'source-material/source-plan.json':c.pin(plan_raw)['sha256'],
             'source-material/source-catalog.json':catalog_sha,
             'source-material/selection.json':c.pin(c.encoded(result))['sha256'],
             'source-material/srcdest/'+archive['filename']:archive['sha256']}
    receipt = dict(schema_version=1,purpose='source-cache-receipt',inputs_sha256=catalog_sha,source=item,
                   object_path='objects/'+archive['sha256'],legal_acceptance=False,source_completeness_accepted=False)
    files['source-material/receipts/'+component+'.json'] = c.pin(c.encoded(receipt))['sha256']
    for notice in item['license_evidence']:
        raw = selected(notice['path'])
        need(c.pin(raw)=={k:notice[k] for k in ('bytes','sha256')},'EXACT_FAMILY_OFFLINE_NOTICE_BYTES')
        files['source-material/notices/'+notice['sha256']] = notice['sha256']
    return result, files


def qualify_pair(first, second, comparison, *, source, source_map_sha256, component, expected, work):
    c, proof = _local('common'), _local('proof')
    m, f = c.M, c.F
    need(component in COMPONENTS, 'EXACT_FAMILY_COMPONENT')
    source, work = m.ordinary(source), m.ordinary(work)
    roots = [m.ordinary(first), m.ordinary(second)]
    need(roots[0] != roots[1] and not roots[0].is_relative_to(roots[1]) and not roots[1].is_relative_to(roots[0])
         and not work.exists() and work.parent.is_dir()
         and all(not work.is_relative_to(p) and not p.is_relative_to(work) for p in (*roots, source)),
         'FRESH_DISJOINT_FAMILY_PAIR_WORK')
    mapping = c.read_source(source, source_map_sha256)
    observed = {}
    m.stream(source/'source-map.json', dict(bytes=(source/'source-map.json').lstat().st_size, sha256=source_map_sha256), observed)
    row = dict(c.load_lock()['components'][component], component=component)
    raw, recipe_inputs, contract = _component_source(source, mapping, component, row, c=c, observed=observed)
    source_material, source_files = source_material_binding(source,mapping,component,row,recipe_inputs,c=c,observed=observed)
    recipe_root = source/'recipes'/component
    contract_path = source/'contracts'/component/'BUILD-CONTRACT.json'
    notices_path = recipe_root/'source-notices.json'
    def read(path, cap=JSON_CAP):
        return m.stream(path, None, observed, collect=True, cap=cap)
    inventory = m.stream(m.ordinary(expected['inventory_path']), expected['inventory_pin'], observed, collect=True)
    lines = inventory.decode('ascii').splitlines(keepends=True)
    need(lines and lines == sorted(lines) and all(re.fullmatch(r'[a-z0-9][a-z0-9+_.-]* [^\s]+\n', line) for line in lines)
         and len({line.split(' ', 1)[0] for line in lines}) == len(lines), 'EXACT_EXTERNAL_PACKAGE_INVENTORY')
    provenance_raw = [read(root/'provenance.json') for root in roots]
    records = [m.decode(raw) for raw in provenance_raw]
    comparison_raw = read(m.ordinary(comparison))
    comparison_value = m.decode(comparison_raw)
    filename = validate_records(*records, comparison_value, row=row, expected=expected, recipe_inputs=recipe_inputs)
    loader, source_module = _checker_modules(raw, recipe_root, component=component, row=row)
    os.mkdir(work, 0o700)
    observations = []
    check_log = 'artifacts/'+filename.removesuffix('.pkg.tar.xz')+'-check.log'
    for number, (root, record) in enumerate(zip(roots, records), 1):
        need(record['source_material'] == source_material
             and {name:value for name,value in record['files'].items() if name.startswith('source-material/')} == source_files,
             'ORIGINAL_FAMILY_OFFLINE_MATERIAL_RECEIPT')
        required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
            'artifacts/environment.txt', 'artifacts/generated.SRCINFO', 'artifacts/config.sha256',
            'artifacts/makepkg.conf', 'artifacts/pacman.conf', 'artifacts/family-stage.json',
            'artifacts/family-configuration.json', 'artifacts/family-notices.json',
            'artifacts/family-dependencies.missing', 'artifacts/family-build-proof.json', check_log}
        if component == 'shadertools':
            required.add('artifacts/family-shader-smoke.json')
        need(type(record['files']) is dict and required <= set(record['files']) and len(record['files']) <= 4096,
             'COMPLETE_CURRENT_FAMILY_RECEIPT_CLOSURE')
        artifact_paths = list((root/'artifacts').iterdir())
        need(len(artifact_paths) <= 4096 and all(not p.is_symlink() and p.is_file() for p in artifact_paths)
             and {p.name for p in artifact_paths if '.pkg.tar.' in p.name and not p.name.endswith('.sig')} == {filename},
             'ONE_CURRENT_FAMILY_PACKAGE_ARCHIVE')
        total = 0
        for relative, checksum in record['files'].items():
            m.member(relative)
            need(re.fullmatch('[0-9a-f]{64}', checksum), 'WHOLE_FAMILY_PROVENANCE_DIGEST')
            sink = f.HashSink()
            m.stream(root/relative, None, observed, cap=ARCHIVE_CAP if relative == 'artifacts/'+filename else FILE_CAP, target=sink)
            got = sink.result()
            total += got['bytes']
            need(got['sha256'] == checksum and total <= 3*1024**3, 'CURRENT_WHOLE_FAMILY_PROVENANCE_OPERAND')
        for relative in ('expected-packages.lock', 'artifacts/packages.lock'):
            need(read(root/relative) == inventory, 'CURRENT_FAMILY_EXACT_INVENTORY')
        need(read(root/'artifacts/family-dependencies.missing') == b'', 'NORMAL_FAMILY_DEPENDENCIES_MUST_SUCCEED')
        need(m.srcinfo(read(root/'artifacts/generated.SRCINFO')) == row['metadata'], 'NORMAL_GENERATED_FAMILY_SRCINFO')
        need(re.search(rb'(?<![A-Za-z0-9_])aarch64(?![A-Za-z0-9_])', read(root/'artifacts/environment.txt')),
             'CURRENT_FAMILY_AARCH64_UNAME_RECEIPT')
        need(snapshot(root/'inputs', c=c).keys() == recipe_inputs.keys(), 'EXACT_FAMILY_RECIPE_SNAPSHOT_NAMESPACE')
        for name, checksum in recipe_inputs.items():
            descriptor = mapping['files']['recipes/'+component+'/'+name]
            m.stream(root/'inputs'/name, {k: descriptor[k] for k in ('bytes', 'sha256')}, observed, mode=0o644)
        log = read(root/check_log, FILE_CAP)
        for marker in (row['marker'], row.get('original_marker')):
            if marker:
                marker = marker.encode()
                need(log.splitlines().count(marker) == 1 and log.count(marker) == 1, 'ONE_EXACT_NORMAL_FAMILY_CHECK_MARKER')
        validation = m.decode(read(root/'validation.json'))
        need(type(validation) is dict and set(validation) == {'errors', 'artifacts'} and validation['errors'] == []
             and type(validation['artifacts']) is list and len(validation['artifacts']) == 1, 'ONE_FAMILY_PACKAGE_VALIDATION')
        report = validation['artifacts'][0]
        actual = f.inspect_archive(root/'artifacts'/filename, io=m, observed=observed)
        validate_validation(actual, report, row=row, recipe_inputs=recipe_inputs, c=c)
        need(actual['archive']['sha256'] == record['artifacts'][filename], 'ACTUAL_CURRENT_FAMILY_ARCHIVE_VALIDATION')
        stage_root = extract_payload(root/'artifacts'/filename, actual, work/('stage-'+str(number)), c=c, observed=observed)
        need(set(snapshot(stage_root, c=c)) == set(actual['members']) - METADATA, 'EXACT_PRIVATE_EXTRACTED_NAMESPACE')
        for name, descriptor in actual['files'].items():
            if name not in METADATA:
                m.stream(stage_root/name, {k: descriptor[k] for k in ('bytes', 'sha256')}, observed,
                         cap=FILE_CAP, mode=descriptor['mode'])
        for name, descriptor in actual['symlinks'].items():
            need(str((stage_root/name).readlink()) == descriptor['target'], 'EXACT_PRIVATE_EXTRACTED_ALIAS')
        stage_before = verify_extraction(stage_root, actual, c=c, observed=observed)
        checker = loader('check_stage')
        with passive():
            if component in ('shadertools', 'declarative'):
                stage = checker.check(stage_root, contract_path, notices_path)
            elif component == 'wayland':
                stage = checker.inspect(stage_root, license_manifest=notices_path,
                                        dependency_policy=recipe_root/'dependency-inputs.json')
            else:
                stage = checker.inspect(stage_root, arch='aarch64', license_manifest=notices_path)
        retained_stage = m.decode(read(root/'artifacts/family-stage.json'))
        need(c.encoded(stage) == c.encoded(retained_stage), 'GENUINE_STAGE_REPLAY_EQUALS_RETAINED_RECEIPT')
        envelope_raw = read(root/'artifacts/family-build-proof.json', proof.MAX_JSON)
        envelope = proof.decode(envelope_raw)
        proof_root = proof.unpack(envelope, output=work/('proof-'+str(number)), component=component, contract=contract)
        proof_before = snapshot(proof_root, c=c)
        cache_descriptor = envelope['files']['build/CMakeCache.txt']
        cache_raw = m.stream(proof_root/'build/CMakeCache.txt',
            {key: cache_descriptor[key] for key in ('bytes', 'sha256')}, observed,
            collect=True, cap=proof.MAX_BYTES, mode=0o644)
        require_serial_cache(cache_raw)
        with passive():
            if component == 'shadertools':
                configured = source_module.configuration(proof_root/'build')
            elif component == 'declarative':
                configured = source_module.configuration(proof_root/'build', contract_path)
            else:
                configured = source_module.configuration(proof_root/'build', recipe_root/'configure.cmake')
        need(c.encoded(configured) == c.encoded(m.decode(read(root/'artifacts/family-configuration.json'))),
             'GENUINE_CONFIGURATION_REPLAY_EQUALS_RETAINED_RECEIPT')
        notices = _notice_receipt(actual, row, raw, component=component, c=c)
        need(c.encoded(notices) == c.encoded(m.decode(read(root/'artifacts/family-notices.json'))),
             'CURRENT_ARCHIVE_NOTICE_RECEIPT_BINDING')
        if component == 'shadertools':
            with passive():
                reflected = loader('reflection').check(proof_root/'shader')
            need(c.encoded(reflected) == c.encoded(m.decode(read(root/'artifacts/family-shader-smoke.json'))),
                 'GENUINE_SHADER_REFLECTION_REPLAY')
        require_snapshot(stage_root, stage_before, c=c)
        require_snapshot(proof_root, proof_before, c=c)
        observations.append(dict(archive=actual['archive'], stage=c.pin(c.encoded(stage)),
            configuration=c.pin(c.encoded(configured)), notices=c.pin(c.encoded(notices)),
            check_log=c.pin(log), build_proof=c.pin(envelope_raw), source_notices=len(notices.get('source_notices', {}))
            if 'source_notices' in notices else notices['notices']))
    # Raw logs/proof may contain distinct build paths. Their own pins stay bound
    # per attempt; semantic stage/config/notices and exact package bytes must match.
    for key in ('archive', 'stage', 'configuration', 'notices'):
        need(observations[0][key] == observations[1][key], 'EXACT_FAMILY_PAIR_POSTCONDITION_'+key)
    result = dict(schema=1, status='PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY', component=component,
        recipe_commit=row['commit'], filename=filename, source_map_sha256=source_map_sha256,
        image=expected['image'], inventory_pin=expected['inventory_pin'], observations=observations,
        comparison=c.pin(comparison_raw), native_acceptance=None, GPG='NOT_RUN', M2='NOT_RUN', Root_acceptance=None)
    return finalize_result(result, expected=expected, provenance_raw=provenance_raw, observed=observed, c=c)


def validate_request(value):
    need(type(value) is dict and set(value) == {'schema', 'kind', 'first', 'second', 'comparison',
         'source', 'source_map_sha256', 'component', 'expected', 'work'} and type(value['schema']) is int
         and value['schema'] == 1 and value['kind'] == REQUEST_KIND and value['component'] in COMPONENTS,
         'EXACT_PASSIVE_QUALIFICATION_REQUEST')
    need(type(value['source_map_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['source_map_sha256']),
         'EXTERNAL_QUALIFICATION_SOURCE_MAP_PIN')
    expected = value['expected']
    need(type(expected) is dict and set(expected) == {'image', 'inventory_pin', 'entry_pin', 'nonce',
         'source_date_epoch', 'inventory_path'}, 'EXACT_FAMILY_PAIR_EXPECTATION')
    for name, path in [(key, value[key]) for key in ('first', 'second', 'comparison', 'source', 'work')]+[
            ('inventory_path', expected['inventory_path'])]:
        need(type(path) is str and 0 < len(path) <= 4096 and Path(path).is_absolute()
             and '..' not in Path(path).parts and all(ord(ch) >= 32 and ord(ch) != 127 for ch in path),
             'ABSOLUTE_QUALIFICATION_REQUEST_PATH_'+name)
    need(type(expected['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}', expected['image'])
         and type(expected['nonce']) is str and re.fullmatch('[0-9a-f]{32}', expected['nonce'])
         and type(expected['source_date_epoch']) is int and expected['source_date_epoch'] >= 0,
         'IMMUTABLE_FAMILY_PAIR_EXPECTATION')
    for key in ('inventory_pin', 'entry_pin'):
        descriptor = expected[key]
        need(type(descriptor) is dict and set(descriptor) == {'bytes', 'sha256'} and type(descriptor['bytes']) is int
             and descriptor['bytes'] > 0 and type(descriptor['sha256']) is str
             and re.fullmatch('[0-9a-f]{64}', descriptor['sha256']), 'EXTERNAL_FAMILY_INPUT_PIN')
    return {name: value[name] for name in ('first', 'second', 'comparison', 'source', 'source_map_sha256',
                                         'component', 'expected', 'work')}


def run_request(path, sha256):
    c = _local('common')
    need(type(sha256) is str and re.fullmatch('[0-9a-f]{64}', sha256), 'EXTERNAL_QUALIFICATION_REQUEST_PIN')
    path, observed = c.M.ordinary(path), {}
    descriptor = dict(bytes=path.lstat().st_size, sha256=sha256)
    raw = c.M.stream(path, descriptor, observed, collect=True, cap=REQUEST_CAP)
    request = validate_request(c.M.decode(raw))
    result = qualify_pair(**request)
    c.M.unchanged(observed)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args(argv)
    c = _local('common')
    sys.addaudithook(c.M.fence)
    result = run_request(args.request, args.request_sha256)
    print(c.encoded(result).decode(), end='')


if __name__ == '__main__':
    main()
