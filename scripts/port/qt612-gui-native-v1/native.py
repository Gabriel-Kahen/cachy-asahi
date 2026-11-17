# SPDX-License-Identifier: MIT
"""Current-byte GUI18 pair consistency, never execution authentication.

validate_pair(*, first, second, comparison, recipe_root, work, binding) takes
original normal-builder records. Caller must independently select/authenticate
the WHOLE binding. Its exact keys are schema=1,
kind=QT612_GUI_NATIVE_PAIR_EXTERNAL_BINDING_V1, recipe_commit=b052...,
image=sha256:<64hex>, inventory_pin/entry_script_pin/producer_binding_pin each
{bytes,sha256}, entry_script_path=<same retained relative original entry path>,
environment_ids=[two exact IDs ending -<nonce>-1/-2], nonce=<32lowerhex>, and
source_date_epoch=<nonnegative int>. No C producer commit is guessed here.

Binding and receipt consistency cannot authenticate a native actor or Root
custody; every result keeps native_execution_authenticated/native_acceptance
false. Actual supervision and admission remain external.
"""
import importlib.util
from collections import Counter
import math
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent


def local(name):
    spec = importlib.util.spec_from_file_location('qt612_gui_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C, A = local('common'), local('archive')
MARKER = b'PASS_QT612_GUI_OFFSCREEN_WIDGETS_OPENGL_API_ONLY'
META = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
JSON_CAP = 32 * C.MIB
BINDING_KEYS = {'schema', 'kind', 'recipe_commit', 'image', 'inventory_pin', 'entry_script_pin',
                'entry_script_path', 'environment_ids', 'nonce', 'source_date_epoch', 'producer_binding_pin'}


def validate_binding(binding):
    C.need(type(binding) is dict and set(binding) == BINDING_KEYS and type(binding['schema']) is int
           and binding['schema'] == 1 and binding['kind'] == 'QT612_GUI_NATIVE_PAIR_EXTERNAL_BINDING_V1'
           and binding['recipe_commit'] == C.RECIPE_COMMIT, 'exact externally selected GUI pair binding schema')
    C.need(type(binding['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}', binding['image'])
           and type(binding['nonce']) is str and re.fullmatch('[0-9a-f]{32}', binding['nonce'])
           and type(binding['source_date_epoch']) is int and binding['source_date_epoch'] >= 0,
           'immutable image/nonce/source date binding')
    for field in ('inventory_pin', 'entry_script_pin', 'producer_binding_pin'):
        C.descriptor(binding[field], JSON_CAP)
    C.relative(binding['entry_script_path'])
    C.need(type(binding['environment_ids']) is list and len(binding['environment_ids']) == 2
           and all(type(value) is str and re.fullmatch('[a-zA-Z0-9_.-]{1,160}', value)
                   and value.endswith('-' + binding['nonce'] + '-' + str(index))
                   for index, value in enumerate(binding['environment_ids'], 1))
           and len(set(binding['environment_ids'])) == 2, 'two exact nonce-bound distinct environment IDs')


class Reader:
    def __init__(self):
        self.observed, self.references = {}, {}

    def read(self, root, name, *, expected=None, sha=None, cap=JSON_CAP, collect=True):
        C.relative(name)
        path = root / name
        before = path.lstat()
        row = dict(path=name, **(expected if expected is not None else dict(bytes=before.st_size, sha256=sha)))
        if row['sha256'] is None:
            stream, first = A.open_regular(A.canonical_path(path), cap)
            with stream:
                raw = stream.read(cap + 1)
                C.need(len(raw) <= cap and C.identity(first) == C.identity(os.fstat(stream.fileno())), 'stable bounded original JSON')
            row.update(C.pin(raw))
        raw = C.read_ref(root, row, cap, collect=collect)
        C.need(C.identity(before) == C.identity(path.lstat()), 'operand identity changed while pinning')
        self.observed[path] = C.identity(before)
        self.references[str(path)] = {key: row[key] for key in ('bytes', 'sha256')}
        return raw

    def json(self, root, name, **kwargs):
        return C.decode(self.read(root, name, **kwargs), JSON_CAP)

    def unchanged(self):
        for path, before in self.observed.items():
            C.need(C.identity(path.lstat()) == before, 'retained operand changed after inspection')


def physical_files(root):
    files, nodes = set(), 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        nodes += len(dirs) + len(names)
        C.need(nodes <= 1024 and len(files) + len(names) <= 512
               and all(stat.S_ISDIR((Path(directory)/name).lstat().st_mode) for name in dirs), 'finite ordinary evidence namespace')
        for name in names:
            path = Path(directory) / name
            C.need(stat.S_ISREG(path.lstat().st_mode), 'only ordinary retained provenance operands')
            files.add(path.relative_to(root).as_posix())
    return files


def srcinfo(raw):
    result = {}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*', line)
        C.need(match is not None, 'original SRCINFO metadata row')
        key, value = match.groups()
        result.setdefault(key, []).append(value)
    return result


def inventory(raw):
    lines = raw.decode('ascii').splitlines(keepends=True)
    C.need(lines and raw.endswith(b'\n') and lines == sorted(lines)
           and all(re.fullmatch(r'[a-z0-9][a-z0-9+_.-]* [^\s]+\n', line) for line in lines)
           and len({line.split(' ', 1)[0] for line in lines}) == len(lines), 'complete sorted unique original pacman -Q inventory')
    return [line.rstrip('\n') for line in lines]


def validation_projection(actual, report):
    C.need(report['artifact'] == C.FILENAME and report['sha256'] == actual['archive']['sha256']
           and report['status'] == 'artifact-static-pass' and report['errors'] == [], 'original normal artifact validation status')
    C.need(set(report['members']) == set(actual['archive_inventory']), 'original validation complete actual member map')
    for name, row in actual['archive_inventory'].items():
        old = report['members'][name]
        kind = {'file': '0', 'directory': '5', 'symlink': '2'}[row['type']]
        C.need(old['type'] == kind or kind == '0' and old['type'] == '\0', 'original validation member type')
        mtime = float(row['mtime']) if isinstance(row['mtime'], str) else row['mtime']
        C.need(math.isfinite(mtime), 'finite original archive mtime')
        expected = dict(type=old['type'], mode=row['mode'], uid=row['uid'], gid=row['gid'],
                        size=row.get('bytes', 0), mtime=mtime, link=row.get('target', ''), sha256=row.get('sha256'))
        C.need(old == expected, 'original validation member/current archive correspondence')
    C.need(report['metadata'] == {'.PKGINFO': actual['metadata']['PKGINFO']['fields'],
                                   '.BUILDINFO': actual['metadata']['BUILDINFO']['fields']}, 'original validation metadata/current archive correspondence')
    geometry = {name: dict(machine=183, load_segments=len(row['load_segments']), errors=[], hardware_status='NOT RUN')
                for name, row in actual['stage']['elf'].items()}
    C.need(report['elf'] == geometry, 'original validation ELF/current structural geometry correspondence')


def validate_pair(*, first, second, comparison, recipe_root, work, binding):
    validate_binding(binding)
    recipe_root, work = C.canonical_root(recipe_root), C.canonical_root(work)
    roots = [C.canonical_root(first), C.canonical_root(second)]
    C.need(roots[0] != roots[1] and not roots[0].is_relative_to(roots[1])
           and not roots[1].is_relative_to(roots[0]), 'two disjoint original build roots')
    reviewed = C.inspect_recipe(recipe_root)
    contract = reviewed['contract']
    active, upstream = contract['native_recipe_files'], contract['upstream']['archive']
    inputs = {name: row['sha256'] for name, row in active.items()} | {upstream['filename']: upstream['sha256']}
    C.need(len(active) == 14 and len(inputs) == 15, 'exact active14 plus original upstream archive build view')
    reader = Reader()
    recipe_metadata = srcinfo(reader.read(recipe_root, C.RECIPE_PATH+'/.SRCINFO', expected={k: active['.SRCINFO'][k] for k in ('bytes', 'sha256')}))
    comparison_path = A.canonical_path(comparison)
    compared = reader.json(comparison_path.parent, comparison_path.name)
    C.need(compared['status'] == 'contents-reproduced' and compared['errors'] == []
           and set(compared['packages']) == {C.FILENAME}
           and all(compared['packages'][C.FILENAME].get(field) is True for field in
                   ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal')), 'unchanged strict original four-way comparison')
    actuals, observations = [], []
    check_log = 'artifacts/' + C.FILENAME.removesuffix('.pkg.tar.xz') + '-check.log'
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/environment.txt', 'artifacts/generated.SRCINFO', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf', 'artifacts/qt612-configuration.json',
                'artifacts/qt612-source-notices.json', 'artifacts/qt612-stage-contract.json',
                'artifacts/' + C.FILENAME, check_log, binding['entry_script_path']}
    for index, root in enumerate(roots):
        record = reader.json(root, 'provenance.json')
        C.need(record['status'] == 'built-package-static-pass' and type(record['exit_code']) is int and record['exit_code'] == 0
               and record['mode'] == 'native' and record['builder_host_arch'] in ('aarch64', 'arm64')
               and record['image'] == record['image_id'] == binding['image']
               and record['clean_environment_id'] == binding['environment_ids'][index]
               and type(record['source_date_epoch']) is int and record['source_date_epoch'] == binding['source_date_epoch']
               and record['expected_packages_sha256'] == binding['inventory_pin']['sha256']
               and record['entry_script_sha256'] == binding['entry_script_pin']['sha256']
               and record['recipe_inputs'] == inputs and record['recipe_metadata'] == recipe_metadata,
               'exact successful normal build record/external binding')
        C.need(type(record['files']) is dict and required <= set(record['files']) and len(record['files']) <= 512
               and type(record['artifacts']) is dict and set(record['artifacts']) == {C.FILENAME}, 'complete retained normal/Qt receipt closure')
        snapshots = {'inputs/' + name for name in inputs}
        physical = physical_files(root)
        C.need(physical == set(record['files']) | snapshots | {'provenance.json'}, 'every retained evidence operand must remain indexed')
        C.need({name.removeprefix('artifacts/') for name in physical if name.startswith('artifacts/')
                and '.pkg.tar.' in name and not name.endswith('.sig')} == {C.FILENAME}, 'exact original single package artifact set')
        for name, digest in record['files'].items():
            C.need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'whole original provenance file hash')
            reader.read(root, name, sha=digest, cap=512*C.MIB, collect=False)
        entry = reader.read(root, binding['entry_script_path'], expected=binding['entry_script_pin'])
        C.need(C.pin(entry) == binding['entry_script_pin'], 'whole original entry bytes')
        expected = reader.read(root, 'expected-packages.lock', expected=binding['inventory_pin'])
        C.need(reader.read(root, 'artifacts/packages.lock', expected=binding['inventory_pin']) == expected, 'identical current complete image inventories')
        installed = inventory(expected)
        for name, digest in inputs.items():
            row = upstream if name == upstream['filename'] else active[name]
            reader.read(root, 'inputs/' + name, expected={key: row[key] for key in ('bytes', 'sha256')}, cap=512*C.MIB, collect=False)
        C.need(srcinfo(reader.read(root, 'artifacts/generated.SRCINFO')) == recipe_metadata, 'original generated SRCINFO equals pinned active recipe')
        environment = reader.read(root, 'artifacts/environment.txt')
        environment_lines = Counter(environment.decode().splitlines())
        C.need(re.search(rb'(?<![A-Za-z0-9_])aarch64(?![A-Za-z0-9_])', environment)
               and all(environment_lines[line] == 1 for line in installed), 'retained native environment and complete inventory text')
        build_log, check = reader.read(root, 'build.log'), reader.read(root, check_log)
        C.need(check.splitlines().count(MARKER) == 1 and check.count(MARKER) == 1
               and build_log.count(MARKER) == 1 and b'Starting check()' in build_log
               and b'Finished making:' in build_log and b'==> ERROR:' not in build_log, 'both original successful actual check logs and GUI smoke marker')
        config = reader.json(root, 'artifacts/qt612-configuration.json')
        notices = reader.json(root, 'artifacts/qt612-source-notices.json')
        stage = reader.json(root, 'artifacts/qt612-stage-contract.json')
        C.need(config == dict(status='PASS_CONFIGURED_PROFILE_ONLY', settings=contract['configuration']['settings_count'], native='NOT_ESTABLISHED')
               and notices == dict(status='PASS_QT612_SOURCE_NOTICES_ONLY', notices=173, bytes=636122), 'original GUI configuration/notices receipts')
        validation = reader.json(root, 'validation.json')
        C.need(validation['errors'] == [] and len(validation['artifacts']) == 1, 'original single-artifact validation receipt')
        actual = A.inspect_archive(root/'artifacts'/C.FILENAME, work, recipe_root)
        C.need(actual['archive']['sha256'] == record['artifacts'][C.FILENAME]
               and actual['stage'] == stage and actual['metadata']['original_builddate'] == str(binding['source_date_epoch']), 'original archive whole pin/stage/raw builddate binding')
        build_inventory = actual['metadata']['BUILDINFO']['fields'].get('installed', [])
        C.need(len(build_inventory) == len(installed) and len(set(build_inventory)) == len(installed)
               and all(type(value) is str and value.endswith(('-aarch64', '-any')) for value in build_inventory)
               and Counter(value.rsplit('-', 1)[0] for value in build_inventory)
                 == Counter(line.replace(' ', '-', 1) for line in installed),
               'original BUILDINFO complete installed inventory/image correspondence')
        validation_projection(actual, validation['artifacts'][0])
        actuals.append(actual)
        observations.append(dict(provenance_pin=reader.references[str(root/'provenance.json')],
            validation_pin=reader.references[str(root/'validation.json')],
            stage_receipt_pin=reader.references[str(root/'artifacts/qt612-stage-contract.json')],
            archive={key: actual['archive'][key] for key in ('bytes', 'sha256')}, environment_id=record['clean_environment_id']))
    first_actual, second_actual = actuals
    C.need(observations[0]['archive'] == observations[1]['archive']
           and {name: row for name, row in first_actual['archive_inventory'].items() if name not in META}
             == {name: row for name, row in second_actual['archive_inventory'].items() if name not in META}
           and first_actual['metadata']['PKGINFO']['raw'] == second_actual['metadata']['PKGINFO']['raw']
           and first_actual['metadata']['BUILDINFO']['raw'] == second_actual['metadata']['BUILDINFO']['raw'], 'current original whole archive/payload/PKGINFO/BUILDINFO strict equality')
    reader.unchanged()
    C.inspect_recipe(recipe_root)
    return dict(schema=1, kind='QT612_GUI_NATIVE_PAIR_RECEIPT_BYTES_CONSISTENT_ONLY', builds=2,
        recipe_commit=C.RECIPE_COMMIT, binding_canonical_pin=C.pin(C.encode(binding)), producer_binding_pin=binding['producer_binding_pin'],
        image=binding['image'], inventory_pin=binding['inventory_pin'], entry_script_pin=binding['entry_script_pin'],
        source_date_epoch=binding['source_date_epoch'], nonce=binding['nonce'], observations=observations,
        archive_pin=observations[0]['archive'], first_provenance_pin=observations[0]['provenance_pin'],
        second_provenance_pin=observations[1]['provenance_pin'],
        comparison_pin=reader.references[str(comparison_path)], comparison=compared,
        reopened_original_operands=len(reader.references), original_operand_pins=reader.references,
        strict_archive_payload_PKGINFO_BUILDINFO_equal=True, native_execution_authenticated=False,
        native_acceptance=False, source_acceptance=None, Root_grants=None, M2=None, installation=None,
        signature=None, dependency_transaction_acceptance=None,
        custody_limit='External binding and supervisor authenticity must be independently selected; matching receipt bytes authenticate no actor')


def no_actors(event, args):
    C.need(not event.startswith(('subprocess.', 'socket.', 'ctypes.'))
           and event not in ('os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'), 'NATIVE_PAIR_DATA_ONLY_NO_ACTORS')
