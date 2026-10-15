#!/usr/bin/env python3
"""Freeze a separate development source packet; preflight never executes stages."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile

PURPOSE = 'frozen-development-only-native-arm-source-packet'
INITIAL = 'scripts/ci/integration.lock.json'
LOCK = 'scripts/ci/development/packet.lock.json'
INITIAL_PURPOSE = 'frozen-development-only-native-integration'
ROOTS = ('scripts', 'tests', 'packages', 'examples')
INITIAL_FILES = ('LICENSE', 'AGENTS.md', 'README.md', '.github/workflows/native-arm-build.yml')
WORKFLOW = '.github/workflows/native-arm-development.yml'
EXTRA_ROOTS = ('scripts/experiments', 'scripts/virtual', 'scripts/client')
DEVELOPMENT = 'scripts/ci/development'
KSM = 'packages/tools/cachy-asahi-ksmctl'
KSM_FILES = {'.SRCINFO', 'LICENSE', 'NOTICE', 'PKGBUILD', 'README.md', 'adaptation.patch',
             'cachy-asahi-ksmctl', 'check-source.py', 'management-policy.md', 'native-stage.md',
             'policy.py', 'source-provenance.json', 'test_ksmctl.py', 'test_policy.py', 'upstream-ksmctl'}
PINS = {INITIAL, 'scripts/ci/inputs.lock.json', 'scripts/ci/recipes.lock.json',
        'scripts/experiments/stage.lock.json', 'scripts/virtual/tooling.lock.json',
        'scripts/virtual/tooling-audit.json', 'manifests/reviewed/ksmctl.json'}
COMPOSITION = 'repository-svg'
INSTALLER_COMPOSITION = 'installer-preflight'
P0_OVERLAY_ROWS = {'scripts/ci/native_arm.py': {'mode': 420, 'sha256': '14de79257ed432fc851299682cec3ab197a4f5a208058aea950ca7e6c98b4b80'}, 'scripts/ci/integration.py': {'mode': 420, 'sha256': 'e448e2074ccca91d49fd07c115b9caa341efccebb3326f826b9eb0bc342ce9d4'}}
ZSH_COMPOSITION = 'repository-svg-zsh'
ZSH_CONTRACT = 'manifests/reviewed/zsh-native-addon.json'
ZSH_EXTRA = frozenset(('scripts/ci/development/zsh_addon.py', 'scripts/ci/development/test_zsh_addon.py',
    'scripts/ci/development/zsh_session.py', 'scripts/ci/development/test_zsh_session.py', ZSH_CONTRACT))
COMPOSED_MODES = (COMPOSITION, INSTALLER_COMPOSITION, ZSH_COMPOSITION)
INSTALLER_EXTRA = frozenset(('scripts/ci/development/p0_ci.py', 'scripts/install/local_transaction.py', 'scripts/install/native_arm_trial.py', 'scripts/install/native_preflight.py', 'scripts/install/p0_entry.py', 'scripts/ci/development/p0_native_arm.py', 'scripts/ci/development/p0_integration.py', 'scripts/install/test_local_transaction.py', 'scripts/install/test_native_arm_trial.py', 'scripts/install/test_native_preflight.py', 'scripts/port/kernel-native-job/runtime.py'))
GENERIC_POLICY = 'manifests/reviewed/repository-generic-policy.json'
COMPOSED_EXTRA = frozenset('''
.github/workflows/native-arm-development.yml
manifests/reviewed/ksmctl.json
manifests/reviewed/repository-generic-policy.json
packages/shells/cachy-asahi-zsh-autosuggestions/.SRCINFO
packages/shells/cachy-asahi-zsh-autosuggestions/LICENSE.project
packages/shells/cachy-asahi-zsh-autosuggestions/LICENSE.upstream
packages/shells/cachy-asahi-zsh-autosuggestions/NOTICE
packages/shells/cachy-asahi-zsh-autosuggestions/PKGBUILD
packages/shells/cachy-asahi-zsh-autosuggestions/README.md
packages/shells/cachy-asahi-zsh-autosuggestions/check-module.py
packages/shells/cachy-asahi-zsh-autosuggestions/integration-proposal.json
packages/shells/cachy-asahi-zsh-autosuggestions/opt-in.zsh
packages/shells/cachy-asahi-zsh-autosuggestions/source-provenance.json
packages/shells/cachy-asahi-zsh-autosuggestions/usage.md
packages/shells/cachy-asahi-zsh-autosuggestions/zsh-autosuggestions.zsh
packages/tools/cachy-asahi-ksmctl/.SRCINFO
packages/tools/cachy-asahi-ksmctl/LICENSE
packages/tools/cachy-asahi-ksmctl/NOTICE
packages/tools/cachy-asahi-ksmctl/PKGBUILD
packages/tools/cachy-asahi-ksmctl/README.md
packages/tools/cachy-asahi-ksmctl/adaptation.patch
packages/tools/cachy-asahi-ksmctl/cachy-asahi-ksmctl
packages/tools/cachy-asahi-ksmctl/check-source.py
packages/tools/cachy-asahi-ksmctl/management-policy.md
packages/tools/cachy-asahi-ksmctl/native-stage.md
packages/tools/cachy-asahi-ksmctl/policy.py
packages/tools/cachy-asahi-ksmctl/source-provenance.json
packages/tools/cachy-asahi-ksmctl/test_ksmctl.py
packages/tools/cachy-asahi-ksmctl/test_policy.py
packages/tools/cachy-asahi-ksmctl/upstream-ksmctl
scripts/ci/development/base_stages.py
scripts/ci/development/common.py
scripts/ci/development/controller.py
scripts/ci/development/initial_artifacts.py
scripts/ci/development/packet.py
scripts/ci/development/repository_authority.py
scripts/ci/development/repository_handoff.py
scripts/ci/development/test_base_stages.py
scripts/ci/development/test_common.py
scripts/ci/development/test_controller.py
scripts/ci/development/test_initial_artifacts.py
scripts/ci/development/test_packet.py
scripts/ci/development/test_repository_authority.py
scripts/ci/development/test_repository_handoff.py
scripts/ci/development/test_virtual_stage.py
scripts/ci/development/virtual_stage.py
scripts/ci/integration.lock.json
scripts/client/client.py
scripts/client/stage.py
scripts/client/test_client.py
scripts/client/test_stage.py
scripts/experiments/arm_c01.py
scripts/experiments/corpus.py
scripts/experiments/stage.lock.json
scripts/experiments/stage.py
scripts/experiments/test_arm_c01.py
scripts/experiments/test_corpus.py
scripts/experiments/test_stage.py
scripts/port/refreshed-desktop/proposed-builder-inventory.lock
scripts/port/repository-client-native/base.py
scripts/port/repository-client-native/common.py
scripts/port/repository-client-native/crypto.py
scripts/port/repository-client-native/entry.py
scripts/port/repository-client-native/orchestrator.py
scripts/port/repository-client-native/provenance.py
scripts/port/repository-client-native/review.lock.json
scripts/port/repository-client-native/source-map.json
scripts/port/repository-client-native/worker.py
scripts/port/repository-client-phase-stage/adapter.py
scripts/port/repository-client-phase-stage/dependencies.py
scripts/port/repository-client-phase-stage/entry.py
scripts/port/repository-client-phase-stage/gate.py
scripts/port/repository-client-phase-stage/phases.py
scripts/port/repository-client-phase-stage/review.lock.json
scripts/port/repository-client-phase-stage/source-map.json
scripts/port/repository-client-stage/adapter.py
scripts/port/repository-client-stage/gate.py
scripts/port/repository-native-handoff/broker.py
scripts/port/repository-native-handoff/capture.py
scripts/port/repository-native-handoff/entry.py
scripts/port/repository-native-handoff/launch.py
scripts/port/repository-native-handoff/producer.py
scripts/port/repository-native-handoff/source-map.json
scripts/port/repository-native-handoff/supervisor.py
scripts/port/repository-native-handoff/transport.py
scripts/virtual/audit_tooling.py
scripts/virtual/common.py
scripts/virtual/controller.py
scripts/virtual/gbm_probe.c
scripts/virtual/guest.py
scripts/virtual/image_decode_probe.c
scripts/virtual/image_decode_report.py
scripts/virtual/prepare.py
scripts/virtual/run.py
scripts/virtual/test_controller.py
scripts/virtual/test_image_decode_probe.py
scripts/virtual/test_virtual.py
scripts/virtual/tooling-audit.json
scripts/virtual/tooling.lock.json
'''.split())
COMPOSED_MAPS = {
    'scripts/port/repository-native-handoff/source-map.json':'scripts/port/repository-native-handoff',
    'scripts/port/repository-client-native/source-map.json':'scripts/port/repository-client-native',
    'scripts/port/repository-client-phase-stage/source-map.json':'scripts/port/repository-client-phase-stage',
}
COMPOSED_PINS = PINS | set(COMPOSED_MAPS) | {GENERIC_POLICY,
    'scripts/port/repository-client-phase-stage/dependencies.py'}
FILE_LIMIT = 8 * 1024**2
TOTAL_LIMIT = 64 * 1024**2
PATH_LIMIT = 20000


class PacketError(ValueError):
    """Stable refusal code without source contents, private paths or hashes."""


def need(condition, code):
    if not condition:
        raise PacketError(code)


def pin(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'full-sha256-required')
    return value


def relative(name):
    need(isinstance(name, str) and name and not name.startswith('/') and '\\' not in name and
         all(ord(c) >= 32 for c in name) and all(p not in ('', '.', '..') for p in name.split('/')), 'unsafe-source-path')
    path = PurePosixPath(name)
    need(not any(p.lower() in {'.git', '.env', '.gnupg', 'private-keys-v1.d'} for p in path.parts), 'private-source-path')
    return path


def source_stat(value):
    need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, 'singly-linked-source-required')
    need(stat.S_IMODE(value.st_mode) in (0o644, 0o755) and value.st_size <= FILE_LIMIT, 'source-mode-or-size-refused')


def regular(path):
    try:
        need(not any(parent.is_symlink() for parent in (path, *path.parents)), 'symlink-source-refused')
        value = path.lstat()
        source_stat(value)
        return value
    except OSError:
        raise PacketError('source-unavailable') from None


def read(path):
    before = regular(path)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        opened = os.fstat(descriptor); source_stat(opened)
        need(identity(before) == identity(opened), 'source-replaced-before-read')
        stream = os.fdopen(descriptor, 'rb'); descriptor = None
        with stream:
            data = stream.read(FILE_LIMIT + 1)
            final_fd = os.fstat(stream.fileno()); source_stat(final_fd)
            need(identity(opened) == identity(final_fd), 'source-changed-during-read')
    except OSError:
        raise PacketError('source-read-failed') from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise PacketError('source-descriptor-close-failed') from None
    after = regular(path)
    need(identity(before) == identity(after) == identity(final_fd) and len(data) == after.st_size, 'source-changed-during-read')
    return data, {'sha256': hashlib.sha256(data).hexdigest(), 'mode': stat.S_IMODE(after.st_mode)}


def decode(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    def invalid(value):
        raise PacketError('nonfinite-json')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, ValueError, RecursionError):
        raise PacketError('invalid-source-json') from None


def pinned(path, digest):
    data, row = read(path)
    need(row['sha256'] == pin(digest), 'metadata-pin-drift')
    return decode(data)


def validate_map(value):
    need(isinstance(value, dict) and value and len(value) <= PATH_LIMIT, 'source-map-required')
    for name, row in value.items():
        relative(name)
        need(isinstance(row, dict) and set(row) == {'sha256', 'mode'}, 'invalid-source-row')
        pin(row['sha256'])
        need(type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'invalid-source-mode')


def validate_pins(pins):
    need(isinstance(pins, dict) and set(pins) == PINS, 'exact-metadata-pins-required')
    for name, digest in pins.items():
        relative(name); pin(digest)


def recipe_paths(root):
    data = decode(read(root / 'scripts/ci/recipes.lock.json')[0])
    need(isinstance(data, dict) and data, 'recipe-map-required')
    result = set()
    for directory, rows in data.items():
        need(relative(directory).parts[0] == 'packages' and isinstance(rows, dict) and rows, 'invalid-recipe-map')
        for name, digest in rows.items():
            relative(name); pin(digest)
            result.add((relative(directory) / relative(name)).as_posix())
    return result, data


def walk(root, subtree, excluded=None):
    directory = root / subtree
    need(directory.is_dir() and not directory.is_symlink(), 'required-source-tree-missing')
    result = set()
    for current, dirs, files in os.walk(directory, followlinks=False):
        current = Path(current)
        need('__pycache__' not in dirs and not any(name.endswith('.pyc') for name in files), 'source-python-cache-refused')
        dirs[:] = sorted(d for d in dirs if d != '__pycache__' and not (excluded and excluded(current, d)))
        for name in dirs:
            need(not (current / name).is_symlink(), 'symlink-source-directory')
        for name in files:
            if not name.endswith('.pyc'):
                result.add((current / name).relative_to(root).as_posix())
        need(len(result) <= PATH_LIMIT, 'source-path-count-exceeded')
    return result


def initial_paths(root, locked):
    def excluded(current, name):
        return (current == root / 'scripts' and name in ('virtual', 'client', 'experiments', 'port', 'platform') or
                current == root / 'scripts/ci' and name == 'development' or
                current == root / 'packages' and name in ('tools', 'libraries'))
    result = set(INITIAL_FILES)
    for subtree in ROOTS:
        for name in walk(root, subtree, excluded):
            filename = PurePosixPath(name).name
            if name != INITIAL and (name in locked or not (filename.endswith('.log') or '.pkg.tar.' in filename)):
                result.add(name)
            elif name != INITIAL:
                try:
                    need(not (root / name).lstat().st_mode & 0o111, 'ignored-executable-source-refused')
                except OSError:
                    raise PacketError('source-unavailable') from None
    need(locked <= result, 'recipe-input-omitted')
    for directory, names in (('scripts/integration', ('fixtures', 'lifecycle', 'repository', 'onboarding', 'desktop')),
                             ('scripts/ci', ('integration', 'integration_export', 'sign_fixture', 'installed_handoff',
                                             'source_suites', 'verify_derived', 'lifecycle_inventory', 'commit_image', 'repository_projection'))):
        need(all(directory + '/' + prefix + name + '.py' in result for name in names for prefix in ('', 'test_')), 'initial-runner-tests-missing')
    return result


def rows(root, paths):
    result, size = {}, 0
    for name in sorted(paths):
        relative(name)
        data, row = read(root / name); size += len(data)
        need(size <= TOTAL_LIMIT, 'source-total-size-exceeded')
        result[name] = row
    return result


def scan(root, initial):
    locked, recipes = recipe_paths(root)
    base_paths = initial_paths(root, locked)
    base = rows(root, base_paths)
    need(base == initial['source_files'], 'initial-source-map-drift')
    for directory, inputs in recipes.items():
        for name, digest in inputs.items():
            need(base[(relative(directory) / relative(name)).as_posix()]['sha256'] == digest, 'recipe-input-drift')
    paths = base_paths | PINS | {WORKFLOW}
    for subtree in EXTRA_ROOTS:
        paths |= walk(root, subtree)
    development = walk(root, DEVELOPMENT)
    need(all(name == LOCK or name.endswith('.py') for name in development) and
         not any(PurePosixPath(name).name == '__init__.py' for name in development), 'unreviewed-development-file')
    paths |= development - {LOCK}
    need({DEVELOPMENT + '/packet.py', DEVELOPMENT + '/test_packet.py'} <= paths, 'packet-source-tests-required')
    ksm = walk(root, KSM)
    need(ksm == {KSM + '/' + name for name in KSM_FILES}, 'exact-reviewed-ksm-inputs-required')
    reviewed = decode(read(root / 'manifests/reviewed/ksmctl.json')[0])
    need(isinstance(reviewed, dict) and set(reviewed) == KSM_FILES, 'reviewed-ksm-map-required')
    paths |= ksm
    result = rows(root, paths)
    for name, digest in reviewed.items():
        need(result[KSM + '/' + name]['sha256'] == pin(digest), 'reviewed-ksm-input-drift')
    return result


def load_initial(root, path, digest, pins):
    validate_pins(pins)
    need(Path(path).absolute() == (root / INITIAL).absolute() and pins[INITIAL] == pin(digest), 'initial-lock-binding-required')
    value = pinned(Path(path), digest)
    keys = {'schema_version', 'purpose', 'development_only', 'selected_for_release', 'recipe_source_commit',
            'recipes_sha256', 'source_date_epoch', 'source_files', 'generated_fixture_files', 'hardware_validation'}
    need(isinstance(value, dict) and set(value) == keys and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['purpose'] == INITIAL_PURPOSE and value['development_only'] is True and
         value['selected_for_release'] is False and value['hardware_validation'] == 'NOT RUN', 'initial-lock-contract-refused')
    need(isinstance(value['recipe_source_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', value['recipe_source_commit']) and
         type(value['source_date_epoch']) is int and value['source_date_epoch'] >= 0 and
         value['recipes_sha256'] == pins['scripts/ci/recipes.lock.json'], 'initial-recipe-binding-refused')
    validate_map(value['source_files']); validate_map(value['generated_fixture_files'])
    return value


def bindings(root, source, pins):
    need(all(source[name]['sha256'] == digest for name, digest in pins.items()), 'packet-metadata-pin-drift')
    stage = pinned(root / 'scripts/experiments/stage.lock.json', pins['scripts/experiments/stage.lock.json'])
    need(isinstance(stage, dict) and isinstance(stage.get('source_files'), dict), 'experiment-lock-refused')
    for name, row in stage['source_files'].items():
        need(source.get('scripts/experiments/' + relative(name).as_posix()) == row, 'experiment-source-binding-drift')
    exporter = stage.get('exporter')
    need(isinstance(exporter, dict) and set(exporter) == {'path', 'mode', 'sha256'} and
         isinstance(exporter['path'], str) and
         source.get(exporter['path']) == {k: exporter[k] for k in ('mode', 'sha256')}, 'experiment-exporter-binding-drift')
    tooling = pinned(root / 'scripts/virtual/tooling.lock.json', pins['scripts/virtual/tooling.lock.json'])
    audit = pinned(root / 'scripts/virtual/tooling-audit.json', pins['scripts/virtual/tooling-audit.json'])
    need(isinstance(tooling, dict) and tooling.get('base_inputs_lock_sha256') == pins['scripts/ci/inputs.lock.json'] and
         isinstance(audit, dict) and audit.get('tooling_lock_sha256') == pins['scripts/virtual/tooling.lock.json'], 'virtual-metadata-binding-drift')


def composed_paths(initial, composition=COMPOSITION):
    need(type(composition) is str and composition in COMPOSED_MODES, 'composed-source-selection-refused')
    need(type(initial) is dict and len(initial['source_files']) == 159 and
         len(initial['generated_fixture_files']) == 125 and len(COMPOSED_EXTRA) == 99,
         'composed-original-contract-refused')
    paths = set(initial['source_files']) | COMPOSED_EXTRA
    if composition == INSTALLER_COMPOSITION:paths |= INSTALLER_EXTRA
    if composition == ZSH_COMPOSITION:paths |= ZSH_EXTRA
    need(len(INSTALLER_EXTRA) == 11 and len(ZSH_EXTRA) == 5 and
         len(paths) == {COMPOSITION:258, INSTALLER_COMPOSITION:269, ZSH_COMPOSITION:263}[composition],
         'composed-source-selection-refused')
    return paths


def composed_pins(pins, composition=COMPOSITION):
    need(type(composition) is str and composition in COMPOSED_MODES, 'composed-source-selection-refused')
    expected = COMPOSED_PINS | ({ZSH_CONTRACT} if composition == ZSH_COMPOSITION else set())
    need(type(pins) is dict and set(pins) == expected, 'exact-composed-metadata-pins-required')
    for name, value in pins.items():
        relative(name); pin(value)
    return {name: pins[name] for name in PINS}


def composed_scan(root, initial, composition=COMPOSITION):
    """Exact full-source selection; never filter an original-source scan."""
    paths = composed_paths(initial, composition)
    for parent in {relative(name).parent for name in paths}:
        directory = root / parent
        need(directory.is_dir() and not directory.is_symlink(), 'required-source-tree-missing')
        entries = os.listdir(directory)
        need(len(entries) <= PATH_LIMIT and '__pycache__' not in entries and
             not any(name.endswith('.pyc') for name in entries), 'source-python-cache-refused')
    actual = rows(root, paths)
    need(all(actual[name] == row for name,row in initial['source_files'].items()), 'initial-source-map-drift')
    if composition == INSTALLER_COMPOSITION:
        variants = {'scripts/ci/native_arm.py':'scripts/ci/development/p0_native_arm.py','scripts/ci/integration.py':'scripts/ci/development/p0_integration.py'}
        need(all(actual[variants[name]] == row for name,row in P0_OVERLAY_ROWS.items()),'P0-variant-source-drift')
    locked, recipes = recipe_paths(root)
    need(len(recipes) == 4 and len(locked) == 71 and locked <= set(initial['source_files']),
         'composed-original-recipes-refused')
    for directory, inputs in recipes.items():
        for name, expected in inputs.items():
            need(actual[directory + '/' + name]['sha256'] == expected, 'recipe-input-drift')
    return actual


def composed_bindings(root, source, pins, composition=COMPOSITION):
    bindings(root, source, composed_pins(pins, composition))
    need(all(source[name]['sha256'] == value for name, value in pins.items()), 'packet-metadata-pin-drift')
    for name, prefix in COMPOSED_MAPS.items():
        value = pinned(root / name, pins[name]); validate_map(value)
        expected = {relative(path).name for path in COMPOSED_EXTRA
                    if path.startswith(prefix + '/') and path.endswith('.py')}
        need(set(value) == expected and all(source.get(prefix + '/' + child) == row
             for child, row in value.items()), 'composed-map-binding-drift')
    policy = pinned(root / GENERIC_POLICY, pins[GENERIC_POLICY])
    need(type(policy) is dict and policy.get('supported_models') == [] and
         policy.get('platform_scope') == 'generic-builder-only' and policy.get('review_status') == 'ACCEPTED',
         'composed-policy-refused')


def freeze_composed(root, output, initial_lock, initial_sha256, pins, *, composition=COMPOSITION):
    root, output = Path(root).absolute(), Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'new-packet-output-required')
    if output.is_relative_to(root):need(output == root / LOCK, 'fixed-packet-path-required')
    initial = load_initial(root, initial_lock, initial_sha256, composed_pins(pins, composition))
    source = composed_scan(root, initial, composition); composed_bindings(root, source, pins, composition)
    value = {'schema_version':2, 'composition':composition, 'purpose':PURPOSE, 'development_only':True,
             'selected_for_release':False, 'hardware_validation':'NOT RUN', 'metadata_pins':dict(pins),
             'initial_source_files':initial['source_files'], 'generated_fixture_files':initial['generated_fixture_files'],
             'source_files':source}
    need(composed_scan(root, initial, composition) == source, 'source-drift-during-freeze')
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    need(len(data) <= FILE_LIMIT, 'packet-size-exceeded')
    try:
        with output.open('xb') as stream:stream.write(data)
        output.chmod(0o644)
    except OSError:raise PacketError('packet-write-failed') from None
    return hashlib.sha256(data).hexdigest()


def freeze(root, output, initial_lock, initial_sha256, pins):
    root, output = Path(root).absolute(), Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'new-packet-output-required')
    if output.is_relative_to(root):
        need(output == root / LOCK, 'fixed-packet-path-required')
    initial = load_initial(root, initial_lock, initial_sha256, pins)
    source = scan(root, initial); bindings(root, source, pins)
    value = {'schema_version': 1, 'purpose': PURPOSE, 'development_only': True, 'selected_for_release': False,
             'hardware_validation': 'NOT RUN', 'metadata_pins': dict(pins), 'initial_source_files': initial['source_files'],
             'generated_fixture_files': initial['generated_fixture_files'], 'source_files': source}
    need(scan(root, initial) == source, 'source-drift-during-freeze')
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    need(len(data) <= FILE_LIMIT, 'packet-size-exceeded')
    try:
        with output.open('xb') as stream:
            stream.write(data)
        output.chmod(0o644)
    except OSError:
        raise PacketError('packet-write-failed') from None
    return hashlib.sha256(data).hexdigest()


def git(root, args, limit=FILE_LIMIT):
    allowed = args == ['rev-parse', 'HEAD'] or (
        isinstance(args, list) and len(args) == 3 and args[:2] in (['cat-file', '-t'], ['cat-file', 'blob']) and
        isinstance(args[2], str) and re.fullmatch(r'[0-9a-f]{40}', args[2])) or (
        isinstance(args, list) and len(args) == 4 and args[:3] == ['ls-tree', '-rz', '--full-tree'] and
        isinstance(args[3], str) and re.fullmatch(r'[0-9a-f]{40}', args[3]))
    need(allowed and type(limit) is int and 0 < limit <= FILE_LIMIT, 'readonly-git-query-required')
    environment = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1',
                       GIT_CONFIG_COUNT='0', GIT_TERMINAL_PROMPT='0', LC_ALL='C')
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
            result = subprocess.run(['git', '--no-optional-locks', '--no-replace-objects', '-C', str(root), *args],
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=diagnostic, env=environment, timeout=30)
            need(result.returncode == 0, 'git-source-query-failed')
            output.seek(0); data = output.read(limit + 1)
            need(len(data) <= limit, 'git-source-output-exceeded')
            return data
    except (OSError, subprocess.SubprocessError):
        raise PacketError('git-source-query-unavailable') from None


def selected(name, locked):
    if name == LOCK or '__pycache__' in relative(name).parts or name.endswith('.pyc'):
        return False
    if name in INITIAL_FILES or name == WORKFLOW or name in PINS:
        return True
    path = relative(name)
    if name.startswith(DEVELOPMENT + '/'):
        return True  # Unknown executable files must not disappear from the Git set.
    if any(name.startswith(subtree + '/') for subtree in (*EXTRA_ROOTS, KSM)):
        return True
    if path.parts[0] not in ROOTS:
        return False
    if len(path.parts) > 1 and (path.parts[0] == 'scripts' and path.parts[1] in ('port', 'platform') or
                              path.parts[0] == 'packages' and path.parts[1] in ('tools', 'libraries')):
        return False
    return name in locked or not (name.endswith('.log') or '.pkg.tar.' in path.name)


def verify_git(root, github_sha, source, packet_sha256, *, composition=None):
    need(composition is None or type(composition) is str and composition in COMPOSED_MODES, 'composed-source-selection-refused')
    need(isinstance(github_sha, str) and re.fullmatch(r'[0-9a-f]{40}', github_sha), 'full-github-sha-required')
    need(git(root, ['cat-file', '-t', github_sha]) == b'commit\n' and
         git(root, ['rev-parse', 'HEAD']).strip() == github_sha.encode(), 'github-checkout-commit-drift')
    locked, unused = recipe_paths(root)
    records = git(root, ['ls-tree', '-rz', '--full-tree', github_sha])
    tree, packet_entry = {}, None
    try:
        for record in records.split(b'\0'):
            if not record:
                continue
            metadata, encoded = record.split(b'\t', 1)
            mode, kind, oid = metadata.decode('ascii').split(' ')
            name = encoded.decode('utf-8'); relative(name)
            if name == LOCK or (name in source if composition in COMPOSED_MODES else selected(name, locked)):
                need(name not in tree and kind == 'blob' and mode in ('100644', '100755') and
                     re.fullmatch(r'[0-9a-f]{40}', oid), 'git-source-entry-refused')
                if name == LOCK:
                    need(packet_entry is None and mode == '100644', 'git-packet-mode-refused')
                    packet_entry = oid
                else:
                    tree[name] = (int(mode[-3:], 8), oid)
            need(len(tree) <= PATH_LIMIT, 'git-source-path-count-exceeded')
    except (UnicodeError, ValueError):
        raise PacketError('invalid-git-source-tree') from None
    need(set(tree) == set(source), 'git-source-path-set-drift')
    need(packet_entry is not None and hashlib.sha256(git(root, ['cat-file', 'blob', packet_entry])).hexdigest() == pin(packet_sha256), 'git-packet-binding-drift')
    for name, (mode, oid) in tree.items():
        data = git(root, ['cat-file', 'blob', oid])
        need(source[name] == {'mode': mode, 'sha256': hashlib.sha256(data).hexdigest()}, 'git-source-bytes-or-mode-drift')


def preflight_composed(root, packet_path, packet_sha256, github_sha, pins=None, *, composition=COMPOSITION):
    need(type(composition) is str and composition in COMPOSED_MODES, 'composed-source-selection-refused')
    root = Path(root).absolute()
    need(Path(packet_path).absolute() == root / LOCK and stat.S_IMODE(regular(Path(packet_path)).st_mode) == 0o644,
         'runtime-packet-path-required')
    value = pinned(Path(packet_path), packet_sha256)
    keys = {'schema_version', 'composition', 'purpose', 'development_only', 'selected_for_release',
            'hardware_validation', 'metadata_pins', 'initial_source_files', 'generated_fixture_files', 'source_files'}
    need(type(value) is dict and set(value) == keys and type(value['schema_version']) is int and
         value['schema_version'] == 2 and type(value['composition']) is str and value['composition'] == composition and value['purpose'] == PURPOSE and
         value['development_only'] is True and value['selected_for_release'] is False and
         value['hardware_validation'] == 'NOT RUN', 'composed-packet-contract-refused')
    original_pins = composed_pins(value['metadata_pins'], composition)
    if pins is not None:
        composed_pins(pins, composition);need(pins == value['metadata_pins'], 'runtime-metadata-pins-drift')
    for field in ('initial_source_files', 'generated_fixture_files', 'source_files'):validate_map(value[field])
    initial = load_initial(root, root / INITIAL, original_pins[INITIAL], original_pins)
    need(value['initial_source_files'] == initial['source_files'] and
         value['generated_fixture_files'] == initial['generated_fixture_files'] and
         set(value['source_files']) == composed_paths(initial, composition), 'packet-initial-lock-binding-drift')
    actual = composed_scan(root, initial, composition)
    need(actual == value['source_files'], 'packet-source-map-drift')
    composed_bindings(root, actual, value['metadata_pins'], composition)
    verify_git(root, github_sha, actual, packet_sha256, composition=composition)
    need(composed_scan(root, initial, composition) == actual, 'source-drift-during-preflight')
    return value


def preflight(root, packet_path, packet_sha256, github_sha, pins=None):
    root = Path(root).absolute()
    need(Path(packet_path).absolute() == root / LOCK and stat.S_IMODE(regular(Path(packet_path)).st_mode) == 0o644, 'runtime-packet-path-required')
    value = pinned(Path(packet_path), packet_sha256)
    keys = {'schema_version', 'purpose', 'development_only', 'selected_for_release', 'hardware_validation',
            'metadata_pins', 'initial_source_files', 'generated_fixture_files', 'source_files'}
    need(isinstance(value, dict) and set(value) == keys and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['purpose'] == PURPOSE and value['development_only'] is True and
         value['selected_for_release'] is False and value['hardware_validation'] == 'NOT RUN', 'packet-contract-refused')
    validate_pins(value['metadata_pins'])
    if pins is not None:
        validate_pins(pins); need(pins == value['metadata_pins'], 'runtime-metadata-pins-drift')
    for field in ('initial_source_files', 'generated_fixture_files', 'source_files'):
        validate_map(value[field])
    initial = load_initial(root, root / INITIAL, value['metadata_pins'][INITIAL], value['metadata_pins'])
    need(value['initial_source_files'] == initial['source_files'] and
         value['generated_fixture_files'] == initial['generated_fixture_files'], 'packet-initial-lock-binding-drift')
    actual = scan(root, initial)
    need(actual == value['source_files'], 'packet-source-map-drift')
    bindings(root, actual, value['metadata_pins'])
    verify_git(root, github_sha, actual, packet_sha256)
    need(scan(root, initial) == actual, 'source-drift-during-preflight')
    return value


def snapshot(root, target, packet):
    root, target = Path(root).absolute(), Path(target).absolute()
    need(not target.exists() and not target.is_symlink() and not target.is_relative_to(root), 'new-external-snapshot-required')
    need(isinstance(packet, dict) and 'source_files' in packet and 'metadata_pins' in packet, 'snapshot-packet-required')
    composed = packet.get('schema_version') == 2
    validate_map(packet['source_files'])
    if composed:
        composition = packet.get('composition')
        need(type(composition) is str and composition in COMPOSED_MODES, 'composed-packet-contract-refused')
        original_pins = composed_pins(packet['metadata_pins'], composition)
        initial = load_initial(root, root / INITIAL, original_pins[INITIAL], original_pins)
        need(set(packet['source_files']) == composed_paths(initial, composition), 'composed-source-selection-refused')
    else:validate_pins(packet['metadata_pins'])
    try:
        target.mkdir()
        for subtree in ROOTS:
            (target / subtree).mkdir(exist_ok=True)
        for name, expected in packet['source_files'].items():
            data, actual = read(root / name); need(actual == expected, 'snapshot-source-drift')
            dest = target / name; dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data); dest.chmod(expected['mode'])
            need(read(dest)[1] == expected, 'snapshot-copy-drift')
        if (root / LOCK).exists():
            data, row = read(root / LOCK)
            need(decode(data) == packet and row['mode'] == 0o644, 'snapshot-packet-binding-drift')
            (target / LOCK).write_bytes(data); (target / LOCK).chmod(0o644)
    except OSError:
        raise PacketError('snapshot-copy-failed') from None
    initial = load_initial(target, target / INITIAL, packet['metadata_pins'][INITIAL],
                           original_pins if composed else packet['metadata_pins'])
    need((composed_scan(target, initial, composition) if composed else scan(target, initial)) == packet['source_files'],
         'snapshot-source-map-drift')
    if composed:composed_bindings(target, packet['source_files'], packet['metadata_pins'], composition)
    else:bindings(target, packet['source_files'], packet['metadata_pins'])
    return target
