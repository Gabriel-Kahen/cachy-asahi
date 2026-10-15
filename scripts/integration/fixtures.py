#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Derive inspectable DEVELOPMENT upgrade recipes. Never execute a PKGBUILD."""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys

PACKAGES = {
    'cachy-asahi-hyprland-settings': 'packages/desktop/cachy-asahi-hyprland-settings',
    'cachy-asahi-fish-config': 'packages/shells/cachy-asahi-fish-config',
    'cachy-asahi-zsh-config': 'packages/shells/cachy-asahi-zsh-config',
    'cachy-asahi-setup': 'packages/settings/cachy-asahi-setup',
}
PAYLOADS = {
    'cachy-asahi-hyprland-settings': ('hyprland.lua', 'usr/share/cachy-asahi/hyprland/hyprland.lua'),
    'cachy-asahi-fish-config': ('config.fish', 'usr/share/cachy-asahi/fish/config.fish'),
    'cachy-asahi-zsh-config': ('config.zsh', 'usr/share/cachy-asahi/zsh/config.zsh'),
    'cachy-asahi-setup': ('cachy-asahi-setup', 'usr/bin/cachy-asahi-setup'),
}
FIELDS = set('pkgbase pkgname pkgdesc pkgver pkgrel epoch url install changelog arch groups license checkdepends makedepends depends optdepends provides conflicts replaces noextract options backup source validpgpkeys sha256sums'.split())
SCALARS = set('pkgbase pkgname pkgdesc pkgver pkgrel epoch url install changelog'.split())
ORDER = 'pkgdesc pkgver pkgrel epoch url install changelog arch groups license checkdepends makedepends depends optdepends provides conflicts replaces noextract options backup source validpgpkeys sha256sums'.split()
PIN = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(data):
    return (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def relative(value):
    if not isinstance(value, str) or '\\' in value or any(ord(c) < 32 for c in value):
        raise ValueError('unsafe relative input path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('unsafe relative input path')
    return path


def read_inside(root, name):
    path = root
    parts = relative(name).parts
    for index, part in enumerate(parts):
        path /= part
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or (index < len(parts) - 1 and not stat.S_ISDIR(mode)):
            raise ValueError('symlink/non-directory input forbidden')
    if not stat.S_ISREG(mode) or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('nonregular/oversized input forbidden')
    return path.read_bytes()


def srcinfo(text):
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([a-z0-9_]+)\s*=\s*(.*?)\s*', line)
        if not match or match[1] not in FIELDS:
            raise ValueError('unsupported SRCINFO field/line')
        result.setdefault(match[1], []).append(match[2])
    return result


def assignments(text):
    """Literal metadata subset only; function bodies are retained as inert text."""
    result, spans = {}, {}
    for match in re.finditer(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', text, re.M):
        key = match[1]
        if key not in FIELDS:
            continue
        if key in result:
            raise ValueError(f'duplicate recipe field: {key}')
        start, end = match.start(2), match.end(2)
        raw = match[2]
        array = raw.startswith('(')
        if array:
            quote = None
            for end in range(start + 1, len(text)):
                char = text[end]
                if char == '\\':
                    raise ValueError('escaped/dynamic recipe metadata unsupported')
                if quote:
                    if char == quote:
                        quote = None
                elif char in "\"'":
                    quote = char
                elif char == ')':
                    break
            else:
                raise ValueError('unterminated recipe array')
            tail = text[end + 1:text.find('\n', end) if '\n' in text[end:] else len(text)].strip()
            if tail and not tail.startswith('#'):
                raise ValueError('nonliteral recipe assignment')
            end += 1
            raw = text[start + 1:end - 1]
        if '$' in raw or '`' in raw or '\\' in raw:
            raise ValueError('dynamic recipe metadata unsupported')
        quote = None
        for index, char in enumerate(raw):
            if quote:
                if char == quote:
                    quote = None
            elif char in "\"'":
                quote = char
            elif char == '#':
                if array or (index and not raw[index - 1].isspace()):
                    raise ValueError('array comments/unquoted hash in metadata unsupported')
                break
            elif char in ';|&<>()~' or (array and char in '*?[]{}'):
                raise ValueError('shell operators/expansions in metadata unsupported')
        values = shlex.split(raw, comments=True)
        if key in SCALARS and len(values) != 1:
            raise ValueError('single literal scalar required')
        if any('\n' in value or '\r' in value for value in values):
            raise ValueError('multiline metadata values unsupported')
        result[key], spans[key] = values, (start, end)
    result.setdefault('pkgbase', result.get('pkgname', []))
    return result, spans


def render_srcinfo(data):
    lines = ['pkgbase = ' + data['pkgbase'][0]]
    for key in ORDER:
        for value in data.get(key, []):
            lines.append(f'\t{key} = {value}')
    return ('\n'.join(lines) + '\n\npkgname = ' + data['pkgname'][0] + '\n').encode()


def patch_metadata(text, updates):
    _, spans = assignments(text)
    patches = []
    for key, values in updates.items():
        if key not in spans:
            raise ValueError(f'cannot patch absent metadata: {key}')
        replacement = shlex.quote(values[0]) if key in SCALARS else '(' + ' '.join(shlex.quote(v) for v in values) + ')'
        patches.append((*spans[key], replacement))
    for start, end, replacement in sorted(patches, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', value):
        raise ValueError('version must be a numeric major.minor.patch triple')
    return tuple(map(int, value.split('.')))


def validate_recipe(name, files):
    data, _ = assignments(files['PKGBUILD'].decode())
    if data != srcinfo(files['.SRCINFO'].decode()):
        raise ValueError(f'{name}: PKGBUILD/SRCINFO metadata differs')
    if data.get('pkgname') != [name] or data.get('pkgbase') != [name] or data.get('arch') != ['any'] or data.get('license') != ['MIT'] or data.get('install'):
        raise ValueError('only reviewed single-package MIT data recipes without hooks supported')
    version_tuple(data['pkgver'][0])
    if not re.fullmatch(r'[1-9][0-9]*', data['pkgrel'][0]):
        raise ValueError('invalid pkgrel')
    if len(data.get('source', [])) != len(data.get('sha256sums', [])):
        raise ValueError('source/checksum count differs')
    for source, checksum in zip(data['source'], data['sha256sums']):
        relative(source)
        if source not in files or not PIN.fullmatch(checksum) or sha(files[source]) != checksum:
            raise ValueError('local source/checksum differs')
    if not files.get('LICENSE', b'').startswith(b'MIT License\n'):
        raise ValueError('MIT attribution missing')
    return data


def derive_setup(files, version, source_commit, lock_pin):
    base = files['cachy-asahi-setup']
    origin = sha(base)
    text = base.decode()
    needle = '    parser = argparse.ArgumentParser(description=__doc__)\n'
    if text.count(needle) != 1 or '--integration-fixture-version' in text:
        raise ValueError('unsupported setup CLI insertion point')
    marker = f'cachy-asahi-setup {version} DEVELOPMENT-FIXTURE'
    text = text.replace(needle, needle + f"    parser.add_argument('--integration-fixture-version', action='version', version={marker!r}, help='read-only DEVELOPMENT fixture identity')\n", 1)
    text += f'\n# DEVELOPMENT UPDATE FIXTURE {version}; original runtime behavior retained.\n'
    ast.parse(text)
    files['cachy-asahi-setup'] = text.encode()
    files['base-setup.py'] = base
    record = json.loads(files['source-provenance.json'], object_pairs_hook=unique)
    if record.get('sha256') != origin or record.get('license_sha256') != sha(files['LICENSE']) or record.get('canonical_path') != 'scripts/setup/setup.py':
        raise ValueError('setup origin provenance differs')
    record.update(sha256=sha(files['cachy-asahi-setup']), development_fixture=True,
                  origin_helper_sha256=origin, origin_checker_sha256=sha(files['check-sync.py']),
                  origin_source_commit=source_commit, origin_lock_sha256=lock_pin,
                  canonical_handoff='DEVELOPMENT ONLY: derived canonical copy within generated fixture tree',
                  source_kind='derived-development-fixture', native_build='NOT RUN', installed='NOT RUN', hardware_tested='NOT RUN')
    files['source-provenance.json'] = json_bytes(record)
    # Extend the checker; retain all its original path/helper/license checks.
    checker = files['check-sync.py'].decode()
    anchor = '        name = record.get("canonical_path")\n'
    if checker.count(anchor) != 1:
        raise ValueError('unsupported fixture checker insertion point')
    guard = (f'        if record.get("development_fixture") is not True or record.get("origin_helper_sha256") != {origin!r}:\n'
             '            raise ValueError("DEVELOPMENT fixture origin declaration differs")\n'
             f'        if digest(copy.with_name("base-setup.py")) != {origin!r}:\n'
             '            raise ValueError("DEVELOPMENT fixture original helper differs")\n')
    files['check-sync.py'] = checker.replace(anchor, guard + anchor, 1).encode()
    # Keep existing sync regression coverage, adding a read-only origin fixture.
    tests = files['test-sync.py'].decode()
    anchor = '        self.write_record()\n'
    if anchor not in tests:
        raise ValueError('unsupported fixture sync tests')
    addition = (f'        self.record.update(development_fixture=True, origin_helper_sha256={origin!r})\n'
                '        self.copy.with_name("base-setup.py").write_bytes(CHECKER.with_name("base-setup.py").read_bytes())\n')
    tests = tests.replace(anchor, addition + anchor, 1)
    anchor = '("LICENSE", "source-provenance.json", "cachy-asahi-setup")'
    if tests.count(anchor) != 1:
        raise ValueError('unsupported fixture symlink regression')
    tests = tests.replace(anchor, '("LICENSE", "source-provenance.json", "cachy-asahi-setup", "base-setup.py")', 1)
    files['test-sync.py'] = tests.encode()
    ast.parse(files['check-sync.py']); ast.parse(files['test-sync.py'])
    return marker


def scan(root):
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError('symlink/special recipe input forbidden')
        if stat.S_ISREG(mode):
            result[str(path.relative_to(root))] = sha(path.read_bytes())
    return result


def real_path(value):
    """Reject symlinks anywhere along an absolute input/output parent path."""
    path = Path(os.path.abspath(value))
    for parent in (*reversed(path.parents), path):
        if parent.is_symlink():
            raise ValueError('symlink path forbidden')
    return path


def generate(repo, lock, output, lock_sha256, source_commit, version=None, epoch=0):
    repo, lock, output = real_path(repo), real_path(lock), real_path(output)
    if not repo.is_dir() or not lock.is_file():
        raise ValueError('source repository and regular lock file required')
    if not PIN.fullmatch(lock_sha256) or not COMMIT.fullmatch(source_commit) or epoch < 0:
        raise ValueError('full reviewed lock SHA256, source commit and nonnegative epoch required')
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('output must be a new directory with an existing parent')
    if output.resolve().is_relative_to(repo):
        raise ValueError('output must be outside source repository')
    raw = lock.read_bytes()
    if sha(raw) != lock_sha256:
        raise ValueError('frozen lock SHA256 differs')
    frozen = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(frozen, dict) or set(frozen) != set(PACKAGES.values()):
        raise ValueError('lock must contain exactly the four reviewed originals')
    snapshots, metadata = {}, {}
    for name, directory in sorted(PACKAGES.items()):
        pins = frozen[directory]
        if not isinstance(pins, dict) or not pins or any(not isinstance(h, str) or not PIN.fullmatch(h) for h in pins.values()):
            raise ValueError('invalid frozen recipe hashes')
        files = {path: read_inside(repo, str(relative(directory) / relative(path))) for path in sorted(pins)}
        if {path: sha(data) for path, data in files.items()} != pins or scan(repo / directory) != pins:
            raise ValueError('frozen recipe inputs differ/missing/extra')
        snapshots[name] = files
        metadata[name] = validate_recipe(name, files)
    licenses = {files['LICENSE'] for files in snapshots.values()}
    if len(licenses) != 1 or read_inside(repo, 'LICENSE') not in licenses:
        raise ValueError('project/package license identity differs')
    setup = snapshots['cachy-asahi-setup']['cachy-asahi-setup']
    if read_inside(repo, 'scripts/setup/setup.py') != setup:
        raise ValueError('canonical/base packaged helper differs')
    highest = max(version_tuple(data['pkgver'][0]) for data in metadata.values())
    version = version or '.'.join(map(str, (*highest[:2], highest[2] + 1)))
    if version_tuple(version) <= highest:
        raise ValueError('fixture version must exceed every baseline version')
    if sum(len(data) for files in snapshots.values() for data in files.values()) > 64 * 1024 * 1024:
        raise ValueError('frozen snapshot exceeds size bound')
    trees, records, diffs = {}, {}, {}
    for name, directory in sorted(PACKAGES.items()):
        base, old = snapshots[name], metadata[name]
        source_names = old['source']
        upgraded = {key: base[key] for key in ('PKGBUILD', '.SRCINFO', *source_names)}
        for doc in ('README.md', 'usage.md'):
            if doc in base:
                upgraded[doc] = base[doc]
        if name == 'cachy-asahi-setup':
            marker = derive_setup(upgraded, version, source_commit, lock_sha256)
            source_names = [*source_names, 'base-setup.py']
        else:
            marker = f'DEVELOPMENT UPDATE FIXTURE {name} {version}'
            comment = '-- ' if name.endswith('hyprland-settings') else '# '
            asset = PAYLOADS[name][0]
            upgraded[asset] += ('\n' + comment + marker + '\n').encode()
        label = f'\nDEVELOPMENT TEST ONLY update fixture {version}; not a release candidate.\nOriginal MIT attribution and platform behavior are retained.\n'
        upgraded['NOTICE'] += label.encode()
        for doc in ('README.md', 'usage.md'):
            if doc in upgraded:
                upgraded[doc] += label.encode()
        updates = {'pkgver': [version], 'pkgrel': ['1'], 'pkgdesc': ['DEVELOPMENT TEST ONLY: ' + old['pkgdesc'][0]],
                   'source': source_names, 'sha256sums': [sha(upgraded[path]) for path in source_names]}
        upgraded['PKGBUILD'] = ('# DEVELOPMENT TEST ONLY update fixture; no release promotion.\n' + patch_metadata(base['PKGBUILD'].decode(), updates)).encode()
        new, _ = assignments(upgraded['PKGBUILD'].decode())
        upgraded['.SRCINFO'] = render_srcinfo(new)
        validate_recipe(name, upgraded)
        if any(new.get(k) != old.get(k) for k in FIELDS - {'pkgdesc', 'pkgver', 'pkgrel', 'source', 'sha256sums'}):
            raise ValueError('fixture changed dependency/license/ownership metadata')
        trees[('baseline', directory)], trees[('upgrade', directory)] = base, upgraded
        diff = ''.join(''.join(difflib.unified_diff(base.get(path, b'').decode().splitlines(True), upgraded.get(path, b'').decode().splitlines(True), fromfile='baseline/' + path, tofile='upgrade/' + path)) for path in sorted(upgraded) if base.get(path) != upgraded[path])
        diffs[name] = diff.encode()
        asset, installed = PAYLOADS[name]
        records[name] = {'recipe': directory, 'base_version': old['pkgver'][0] + '-' + old['pkgrel'][0],
                         'upgrade_version': version + '-1', 'base_inputs_sha256': {p: sha(b) for p, b in base.items()},
                         'fixture_inputs_sha256': {p: sha(b) for p, b in upgraded.items()},
                         'base_recipe_sha256': sha(base['PKGBUILD']), 'fixture_recipe_sha256': sha(upgraded['PKGBUILD']),
                         'diff': 'diffs/' + name + '.diff', 'diff_sha256': sha(diffs[name]),
                         'baseline_recipe': 'baseline/' + directory, 'upgrade_recipe': 'upgrade/' + directory,
                         'reviewed_inputs': {phase: f'reviewed-inputs/{phase}/{name}.json' for phase in ('baseline', 'upgrade')},
                         'payload_expectations': [{'path': installed, 'base_sha256': sha(base[asset]), 'fixture_sha256': sha(upgraded[asset]), 'marker': marker}],
                         'rollback_expectation': {'version': old['pkgver'][0] + '-' + old['pkgrel'][0], 'installed_path': installed,
                                                  'payload_sha256': sha(base[asset]), 'artifact_status': 'NOT BUILT'},
                         'behavior_expectations': ['same package identity/ownership and dependencies', 'MIT notices retained', 'rollback uses exact baseline recipe/artifact version'],
                         'cli_expectation': {'argv': ['--integration-fixture-version'], 'stdout': marker + '\n', 'writes_user_state': False} if name == 'cachy-asahi-setup' else None}
    manifest = {'schema_version': 1, 'development_only': True, 'selected_for_release': False,
                'source_commit': source_commit, 'source_commit_verification': 'caller-supplied full pin; byte snapshot independently bound to reviewed lock; no Git command executed',
                'frozen_lock_sha256': lock_sha256, 'generator_sha256': sha(Path(__file__).read_bytes()),
                'source_date_epoch': epoch, 'packages': records, 'native_build': 'NOT RUN',
                'package_upgrade': 'NOT RUN', 'M2_validation': 'NOT RUN'}
    # All validation/transformation precedes the single exclusive output creation.
    output.mkdir(mode=0o700)
    def write(name, data, executable=False):
        target = output / relative(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data); target.chmod(0o755 if executable else 0o644)
        os.utime(target, (epoch, epoch))
    for (phase, directory), files in trees.items():
        for name, data in files.items():
            write(f'{phase}/{directory}/{name}', data, name in {'cachy-asahi-setup', 'cachy-asahi-screenshot'})
    license_bytes = next(iter(licenses))
    for phase in ('baseline', 'upgrade'):
        write(phase + '/LICENSE', license_bytes)
        write(phase + '/scripts/setup/setup.py', trees[(phase, PACKAGES['cachy-asahi-setup'])]['cachy-asahi-setup'], True)
        # Activates the original prepare() canonical check only within this generated tree.
        write(phase + '/AGENTS.md', b'# Generated DEVELOPMENT fixture tree, never a release candidate.\n')
        inputs = {directory: {name: sha(data) for name, data in trees[(phase, directory)].items()} for directory in PACKAGES.values()}
        write(phase + '-recipes.lock.json', json_bytes(inputs))
        for name, directory in PACKAGES.items():
            write(f'reviewed-inputs/{phase}/{name}.json', json_bytes(inputs[directory]))
    for name, diff in diffs.items():
        write('diffs/' + name + '.diff', diff)
    write('frozen-base.lock.json', raw)
    write('fixture-manifest.json', json_bytes(manifest))
    for directory in sorted((path for path in output.rglob('*') if path.is_dir()), reverse=True):
        directory.chmod(0o755)
        os.utime(directory, (epoch, epoch))
    os.utime(output, (epoch, epoch))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--lock-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version')
    parser.add_argument('--source-date-epoch', type=int, default=0)
    args = parser.parse_args()
    try:
        result = generate(args.repo, args.lock, args.output, args.lock_sha256, args.source_commit, args.version, args.source_date_epoch)
    except (OSError, ValueError, UnicodeError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'failed', 'error': str(error), 'development_only': True}), file=sys.stderr)
        return 1
    print(json.dumps({'status': 'generated-development-fixtures', 'packages': sorted(result['packages']), 'native_build': 'NOT RUN', 'package_upgrade': 'NOT RUN', 'M2_validation': 'NOT RUN'}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
