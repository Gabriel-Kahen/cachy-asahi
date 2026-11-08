#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source/payload checks and private staging; never installs packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

NAME, VERSION = 'cachy-asahi-release-tools', '0.4.0-1'
DEPENDENCIES = ['python>=3.14', 'zstd', 'gnupg', 'libarchive', 'pacman']

RUNTIME = {'endpoint__client.py': {'bytes': 28669, 'sha256': '48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/client/client.py'}, 'endpoint__copy_endpoint.py': {'bytes': 5417, 'sha256': 'c4de7e4c2eebc7a0fb510377480c19eee873bd65ab965ad6ed04ac0aa7aada79', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/endpoint_copy_v1/copy_endpoint.py'}, 'endpoint__dependencies.json': {'bytes': 1492, 'sha256': '2b403c29fb33296a5c216031871b19f147cea04a0457f9066a13eb041466a8c6', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/endpoint_transport_v1/dependencies.json'}, 'endpoint__endpoint.py': {'bytes': 7620, 'sha256': 'e94520d9cc6ee0bb8ac007227dc51bc677de9efff7464f453ad7682eaa026e79', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/client/endpoint.py'}, 'endpoint__export_repository.py': {'bytes': 15157, 'sha256': '9d07089a8855a1b11ad8a8f2ef680b00aa4ea48f7f422e05ce83a279780595ea', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/export_repository.py'}, 'endpoint__offline_kit.py': {'bytes': 14796, 'sha256': '8f9cdb4ad26525fb1c4c906a752f56e8115a3c39b8aa758dd86dca7d032f54b3', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/offline_kit.py'}, 'endpoint__release.py': {'bytes': 41320, 'sha256': 'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/release.py'}, 'endpoint__source_delivery.py': {'bytes': 16456, 'sha256': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/source_delivery.py'}, 'endpoint__transport.py': {'bytes': 15138, 'sha256': '759f18f84a3c23a78ce7a5b6d02674edcce149fbcfb80ef1fc6c9454cbbe2851', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/endpoint_transport_v1/transport.py'}, 'legacy__archive_stream.py': {'bytes': 11938, 'sha256': '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/update/archive_stream.py'}, 'legacy__compare_sboms.py': {'bytes': 19959, 'sha256': '219296c46902257f64203e3b3b41ece42a2e21a7d818f305bac858767aeff1b4', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/compare_sboms.py'}, 'legacy__launcher': {'bytes': 6928, 'sha256': 'e263381111012ef0da8d95b3444234f65cb229862be96c69302f0d76a6a8b786', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/bin/cachy-asahi-release-tools'}, 'legacy__package_checks.py': {'bytes': 17706, 'sha256': 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/checks/package_checks.py'}, 'legacy__recipe_source_delivery.py': {'bytes': 24188, 'sha256': '779f8147a13d3f90d11b9e5610f2d7d74fce28d0732797331fc832f0e87323be', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/recipe_source_delivery.py'}, 'legacy__recipe_source_delivery_v2.py': {'bytes': 26264, 'sha256': 'cbc13a6e2d604dfec9d0090cb22d279952f2c96b3d1196c2e8a18ee83ad922ae', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/recipe_source_delivery_v2.py'}, 'legacy__release_sbom.py': {'bytes': 31044, 'sha256': '1a53831128858c6c629f2449a7276a52846e52ebf426baa6f1c010aa209af486', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/release_sbom.py'}, 'legacy__source_delivery.py': {'bytes': 16456, 'sha256': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e', 'installed_path': 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/source_delivery.py'}}
PAYLOAD = {'usr/bin/cachy-asahi-release-tools': {'mode': 493, 'source': 'cachy-asahi-release-tools'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/client/client.py': {'mode': 420, 'source': 'endpoint__client.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/client/endpoint.py': {'mode': 420, 'source': 'endpoint__endpoint.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/endpoint_copy_v1/copy_endpoint.py': {'mode': 420, 'source': 'endpoint__copy_endpoint.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/endpoint_transport_v1/dependencies.json': {'mode': 420, 'source': 'endpoint__dependencies.json'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/endpoint_transport_v1/transport.py': {'mode': 420, 'source': 'endpoint__transport.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/export_repository.py': {'mode': 420, 'source': 'endpoint__export_repository.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/offline_kit.py': {'mode': 420, 'source': 'endpoint__offline_kit.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/release.py': {'mode': 420, 'source': 'endpoint__release.py'}, 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/scripts/release/source_delivery.py': {'mode': 420, 'source': 'endpoint__source_delivery.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/bin/cachy-asahi-release-tools': {'mode': 493, 'source': 'legacy__launcher'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/checks/package_checks.py': {'mode': 420, 'source': 'legacy__package_checks.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/compare_sboms.py': {'mode': 420, 'source': 'legacy__compare_sboms.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/recipe_source_delivery.py': {'mode': 420, 'source': 'legacy__recipe_source_delivery.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/recipe_source_delivery_v2.py': {'mode': 420, 'source': 'legacy__recipe_source_delivery_v2.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/release_sbom.py': {'mode': 420, 'source': 'legacy__release_sbom.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/release/source_delivery.py': {'mode': 420, 'source': 'legacy__source_delivery.py'}, 'usr/lib/cachy-asahi/release-tools-v4/legacy-v2/lib/cachy-asahi/release-tools-v2/scripts/update/archive_stream.py': {'mode': 420, 'source': 'legacy__archive_stream.py'}, 'usr/share/doc/cachy-asahi-release-tools/README.md': {'mode': 420, 'source': 'README.md'}, 'usr/share/doc/cachy-asahi-release-tools/payload-map.json': {'mode': 420, 'source': 'payload-map.json'}, 'usr/share/doc/cachy-asahi-release-tools/source-provenance.json': {'mode': 420, 'source': 'source-provenance.json'}, 'usr/share/licenses/cachy-asahi-release-tools/LICENSE': {'mode': 420, 'source': 'LICENSE'}, 'usr/share/licenses/cachy-asahi-release-tools/NOTICE': {'mode': 420, 'source': 'NOTICE'}}
SOURCES = set(RUNTIME) | {NAME, 'check_package.py', 'test_package.py', 'README.md', 'source-provenance.json', 'payload-map.json', 'NOTICE', 'LICENSE', 'fixture__provenance.json', 'fixture__test_endpoint.py', 'fixture__test_export_repository.py', 'fixture__test_release.py', 'fixture__legacy-v2.tar.gz', 'fixture__previous-v3.tar.gz'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def array(text, name):
    matches = re.findall(r'^' + re.escape(name) + r'=\(([^)]*)\)$', text, re.M)
    need(len(matches) == 1, 'one literal recipe array required: ' + name)
    return shlex.split(matches[0])


def verify_sources(recipe_root):
    root = Path(recipe_root).resolve()
    text = (root / 'PKGBUILD').read_text()
    names, hashes = array(text, 'source'), array(text, 'sha256sums')
    need(len(names) == len(set(names)) == len(hashes) == 31 and set(names) == SOURCES, 'exact finite 31-source pins required')
    need(all(Path(name).name == name for name in names), 'makepkg local source basenames required')
    need(array(text, 'noextract') == ['fixture__legacy-v2.tar.gz', 'fixture__previous-v3.tar.gz'], 'closed TEST recipes must not auto-extract')
    need(array(text, 'depends') == DEPENDENCIES, 'exact runtime dependencies required')
    need(array(text, 'arch') == ['any'] and array(text, 'license') == ['MIT'], 'recipe architecture/license')
    need(re.search(r'^pkgname=' + NAME + r'$', text, re.M) and
         re.search(r'^pkgver=0\.4\.0$', text, re.M) and re.search(r'^pkgrel=1$', text, re.M), 'fixed package identity')
    for name, pin in zip(names, hashes):
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'local source path required')
        path = root / name
        need(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'regular local source required')
        need(digest(path) == pin, 'source checksum mismatch: ' + name)
    srcinfo = {}
    for line in (root / '.SRCINFO').read_text().splitlines():
        if ' = ' in line:
            key, value = line.strip().split(' = ', 1); srcinfo.setdefault(key, []).append(value)
    for key, expected in [('pkgbase', [NAME]), ('pkgname', [NAME]), ('pkgver', ['0.4.0']),
                          ('pkgrel', ['1']), ('arch', ['any']), ('license', ['MIT']),
                          ('depends', DEPENDENCIES), ('source', names), ('sha256sums', hashes)]:
        need(srcinfo.get(key) == expected, 'SRCINFO mismatch: ' + key)
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    need(set(provenance['files']) == set(RUNTIME), 'finite nine endpoint plus eight legacy closure required')
    for name, row in provenance['files'].items():
        need({k: row[k] for k in ('bytes', 'sha256', 'installed_path')} == RUNTIME[name], 'fixed merged/frozen runtime identity: ' + name)
        need(name in names and row['license'] == 'MIT' and digest(root / name) == row['sha256']
             and (root / name).stat().st_size == row['bytes'], 'retained code pin: ' + name)
        need(re.fullmatch('[0-9a-f]{40}', row['origin_commit']), 'full source revision required')
    need(digest(root / 'LICENSE') == provenance['license_file_sha256'], 'project MIT license pin')
    payload = json.loads((root / 'payload-map.json').read_bytes())
    need(payload['package'] == NAME and payload['version'] == VERSION and payload['files'] == PAYLOAD,
         'exact finite 23-file payload map required')
    dependencies = json.loads((root / 'endpoint__dependencies.json').read_bytes())
    prefix = 'usr/lib/cachy-asahi/release-tools-v4/endpoint-current/'
    expected = {row['installed_path'].removeprefix(prefix): {k: row[k] for k in ('bytes', 'sha256')}
                for name, row in RUNTIME.items() if name.startswith('endpoint__')
                and name not in ('endpoint__transport.py', 'endpoint__dependencies.json')}
    need(dependencies['schema_version'] == 1 and dependencies['files'] == expected,
         'exact seven-file transport dependency join')
    for name in names:
        if name.endswith('.py') or name == NAME or name == 'legacy__launcher':
            compile((root / name).read_bytes(), name, 'exec')
    return {'sources': len(names), 'runtime_code_files': len(RUNTIME), 'version': VERSION}


def verify_payload(recipe_root, prefix):
    root, prefix = Path(recipe_root), Path(prefix)
    payload = json.loads((root / 'payload-map.json').read_bytes())['files']
    need(payload == PAYLOAD, 'fixed installed payload map')
    need(all(not p.is_symlink() for p in prefix.rglob('*')), 'installed symlink refused')
    paths = {p.relative_to(prefix).as_posix(): p for p in prefix.rglob('*') if not p.is_dir()}
    need(set(paths) == set(payload), 'installed payload set differs')
    parents = {str(parent) for name in payload for parent in Path(name).parents if str(parent) != '.'}
    need({p.relative_to(prefix).as_posix() for p in prefix.rglob('*') if p.is_dir()} == parents,
         'installed directory set differs')
    for name, row in payload.items():
        path = paths[name]
        need(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1 and
             stat.S_IMODE(path.stat().st_mode) == row['mode'] and
             path.read_bytes() == (root / row['source']).read_bytes(), 'installed payload bytes/mode: ' + name)
    return {'files': len(payload), 'version': VERSION}


def stage(recipe_root, prefix):
    root, prefix = Path(recipe_root).resolve(), Path(prefix).absolute()
    verify_sources(root)
    need(not os.path.lexists(prefix) and prefix.parent.is_dir(), 'fresh private staging prefix required')
    with tempfile.TemporaryDirectory(prefix='release-tools-v4-stage-') as temporary:
        sources = Path(temporary) / 'sources'; sources.mkdir(mode=0o700)
        for name in array((root / 'PKGBUILD').read_text(), 'source'):
            path = sources / name; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, path)
        subprocess.run(['bash', '-euc', 'source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; package',
                        'package-stage', str(root), str(sources), str(prefix)], check=True)
    verify_payload(root, prefix)
    return prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify_sources(args.recipe_root), sort_keys=True))


if __name__ == '__main__':
    main()
