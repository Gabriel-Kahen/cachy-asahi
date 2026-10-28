#!/usr/bin/env python3
"""Version 2: build reviewed recipes in fresh, pinned OCI containers; never install on host."""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_materials

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))
from package_checks import digest, package, recipe, conflicts, metadata, FIELDS, ARCH_FIELDS


def capture(command):
    return subprocess.check_output(command, text=True).strip()


def image_pin(value):
    if not re.fullmatch(r'(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}', value):
        raise argparse.ArgumentTypeError('image must be repository@sha256:<64 hex> or sha256:<image ID>; tags are forbidden')
    return value


def normalize_metadata(data):
    """Complete effective single-package input; absent fields are significant."""
    if len(data.get('pkgname', [])) != 1:
        raise ValueError('split packages are unsupported')
    result = {}
    for key in FIELDS:
        if key.endswith('_aarch64'):
            continue
        values = list(data.get(key, []))
        if key in ARCH_FIELDS:
            values += data.get(key + '_aarch64', [])
        result[key] = values if key in ('source', 'sha256sums') else sorted(values)
    result['epoch'] = data.get('epoch', ['0'])
    result['pkgbase'] = data.get('pkgbase', data['pkgname'])
    return result


def bind_generated(reviewed, generated):
    left, right = normalize_metadata(reviewed), normalize_metadata(generated)
    for key in left:
        if left[key] != right[key]:
            raise ValueError(f'isolated generated metadata differs from reviewed {key}')


def bind_artifact(reviewed, report, recipe_hash):
    data = normalize_metadata(reviewed)
    pkg = report['metadata'].get('.PKGINFO', {})
    version = data['pkgver'][0] + '-' + data['pkgrel'][0]
    if data['epoch'][0] != '0':
        version = data['epoch'][0] + ':' + version
    expected = {'pkgname': data['pkgname'], 'pkgbase': data['pkgbase'],
                'pkgver': [version], 'arch': data['arch'], 'license': data['license']}
    mapping = {'depends': 'depend', 'makedepends': 'makedepend', 'checkdepends': 'checkdepend',
               'optdepends': 'optdepend', 'provides': 'provides', 'conflicts': 'conflict',
               'replaces': 'replaces', 'backup': 'backup'}
    for source, target in mapping.items():
        expected[target] = data[source]
    errors = [f'artifact metadata differs from reviewed {key}' for key, values in expected.items()
              if sorted(pkg.get(key, [])) != sorted(values)]
    actual_hash = report['metadata'].get('.BUILDINFO', {}).get('pkgbuild_sha256sum', [])
    if actual_hash != [recipe_hash]:
        errors.append('artifact .BUILDINFO differs from reviewed PKGBUILD hash')
    if ('.INSTALL' in report['members']) != bool(data['install']):
        errors.append('artifact installation hook differs from reviewed metadata')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('recipe', type=Path, help='recipe directory')
    parser.add_argument('--image', required=True, type=image_pin)
    parser.add_argument('--output', type=Path, required=True, help='new evidence directory')
    parser.add_argument('--mode', choices=('native', 'emulated'), required=True)
    parser.add_argument('--source-date-epoch', type=int, required=True)
    parser.add_argument('--network', choices=('none', 'bridge'), default='none')
    parser.add_argument('--timeout', type=int, default=3600)
    parser.add_argument('--expected-packages', type=Path, required=True,
                        help='reviewed sorted pacman -Q lock from the pinned image')
    parser.add_argument('--reviewed-inputs', type=Path, required=True,
                        help='reviewed input_sha256 object from static recipe report')
    parser.add_argument('--source-plan', type=Path, help='opt-in reviewed offline source binding plan')
    parser.add_argument('--source-plan-sha256', help='independently reviewed source plan SHA-256')
    parser.add_argument('--source-catalog', type=Path, help='source_cache input catalog bound by the plan')
    parser.add_argument('--source-cache', type=Path, help='existing private source_cache directory; offline verification only')
    args = parser.parse_args()
    evidence = {'schema_version': 1, 'status': 'preflight-failed', 'hardware_status': 'NOT RUN',
                'mode': args.mode, 'image': args.image, 'source_date_epoch': args.source_date_epoch,
                'network': args.network, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    out = args.output.resolve()
    created = False
    try:
        if args.source_date_epoch < 0 or args.timeout < 1:
            raise ValueError('epoch must be nonnegative and timeout positive')
        base = args.recipe.resolve()
        if not base.is_dir():
            raise ValueError('recipe directory missing')
        if any(',' in str(p) or '\n' in str(p) for p in (base, out, args.expected_packages.resolve())):
            raise ValueError('bind mount paths cannot contain commas/newlines')
        if out.is_relative_to(base):
            raise ValueError('output must be outside recipe directory')
        report = recipe(base / 'PKGBUILD')
        if report['errors']:
            raise ValueError('; '.join(report['errors']))
        expected = json.loads(args.reviewed_inputs.read_text())
        if expected != report['input_sha256']:
            raise ValueError('recipe inputs differ from independently reviewed digest set')
        source_options = (args.source_plan, args.source_plan_sha256, args.source_catalog, args.source_cache)
        if any(value is not None for value in source_options) and not all(value is not None for value in source_options):
            raise ValueError('offline sources require plan, plan checksum, catalog and cache together')
        prepared_sources = None
        if args.source_plan is not None:
            if args.network != 'none':
                raise ValueError('offline source staging requires --network none')
            prepared_sources = source_materials.prepare(report, *source_options)
        lock = args.expected_packages.read_text()
        if not lock.strip() or lock != ''.join(sorted(lock.splitlines(keepends=True))):
            raise ValueError('expected package lock must be nonempty and sorted')
        image = json.loads(capture(['docker', 'image', 'inspect', args.image]))[0]
        if image['Architecture'] != 'arm64' or image['Os'] != 'linux':
            raise ValueError('builder image is not linux/arm64')
        host_arch = capture(['docker', 'info', '--format', '{{.Architecture}}'])
        native = host_arch in ('aarch64', 'arm64')
        if native != (args.mode == 'native'):
            raise ValueError(f'mode {args.mode} contradicts Docker server architecture {host_arch}')
        # A fresh unique directory prevents stale output from satisfying success gates.
        out.mkdir(mode=0o700 if prepared_sources else 0o777, parents=True, exist_ok=False)
        created = True
        inputs = out / 'inputs'
        shutil.copytree(base, inputs, symlinks=False)
        snapshot = recipe(inputs / 'PKGBUILD')
        if snapshot['input_sha256'] != report['input_sha256']:
            raise ValueError('recipe inputs changed during snapshot')
        if prepared_sources:
            material_dir = out / 'source-material'
            evidence['source_material'] = source_materials.stage(prepared_sources, material_dir)
            evidence['files'] = {str(p.relative_to(out)): digest(p)
                                 for p in sorted(material_dir.rglob('*')) if p.is_file()}
        evidence.update({'recipe_inputs': report['input_sha256'], 'recipe_metadata': report['metadata'],
                         'builder_host_arch': host_arch, 'image_id': image['Id'],
                         'expected_packages_sha256': digest(args.expected_packages), 'status': 'building'})
        expected_lock = out / 'expected-packages.lock'
        expected_lock.write_text(lock)
        evidence['expected_packages_sha256'] = digest(expected_lock)
        artifacts = out / 'artifacts'
        artifacts.mkdir()
        entry = Path(__file__).with_name('container-entry-v2.sh').resolve()
        evidence['entry_script_sha256'] = digest(entry)
        name = 'cachy-asahi-' + os.urandom(8).hex()
        command = ['docker', 'run', '--rm', '--name', name, '--pull=never',
                   '--platform', 'linux/arm64', '--user', f'{os.getuid()}:{os.getgid()}',
                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                   '--pids-limit', '512', '--memory', '4g', '--cpus', '4',
                   '--network', args.network, '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g',
                   '--env', 'CACHY_ASAHI_CONTAINER=1', '--env', f'SOURCE_DATE_EPOCH={args.source_date_epoch}',
                   '--mount', f'type=bind,src={inputs},dst=/inputs,readonly',
                   '--mount', f'type=bind,src={artifacts},dst=/out',
                   '--mount', f'type=bind,src={entry},dst=/builder-entry.sh,readonly',
                   '--mount', f'type=bind,src={expected_lock},dst=/expected-packages.lock,readonly',
                   '--entrypoint', '/bin/bash', args.image, '/builder-entry.sh']
        if prepared_sources:
            # Insert Docker controls before --entrypoint/image, never as recipe arguments.
            index = command.index('--entrypoint')
            command[index:index] = ['--env', 'CACHY_ASAHI_OFFLINE_SOURCES=1', '--mount',
                f'type=bind,src={material_dir / "srcdest"},dst=/offline-sources,readonly']
        evidence['command'] = command
        evidence['clean_environment_id'] = name
        (out / 'provenance.json').write_text(json.dumps(evidence, indent=2) + '\n')
        try:
            with (out / 'build.log').open('wb') as log:
                completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
            evidence['exit_code'] = completed.returncode
        except subprocess.TimeoutExpired:
            # Stop only this uniquely named container, never global Docker jobs.
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            raise ValueError('builder timeout; this build container was removed')
        if completed.returncode:
            raise ValueError(f'container build exited {completed.returncode}; see build.log')
        required_outputs = ('environment.txt', 'packages.lock', 'config.sha256', 'makepkg.conf',
                            'pacman.conf', 'generated.SRCINFO')
        if any(not (artifacts / name).is_file() for name in required_outputs):
            raise ValueError('missing required builder environment/config/metadata evidence')
        if any(p.is_symlink() for p in artifacts.rglob('*')):
            raise ValueError('symlink builder output forbidden')
        if (artifacts / 'packages.lock').read_text() != lock:
            raise ValueError('builder package inventory differs from approved lock')
        generated = metadata((artifacts / 'generated.SRCINFO').read_text())
        bind_generated(report['metadata'], generated)
        paths = sorted(p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig'))
        if not paths:
            raise ValueError('builder produced no packages')
        reports = [package(path) for path in paths]
        errors = conflicts(reports) + [error for r in reports for error in r['errors']]
        for result in reports:
            errors.extend(bind_artifact(report['metadata'], result, report['input_sha256']['PKGBUILD']))
        if len(reports) != 1:
            errors.append('single-package recipe must produce exactly one artifact')
        (out / 'validation.json').write_text(json.dumps({'artifacts': reports, 'errors': errors}, indent=2) + '\n')
        if errors:
            raise ValueError('; '.join(errors))
        evidence['artifacts'] = {p.name: digest(p) for p in paths}
        evidence.setdefault('files', {}).update({str(p.relative_to(out)): digest(p)
                                                for p in sorted(artifacts.iterdir()) if p.is_file()})
        evidence['files']['expected-packages.lock'] = digest(expected_lock)
        evidence['files']['build.log'] = digest(out / 'build.log')
        evidence['files']['validation.json'] = digest(out / 'validation.json')
        evidence['status'] = 'built-package-static-pass'
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, tarfile.TarError) as error:
        evidence.update({'status': 'failed', 'error': str(error)})
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if created:
            evidence['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            (out / 'provenance.json').write_text(json.dumps(evidence, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
