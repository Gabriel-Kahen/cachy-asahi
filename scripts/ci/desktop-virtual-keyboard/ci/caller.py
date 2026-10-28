#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CI source proof and bounded public retention; never launches build/VM actors."""
import argparse
import hashlib
import importlib.util
import sys
import json
import os
from pathlib import Path
import re
import shutil
import stat

MAX_TOTAL = 128 * 1024**2
VIEWS=('shell','editor','result')
FRAMES=tuple(stage+'-'+view for stage in ('minimal','overlay') for view in VIEWS)
SLICE = 'scripts/ci/desktop-virtual-keyboard'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, cap):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'public/source symlink refused')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size <= cap,
         'missing/unsafe/oversized public file: ' + path.name)
    return info


def read_json(path, cap=16 * 1024**2):
    regular(path, cap)
    return json.loads(path.read_text())


def verify_files(workspace, files):
    for relative, row in files.items():
        path = Path(relative)
        need(not path.is_absolute() and '..' not in path.parts, 'unsafe manifest path')
        target = workspace / path
        need(not any(p.is_symlink() for p in (target, *target.parents)), 'source symlink refused')
        info = regular(target, 16 * 1024**2)
        need(info.st_size == row['bytes'] and digest(target) == row['sha256'], 'source pin differs: ' + relative)


def prove(workspace, manifest, environment):
    source = environment['SOURCE_SHA']
    need(re.fullmatch('[0-9a-f]{40}', source) and
         source == environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'],
         'explicit source/workflow revision must agree')
    need(environment['RUNNER_ARCH'] == 'ARM64' and environment['RUNNER_OS'] == 'Linux', 'native ARM runner required')
    run, attempt = environment['GITHUB_RUN_ID'], environment['GITHUB_RUN_ATTEMPT']
    need(re.fullmatch('[1-9][0-9]{0,19}', run) and re.fullmatch('[1-9][0-9]{0,9}', attempt), 'run identity differs')
    verify_files(workspace, manifest['files'])
    token = hashlib.sha256(('desktop-virtual-keyboard:' + run + ':' + attempt + ':' + source).encode()).hexdigest()[:16]
    return dict(status='SOURCE_PROOF_PASS', source_sha=source, workflow_sha=source,
                run_id=run, run_attempt=attempt, source_files=len(manifest['files']), job_token=token)


def frame(path):
    info = regular(path, 8 * 1024**2)
    with path.open('rb') as stream:
        header = stream.read(64)
    match = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', header)
    need(match is not None, 'invalid QMP PPM header')
    width, height = map(int, match.groups())
    need((width, height) == (1024, 768) and info.st_size == match.end() + width * height * 3,
         'invalid QMP PPM geometry/length')
    return dict(width=width, height=height, bytes=info.st_size, sha256=digest(path), visual_review='NOT_RUN')


def retain(base, runtime, proof, output):
    need(not output.exists() and not output.is_symlink(), 'fresh public retention directory required')
    output.mkdir(mode=0o700)
    result = dict(status='NOT_ACCEPTED', files={}, frames={}, failure_frames={}, errors=[], native_scope='GENERIC_ARM_ONLY',
                  hardware='NOT_RUN', battery='NOT_RUN', audio='NOT_RUN', visual_review='NOT_RUN',
                  workflow_scope='managed-virtual-keyboard',
                  physical_input='NOT_RUN', terminal_exit='UNOBSERVED_NONCHILD',
                  managed_session='PENDING', GUI='PIXELS_PENDING_REVIEW')
    total = 0

    def copy(source, relative, cap, required=False):
        nonlocal total
        if not source.exists() and not source.is_symlink() and not required:
            return
        try:
            info = regular(source, cap)
            need(total + info.st_size <= MAX_TOTAL, 'public retention total byte limit')
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            total += info.st_size
            result['files'][relative] = dict(bytes=info.st_size, sha256=digest(target))
        except Exception as error:
            result['errors'].append(str(error)[:512])

    copy(proof, 'source-proof.json', 128 * 1024, required=True)
    for name, cap in (('report.json', 512 * 1024), ('seed-report.json', 16 * 1024),
                      ('installed-packages.lock', 256 * 1024)):
        copy(base / name, 'base/' + name, cap, required=name != 'seed-report.json')
    for name, cap in (('runtime.json', 16 * 1024**2), ('guest.log', 8 * 1024**2),
                      ('events.log', 8 * 1024**2), ('configuration.log', 16 * 1024**2),
                      ('package-build.log', 16 * 1024**2), ('base-reference.log', 16 * 1024**2),
                      ('runtime-image.log', 16 * 1024**2), ('fixture.log', 16 * 1024**2),
                      ('package/provenance.json', 2 * 1024**2), ('package/validation.json', 2 * 1024**2),
                      ('package/expected-packages.lock', 256 * 1024), ('config/desktop/desktop.json', 2 * 1024**2)):
        copy(runtime / name, 'runtime/' + name, cap, required=name in ('runtime.json', 'guest.log', 'events.log'))
    for index in range(24):
        name = 'config/desktop/command-' + str(index) + '.txt'
        copy(runtime / name, 'runtime/' + name, 1024**2)
    for stage in FRAMES:
        path = runtime / 'frames' / (stage + '.ppm')
        try:
            result['frames'][stage] = frame(path)
        except Exception as error:
            result['errors'].append(stage + ': ' + str(error)[:512])
        copy(path, 'frames/' + stage + '.ppm', 8 * 1024**2, required=True)
    # Two optional, fixed failure-only leaves. They never count toward six success captures.
    for phase in ('minimal','overlay'):
        path=runtime/'frames'/(phase+'-failure.ppm')
        if not path.exists() and not path.is_symlink():continue
        try:
            result['failure_frames'][phase]=dict(frame(path),diagnostic_only=True,success_evidence=False)
        except Exception as error:result['errors'].append(phase+' failure capture: '+str(error)[:512])
        copy(path,'frames/'+phase+'-failure.ppm',8*1024**2)
    try:
        original = read_json(base / 'report.json', 512 * 1024)
        report = read_json(runtime / 'runtime.json')
        source_proof = read_json(proof, 128 * 1024)
        need(source_proof['status'] == 'SOURCE_PROOF_PASS' and source_proof['generated_runner'] == 'PASS',
             'source/generated-runner proof absent')
        need(original['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and original.get('packages')==574 and
             original['owned_cleanup']['status'] == 'PASS', 'base build/owned cleanup did not pass')
        need(digest(base/'installed-packages.lock')=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac', 'exact held574 installed lock differs')
        need(original['ownership']['token'] == source_proof['job_token'], 'base owner token differs')
        need(original['owned_cleanup']['image'] == dict(id=original['image'], absence_verified=True) and
             original['owned_cleanup']['probe']['absence_verified'] is True, 'base resource absence unproved')
        need(report['status']=='PASS_MANAGED_VIRTUAL_KEYBOARD_METADATA' and
             report['configuration']=='desktop-container-verifier-pass' and
             report.get('workflow_scope')=='managed-virtual-keyboard' and
             report.get('physical_input')=='NOT_RUN', 'installed GUI metadata acceptance absent')
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        spec=importlib.util.spec_from_file_location('public_keyboard_contract',Path(__file__).resolve().parents[1]/'contract.py')
        contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
        observed=contract.verify_result(report['events'])
        need(observed==report['keyboard_contract'],'replayed keyboard event contract differs')
        need(report['base_image'] == original['image'] and report['runtime_package_count'] == 591,
             'base/runtime composition differs')
        need(len(report['cleanup']) == 14 and report['base_reference_cleanup']['ok'] is True and
             all(row.get('exit') == 0 for row in report['cleanup'] if 'guest_disk_removed' not in row) and
             any(row.get('guest_disk_removed') is True for row in report['cleanup']), 'runtime cleanup incomplete')
        need(set(report['frames'])==set(FRAMES),'exact runtime capture set differs')
        for stage in FRAMES:
            need(result['frames'][stage]['sha256'] == report['frames'][stage]['sha256'], 'captured frame hash differs')
        need(not result['failure_frames'] and not report.get('failure_frames') and not result['errors'], 'public retention incomplete or contains failure diagnostics')
        result.update(managed_session=observed['managed_session'])
        result['status'] = 'PASS_KEYBOARD_METADATA_PIXELS_PENDING_VISUAL_REVIEW'
    except Exception as error:
        result['errors'].append(str(error)[:512])
    result['total_bytes'] = total
    (output / 'retention.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('proof', 'stage', 'retain'))
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.phase == 'proof':
        result = prove(args.workspace.resolve(), read_json(args.manifest, 512 * 1024), os.environ)
        result['manifest_sha256'] = digest(args.manifest)
        with args.proof.open('x') as stream:
            json.dump(result, stream, indent=2);stream.write('\n')
        args.proof.chmod(0o600)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('job_token=' + result['job_token'] + '\n')
    elif args.phase == 'stage':
        manifest = read_json(args.manifest, 512 * 1024)
        verify_files(args.workspace.resolve(), manifest['generated_runner'])
        result = read_json(args.proof, 128 * 1024)
        need(result['manifest_sha256'] == digest(args.manifest), 'stage/source manifest differs')
        result['generated_runner'] = 'PASS'
        args.proof.write_text(json.dumps(result, indent=2) + '\n')
    else:
        result = retain(args.base, args.runtime, args.proof, args.output)
    print(json.dumps(result, indent=2))
    return int(result['status'] not in ('SOURCE_PROOF_PASS', 'PASS_KEYBOARD_METADATA_PIXELS_PENDING_VISUAL_REVIEW'))


if __name__ == '__main__':
    raise SystemExit(main())
