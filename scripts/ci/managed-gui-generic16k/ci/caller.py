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
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery')
FRAMES=tuple(stage+'-'+view for stage in ('minimal','overlay') for view in VIEWS)
SLICE = 'scripts/ci/managed-gui-generic16k'


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


def verify_kernel_contract_pin(manifest):
    source = manifest['files'].get(SLICE + '/kernel_contract.py')
    need(source is not None and manifest.get('generated_runner', {}).get('kernel_contract.py') == source,
         'copied kernel_contract.py source/generated pins differ')


def prove(workspace, manifest, environment):
    source = environment['SOURCE_SHA']
    need(re.fullmatch('[0-9a-f]{40}', source) and
         source == environment['GITHUB_SHA'] == environment['GITHUB_WORKFLOW_SHA'],
         'explicit source/workflow revision must agree')
    need(environment['RUNNER_ARCH'] == 'ARM64' and environment['RUNNER_OS'] == 'Linux', 'native ARM runner required')
    run, attempt = environment['GITHUB_RUN_ID'], environment['GITHUB_RUN_ATTEMPT']
    need(re.fullmatch('[1-9][0-9]{0,19}', run) and re.fullmatch('[1-9][0-9]{0,9}', attempt), 'run identity differs')
    verify_files(workspace, manifest['files'])
    verify_kernel_contract_pin(manifest)
    token = hashlib.sha256(('managed-gui-generic16k:' + run + ':' + attempt + ':' + source).encode()).hexdigest()[:16]
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


def retain(base, runtime, proof, output, runner, manifest_path, kernel_work=None, acquisition=None, seed=None):
    need(not output.exists() and not output.is_symlink(), 'fresh public retention directory required')
    output.mkdir(mode=0o700)
    result = dict(status='NOT_ACCEPTED', files={}, frames={}, errors=[], native_scope='GENERIC_ARM_ONLY',
                  hardware='NOT_RUN', battery='NOT_RUN', audio='NOT_RUN', visual_review='NOT_RUN',
                  workflow_scope='installed-welcome-doctor-managed-gui', diagnostic_scope='GENERIC_ARM64_16K_SOFTWARE_FIXTURE_ONLY',
                  physical_input='NOT_RUN', terminal_action_exit='UNOBSERVED_NONCHILD',
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
    copy(runtime/'elf16k.json','runtime/elf16k.json',16*1024**2,required=True)
    copy(runtime/'controller.log','runtime/controller.log',16*1024**2)
    copy(runner/'kernel-profile.json','runtime/kernel-profile.json',65536,required=True)
    if acquisition is not None:copy(acquisition,'kernel/acquisition.json',16384,required=True)
    if seed is not None:copy(seed,'kernel/retained-source-seed.json',16384)
    if kernel_work is not None:
        for name,cap in (('build-receipt.json',65536),('build/.config',262144)):
            copy(kernel_work/'helper/built'/name,'kernel/'+Path(name).name,cap)
        for name in ('configure.log','build.log'):
            path=kernel_work/'helper/built'/name
            if path.exists():
                try:
                    regular(path,16*1024**2)
                    with path.open('rb') as stream:stream.seek(max(0,path.stat().st_size-8192));raw=stream.read(8192)
                    target=output/'kernel'/(name+'.tail');target.parent.mkdir(exist_ok=True);target.write_bytes(raw)
                    total+=len(raw);result['files']['kernel/'+name+'.tail']=dict(bytes=len(raw),sha256=digest(target))
                except Exception as error:result['errors'].append(str(error)[:512])
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
    try:
        original = read_json(base / 'report.json', 512 * 1024)
        report = read_json(runtime / 'runtime.json')
        source_proof = read_json(proof, 128 * 1024)
        need(source_proof['status'] == 'SOURCE_PROOF_PASS' and source_proof['generated_runner'] == 'PASS',
             'source/generated-runner proof absent')
        need(original['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and
             original['owned_cleanup']['status'] == 'PASS', 'base build/owned cleanup did not pass')
        need(original['ownership']['token'] == source_proof['job_token'], 'base owner token differs')
        need(original['owned_cleanup']['image'] == dict(id=original['image'], absence_verified=True) and
             original['owned_cleanup']['probe']['absence_verified'] is True, 'base resource absence unproved')
        need(report['status']=='PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_REVIEW' and
             report['configuration']=='desktop-container-verifier-pass' and
             report.get('workflow_scope')=='installed-welcome-doctor-managed-gui' and
             report.get('physical_input')=='NOT_RUN', 'installed GUI metadata acceptance absent')
        lock=report['candidate_input']
        need(lock['eligibility']=='PRIVATE_GUI_TRIAL_ONLY' and
             lock['transport']['checkout_source']=='8a38b3fd5963e61fc94707dd87e5dcd626a518a3' and
             lock['transport']['index_sha256']=='3d200c4cd19bd7ca15426ae34617bb4fad6c83b194f1d25533ad9f462c9c0580' and
             lock['producer_lifecycle']=='FAIL_USER_PRESERVATION_CHECK', 'frozen candidate transport/history differs')
        manifest=read_json(manifest_path,512*1024)
        need(source_proof['manifest_sha256']==digest(manifest_path),'retention source manifest differs')
        verify_files(runner,manifest['generated_runner'])
        sys.path.insert(0,str(runner))
        spec=importlib.util.spec_from_file_location('public_welcome_gui16k_contract',runner/'contract.py')
        contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
        observed=contract.verify_result(report['events'],lock)
        need(observed==report['gui_contract'],'replayed GUI event contract differs')
        need(report['base_image'] == original['image'] and report['runtime_package_count'] == 593,
             'base/runtime composition differs')
        need(len(report['cleanup']) == 14 and report['base_reference_cleanup']['ok'] is True and
             all(row.get('exit', 0) == 0 for row in report['cleanup']) and
             any(row.get('guest_disk_removed') is True for row in report['cleanup']), 'runtime cleanup incomplete')
        for stage in FRAMES:
            need(result['frames'][stage]['sha256'] == report['frames'][stage]['sha256'], 'captured frame hash differs')
        kernel=observed['diagnostic_kernel']
        need(kernel==report['diagnostic_kernel'] and kernel['page_size']==16384 and
             report['kernel_work_removed'] is True and report['runtime_Image_removed'] is True and
             report['producer_cleanup']==original['owned_cleanup'] and report['job_token']==source_proof['job_token'] and
             report['source_sha']==source_proof['source_sha'] and report['controller']['natural_exit'] is True and
             report['controller']['group_absent'] is True and report['controller']['exit']==0 and
             report['controller_runtime_status']=='PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_GENERIC16K_METADATA',
             'exact16K kernel/controller/ordered cleanup join absent')
        built=report['kernel_build'];cfg=report['kernel_config'].encode()
        need(built['status']=='BUILT_ONLY' and built['kernel_build']=='PASS' and built['profile']==kernel['profile'] and
             built['helper']['sha256']==kernel['helper_sha256'] and built['fragment']['sha256']==kernel['fragment_sha256'] and
             built['diagnostic_fragment']['sha256']==kernel['diagnostic_fragment_sha256'] and
             built['image']['sha256']==kernel['Image']['sha256'] and built['image']['bytes']==kernel['Image']['bytes'] and
             len(cfg)==kernel['config']['bytes'] and hashlib.sha256(cfg).hexdigest()==kernel['config']['sha256'] and
             built['config']['sha256']==kernel['config']['sha256'],'retained build/Image/config binding differs')
        acquired=read_json(acquisition,16384)
        paths={'RESTORED_HASH_VERIFIED':'HIT_HASH_VERIFIED',
               'RETAINED_ARCHIVE_HASH_VERIFIED':'MISS_RETAINED_ARCHIVE_HASH_VERIFIED',
               'FETCHED_HASH_VERIFIED':'MISS_FETCHED_HASH_VERIFIED'}
        mode=acquired.get('status');cache=acquired.get('cache',{})
        need(mode in paths and cache.get('status')==paths[mode] and
             cache.get('key')=='asahi-kernel-source-v1-'+kernel['archive_sha256']+'-262965559' and
             acquired.get('source_revision')==kernel['source_revision'] and
             acquired.get('sha256')==kernel['archive_sha256'] and acquired.get('bytes')==262965559 and
             acquired.get('partial_absent') is True and acquired.get('cache_partial_absent') is True and
             acquired['result']['sha256']==kernel['archive_sha256'] and acquired['result']['bytes']==262965559,
             'exact reusable archive acquisition/receipt join absent')
        if mode!='RESTORED_HASH_VERIFIED':
            seeded=read_json(seed,16384)
            need(seeded.get('asset_id')==647949735 and seeded.get('release_id')==415175342 and
                 seeded.get('expected_sha256')==kernel['archive_sha256'] and seeded.get('expected_bytes')==262965559 and
                 seeded.get('release_draft') is False and seeded.get('release_prerelease') is True and
                 seeded.get('natural_exit') is True and seeded.get('group_absent') is True and seeded.get('partial_absent') is True and
                 seeded.get('release_admission') is False,'fixed retained-source seed identity/custody absent')
            if mode=='RETAINED_ARCHIVE_HASH_VERIFIED':
                need(seeded.get('status')=='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED' and seeded.get('exit')==0 and
                     seeded.get('sha256')==kernel['archive_sha256'] and seeded.get('bytes')==262965559,'exact retained source bytes absent')
            else:
                need(seeded.get('status')=='RETAINED_ASSET_UNAVAILABLE' and type(seeded.get('exit')) is int and seeded['exit']>0,
                     'true-miss direct fallback lacks retained-source unavailability receipt')
        elf=read_json(runtime/'elf16k.json')
        need(elf['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT' and
             digest(runtime/'elf16k.json')==report['elf16k']['sha256'] and
             len(elf['ELF'])==report['elf16k']['ELFs'] and
             {'usr/bin/cachy-asahi-welcome','usr/bin/python3.14','usr/lib/systemd/systemd',
              'usr/local/bin/gbm-probe','usr/local/bin/welcome-a11y'}<={r['path'] for r in elf['ELF']},'full installed-tree ELF16K gate absent')
        need(not result['errors'], 'public retention incomplete')
        result.update(managed_session=observed['managed_session'],producer_input_lifecycle=lock['producer_lifecycle'])
        result['status'] = 'PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_VISUAL_REVIEW'
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
    for name in ('runner','kernel-work','acquisition','seed'):parser.add_argument('--'+name,type=Path)
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
        result = retain(args.base, args.runtime, args.proof, args.output,args.runner,args.manifest,args.kernel_work,args.acquisition,args.seed)
    print(json.dumps(result, indent=2))
    return int(result['status'] not in ('SOURCE_PROOF_PASS', 'PASS_GENERIC16K_INSTALLED_GUI_METADATA_PIXELS_PENDING_VISUAL_REVIEW'))


if __name__ == '__main__':
    raise SystemExit(main())
