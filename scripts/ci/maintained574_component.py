#!/usr/bin/env python3
"""Explicit native daemon cleanup component; never runs an image process."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

HELPER_SHA256 = 'ebf62455e25b5471427224c4df9d75c0c1fd3a0f09a1864596171498740d4527'
NATIVE_SHA256 = 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'
PROCESS_SHA256 = '29c854180f55fe14475329601580e0345b50bc5ab365850c04003fa0b051c1a9'
DOCKERFILE = 'FROM scratch\nCMD ["/component-not-executed"]\n'
CASES = ('normal', 'name-recover', 'foreignref', 'collision', 'unknown-handle-loss')
process = None


def need(value, reason):
    if not value:
        raise ValueError(reason)


def load(name, path, pin):
    need(hashlib.sha256(path.read_bytes()).hexdigest() == pin, 'source binding differs')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def command(argv, log, timeout):
    # Reuse the existing bounded process-group wait/TERM/KILL utility unchanged.
    need(not log.exists(), 'fresh command log required')
    try:
        process.command(argv, log, dict(os.environ), timeout)
        return 0  # Utility observed natural wait exit0; timeout never returns here.
    except process.CommandExit as error:
        return error.code


def invoke(args, log, timeout):
    return command(['/usr/bin/docker', *args], log, timeout)


def container(h, cid, name, image, token):
    need(re.fullmatch('[0-9a-f]{64}', cid), 'invalid created CID')
    rows = json.loads(h.docker('container', 'inspect', cid))
    need(len(rows) == 1, 'ambiguous container')
    row = rows[0]
    need(row['Id'] == cid and row['Name'] == '/' + name and row['Image'] == image
         and row['Config']['Labels'][h.OWNER_LABEL] == token
         and row['State']['Running'] is False and row['State']['Status'] == 'created',
         'created stopped container identity differs')
    return cid


def create(h, out, report, extra=False):
    owner = report['ownership']; token = owner['token']; image = owner['image']
    name = owner['probe_name'] + ('-reference' if extra else '')
    cidfile = out / ('reference-cid' if extra else owner['probe_cidfile'])
    if not extra:
        owner['probe_started'] = True
        h.save_report(out, report)
    rc = invoke(['create', '--pull=never', '--platform=linux/arm64', '--network=none', '--cap-drop=ALL',
                 '--security-opt=no-new-privileges', '--read-only', '--name', name,
                 '--cidfile', str(cidfile), '--label', h.OWNER_LABEL + '=' + token, image],
                out / ('reference-create.log' if extra else 'create.log'), 20)
    # No start/run request and no probe_complete claim, even after create exit0.
    report['reference_create_returncode' if extra else 'create_returncode'] = rc
    h.save_report(out, report)
    need(rc == 0, 'metadata-only create failed; no fallback is permitted')
    cid = cidfile.read_text().strip()
    container(h, cid, name, image, token)
    report['created_reference' if extra else 'created_probe'] = dict(
        id=cid, name=name, image=image, job_label=token, running=False, state='created')
    h.save_report(out, report)
    return cid


def kept(h, report, cid=None):
    owner = report['ownership']; image = owner['image']
    need(h.inspect_image(image, owner['token'])['Id'] == image, 'expected image was not preserved')
    if cid:
        container(h, cid, owner['probe_name'], image, owner['token'])


def cleanup(h, out, token, fd, attempt):
    # The existing cleanup CLI takes its own output-directory lock.
    fcntl.flock(fd, fcntl.LOCK_UN)
    try:
        rc = command([sys.executable, '-B', str(Path(h.__file__).resolve()), 'cleanup',
                      '--inputs', str(Path(h.__file__).parent / 'maintained-desktop574-inputs.json'),
                      '--output', str(out), '--job-token', token],
                     out / ('cleanup-' + attempt + '.log'), 240)
    finally:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result = json.loads((out / 'report.json').read_text())['owned_cleanup']
    need(rc == int(result['status'] != 'PASS'), 'cleanup CLI/result differs')
    return result


def case(h, root, name, token):
    out = root / name; out.mkdir(mode=0o700)
    fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        owner = h.owner_begin(out, token)
        report = dict(scope='METADATA_ONLY_CLEANUP_COMPONENT', ownership=owner,
                      native_574='NOT_RUN', probe_process='NOT_RUN', hardware='NOT_RUN')
        h.save_report(out, report)
        (out / 'home').mkdir(mode=0o700)
        context = out / 'context'; context.mkdir(mode=0o700)
        (context / 'Dockerfile').write_text(DOCKERFILE)
        owner['build_started'] = True; h.save_report(out, report)
        rc = invoke(['build', '--progress=plain', '--network=none', '--pull=false',
                     '--platform=linux/arm64', '--iidfile', str(out / 'image-id'),
                     '--tag', owner['image_tag'], '--label', h.OWNER_LABEL + '=' + token,
                     str(context)], out / 'build.log', 60)
        report['build_returncode'] = rc
        if rc == 0:
            owner['build_complete'] = True
        h.save_report(out, report)
        need(rc == 0, 'metadata-only build failed')
        image = (out / 'image-id').read_text().strip()
        metadata = h.inspect_image(image, token)
        need(metadata['Id'] == image and image not in owner['before_images'], 'new image proof differs')
        need(metadata.get('RepoTags') == [owner['image_tag']] and not metadata.get('RepoDigests'),
             'built image tag/digest differs')
        owner['image'] = image; h.save_report(out, report)
        result = dict(case=name, observed_build_returncode=rc, image=image,
                      image_inspect=dict(architecture=metadata['Architecture'], os=metadata['Os'],
                                         job_label=token, tag=owner['image_tag']),
                      probe_process='NOT_RUN', deliberate_fault=None)
        cid = create(h, out, report)
        result['created_probe'] = report['created_probe']
        if name == 'name-recover':
            (out / 'probe-cid').unlink()
            result['deliberate_fault'] = 'CIDfile removed after real create/inspect; name retained'
        if name == 'collision':
            before = (out / 'report.json').read_bytes()
            fresh = out / 'colliding-output'; fresh.mkdir(mode=0o700)
            try:
                h.owner_begin(fresh, token)
            except ValueError as error:
                need(str(error) == 'job identity collision', 'unexpected collision refusal')
            else:
                raise ValueError('real token collision was admitted')
            need((out / 'report.json').read_bytes() == before and not list(fresh.iterdir()),
                 'collision changed report/output')
            kept(h, report, cid)
            result['collision'] = 'REFUSED_REAL_EXISTING_TAG_LABEL; ORIGINAL_REPORT_BYTES_PRESERVED'
        if name == 'unknown-handle-loss':
            # Genuine CID retained privately, actual container removed, CIDfile withheld.
            (out / 'probe-cid').rename(out / 'withheld-cid')
            container(h, cid, owner['probe_name'], image, token)
            h.docker('rm', cid)
            need(not h.docker('container', 'ls', '-a', '--no-trunc', '--filter',
                              'id=' + cid, '--format', '{{.ID}}'), 'fixture probe remains')
            result['deliberate_fault'] = 'real stopped CID removed; genuine CIDfile withheld; no process interruption'
        reference = create(h, out, report, extra=True) if name == 'foreignref' else None
        if reference:
            result['created_reference'] = report['created_reference']
        first = cleanup(h, out, token, fd, 'first')
        result['first_cleanup'] = first
        if name in ('normal', 'name-recover', 'collision'):
            need(first['status'] == 'PASS', 'normal/name/collision cleanup failed')
        else:
            need(first['status'] == 'FAIL', 'guard cleanup unexpectedly passed')
            kept(h, report)
            if name == 'unknown-handle-loss':
                need(first['probe'] == 'UNKNOWN', 'unknown probe was not refused')
                (out / 'withheld-cid').rename(out / 'probe-cid')
            if reference:
                need(first['probe']['absence_verified'] is True, 'owned probe was not retired first')
                container(h, reference, owner['probe_name'] + '-reference', image, token)
                h.docker('rm', reference)  # Only our independently verified stopped fixture reference.
                need(not h.docker('container', 'ls', '-a', '--no-trunc', '--filter',
                                  'id=' + reference, '--format', '{{.ID}}'), 'fixture reference remains')
            result['final_cleanup'] = cleanup(h, out, token, fd, 'recovery')
            need(result['final_cleanup']['status'] == 'PASS', 'final exact cleanup failed')
        result['status'] = 'PASS'
        report = json.loads((out / 'report.json').read_text())
        report['component_result'] = result; h.save_report(out, report)
        return result
    finally:
        os.close(fd)


def main():
    global process
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(); os.umask(0o077)
    out = args.output.absolute()
    need(not any(p.is_symlink() for p in (out, *out.parents)), 'symlink output forbidden')
    out.mkdir(mode=0o700)  # Fresh only; never resume an UNKNOWN run.
    public = out / 'public'; public.mkdir(mode=0o700)
    result = dict(status='FAIL', scope='METADATA_ONLY_CLEANUP_COMPONENT', cases=[],
                  native_574='NOT_RUN', probe_process='NOT_RUN', hardware='NOT_RUN',
                  helper_sha256=HELPER_SHA256, native_guard_sha256=NATIVE_SHA256,
                  process_utility_sha256=PROCESS_SHA256,
                  source_commit=os.environ.get('COMPONENT_SOURCE_COMMIT'),
                  component_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    save(public / 'component.json', result)
    try:
        need(not any(name.startswith('DOCKER_') for name in os.environ), 'Docker overrides forbidden')
        here = Path(__file__).resolve().parent
        h = load('component_owned574', here / 'maintained_desktop574.py', HELPER_SHA256)
        native = load('component_native_guard', here / 'native_arm.py', NATIVE_SHA256)
        process = load('component_process', here / 'asahi-lsp-build/job.py', PROCESS_SHA256)
        runner = public / 'runner'; runner.mkdir(mode=0o700)
        native.probe(runner)  # Existing native host/daemon/non-root/local-socket guard.
        baseline = h.docker('image', 'ls', '-a', '--no-trunc', '-q').splitlines()
        need(all(re.fullmatch('sha256:[0-9a-f]{64}', image) for image in baseline), 'invalid initial image IDs')
        result['pre_fixture_image_ids'] = sorted(set(baseline))
        for name in CASES:
            result['active_case'] = name; save(public / 'component.json', result)
            result['cases'].append(case(h, out, name, uuid.uuid4().hex[:16]))
            present = h.docker('image', 'ls', '-a', '--no-trunc', '-q').splitlines()
            need(set(baseline) <= set(present), 'pre-fixture image ID lost')
            save(public / 'component.json', result)
        result.pop('active_case'); result.update(status='PASS', pre_fixture_image_ids_preserved=True)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['error_kind'] = type(error).__name__
        if result.get('active_case'):
            try:
                state = json.loads((out / result['active_case'] / 'report.json').read_text())
                result['failure_observations'] = {key: state[key] for key in
                    ('build_returncode', 'create_returncode', 'reference_create_returncode',
                     'ownership', 'created_probe', 'created_reference', 'owned_cleanup') if key in state}
            except (OSError, ValueError) as snapshot_error:
                result['failure_snapshot_error_kind'] = type(snapshot_error).__name__
        # Timed-out clients cannot prove daemon completion. Preserve private records.
        return 1
    finally:
        save(public / 'component.json', result)


if __name__ == '__main__':
    raise SystemExit(main())
