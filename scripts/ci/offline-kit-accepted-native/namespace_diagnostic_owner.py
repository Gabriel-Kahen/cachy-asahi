#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit existing-image namespace diagnostic. Never bootstrap or transact packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
LANE = 'scripts/ci/offline-kit-accepted-native'
MAP = LANE + '/source-map.json'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def raw_file(path, limit=16 * 1024**2):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit
         and not any(p.is_symlink() for p in path.parents), 'bounded ordinary diagnostic input')
    raw = path.read_bytes()
    need(len(raw) == info.st_size, 'stable diagnostic input size')
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def owner_module(args):
    """Join the explicit external map pin before executing the held owner module."""
    need(args.execute is True, 'explicit --execute required; no actor fallback')
    need(type(args.manifest_sha256) is str and re.fullmatch('[0-9a-f]{64}', args.manifest_sha256),
         'current exact Source map pin required')
    raw = raw_file(ROOT / MAP)
    need(digest(raw) == args.manifest_sha256, 'current exact Source map bytes')
    manifest = json.loads(raw)
    need(manifest['schema'] == 1 and manifest['actual'] is None, 'source-only map required')
    bodies = {}
    for name in ('namespace_diagnostic_owner.py', 'owner.py', 'owner_common.py'):
        path = HERE / name
        body = raw_file(path)
        need(manifest['files'][LANE + '/' + name] == dict(bytes=len(body), sha256=digest(body),
             mode=stat.S_IMODE(path.stat().st_mode)), 'same mapped diagnostic owner closure')
        bodies[name] = body
    module = types.ModuleType('_namespace_diagnostic_held_owner')
    module.__file__ = str(HERE / 'owner.py')
    exec(compile(bodies['owner.py'], module.__file__, 'exec'), module.__dict__)
    return module


def prerequisites(owner, args):
    """All local admission checks precede actor construction and fresh output."""
    manifest, own, temporary = owner.admitted(args)
    C = owner.C
    work = C.safe_path(args.work)
    info = work.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'ordinary private same-owner work root')
    proof = C.load(work / 'source-proof.json')
    need(proof['status'] == 'PASS_PRESECRET_COMPLETE_ACCEPTED_TOOLS_SOURCE'
         and proof['identity'] == own and proof['map_sha256'] == args.manifest_sha256
         and type(proof['files']) is int and proof['files'] == len(manifest['files']) + 3
         and proof['native'] == 'NOT_RUN', 'complete current presecret Source proof required')
    need(not any(os.path.lexists(work / n) for n in
         ('kit-actors', 'kit-results.json', 'maintenance', 'diagnostics', 'ordered-cleanup.json')),
         'diagnostic must precede every kit transaction and image retirement')
    bootstrap = C.load(work / 'bootstrap.json')
    need(bootstrap['status'] == 'PASS_ACTUAL_FRESH_ACCEPTED574_PRODUCER'
         and bootstrap['identity'] == own and type(bootstrap['image']) is str
         and re.fullmatch('sha256:[0-9a-f]{64}', bootstrap['image']),
         'existing same-owner immutable574 bootstrap receipt required')
    base = temporary / 'desktop574'
    report = C.load(base / 'report.json')
    held = report['ownership']
    image = bootstrap['image']
    need(report['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and report['native_build'] == 'PASS'
         and report['image'] == held['image'] == image and held['token'] == own['token']
         and all(held[k] is True for k in ('build_started', 'build_complete', 'probe_started', 'probe_complete'))
         and type(report['build_returncode']) is int and report['build_returncode'] == 0
         and 'owned_cleanup' not in report, 'unretired successful original574 ownership required')
    need(C.read(base / 'image-id') in (image.encode(), (image + '\n').encode())
         and C.sha(C.read(base / 'installed-packages.lock')) == owner.LOCK
         and C.sha(C.read(HERE / 'expected-packages.lock')) == owner.LOCK,
         'existing immutable574 image and exact inventory join')
    helper = C.read(HERE / 'trial-code/namespace_diagnostic.py')
    need(manifest['files'][LANE + '/trial-code/namespace_diagnostic.py'] ==
         dict(bytes=len(helper), sha256=C.sha(helper),
              mode=stat.S_IMODE((HERE / 'trial-code/namespace_diagnostic.py').stat().st_mode)),
         'same Source diagnostic helper')
    C.candidate_policy()
    need(not os.path.lexists(work / 'namespace-diagnostic'), 'one-shot fresh diagnostic namespace required')
    return manifest, own, work, image, C.sha(helper), report



def captured_output(C, output, context_sha, helper_sha):
    allowed = {'namespace-context.json', 'namespace-parent.json', 'namespace-child.json',
               'namespace-status.json', 'namespace-supervisor/command.log'}
    files = {}; total = 0; dirs = set()
    for folder, children, names in os.walk(output, followlinks=False):
        for name in children:
            path = Path(folder) / name
            need(not path.is_symlink() and path.relative_to(output).as_posix() == 'namespace-supervisor',
                 'finite ordinary diagnostic directory')
            dirs.add(path.relative_to(output).as_posix())
        for name in names:
            path = Path(folder) / name; relative = path.relative_to(output).as_posix()
            need(relative in allowed, 'finite diagnostic output leaf')
            raw = C.read(path); total += len(raw)
            need(total <= 20 * 1024**2, 'bounded diagnostic output total')
            files[relative] = dict(bytes=len(raw), sha256=C.sha(raw))
    need({'namespace-context.json', 'namespace-parent.json', 'namespace-status.json'} <= set(files)
         and dirs == ({'namespace-supervisor'} if 'namespace-supervisor/command.log' in files else set()),
         'complete finite diagnostic output namespace')
    status = C.load(output / 'namespace-status.json')
    need(type(status['schema_version']) is int and status['schema_version'] == 1
         and status['status'] == 'CAPTURED_NAMESPACE_DIAGNOSTIC_ONLY'
         and status['context_sha256'] == context_sha and status['helper_sha256'] == helper_sha
         and status['acceptance'] is False and status['native_admission'] is False
         and status['no_kit_transactions'] is True and type(status['child_status']) is str
         and status['supervision'] == 'HELD_RUNTIME_RETURNED'
         and type(status['returncode']) is int and status['runtime_error'] is None,
         'bound capture-only completed diagnostic status')
    expected = {name: row for name, row in files.items()
                if name not in ('namespace-context.json', 'namespace-status.json')}
    need(status['report_pins'] == expected, 'exact observed diagnostic report byte pins')
    return dict(files=files, bytes=total, child_status=status['child_status'],
                supervision=status['supervision'], returncode=status['returncode'])


def capture(args):
    owner = owner_module(args)
    manifest, own, work, image, helper_sha, producer = prerequisites(owner, args)
    C = owner.C
    current = C.fresh(work / 'namespace-diagnostic')
    current.chmod(0o700)
    result = dict(status='CAPTURE_FAILED_DIAGNOSTIC_ONLY', identity=own, image=image,
                  acceptance=False, native_admission=False, no_kit_transactions=True,
                  hardware='NOT_RUN', release='NOT_ADMITTED', image_retirement='NOT_REQUESTED')
    failure = None
    try:
        inputs = C.fresh(current / 'inputs'); inputs.chmod(0o555)
        media = C.fresh(current / 'media'); media.chmod(0o555)
        output = C.fresh(current / 'out'); output.chmod(0o700)
        nonce = os.urandom(16).hex()
        context = dict(schema_version=1, purpose='ONE_PRIVATE_PROPAGATION_MOUNT_DIAGNOSTIC_ONLY',
                       source_sha=own['source_sha'], feature_code_sha=own['feature_code_sha'],
                       run_id=own['run_id'], image=image, token=own['token'], nonce=nonce,
                       helper_sha256=helper_sha, map_sha256=args.manifest_sha256, no_kit_transactions=True)
        C.save(output / 'namespace-context.json', context)
        (output / 'namespace-context.json').chmod(0o600)
        context_sha = C.sha(C.read(output / 'namespace-context.json'))
        result.update(context_sha256=context_sha, helper_sha256=helper_sha,
                      map_sha256=args.manifest_sha256,
                      bootstrap_sha256=C.sha(C.read(work / 'bootstrap.json')))
        selected = dict(own, accepted_tool='namespace-diagnostic', candidate_nonce=nonce,
                        candidate_selection_sha=context_sha)
        actor = C.Actors(current / 'actors', 360)
        core = C.module(ROOT / 'scripts/ci/maintained_desktop574.py', '_diagnostic_existing574_image')
        core.docker = actor.docker
        inspection = core.inspect_image(image, own['token'])
        C.need(inspection['Id'] == image, 'owned immutable574 image')
        C.save(current / 'image-inspection.json', inspection)
        mounts = [('/trial-code', str(HERE / 'trial-code'), False),
                  ('/source', str(HERE / 'candidate-source'), False),
                  ('/inputs', str(inputs), False),
                  ('/builder-packages.lock', str(HERE / 'expected-packages.lock'), False),
                  ('/media', str(media), False), ('/out', str(output), True)]
        C.trial_actor(actor, selected, image, current, 'candidate', mounts, mode='namespace-diagnostic')
        need(C.sha(C.read(output / 'namespace-context.json')) == context_sha, 'diagnostic context unchanged')
        result.update(status='CAPTURED_NAMESPACE_DIAGNOSTIC_ONLY',
                      capture=captured_output(C, output, context_sha, helper_sha))
    except BaseException as error:
        failure = error
        result['error'] = type(error).__name__ + ': ' + str(error)[:2048]
    finally:
        C.save(current / 'owner-result.json', result)
    if failure is not None:
        raise failure
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--work', required=True)
    capture(parser.parse_args())


if __name__ == '__main__':
    main()
