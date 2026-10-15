# SPDX-License-Identifier: MIT
"""Opt-in existing QEMU trial while the lifecycle-installed image is still owned."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys

import integration
import native_arm as native


@contextmanager
def owner_module(directory):
    """Keep the VM owner's sibling imports separate from other CI modules."""
    names = ('common', 'audit_tooling', 'image_decode_report', 'direct_virtual_controller')
    previous = {name: sys.modules.get(name) for name in names}
    path = list(sys.path)
    try:
        for name in names:
            sys.modules.pop(name, None)
        sys.path.insert(0, str(directory))
        spec = importlib.util.spec_from_file_location(names[-1], directory / 'controller.py')
        owner = importlib.util.module_from_spec(spec)
        sys.modules[names[-1]] = owner
        spec.loader.exec_module(owner)
        yield owner
    finally:
        sys.path[:] = path
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def copy_pinned(source, target, pin):
    integration.regular(source)
    integration.need(native.sha(source) == pin, 'virtual input differs from its pin')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    integration.need(native.sha(target) == pin, 'virtual input changed during copy')


def consume(controller, tooling_cache, output):
    """Use existing lifecycle metadata and cached tooling; no download or build."""
    integration.need(controller.report['stages'].get('lifecycle', {}).get('status') == 'PASS'
                     and re.fullmatch(r'sha256:[0-9a-f]{64}', controller.installed or ''),
                     'successful live lifecycle-installed image required')
    source = native.ROOT / 'scripts/virtual'
    tooling_cache, output = tooling_cache.resolve(), output.resolve()
    integration.need(not output.exists(), 'new virtual output required')
    for other in (native.ROOT, controller.native_out, controller.work, tooling_cache):
        other = Path(other).resolve()
        integration.need(not output.is_relative_to(other) and not other.is_relative_to(output),
                         'virtual output must be separate from source/build/work/cache')
    run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    integration.need(re.fullmatch(r'[1-9][0-9]{0,19}', run_id)
                     and re.fullmatch(r'[1-9][0-9]{0,9}', attempt), 'workflow run and attempt required')
    controller.report['virtual'] = {'status': 'FAIL', 'hardware_validation': 'NOT RUN', 'visual_review': 'NOT RUN'}
    output.mkdir(mode=0o700)
    inputs = output / 'inputs'; inputs.mkdir(mode=0o700)
    handoff = controller.work / 'lifecycle-raw'
    paths = {
        'base_inputs_lock': controller.native_out / 'inputs.lock.json',
        'base_lock': controller.native_out / 'packages.lock',
        'installed_lock': handoff / 'installed-packages.lock',
        'lifecycle_receipt': handoff / 'lifecycle/result.json',
        'installed_image_receipt': handoff / 'installed-image.json',
        'committed_config': handoff / 'committed-config.json',
        'committed_verification': handoff / 'committed-image/result.json',
        'commit_receipt': handoff / 'commit-receipt.json',
        'tooling_lock': source / 'tooling.lock.json',
        'tooling_audit': source / 'tooling-audit.json'}
    files = {}
    for alias, path in paths.items():
        relative = 'metadata/' + alias + path.suffix
        pin = native.sha(path)
        copy_pinned(path, inputs / relative, pin)
        files[alias] = {'path': relative, 'sha256': pin}
    rows = json.loads(paths['committed_verification'].read_text())['baseline']
    integration.need(rows == controller.rows['baseline'], 'verified original package rows differ')
    for row in rows:
        relative = PurePosixPath(row['archive'])
        integration.need(not relative.is_absolute() and '..' not in relative.parts
                         and relative.parts[0] == 'baseline', 'baseline archive path required')
        copy_pinned(controller.archives / row['archive'], inputs / row['archive'], row['sha256'])
    lock = json.loads(paths['tooling_lock'].read_text())
    blobs = list(lock['keyring_files'])
    for row in lock['packages']:
        blobs += [row, {'filename': row['filename'] + '.sig', 'sha256': row['signature_sha256'],
                        'size': row['signature_size']}]
    integration.need(len(blobs) == 45, 'complete existing tooling closure required')
    for row in blobs:
        integration.need(Path(row['filename']).name == row['filename'], 'flat tooling filename required')
        path = tooling_cache / row['filename']
        integration.need(path.stat().st_size == row['size'], 'tooling input size differs')
        copy_pinned(path, inputs / 'tooling-cache' / row['filename'], row['sha256'])
    with owner_module(source) as owner:
        contract = {'schema_version': 1, 'execution': 'native-aarch64-controller-qemu-tcg-guest',
                    'installed_image_id': controller.installed, 'source_commit': controller.commit,
                    'baseline_source_commit': controller.commit, 'run_id': run_id, 'run_attempt': attempt,
                    'core_sha256': owner.CORE, 'audit_tooling_sha256': owner.AUDITOR_PIN,
                    'controller_sha256': native.sha(source / 'controller.py'), 'baseline': rows,
                    'files': files, 'cache_dir': 'tooling-cache'}
        path = inputs / 'controller-contract.json'; native.save(path, contract)
        # In-process invocation preserves the owner's signal/deadline/cleanup path.
        # The outer integration finally still removes the lifecycle-installed image.
        try:
            passed = owner.main(['--contract', str(path), '--contract-sha256', native.sha(path),
                                 '--output', str(output / 'owner-public')])
        finally:
            if getattr(owner, 'CANCELLED', False):
                controller.cancelled = True
    report = json.loads((output / 'owner-public/result.json').read_text())
    integration.need(passed and report['status'] == 'CAPTURED_REQUIRES_VISUAL_REVIEW'
                     and report.get('private_workspace_cleanup') == 'PASS'
                     and all(row['status'] == 'PASS' for row in report['cleanup']),
                     'virtual trial failed; inspect owner result and bounded diagnostics')
    controller.report['virtual']['status'] = report['status']
