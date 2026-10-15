#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run package lifecycle/desktop integration using an existing native build output.

Requires the original Docker image on the same native ARM daemon. Does not
download dependencies, rebuild original packages, dispatch CI or run broad suites.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess

import integration
import native_arm as native


def prepared_build(directory, recipe_pin):
    """Check existing native build metadata and original archives before Docker use."""
    result = json.loads((directory / 'result.json').read_text())
    bootstrap = json.loads((directory / 'bootstrap.json').read_text())
    image = (directory / 'image-id').read_text().strip()
    native.check_pin(recipe_pin)
    integration.need(result['status'] in ('native-builds-and-byte-comparison-pass', 'failed')
                     and result['native_build'] == 'PASS' and result['reviewed_recipes_sha256'] == recipe_pin,
                     'successful native build for these recipes required')
    integration.need(re.fullmatch(r'sha256:[0-9a-f]{64}', image) and bootstrap['status'] == 'image-provisioned'
                     and bootstrap['image_id'] == image, 'original immutable builder image required')
    integration.need(native.sha(directory / 'inputs.lock.json') == result['reviewed_inputs_sha256'] == bootstrap['inputs_sha256']
                     and native.sha(directory / 'packages.lock') == bootstrap['packages_lock_sha256'], 'build input/inventory drift')
    reviews = native.load_pinned(native.ROOT / 'scripts/ci/recipes.lock.json', recipe_pin)
    for name in native.RECIPES:
        original = None
        for attempt in (1, 2):
            path, row = integration.artifact(directory / f'{name}-{attempt}', name)
            provenance = json.loads((directory / f'{name}-{attempt}' / 'provenance.json').read_text())
            integration.need(provenance['mode'] == 'native' and provenance['image_id'] == image
                             and provenance['expected_packages_sha256'] == bootstrap['packages_lock_sha256'], 'native archive provenance drift')
            expected = next(value for path, value in reviews.items() if Path(path).name == name)
            integration.need(provenance['recipe_inputs'] == expected, 'archive recipe differs from current pinned recipe')
            if original is not None:
                integration.need(row == original, 'original package pair differs')
            original = row
    return image


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-output', required=True, type=Path)
    parser.add_argument('--integration-lock', required=True, type=Path)
    parser.add_argument('--integration-sha256', required=True)
    parser.add_argument('--recipes-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--virtual-tooling-cache', type=Path)
    parser.add_argument('--virtual-output', type=Path)
    args = parser.parse_args(argv)
    integration.need(bool(args.virtual_tooling_cache) == bool(args.virtual_output), 'both virtual options required')
    # Refuse emulation/host mutation before creating output or invoking Docker.
    integration.need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64')
                     and os.getuid() != 0, 'non-root native ARM Linux host required')
    integration.need(re.fullmatch(r'[0-9a-f]{40}', args.source_commit or ''), 'exact current source commit required')
    source = native.ROOT.resolve()
    native_out, output = args.native_output.resolve(), args.output.resolve()
    integration.need(not output.exists() and not output.is_relative_to(source) and not output.is_relative_to(native_out)
                     and not native_out.is_relative_to(output), 'new separate output outside source/build required')
    image = prepared_build(native_out, args.recipes_sha256)
    inputs = json.loads((native_out / 'inputs.lock.json').read_text())
    lock = integration.preflight(source, args.integration_lock, args.integration_sha256,
                                 args.recipes_sha256, inputs['source_date_epoch'])
    probe = output.parent / (output.name + '-probe')
    probe.mkdir()
    native.probe(probe)  # Existing native-host/local-daemon guard.
    actual = json.loads(native.run(['docker', 'image', 'inspect', image], timeout=60))[0]
    integration.need(actual['Id'] == image and actual['Architecture'] == 'arm64' and actual['Os'] == 'linux',
                     'original native image must still exist on this daemon')
    inventory = native.run(['docker', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                            '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat', image,
                            '/builder-packages.lock'], timeout=60) + '\n'
    integration.need(inventory == (native_out / 'packages.lock').read_text(), 'image inventory differs from build')
    controller = integration.Controller(image, native_out, output, lock, args.source_commit, package_only=True)
    if args.virtual_tooling_cache is None:
        return 0 if controller.run() else 1
    from virtual_retry import consume
    return 0 if controller.run(consumers=lambda current: consume(
        current, args.virtual_tooling_cache, args.virtual_output)) else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
