#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the signed FirstLogin supplement without modifying Overlay583 staging."""

import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCHIVE = 'cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst'
SIGNER = '18E721CE9D7928221AD3163BA91B1AFC7142F94E'
MATERIALS = {
    ARCHIVE: dict(bytes=19471, sha256='d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839'),
    ARCHIVE+'.sig': dict(bytes=310, sha256='5ebb96292992563107844d11aa2b15ff72361eba0be1dd8b09590cbb5eefc4a9'),
    'project-public.gpg': dict(bytes=665, sha256='2729c52fee2286b90a69459cd3d882be87ce8ce823131b6bf9c7f02f2a0f36c8'),
}
TARGET = dict(bytes=11450, sha256='12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba')
PREFLIGHT_SHA = 'efbd1147613ab68721a05268c7973282936b5b61de09268c84f473b02566a3c7'
JOURNEY_SHA = 'ea924ca25fcd861316437a6ed46a29cbf79c8c43c4cab973834da0c3560460b5'
PROCESS_SHA = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
LAUNCHER_SHA = 'a5e2b72ff58eac2763c0ad65f36c0c883a60ce20e97c38acc4bace9d30a18144'
BACKEND_SHA = '41ade792884afced7a078c6926d3f18d7a9e40fca50191c7d77d34678711921c'
PROVENANCE = {
    'host_build': 'x86_64',
    'native_arm_build': 'NOT RUN',
    'package_arch': 'any',
    'candidate': '0.1.0-2',
    'pkgbuild_sha256': 'e157ded80cee91404f3d6cba0f4d693592532dc262ff25f6ab910f1fc1ba6cbd',
    'recipe_packaging_commit': 'eb762634',
    'implementation_commit': '409cb24ba224508aeea1b692b1a164505cd0101a',
    'test_signer': SIGNER,
    'production_trust': False,
}
REQUIRED_INSTALLED = {
    'cachy-asahi-setup': '0.3.0-1', 'cachy-asahi-fish-config': '0.1.0-1',
    'cachy-asahi-zsh-config': '0.1.0-1', 'python': '3.14.8-1',
    'fish': '4.9.3-1', 'zsh': '5.9.2-1', 'util-linux': '2.42.4-1',
    'shadow': '4.20.0.arch1-1',
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(*, staging, preflight, archive, signature, public_key, output):
    repository = HERE.parents[2]
    trial = load(repository/'scripts/install/overlay583_trial/trial.py', 'first_login_overlay583_trial_data')
    before = trial.read(staging/'target.lock', TARGET, cap=256*1024)
    entries = trial.canonical_lock(before, 583)
    trial.need({name: entries.get(name) for name in REQUIRED_INSTALLED} == REQUIRED_INSTALLED
               and 'cachy-asahi-first-login' not in entries, 'exact Overlay583 Setup8 and shell dependencies required')
    preflight_raw = trial.read(preflight, cap=128*1024)
    record = trial.decode(preflight_raw)
    trial.need(sha256(preflight_raw).hexdigest() == PREFLIGHT_SHA
               and record['status'] == 'verified-offline-install-preflight'
               and record['base_archives_authenticated'] is True
               and record['pacman_siglevel'] == 'Required TrustedOnly'
               and record['target_lock_sha256'] == TARGET['sha256'],
               'exact retained authenticated Overlay583 preflight')
    payload = {name: trial.read(path, MATERIALS[name], cap=64*1024)
               for name, path in zip(MATERIALS, (archive, signature, public_key), strict=True)}
    code = {
        'stage.py': (HERE/'stage.py', None),
        'guest.py': (HERE/'guest.py', None),
        'target.py': (HERE/'target.py', None),
        'journey.py': (HERE.parent/'first_login_installed_journey.py', JOURNEY_SHA),
        'owned_process.py': (repository/'scripts/virtual/owned_process.py', PROCESS_SHA),
    }
    for name, (path, digest) in code.items():
        raw = trial.read(path, cap=128*1024)
        trial.need(digest is None or sha256(raw).hexdigest() == digest, 'unchanged retained helper '+name)
        payload[name] = raw
    installed = before + b'cachy-asahi-first-login 0.1.0-2\n'
    installed = trial.sorted_rows(installed)
    trial.canonical_lock(installed, 584)
    packet = dict(kind='FIRST_LOGIN_OVERLAY583_SUPPLEMENT_V1', files={name: trial.pin(raw) for name, raw in payload.items()},
                  overlay_before=TARGET, overlay_after=trial.pin(installed),
                  preflight=trial.pin(preflight_raw), provenance=PROVENANCE,
                  template_profile='fish0.1.0-1-zsh0.1.0-1', Root_authority=None, installation='NOT RUN')
    output = trial.ordinary(output)
    output.mkdir(mode=0o700)
    for name, raw in payload.items():
        with (output/name).open('xb') as stream:
            stream.write(raw)
    (output/'supplement.json').write_bytes(trial.encoded(packet))
    return packet


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for item in ('staging', 'preflight', 'archive', 'signature', 'public-key', 'output'):
        parser.add_argument('--'+item, type=Path, required=True)
    print(json.dumps(prepare(**vars(parser.parse_args())), indent=2, sort_keys=True))
