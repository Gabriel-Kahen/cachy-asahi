#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the signed FirstLogin supplement without modifying Overlay583 staging."""

import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ARCHIVE = 'cachy-asahi-first-login-0.1.0-2-any.pkg.tar.zst'
SIGNER = '18E721CE9D7928221AD3163BA91B1AFC7142F94E'
SIGNATURE = ARCHIVE+'.sig'
PUBLIC = 'rehearsal-TEST-public.gpg'
ORIGINAL_SIGNATURE = ARCHIVE+'.original.sig'
ORIGINAL_PUBLIC = 'original-project-public.gpg'
KIND = 'FIRST_LOGIN_OVERLAY583_SUPPLEMENT_V2'
TEST_VALIDITY = 86400
MATERIALS = {
    ARCHIVE: dict(bytes=19471, sha256='d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839'),
    ORIGINAL_SIGNATURE: dict(bytes=310, sha256='5ebb96292992563107844d11aa2b15ff72361eba0be1dd8b09590cbb5eefc4a9'),
    ORIGINAL_PUBLIC: dict(bytes=665, sha256='2729c52fee2286b90a69459cd3d882be87ce8ce823131b6bf9c7f02f2a0f36c8'),
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
    'original_test_signer': SIGNER,
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


def valid_rehearsal(record):
    return (type(record) is dict and set(record)=={'fingerprint','created','expires','test_only'}
            and record['test_only'] is True and type(record['fingerprint']) is str
            and re.fullmatch('[0-9A-F]{40}',record['fingerprint']) is not None
            and record['fingerprint'] != SIGNER and type(record['created']) is int
            and type(record['expires']) is int and record['expires']-record['created']==TEST_VALIDITY)


def test_signature(trial, payload):
    """Sign only the immutable archive, and retire the isolated private key home."""
    guest = load(HERE/'guest.py','first_login_signature_status')
    with tempfile.TemporaryDirectory(prefix='overlay583-first-login-gpg-') as temp:
        root = Path(temp)
        home = root/'key-home'
        verify = root/'verify-home'
        home.mkdir(mode=0o700)
        verify.mkdir(mode=0o700)
        fixed = {'PATH':'/usr/bin:/bin','LC_ALL':'C'}
        archive, original, key = (root/name for name in (ARCHIVE,ORIGINAL_SIGNATURE,ORIGINAL_PUBLIC))
        for path in (archive,original,key):
            path.write_bytes(payload[path.name])

        def gpg(home, *args):
            return subprocess.run(['/usr/bin/gpg','--no-options','--homedir',str(home),'--batch',
                                   '--no-auto-key-retrieve',*args],stdin=subprocess.DEVNULL,
                                  env=fixed,capture_output=True,check=True,timeout=30).stdout

        def gpgv(keyring, signature):
            return subprocess.run(['/usr/bin/gpgv','--homedir',str(verify),'--status-fd','1',
                                   '--keyring',str(keyring),str(signature),str(archive)],
                                  stdin=subprocess.DEVNULL,env=fixed,capture_output=True,
                                  check=True,timeout=30).stdout

        trial.need(guest.good_signature(gpgv(key,original),SIGNER,historical=True),
                   'Original TEST signature cryptographic provenance differs')
        pinentry = ['--pinentry-mode','loopback','--passphrase','']
        try:
            gpg(home,*pinentry,'--quick-generate-key','Cachy-Asahi FirstLogin Overlay583 Rehearsal TEST',
                'ed25519','sign','1d')
            entries = gpg(home,'--with-colons','--fingerprint','--list-keys').decode('ascii').splitlines()
            public = [line.split(':') for line in entries if line.startswith('pub:')]
            fingerprints = [line.split(':')[9] for line in entries if line.startswith('fpr:')]
            trial.need(len(public)==len(fingerprints)==1,'One fresh local TEST signer required')
            signer = fingerprints[0]
            record = dict(fingerprint=signer,created=int(public[0][5]),expires=int(public[0][6]),test_only=True)
            trial.need(valid_rehearsal(record),'Bounded one-day TEST signing key required')
            public_key, signature = root/PUBLIC, root/SIGNATURE
            public_key.write_bytes(gpg(home,'--export',signer))
            gpg(home,'--local-user',signer,*pinentry,'--output',str(signature),'--detach-sign',str(archive))
            trial.need(guest.good_signature(gpgv(public_key,signature),signer),
                       'Fresh current-time TEST signature differs')
            payload[PUBLIC]=trial.read(public_key,cap=16*1024)
            payload[SIGNATURE]=trial.read(signature,cap=16*1024)
        finally:
            subprocess.run(['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],
                           stdin=subprocess.DEVNULL,env=fixed,capture_output=True,check=True,timeout=15)
    return record


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
    rehearsal = test_signature(trial,payload)
    packet = dict(kind=KIND, files={name: trial.pin(raw) for name, raw in payload.items()}, rehearsal=rehearsal,
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
