#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare finite TEST-signed inputs; no package installation or container run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = ROOT/'packages/tools/cachy-asahi-install-handoff'
PACKAGE_SHA = 'cf34935122855ca6aaa02f4c11987d53530e0e729c03698fa03aa1586ffac59e'
IMAGE = 'sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145'
LIFECYCLE_SHA = '1f4d8763e3380f700b75e0a2be4980eb3a0550977280db7997c655d50f842e73'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()


def source_snapshot(archive, target, expected):
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        assert len(members) == len(expected)
        assert len({row.name for row in members}) == len(members)
        for row in members:
            assert row.isfile() and row.name.startswith(target.name+'/')
            name = row.name[len(target.name)+1:]
            assert name in expected and '..' not in Path(name).parts
            raw = tar.extractfile(row).read(4*1024**2+1)
            assert len(raw) == expected[name]['bytes'] == row.size and sha(raw) == expected[name]['sha256']
            path = target/name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(raw)
            path.chmod(0o644)


def prepare(artifact, output, nonce):
    assert artifact.is_absolute() and not artifact.is_symlink() and artifact.is_file()
    assert re.fullmatch('[0-9a-f]{32}', nonce)
    raw = artifact.read_bytes()
    assert len(raw) == 184625 and sha(raw) == PACKAGE_SHA
    assert output.is_absolute() and not output.exists() and not output.is_symlink()
    output.mkdir(mode=0o700)
    inputs, runner = output/'inputs', output/'runner'
    inputs.mkdir(mode=0o700)
    runner.mkdir(mode=0o700)
    provenance_raw = (PACKAGE_ROOT/'source-provenance.json').read_bytes()
    assert provenance_raw == subprocess.check_output(['git','-C',str(ROOT),'show','282364173f497f1052267c3901dda395dd59e03f:packages/tools/cachy-asahi-install-handoff/source-provenance.json'])
    provenance = json.loads(provenance_raw)
    for field in ('source_archive','check_source_archive'):
        row = provenance[field]
        source = PACKAGE_ROOT/row['path']
        assert source.stat().st_size == row['bytes'] and sha(source.read_bytes()) == row['sha256']
    lifecycle_raw = (ROOT/'scripts/integration/lifecycle.py').read_bytes()
    assert sha(lifecycle_raw) == LIFECYCLE_SHA
    (runner/'lifecycle.py').write_bytes(lifecycle_raw)
    for name in ('guest.py','controls.py'):
        (runner/name).write_bytes(Path(__file__).with_name(name).read_bytes())
    source_files = {path.name:sha(path.read_bytes()) for path in runner.iterdir()}
    with tempfile.TemporaryDirectory(prefix='install-handoff-TEST-producer-') as temporary:
        scratch = Path(temporary)
        source_snapshot(PACKAGE_ROOT/'private-source.tar.gz', scratch/'private', provenance['runtime_files'])
        source_snapshot(PACKAGE_ROOT/'check-source.tar.gz', scratch/'checks', provenance['check_files'])
        D = load('candidate_original_runtime', scratch/'private/scripts/install/fresh_handoff/runtime.py')
        lock = D.verify(scratch/'private', provenance['runtime_sha256'])
        H = load('candidate_original_handoff', scratch/'private/scripts/install/fresh_handoff/handoff.py')
        H.DELIVERED_SOURCE_LOCK = lock
        F = load('candidate_original_TEST_fixture', scratch/'checks/scripts/install/fresh_handoff/signed_fixture.py')
        context = ['git','-C',str(F.ROOT),'rev-parse','HEAD']
        def source_context(argv, **kwargs):
            if list(argv) == context:
                value = lock['source_commit']+'\n'
                return value if kwargs.get('text') else value.encode()
            return subprocess.check_output(argv, **kwargs)
        F.subprocess = SimpleNamespace(check_output=source_context)
        F.T.ReleaseTests.setUpClass()
        owner = unittest.TestCase(methodName='runTest')
        original = H.R.P.auth.KEYS
        try:
            fixture = F.SignedFixture(owner,H)
            H.R.P.auth.KEYS = {**original,'alarm':fixture.anchor}
            fixture.materialize()
            selected = inputs/'selection.json'
            selected.write_bytes(encoded(fixture.chosen))
            handoff = H.prepare(argparse.Namespace(selection=selected,selection_sha256=sha(selected.read_bytes()),
                candidate=fixture.candidate,recovery=fixture.recovery,state_dir=fixture.state,output=inputs/'handoff'))
            archive = inputs/'package.pkg.tar.zst'
            archive.write_bytes(raw)
            F.T.r.sign(archive,fixture.key,fixture.env)
            public = F.T.r.run(['gpg','--batch','--armor','--export',fixture.key],env=fixture.env)
            (inputs/'TEST-public.asc').write_bytes(public)
            package_signature = (inputs/'package.pkg.tar.zst.sig').read_bytes()
            files, links = H.K.inventory(inputs/'handoff')
            handoff_record = dict(receipt_sha256=handoff['receipt_sha256'],
                selection_sha256=sha(selected.read_bytes()),runtime_sha256=handoff['runtime_sha256'],
                archive_certificate_fingerprint=fixture.anchor[0],archive_certificate_sha256=fixture.anchor[1],
                files=files,symlinks=links)
            signer = dict(fingerprint=fixture.key,certificate_sha256=sha(public),certificate_bytes=len(public))
            signing_home = fixture.home
        finally:
            H.R.P.auth.KEYS = original
            owner.doCleanups()
            F.T.ReleaseTests.tearDownClass()
        assert not signing_home.exists()
    assert not scratch.exists()
    payload = json.loads((PACKAGE_ROOT/'payload-map.json').read_bytes())
    assert (PACKAGE_ROOT/'payload-map.json').read_bytes() == subprocess.check_output(['git','-C',str(ROOT),'show','282364173f497f1052267c3901dda395dd59e03f:packages/tools/cachy-asahi-install-handoff/payload-map.json'])
    rows = dict(payload['files'])
    own = PACKAGE_ROOT/'payload-map.json'
    rows[payload['unlisted_self']['path']] = dict(bytes=own.stat().st_size,sha256=sha(own.read_bytes()),mode=0o644)
    contract = dict(schema_version=1,purpose='TEST-signed-install-handoff-host-container',
        execution='host-x86_64-disposable-docker',image_id=IMAGE,nonce=nonce,
        package=dict(path='package.pkg.tar.zst',sha256=PACKAGE_SHA,bytes=len(raw),
                     signature_sha256=sha(package_signature),signature_bytes=len(package_signature)),
        signer=signer,handoff=handoff_record,payload=rows,source_files=source_files)
    config = ('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\n'
              'LocalFileSigLevel = Required TrustedOnly\nGPGDir = /tmp/handoff-test-keyring-'+nonce+
              '\nHookDir = /builder-disabled-hooks\n')
    (inputs/'pacman.conf').write_text(config)
    (inputs/'contract.json').write_bytes(encoded(contract))
    return dict(status='PREPARED_TEST_ONLY',contract_sha256=sha(encoded(contract)),
                private_signing_home_removed=True,producer_sources_removed=True,package_sha256=PACKAGE_SHA,
                image_id=IMAGE,inputs=str(inputs),runner=str(runner))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--nonce',required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.artifact,args.output,args.nonce),sort_keys=True))
