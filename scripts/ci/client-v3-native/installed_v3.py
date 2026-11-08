#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Real installed CLI/signature/state journey; only owned ephemeral TEST keys."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys

PIN = '4cf428452d08ea212d8bb92d899329f3445d15877c5b79e5ff5f138b0a696e76'
encode = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def journey(work, prefix=Path('/'), fixtures=Path('/runner')):
    work = Path(work)
    assert work.is_absolute() and work.is_dir() and not list(work.iterdir()) and stat.S_IMODE(work.stat().st_mode) == 0o700
    product = prefix / 'usr/share/cachy-asahi/repository-runtime/scripts/client/client_v3.py'
    assert hashlib.sha256(product.read_bytes()).hexdigest() == PIN
    fixture = load('native_v3_trusted_TEST_fixture', fixtures / 'fixture-client/test_client_v2.py')
    cls = fixture.GPGTests
    original = subprocess.run
    transcript = []
    pidfd = None
    started = False
    agent_retired = False
    def record(argv, *args, **kwargs):
        result = original(argv, *args, **kwargs)
        row = dict(argv=[str(x) for x in argv], exit=result.returncode)
        for role in ('stdout', 'stderr'):
            raw = getattr(result, role)
            assert isinstance(raw, bytes) and len(raw) <= 65536
            row[role] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), base64=base64.b64encode(raw).decode())
        transcript.append(row)
        assert len(encode(transcript)) <= 65536
        return result
    subprocess.run = record  # Instrument real calls; no return value or cryptographic result is changed.
    try:
        started = True
        cls.setUpClass()
        agent = subprocess.run(['gpg-connect-agent', '--homedir', str(cls.home), '--no-autostart', 'GETINFO pid', '/bye'], capture_output=True, timeout=30)
        assert agent.returncode == 0
        pid = int(next(x[2:] for x in agent.stdout.decode().splitlines() if x.startswith('D ')))
        pidfd = os.pidfd_open(pid)
        assert not select.select([pidfd], [], [], 0)[0]
        keyring = work / 'TEST-public.gpg'
        keyring.write_bytes(cls.public)
        state = work / 'state'
        state.mkdir(mode=0o700)
        cli = [sys.executable, '-I', '-B', str(prefix / 'usr/bin/cachy-asahi-repository-client')]
        now = fixture.datetime.now(fixture.timezone.utc)
        def draft(path, sequence):
            value = subprocess.run(cli + ['build', '--bundle', str(cls.bundle), '--namespace', 'dev.example', '--signer', cls.key,
                '--output', str(path), '--sequence', str(sequence), '--issued-utc', fixture.c.utc(now - fixture.timedelta(seconds=60)),
                '--expires-utc', fixture.c.utc(now + fixture.timedelta(hours=1))], capture_output=True, timeout=60)
            assert value.returncode == 0
            cls.sign(path)
        def arguments(metadata, apply=False):
            return ['verify', '--bundle', str(cls.bundle), '--metadata', str(metadata), '--signature', str(metadata) + '.sig',
                '--public-keyring', str(keyring), '--signer', cls.key, '--namespace', 'dev.example', '--state-dir', str(state),
                '--minimum-sequence', '1'] + (['--apply'] if apply else [])
        first = work / 'metadata1.json'
        draft(first, 1)
        readonly = subprocess.run(cli + arguments(first), capture_output=True, timeout=60)
        assert readonly.returncode == 0 and json.loads(readonly.stdout)['status'] == 'verified-development' and not list(state.iterdir())
        applied = subprocess.run(cli + arguments(first, True), capture_output=True, timeout=60)
        assert applied.returncode == 0
        value = json.loads(applied.stdout)
        assert value['status'] == 'applied-development' and value['state_changed'] and value['checkpoint_directory_synced'] and not value['stable_accepted']
        checkpoint = state / 'checkpoint.json'
        prior = checkpoint.read_bytes()
        assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600 and json.loads(prior)['sequence'] == 1
        again = subprocess.run(cli + arguments(first), capture_output=True, timeout=60)
        assert again.returncode == 0 and not json.loads(again.stdout)['cold_start'] and checkpoint.read_bytes() == prior
        second = work / 'metadata2.json'
        draft(second, 2)
        witness = work / 'rebind-witness'
        witness.mkdir(mode=0o700)
        detached = work / 'detached-state'
        refused = subprocess.run([sys.executable, '-I', '-B', str(fixtures / 'rename_after_real_verification.py'), str(product), str(witness),
            str(state), str(detached), '3', *arguments(second, True)], capture_output=True, timeout=60)
        assert refused.returncode == 1 and not refused.stdout and b'state directory path changed during verification' in refused.stderr
        observation = json.loads((witness / 'real-verifier-record.json').read_bytes())
        assert observation['completed_bundle_targets'] == 3 and len(observation['actual_verified_signatures']) == 5
        assert observation['state_renamed_after_all_real_signatures'] and observation['crypto_success_mocks'] == 0
        for index, row in enumerate(observation['actual_GPG_commands']):
            assert row['exit'] == 0
            for role in ('stdout', 'stderr'):
                raw = (witness / f'gpg-{index:02d}.{role}').read_bytes()
                assert row[role] == dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                row[role]['base64'] = base64.b64encode(raw).decode()
            assert b'[GNUPG:] VALIDSIG ' in base64.b64decode(row['stdout']['base64'])
        transcript.append(dict(real_rebind_verifier=observation))
        assert not list(state.iterdir()) and (detached / 'checkpoint.json').read_bytes() == prior
        assert [p.name for p in detached.iterdir()] == ['checkpoint.json'] and keyring.read_bytes() == cls.public
    finally:
        if started:
            base = getattr(cls, 'base', None)
            cls.doClassCleanups()  # Fixture cleanup names only its own explicit TEST homedir.
            agent_retired = pidfd is not None and bool(select.select([pidfd], [], [], 10)[0]) and base is not None and not base.exists()
        if pidfd is not None:
            os.close(pidfd)
        subprocess.run = original
    assert agent_retired
    raw = encode(transcript)
    assert len(raw) <= 65536
    (work / 'command-transcript.json').write_bytes(raw)
    return dict(status='PASS_INSTALLED_V3_REAL_SIGNED_APPLY_AND_REBIND', actual_cli_readonly=True, actual_cli_apply=True,
                idempotent_readonly=True, rename_after_real_verification=True, refused_before_checkpoint_write=True,
                checkpoint_preserved=True, private_agent_retired=True, real_signature_checks_before_rebind=5,
                crypto_success_mocks=0, collected_code_imports=0, installed_source=True,
                transcript_bytes=len(raw), transcript_sha256=hashlib.sha256(raw).hexdigest(), transcript=transcript)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    if os.uname().machine != 'aarch64' or os.geteuid() == 0 or sys.flags.optimize:
        raise ValueError('ordinary native ARM installed component actor required')
    print(json.dumps(journey(args.work), sort_keys=True))
