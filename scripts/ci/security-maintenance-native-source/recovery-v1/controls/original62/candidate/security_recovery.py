# SPDX-License-Identifier: MIT
"""One recovery attempt inside a caller-fenced disposable root; no CLI or runner.

The native adapter must authenticate the new checkpoint/retirement, input pins,
baseline and generated-database expectations before calling this module. This
library cannot establish namespace isolation or authenticate dictionary receipts.
"""
from dataclasses import dataclass
import hashlib
import json
import re

import security_recovery_fs as fs
from security_recovery_state import NAME, NEW, classify_recovery, verify_recovered

PREFIX = 'opt/native-security-v1/recovery/'
ARCHIVE = PREFIX + NAME + '-0.1.0-2-any.pkg.tar.zst'
CONFIG = PREFIX + 'pacman.conf'
KEYRING = PREFIX + 'test-public.gpg'
OPTIONS = dict(Architecture='aarch64', RootDir='/', DBPath='/var/lib/pacman',
               SigLevel='Required', LocalFileSigLevel='Required',
               GPGDir='/' + PREFIX + 'trust', HookDir='/' + PREFIX + 'empty-hooks',
               CacheDir='/' + PREFIX + 'cache', LogFile='/' + PREFIX + 'pacman.log')


class RecoveryFailure(ValueError):
    def __init__(self, phase, completed, cause):
        super().__init__(f'{phase}: {cause}; partial effects must be reconciled, never retried')
        self.phase, self.completed = phase, tuple(completed)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


@dataclass(frozen=True)
class Pin:
    bytes: int
    sha256: str

    def check(self, raw):
        need(type(self.bytes) is int and 0 < self.bytes <= fs.LEAF_CAP
             and type(self.sha256) is str and re.fullmatch('[0-9a-f]{64}', self.sha256),
             'bounded input pin')
        need(len(raw) == self.bytes and hashlib.sha256(raw).hexdigest() == self.sha256,
             'recovery input changed')


@dataclass(frozen=True)
class Inputs:
    archive: Pin
    signature: Pin
    config: Pin
    keyring: Pin
    signer: str


@dataclass(frozen=True)
class Command:
    step: str
    argv: tuple[str, ...]
    seconds: int
    output_cap: int


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    retirement: dict


def _run(runner, command):
    result = runner.run(command)
    need(type(result) is CommandResult and type(result.stdout) is bytes
         and len(result.stdout) <= command.output_cap, 'bounded owned command result')
    r = result.retirement
    need(type(r) is dict and type(r.get('exit')) is int and r['exit'] == 0
         and r.get('error') is None and r.get('timeout') is False
         and r.get('forced_retirement') is False
         and all(r.get(k) is True for k in
                 ('passed', 'reaped', 'group_absent', 'pid_reserved_until_retirement')),
         'natural owned-command retirement required')
    return result.stdout


def _inputs(root_fd, policy, inputs):
    need(type(inputs) is Inputs and type(inputs.signer) is str
         and re.fullmatch('[0-9A-F]{40}', inputs.signer), 'exact TEST signing authority')
    raw = {}
    for path, expected in ((ARCHIVE, inputs.archive), (ARCHIVE + '.sig', inputs.signature),
                           (CONFIG, inputs.config), (KEYRING, inputs.keyring)):
        body, entry = fs.read_regular(root_fd, path)
        need(type(expected) is Pin, 'immutable input pins')
        expected.check(body)
        need((entry['uid'], entry['gid']) == (policy.owner_uid, policy.owner_gid)
             and entry['mode'] & 0o022 == 0, 'owned inputs without group/other writes')
        raw[path] = body
    options = {}
    section = False
    for line in raw[CONFIG].decode('ascii').splitlines():
        if not line.strip():
            continue
        if line == '[options]':
            need(not section, 'one options section'); section = True
            continue
        key, separator, value = line.partition(' = ')
        need(section and separator and key not in options, 'closed private configuration')
        options[key] = value
    need(options == OPTIONS, 'Required/Required fixed private config; no overrides/includes')


def verify_signature(status, signer):
    need(type(status) is bytes and len(status) <= 65536, 'bounded signature status')
    records = []
    for line in status.decode('ascii').splitlines():
        need(line.startswith('[GNUPG:] '), 'machine signature status only')
        parts = line[9:].split()
        need(parts and parts[0] in {'NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG'},
             'unknown, expired or invalid signature status')
        records.append(parts)
    valid = [r for r in records if r[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == signer
         and valid[0][-1] == signer, 'one exact primary-key VALIDSIG')
    need(sum(r[0] == 'GOODSIG' for r in records) == 1, 'one good signature')


def _inventory(raw, baseline):
    expected = {}
    for name, entry in baseline['db'].items():
        if '/' not in name and entry['kind'] == 'dir':
            parts = name.rsplit('-', 2)
            need(len(parts) == 3 and parts[0] not in expected, 'baseline package directory syntax')
            expected[parts[0]] = '-'.join(parts[1:])
    expected[NAME] = '0.1.0-2'
    actual = {}
    for line in raw.decode('ascii').splitlines():
        parts = line.split(' ')
        need(len(parts) == 2 and all(parts) and parts[0] not in actual, 'exact query inventory')
        actual[parts[0]] = parts[1]
    need(len(actual) == 350 and actual == expected, 'complete 349-to-350 inventory and candidate version')


def _expectations(baseline, policy, db, payload):
    need(type(db) is dict and len(db) <= 64 and type(payload) is dict
         and set(payload) == set(policy.payload_names), 'finite expected recovery namespace')
    need(len(json.dumps([db, payload], allow_nan=False)) <= 1048576, 'bounded expected records')
    db, payload = json.loads(json.dumps([db, payload], allow_nan=False))
    def shape(value, number):
        if value is None:
            return None
        need(type(value) is dict and not {'dev', 'ino', 'nlink'} & set(value),
             'content expectations exclude future identities')
        return dict(value, dev=0, ino=2**63 + number,
                    nlink=2 if value.get('kind') == 'dir' else 1)
    # Placeholder identities validate schema only; they are never evidence.
    projected = dict(db=dict(baseline['db']), payload={}, lock=None)
    projected['db'].update({n: shape(v, i) for i, (n, v) in enumerate(db.items())})
    projected['payload'] = {n: shape(v, i + 64) for i, (n, v) in enumerate(payload.items())}
    verify_recovered(baseline, projected, policy, db, payload)
    return db, payload


def recover(root_fd, baseline, policy, evidence, inputs, candidate_db, candidate_payload, runner):
    """Verify signature, remove only the exact orphan state, install and verify.

    Runner is a trusted future native owned-command adapter, not supplied here.
    This method never retries or repairs a partial failure. Expected generated DB
    metadata must be independently prepared, not inferred from this result.
    """
    completed, phase = [], 'admit'
    try:
        # Validate and freeze expectations before any command or mutation.
        candidate_db, candidate_payload = _expectations(baseline, policy, candidate_db, candidate_payload)
        snapshot = fs.snapshot(root_fd, policy.payload_names,
                               owner_uid=policy.owner_uid, owner_gid=policy.owner_gid)
        plan = classify_recovery(baseline, snapshot, policy, evidence)
        _inputs(root_fd, policy, inputs)
        phase = 'verify-signature'
        status = _run(runner, Command(phase, ('/usr/bin/gpgv', '--status-fd=1', '--keyring',
                      '/' + KEYRING, '/' + ARCHIVE + '.sig', '/' + ARCHIVE), 30, 65536))
        verify_signature(status, inputs.signer)
        _inputs(root_fd, policy, inputs)
        completed.append(phase)
        phase = 'orphan-cleanup'
        need(fs.snapshot_sha256(snapshot) == plan.interrupted_sha256, 'plan snapshot pin')
        cleanup = fs.cleanup(root_fd, policy.payload_names, snapshot,
                             owner_uid=policy.owner_uid, owner_gid=policy.owner_gid)
        need(cleanup['after_directory_sha256'] == plan.after_directory_sha256
             and cleanup['after_unlock_sha256'] == plan.after_unlock_sha256,
             'exact cleanup transitions restore baseline')
        completed.append(phase)
        _inputs(root_fd, policy, inputs)
        phase = 'signed-candidate-install'
        _run(runner, Command(phase, ('/usr/bin/pacman', '--config', '/' + CONFIG,
             '--noconfirm', '--noscriptlet', '-U', '/' + ARCHIVE), 180, 1048576))
        completed.append(phase)
        _inputs(root_fd, policy, inputs)
        phase = 'verify-recovered'
        inventory = _run(runner, Command(phase, ('/usr/bin/pacman', '--config', '/' + CONFIG,
                                         '-Q'), 30, 1048576))
        _inventory(inventory, baseline)
        recovered = fs.snapshot(root_fd, policy.payload_names,
                                owner_uid=policy.owner_uid, owner_gid=policy.owner_gid)
        verified = verify_recovered(baseline, recovered, policy, candidate_db, candidate_payload)
        completed.append(phase)
        return dict(status='VERIFIED_RECOVERY_SEQUENCE_WITH_CALLER_OWNED_ADAPTER',
                    completed=completed, snapshot_sha256=verified.snapshot_sha256,
                    cleanup=cleanup, binding=policy.binding(), retry=False,
                    native_acceptance=None)
    except Exception as error:
        raise RecoveryFailure(phase, completed, error) from error
