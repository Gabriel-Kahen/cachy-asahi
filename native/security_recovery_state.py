# SPDX-License-Identifier: MIT
"""Pure, bounded recovery DATA checks; no filesystem, process or package actors.

The caller must authenticate its future checkpoint, frozen baseline, signed
candidate expectations and owned-interruption retirement receipts. Dictionary
checks here do not authenticate those facts or establish native acceptance.
"""
from dataclasses import dataclass
import hashlib
import json
import re

NAME = 'cachy-asahi-security-maintenance'
OLD = NAME + '-0.1.0-1'
NEW = NAME + '-0.1.0-2'
PROTOCOL = 'security-upgrade-interruption-empty-db-v1'
PHASE = 'AFTER_OLD_REMOVAL_BEFORE_CANDIDATE_EXTRACTION'
EMPTY = hashlib.sha256(b'').hexdigest()
OLD_OBSERVATION_SOURCES = frozenset({
    'ff8241ec2c73b69d6e54b8ee15209ef30760d619',
    '850368889d6dcabdc8afbe87f64f05650c44f90a',
})
BASE_FIELDS = frozenset({'kind', 'dev', 'ino', 'mode', 'uid', 'gid', 'nlink'})


class RecoveryRefusal(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise RecoveryRefusal(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def snapshot_sha256(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def natural(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**64-1


def relative(name):
    return (type(name) is str and len(name) <= 512 and re.fullmatch(r'[A-Za-z0-9_./+:@-]+', name)
            and not name.startswith('/') and len(name.split('/')) <= 16
            and all(re.fullmatch(r'[A-Za-z0-9_.+:@-]+', p) and p not in ('.', '..')
                    for p in name.split('/')))


@dataclass(frozen=True)
class Entry:
    kind: str
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    bytes: int | None = None
    sha256: str | None = None

    def as_record(self):
        record = {k: getattr(self, k) for k in BASE_FIELDS}
        if self.kind == 'file':
            record.update(bytes=self.bytes, sha256=self.sha256)
        return record


def entry(record):
    need(type(record) is dict and record.get('kind') in ('dir', 'file'), 'ordinary entry only')
    fields = BASE_FIELDS | ({'bytes', 'sha256'} if record['kind'] == 'file' else set())
    need(set(record) == fields, 'exact entry fields')
    need(all(natural(record[k], 1 if k in ('ino', 'nlink') else 0)
             for k in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink')), 'entry integer metadata')
    need(record['mode'] <= 0o7777, 'permission bits only')
    if record['kind'] == 'file':
        need(record['nlink'] == 1 and natural(record['bytes']) and record['bytes'] <= 1024**2,
             'single-link file and 1MiB leaf bound')
        need(type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}', record['sha256']), 'file digest')
        need(record['bytes'] != 0 or record['sha256'] == EMPTY, 'empty file digest')
    else:
        need(1 <= record['nlink'] <= 4098, 'directory link bound')
    return Entry(**record)


@dataclass(frozen=True)
class RecoveryPolicy:
    source: str
    ref: str
    run: str
    payload_names: tuple[str, ...]
    owner_uid: int = 0
    owner_gid: int = 0
    attempt: int = 1
    baseline_packages: int = 349

    def binding(self):
        return dict(source=self.source, ref=self.ref, run=self.run, attempt=self.attempt)

    def validate(self):
        need(type(self.source) is str and re.fullmatch('[0-9a-f]{40}', self.source)
             and self.source not in OLD_OBSERVATION_SOURCES, 'fresh interruption Source; old observation roles consumed')
        need(type(self.ref) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9._+/-]+', self.ref)
             and relative(self.ref) and '..' not in self.ref
             and not self.ref.endswith('.')
             and all(not part.startswith('.') and not part.endswith('.lock') for part in self.ref.split('/')),
             'literal valid future Git ref')
        need(type(self.run) is str and re.fullmatch('[1-9][0-9]{0,19}', self.run)
             and type(self.attempt) is int and self.attempt == 1, 'fresh actual run/attempt')
        need(type(self.payload_names) is tuple and 1 <= len(self.payload_names) <= 64
             and len(set(self.payload_names)) == len(self.payload_names)
             and all(relative(n) for n in self.payload_names), 'finite unique usr-relative payload names')
        need(natural(self.owner_uid) and natural(self.owner_gid)
             and type(self.baseline_packages) is int and self.baseline_packages == 349, 'fixed 349 baseline and owner')


def validate_snapshot(snapshot, policy):
    need(type(snapshot) is dict and set(snapshot) == {'db', 'payload', 'lock'}, 'exact snapshot fields')
    db, payload = snapshot['db'], snapshot['payload']
    need(type(db) is dict and len(db) <= 4096 and type(payload) is dict
         and set(payload) == set(policy.payload_names), 'finite complete database and declared payload')
    total = 0
    for name, value in db.items():
        need(relative(name), 'relative database entry')
        item = entry(value)
        need(item.uid == policy.owner_uid and item.gid == policy.owner_gid, 'database owner')
        components = name.split('/')
        for i in range(1, len(components)):
            ancestor = '/'.join(components[:i])
            need(ancestor in db and db[ancestor]['kind'] == 'dir', 'complete database directory namespace')
        total += item.bytes or 0
    for value in payload.values():
        if value is not None:
            item = entry(value)
            need(item.kind == 'file' and item.uid == policy.owner_uid and item.gid == policy.owner_gid,
                 'ordinary owned payload')
            total += item.bytes
    if snapshot['lock'] is not None:
        item = entry(snapshot['lock'])
        need(item.kind == 'file' and item.uid == policy.owner_uid and item.gid == policy.owner_gid, 'owned ordinary lock')
    need(total <= 64*1024**2 and len(encoded(snapshot)) <= 1024**2, '64MiB data and 1MiB snapshot bounds')


def _baseline(snapshot, policy):
    validate_snapshot(snapshot, policy)
    db = snapshot['db']
    need(snapshot['lock'] is None and all(v is None for v in snapshot['payload'].values()), 'clean pre-package baseline')
    roots = [n for n, value in db.items() if '/' not in n and value['kind'] == 'dir']
    names = []
    for root in roots:
        parts = root.rsplit('-', 2)
        need(len(parts) == 3 and all(parts), 'package directory requires name-version-release')
        need(parts[0] != NAME, 'baseline excludes every Security package version')
        names.append(parts[0])
    need(len(roots) == len(set(names)) == policy.baseline_packages,
         'exact 349 distinct baseline package identities')


@dataclass(frozen=True)
class RecoveryPlan:
    interrupted_sha256: str
    after_directory_sha256: str
    after_unlock_sha256: str
    empty_directory: Entry
    stale_lock: Entry
    cleanup_order: tuple[str, str] = ('var/lib/pacman/local/' + NEW, 'var/lib/pacman/db.lck')
    status: str = 'RECOVER_ONLY_EMPTY_PREPARED_DB_AND_OWNED_STALE_LOCK'


def classify_recovery(baseline, interrupted, policy, evidence):
    """Authorize DATA plan only; caller owns receipt authentication and runtime fencing."""
    need(type(policy) is RecoveryPolicy, 'exact recovery policy')
    policy.validate()
    _baseline(baseline, policy)
    validate_snapshot(interrupted, policy)
    need(type(evidence) is dict and set(evidence) == {'protocol', 'binding', 'baseline_sha256', 'checkpoint', 'retirement'}, 'new interruption evidence fields')
    need(evidence['protocol'] == PROTOCOL and evidence['binding'] == policy.binding()
         and type(evidence['binding']) is dict and type(evidence['binding'].get('attempt')) is int,
         'exact new protocol and actual binding')
    need(evidence['baseline_sha256'] == snapshot_sha256(baseline), 'frozen baseline binding')
    cp, retired = evidence['checkpoint'], evidence['retirement']
    need(type(cp) is dict and set(cp) == {'type', 'phase', 'package', 'pid', 'ppid', 'starttime', 'event', 'percent', 'howmany', 'current', 'prepared_directory', 'lock'}, 'exact checkpoint fields')
    need(cp['type'] == 'FIRST_UPGRADE_ZERO' and cp['phase'] == PHASE and cp['package'] == NAME,
         'Security pre-extraction upgrade checkpoint')
    need(all(type(cp[k]) is int and cp[k] == v for k, v in {'event': 1, 'percent': 0, 'howmany': 1, 'current': 1}.items())
         and natural(cp['pid'], 2) and natural(cp['ppid'], 2) and cp['pid'] != cp['ppid'] and natural(cp['starttime'], 1), 'one first-zero callback and owned process identity')
    need(type(retired) is dict and set(retired) == {'pid', 'starttime', 'method', 'signal', 'reaped', 'group_absent', 'descendants_absent', 'pid_reserved_until_retirement', 'checkpoint_blocked_until_interrupt'}, 'exact owned retirement fields')
    need(type(retired['pid']) is int and retired['pid'] == cp['pid'] and type(retired['starttime']) is int and retired['starttime'] == cp['starttime']
         and retired['method'] == 'OWNED_PIDFD_INTERRUPT' and type(retired['signal']) is int and retired['signal'] == 9
         and all(retired[k] is True for k in ('reaped', 'group_absent', 'descendants_absent', 'pid_reserved_until_retirement', 'checkpoint_blocked_until_interrupt')), 'verified owned interruption retirement required; no normal-END reuse')
    db = interrupted['db']
    need(set(db) == set(baseline['db']) | {NEW}
         and encoded({n: v for n, v in db.items() if n != NEW}) == encoded(baseline['db']), 'only one empty prepared directory over exact baseline')
    directory = entry(db[NEW])
    need(directory.kind == 'dir' and directory.mode == 0o755 and directory.nlink in (1, 2)
         and encoded(cp['prepared_directory']) == encoded(db[NEW]), 'exact empty prepared directory identity')
    need(all(v is None for v in interrupted['payload'].values()), 'no old or candidate payload remains')
    lock = entry(interrupted['lock'])
    need(lock.kind == 'file' and lock.mode == 0 and lock.bytes == 0
         and encoded(cp['lock']) == encoded(interrupted['lock']), 'exact empty mode000 checkpoint lock')
    after_dir = dict(db=baseline['db'], payload=interrupted['payload'], lock=interrupted['lock'])
    after_lock = dict(db=baseline['db'], payload=interrupted['payload'], lock=None)
    return RecoveryPlan(snapshot_sha256(interrupted), snapshot_sha256(after_dir), snapshot_sha256(after_lock), directory, lock)


def _content(record):
    item = entry(record)
    return {k: v for k, v in item.as_record().items() if k not in ('dev', 'ino', 'nlink')}


def _expected(record):
    need(type(record) is dict and record.get('kind') in ('file', 'dir'), 'ordinary expected candidate content')
    fields = {'kind', 'mode', 'uid', 'gid'} | ({'bytes', 'sha256'} if record['kind'] == 'file' else set())
    need(set(record) == fields, 'candidate expectations exclude object identities')
    entry(dict(record, dev=0, ino=1, nlink=1))


@dataclass(frozen=True)
class RecoveryVerification:
    snapshot_sha256: str
    status: str = 'VERIFIED_RECOVERED_STATE_DATA_ONLY'


def verify_recovered(baseline, recovered, policy, candidate_db, candidate_payload):
    """Check trusted expected candidate content; never return another cleanup plan.

    Candidate DB expectations include pacman's generated metadata, and must come
    from a separately verified native/control authority, not just archive claims.
    Expected entries omit dev/ino/nlink because the installation creates objects.
    """
    need(type(policy) is RecoveryPolicy, 'exact recovery policy')
    policy.validate()
    _baseline(baseline, policy)
    validate_snapshot(recovered, policy)
    need(recovered['lock'] is None, 'successful pacman released its lock')
    need(type(candidate_db) is dict and NEW in candidate_db and type(candidate_payload) is dict
         and set(candidate_payload) == set(policy.payload_names)
         and all(type(v) is dict for v in candidate_db.values())
         and all(v is None or type(v) is dict for v in candidate_payload.values()), 'complete trusted candidate expectations')
    need(all(relative(n) and (n == NEW or n.startswith(NEW + '/')) for n in candidate_db), 'candidate database scope only')
    for value in list(candidate_db.values()) + [v for v in candidate_payload.values() if v is not None]:
        _expected(value)
    need(candidate_db[NEW].get('kind') == 'dir' and all(candidate_db.get(NEW + '/' + leaf, {}).get('kind') == 'file' for leaf in ('desc', 'files')), 'candidate directory plus desc/files metadata required')
    need(set(recovered['db']) == set(baseline['db']) | set(candidate_db)
         and encoded({n: recovered['db'][n] for n in baseline['db']}) == encoded(baseline['db']), 'baseline database held after recovery')
    need(all(encoded(_content(recovered['db'][n])) == encoded(value) for n, value in candidate_db.items()), 'exact expected candidate database content and permissions')
    need(all(encoded(_content(recovered['payload'][n]) if recovered['payload'][n] is not None else None) == encoded(value)
             for n, value in candidate_payload.items()), 'exact expected candidate payload content and permissions')
    return RecoveryVerification(snapshot_sha256(recovered))
