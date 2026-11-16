#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Check the exact finite predecessor inverse; never execute either source."""
import hashlib
import json
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
LOCKS = {
    'arm16k_no_package_control': '63ca909ef5828c43668fe3c56586a5fffa92badd1abcd670118802acd13213df',
    'arm16k_perl5423_vm': 'da1c8749a281b767f50ca696cf7818d1925aa852057d7de011b4c3ddd8eca75d',
}


def rows(root):
    result = {}
    for path in root.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('ordinary single-link source files required')
        raw = path.read_bytes()
        result[path.relative_to(root).as_posix()] = dict(
            bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            mode=stat.S_IMODE(info.st_mode))
    return result


def verify():
    for family, digest in LOCKS.items():
        root = HERE/'predecessor'/family
        raw = (root/'source.lock.json').read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('exact predecessor source lock required')
        expected = json.loads(raw)['files']
        observed = rows(root)
        observed.pop('source.lock.json')
        if expected != observed:
            raise ValueError('complete predecessor bytes modes membership required')
    family = 'arm16k_perl5423_vm'
    if rows(HERE/'predecessor'/family) != rows(HERE/'source'/family):
        raise ValueError('complete dependency65 must remain byte/mode identical')
    before = rows(HERE/'predecessor'/'arm16k_no_package_control')
    after = rows(HERE/'source'/'arm16k_no_package_control')
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    allowed = {'plan.py', 'contracts.py', 'operator-inputs.TEMPLATE.json',
               'test_prepare.py', 'test_warm.py', 'source.lock.json'}
    if not set(changed) <= allowed:
        raise ValueError('unexpected successor source difference')
    return dict(kind='FINITE_WARM_CONTROL_PREDECESSOR_INVERSE_V1',
        predecessor_locks=LOCKS, changed=changed, dependency65_unchanged=True,
        actor_controller_reader_constructor_unchanged=True,
        actual_source=None, actual_ref=None, actual_VM=None, Root_acceptance=None)


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True, indent=2))
