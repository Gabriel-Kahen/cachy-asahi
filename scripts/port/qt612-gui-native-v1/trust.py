# SPDX-License-Identifier: MIT
"""Finite GUI namespace projection of the unchanged public TEST verifier."""
import hashlib
from pathlib import Path

SHARED_PIN = dict(bytes=13961, sha256='4beeabd05804712fe6696d8cebc288b93b59b05ad58caf8208cd31769d6b16dc')
CHANGES = (
    ('BANKSTOWN_QT3_PROJECT_TEST_SIGNATURE_ONLY', 'QT612_GUI18_PROJECT_TEST_SIGNATURE_ONLY_V1'),
    ("Path(__file__).resolve().parents[1] / 'management-tools-generic16k/signature_observer.py'",
     "Path(__file__).resolve().parents[3] / 'scripts/ci/management-tools-generic16k/signature_observer.py'"),
)


def project(raw):
    if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != SHARED_PIN:
        raise ValueError('whole unchanged signature verifier pin')
    value = raw.decode()
    for before, after in CHANGES:
        if value.count(before) != 1 or after in value:
            raise ValueError('exact finite GUI signature namespace projection')
        value = value.replace(before, after, 1)
    restored = value
    for before, after in reversed(CHANGES):
        restored = restored.replace(after, before, 1)
    if restored.encode() != raw:
        raise ValueError('whole signature algorithm inverse')
    return value.encode()


_path = Path(__file__).resolve().with_name('signature-shared.py.DATA')
if _path.is_symlink() or _path.stat().st_nlink != 1:
    raise ValueError('ordinary retained signature program')
exec(compile(project(_path.read_bytes()), str(_path) + ':GUI18', 'exec'), globals())
