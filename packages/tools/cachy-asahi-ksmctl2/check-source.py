#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 cachy-asahi contributors
"""Verify original/derived/license/diff pins without executing package sources."""
import difflib
import hashlib
import json
from pathlib import Path
import sys


def main():
    root = Path(__file__).resolve().parent
    try:
        record = json.loads((root / 'source-provenance.json').read_bytes())
        for name, key in (('upstream-ksmctl', 'upstream_sha256'), ('cachy-asahi-ksmctl', 'derived_source_sha256'),
                          ('LICENSE', 'license_sha256'), ('adaptation.patch', 'patch_sha256')):
            path = root / name
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record[key]:
                raise ValueError('source provenance differs: ' + name)
        if (record['upstream_commit'] != 'c7cf5b4f2c70f28ed50601b3f75b19da93ba663f'
                or record['upstream_sha256'] != 'cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9'
                or record['license_sha256'] != 'edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6'
                or record['license'] != 'GPL-2.0-or-later'):
            raise ValueError('reviewed origin/license declaration differs')
        origin = (root / 'upstream-ksmctl').read_text()
        derived = (root / 'cachy-asahi-ksmctl').read_text()
        notice = []
        for line in origin.splitlines()[1:]:
            if not line.startswith('#'):
                break
            notice.append(line)
        if any(line not in derived.splitlines() for line in notice):
            raise ValueError('original copyright/GPL notice missing')
        patch = ''.join(difflib.unified_diff(origin.splitlines(True), derived.splitlines(True),
                                            fromfile='upstream/ksmctl', tofile='cachy-asahi-ksmctl'))
        if patch != (root / 'adaptation.patch').read_text():
            raise ValueError('adaptation patch differs from complete source change')
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    print('PASS: original, derivative, license and complete diff match pinned provenance')
    return 0


if __name__ == '__main__':
    sys.exit(main())
