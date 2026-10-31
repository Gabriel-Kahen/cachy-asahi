#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only final source binding after native600 acceptance; no actors or Git mutation."""
import argparse
from pathlib import Path
import policy as P


def freeze(root):
    P.policy();folder=root/P.PREFIX
    names=[str(p.relative_to(root)) for p in sorted(folder.iterdir()) if p.is_file() and p.name!='source-manifest.json']
    names.append('.github/workflows/native-arm-setup5-expanded600.yml')
    files={n:{k:v for k,v in P.ref(root/n).items() if k!='path'} for n in names}
    value=dict(schema_version=1,scope='ISOLATED_SETUP5_ON_SIGNED600_THEN_UNCHANGED_ORIGINAL_FULL600',files=files,
        hardware='NOT_RUN',native='NOT_RUN_BY_FREEZE')
    (folder/'source-manifest.json').write_bytes(P.encoded(value));return value


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);a=p.parse_args()
    print(P.encoded(freeze(P.safe(a.source_root.absolute()))).decode(),end='')
