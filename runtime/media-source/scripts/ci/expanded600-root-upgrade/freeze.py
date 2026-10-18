#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write/check this dedicated source manifest; never bind policy or run actors."""
import argparse
from pathlib import Path
import contract as C


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--check',action='store_true');a=p.parse_args()
    root=C.safe(a.root.absolute());directory=root/'scripts/ci/expanded600-root-upgrade'
    names=[p for p in directory.iterdir() if p.suffix in ('.py','.json','.lock','.md') and p.name!='source-manifest.json']
    names.append(root/'.github/workflows/native-arm-expanded600-root-upgrade.yml')
    rows={p.relative_to(root).as_posix():dict(bytes=p.stat().st_size,sha256=C.sha(p)) for p in sorted(names)}
    manifest=directory/'source-manifest.json'
    if a.check:C.need(C.read(manifest)==rows,'dedicated source manifest differs')
    else:manifest.write_bytes(C.encoded(rows))
    print('EXPANDED600_ROOT_UPGRADE_SOURCE_FILES='+str(len(rows)));return 0


if __name__=='__main__':raise SystemExit(main())
