#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Four owned consumers: probe, two offline builds, installed setup4/5 lifecycle."""
from pathlib import Path
import sys
import contract as C
import prepare
import retained


def pair_gate(value):
    C.need(value['status']=='contents-reproduced' and not value['errors'] and len(value['packages'])==1 and all(all(row[k] is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal')) for row in value['packages'].values()),'both complete archives, BUILDINFO and payload must reproduce')


if __name__=='__main__':
    C.need('--source' in sys.argv and '--setup4-pair' in sys.argv,'explicit source and retained setup4 pair required')
    root=C.safe(Path(sys.argv[sys.argv.index('--source')+1]).absolute());C.verify_source(root)
    index=sys.argv.index('--setup4-pair');C.OLD_PAIR=C.safe(Path(sys.argv[index+1]).absolute());retained.verify(C.OLD_PAIR);del sys.argv[index:index+2]
    raise SystemExit(prepare.adapter('run',root)['main']())
