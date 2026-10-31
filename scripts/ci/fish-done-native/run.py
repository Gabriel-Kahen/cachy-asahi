#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fish-only adapter; the frozen three-package native lane is unchanged."""
from pathlib import Path
import sys
import contract as C
import prepare


def pair_gate(result):
    C.need(result['status']=='contents-reproduced' and not result['errors'] and len(result['packages'])==1 and
           all(all(row[k] is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'))
               for row in result['packages'].values()),'complete Fish archive bytes and payload must reproduce')


if __name__=='__main__':
    # The inherited parser supplies the same --source/--base-dir/--output/--consumer-token contract.
    C.need('--source' in sys.argv,'explicit source root required')
    root=C.safe(Path(sys.argv[sys.argv.index('--source')+1]).absolute());C.verify_source(root)
    prepare.adapter('run',root)['main']()
