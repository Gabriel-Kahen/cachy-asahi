# SPDX-License-Identifier: MIT
"""Same-process identity immediately before the sole fixed bwrap exec."""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import guest as G


def main(nonce, release):
    G.guard(nonce, release)
    context = G.observe()
    C.context_valid(context, release)
    selected = C.decode(C.read(Path('/probe/selection.json')))
    binary = Path('/usr/bin/bwrap')
    info = binary.lstat()
    C.need(info.st_uid == info.st_gid == 0 and info.st_mode & 0o7777 == 0o755 and
           C.pin(C.read(binary, 16 * 1024**2)) == selected['bwrap'], 'non-setuid exact selected bwrap')
    context['bwrap'] = dict(selected['bwrap'], mode=0o755, uid=info.st_uid, gid=info.st_gid)
    G.emit('NSVM_EXEC_V1', nonce, context)
    try:
        os.execve(C.BWRAP[0], C.BWRAP + [nonce, release], C.ENV)
    except OSError:
        return 126


if __name__ == '__main__':
    C.need(len(sys.argv) == 3, 'two explicit guest selectors')
    raise SystemExit(main(*sys.argv[1:]))
