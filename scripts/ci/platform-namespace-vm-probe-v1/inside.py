# SPDX-License-Identifier: MIT
"""Raw inner context plus kernel credential packet; no second namespace operation."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import guest as G
import witness as W


def main(nonce, release):
    G.guard(nonce, release, inner=True)
    context = G.observe()
    W.send(context, nonce, release)  # Retain raw observation before any parent acceptance predicate.
    C.context_shape(context, release, outer=False)
    G.emit('NSVM_INSIDE_V1', nonce, context)
    return 0


if __name__ == '__main__':
    C.need(len(sys.argv) == 3, 'two explicit guest selectors')
    raise SystemExit(main(*sys.argv[1:]))
