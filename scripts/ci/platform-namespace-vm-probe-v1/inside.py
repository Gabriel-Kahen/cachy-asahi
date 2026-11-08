# SPDX-License-Identifier: MIT
"""In-namespace observation; no shell and no second namespace operation."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import guest as G

if __name__ == '__main__':
    C.need(len(sys.argv) == 3, 'two explicit guest selectors')
    nonce, release = sys.argv[1:]
    G.guard(nonce, release, inner=True)
    context = G.observe()
    C.context_valid(context, release, outer=False)
    G.emit('NSVM_INSIDE_V1', nonce, context)
