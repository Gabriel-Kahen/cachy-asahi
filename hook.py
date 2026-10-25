# SPDX-License-Identifier: MIT
"""An actual post-transaction dispatcher witness, not a replacement hook."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,guest_guard as G
s=C.decode(C.read('/workspace/selection.json'));G.guard(s,'hook')
expected=C.decode(C.read('/run/core-hook-expected.json'));raw=sys.stdin.buffer.read(65537);C.need(len(raw)<=65536 and raw.endswith(b'\n'),'bounded genuine NeedsTargets stream');targets=raw.decode().splitlines();C.need(len(targets)==len(set(targets))and sorted(targets)==expected['targets']and expected['nonce']==s['nonce'],'exact libalpm target dispatcher')
p=Path('/run/core-hook-witness.json');C.need(not p.exists(),'one genuine hook dispatch');p.write_bytes(C.encoded(expected))
