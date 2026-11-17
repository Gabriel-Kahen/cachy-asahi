# SPDX-License-Identifier: MIT
"""One-leaf Source387 diagnostic delta; preserve commands/predicates/statuses."""
import hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD=b'''checkpoint_phase cache_restoration
initialized_cache_transaction_restored
initialized_guard
cache_snapshot > "$S/after.cache";same_bytes "$S/before.cache" "$S/after.cache"
'''
NEW=b'''checkpoint_phase cache_restoration
_cr_mark RESTORED_ENTER
initialized_cache_transaction_restored
_cr_mark RESTORED_DONE
_cr_mark GUARD_ENTER
initialized_guard
_cr_mark GUARD_DONE
{ _cr_public RESTORED; } 2>/dev/null || :
_cr_mark SNAPSHOT_ENTER
cache_snapshot > "$S/after.cache"
_cr_mark SNAPSHOT_DONE
_cr_mark COMPARE_ENTER
same_bytes "$S/before.cache" "$S/after.cache"
_cr_mark COMPARE_DONE
'''
BASE=b'cache_snapshot > "$S/before.cache"\n'
BASE_NEW=BASE+b'_cr_mark BASELINE_CAPTURED\n{ _cr_public BASELINE; } 2>/dev/null || :\n'
def need(v,why):
 if not v:raise ValueError(why)
def pin(body):return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
def verify():
 v=json.loads((HERE/'source.lock.json').read_bytes());files=v['files'];need({p.name for p in HERE.iterdir()}==set(files)|{'source.lock.json'},'closed diagnostic family')
 for n,row in files.items():
  p=HERE/n;need(not p.is_symlink()and dict(**pin(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode))==row,'whole diagnostic bytes/mode')
def transform(root):
 verify();v=json.loads((HERE/'inputs.DATA.json').read_bytes());need(pin(root)==v['root'],'exact frozen Source387 root preimage');need(root.count(OLD)==root.count(BASE)==root.count(b'cache_snapshot() (')==1,'one unchanged restoration/baseline snapshot location')
 helper=(HERE/'diagnostics.sh').read_bytes();result=root.replace(b'cache_snapshot() (',helper+b'\ncache_snapshot() (').replace(OLD,NEW).replace(BASE,BASE_NEW);return result

def inverse(generated):
 verify();helper=(HERE/'diagnostics.sh').read_bytes();need(generated.count(helper+b'\ncache_snapshot() (')==generated.count(NEW)==generated.count(BASE_NEW)==1,'exact diagnostic delta membership');old=generated.replace(helper+b'\ncache_snapshot() (',b'cache_snapshot() (').replace(NEW,OLD).replace(BASE_NEW,BASE);need(transform(old)==generated,'whole source root inverse');return old
