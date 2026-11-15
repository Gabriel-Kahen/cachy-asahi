# SPDX-License-Identifier: MIT
"""Verify only the enumerated whole-native ALPM reader and diagnostic delta."""
import ast,hashlib
BEFORE=b"    packages = []\n    for desc in Path('/var/lib/pacman/local').glob('*/desc'):\n        c.need(len(packages) < 400, 'finite installed image inventory')\n        rows = c.read(desc, 1024**2).decode().splitlines()\n        packages.append(rows[rows.index('%NAME%') + 1] + ' ' + rows[rows.index('%VERSION%') + 1])\n    inventory = ('\\n'.join(sorted(packages)) + '\\n').encode()\n    c.need(c.pin(inventory)['sha256'] == INVENTORY and inventory == p.pinned(xs['inventory'], 1024**2),\n           'actual signed349 image inventory differs')\n"
AFTER=b"    admitted_raw = p.pinned(xs['inventory'], 1024**2)\n    admitted = alpm_inventory(admitted_raw)\n    packages = []\n    for desc in Path('/var/lib/pacman/local').glob('*/desc'):\n        c.need(len(packages) < 400, 'finite installed image inventory')\n        packages.append(read_alpm_desc(desc, admitted))\n    inventory = ('\\n'.join(sorted(packages)) + '\\n').encode()\n    c.need(c.pin(inventory)['sha256'] == INVENTORY and inventory == admitted_raw,\n           'actual signed349 image inventory differs')\n"
HELPERS={'alpm_inventory': {'bytes': 900, 'sha256': 'e413cd3397184d2b7cd7dd633a0204355fc73b0feb88b9ac104afc429e7a6e3c'}, 'read_alpm_desc': {'bytes': 2972, 'sha256': 'b890eb609023d5c62917eb0d35392bf8353a97207205a92eb1a2872442cbbf60'}}

def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def functions(raw):
 text=raw.decode();return {n.name:ast.get_source_segment(text,n).encode()for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
def validate(old,new,io):
 a,b=functions(old),functions(new);io.need(set(b)==set(a)|set(HELPERS),'only two new ALPM desc helpers')
 io.need(all(pin(b[n])==v for n,v in HELPERS.items()),'exact reviewed bounded fixed-root ALPM descriptor functions')
 io.need(a['actor'].count(BEFORE)==b['actor'].count(AFTER)==1 and b['actor'].replace(AFTER,BEFORE)==a['actor'],'one exact actor inventory seam')
 old_comment=b'code = actor(admission_sha)  # Original actor/probe/JSON implementation is byte-identical.'
 new_comment=b'code = actor(admission_sha)  # Explicit v6 ALPM-read seam; other runtime probes/JSON are unchanged.'
 old_error=b'                raise failure from error'
 new_error=b"                failure.add_note('XS v6 preentry receipt unavailable: ' + type(error).__name__ + ': ' + str(error)[:512])\n                raise failure from None"
 io.need(b['actor_dispatch'].count(new_comment)==b['actor_dispatch'].count(new_error)==1 and b['actor_dispatch'].replace(new_comment,old_comment).replace(new_error,old_error)==a['actor_dispatch'],'only primary error preservation diagnostic seam')
 start=new.index(b'def alpm_inventory(');end=new.index(b'def actor(admission_sha):',start);restored=(new[:start]+new[end:]).replace(AFTER,BEFORE).replace(new_comment,old_comment).replace(new_error,old_error)
 io.need(restored==old,'whole native inverse: global imports/constants/path/runtime/probes/caps/work/budgets unchanged')
 return dict(actor_before=pin(a['actor']),actor_after=pin(b['actor']),frozen_functions={n:pin(a[n])for n in('operation','inputs','bundle_check','daemon_join')},helpers=HELPERS,global_path_guard='UNCHANGED',primary_error='PRESERVE_PRIMARY_WITH_BOUNDED_SECONDARY_NOTE_NO_EARLY_SUCCESS')
