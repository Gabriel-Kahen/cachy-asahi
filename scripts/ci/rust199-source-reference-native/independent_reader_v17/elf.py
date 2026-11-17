# SPDX-License-Identifier: MIT
"""One explicit native4K projection of the pinned independent ELF parser.

Source326 has no16K linker promise. Record native ELF data without inventing M2
qualification; preserve the parser's class/machine/segment/dynamic bounds.
"""
import ast,hashlib
BEFORE="need(loads and all(r[7] >= 16384 and r[7] & (r[7]-1) == 0 and r[2]%16384 == r[3]%16384 for r in loads), 'actual ELF 16K PT_LOAD geometry refused')"
AFTER="need(loads and all(r[7] >= 4096 and r[7] & (r[7]-1) == 0 and r[2]%4096 == r[3]%4096 for r in loads), 'native ELF 4K PT_LOAD geometry refused; no16K qualification')"
PATH_BEFORE="(target == PREFIX or target.startswith(PREFIX+'/'))"
PATH_AFTER="(target == PREFIX or target.startswith(PREFIX+'/') or target == RUST_PREFIX or target.startswith(RUST_PREFIX+'/'))"
def parser(helper,raw):
 text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='elf');body=ast.get_source_segment(text,node)
 if body.count(BEFORE)!=1 or AFTER in body or body.count(PATH_BEFORE)!=1 or PATH_AFTER in body:raise ValueError('fixed independent ELF geometry seam')
 updated=body.replace(BEFORE,AFTER).replace(PATH_BEFORE,PATH_AFTER)
 if updated.replace(PATH_AFTER,PATH_BEFORE).replace(AFTER,BEFORE)!=body:raise ValueError('whole independent ELF inverse')
 scope=dict(helper.__dict__,RUST_PREFIX='/opt/cachy-asahi/rust199-source-reference');exec(compile(updated,'<fixed-independent-Rust-native-ELF>','exec'),scope)
 return scope['elf'],dict(before_sha256=hashlib.sha256(body.encode()).hexdigest(),after_sha256=hashlib.sha256(updated.encode()).hexdigest(),only_native4k_geometry_and_exact_rust_private_prefix_projection=True,hardware_qualification=False)
