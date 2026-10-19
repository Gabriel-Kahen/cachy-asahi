# SPDX-License-Identifier: MIT
"""Private native Apps7 pure path predicates; every filesystem check stays held."""
import ast,hashlib,re,types
from pathlib import Path
ORIGINAL='scripts/apps/full574_statx.py'
# Whole original Apps binding, including every source pin/traversal/hash body.
ORIGINAL_PIN={'bytes': 5897, 'sha256': 'bf3b6bf522d353142808f027dd3e20032648ef7d0ebb6d8aa1d8a0c50a1db51f'}
_CONTROL=re.compile('[\x00-\x1f]')
def need(ok,why):
 if not ok:raise ValueError(why)
def relative(value):
 # Exact POSIX Path.as_posix()==value predicate; the lone '.' is preserved.
 need(type(value)is str and value and '\0'not in value and not value.startswith('/')and(value=='.'or all(p not in('','.','..')for p in value.split('/'))),'noncanonical payload path')
 return value

def cap_path(name,limits,max_path):
 need(type(name)is str and name and len(name.encode('utf-8','surrogateescape'))<=max_path and '\0'not in name and _CONTROL.search(name)is None,'bounded ordinary node path required')
 parts=()if name=='.'else tuple(name.split('/'))
 need(not name.startswith('/')and(name=='.'or all(p not in('','.','..')for p in parts))and len(parts)<=limits.max_depth+1,'contained canonical node path required')
 return parts

def bind(fast,root,roots,caps,copy_scope,aux_copy,read):
 raw=read(root/ORIGINAL);need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==ORIGINAL_PIN,'whole native Apps binding source differs')
 text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='bind');body=ast.get_source_segment(text,node);original=body
 edits=[
  ("    facade=types.SimpleNamespace(**vars(roots))", "    installer=types.SimpleNamespace(**dict(vars(roots.installer),relative=_native_relative))\n    observer=clone(roots.observe,dict(roots.observe.__globals__,installer=installer))\n    private_roots=types.SimpleNamespace(**dict(vars(roots),installer=installer,observe=observer))\n    facade=types.SimpleNamespace(**vars(private_roots))"),
  ("helper._observer600(roots,path,**kwargs)","helper._observer600(private_roots,path,**kwargs)"),
  ("    cap_space=dict(vars(caps),_mount=helper._mount600(caps._mount))", "    cap_space=dict(vars(caps),_mount=helper._mount600(caps._mount),_path=lambda name,limits:_native_cap_path(name,limits,caps.MAX_PATH))"),
  ("for name in ('_scan','observe','restore')", "for name in ('_graph','validate_map','_scan','observe','restore')"),
  ("    return types.SimpleNamespace(roots=facade,caps=cap_facade,copy_scope=proof_facade,aux=aux_facade,receipt=receipt)", "    receipt['native_path_predicates']='PRIVATE_EQUIVALENT_POSIX_ONLY_NO_SYSCALL_OR_OBSERVATION_CACHE'\n    return types.SimpleNamespace(roots=facade,caps=cap_facade,copy_scope=proof_facade,aux=aux_facade,receipt=receipt)")]
 for a,b in edits:need(body.count(a)==1,'one exact private path binding seam');body=body.replace(a,b)
 inverse=body
 for a,b in reversed(edits):need(inverse.count(b)==1,'one inverse private path seam');inverse=inverse.replace(b,a)
 need(inverse==original,'all original binding bytes outside declared seams held')
 namespace=dict(vars(fast),_native_relative=relative,_native_cap_path=cap_path)
 exec(compile(body,str(root/ORIGINAL)+':private-native-path-predicates','exec'),namespace)
 return namespace['bind'](root,roots,caps,copy_scope,aux_copy,read)
