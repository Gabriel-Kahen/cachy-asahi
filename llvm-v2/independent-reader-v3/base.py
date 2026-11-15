# SPDX-License-Identifier: MIT
"""Frozen v2 passive predicates; no Source or artifact code imports."""
import ast,hashlib,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent;V2=HERE.parent/'v2'
PINS={'reader.py':'e3fed71e01be989b5c84cd0e33124ca096e452eda380f4840b45786cb385335c','pins.json':'c9a1013cac557e992ab2ad824821ad868c87d73c2b9da60e860d05a70742a328'}
def raw(name):
 p=V2/name
 if p.is_symlink()or not p.is_file()or p.stat().st_size>128*1024:raise ValueError('ordinary bounded frozen v2 predicate')
 body=p.read_bytes()
 if hashlib.sha256(body).hexdigest()!=PINS[name]:raise ValueError('frozen passive v2 input differs: '+name)
 return body
spec=importlib.util.spec_from_file_location('llvm_v3_frozen_v2',V2/'reader.py');v=importlib.util.module_from_spec(spec);exec(compile(raw('reader.py'),str(V2/'reader.py'),'exec'),v.__dict__);old_pins=v.decode(raw('pins.json'))
def historical_successor():
 """Only historical251 reads become in-memory tuples. No actual tuple changes."""
 body=raw('reader.py');nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='source_successor']
 if len(nodes)!=1:raise ValueError('one frozen historical inverse predicate')
 original=ast.get_source_segment(body.decode(),nodes[0]).encode();seams=[(b"load(source/'successor-v2.json')",b"decode(source['successor-v2.json'][0])"),(b"read(source/'actor/entry.sh')",b"source['actor/entry.sh'][0]"),(b"load(source/'contract.json')",b"decode(source['contract.json'][0])"),(b"load(source/'policy.json')",b"decode(source['policy.json'][0])"),(b"read(source/'.github/workflows/native-arm-build.yml')",b"source['.github/workflows/native-arm-build.yml'][0]"),(b"read(source/'.github/workflows/native-arm-llvm23-source-reference-v2.yml')",b"source['.github/workflows/native-arm-llvm23-source-reference-v2.yml'][0]")]
 result=original
 for old,new in seams:
  if result.count(old)!=1:raise ValueError('one exact historical Source read seam')
  result=result.replace(old,new)
 inverse=result
 for old,new in reversed(seams):
  if inverse.count(new)!=1:raise ValueError('unambiguous historical projection inverse')
  inverse=inverse.replace(new,old)
 if inverse!=original:raise ValueError('complete historical predicate inverse')
 namespace=dict(vars(v));exec(compile(result,'<frozen-passive251-in-memory-inverse>','exec'),namespace)
 return namespace['source_successor'],dict(before_sha256=hashlib.sha256(original).hexdigest(),after_sha256=hashlib.sha256(result).hexdigest(),seams=len(seams),inverse='EXACT_FUNCTION_BYTES',actual_Source_ref_run_job_map_changes=False)
