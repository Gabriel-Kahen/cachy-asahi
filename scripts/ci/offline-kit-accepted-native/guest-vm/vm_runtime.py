# SPDX-License-Identifier: MIT
"""Private VM variant of held owned-process class: one live output bound only."""
import ast,hashlib
from pathlib import Path
COMMON_SHA='dbb12f84b78a1b4c2d4916bcd82f0993f83765f09105de638c17ebafd4ce8ecd'
OUTPUT_LIMIT=16*1024**2

def derive(common):
 raw=Path(common.__file__).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=COMMON_SHA:raise ValueError('held native process owner required')
 tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Actors')
 run=next(n for n in node.body if isinstance(n,ast.FunctionDef)and n.name=='run')
 candidates=[n for n in ast.walk(run)if isinstance(n,ast.While)and n.body and isinstance(n.body[0],ast.Assign)and len(n.body)>1 and isinstance(n.body[1],ast.If)and ast.dump(n.body[0].value,include_attributes=False)==ast.dump(ast.parse('observe()',mode='eval').body,include_attributes=False)]
 if len(candidates)!=1:raise ValueError('one held actor observation loop')
 check=ast.parse("need(os.fstat(stream.fileno()).st_size <= 16 * 1024**2, 'live VM actor output limit')").body[0]
 candidates[0].body.insert(0,check);changed=ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[]));namespace=dict(vars(common));exec(compile(changed,str(Path(__file__).absolute()),'exec'),namespace);value=namespace['Actors']
 # Strip-inverse proof: every held class AST node except the single check is exact.
 candidates[0].body.pop(0)
 original=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef)and n.name=='Actors')
 if ast.dump(node,include_attributes=False)!=ast.dump(original,include_attributes=False):raise ValueError('whole process owner inverse')
 return value
