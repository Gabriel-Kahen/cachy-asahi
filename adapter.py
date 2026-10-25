# SPDX-License-Identifier: MIT
"""Load exact immutable Core800 mechanisms, keeping all original predicate bodies."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as G
LANE='scripts/ci/core-native-lifecycle'

def core(root):
 root=Path(root);lane=root/LANE;sys.path.insert(0,str(lane))
 C=G.load('contract',lane/'contract.py');F=G.load('fixture',lane/'fixture.py');T=G.load('_core_original_container',lane/'container.py')
 G.need(Path(C.__file__).resolve()==(lane/'contract.py').resolve()and T.C is C and T.F is F,'exact source-contained full original body bindings')
 api=C.helpers(root/'runtime/runtime-vm');return type('CoreBodies',(),dict(C=C,F=F,T=T,api=api,root=root))

def source_rows(root):
 result={};root=Path(root)
 for p in root.rglob('*'):
  name=p.relative_to(root).as_posix()
  if name.split('/')[0]=='.git':continue
  G.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary closed immutable source')
  if p.is_file():result[name]=G.pin(G.read(p,32*1024**2))
 return result

def verify(root,profile):
 G.need(set(profile)=={'source','ref','files'}and len(profile['source'])==40,'whole genuine source profile')
 G.need(source_rows(root)==profile['files'],'every immutable input source member/pin');return profile
