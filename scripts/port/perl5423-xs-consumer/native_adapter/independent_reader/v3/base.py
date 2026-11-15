# SPDX-License-Identifier: MIT
"""Pinned read-only passive ancestors. No Source actor/producer/package imports."""
import ast,hashlib,importlib.util,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE=Path(os.environ.get('CACHY_XS_V3_READER_BASE',HERE.parent))
PINS={'data.py':'7f4352e07fa13ee718ecc7009c44df8b7851e8c45a815b10c3c5808c8ca49747','bootstrap.py':'3bd3b507b4fd2148db679116c9a4eeb9f54cb780c5662608d059e223d2f6552d','consumer.py':'d1dff4ae3dde90e52ce702b19a781ec717b2446de5a8b03e44b4eea2f3a93a93','v2/reader.py':'54c6a55a5b5ff2ecdce517ccb513dc9876ab9bf96f94294bf3deadf277884b25','v2/adapters.py':'0c30d617bbbcbd361efdf6c6c2803bbe69acba214e645398c6b67a079475c2fa'}
def raw(name):
 p=BASE/name
 if not p.is_absolute()or p.is_symlink()or p.stat().st_size>128*1024:raise ValueError('ordinary bounded frozen passive module')
 body=p.read_bytes()
 if hashlib.sha256(body).hexdigest()!=PINS[name]:raise ValueError('whole frozen passive module differs: '+name)
 return body

def load(name,scope,change=None):
 body=raw(name)
 if change is not None:body=change(body)
 spec=importlib.util.spec_from_file_location('xs_v3_passive_'+scope,BASE/name);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(body,str(BASE/name),'exec'),m.__dict__);return m
# These trusted passive modules define predicates; importing them enters no role.
d=load('data.py','data');previous=load('v2/reader.py','previous');previous.d=d

def original(*args):
 tree=ast.parse(raw('v2/reader.py'));nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='original']
 if len(nodes)!=1:raise ValueError('one frozen Original predicate')
 count=0
 for n in ast.walk(nodes[0]):
  if isinstance(n,ast.Constant)and n.value=='perl5423-native-xs-v2-':n.value='perl5423-native-xs-v3-';count+=1
 if count!=1:raise ValueError('one exact Original artifact-name literal projection')
 code=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]));namespace=dict(vars(previous),d=d);exec(compile(code,'<trusted-passive-v3-Original-name-projection>','exec'),namespace);return namespace['original'](*args)
