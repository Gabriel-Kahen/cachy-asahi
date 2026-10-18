# SPDX-License-Identifier: MIT
"""Load only the two closed historical SOURCE worker roles, never runtime code."""
import contextlib,importlib.util,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
_CACHE={}

@contextlib.contextmanager
def aliases(values):
 old={k:sys.modules.get(k)for k in values};sys.modules.update(values)
 try:yield
 finally:
  for k,v in old.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def load(role):
 if role not in('apps','welcome'):raise ValueError('exact two selected source roles')
 if role in _CACHE:return _CACHE[role]
 home=ROOT/('held-'+role+'-worker')/'scripts/ci'/('current606-apps7-copy'if role=='apps'else'current606-welcome5-copy')
 modules={}
 def one(name):
  spec=importlib.util.spec_from_file_location('_joint_'+role+'_'+name,home/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m
  with aliases(modules):spec.loader.exec_module(m)
  modules[name]=m;return m
 for n in('contract','guard','physical','lifecycle','supervised','rooted_fixture','plan','driver','alpm_step'):one(n)
 _CACHE[role]=modules;return modules
