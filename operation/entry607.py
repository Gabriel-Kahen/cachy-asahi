# SPDX-License-Identifier: MIT
"""Verified607 child dispatch; held worker supervision redirects one literal path."""
import importlib.util,os,re,sys,types
from pathlib import Path
SOURCE=Path('/source');HERE=Path(__file__).resolve().parent
LANE='scripts/ci/apps7-full574-repair-native'
PUBLIC_TRANSACTION='/source/'+LANE+'/transaction.py'
PUBLIC_INSPECTION='/source/'+LANE+'/inspection.py'
TRANSACTION='/operation/transaction607.py';INSPECTION='/operation/inspection607.py';BOUNDARY='/operation/boundary607.py'
PROFILE_ENV='APPS16_INTERRUPTION_PROFILE_SHA256'

def need(ok,why):
 if not ok:raise ValueError(why)
def _load(name,path):
 spec=importlib.util.spec_from_file_location('_apps607_entry_'+name,path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def redirect(argv):
 """Exactly one executable-script slot; every other byte and worker flag is held."""
 need(type(argv)is list and 5<len(argv)<=256 and argv[:3]==[sys.executable,'-I','-B']and argv[-1]=='--worker'and argv.count('--worker')==1 and all(type(v)is str and '\0'not in v for v in argv)and sum(len(v.encode())+1 for v in argv)<=1024**2,'exact original directly supervised worker argv')
 targets={PUBLIC_TRANSACTION:TRANSACTION,PUBLIC_INSPECTION:INSPECTION};need(argv[3]in targets,'only exact public native worker scripts redirect607')
 value=list(argv);value[3]=targets[argv[3]];need(value[:3]+value[4:]==argv[:3]+argv[4:],'all original worker arguments held');return value

def private_supervisor(original):
 """Private facade: original supervisor, kwargs and cleanup implementation held."""
 facade=types.SimpleNamespace(**vars(original));ordinary=original.run
 def run(argv,**kwargs):return ordinary(redirect(argv),**kwargs)
 facade.run=run;return facade

def bind_transaction(T,K,N):
 T.environment_guard();K.bind(T,N);T.SUP=private_supervisor(T.SUP);return T

def boundary_adapter(B,K,N):
 """Process-private boundary constants and pre-wrap closure binding only."""
 need(B.NORMAL==PUBLIC_TRANSACTION and B.WRAPPER=='/operation/boundary.py','exact held boundary constants before607 adaptation')
 ordinary=B.wrap_commit;B.NORMAL=TRANSACTION;B.WRAPPER=BOUNDARY
 def wrap_commit(T,workspace,context):
  bind_transaction(T,K,N)
  return ordinary(T,workspace,context)
 B.wrap_commit=wrap_commit;return B

def _components(kind):
 need(kind in('transaction','inspection','boundary'),'finite607 child role')
 profile=os.environ.get(PROFILE_ENV);need(type(profile)is str and re.fullmatch('[0-9a-f]{64}',profile),'independent Root607 operation profile before public code')
 X=_load('common',HERE/'common.py');X.verify(SOURCE,profile)
 B=_load('boundary',HERE/'boundary.py');B.pre_environment()
 C=_load('contract',SOURCE/LANE/'contract.py');C.source(SOURCE)
 K=_load('backend',HERE/'backend607.py');N=C.adapter(SOURCE)
 if kind=='boundary':return dict(B=B,K=K,N=N)
 T=C.load('entry607_transaction',SOURCE/LANE/'transaction.py');T.environment_guard()
 P=C.load('entry607_inspection',SOURCE/LANE/'inspection.py')if kind=='inspection'else None
 return dict(T=T,P=P,K=K,N=N)

def run(kind):
 """Each parent and every freshly executed thin worker enters this same gate."""
 parts=_components(kind);K,N=parts['K'],parts['N']
 if kind=='boundary':return boundary_adapter(parts['B'],K,N).main()
 T=bind_transaction(parts['T'],K,N)
 if kind=='transaction':return T.main()
 P=parts['P'];P.backend=lambda:T
 return P.main()
