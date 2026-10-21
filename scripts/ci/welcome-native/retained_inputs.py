# SPDX-License-Identifier: MIT
"""Exact existing owned574 cache; source/Git proof precedes unchanged policy CLIs."""
import argparse,importlib.util,json,os,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def context(root,temp):
 root,temp=Path(root).absolute(),Path(temp).absolute()
 if not(root.is_dir()and temp.is_dir()and all('..'not in p.parts for p in(root,temp))and not any(p.is_symlink()for p in(root,*root.parents,temp,*temp.parents))and HERE==root/'scripts/ci/welcome-native'):raise ValueError('validated fixed source and explicit owned temp paths required')
 maintained=HERE/'retained-inputs';sys.path.insert(0,str(maintained));return root,temp,load('_welcome8_fixed_prepare',maintained/'prepare.py')
def save(path,value):
 with path.open('x')as f:json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def early(root,temp):
 start=time.monotonic();deadline=start+50;root,temp,p=context(root,temp);cases={};carrier=root/'retained-complete574-inputs'
 for case in('32','20','8'):
  m=load('_welcome8_original_archive'+case,HERE/('archive'+case+'.py'));v=m.policy(HERE/('archive'+case+'-policy.json'),root/'scripts/ci/maintained-desktop574-inputs.json');cases[case]=p.L.prefill(carrier,temp/('doctor2-frozen574-archive'+case),v,deadline,git_dir=carrier/'.git',profile_dir=p.HERE)
 result=dict(schema=1,status='WELCOME8_EXACT_LEGACY_PREFILL_DATA_ONLY',cases=cases,seconds=time.monotonic()-start,seconds_limit=50,actual=None);p.L.tick(deadline);save(temp/'welcome8-retained-early.json',result);return result

def seed(root,temp):
 start=time.monotonic();deadline=start+50;root,temp,p=context(root,temp);carrier=root/'retained-complete574-inputs';old=json.loads(p.L.read(temp/'welcome8-retained-early.json',deadline,4*1024**2));indexes={}
 for case in('32','20','8'):
  m=load('_welcome8_original_archive'+case,HERE/('archive'+case+'.py'));v=m.policy(HERE/('archive'+case+'-policy.json'),root/'scripts/ci/maintained-desktop574-inputs.json');indexes[case]=m.checked_index(temp/('doctor2-frozen574-archive'+case),v)
 prepared=p.prepare(carrier,temp/'desktop574/context/deps','desktop574',root/'scripts/ci/maintained-desktop574-inputs.json',deadline,carrier/'.git');result=dict(schema=1,status='WELCOME8_RETAINED_INPUT_DATA_ONLY',early=old,preparation=prepared,legacy_indexes=indexes,seed_seconds=time.monotonic()-start,seed_limit=50,actual=None);p.L.tick(deadline);load('_welcome8_cache_data',HERE/'cache_data.py').validate(result);save(temp/'welcome8-retained-custody.json',result);return result
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('early','seed'));parser.add_argument('--root',type=Path,required=True);parser.add_argument('--temp',type=Path,required=True);a=parser.parse_args();print(json.dumps((early if a.phase=='early'else seed)(a.root,a.temp),sort_keys=True))
