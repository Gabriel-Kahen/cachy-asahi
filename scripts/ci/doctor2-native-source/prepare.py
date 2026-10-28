#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Close exact Doctor2 native62 from genuine705 source; default stays UNBOUND."""
import argparse,hashlib,json,os,shutil,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
CARRIER='705c5a095f9cabbfd2f3cd137127f4bbc7665f52'

def need(ok,message):
 if not ok:raise ValueError(message)
def ordinary(path):
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute source required');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=16*1024**2,'bounded regular source required');return path.read_bytes()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(p not in ('','.','..')for p in name.split('/')),'safe relative source required');return Path(name)
def files(root):
 result={}
 for base,dirs,names in os.walk(root):
  if Path(base)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  need(not any((Path(base)/n).is_symlink()for n in dirs),'source directory alias refused')
  for n in names:
   p=Path(base)/n;result[p.relative_to(root).as_posix()]=pin(ordinary(p))
 return result

def prepare(current,native,output,selected=False):
 lock=json.loads(ordinary(HERE/'source.json'));need(lock['carrier_source']==CARRIER and len(lock['selected_files'])==len(lock['default_files'])==62,'finite genuine705 source62 required')
 need(files(native)==lock['selected_files'],'closed exact public705 source required')
 need({p.name for p in(current/lock['doctor_recipe']).iterdir()}=={Path(n).name for n in lock['doctor_files']},'current Doctor2 eight-input set differs')
 for n,row in lock['doctor_files'].items():need(pin(ordinary(current/relative(n)))==row,'current Doctor2 differs from native source: '+n)
 expected=lock['selected_files']if selected else lock['default_files'];need(len(lock['doctor_files'])==8 and set(expected)==set(lock['selected_files']),'finite Doctor2 recipe/context required')
 need(output.is_absolute()and output.parent.is_dir()and not output.exists()and native not in output.parents and not any(p.is_symlink()for p in(output,*output.parents)),'fresh separate source output required')
 # Read and validate everything before creating output. No Git/API or candidate actor.
 planned={n:ordinary(native/relative(n))for n in lock['selected_files']}
 if not selected:
  for n,text in lock['default_delta'].items():need(n in planned,'unexpected default operand');planned[n]=text.encode()
 need({n:pin(raw)for n,raw in planned.items()}==expected,'default/selected whole62 emission differs')
 output.mkdir(mode=0o700)
 for n,raw in planned.items():
  p=output/relative(n);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
 need(files(output)==expected,'post-copy whole62 source differs')
 policy=json.loads((output/'scripts/ci/welcome-native/doctor2-policy.json').read_bytes());need(all(policy[n]is None for n in('actual_source','actual_ref','actual_run')),'actual source/ref/run must remain NULL');need(policy['status']==('ROOT_SELECTED_DOCTOR2_NATIVE_PAIR'if selected else'UNBOUND'),'default selection differs')
 return dict(status='EMITTED_EXACT_SOURCE_ONLY',carrier=CARRIER,files=62,selected=selected,source=None,ref=None,run=None,hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('current-root','native-root','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--selected',action='store_true');a=p.parse_args();print(json.dumps(prepare(a.current_root.absolute(),a.native_root.absolute(),a.output.absolute(),a.selected),sort_keys=True))
