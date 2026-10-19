#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact Boot79 from its genuine source; default remains UNBOUND."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
CARRIER='2c524830adb007e3b49392ceb54dd4cc5236c77d'

def need(ok,message):
 if not ok:raise ValueError(message)
def ordinary(path):
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute input required');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=16*1024**2,'bounded regular input required');return path.read_bytes()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(p not in ('','.','..')for p in name.split('/')),'safe relative input required');return Path(name)
def files(root):
 need(root.is_absolute()and root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary absolute root required');result={}
 for base,dirs,names in os.walk(root):
  if Path(base)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  need(not any((Path(base)/n).is_symlink()for n in dirs),'directory alias refused')
  for n in names:
   p=Path(base)/n;result[p.relative_to(root).as_posix()]=pin(ordinary(p))
 return result

def prepare(current,native,output,selected=False):
 lock=json.loads(ordinary(HERE/'source.json'));need(lock['schema_version']==1 and lock['carrier_source']==CARRIER and len(lock['selected_files'])==len(lock['default_files'])==79,'finite genuine Boot79 required')
 need(all(lock[n]is None for n in('actual_source','actual_ref','actual_run')),'actual identities must remain NULL');need(files(native)==lock['selected_files'],'whole genuine Boot79 source differs')
 recipe=current/relative(lock['boot_recipe']);need({p.name for p in recipe.iterdir()}=={Path(n).name for n in lock['boot_files']}and len(lock['boot_files'])==7,'current Boot seven-input set differs')
 for n,row in lock['boot_files'].items():need(pin(ordinary(current/relative(n)))==row,'current Boot input differs: '+n)
 expected=lock['selected_files']if selected else lock['default_files'];need(set(expected)==set(lock['selected_files'])and len(lock['default_delta'])==5,'finite selected/default closure required')
 need(output.is_absolute()and output.parent.is_dir()and not output.exists()and native not in output.parents and not any(p.is_symlink()for p in(output,*output.parents)),'fresh separate output required')
 planned={n:ordinary(native/relative(n))for n in lock['selected_files']}
 if not selected:
  for n,text in lock['default_delta'].items():need(n in planned,'unexpected default operand');planned[n]=text.encode()
 need({n:pin(raw)for n,raw in planned.items()}==expected,'whole selected/default79 emission differs')
 policy=json.loads(planned['scripts/ci/welcome-native/boot-policy.json']);need(all(policy[n]is None for n in('actual_source','actual_ref','actual_run')),'actual identities must remain NULL');need(policy['status']==('ROOT_SELECTED_BOOT_NATIVE_PAIR'if selected else'UNBOUND'),'default selection differs')
 if not selected:need(all(policy[n]is None for n in('recipe','version','input_sha256')),'default operands must remain NULL')
 # Complete inputs and planned output are authenticated before output creation.
 output.mkdir(mode=0o700)
 for n,raw in planned.items():
  p=output/relative(n);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
 need(files(output)==expected,'post-copy whole79 differs')
 return dict(status='EMITTED_EXACT_SOURCE_ONLY',carrier=CARRIER,files=79,selected=selected,source=None,ref=None,run=None,hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('current-root','native-root','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--selected',action='store_true');a=p.parse_args();print(json.dumps(prepare(a.current_root.absolute(),a.native_root.absolute(),a.output.absolute(),a.selected),sort_keys=True))
