"""Closed code-only runtime bundle; no actors, private map inputs or activation."""
import argparse,hashlib,json,os,shutil,stat
from pathlib import Path
D=Path(__file__).resolve().parent
OWN=('inputs.py','source-pins.json','policy.json','qualification-pins.json','prerequisites.py','native_prepare.py','native_controller.py','runtime_policy.py','map_join.py','lease_table.py','leases.py','runtime_context.py','supervisor.py','service.py','mount_proxy.py','bootstrap_loader.py','worker_api.py','worker.py','owner.py','dispose.py','entry.py','stage.py','disk_adapter.py','factory.py','test_controls.py','runtime_check.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary exact source');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded singlelink source');raw=path.read_bytes();need(len(raw)==s.st_size and(s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns)==(path.stat().st_dev,path.stat().st_ino,path.stat().st_mtime_ns,path.stat().st_ctime_ns),'stable source');return raw

def emit(output):
 output=output.absolute();need(not output.exists()and not output.is_symlink()and not any(p.is_symlink()for p in output.parents),'fresh ordinary output');rows=json.loads(read(D/'source-pins.json'));raw={}
 for name,row in rows['files'].items():
  b=read(D.parent/name);need(pin(b)==row,'whole input '+name);raw[name]=b
 supplement=rows['runtime_supplement'];basis=supplement['basis'];held={n[len(basis):]:b for n,b in raw.items()if n.startswith(basis)};need(len(held)==226,'whole held VM226 role')
 for name,b in held.items():raw['runtime-vm/'+name]=b
 need(supplement['output']not in raw and pin(raw[supplement['input']])==supplement['pin'],'one exact original manifest closure supplement');raw[supplement['output']]=raw[supplement['input']]
 for name in OWN:raw['immutable/'+name]=read(D/name)
 selected=json.loads(raw['immutable/qualification-pins.json']);need(all(v is None for k,v in selected.items()if k!='purpose'),'source-selected genuine prerequisite inputs remain NULL')
 policy=json.loads(raw['immutable/policy.json']);need(all(policy[k]is None for k in('actual_source','actual_ref','actual_run','kernel_build_decision','kernel_boot_decision','source_decision','producer_retirement','native_map','source_image_receipt','bootstrap','broker')),'all new-purpose qualifiers NULL')
 output.mkdir(mode=0o700)
 for name,b in raw.items():p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 proof=dict(schema_version=1,purpose='GNU_IMMUTABLE_RUNTIME_V1_SOURCE_ONLY_NOT_ACTIVATED',files={n:pin(b)for n,b in raw.items()},input_files=len(rows['files']),own_files=len(OWN),runtime_vm=dict(held=226,supplement=1,total=227),actual_source=None,actual_ref=None,actual_run=None)
 (output/'runtime-source.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n');return proof

def check(output):
 output=output.absolute();proof=json.loads(read(output/'runtime-source.json'));rows=proof['files'];need(not any(p.is_symlink()for p in output.rglob('*')if p.relative_to(output).parts[0]!='.git'),'no source symlink or directory alias');actual={p.relative_to(output).as_posix()for p in output.rglob('*')if p.is_file()and p.relative_to(output).parts[0]!='.git'}
 need(actual==set(rows)|{'runtime-source.json'},'exact bundle closure; only top-level Git metadata ignored')
 for n,row in rows.items():need(pin(read(output/n))==row,'bundle source pin '+n)
 return dict(status='PASS_CLOSED_CODE_ONLY_RUNTIME_BUNDLE',source_files=len(rows)+1,input_files=proof['input_files'],own_files=proof['own_files'],actual_source=None,actual_ref=None,actual_run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('emit','check'));p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.output)if a.action=='emit'else check(a.output),sort_keys=True))
