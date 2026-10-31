"""Finite source-only19-file emitter. No decisions, Git, network or actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
L='scripts/ci/gnu-verity-kernel-native';WF='.github/workflows/native-arm-gnu-verity-kernel.yml'
BORROWED={'scripts/ci/managed-gui-generic16k/build_kernel.py':('ccbead2912144c5aa4fcb3ce7af76b3c11f28fcde7987e5f32edb060ff7b0ee9',12900),'scripts/ci/managed-gui-generic16k/kernel.fragment':('88819f00ebef80e385ebdfae6cc101ef21145e0bbd6bb12532b0d41a85c16d28',1808),'scripts/ci/managed-gui-generic16k/kernel_contract.py':('30a4544e5407dbf932d9ec26bbd6bf21eab53347544afa134cd3a5870752cbff',4659),'scripts/ci/managed-gui-generic16k/run.py':('64e279b7ce4b04f115a7e1897377ce59ea5c15010a97a0f22cf16e35ce5e7e46',10493),'scripts/ci/tools-generic16k/acquire_kernel.py':('4a372e1f4bfbd1f8604579873fc6fbdec91ac2555bb36f028646017b44b8c23f',8844),'scripts/virtual/generic16k/fetch_inputs.py':('212a0a9efc7c386158526ce40683a3646a899a9c7fd2c3140d6e24a02d778043',7768),'scripts/virtual/generic16k/inputs.json':('bdfa44ed1d017c0d0e15c1f3af87bdf4a91923c20e812c861ca522d2cf428492',1057)}
OWN=('input-policy.json','lane.py','prepare.py','runtime.py','test_lane.py','verity_profile.py','fixtures/baseline.config','fixtures/configuration-rules.json','fixtures/configuration-source-proof.json')

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute source');info=path.lstat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<info.st_size<=1024**2,'bounded ordinary source');raw=path.read_bytes();need(len(raw)==info.st_size,'source size drift');return raw
def emit(own,inputs,out):
 own,inputs,out=(Path(p).absolute()for p in(own,inputs,out));need(not out.exists()and not out.is_symlink()and not any(p.is_symlink()for p in out.parents),'fresh source-only output')
 raw={}
 for n,(sha,size)in BORROWED.items():
  b=read(inputs/n);need(pin(b)==dict(bytes=size,sha256=sha),'whole borrowed input: '+n);raw[n]=b
 for n in OWN:raw[L+'/'+n]=read(own/L/n)
 policy=json.loads(raw[L+'/input-policy.json']);need(all(policy[k]is None for k in('actual_source','actual_ref','actual_run','native_package_decision')),'all future authorities NULL')
 mf=read(own/L/'source-manifest.json');row=json.loads(mf);need(row['files']=={n:pin(b)for n,b in raw.items()},'exact16 payload manifest');raw[L+'/source-manifest.json']=mf
 workflow=read(own/WF);need(raw[L+'/lane.py']and pin(raw[L+'/lane.py'])['sha256'].encode()in workflow and pin(mf)['sha256'].encode()in workflow,'fixed two workflow stamp operands');raw[WF]=workflow;raw['.github/workflows/native-arm-build.yml']=workflow;need(len(raw)==19,'closed19 source')
 out.mkdir(mode=0o700)
 for n,b in raw.items():p=out/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 return dict(status='EMITTED_SOURCE_ONLY_NO_BUILD_BOOT_OR_ACCEPTANCE',files={n:pin(b)for n,b in raw.items()},source=None,ref=None,run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('own','inputs','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.own,a.inputs,a.output),sort_keys=True))
