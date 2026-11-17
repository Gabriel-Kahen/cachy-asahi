#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Existing readonly-observer pattern; write bounded DATA, never a Root certificate."""
import argparse,hashlib,importlib.util,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def module(n):
 s=importlib.util.spec_from_file_location('initialized_observer_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def small(path,cap):
 p=Path(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  if not(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap):raise ValueError('bounded ordinary public input DATA')
  raw=os.read(fd,cap+1);identity=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_size','st_nlink','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=before.st_size or identity(before)!=identity(os.fstat(fd)) or identity(before)!=identity(p.lstat()):raise ValueError('stable bounded public input DATA')
  return raw
 finally:os.close(fd)


def observe(auth_path,auth_sha,raw,prepared,proof_path,closure_path,output):
 Q=module('qualification');raw_auth=small(auth_path,16384);Q.need(len(raw_auth)<=16384 and hashlib.sha256(raw_auth).hexdigest()==auth_sha,'external bounded exact Root scan authority')
 import json,time
 auth=json.loads(raw_auth);Q.need(raw_auth==Q.canonical(auth),'canonical Root scan authority')
 proof_raw=small(proof_path,16384);closure_raw=small(closure_path,65536);Q.need(len(proof_raw)<=16384 and len(closure_raw)<=65536,'bounded actual empty proof and terminal closure')
 proof=json.loads(proof_raw);closure=json.loads(closure_raw);Q.need(proof_raw==Q.canonical(proof) and closure_raw==Q.canonical(closure),'canonical actual proof/closure')
 L=Q.authorize_scan(auth,proof,closure,int(time.time()));K,I=L.contracts,L.image;out=K.ordinary(output)
 K.need(str(out)==auth['output'] and not out.exists() and out.parent.is_dir() and out.parent.stat().st_uid==os.getuid() and not out.parent.stat().st_mode&0o022,'fresh explicit own-UID nonwritable initialized observation parent')
 inputs=[K.ordinary(p)for p in(raw,prepared,proof_path,closure_path,auth_path,HERE,L.root)]
 K.need(all(out!=p and out not in p.parents and p not in out.parents for p in inputs),'observation output disjoint from Source/private inputs')
 K.need(K.pin(prepared)==Q.PREPARED,'whole actual initialized prepared metadata')
 prepared_data=K.load(prepared);inventory={r['name']:r['version']for r in prepared_data['base_packages']}
 K.need(len(inventory)==len(prepared_data['base_packages'])==111 and prepared_data['files']['guest.raw']==Q.RAW,'exact initialized111 prepared/raw join')
 scan=module('scanner').scan(raw,auth,proof,closure,lambda:None);owned=I.owners(scan,inventory);snapshot=module('policy').snapshot(scan)
 rows={'namespace.json':scan['nodes'],'alpm-records.json':scan['records'],'ownership.json':owned,'scan.DATA.json':scan,'initialized-state.DATA.json':snapshot}
 rows={n:Q.canonical(v)for n,v in rows.items()}
 report=dict(kind='OBSERVED_INITIALIZED_PERL_BASELINE_DATA_V1',status='READONLY_OBSERVATION_NOT_ROOT_BASELINE_OR_RUNTIME_CERTIFICATE',source_lock=auth['source_lock'],source65_lock=Q.SOURCE65,raw=Q.RAW,prepared=Q.PREPARED,empty_proof=Q.pin(proof),empty_closure=Q.pin(closure),inventory=inventory,baseline_count=111,filesystem_free_bytes=scan['filesystem_free_bytes'],namespace=K.json_pin({p:I.stable(v)for p,v in scan['nodes'].items()}),initialized_state=K.json_pin(snapshot),files={n:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())for n,b in rows.items()},Root_scan_certificate=None,Root_baseline_certificate=None,Root_runtime_certificate=None,Root_acceptance=None,Perl_preservation=None,VM_acceptance=None,M2=None,release=None)
 rows['observation.DATA.json']=Q.canonical(report);K.need(sum(map(len,rows.values()))<=auth['output_cap_bytes'],'aggregate readonly observation output cap')
 K.need(K.pin(prepared)==Q.PREPARED and small(auth_path,16384)==raw_auth,'prepared/authority stable after observation')
 Q.source(auth['source_lock']);os.umask(0o077);out.mkdir(mode=0o700)
 for name,body in rows.items():
  with(out/name).open('xb')as f:f.write(body);f.flush();os.fsync(f.fileno())
  (out/name).chmod(0o600)
 K.need(K.pin(raw)==Q.RAW and K.pin(prepared)==Q.PREPARED and small(auth_path,16384)==raw_auth and small(proof_path,16384)==proof_raw and small(closure_path,65536)==closure_raw,'all initialized inputs invariant after DATA output')
 return report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--observe-root-initialized',action='store_true',required=True)
 for n in('authority','raw','prepared','empty-proof','empty-closure','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--authority-sha256',required=True);a=p.parse_args()
 if not(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()in(0,1000)):raise ValueError('isolated existing Root bounded observer context required')
 print(module('qualification').canonical(observe(a.authority,a.authority_sha256,a.raw,a.prepared,a.empty_proof,a.empty_closure,a.output)).decode(),end='')
if __name__=='__main__':main()
