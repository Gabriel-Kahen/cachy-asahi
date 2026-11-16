#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-only bounded read-only raw DATA scan; no guest or acceptance on import."""
import argparse,hashlib,importlib.util,os,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent


def module(n):
 s=importlib.util.spec_from_file_location('perl_observer_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):raise RuntimeError('readonly DATA observer forbids '+event)


def authority(value,source,output,K):
 K.keys(value,('kind','issued_by','accepted','operation','source_lock','raw','prepared','output','uid','created_utc','expires_utc','scan_seconds','output_cap_bytes','external_resource_enforcement'),'readonly observer authority')
 K.root_cert(value,'ROOT_PERL5423_READONLY_BASELINE_AUTHORITY_V1')
 K.need(value['operation']==K.OP and value['source_lock']==source and value['output']==str(output) and value['uid']==os.getuid()!=0,'exact Root observer Source/output/UID')
 now=int(time.time());K.need(type(value['created_utc'])is type(value['expires_utc'])is int and 0<=now-value['created_utc']<=3600 and now<value['expires_utc']<=value['created_utc']+3600,'fresh finite readonly authority')
 K.need(type(value['scan_seconds'])is int and 1<=value['scan_seconds']<=900 and type(value['output_cap_bytes'])is int and 1<=value['output_cap_bytes']<=128*1024**2,'finite read-only scan and aggregate output caps')
 K.need(value['external_resource_enforcement']=='ROOT_CUSLS_WHOLE_PROCESS_MEMORY_CPU_PID_QUOTA_AND_OUTPUT_GUARD','Root external resource enforcement required; scanner supplies time/read/output bounds only')
 for n in('raw','prepared'):
  K.keys(value[n],('path','bytes','sha256'),'exact original '+n);K.ordinary(value[n]['path']);K.pin_shape({k:value[n][k]for k in('bytes','sha256')})


def render(scan,inventory):
 K,I=module('contracts'),module('image');owned=I.owners(scan,inventory)
 return {'ownership.json':K.canonical(owned),'namespace.json':K.canonical(scan['nodes']),'alpm-records.json':K.canonical(scan['records'])}


def observe(authpath,authsha,sourcesha,output):
 K,A,I=module('contracts'),module('adapter'),module('image');source=A.source(sourcesha);authpath=K.ordinary(authpath)
 K.need(K.pin(authpath)['sha256']==authsha,'external exact Root readonly authority SHA');value=K.load(authpath);output=K.ordinary(output);authority(value,source,output,K)
 K.need(not output.exists() and output.parent.is_dir() and output.parent.stat().st_uid==os.getuid() and not output.parent.stat().st_mode&0o022,'fresh private owned readonly DATA output')
 inputs={n:K.ordinary(value[n]['path'])for n in('raw','prepared')}
 K.need(all(output!=p and output not in p.parents and p not in output.parents for p in(*inputs.values(),authpath,HERE)),'readonly output disjoint from immutable inputs/Source/authority')
 deadline=time.monotonic()+value['scan_seconds'];K.END=deadline
 expected={n:{k:value[n][k]for k in('bytes','sha256')}for n in inputs}
 identity=lambda p:tuple(getattr(p.lstat(),n)for n in('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_nlink'))
 identities={n:identity(p)for n,p in inputs.items()}
 def guard():K.need(time.monotonic()<deadline,'finite readonly observation deadline')
 def verify():
  for n,p in inputs.items():
   guard();K.need(identity(p)==identities[n] and K.pin(p)==expected[n] and identity(p)==identities[n],'immutable original '+n+' pin/identity')
 verify();prepared=K.load(inputs['prepared']);inventory={}
 for row in prepared['base_packages']:
  K.need(row['name']not in inventory,'unique prepared package inventory');inventory[row['name']]=row['version']
 K.need(inventory and prepared['files']['guest.raw']==expected['raw'],'actual prepared/raw/inventory join')
 scan=I.scan(inputs['raw'],deadline,guard);rows=render(scan,inventory);verify()
 K.need(K.pin(authpath)['sha256']==authsha and A.source(sourcesha)==source,'readonly authority/Source stable')
 summary=dict(kind='OBSERVED_READONLY_EXT4_BASELINE_DATA_V1',status='READONLY_DATA_NOT_ROOT_CERTIFICATE_OR_RUNTIME_ACCEPTANCE',Source_lock=source,authority=K.pin(authpath),inputs={n:value[n]for n in inputs},inventory=inventory,baseline_count=len(inventory),nodes=len(scan['nodes']),owned_paths=len(I.owners(scan,inventory)),filesystem_free_bytes=scan['filesystem_free_bytes'],pacman_log=None if scan['log_data_b64']is None else dict(observed=True,base64=scan['log_data_b64']),files={n:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())for n,b in rows.items()},Root_baseline_certificate=None,Root_runtime_certificate=None,VM_acceptance=None,hardware_acceptance=None,limitations=['Readonly ext4 structural DATA, not filesystem-integrity acceptance','No PAM, guest execution, GPG, ALPM transaction or runtime qualification'],original_raw_and_prepared_unchanged=True)
 rows['observation.json']=K.canonical(summary)
 K.need(sum(map(len,rows.values()))<=value['output_cap_bytes'],'aggregate bounded readonly DATA output');guard();os.umask(0o077);output.mkdir(mode=0o700)
 for name,body in rows.items():
  guard()
  with(output/name).open('xb')as f:f.write(body)
  (output/name).chmod(0o600)
 verify();return {n:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())for n,b in rows.items()}


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--observe-readonly-root-bound',action='store_true')
 for n in('authority','output'):p.add_argument('--'+n,type=Path,required=True)
 for n in('authority-sha256','source-lock-sha256'):p.add_argument('--'+n,required=True)
 a=p.parse_args();K=module('contracts');K.need(a.observe_readonly_root_bound and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0,'explicit isolated ordinary-user Root-bound readonly entry');sys.addaudithook(fence)
 print(K.canonical(observe(a.authority,a.authority_sha256,a.source_lock_sha256,a.output)).decode(),end='')
if __name__=='__main__':main()
