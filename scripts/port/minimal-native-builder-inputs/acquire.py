# SPDX-License-Identifier: MIT
"""Retrieve exact builder operands as DATA; authentication/native entry refuse."""
import argparse,base64,concurrent.futures,hashlib,importlib.util,json,os,shutil,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pin(p):return dict(bytes=p.stat().st_size,sha256=sha(p))
def engine():
 n='scripts/port/supported-composition/ci-runtime/acquire.py';e=json.loads((HERE/'profile.DATA.json').read_bytes())['engines'][n];p=ROOT/n;need(pin(p)==e,'whole maintained acquisition helper');s=importlib.util.spec_from_file_location('bounded_existing_composition_acquisition',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def acquire(lock_path,lock_sha,cache,*,transfer=None,total_seconds=900):
 need(lock_path.is_absolute()and not any(p.is_symlink()for p in(lock_path,*lock_path.parents))and sha(lock_path)==lock_sha,'externally pinned exact builder lock')
 need(pin(lock_path)==json.loads((HERE/'profile.DATA.json').read_bytes())['builder_lock'],'fixed separate builder manifest');d=json.loads(lock_path.read_bytes());need(d['kind']=='SEPARATE_MINIMAL_NATIVE_LIBRARY_BUILDER_INPUTS_V1'and d['metadata_graph_status']=='PASS'and not d['graph_blockers']and not d['rootfs_reconciliation']['missing'],'complete normal builder graph before acquisition')
 C=engine();transfer=transfer or C.fetch;need(cache.is_absolute()and not any(p.is_symlink()for p in(cache,*cache.parents)),'ordinary absolute owned cache')
 cache.mkdir(mode=0o700,exist_ok=True);need(cache.stat().st_uid==os.getuid()and stat.S_IMODE(cache.stat().st_mode)==0o700,'private owned cache mode')
 package_dir=cache/'packages';package_dir.mkdir(mode=0o700,exist_ok=True);need(not package_dir.is_symlink()and package_dir.stat().st_uid==os.getuid()and stat.S_IMODE(package_dir.stat().st_mode)==0o700,'private exact package directory')
 rows={};embedded={}
 for r in d['packages']:
  a=r['archive'];name=a['filename'];need(name not in rows and '/'not in name,'unique normal package filename');rows[name]=dict(bytes=a['bytes'],sha256=a['sha256'],source=r['url']);sig=base64.b64decode(a['signature_b64'],validate=True);need(dict(bytes=len(sig),sha256=hashlib.sha256(sig).hexdigest())==dict(bytes=a['signature_bytes'],sha256=a['signature_sha256']),'exact catalog signature bytes');embedded[name+'.sig']=sig
 for r in [d['rootfs'],*d['keyring_files'],*d['upstream_sources']]:
  need(r['filename']not in rows,'unique bootstrap input');rows[r['filename']]=dict(bytes=r['size'],sha256=r['sha256'],source=r['url'])
 for r in d['catalogs']:rows[r['repo']+'.db']=dict(bytes=r['bytes'],sha256=r['sha256'],source=r['url'])
 r=d['rootfs'];rows[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'],source=r['url']+'.sig')
 need(sum(x['bytes']for x in rows.values())<2*1024**3,'finite complete compressed operand budget')
 need(not any(p.name not in rows and p.name not in embedded for p in package_dir.iterdir()),'closed exact input cache membership')
 pending=sum(r['bytes']for n,r in rows.items()if not(package_dir/n).exists())+sum(len(b)for n,b in embedded.items()if not(package_dir/n).exists());need(shutil.disk_usage(cache).free>=2*1024**3+pending,'reserve complete pending intake plus live2GiB before concurrency')
 end=time.monotonic()+total_seconds;report=dict(kind=d['kind'],status='HOLD_INPUTS_OR_AUTHENTICATION',builder_lock=dict(path=str(lock_path),**pin(lock_path)),inputs={},failures=[],signature_authentication=None,native=None,Root_selection=None,cache=str(package_dir))
 def get(item):
  n,r=item;need(time.monotonic()<end,'finite whole intake deadline');need(shutil.disk_usage(cache).free>=2*1024**3+r['bytes'],'live2GiB reserve before each exact transfer');p=package_dir/n
  if C.verified(p,r)is None:
   need(not p.exists()and not p.is_symlink(),'different existing cache input refuses')
   partial=package_dir/(n+'.partial');need(not partial.exists(),'prior partial requires separate investigation, no silent retry')
   try:
    prior=cache/n
    if n.endswith('.db')and C.verified(prior,r)is not None:shutil.copyfile(prior,partial)
    else:transfer(dict(r,bytes=max(1,r['bytes'])),partial,end-time.monotonic())
    need(C.verified(partial,r)is not None,'retrieved exact whole size/SHA');partial.rename(p)
   except Exception:raise
  return n,pin(p)
 with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:
  fs={pool.submit(get,item):item[0]for item in rows.items()}
  for f in concurrent.futures.as_completed(fs):
   try:n,p=f.result();report['inputs'][n]=p
   except Exception as e:report['failures'].append(dict(filename=fs[f],type=type(e).__name__,message=str(e)[:200]))
 for n,b in embedded.items():
  q=package_dir/n
  if q.exists():need(pin(q)==dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()),'cached signature exact')
  else:
   with q.open('xb')as f:f.write(b)
  report['inputs'][n]=pin(q)
 report['all_inputs_retrieved']=not report['failures']and len(report['inputs'])==len(rows)+len(embedded)
 if report['all_inputs_retrieved']:report['status']='COMPLETE_RETRIEVED_DATA_AUTHENTICATION_UNISSUED'
 report['elapsed_seconds']=total_seconds-max(0,end-time.monotonic());report['storage_remaining_bytes']=shutil.disk_usage(cache).free
 return report

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lock',type=Path,required=True);p.add_argument('--lock-sha256',required=True);p.add_argument('--cache',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args();need(not a.report.exists(),'fresh immutable intake report');r=acquire(a.lock,a.lock_sha256,a.cache);a.report.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps(dict(status=r['status'],inputs=len(r['inputs']),failures=r['failures'],bytes=sum(x['bytes']for x in r['inputs'].values())),indent=2));raise SystemExit(0 if r['all_inputs_retrieved']else 2)
