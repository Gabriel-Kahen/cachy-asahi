# SPDX-License-Identifier: MIT
"""Pure material/transcript/adoption gate. No GPG, package execution or native entry."""
import argparse,base64,hashlib,importlib.util,json,os,stat,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def need(ok,why):
 if not ok:raise ValueError(why)
def read(path,limit=2*1024**3):
 p=Path(path);need(p.is_absolute()and not any(x.is_symlink()for x in(p,*p.parents)),'ordinary exact input path');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=limit,'bounded ordinary single-link input');h=hashlib.sha256();body=bytearray()if limit<=16*1024**2 else None
  total=0
  while block:=os.read(fd,1024**2):
   total+=len(block);need(total<=s.st_size and total<=limit,'whole bounded read extent');h.update(block)
   if body is not None:body.extend(block)
  ident=lambda x:tuple(getattr(x,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  need(ident(s)==ident(os.fstat(fd))==ident(p.lstat()),'whole stable identity');return dict(bytes=s.st_size,sha256=h.hexdigest()),None if body is None else bytes(body)
 finally:os.close(fd)
def load(path,expected):
 got,raw=read(path,16*1024**2);need(got==expected,'externally pinned whole DATA');return json.loads(raw)
def module(path,name):
 expected=json.loads((HERE/'profile.DATA.json').read_bytes())['engines'][path.relative_to(ROOT).as_posix()];need(read(path,16*1024**2)[0]==expected,'whole maintained engine source');s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def material_check(d,cache,*,package_metadata=True):
 need(cache.is_absolute()and cache.is_dir()and not cache.is_symlink()and cache.stat().st_uid==os.getuid()and stat.S_IMODE(cache.stat().st_mode)==0o700,'owned private exact input directory');need(d['metadata_graph_status']=='PASS'and not d['graph_blockers']and not d['rootfs_reconciliation']['missing'],'full coherent metadata graph')
 expected={}
 for r in d['packages']:
  a=r['archive'];expected[a['filename']]=dict(bytes=a['bytes'],sha256=a['sha256']);expected[a['filename']+'.sig']=dict(bytes=a['signature_bytes'],sha256=a['signature_sha256']);sig=base64.b64decode(a['signature_b64'],validate=True);need(dict(bytes=len(sig),sha256=hashlib.sha256(sig).hexdigest())==expected[a['filename']+'.sig'],'exact embedded signature')
 for r in[d['rootfs'],*d['keyring_files'],*d['upstream_sources']]:expected[r['filename']]=dict(bytes=r['size'],sha256=r['sha256'])
 for r in d['catalogs']:expected[r['repo']+'.db']=dict(bytes=r['bytes'],sha256=r['sha256'])
 r=d['rootfs'];expected[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'])
 need({p.name for p in cache.iterdir()}==set(expected),'complete422 input namespace, no partial/unlisted files')
 for n,row in expected.items():need(read(cache/n)[0]==row,'exact complete input '+n)
 if package_metadata:
  # The small UI prefix parser does not cover all official package layouts.
  # Use the maintained complete streaming archive inspector, unchanged.
  N=module(ROOT/'scripts/ci/native_arm.py','maintained_complete_package_inspector')
  for r in d['packages']:
   a=r['archive'];expected_row=dict(name=r['name'],version=r['version'],arch=r['arch'],license=r['licenses_declared'],depends=r['depends'],provides=r['provides'],conflicts=r['conflicts'],replaces=r['replaces'])
   N.inspect_package(cache/a['filename'],expected_row)
 return dict(files=len(expected),bytes=sum(r['bytes']for r in expected.values()),all_materials_exact=True,PKGINFO='PASS'if package_metadata else'NOT RUN',signature_authentication=None,Root_native_authority=None)

def target_gate(d,target):
 need(target in('llhttp','libgit2'),'explicit original library target')
 need(target=='llhttp','libgit2 HOLD: separately signed/authenticated project llhttp provider UNISSUED; new bound profile required')
 return target

def authenticated(d,lock_pin,cache,adoption=None):
 need(type(adoption)is dict and adoption.get('issuer')=='Root'and adoption.get('status')=='ROOT_ADOPTED_MINIMAL_NATIVE_BUILDER_INPUT_AUTHENTICATION_ONLY'and adoption.get('accepted')is True,'Root signature authentication UNISSUED; no native entry')
 raw=(json.dumps(d,indent=2,sort_keys=True)+'\n').encode();need(lock_pin==json.loads((HERE/'profile.DATA.json').read_bytes())['builder_lock']and lock_pin==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),'whole fixed builder manifest')
 need(set(adoption)==set(json.loads((HERE/'Root-authentication.TEMPLATE.json').read_bytes()))and adoption['all_verifiers_naturally_retired']is True and adoption['current_official_trust_reviewed']is True,'exact Root input-authentication schema and natural verifier closure');need(adoption['builder_lock']==lock_pin and adoption['signer_fingerprint']==d['signer_fingerprint']and adoption['Root_native_authority']is None,'exact build-only authentication binding')
 records=load(Path(adoption['signatures']['path']),{k:adoption['signatures'][k]for k in('bytes','sha256')});N=module(ROOT/'scripts/ci/native_arm.py','maintained_signature_status_parser')
 names={r['archive']['filename']for r in d['packages']}|{d['rootfs']['filename']};need(set(records)==names,'all207 original signed operands verified')
 for name,row in records.items():
  need(row['exit_code']==0,'actual verifier natural exit0');N.valid_signature(row['status'],d['signer_fingerprint']);need(not any('[GNUPG:] '+x in row['status']for x in('FAILURE','ERROR','NODATA','BADARMOR')),'strict verifier status')
 materials=material_check(d,cache);return dict(status='AUTHENTICATED_BUILD_INPUT_DATA_ONLY_FRESH_NATIVE_SELECTION_REQUIRED',materials=materials,Root_native_authority=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lock',type=Path,required=True);p.add_argument('--lock-sha256',required=True);p.add_argument('--cache',type=Path,required=True);p.add_argument('--target',choices=('llhttp','libgit2'),default='llhttp');p.add_argument('--Root-adoption',type=Path);p.add_argument('--Root-adoption-sha256');a=p.parse_args();lp=read(a.lock,16*1024**2)[0];need(lp==json.loads((HERE/'profile.DATA.json').read_bytes())['builder_lock']and lp['sha256']==a.lock_sha256,'whole fixed separate builder lock');d=load(a.lock,lp)
 if a.Root_adoption:
  ap=read(a.Root_adoption,16384)[0];need(ap['sha256']==a.Root_adoption_sha256,'externally pinned Root adoption');adoption=load(a.Root_adoption,ap)
 else:adoption=None
 try:target_gate(d,a.target);r=authenticated(d,lp,a.cache,adoption)
 except ValueError as e:print(json.dumps(dict(status='HOLD_AUTHENTICATION_UNISSUED',reason=str(e),native=None)));raise SystemExit(2)
 print(json.dumps(r,sort_keys=True))
