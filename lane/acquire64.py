"""Reconstruct exact128 public input leaves privately; complete signed DATA proof."""
import argparse,concurrent.futures,hashlib,json,os,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C
p=argparse.ArgumentParser();p.add_argument('--core',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
C.preflight();C.policy();out=C.private(a.evidence,True);core=a.core
os.umask(0o077);os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',LANG='C.UTF-8',HOME=str(out))
deadline=time.monotonic()+C.BUDGET['new64']
sys.path.insert(0,str(core/'trusted-tools'));import authenticate as A
lock=C.load(core/'builder-inputs.lock.json');C.need(len(lock['packages'])==64 and lock['signer_fingerprint']==A.SIGNER,'exact original signed64 signer/lock')
cache=core/'builder-context/deps';C.private(cache)
# Keep original pinned download/redirect/size/hash logic, without a fallback.
def fetch(row):
 C.need(time.monotonic()<deadline,'signed64 acquisition deadline')
 A.fetch(row,cache);A.fetch(A.native.signature_item(row),cache);return row['name']
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:names=list(pool.map(fetch,lock['packages']))
C.save(out/'acquisition.json',dict(status='ALL64_EXACT_BYTES_RECONSTRUCTED_NOT_YET_AUTHENTICATED',names=names,files={rel:C.pin(C.read(core/rel))for rel in C.omitted()}))
records=[]
with tempfile.TemporaryDirectory(prefix='public-gpg-',dir=out)as home:
 gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',home,'--no-auto-key-retrieve','--no-autostart']
 r=subprocess.run(gpg+['--import',str(core/'builder-keyring/archlinuxarm.gpg')],capture_output=True,timeout=30)
 C.need(r.returncode==0,'pinned public key import');(out/'key-import.stdout').write_bytes(r.stdout);(out/'key-import.stderr').write_bytes(r.stderr)
 for row in lock['packages']:
  C.need(time.monotonic()<deadline,'signed64 authentication deadline')
  command=gpg+['--status-fd','1','--verify',str(cache/(row['filename']+'.sig')),str(cache/row['filename'])]
  r=subprocess.run(command,capture_output=True,text=True,timeout=min(30,max(1,deadline-time.monotonic())))
  (out/(row['name']+'.gpg-status')).write_text(r.stdout);(out/(row['name']+'.gpg-stderr')).write_text(r.stderr)
  A.status(r)
  status=[line.split()[1:]for line in r.stdout.splitlines()if line.startswith('[GNUPG:] ')]
  C.need(not any(v[0]in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED')for v in status),'current signature/key validity')
  observation=A.observe(cache/row['filename'],row);C.save(out/(row['name']+'.json'),observation)
  records.append(dict(name=row['name'],archive=C.pin(C.read(cache/row['filename'])),signature=C.pin(C.read(cache/(row['filename']+'.sig'))),status=C.pin(r.stdout.encode()),observation=C.pin(C.ENC(observation)),exit=r.returncode))
C.materialized(core)
C.save(out/'authentication.json',dict(status='PASS_CURRENT_OFFICIAL_SIGNATURE_AND_COMPLETE_PKGINFO_64',signer=A.SIGNER,seconds_limit=C.BUDGET['new64'],records=records,public_only_GPG_home_retired=True,source_only_data='NO_PACKAGE_EXECUTION',original403_restored=True))
print('PASS: current official signed64 + complete descriptor joins, full original403 privately restored')
