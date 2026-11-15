#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal staged, ordinary Git source leaves using Git-representable modes only."""
import argparse,hashlib,importlib.util,json,os,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent


def git(*argv):
 r=subprocess.run(['/usr/bin/git','-C',str(HERE),*argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
 if len(r.stdout)>4*1024**2:raise ValueError('bounded local Git DATA')
 return r.stdout


def seal():
 spec=importlib.util.spec_from_file_location('perl_seal_contracts',HERE/'contracts.py');K=importlib.util.module_from_spec(spec);spec.loader.exec_module(K)
 root=Path(os.fsdecode(git('rev-parse','--show-toplevel')).strip());prefix=HERE.relative_to(root).as_posix()+'/'
 rows=git('ls-files','--full-name','--stage','-z','--',str(HERE)).split(b'\0');files={}
 for raw in rows:
  if not raw:continue
  metadata,name=raw.split(b'\t',1);mode,oid,stage=metadata.decode().split();name=os.fsdecode(name)
  K.need(stage=='0' and mode in('100644','100755') and name.startswith(prefix),'ordinary tracked stage0 Git source leaves only')
  relative=name[len(prefix):]
  if relative=='source.lock.json':continue
  path=HERE/relative;K.ordinary(path);info=path.lstat();expected_mode=0o644 if mode=='100644'else 0o755
  K.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==expected_mode,'ordinary single-link source with exact Git-representable mode: '+relative)
  blob=git('cat-file','blob',oid);K.need(path.read_bytes()==blob,'stage complete source bytes before sealing: '+relative)
  files[relative]=dict(bytes=len(blob),sha256=hashlib.sha256(blob).hexdigest(),mode=expected_mode)
 actual={p.relative_to(HERE).as_posix()for p in HERE.rglob('*')if not p.is_dir() and p.name!='source.lock.json'}
 K.need(actual==set(files),'untracked/ignored/special source leaves must be removed; never sealed')
 lock=dict(schema=1,kind='ARM16K_PERL5423_CASE_SOURCE_LOCK_V1',operation=K.OP,files=files,actual={n:None for n in('source','ref','authority','case_prepared','image_prepared','VM','ALPM','runtime','Root_acceptance')})
 (HERE/'source.lock.json').write_bytes(K.canonical(lock));(HERE/'source.lock.json').chmod(0o644)
 return K.pin(HERE/'source.lock.json')


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--seal-staged-source',action='store_true');a=p.parse_args()
 if not(a.seal_staged_source and sys.flags.isolated and sys.dont_write_bytecode and __debug__):p.error('explicit isolated staged-source authoring only')
 print(json.dumps(seal(),sort_keys=True))
if __name__=='__main__':main()
