#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fixture-only genuine public ALPM dependency install; never a removal option."""
import argparse,os,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def dependency_flag(header):
 C.need(type(header) is str and len(header.encode())<=1024**2,'bounded native ALPM header required')
 rows=re.findall(r'\bALPM_TRANS_FLAG_ALLDEPS\s*=\s*([^,}\n]+)',header)
 C.need(len(rows)==1 and re.fullmatch(r'\(1\s*<<\s*8\)',rows[0].strip()),'native ABI header ALLDEPS constant required')
 return 1<<8

def factory(original,flags):
 def create(*args,**kwargs):
  alpm=original(*args,**kwargs);initialize=alpm.alpm_trans_init
  def init(handle,actual):
   C.need(handle==alpm.handle and actual==flags and not actual&(1<<8),'exact original install flags required')
   return initialize(handle,actual|(1<<8))
  alpm.alpm_trans_init=init;return alpm
 return create

def main():
 C.source(Path('/source'));C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1','only original native fixture actor')
 argv=sys.argv[1:];C.need(argv and argv[0]=='apply' and '--operation' in argv and argv[argv.index('--operation')+1]=='install','install fixture only')
 i=argv.index('--applications')+1;names=[]
 while i<len(argv) and not argv[i].startswith('--'):names.append(argv[i]);i+=1
 C.need(names==['cache'],'only authenticated Cache install, with actual Runtime dependency')
 header=Path('/usr/include/alpm.h').read_text();dependency_flag(header)
 T=C.load('dependency_install_original',Path('/source/scripts/apps/transaction.py'))
 if '--worker' not in argv:
  p=argparse.ArgumentParser(add_help=False)
  for n in ('policy','policy-sha256','lease','lease-sha256'):p.add_argument('--full574-'+n,required=True)
  a,_=p.parse_known_args(argv)
  row=T.SUP.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),*argv,'--worker'],env=dict(os.environ),cwd='/work',timeout=T.execution_seconds(a),output_limit=1024**2)
  C.need(row['termination'] is None and row['direct_child_reaped'] and row['returncode'] in (0,1),'fixture worker incomplete; commit UNKNOWN')
  sys.stdout.buffer.write(row['stdout']);sys.stderr.buffer.write(row['stderr']);return row['returncode']
 original=T.F.Alpm;T.F.Alpm=factory(original,T.I.FLAGS)
 original_apply=T.apply
 def apply(args):
  value=original_apply(args);value['fixture_install_reason']=dict(authority='PUBLIC_ALPM_ALLDEPS_INSTALL_FLAG_ONLY',flag=1<<8,original_flags=T.I.FLAGS,native_alpm_header_sha256=C.sha(header.encode()),actual_reason='MUST_BE_INDEPENDENTLY_READ_FROM_LOCAL_ALPM');return value
 T.apply=apply
 try:return T.main()
 finally:T.F.Alpm=original;T.apply=original_apply
if __name__=='__main__':raise SystemExit(main())
