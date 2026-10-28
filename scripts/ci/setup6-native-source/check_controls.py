#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the exact source27, recovery74 and original23 suites; no package/native actors."""
import argparse,json,os,re,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import prepare as P

def check(source,carrier,context,output):
 expected,_=P.render(carrier);need=P.need;need(P.files(source)==expected,'exact whole73 source before controls');old,_=P.render(carrier,True);need(P.files(context)==old,'exact whole44 context before original controls');output=P.ordinary(output);need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(source)and not output.is_relative_to(context)and not output.is_relative_to(carrier),'fresh separate source-control output');output.mkdir(mode=0o700);env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',SETUP6_NATIVE_SOURCE=str(source),SETUP6_TEST_RETAINED5=str(carrier));rows=[]
 for label,start,count in [('setup6-lane',source/'scripts/ci/setup6-native',27),('setup6-recovery',source/'scripts/setup',74),('setup5-original',context/'scripts/ci/setup5-native',23)]:
  command=[sys.executable,'-I','-B','-Werror','-m','unittest','discover','-s',str(start),'-p','test_*.py','-v'];t=time.monotonic()
  with(output/(label+'.stdout')).open('xb')as a,(output/(label+'.stderr')).open('xb')as b:r=subprocess.run(command,env=env,stdout=a,stderr=b,timeout=120)
  raw=P.read(output/(label+'.stderr'))
  if r.returncode!=0 or b'skipped'in raw or b'\nOK\n'not in raw:
   sys.stderr.write('FAILED_SOURCE_CONTROL '+label+'\n'+raw[-65536:].decode(errors='replace'));sys.stderr.flush()
  need(r.returncode==0 and re.search(rb'Ran '+str(count).encode()+rb' tests?\b',raw)and b'\nOK\n'in raw and b'skipped'not in raw,'complete original '+label+' suite required');rows.append(dict(suite=label,tests=count,exit=r.returncode,seconds=time.monotonic()-t,command=command))
 need(P.files(source)==expected and P.files(context)==old,'complete source contexts held after controls');P.carrier(carrier,P.profile(),old);value=dict(status='PASS_SOURCE_ONLY_27_74_23_NO_NATIVE_TRANSFER',python=sys.version,rows=rows,actual_run=None,native='NOT_RUN',hardware='NOT_RUN');(output/'result.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');return value
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','setup5-carrier','setup5-context','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(check(*(getattr(a,n.replace('-','_')).absolute()for n in('source','setup5-carrier','setup5-context','output'))),sort_keys=True))
