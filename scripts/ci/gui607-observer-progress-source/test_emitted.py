# SPDX-License-Identifier: MIT
"""Run complete emitted source tests against exact historical DATA fixtures."""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import stage_source_inputs as S

def run(args):
 F=S.F;q=S.profile();raw=F.read(S.HERE/'profile.json');F.need(F.pin(raw)==F.PROFILE,'exact source profile');p=json.loads(raw)
 source=S.joined(args.source,p['result']['files']);roots={k:S.joined(getattr(args,k),q['fixtures'][k])for k in('record22','public991','assets484')}
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',WELCOME5_GUI_ASSETS=str(roots['assets484']),WELCOME5_GUI_SOURCE=str(source/'parent574/original'))
 for name in('WELCOME5_GUI_DEVELOPMENT','LATEST607_AUTHOR_RECEIPTS','OBSERVER_AUTHOR_RECEIPTS','OBSERVER_AUTHOR_RECEIPT_PATH'):env.pop(name,None)
 rows=[]
 for name,count,extra in(('test_build_inventory.py',8,[]),('test_runner_context.py',4,['--assets',str(roots['assets484'])]),('test_observer.py',26,['--assets',str(roots['assets484'])]),('test_source.py',7,['--record',str(roots['record22']),'--public',str(roots['public991']),'--assets',str(roots['assets484'])])):
  # Keep all seven inherited tests, with the original strict warning flag.
  argv=[sys.executable,'-I','-B']+(['-Werror']if name=='test_source.py'else[])+[str(source/'implementation'/name)]+extra
  start=time.monotonic();child=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=env,timeout=180);elapsed=time.monotonic()-start
  sys.stdout.buffer.write(child.stdout);sys.stderr.buffer.write(child.stderr);sys.stdout.flush();sys.stderr.flush()
  F.need(child.returncode==0 and ('Ran '+str(count)+' tests').encode()in child.stderr,'complete emitted '+name+' failed; no skip or subset permitted')
  rows.append(dict(argv=argv,exit=child.returncode,tests=count,seconds=elapsed,cap=180,stdout=F.pin(child.stdout),stderr=F.pin(child.stderr)))
 S.joined(source,p['result']['files'])
 return dict(status='PASS_COMPLETE_SOURCE_TEST_COMMANDS',commands=rows,native='NOT_RUN',actual_replay=False,GUI='NOT_ACCEPTED',M2='NOT_RUN')
if __name__=='__main__':
 ap=argparse.ArgumentParser(description=__doc__)
 for name in('source','record22','public991','assets484'):ap.add_argument('--'+name,required=True)
 print(json.dumps(run(ap.parse_args()),sort_keys=True,indent=2))
