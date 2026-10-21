"""Fallback only the same recorded completed original-owned images, never global prune."""
import argparse,importlib.util,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();C.preflight();C.policy();out=C.private(a.output)
if not(out/'owner.json').exists():raise SystemExit('No admitted owner state; nothing may be removed')
v=C.load(out/'owner.json');spec=importlib.util.spec_from_file_location('fallback_original574',C.ROOT/'baseline/maintained_desktop574.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
results={}
for kind,folder,key in(('candidate',out/'candidate','candidate_nonce'),('baseline',out,'nonce')):
 if(folder/'report.json').exists():
  report=C.load(folder/'report.json');result=M.retire_owned(folder,v[key],report);report['owned_cleanup']=result;M.save_report(folder,report);results[kind]=result
 else:results[kind]=dict(status='UNKNOWN_NO_COMPLETE_ORIGINAL_REPORT')
C.save(out/'fallback-cleanup.json',results)
# Fallback cleanup cannot change frozen export/index or promote a failed role.
print(C.ENC(results).decode(),end='')
raise SystemExit(0 if all(x.get('status')=='PASS'for x in results.values())else 1)
