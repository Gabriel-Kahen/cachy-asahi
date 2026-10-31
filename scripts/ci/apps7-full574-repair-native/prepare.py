#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the separate NULL-default Apps7 repair source; no actor or publication."""
import argparse,hashlib,json
from pathlib import Path
import derive as D
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/apps-full574-repair-native';NEW=D.LANE
WF='.github/workflows/native-arm-apps7-full574-repair.yml'
OWN=('prepare.py','derive.py','derivation-pins.json','source-pins.json','packet.py','policy.json','README.md','test_lane.py','test_inspection.py','cli-pins.json','job.py','supervise.py','snapshot.py','fixture.py','scrub.py','export_extract.py','closure.py','transaction.py','inspection.py','source_only.py','path_view.py','test_path_view.py')
need=D.need;pin=D.pin
encoded=lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def workflow(raw):
 text=raw.decode();old='native-arm-apps-full574-repair';need(text.count(old)>=2,'original native workflow name/group')
 text=text.replace(old,'native-arm-apps7-full574-repair')
 need(text.count(OLD)==1,'one explicit workflow slice');text=text.replace(OLD,NEW)
 # Only this longer cumulative test harness changes; product600/caller610 held.
 for old,new in (("    timeout-minutes: 120","    timeout-minutes: 142"),("        timeout-minutes: 60","        timeout-minutes: 82"),("--kill-after=30s 3550s","--kill-after=30s 4870s")):
  need(text.count(old)==1,'one exact cumulative harness profile seam: '+old);text=text.replace(old,new)
 # https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency
 # Keep up to100 pending serial runs; FIFO follows queue entry, not dispatch.
 before='concurrency:\n  group: native-arm-apps7-full574-repair\n  cancel-in-progress: false\n'
 after='concurrency:\n  group: native-arm-apps7-full574-repair\n  queue: max\n  cancel-in-progress: false\n'
 need(text.count(before)==1,'one exact serial noncancelling Apps7 queue');text=text.replace(before,after)
 return text.encode()

def emit(root,output,native_source=None):
 native_source=root if native_source is None else native_source
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files']
 need(not output.exists() and output.parent.is_dir(),'fresh source directory')
 for n,r in rows.items():
  p=(root if n.startswith('packages/tools/cachy-asahi-apps7/') else native_source)/n;need(p.is_file() and not any(q.is_symlink() for q in (p,*p.parents)) and p.stat().st_nlink==1 and pin(p.read_bytes())==r,'held original/source recipe differs: '+n)
 derived={};ledger={}
 for name in ('contract','base_lifecycle','lifecycle','checks'):derived[name+'.py'],ledger[name]=D.derive(native_source,name)
 output.mkdir(mode=0o700)
 def write(n,raw):
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 for n in rows:write(n,((root if n.startswith('packages/tools/cachy-asahi-apps7/') else native_source)/n).read_bytes())
 for n in OWN:write(NEW+'/'+n,(HERE/n).read_bytes())
 for n,raw in derived.items():write(NEW+'/'+n,raw)
 write(NEW+'/input-policy.json',(HERE/'policy.json').read_bytes())
 manifest=dict(schema_version=1,status='FROZEN_APPS7_NATIVE574_SIGNED_REPAIR_CASE_SOURCE',files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in sorted(output.rglob('*')) if p.is_file()},native='NOT_RUN',hardware='NOT_RUN')
 write(NEW+'/source-manifest.json',encoded(manifest))
 wf=workflow((native_source/'.github/workflows/native-arm-apps-full574-repair.yml').read_bytes());write(WF,wf)
 return dict(status='SOURCE_ONLY_UNBOUND_APPS7_NATIVE574_REPAIR',manifest=pin(encoded(manifest)),files=len(manifest['files']),workflow=pin(wf),derivations=ledger,packet_source=None,actual_runs=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--native-source',type=Path);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute(),a.native_source.absolute() if a.native_source else None),sort_keys=True))
