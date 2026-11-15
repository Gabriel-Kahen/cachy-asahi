#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit NM lifecycle adapter over the unchanged successful seat controller."""
import argparse,hashlib,importlib.util,json,os,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;SEAT=HERE.parent/'systemd_tcg_seat_guest'
PINS={'boot.py':'5427fa4f6ae58734e8b9a37eac50fac6561a7593ffd318d1f92b6f13fb067d68','keyboard.py':'040ca60ad6cdd4534a813072f133a7291d19898e89afe26c7a0c8477188ff279','input_seat.py':'34559e846e14164ac7cb54d6879d106c1a911bf611c988252eebd46700e0c611'}
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
V=load('NM_seat_result',HERE/'result.py')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-nm-seat-reference-boot',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--tool-image',required=True);p.add_argument('--tool-image-id',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_first_nm_seat_reference_boot and __debug__ and os.geteuid()!=0):p.error('explicit Root-reviewed NM-seat invocation and ordinary host user required')
 for name,pin in PINS.items():assert hashlib.sha256((SEAT/name).read_bytes()).hexdigest()==pin,'successful seat source drift: '+name
 controller=load('NM_seat_frozen_controller',SEAT/'boot.py');original=sys.argv;sys.argv=[str(SEAT/'boot.py'),'--allow-first-real-seat-reference-boot','--prepared',str(a.prepared),'--prepared-sha256',a.prepared_sha256,'--tool-image',a.tool_image,'--tool-image-id',a.tool_image_id,'--output',str(a.output)]
 try:code=controller.main()
 finally:sys.argv=original
 out=a.output.resolve();foundation=json.loads((out/'report.json').read_text());report={'schema_version':1,'status':'HOLD','scope':'x86 real-seat ordinary NM profiles/denials software only','native_ARM_M2_release':'NOT RUN','foundation_report':str(out/'report.json'),'foundation_status':foundation['status']}
 try:
  if foundation['status']=='PASS_X86_REAL_SEAT_REFERENCE_ONLY':report['nm_journey']=foundation['seat']['nm_journey']
  else:
   text=(out/'serial.redacted.log').read_text().replace('\r','');nonce=json.loads((a.prepared/'prepared.json').read_text())['nonce'];rows=re.findall(r'(?m)^SEAT_HOLD '+nonce+r' (\{[^\n]*\})$',text)
   if rows:report['held_observation']=json.loads(rows[-1])
  assert code==0 and foundation['status']=='PASS_X86_REAL_SEAT_REFERENCE_ONLY',foundation.get('failure')
  V.accept(report['nm_journey']);report['status']='PASS_X86_REAL_SEAT_NM_PROFILE_LIFECYCLE_ONLY'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 (out/'journey.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({'status':report['status'],'report':str(out/'journey.json'),'failure':report.get('failure')}));return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())
