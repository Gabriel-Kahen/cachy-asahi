#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Separate actual172-addition ARM UI+NM+iptables+current-Xvfb metadata proposal."""
import argparse,hashlib,importlib.util,json,resource,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
def run(output):
 P=load('UI_ARM_held_planner',ROOT/'scripts/port/arm16k-first-login-ui-inputs/plan.py');S=load('UI_ARM_held_proposals',ROOT/'scripts/port/arm16k-first-login-ui-inputs/seat_proposals/propose.py');facts=json.loads((S.HERE/'actual-results.json').read_text());ref=facts['UI_plus_NM_explicit_iptables']['report'];old=json.loads(P.bound(ref));current_path=Path('/tmp/cachy-asahi-arm16k-current-xvfb-20261115/acquisition.json');current_facts=json.loads((ROOT/'scripts/port/arm16k-first-login-ui-inputs/current_xvfb/actual-result.json').read_text());pin=current_facts['evidence_pins'][str(current_path)];current=P.bound({'path':str(current_path),**pin});replacement=S.current_row(current_path)
 rows=[dict(r)for r in old['materials']];assert len(rows)==172 and len({r['name']for r in rows})==172
 for i,row in enumerate(rows):
  if row['name']=='xorg-server-xvfb':assert row['version']=='21.1.25-1';rows[i]=replacement
 assert next(r for r in rows if r['name']=='networkmanager')['version']=='1.58.1-2';assert next(r for r in rows if r['name']=='iptables')['version']=='1:1.8.13-1'
 c=json.loads((P.HERE/'inputs.json').read_text());base=json.loads(P.bound({**c['baseline'],'path':str(P.HERE/c['baseline']['filename'])}));anchors=P.anchor_rows(base);assert {r['name']:r['version']for r in json.loads(P.bound(c['reference_prepared']))['base_packages']}=={r['name']:r['version']for r in anchors}
 prepared=P.prepare_proposal(anchors,rows);assert prepared['status']=='PASS_EXPLICIT_FINITE_METADATA_PREPARE'and prepared['final_count']==283
 return {'schema_version':1,'kind':'ARM16K_FIRST_LOGIN_UI_COMPOSITION_PROPOSAL_V1','status':'HOLD_ROOT_ADMISSION_AND_ARCHIVE_AUDIT','operation':'arm16k-first-login-ui-vm-v1','baseline':111,'additions':172,'final':283,'metadata_prepare':prepared,'materials':rows,'distinct_proposal_sources':{'old_UI_plus_NM_iptables':ref,'current_Xvfb':{'path':str(current_path),**pin}},'changed_root_only':{'name':'xorg-server-xvfb','before':'21.1.25-1','after':replacement['version'],'archive':replacement['archive']},'declared_archive_bytes':sum(r['archive']['bytes']for r in rows),'holds':['complete172 byte/signature/metadata/ownership admission pending','unknownruntimeABI may be resolved only by separately Root-admitted boundedVM; known incompatibilities must remain visible','minimal155 actual virtio/PAM/RTC/seat trial must passfirst','no existingproposal/pin/trust/default changed','no install/daemon/VM/nativebuild/M2/release']}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(__debug__ and sys.flags.isolated):p.error('isolated interpreter and assertions required')
 resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0));a.output.mkdir(mode=0o700,exist_ok=False)
 try:report=run(a.output)
 except Exception as error:report={'status':'HOLD_METADATA_INPUT_REFUSAL','category':type(error).__name__,'reason':str(error)[:512]}
 (a.output/'proposal.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps({k:report.get(k)for k in ['status','baseline','additions','final','declared_archive_bytes','category','reason']}));raise SystemExit(2)
