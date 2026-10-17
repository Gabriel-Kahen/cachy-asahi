#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source binding; original producer/signer/cleanup bodies stay unchanged."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;OLD='scripts/ci/apps-full574-native';NEW='scripts/ci/apps-full574-repair-native';WF='.github/workflows/native-arm-apps-full574-repair.yml'
OWN=('packet.py','job.py','lifecycle.py','checks.py','supervise.py','prepare.py','test_lane.py','policy.json','source-pins.json','README.md','cli-pins.json','test_inspection.py','test_cases.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def replace(text,old,new):
 need(text.count(old)==1,'one frozen source seam: '+old[:64]);return text.replace(old,new)
def contract(text):
 for old,new in (("LANE='"+OLD+"'","LANE='"+NEW+"'"),("'0.1.0-5'","'0.1.0-6'"),("'cachy-asahi-orphans':'0.1.0-1'","'cachy-asahi-orphans':'0.1.0-2'"),("'ROOT_BOUND_NATIVE574_APPS_INPUTS'","'ROOT_BOUND_NATIVE574_SIGNED_REPAIR_INPUTS'"),("'FROZEN_NATIVE574_APPS_SOURCE'","'FROZEN_NATIVE574_SIGNED_REPAIR_CASE_SOURCE'"),("STATUS='PASS_NATIVE574_APPS_COPIED_ROOT_TRANSACTIONS_AND_TEARDOWN'","STATUS='PASS_NATIVE574_SIGNED_REPAIR_CASE_AND_ORDERED_TEARDOWN'")):text=replace(text,old,new)
 def function(name,body):
  nonlocal text
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name);lines=text.splitlines(keepends=True);lines[node.lineno-1:node.end_lineno]=[body];text=''.join(lines)
 function('inputs',"def inputs(root,packet_root):\n binding=source(root);native=load('current_pair_packet',HERE/'packet.py').module(sys.modules[__name__],root);value=native.packet(packet_root);checks=load('package_checks',root/'scripts/checks/package_checks.py');payload,origins=native.package_payload(packet_root,value,checks);closure=adapter(root)\n need(closure.VERSIONS==VERSIONS,'exact current recipe and full574 repair identity required')\n for row in value['packages'].values():\n  for side in ('a','b'):closure.candidate_metadata(checked(packet_root,row['files'][side]))\n return value,payload,origins\n")
 function('result',"def result(value):\n return load('actual_repair_result',HERE/'checks.py').result(sys.modules[__name__],value)\n")
 text+="\nCASES=('repair-bytes','repair-missing')\ndef case(value):\n need(type(value) is str and value in CASES,'one explicit repair case required');return value\n"
 text=replace(text,"value.get('status')=='ROOT_BOUND_NATIVE574_SIGNED_REPAIR_INPUTS'","value.get('cases')==list(CASES) and value.get('aggregate')=='BOTH_INDEPENDENT_ROOT_CASE_DECISIONS_REQUIRED' and value.get('status')=='ROOT_BOUND_NATIVE574_SIGNED_REPAIR_INPUTS'")
 return text

def workflow(text):
 text=text.replace('native-arm-apps-full574-transaction','native-arm-apps-full574-repair').replace(OLD,NEW).replace('apps-full574-transactions-${{','apps-full574-repair-${{')
 text=replace(text,'-p test_lane.py -v',"-p 'test*.py' -v")
 text=replace(text,'      - name: Actual native574 Apps copied-root transactions\n','      - name: Actual native574 Apps copied-root transactions\n        id: repair_trial\n')
 text=replace(text,'python3 -I -B "$SLICE/job.py" run --source','python3 -I -B "$SLICE/supervise.py" run --handoff "$RUNNER_TEMP/apps574-repair-job.json" --source')
 text=replace(text,'python3 -I -B "$SLICE/job.py" cleanup --source',"python3 -I -B \"$SLICE/supervise.py\" cleanup --handoff \"$RUNNER_TEMP/apps574-repair-job.json\" --job-outcome '${{ steps.repair_trial.outcome }}' --source")
 text=replace(text,'    inputs:\n','    inputs:\n      repair_case:\n        description: One independent full574 signed repair case\n        type: choice\n        required: true\n        options:\n          - repair-bytes\n          - repair-missing\n')
 text=replace(text,'      SOURCE_SHA: ${{ inputs.source_sha }}\n','      SOURCE_SHA: ${{ inputs.source_sha }}\n      REPAIR_CASE: ${{ inputs.repair_case }}\n')
 need(text.count('--source "$GITHUB_WORKSPACE"')==5,'five explicit source/case owner invocations')
 text=text.replace('--source "$GITHUB_WORKSPACE"','--case "$REPAIR_CASE" --source "$GITHUB_WORKSPACE"')
 return text

def emit(root,output):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];cli=json.loads((HERE/'cli-pins.json').read_bytes())['files'];need(set(cli)=={'scripts/apps/repair_inspection.py','scripts/apps/test_repair_inspection.py','scripts/apps/REPAIR_INSPECTION.md'} and all(rows.get(n)==r for n,r in cli.items()),'exact frozen supervised readonly CLI3 source rows');need(0<len(rows)<=256 and not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh finite ordinary source output')
 for name,row in rows.items():
  p=root/name;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'exact original source differs: '+name)
 output.mkdir(mode=0o700)
 def write(name,raw):
  p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 for name in rows:write(name,(root/name).read_bytes())
 for name in OWN:write(NEW+'/'+name,(HERE/name).read_bytes())
 write(NEW+'/contract.py',contract((root/OLD/'contract.py').read_text()).encode());write(NEW+'/input-policy.json',(HERE/'policy.json').read_bytes())
 for name in ('snapshot.py','fixture.py','scrub.py'):
  write(NEW+'/'+name,("#!/usr/bin/python3 -I\nimport sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C\nH=C.load('original_"+name[:-3]+"',Path('/source/"+OLD+'/'+name+"'));H.C=C\nif __name__=='__main__':H.main()\n").encode())
 write(NEW+'/export_extract.py',(root/OLD/'export_extract.py').read_bytes())
 files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in output.rglob('*') if p.is_file()};write(NEW+'/source-manifest.json',encoded(dict(schema_version=1,status='FROZEN_NATIVE574_SIGNED_REPAIR_CASE_SOURCE',files=files,native='NOT_RUN',hardware='NOT_RUN')));write(WF,workflow((root/'.github/workflows/native-arm-apps-full574-transaction.yml').read_text()).encode());return dict(status='SOURCE_ONLY_UNBOUND',source_files=len(files),workflow=pin((output/WF).read_bytes()),manifest=pin((output/NEW/'source-manifest.json').read_bytes()))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
