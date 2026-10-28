#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source-only selected-cleanup native lane over the original Apps owner."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/apps-full574-native';NEW='scripts/ci/orphans-full574-native'
OWN=('supervise.py','test_supervise.py','held_payloads.py','fixture_backend.py','selected_fixture.py','test_held_payloads.py','job.py','modes.py','test_modes.py','prepare.py','policy.json','source-pins.json','lifecycle.py','stage_source.py','install_dependency.py','cancel.py','checks.py','test_lane.py','README.md','cache-only-plan-39010123449.json')
WF='.github/workflows/native-arm-orphans-full574-cleanup.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def source(root):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(0<len(rows)<=256,'finite original owner/source closure required')
 for n,row in rows.items():
  p=root/n;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'original source differs: '+n)
 return rows

def emit(root,output):
 rows=source(root);need(not output.exists() and output.parent.is_dir() and not any(x.is_symlink() for x in (output,*output.parents)),'fresh ordinary native source output');output.mkdir(mode=0o700)
 for n in rows:
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((root/n).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True,exist_ok=True)
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 text=(root/OLD/'contract.py').read_text().replace("LANE='"+OLD+"'","LANE='"+NEW+"'").replace("LABEL='org.cachy-asahi.apps-full574-native'","LABEL='org.cachy-asahi.orphans-full574-native'").replace("STATUS='PASS_NATIVE574_APPS_COPIED_ROOT_TRANSACTIONS_AND_TEARDOWN'","STATUS='PASS_NATIVE574_SELECTED_ORPHAN_CLEANUP_AND_TEARDOWN'").replace("'ROOT_BOUND_NATIVE574_APPS_INPUTS'","'ROOT_BOUND_NATIVE574_ORPHAN_CLEANUP_INPUTS'").replace("'FROZEN_NATIVE574_APPS_SOURCE'","'FROZEN_NATIVE574_ORPHAN_CLEANUP_SOURCE'")
 text=text.replace('def adapter(root):',"def adapter(root,inputs=Path('/inputs')):").replace(' return module\n'," return load('held_payload_facade',HERE/'held_payloads.py').facade(sys.modules[__name__],root,module,inputs)\n")
 tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='result');lines=text.splitlines(keepends=True);lines[node.lineno-1:node.end_lineno]=["def result(value):\n return load('cleanup_result_checks',HERE/'checks.py').result(sys.modules[__name__],value)\n"];(lane/'contract.py').write_text(''.join(lines))
 # Original owner custody is reused; modes derives only the selected run/retention and scoped actor budget.
 # Independent mode wrapper is copied byte-for-byte from OWN.
 for n in ('snapshot.py','fixture.py','scrub.py'):
  (lane/n).write_text("#!/usr/bin/python3 -I\nimport sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C\nH=C.load('original_"+n[:-3]+"',Path('/source/"+OLD+'/'+n+"'))\nif __name__=='__main__':H.main()\n")
 (lane/'export_extract.py').write_bytes((root/OLD/'export_extract.py').read_bytes());(lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={n:pin((output/n).read_bytes()) for n in rows};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()})
 (lane/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,status='FROZEN_NATIVE574_ORPHAN_CLEANUP_SOURCE',files=files,native='NOT_RUN',hardware='NOT_RUN')))
 import importlib.util
 spec=importlib.util.spec_from_file_location('orphan_modes_prepare',HERE/'modes.py');C_modes=importlib.util.module_from_spec(spec);spec.loader.exec_module(C_modes)
 text=(root/'.github/workflows/native-arm-apps-full574-transaction.yml').read_text().replace('native-arm-apps-full574-transaction','native-arm-orphans-full574-cleanup').replace(OLD,NEW).replace('apps-full574-transactions-${{','orphans-full574-cleanup-${{')
 text=text.replace("          python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/apps -p 'test_*.py' -v", "          python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/apps -p 'test_*.py' -v\n          python3 -I -B scripts/orphans/test_selected.py")
 spec=importlib.util.spec_from_file_location('orphan_job_supervision_prepare',HERE/'supervise.py');C_supervise=importlib.util.module_from_spec(spec);spec.loader.exec_module(C_supervise)
 text=C_supervise.workflow(C_modes.workflow(text))
 text=text.replace('        run: >-\n          python3 -I -B "$SLICE/job.py" check --trial "$TRIAL" --source "$GITHUB_WORKSPACE"\n          --packet "$GITHUB_WORKSPACE/retained-apps574-inputs/payload"\n','        run: |\n          python3 -I -B "$SLICE/job.py" check --trial "$TRIAL" --source "$GITHUB_WORKSPACE" \\\n            --packet "$GITHUB_WORKSPACE/retained-apps574-inputs/payload"\n          python3 -I -B "$SLICE/test_held_payloads.py" \\\n            --actual-packet "$GITHUB_WORKSPACE/retained-apps574-inputs/payload"\n')
 wf=output/WF;wf.parent.mkdir(parents=True,exist_ok=True);wf.write_text(text)
 value=dict(status='SOURCE_ONLY_NATIVE_ORPHAN_CLEANUP_UNBOUND',source_files=len(rows),manifest=pin((lane/'source-manifest.json').read_bytes()),workflow=pin(wf.read_bytes()),native='NOT_RUN',baseline_policy='ORIGINAL574_AND_FOUR_APP_GUARD_UNCHANGED',fixture_reason='PUBLIC_ALLDEPS_INSTALL_ONLY_NO_DATABASE_EDIT',cleanup='EXACT_EXISTING_SELECTED_API_NO_REASON_FLAGS',release='NOT_ADMITTED');(output/'native-adaptation.json').write_bytes(encoded(value));return value
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
