#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite Apps5→6 full604 source emission; all future native/fresh authority UNBOUND."""
import argparse,ast,hashlib,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-current-management-updater';NEW='scripts/ci/expanded604-apps6-updater'
BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5';AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
BASELINE='ed776a706fc711c5bcc4d933f38e88e7791bc9f6';BASELINE_DECISIONS='1c953fb9b1f9442f40895f886b659534424345ce'
PACKAGE='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7';NATIVE='ec135f26326158591e6d25d5f670083d5306b071';RECIPE='aa4d6ed7865aab606a55e7de94e50d6966f47f7b926a39efd4b3f64eec403778'
MODULES=('contract.py','gate.py','run.py','before_cache.py','freeze.py')
OWN=('prepare.py','adapter.py','selected_package.py','apps6-product.json','policy.json','source-pins.json','test_lane.py','README.md')
WF='.github/workflows/native-arm-expanded604-apps6-updater.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sources(root):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(0<len(rows)<=512,'finite updater source closure')
 for n,row in rows.items():
  p=root/n;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'pinned updater source differs: '+n)
 return rows

def adapt(raw,name):
 text=raw.decode()
 # Simultaneous replacement avoids confusing old AFTER with the new BEFORE.
 changes={OLD:NEW,'expanded604-current-management-updater':'expanded604-apps6-updater',
 '5553e3c67423dffa54e521a211ff471faf6b384f61ff5bb56495b05b39600566':BEFORE,BEFORE:AFTER,
 'ROOT_BOUND_ACTUAL_CURRENT604_PREREQUISITES':'ROOT_BOUND_ACTUAL_APPS6_CURRENT604_PREREQUISITES',
 'ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION':'ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION',
 'ROOT_ACCEPTED_SIGNED_CURRENT604_FRESH_INSTALLER':'ROOT_ACCEPTED_SIGNED_APPS6_CURRENT604_FRESH_INSTALLER',
 'GENERIC4K_NATIVE_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY':'GENERIC4K_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY'}
 text=re.sub('|'.join(re.escape(k) for k in sorted(changes,key=len,reverse=True)),lambda m:changes[m[0]],text)
 def r(a,b,count=1):
  nonlocal text
  need(text.count(a)==count,'Apps6 updater '+name+' anchor: '+a[:120]);text=text.replace(a,b)
 if name=='contract.py':
  r("PACKAGE='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'","PACKAGE='"+PACKAGE+"'\nNATIVE='"+NATIVE+"'\nRECIPE='"+RECIPE+"'")
  r("'fresh600_decisions','native604_decisions')","'fresh600_decisions','native604_decisions','apps6_source','apps6_native_source')")
  r("before['cachy-asahi-setup']=='0.1.0-3' and after==before|{'cachy-asahi-setup':'0.1.0-5'}", "before['cachy-asahi-apps']=='0.1.0-5' and after==before|{'cachy-asahi-apps':'0.1.0-6'} and before['cachy-asahi-setup']==after['cachy-asahi-setup']=='0.1.0-5'")
  r("{'cachy-asahi-apps':'0.1.0-5','cachy-asahi-cache'","{'cachy-asahi-apps':'0.1.0-6','cachy-asahi-cache'")
  r("    if bound:\n", "    need(value.get('baseline_source')=='"+BASELINE+"' and value.get('baseline_decisions_source')=='"+BASELINE_DECISIONS+"','exact held Apps5/Setup5 baseline required')\n    if bound:\n")
  r("        for row in value['prerequisites'].values():", "        H=load('apps6_input_authority',HERE.parent/'expanded604-apps6/apps_inputs.py');H.require(load('apps6_composition_ref_helpers',HERE.parent/'expanded604-apps6/contract.py'),value.get('apps6',{}))\n        need(value['installer_inputs']['apps6_source']==value['apps6']['carrier_source'] and value['installer_inputs']['apps6_native_source']==NATIVE,'same accepted Apps6 inputs required')\n        for row in value['prerequisites'].values():")
  r("row.get('package_sha256')==PACKAGE", "row.get('package_sha256')=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'")
 if name=='gate.py':
  r("root/'scripts/ci/expanded604-current-management-installer/contract.py'","root/'scripts/ci/expanded604-apps6-installer/contract.py'")
  r("fresh600_decisions=bound['fresh600']['carrier_source']", "apps6_source=comp['apps6']['carrier_source'],apps6_native_source=comp['apps6']['native_source'],\n         fresh600_decisions=bound['fresh600']['carrier_source']")
  r("api.HERE.parent/'expanded604-current-management/materializer.py'", "api.HERE.parent/'expanded604-apps6/materializer.py'")
  r("    return api,materializer,composition,decisions,summary", "    need_baseline=C.load('apps6_baseline_gate',C.HERE/'baseline.py')\n    baseline,baseline_materializer,baseline_policy=need_baseline.load(C,args,policy)\n    return baseline,baseline_materializer,baseline_policy,decisions,summary")
  r("'implementation','installer_source','decision_source','upgrader_source',*C.INPUTS", "'implementation','installer_source','decision_source','upgrader_source','baseline_source','baseline_decisions_source',*C.INPUTS")
  r("for name in ('installer_source','decision_source','upgrader_source',*C.INPUTS", "for name in ('installer_source','decision_source','upgrader_source','baseline_source','baseline_decisions_source',*C.INPUTS")
  r("upgrader_source=C.SOURCES[args.case])", "upgrader_source=C.SOURCES[args.case],baseline_source=policy['baseline_source'],baseline_decisions_source=policy['baseline_decisions_source'])")
 if name=='run.py':
  r("'implementation','installer-source','decision-source','upgrader-source','preparation-source'", "'implementation','installer-source','decision-source','upgrader-source','baseline-source','baseline-decisions-source','preparation-source'")
  r("pair=C.old600()[0].stage_pair(a.setup_source,output/'setup5')", "pair=C.load('apps6_pair_stage',C.HERE/'baseline.py').stage(C,a.apps6_source,output/'apps6',policy['apps6'])")
  r("pair/'packages/cachy-asahi-setup-a/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz'", "pair/'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-6-any.pkg.tar.xz'")
  r("pair/'runtime/cachy-asahi-setup-a/provenance.json'", "pair/'public/runtime/cachy-asahi-apps-a/provenance.json'")
  r('a.management_source,a.setup_source,a.welcome_source,a.installer_source)', 'a.management_source,a.setup_source,a.welcome_source,a.baseline_source)')
  r('before_cache.replace_setup3(ready,expanded,producer_output,a.installer_source,IC.COMPOSITION,owner)', 'before_cache.bind(expanded,IC.COMPOSITION,owner)')
  r("('candidate','inputs','setup5')", "('candidate','inputs','apps6')")
 if name=='freeze.py':
  r("    names.update(C.read(C.HERE/'source-pins.json')['files'])","    names.update(C.read(C.HERE/'source-pins.json')['files'])\n    names.update(C.read(C.HERE/'source-pins.json')['fresh_files'])")
 if name=='before_cache.py':
  r("STATUS='READY_SIGNED_EXPANDED604_SETUP3'", "STATUS='READY_SIGNED_EXPANDED604'")
  tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='replace_setup3');lines=text.splitlines(keepends=True)
  body="def bind(target,api,owner):\n    C.need(owner['purpose']=='expanded604-apps6-updater' and target==Path(owner['output'])/'ready604' and C.read(target.parent/'owner.json')==owner,'exact owned baseline cache')\n    value,ref,inventory=api.target_manifest(target)\n    C.need(inventory==C.locks()[0] and inventory['cachy-asahi-setup']=='0.1.0-5','held authentic Apps5/Setup5 current604 baseline')\n    verify(target,api)\n    (target.parent/'before-cache.json').write_bytes(C.encoded(dict(status='UNCHANGED_SIGNED_APPS5_CURRENT604_BASELINE',before_sha256=C.BEFORE,after_sha256=C.AFTER,manifest=ref,other603='UNCHANGED',actors='NOT_RUN')))\n    return target\n"
  lines[node.lineno-1:node.end_lineno]=[body];text=''.join(lines)
 ast.parse(text);return text.encode()

def workflow(raw,rows,owner,manifest):
 text=raw.decode().replace(OLD,NEW).replace('native-arm-expanded604-current-management-updater','native-arm-expanded604-apps6-updater')
 for n,new in ((OLD+'/run.py',owner),(OLD+'/source-manifest.json',manifest)):
  key=rows[n]['sha256'];need(text.count(key)==1,'exact updater workflow marker');text=text.replace(key,new)
 marker='      - name: Retrieve only the six original pinned audio inputs';need(text.count(marker)==1,'updater audio seam');extra=''
 for role,path in (('apps6_source','apps6-inputs'),('apps6_native_source','apps6-native'),('baseline_source','apps5-baseline'),('baseline_decisions_source','apps5-baseline-decisions')):
  extra+='      - name: Checkout exact '+role+'\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ steps.root_policy.outputs.'+role+' }}\n          path: '+path+'\n          persist-credentials: false\n'
 text=text.replace(marker,extra+marker)
 anchor='--audio-inputs "$RUNNER_TEMP/audio-archives"';need(text.count(anchor)==2,'gate and runtime argv');text=text.replace(anchor,'--apps6-source "$GITHUB_WORKSPACE/apps6-inputs/payload" --apps6-native-source "$GITHUB_WORKSPACE/apps6-native" --baseline-source "$GITHUB_WORKSPACE/apps5-baseline" --baseline-decisions-source "$GITHUB_WORKSPACE/apps5-baseline-decisions" \\\n            '+anchor)
 return text.encode()

def emit(root,fresh,output):
 rows=sources(root);fresh_rows=json.loads((HERE/'source-pins.json').read_bytes())['fresh_files']
 for n,row in fresh_rows.items():
  p=fresh/n;need(not any(q.is_symlink() for q in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'pinned Apps6 fresh source differs: '+n)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary updater output');output.mkdir(mode=0o700)
 # The fresh source carries the finite new Apps6 composition/authentication definitions.
 for n,row in fresh_rows.items():
  p=fresh/n;need(pin(p.read_bytes())==row,'exact new fresh support closure');dest=output/n;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
 for n,row in rows.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((root/n).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True);changes={}
 for n in OWN+('baseline.py',):(lane/n).write_bytes((HERE/n).read_bytes())
 for n in MODULES:raw=adapt((root/OLD/n).read_bytes(),n);(lane/n).write_bytes(raw);changes[n]=pin(raw)
 for n,src in (('before604.lock',root/'scripts/ci/expanded604-current-management/expected604.lock'),('after604.lock',fresh/'scripts/ci/expanded604-apps6/expected604.lock')):(lane/n).write_bytes(src.read_bytes())
 need(pin((lane/'before604.lock').read_bytes())['sha256']==BEFORE and pin((lane/'after604.lock').read_bytes())['sha256']==AFTER,'exact Apps5→6 locks');(lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in output.rglob('*') if p.is_file()};manifest=lane/'source-manifest.json';manifest.write_bytes(encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='APPS5_TO6_ONLY_UNBOUND',native='NOT_RUN',hardware='NOT_RUN')))
 wf=output/WF;wf.parent.mkdir(parents=True,exist_ok=True);wf.write_bytes(workflow((root/'.github/workflows/native-arm-expanded604-current-management-updater.yml').read_bytes(),rows,pin((lane/'run.py').read_bytes())['sha256'],pin(manifest.read_bytes())['sha256']))
 receipt=dict(status='SOURCE_ONLY_APPS5_TO6_CURRENT604_UNBOUND',before_sha256=BEFORE,after_sha256=AFTER,protected_packages=603,case_sources=json.loads((root/OLD/'input-policy.json').read_bytes()).get('case_sources','THREE_ORIGINAL_HELD_SOURCE_BASES'),changes=changes,native='NOT_RUN');(output/'updater-adaptation.json').write_bytes(encoded(receipt));return receipt
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','fresh','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.fresh.absolute(),a.output.absolute()),sort_keys=True))
