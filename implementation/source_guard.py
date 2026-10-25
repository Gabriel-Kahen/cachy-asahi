# SPDX-License-Identifier: MIT
"""Closed ordinary source plus complete old runtime byte inverses, no actors."""
import ast,json
import common as C,adapter,runtime,baseline

def inverse(raw,row):
 value=raw.decode()
 for r in reversed(row['extra']):C.need(value.count(r['after'])==r.get('count',1),'whole extra inverse');value=value.replace(r['after'],r['before'])
 value=value.encode()
 for r in sorted(row['edits'],key=lambda r:r['start']):
  a=r['start'];b=a+len(r['after'].encode());C.need(value[a:b]==r['after'].encode(),'whole typed inverse');value=value[:a]+r['before'].encode()+value[b:]
 C.need(C.pin(value)==row['before'],'complete original runtime body inverse');return value

def verify(held=None):
 p=C.profile();manifest=json.loads(C.read(C.ROOT/'source-manifest.json'));C.need(C.rows(C.ROOT)==dict(manifest['files'],**{'source-manifest.json':C.pin(C.read(C.ROOT/'source-manifest.json'))}),'entire current source closure');C.locks()
 C.need(C.rows(C.ROOT/'parent4k')==p['parent4k_files']and len(p['parent4k_files'])==10,'entire original native4K parent10 held')
 count=0
 for case in C.CASES:
  root=C.ROOT/'cases'/case;C.need(C.rows(root)==p['cases'][case],'exact complete607 capsule');before={}
  for n,w in p['cases'][case].items():
   raw=C.checked(root/n,w)
   if n.endswith('.py'):
    old=inverse(raw,p['old_source_lineage'][case][n]);new,row=adapter.transform(old,n);C.need(new==raw and row==p['old_source_lineage'][case][n],'whole finite bidirectional typed source derivation');before[n]=C.pin(old);count+=1
   elif n.endswith('/expected-updater-v2.lock'):before[n]=p['case_before'][case][n]
   elif n.endswith('/expected-setup4-v2.lock'):before[n]=p['case_before'][case][n]
   elif n!='upgrade-config.json':before[n]=C.pin(raw)
  C.need(all(p['case_before'][case][n]==w for n,w in before.items()),'all old Python and other held capsule files inverse');cfg=json.loads(C.read(root/'upgrade-config.json'));C.need({k:cfg[k]for k in('stage_seconds','copy_seconds','driver_seconds','verify_seconds')}==dict(stage_seconds=1200,copy_seconds=1200,driver_seconds=1860 if case=='normal'else 2400,verify_seconds=600),'all original nested budgets')
  for n,digest in cfg['code_pins'].items():C.need(C.pin(C.read(root/n))['sha256']==digest,'all source capsule code pins')
  prior=json.loads(json.dumps(cfg));prior['code_pins']={n:p['case_before'][case][n]['sha256']for n in cfg['code_pins']};prior['external_pins']['/persistent_scope.py']=p['case_before'][case]['scripts/ci/full-root-upgrade-caller/persistent_scope.py']['sha256'];prior['scale'].update(before_lock_sha256=adapter.OLD_BEFORE,after_lock_sha256=adapter.OLD_AFTER);C.need(prior==p['case_before_config'][case]and C.pin(C.enc(prior))==p['case_before'][case]['upgrade-config.json'],'complete original config inverse; no unrelated guard/clock changes')
 if held is not None:
  held=C.safe(held);C.need(C.rows(held)==p['held_files']and len(p['held_files'])==489,'entire external held b21 source489');runtime.derive_owner(C.read(held/runtime.OLD/'run.py'));old=C.load('_latest607_proof_old_contract',held/runtime.OLD/'contract.py');api=old.scoped('_latest607_proof_composition',held/'scripts/ci/expanded604-apps6-public-pair-installer/contract.py',{});runtime.cache.module(old,C.read(held/runtime.OLD/'before_cache.py'))
 binding=__import__('namespace_context').verify()
 C.need(count>200,'nonzero entire three-case Python source control inventory');return dict(binding=binding,status='SOURCE_ONLY_LATEST607_UPDATER',cases=3,python_bodies=count,before=p['before'],after=p['after'],actors='NOT_RUN',fresh607='UNBOUND',baseline607='UNBOUND',Core7='SEPARATE_UNQUALIFIED_TRACK',hardware='NOT_RUN',release='NOT_ADMITTED')

def inputs(held,fresh,public):
 fact=verify(held);before=C.rows(fresh);C.need(before==C.profile()['fresh_source_files'],'whole corrected1197 fixed-target installer source');module,ledger=baseline.module(fresh);base=json.loads(C.read(C.safe(public)/'plan/target604-manifest.json'));kept,expected,lock=baseline.selection(fresh,base);checks=C.load('_latest607_current_source_archive_gate',C.safe(held)/'scripts/checks/package_checks.py');reports=module.inspect(C.safe(public),checks);C.need(len(reports)==7 and len(kept)==600 and expected==C.locks()[0]and C.pin(lock)==C.profile()['before'],'nonzero genuine seven archive/metadata/payload/signature-pin gates and600 held rows');C.need(before==C.rows(fresh),'complete corrected fresh source preserved');return dict(fact,source_inputs=dict(corrected_fresh_files=len(before),held_source_files=489,held_original_archives=600,incoming_archive_guards=len(reports),whole_materializer_inverse=len(ledger)),source_gate_only=True,installed_state='NOT_RUN')
