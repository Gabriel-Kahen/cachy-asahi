# SPDX-License-Identifier: MIT
"""Selected607 owner context, source-relative and typed; original606 remains whole."""
import hashlib,importlib.util,json,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
POLICY_SHA='5853748e4f20d436d3fd3542a0ee10e486743f722cad7425c35815d6b866d380'
STEP='''      - name: Selected607 actual owner-context controls before secrets
        timeout-minutes: 3
        run: python3 -I -B gui607-source/implementation/test_runner_context.py --assets "$RUNNER_TEMP/welcome5-assets"
'''
NATIVE_BEFORE="owner=load('_current606_full_original_runtime_owner',HERE/'factory/run.py');result=owner.run_service1800"
NATIVE_AFTER="owner=load('_selected607_owner_context',HERE/'runner_context.py').owner(load('_current606_full_original_runtime_owner',HERE/'factory/run.py'));result=owner.run_service1800"
EXPORT_BEFORE="load('_current606_fresh_whole_runner_export',HERE/'factory/context606.py').authorize_runner(runner)"
EXPORT_AFTER="load('_selected607_export_context',HERE/'runner_context.py').authorize_runner(runner)"
SUFFIX=b'\n# Selected607 runner context; whole682 and every older source gate remain mandatory.\ndef verify(require_known=False):\n return __import__(\'runner_context_guard\').verify(require_known)\n'
def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def edited(raw,edits):
 text=raw.decode()
 for a,b in edits:need(text.count(a)==1,'one selected607 context seam');text=text.replace(a,b,1)
 back=text
 for a,b in reversed(edits):need(back.count(b)==1,'one whole context inverse');back=back.replace(b,a,1)
 need(back.encode()==raw,'entire original682 body inverse');return text.encode()
def workflow(raw):
 anchor=b'      - name: Fixed observer and original timeout-retention controls before secrets\n';need(raw.count(anchor)==1 and STEP.encode()not in raw,'one new presecret context control');return raw.replace(anchor,STEP.encode()+anchor,1)
def policy():
 raw=(HERE/'runner-context-policy.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==POLICY_SHA,'fixed source-generated607 runner policy');return json.loads(raw)
def authorize_runner(runner):
 F=load('_selected607_fixed_factory',HERE/'factory/factory.py');C=load('_selected607_fixed_context',HERE/'factory/context606.py');V=load('_selected607_service_profile',HERE/'factory/service_capacity.py');O=load('_selected607_observer_profile',HERE/'observer_apply.py');p=policy();proof=C.authorize_runner(Path(runner));need(sorted(proof)==p['proof_keys'],'exact typed607 proof schema');key=proof['profile']+'-'+proof['mode'];need(key in p['code']and proof['page_size']==(4096 if proof['mode']=='generic4k'else 16384),'fixed source-selected profile/page mode');need(proof['service_validation_profile']==V.annotation()and C.read(Path(runner)/'service-vm-profile.json')==V.enc(V.SPEC)and proof['observer_diagnostic']==O.ANNOTATION,'whole selected service/observer typed annotations');need(proof['accepted_input_source']==F.obj(HERE/'factory/profile.json')['source']and proof['GUI']=='NOT_RUN'and proof['hardware']=='NOT_RUN'and proof['release']=='NOT_ADMITTED','source emission never actual acceptance')
 actual={q.relative_to(runner).as_posix():pin(C.read(q))for q in sorted(Path(runner).rglob('*'))if q.is_file()and q.suffix in('.py','.sh','.c')}
 need(actual==p['code'][key],'entire source-generated executable code closure; no foreign code inputs');need(pin(C.read(Path(runner)/'expected606.lock'))==p['target'],'whole fixed607 target');return proof

def owner(original):
 # Cloned footer's globals() is the namespace passed to the unchanged service
 # facade; its compiled run resolves these exact F/C objects while executing.
 F=load('_selected607_owner_factory',HERE/'factory/factory.py');C=load('_selected607_owner_context',HERE/'factory/context606.py');space=dict(vars(original));space.update(F=F,C=types.SimpleNamespace(**dict(vars(C),authorize_runner=authorize_runner)));fn=original.run_service1800;space['run_service1800']=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__);space['run_service1800'].__kwdefaults__=fn.__kwdefaults__;need(space['run_service1800'].__globals__['F']is F and space['run_service1800'].__globals__['C'].authorize_runner is authorize_runner,'executing607 owner must bind source-owned factory/context');m=types.ModuleType('_selected607_owner');vars(m).update(space);return m
