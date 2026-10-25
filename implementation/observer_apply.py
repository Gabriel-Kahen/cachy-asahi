# SPDX-License-Identifier: MIT
"""Exact lexical work reduction and fixed retained observer DATA; all clocks held."""
import ast,hashlib,json,shutil,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
BEFORE={'bytes':23555,'sha256':'fe1232ae6b510021910b4fb80016ac3b4668c6e4386cdae45e7b95196e400756'}
AFTER={'bytes':23916,'sha256':'d567aea0616bf92450e25e40daa54049ecc630dc7c988d2a55e19459e1958a8f'}
ANNOTATION=dict(role='EXACT_INSTALLED607_VERIFY',diagnostic_bytes=2048,observer_seconds=600,caller_seconds=600,service_seconds=1800,loop_seconds=1900,runtime_seconds=2350,owner_wait_seconds=2800,native_owner_seconds=6600,hotspot='UNKNOWN',native_fit='NOT_ESTABLISHED',M2_performance='NOT_RUN',acceptance=False)
STEP='''      - name: Fixed observer and original timeout-retention controls before secrets
        timeout-minutes: 3
        run: python3 -I -B gui607-source/implementation/test_observer.py --assets "$RUNNER_TEMP/welcome5-assets"
'''
CMD_BEFORE=b'python3 -I -B gui607-source/parent574/apps16_common.py'
CMD_AFTER=b'python3 -I -B gui607-source/implementation/presecret_control.py --control apps16-common --apps16-inputs \\"$GITHUB_WORKSPACE/apps16-inputs\\"'
SUFFIX=b'\n# Explicit observer child: whole676 AND574 source predicates remain mandatory.\ndef verify(require_known=False):\n return __import__(\'observer_guard\').verify(require_known)\n'
NATIVE_BEFORE="return load('_current606_source_bound_factory',HERE/'factory/factory.py').service1800()"
NATIVE_AFTER="return load('_installed607_observer_facade',HERE/'observer_apply.py').factory(load('_current606_source_bound_factory',HERE/'factory/factory.py').service1800())"

def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def edited(raw,rows):
 text=raw.decode()
 for a,b in rows:need(text.count(a)==1,'one fixed observer source seam');text=text.replace(a,b,1)
 back=text
 for a,b in reversed(rows):need(back.count(b)==1,'unique entire observer inverse');back=back.replace(b,a,1)
 need(back.encode()==raw,'whole observer body inverse');return text.encode()
def workflow(raw):
 anchor=b'      - name: Latest607 typed target and full source controls before secrets\n';need(raw.count(anchor)==1 and STEP.encode()not in raw and raw.count(CMD_BEFORE)==1,'one fixed observer step and original source control');value=raw.replace(anchor,STEP.encode()+anchor,1).replace(CMD_BEFORE,CMD_AFTER,1);need(unworkflow(value)==raw,'entire original676 workflow inverse');return value
def unworkflow(raw):
 need(raw.count(STEP.encode())==1 and raw.count(CMD_AFTER)==1,'one fixed control step/operand inverse');return raw.replace(STEP.encode(),b'',1).replace(CMD_AFTER,CMD_BEFORE,1)
def stage_body():
 text=(HERE/'observer_stage.py').read_text();need(text.count('import json,os,time\n')==1 and text.count('STAGES')==3 and text.count('CAP')==2 and text.count('class Stages:')==1,'exact fixed inline stage source');return text.replace('import json,os,time\n','',1).replace('STAGES','_OBSERVER_STAGES').replace('CAP','_OBSERVER_STAGE_CAP').replace('class Stages:','class _ObserverStages:',1)
def observer_rows():
 init="""    if mode=='verify':
        global _observer_mark
        _observer_mark=_ObserverStages().mark
"""
 return [("def observe(root,helper,expected,*,deadline=600):","_observer_mark=lambda _:False\n\ndef observe(root,helper,expected,*,deadline=600):"),("end=time.monotonic()+deadline;rows=helper.database(root,max_packages=607)","end=time.monotonic()+deadline;_observer_mark('inventory_begin');rows=helper.database(root,max_packages=607)"),("'exact actual607 ALPM inventory required')","'exact actual607 ALPM inventory required');_observer_mark('inventory_end')"),("    initial_database=records()","    _observer_mark('metadata_begin');initial_database=records();_observer_mark('metadata_end')"),("    for row in rows:\n        need(row['name'] not in owners","    _observer_mark('payload_begin')\n    for row in rows:\n        need(row['name'] not in owners"),("    links=[]","    _observer_mark('payload_end')\n    links=[]"),("    need(helper.database(root,max_packages=607)==rows","    _observer_mark('recheck_begin')\n    need(helper.database(root,max_packages=607)==rows"),("'database/root drift or deadline across complete payload read')","'database/root drift or deadline across complete payload read');_observer_mark('recheck_end')"),("    actual=observe(Path(root),load_db(Path(helper_path)),expected)",init+"    actual=observe(Path(root),load_db(Path(helper_path)),expected)"),("if __name__=='__main__':main()",stage_body()+"\nif __name__=='__main__':main()")]
def apply(out):
 out=Path(out);need(pin((out/'alpm_reader.py').read_bytes())==AFTER,'actual copied helper is exact frozen lexical product');p=out/'installed606.py';before=p.read_bytes();after=edited(before,observer_rows());ast.parse(after);p.write_bytes(after);need(not(out/'observer_stage.py').exists(),'no new generated/transport member');return dict(installed606=dict(before=pin(before),after=pin(after)),alpm_reader=AFTER)
def factory(original):
 space=dict(vars(original));prepare=original.prepare_code;seal=original.seal
 def prepare_code(*a,**k):
  result=prepare(*a,**k);changes=apply(a[2]if len(a)>2 else k['out']);return result[0],dict(result[1],observer_source_work=changes)
 def final_seal(out,*a,**k):
  value=seal(out,*a,**k);value['observer_diagnostic']=ANNOTATION;(Path(out)/'current606-proof.json').write_bytes(enc(value));return value
 space.update(prepare_code=prepare_code,seal=final_seal);fn=original.emit;space['emit']=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__);space['emit'].__kwdefaults__=fn.__kwdefaults__;need(space['emit'].__globals__['prepare_code']is prepare_code and space['emit'].__globals__['seal']is final_seal,'executing emitter must bind observer facade');m=types.ModuleType('_fixed_lexical_observer_factory');vars(m).update(space);return m
