# SPDX-License-Identifier: MIT
"""Exact lexical work reduction and fixed retained observer DATA; all clocks held."""
import ast,hashlib,json,shutil,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
BEFORE={'bytes':23555,'sha256':'fe1232ae6b510021910b4fb80016ac3b4668c6e4386cdae45e7b95196e400756'}
AFTER={'bytes':23916,'sha256':'d567aea0616bf92450e25e40daa54049ecc630dc7c988d2a55e19459e1958a8f'}
ANNOTATION={'role': 'EXACT_INSTALLED607_VERIFY', 'diagnostic_bytes': 2048, 'observer_seconds': 1200, 'caller_seconds': 1210, 'service_seconds': 1800, 'loop_seconds': 1900, 'runtime_seconds': 2350, 'owner_wait_seconds': 2800, 'native_owner_seconds': 6600, 'hotspot': 'UNKNOWN', 'native_fit': 'NOT_ESTABLISHED', 'M2_performance': 'NOT_RUN', 'acceptance': False, 'validation_profile': {'kind': 'GUI_TCG_INSTALLED607_READBACK1200_V1', 'role': 'EXACT_INSTALLED607_VERIFY', 'observer_seconds': 1200, 'caller_seconds': 1210, 'default_observer_seconds': 600, 'default_caller_seconds': 600, 'capture_seconds': 600, 'diagnostic_elapsed_cap_ns': 1215000000000, 'service_seconds': 1800, 'loop_seconds': 1900, 'runtime_seconds': 2350, 'owner_wait_seconds': 2800, 'native_owner_seconds': 6600, 'old600_fit': 'NOT_ESTABLISHED', 'native_fit': 'NOT_ESTABLISHED', 'service_reservation': 'NOT_RESERVED', 'M2_performance': 'NOT_RUN', 'hotspot': 'UNKNOWN', 'actual_source': None, 'actual_ref': None, 'actual_run': None}}
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
def mount_body():
 path=HERE.parent/'parent574/original/scripts/ci/expanded600-installer-vm/observer600.py';raw=path.read_bytes();need(pin(raw)=={'bytes':2784,'sha256':'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607'},'whole held observer600 query source');node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='_mount600');return ast.get_source_segment(raw.decode(),node)
def selected_verify_body():
 return '''def _selected_verify_observe(root,helper,expected,*,deadline):
    import types
    need(type(deadline)is int and deadline==1200,'exact selected verify1200 query role')
    original_capabilities=capabilities
    def selected_capabilities():
        caps=original_capabilities()
        original_mount=caps._mount
        caps._mount=_mount600(original_mount)
        need(caps._mount is not original_mount and caps._attrs.__globals__ is vars(caps),
             'fresh private selected capability module binding')
        return caps
    namespace=dict(observe.__globals__,capabilities=selected_capabilities)
    selected=types.FunctionType(observe.__code__,namespace,observe.__name__,observe.__defaults__,observe.__closure__)
    selected.__kwdefaults__=observe.__kwdefaults__
    need(selected.__globals__['capabilities']is selected_capabilities and
         observe.__globals__['capabilities']is original_capabilities,
         'actual selected observe globals and original capture binding')
    return selected(root,helper,expected,deadline=deadline)
'''

def observer_rows():
 init="""    if mode=='verify':
        global _observer_mark
        _observer_mark=_ObserverStages().mark
"""
 return [("def observe(root,helper,expected,*,deadline=600):","_observer_mark=lambda _:False\n\ndef observe(root,helper,expected,*,deadline=600):"),("end=time.monotonic()+deadline;rows=helper.database(root,max_packages=607)","end=time.monotonic()+deadline;_observer_mark('inventory_begin');rows=helper.database(root,max_packages=607)"),("'exact actual607 ALPM inventory required')","'exact actual607 ALPM inventory required');_observer_mark('inventory_end')"),("    initial_database=records()","    _observer_mark('metadata_begin');initial_database=records();_observer_mark('metadata_end')"),("    for row in rows:\n        need(row['name'] not in owners","    _observer_mark('payload_begin')\n    for row in rows:\n        need(row['name'] not in owners"),("    links=[]","    _observer_mark('payload_end')\n    links=[]"),("    need(helper.database(root,max_packages=607)==rows","    _observer_mark('recheck_begin')\n    need(helper.database(root,max_packages=607)==rows"),("'database/root drift or deadline across complete payload read')","'database/root drift or deadline across complete payload read');_observer_mark('recheck_end')"),("    actual=observe(Path(root),load_db(Path(helper_path)),expected)",init+"    actual=(_selected_verify_observe if mode=='verify' else observe)(Path(root),load_db(Path(helper_path)),expected,deadline=1200 if mode=='verify' else 600)"),("if __name__=='__main__':main()",mount_body()+"\n"+selected_verify_body()+"\n"+stage_body()+"\nif __name__=='__main__':main()")]
def forward_body():
 return r'''class _ObserverStageForward:
    """Fixed selected observer DATA only; loss never changes command authority."""
    prefix=b'INSTALLED607_OBSERVER_STAGE_DATA '
    stages=('inventory_begin','inventory_end','metadata_begin','metadata_end','payload_begin','payload_end','recheck_begin','recheck_end')
    def __init__(self,send):
        self.send=send;self.pending=b'';self.discard=False;self.last=0;self.input_bytes=0;self.output_bytes=0

    def record(self,raw):
        try:
            if not raw.startswith(self.prefix) or not raw.endswith(b'\n') or len(raw)>512:return False
            value=json.loads(raw[len(self.prefix):].decode('utf8','strict'))
            if type(value)is not dict or set(value)!={'schema','role','stage','ordinal','elapsed_ns','status'}:return False
            if type(value['schema'])is not int or value['schema']!=1 or value['role']!='EXACT_INSTALLED607_VERIFY' or value['status']!='BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE':return False
            if type(value['stage'])is not str or value['stage']not in self.stages:return False
            ordinal=self.stages.index(value['stage'])+1
            if type(value['ordinal'])is not int or value['ordinal']!=ordinal or ordinal<=self.last:return False
            if type(value['elapsed_ns'])is not int or not 0<=value['elapsed_ns']<=1215000000000:return False
            canonical=self.prefix+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
            if raw!=canonical or self.input_bytes+len(raw)>2048:return False
            fields={k:value[k]for k in ('schema','stage','ordinal','elapsed_ns','status')}
            framed=('DESKTOP574_EVENT '+json.dumps(dict(event='installed607_observer_stage_DATA',**fields),sort_keys=True)+'\n').encode()
            if self.output_bytes+len(framed)>2048:return False
            self.last=ordinal;self.input_bytes+=len(raw);self.output_bytes+=len(framed)
            self.send('installed607_observer_stage_DATA',**fields)
            return True
        except BaseException:
            return False

    def feed(self,raw):
        try:
            if type(raw)is not bytes or len(raw)>65536:return False
            start=0
            while start<len(raw):
                end=raw.find(b'\n',start);end=len(raw)if end<0 else end+1;piece=raw[start:end];start=end
                if not self.discard:
                    if len(self.pending)+len(piece)>512:self.pending=b'';self.discard=True
                    else:self.pending+=piece
                if piece.endswith(b'\n'):
                    if not self.discard:self.record(self.pending)
                    self.pending=b'';self.discard=False
            return True
        except BaseException:
            self.pending=b'';self.discard=True
            return False
'''

def forwarding_rows():
 return [("class Logged:",forward_body()+"\n\nclass Logged:"),("        self.overflow = False","        self.overflow = False\n        self._observer_forward = None\n        if name == 'installed606-preserved':\n            need(type(argv)is list and argv==['/usr/bin/python3','-I','-B',str(SHARE/'installed606.py'),'verify','/',str(SHARE/'alpm_reader.py'),str(SHARE/'expected.lock'),str(SHARE/'installed606.json')], 'exact selected installed607 verify command role')\n            self._observer_forward = _ObserverStageForward(emit)"),("            count = 0\n            with path.open('xb') as output, pipe:\n                while raw := pipe.read(65536):","            count = 0\n            forwarding = self._observer_forward if path == self.paths[1] else None\n            with path.open('xb') as output, pipe:\n                while raw := (pipe.read1(65536) if forwarding is not None else pipe.read(65536)):"),("                    output.write(raw[:max(0, MAX_LOG - count)])\n                    count += len(raw)","                    output.write(raw[:max(0, MAX_LOG - count)])\n                    if forwarding is not None:forwarding.feed(raw)\n                    count += len(raw)")]

def apply(out):
 out=Path(out);need(pin((out/'alpm_reader.py').read_bytes())==AFTER,'actual copied helper is exact frozen lexical product');p=out/'installed606.py';before=p.read_bytes();after=edited(before,observer_rows());ast.parse(after);p.write_bytes(after);guest=out/'base_guest.py';guest.write_bytes(edited(edited(guest.read_bytes(),[("logs,'installed606-preserved',timeout=600)","logs,'installed606-preserved',timeout=1210)")]),forwarding_rows()));need(not(out/'observer_stage.py').exists(),'no new generated/transport member');return dict(installed606=dict(before=pin(before),after=pin(after)),alpm_reader=AFTER)
def factory(original):
 space=dict(vars(original));prepare=original.prepare_code;seal=original.seal
 def prepare_code(*a,**k):
  result=prepare(*a,**k);changes=apply(a[2]if len(a)>2 else k['out']);return result[0],dict(result[1],observer_source_work=changes)
 def final_seal(out,*a,**k):
  value=seal(out,*a,**k);value['observer_diagnostic']=ANNOTATION;(Path(out)/'current606-proof.json').write_bytes(enc(value));return value
 space.update(prepare_code=prepare_code,seal=final_seal);fn=original.emit;space['emit']=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__);space['emit'].__kwdefaults__=fn.__kwdefaults__;need(space['emit'].__globals__['prepare_code']is prepare_code and space['emit'].__globals__['seal']is final_seal,'executing emitter must bind observer facade');m=types.ModuleType('_fixed_lexical_observer_factory');vars(m).update(space);return m
