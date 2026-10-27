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
 return '''def _selected_root_helper607(helper):
    import types
    original_directory=helper.directory
    literal=Path('/');literal_type=type(literal)
    validator=helper.relative;components={}
    def parts(name):
        # Strings and validated components are immutable configuration only.
        # Never retain descriptors, inodes, mounts, xattrs or other live facts.
        if type(name)is str and helper.relative is validator:
            value=components.get(name)
            if value is not None:return value
            value=tuple(validator(name).split('/'))
            if len(components)<4096:components[name]=value
            return value
        return tuple(helper.relative(name).split('/'))
    @contextmanager
    def directory(root,name):
        if type(root)is not literal_type or root!=literal:
            with original_directory(root,name)as fd:yield fd
            return
        # Every call opens and checks the complete live component chain.
        fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)]
        device=os.fstat(fds[0]).st_dev
        try:
            for component in parts(name):
                fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fds[-1])
                fds.append(fd);helper.need(os.fstat(fd).st_dev==device,'database mount crossing refused')
            yield fds[-1]
        finally:
            for fd in reversed(fds):os.close(fd)
    selected=types.SimpleNamespace(**vars(helper));selected.directory=directory
    need(helper.directory is original_directory and selected.directory is not original_directory,'private selected directory binding')
    return selected

def _selected_verify_observe(root,helper,expected,*,deadline):
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
    selected=types.FunctionType((_payload_observe607.__code__ if observe is _payload_original607 else observe.__code__),namespace,observe.__name__,observe.__defaults__,observe.__closure__)
    selected.__kwdefaults__=observe.__kwdefaults__
    need(selected.__globals__['capabilities']is selected_capabilities and
         observe.__globals__['capabilities']is original_capabilities,
         'actual selected observe globals and original capture binding')
    selected_helper=(_selected_root_helper607(helper)if type(root)is type(Path('/'))and root==Path('/')else helper)
    return selected(root,selected_helper,expected,deadline=deadline)
'''

PAYLOAD_BODY607=r'''class _Payload607:
    """Finite source-lock package ordinals; stderr DATA cannot change verification."""
    def __init__(self,expected):
        self.packages={name:index+1 for index,name in enumerate(sorted(expected))}
        self.start=time.monotonic_ns();self.count=0;self.bytes=0

    def mark(self,boundary,package,nodes,payload_bytes):
        try:
            ordinal=self.packages.get(package)
            if boundary not in ('begin','end') or type(ordinal)is not int or not 1<=ordinal<=607:return False
            if type(nodes)is not int or not 0<=nodes<=200000 or type(payload_bytes)is not int or not 0<=payload_bytes<=6*1024**3:return False
            if self.count>=1214:return False
            value=dict(schema=1,package=ordinal,boundary=boundary,nodes=nodes,payload_bytes=payload_bytes,
                       elapsed_ns=min(max(time.monotonic_ns()-self.start,0),1215000000000),status='PROGRESS_DATA_ONLY')
            raw=b'INSTALLED607_PAYLOAD_DATA '+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
            if len(raw)>192 or self.bytes+len(raw)>233088:return False
            self.count+=1;self.bytes+=len(raw)
            return os.write(2,raw)==len(raw)
        except Exception:
            return False
'''
def observer_rows():
 init="""    if mode=='verify':
        global _observer_mark
        _observer_mark=_ObserverStages().mark
"""
 rows=[("def observe(root,helper,expected,*,deadline=600):","_observer_mark=lambda _:False\n\ndef observe(root,helper,expected,*,deadline=600):"),("end=time.monotonic()+deadline;rows=helper.database(root,max_packages=607)","end=time.monotonic()+deadline;_observer_mark('inventory_begin');rows=helper.database(root,max_packages=607)"),("'exact actual607 ALPM inventory required')","'exact actual607 ALPM inventory required');_observer_mark('inventory_end')"),("    initial_database=records()","    _observer_mark('metadata_begin');initial_database=records();_observer_mark('metadata_end')"),("    for row in rows:\n        need(row['name'] not in owners","    _observer_mark('payload_begin')\n    for row in rows:\n        need(row['name'] not in owners"),("    links=[]","    _observer_mark('payload_end')\n    links=[]"),("    need(helper.database(root,max_packages=607)==rows","    _observer_mark('recheck_begin')\n    need(helper.database(root,max_packages=607)==rows"),("'database/root drift or deadline across complete payload read')","'database/root drift or deadline across complete payload read');_observer_mark('recheck_end')"),("    actual=observe(Path(root),load_db(Path(helper_path)),expected)",init+"    actual=(_selected_verify_observe if mode=='verify' else observe)(Path(root),load_db(Path(helper_path)),expected,deadline=1200 if mode=='verify' else 600)"),("if __name__=='__main__':main()",mount_body()+"\n"+selected_verify_body()+"\n"+stage_body()+"\nif __name__=='__main__':main()")]
 rendered=edited((HERE/'factory/installed607.py').read_bytes(),rows)
 node=next(n for n in ast.parse(rendered).body if isinstance(n,ast.FunctionDef)and n.name=='observe')
 payload=ast.get_source_segment(rendered.decode(),node)
 for before,after in (
  ('def observe(root,helper,expected,*,deadline=600):','def _payload_observe607(root,helper,expected,*,deadline=600):'),
  ("    for row in rows:\n        need(row['name'] not in owners", "    progress=_Payload607(expected)\n    for row in rows:\n        progress.mark('begin',row['name'],len(nodes),total)\n        need(row['name'] not in owners"),
  ("    _observer_mark('payload_end')", "        progress.mark('end',row['name'],len(nodes),total)\n    _observer_mark('payload_end')")):
  need(payload.count(before)==1,'one source-owned package progress seam');payload=payload.replace(before,after,1)
 before,after=rows[-1];needle="\nif __name__=='__main__':main()";need(after.count(needle)==1,'one existing generated footer')
 rows[-1]=(before,after.replace(needle,"\n_payload_original607=observe\n"+PAYLOAD_BODY607+"\n"+payload+needle,1))
 return rows
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
            fields={('observer_stage'if k=='stage'else k):value[k]for k in ('schema','stage','ordinal','elapsed_ns','status')}
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

# Source-owned finite recheck DATA: selected verify only, exact common guest clock.
RECHECK607_BODY=r'''class _Recheck607:
    """Seven finite DATA records, with a guest clock anchor; never authority."""
    phases=('observer_begin','database_begin','database_end','records_begin','records_end','root_begin','root_end')
    def __init__(self):
        self.start=time.monotonic_ns();self.last=-1;self.bytes=0

    def mark(self,phase):
        try:
            if type(phase)is not str or phase not in self.phases:return False
            ordinal=self.phases.index(phase)
            if ordinal<=self.last:return False
            now=time.monotonic_ns()
            if type(now)is not int or not 0<=now<2**63:return False
            elapsed=now-self.start
            if not 0<=elapsed<=1215000000000:return False
            value=dict(schema=1,phase=phase,ordinal=ordinal+1,monotonic_ns=now,
                       elapsed_ns=elapsed,status='RECHECK_DATA_ONLY_NOT_ACCEPTANCE')
            raw=b'INSTALLED607_RECHECK_DATA '+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
            if len(raw)>256 or self.bytes+len(raw)>1792:return False
            self.last=ordinal;self.bytes+=len(raw)
            return os.write(2,raw)==len(raw)
        except Exception:
            return False

    def call(self,phase,operation):
        self.mark(phase+'_begin')
        result=operation()
        self.mark(phase+'_end')
        return result
'''
RECHECK607_FORWARD=r'''class _RecheckForward607:
    """Selected stderr DATA only; no command success or cleanup authority."""
    prefix=b'INSTALLED607_RECHECK_DATA '
    phases=('observer_begin','database_begin','database_end','records_begin','records_end','root_begin','root_end')
    def __init__(self,send):
        self.send=send;self.pending=b'';self.discard=False;self.last=0
        self.input_bytes=0;self.output_bytes=0;self.clock=-1;self.elapsed=-1;self.offset=None

    def record(self,raw):
        try:
            if not raw.startswith(self.prefix)or not raw.endswith(b'\n')or len(raw)>256:return False
            value=json.loads(raw[len(self.prefix):].decode('utf8','strict'))
            if type(value)is not dict or set(value)!={'schema','phase','ordinal','monotonic_ns','elapsed_ns','status'}:return False
            if type(value['schema'])is not int or value['schema']!=1 or value['status']!='RECHECK_DATA_ONLY_NOT_ACCEPTANCE':return False
            if type(value['phase'])is not str or value['phase']not in self.phases:return False
            ordinal=self.phases.index(value['phase'])+1
            if type(value['ordinal'])is not int or value['ordinal']!=ordinal or ordinal<=self.last:return False
            if type(value['monotonic_ns'])is not int or not self.clock<=value['monotonic_ns']<2**63 or value['monotonic_ns']<0:return False
            if type(value['elapsed_ns'])is not int or not max(self.elapsed,0)<=value['elapsed_ns']<=1215000000000:return False
            offset=value['monotonic_ns']-value['elapsed_ns']
            if offset<0 or self.offset is not None and offset!=self.offset:return False
            canonical=self.prefix+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
            if raw!=canonical or self.input_bytes+len(raw)>1792:return False
            framed=('DESKTOP574_EVENT '+json.dumps(dict(event='installed607_recheck_DATA',**value),sort_keys=True)+'\n').encode()
            if self.output_bytes+len(framed)>2304:return False
            self.last=ordinal;self.clock=value['monotonic_ns'];self.elapsed=value['elapsed_ns'];self.offset=offset
            self.input_bytes+=len(raw);self.output_bytes+=len(framed)
            self.send('installed607_recheck_DATA',**value)
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
                    if len(self.pending)+len(piece)>256:self.pending=b'';self.discard=True
                    else:self.pending+=piece
                if piece.endswith(b'\n'):
                    if not self.discard:self.record(self.pending)
                    self.pending=b'';self.discard=False
            return True
        except BaseException:
            self.pending=b'';self.discard=True
            return False

class _ObserverAndRecheck607:
    def __init__(self,send):
        self.original=_ObserverStageForward(send);self.recheck=_RecheckForward607(send)
    def feed(self,raw):
        self.original.feed(raw);self.recheck.feed(raw)
'''
RECHECK607_EDITS=(
 ("    end=time.monotonic()+deadline;","    end=time.monotonic()+deadline;diagnostic=_Recheck607();diagnostic.mark('observer_begin');"),
 ("need(helper.database(root,max_packages=607)==rows and records()==initial_database and root_identity==helper.identity(root.lstat()) and time.monotonic()<end,",
  "need(diagnostic.call('database',lambda:helper.database(root,max_packages=607))==rows and diagnostic.call('records',records)==initial_database and root_identity==diagnostic.call('root',lambda:helper.identity(root.lstat())) and time.monotonic()<end,"),
)
def _recheck_payload607(raw,inverse=False):
 nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='_payload_observe607']
 need(len(nodes)==1,'one actual selected recheck payload body')
 before=ast.get_source_segment(raw.decode(),nodes[0]);body=before.encode()
 rows=[(b,a)for a,b in reversed(RECHECK607_EDITS)]if inverse else RECHECK607_EDITS
 for a,b in rows:body=edited(body,[(a,b)])
 return edited(raw,[(before,body.decode())])
def recheck_installed607(raw):
 result=_recheck_payload607(raw)
 return edited(result,[('_payload_original607=observe',RECHECK607_BODY+'\n_payload_original607=observe')])
def unrecheck_installed607(raw):
 result=edited(raw,[(RECHECK607_BODY+'\n_payload_original607=observe','_payload_original607=observe')])
 return _recheck_payload607(result,True)
def recheck_observer_rows607(rows):
 rows=list(rows);before,after=rows[-1];rows[-1]=(before,recheck_installed607(after.encode()).decode());return rows
def unrecheck_observer_rows607(rows):
 rows=list(rows);before,after=rows[-1];rows[-1]=(before,unrecheck_installed607(after.encode()).decode());return rows
def recheck_forwarding_rows607(rows):
 rows=list(rows);before,after=rows[0];rows[0]=(before,edited(after.encode(),[('class Logged:',RECHECK607_FORWARD+'\n\nclass Logged:')]).decode())
 before,after=rows[1];rows[1]=(before,edited(after.encode(),[('self._observer_forward = _ObserverStageForward(emit)','self._observer_forward = _ObserverAndRecheck607(emit)')]).decode());return rows
def unrecheck_forwarding_rows607(rows):
 rows=list(rows);before,after=rows[1];rows[1]=(before,edited(after.encode(),[('self._observer_forward = _ObserverAndRecheck607(emit)','self._observer_forward = _ObserverStageForward(emit)')]).decode())
 before,after=rows[0];rows[0]=(before,edited(after.encode(),[(RECHECK607_FORWARD+'\n\nclass Logged:','class Logged:')]).decode());return rows
_recheck_prior_observer_rows607=observer_rows
def observer_rows():return recheck_observer_rows607(_recheck_prior_observer_rows607())
_recheck_prior_forwarding_rows607=forwarding_rows
def forwarding_rows():return recheck_forwarding_rows607(_recheck_prior_forwarding_rows607())

# Explicit generic VM reservation; original default modules stay byte-held.
RESERVATION607={'M2_performance': 'NOT_RUN', 'acceptance': False, 'actual': None, 'cleanup_seconds': 450, 'current1800_fit': 'NOT_ESTABLISHED', 'current3460_fit': 'NOT_ESTABLISHED', 'default_loop_seconds': 1300, 'default_owner_wait_seconds': 2200, 'default_runtime_seconds': 1750, 'default_service_seconds': 1200, 'doctor_profile_seconds': 1080, 'inventory_caller_seconds': 60, 'loop_seconds': 3560, 'native_hotspot': 'UNKNOWN', 'native_owner_seconds': 6600, 'observation_seconds': 600, 'old1200_fit': 'NOT_ESTABLISHED', 'old1800_fit': 'NOT_ESTABLISHED', 'original_helpers': {'doctor_lifetime.py': {'bytes': 14227, 'sha256': '317f020b3b9e2a1bf15156d29399162915c8b3bd23531181921d7169ca4a21be'}, 'factory.py': {'bytes': 20793, 'sha256': 'dd2bebb61a5c5e75f96b2a4fbb2d768e0a89ea8f641fb48d392bcd5d8333647d'}, 'run.py': {'bytes': 6065, 'sha256': 'ea3cc4132ddac813d78daac6219062556afd99b25012969f7fe12c74b606b4ca'}}, 'owner_wait_seconds': 4460, 'product_scan_seconds': 30, 'profile': 'GUI_TCG_RESERVED_READBACK_3460_V1', 'ref': None, 'reservation': {'admission': 'REFUSE_BEFORE_VERIFY_IF_SHARED_REMAINING_BELOW1660', 'caller_seconds': 1210, 'cleanup_seconds': 450, 'loop_slack_seconds': 100, 'observer_seconds': 1200, 'one_shared_deadline': True, 'owner_cleanup_seconds': 450, 'pre_observer_seconds': 1800, 'readback_tail_seconds': 1660, 'restoration': 'MUST_COMPLETE_WITHIN_PRE_OBSERVER_PARTITION_FOR_READBACK_ADMISSION', 'runtime_cleanup_seconds': 450}, 'run': None, 'runtime_seconds': 4010, 'schema_version': 1, 'scope': 'OPT_IN_VM_FUNCTIONAL_VALIDATION_ONLY_NOT_PERFORMANCE', 'service_purpose': 'TCG_VALIDATION_FIXTURE_RESERVED_SERVICE_3460S', 'service_seconds': 3460, 'source': None}

# Only this explicit selected VM annotation changes; original/default facts remain.
ANNOTATION=dict(ANNOTATION,service_seconds=3460,loop_seconds=3560,runtime_seconds=4010,
    owner_wait_seconds=4460,old1800_fit='NOT_ESTABLISHED',reserved3460_fit='NOT_ESTABLISHED',
    validation_profile=dict(ANNOTATION['validation_profile'],kind='GUI_TCG_RESERVED_READBACK_3460_V1',
        service_seconds=3460,loop_seconds=3560,runtime_seconds=4010,owner_wait_seconds=4460,
        service_reservation='SHARED_DEADLINE_CALLER1210_CLEANUP450_REQUIRED',
        old1800_fit='NOT_ESTABLISHED',reserved3460_fit='NOT_ESTABLISHED',
        reservation=dict(RESERVATION607['reservation'])))

def _reservation_capacity607():
    import importlib.util
    spec=importlib.util.spec_from_file_location('_held_service1800_reservation_basis',HERE/'factory/service_capacity.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def reservation_spec():
    return json.loads(enc(RESERVATION607))

def reservation_annotation():
    return{k:v for k,v in reservation_spec().items()if k!='original_helpers'}

def _reservation_lifetime_body607():
    return '''

def reserve_readback607():
    """Admit only with full1210 caller and450 cleanup on the same lease."""
    owner=service_lease();now=time.monotonic_ns()
    need(owner['started_ns']<=now and now+(1210+450)*10**9<=owner['deadline_ns'],
         'selected VM readback requires full1210 caller and450 cleanup reservation')
    return owner
'''

def reserved_apply607(out):
    out=Path(out);changes={}
    def replace_file(name,rows):
        path=out/name;before=path.read_bytes();after=edited(before,rows)
        ast.parse(after)if name.endswith('.py')else None
        path.write_bytes(after);changes[name]=dict(before=pin(before),after=pin(after))
    purpose='TCG_VALIDATION_FIXTURE_SERVICE_1800S';newpurpose=RESERVATION607['service_purpose']
    lifetime=(out/'doctor_lifetime.py').read_bytes()
    need(lifetime.count(purpose.encode())==3,'three existing selected service purpose operands')
    text=lifetime.decode().replace(purpose,newpurpose)
    need(text.replace(newpurpose,purpose).encode()==lifetime,'whole service purpose inverse')
    text=edited(text.encode(),[('SERVICE_SECONDS=1800','SERVICE_SECONDS=3460')])+_reservation_lifetime_body607().encode()
    ast.parse(text);(out/'doctor_lifetime.py').write_bytes(text)
    changes['doctor_lifetime.py']=dict(before=pin(lifetime),after=pin(text))
    management=(out/'management_root.py').read_bytes()
    functions=[n for n in ast.parse(management).body if isinstance(n,ast.FunctionDef)and n.name=='serve']
    need(len(functions)==1,'one original management serve source')
    body=ast.get_source_segment(management.decode(),functions[0])
    selected=edited(body.encode(),[
        ('def serve(base,session,env,logs,deadline_ns):','def _reserved_serve607(base,session,env,logs,deadline_ns):'),
        ("C.need(time.monotonic_ns()<deadline_ns,'managed session deadline')",
         "C.need(time.monotonic_ns()<deadline_ns-(1210+450)*10**9,'managed session readback reservation deadline')")])
    combined=management+b'\n\n'+selected+b'\n'
    need(combined[:len(management)]==management,'original management root stays byte-held')
    ast.parse(combined);(out/'management_root.py').write_bytes(combined)
    changes['management_root.py']=dict(before=pin(management),after=pin(combined))
    replace_file('base_guest.py',[
        ("code = management_root.serve(managed_base, session, env, logs, DL.service_lease()['deadline_ns'])",
         "code = management_root._reserved_serve607(managed_base, session, env, logs, DL.service_lease()['deadline_ns'])"),
        ("        proof=command(['/usr/bin/python3','-I','-B',str(SHARE/'installed606.py')",
         "        DL.reserve_readback607()\n        proof=command(['/usr/bin/python3','-I','-B',str(SHARE/'installed606.py')")])
    replace_file('desktop574_fixture.sh',[('TimeoutStartSec=1800','TimeoutStartSec=3460')])
    replace_file('desktop574_runtime.py',[
        ('deadline = time.monotonic() + 1900','deadline = time.monotonic() + 3560'),
        ('signal.setitimer(signal.ITIMER_REAL, 2350)','signal.setitimer(signal.ITIMER_REAL, 4010)')])
    (out/'service-vm-profile.json').write_bytes(enc(reservation_spec()))
    (out/'service-capacity-proof.json').write_bytes(enc(dict(status='SOURCE_ONLY_EXPLICIT_RESERVED_TCG_SERVICE3460',
        profile=reservation_annotation(),derivatives=changes,actual=None)))
    return changes

def reserved_owner(namespace,*args,**kwargs):
    held=_reservation_capacity607();basis=held.profile();path=Path(namespace['__file__'])
    raw=held.read(path);footer=held.RUN_FOOTER.encode()
    need(raw.endswith(footer)and pin(raw[:-len(footer)])==basis['original_helpers']['run.py'],
         'whole original2200 owner before selected reservation facade')
    original=raw[:-len(footer)]
    body=next(ast.get_source_segment(original.decode(),n)for n in ast.parse(original).body if isinstance(n,ast.FunctionDef)and n.name=='run')
    text=edited(body.encode(),[('child.process.wait(timeout=2200)','child.process.wait(timeout=6680)')])
    runner=Path(args[1]if len(args)>1 else kwargs['runner'])
    proof=json.loads(held.read(runner/'current606-proof.json'))
    need(proof.get('service_validation_profile')==reservation_annotation()and
         held.read(runner/'service-vm-profile.json')==enc(reservation_spec()),'complete selected reservation profile required')
    text=_positive_owner_text607(text);H=_positive_helper607();policy=dict(schema=1,phases={n:dict(seconds=6880 if n=='vm'else 480 if n=='cleanup'else 21,local_io_seconds=100 if n=='vm'else 20 if n=='cleanup'else 1,fixed_tail_seconds=0)for n in('prep','vm','contract','cleanup')});space=dict(namespace,_positive_clock_owner=H,_positive_owner_policy=policy);exec(compile(text,str(path),'exec'),space)
    return space['run'](*args,**kwargs)

_reservation_original_apply607=apply
def apply(out):
    result=_reservation_original_apply607(out)
    return dict(result,reserved_vm=reserved_apply607(out))

_reservation_original_factory607=factory
def factory(original):
    selected=_reservation_original_factory607(original);space=dict(vars(selected));seal=selected.seal
    def reserved_seal(out,*args,**kwargs):
        result=seal(out,*args,**kwargs);result['service_validation_profile']=reservation_annotation()
        (Path(out)/'current606-proof.json').write_bytes(enc(result));return result
    space['seal']=reserved_seal;fn=selected.emit
    space['emit']=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__)
    space['emit'].__kwdefaults__=fn.__kwdefaults__
    need(space['emit'].__globals__['prepare_code']is selected.prepare_code and
         space['emit'].__globals__['seal']is reserved_seal,'executing reserved emitter bindings')
    module=types.ModuleType('_selected607_reserved_vm_factory');vars(module).update(space);return module

# Selected positive host clocks. Ancestor diagnostic/service annotations remain
# ancestry DATA; positive_budget_profile is the sole selected host policy.
_POSITIVE_CLOCK_BODY=b'# SPDX-License-Identifier: MIT\n"""Selected host phase leases. Timing DATA and admission never grant acceptance.\n\nPolicy is DATA: {schema: 1, phases: {prep|vm|contract|cleanup:\n    {seconds: int, local_io_seconds: int, fixed_tail_seconds: int}}}.\nThe local-I/O pool and fixed tail are included in each phase\'s total seconds.\nNo guest timestamp, process, GPG, filesystem or network actor is consulted.\n"""\nfrom contextlib import contextmanager\nfrom dataclasses import dataclass\nimport json\nimport math\nimport signal\nimport threading\nimport time\n\nNANO = 10**9\nMAX_SECONDS = 86400\nPHASES = (\'prep\', \'vm\', \'contract\', \'cleanup\')\n\n\ndef need(ok, why):\n    if not ok:\n        raise ValueError(why)\n\n\ndef integer(value, *, positive=False):\n    return type(value) is int and (1 if positive else 0) <= value <= MAX_SECONDS\n\n\ndef label(value):\n    need(type(value) is str and 0 < len(value) <= 64 and value.isascii()\n         and value.isprintable(), \'bounded ASCII phase label required\')\n    return value\n\n\n@dataclass(frozen=True, slots=True)\nclass PhaseSpec:\n    seconds: int\n    local_io_seconds: int\n    fixed_tail_seconds: int\n\n\n@dataclass(frozen=True, slots=True)\nclass Policy:\n    phases: tuple\n\n    def spec(self, name):\n        need(type(name) is str and name in PHASES, \'fixed host phase required\')\n        return self.phases[PHASES.index(name)]\n\n\ndef validate_policy(value):\n    """Validate before consulting a clock or changing a signal/timer."""\n    if type(value) is Policy:\n        value = dict(schema=1, phases={name: dict(\n            seconds=spec.seconds, local_io_seconds=spec.local_io_seconds,\n            fixed_tail_seconds=spec.fixed_tail_seconds)\n            for name, spec in zip(PHASES, value.phases)}) if (\n                type(value.phases) is tuple and len(value.phases) == 4\n                and all(type(v) is PhaseSpec for v in value.phases)) else None\n    need(type(value) is dict and set(value) == {\'schema\', \'phases\'}\n         and type(value[\'schema\']) is int and value[\'schema\'] == 1,\n         \'closed version1 phase policy required\')\n    rows = value[\'phases\']\n    need(type(rows) is dict and set(rows) == set(PHASES), \'four exact phases required\')\n    specs = []\n    for name in PHASES:\n        row = rows[name]\n        need(type(row) is dict and set(row) == {\n            \'seconds\', \'local_io_seconds\', \'fixed_tail_seconds\'}, \'closed phase specification\')\n        need(integer(row[\'seconds\'], positive=True)\n             and integer(row[\'local_io_seconds\'], positive=True)\n             and integer(row[\'fixed_tail_seconds\'])\n             and row[\'local_io_seconds\'] + row[\'fixed_tail_seconds\'] < row[\'seconds\'],\n             \'positive phase with contained local-I/O and fixed-tail reservations required\')\n        specs.append(PhaseSpec(**row))\n    return Policy(tuple(specs))\n\n\nclass PositiveDeadline(BaseException):\n    """Cannot be swallowed by a retained cleanup\'s broad except Exception."""\n    pass\n\n\nPhaseTimeout = PositiveDeadline\n\n\nclass _Clock:\n    def __init__(self, read):\n        self.read, self.last = read, None\n\n    def now(self):\n        value = self.read()\n        need(type(value) is int and 0 <= value < 2**63, \'finite monotonic_ns required\')\n        need(self.last is None or value >= self.last, \'host monotonic clock regressed\')\n        self.last = value\n        return value\n\n\nclass _Alarm:\n    def __init__(self, clock, backend, duration_ns, tail_ns, timeout):\n        self.clock, self.backend = clock, backend\n        self.duration_ns, self.tail_ns, self.timeout = duration_ns, tail_ns, timeout\n        self.changed = False\n\n    def __enter__(self):\n        need(threading.current_thread() is threading.main_thread(),\n             \'POSIX phase alarm requires main thread\')\n        b = self.backend\n        self.start = self.clock.now()\n        self.handler = b.getsignal(b.SIGALRM)\n        timer = b.getitimer(b.ITIMER_REAL)\n        need(type(timer) in (tuple, list) and len(timer) == 2\n             and all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in timer),\n             \'finite prior POSIX timer required\')\n        self.prior_ns = int(timer[0] * NANO)\n        need(timer[0] == 0 or self.prior_ns > 0,\n             \'active prior timer must have representable remaining nanoseconds\')\n        self.interval = timer[1]\n        self.outer_deadline = self.start + self.prior_ns if self.prior_ns else None\n        self.deadline = self.start + self.duration_ns\n        need(self.outer_deadline is None or\n             self.deadline + self.tail_ns <= self.outer_deadline,\n             \'full phase and tail do not fit existing outer timer\')\n        try:\n            self.changed = True\n            b.signal(b.SIGALRM, self._expired)\n            now = self.clock.now()\n            need(now < self.deadline and (self.outer_deadline is None or\n                 self.deadline + self.tail_ns <= self.outer_deadline), \'phase setup exhausted lease\')\n            b.setitimer(b.ITIMER_REAL, (self.deadline - now) / NANO)\n        except BaseException:\n            self._restore()\n            raise\n        return self\n\n    def _expired(self, signum, frame):\n        self._mark_timeout()\n        raise PhaseTimeout(\'host phase deadline expired\')\n\n    def _mark_timeout(self):\n        self.timeout()\n        parent = getattr(self.handler, \'__self__\', None)\n        if isinstance(parent, _Alarm):\n            parent._mark_timeout()\n\n    def _restore(self):\n        if not self.changed:\n            return\n        self.changed = False\n        b = self.backend\n        # Attempt all three restoration operations even when one fails.\n        try:\n            b.setitimer(b.ITIMER_REAL, 0)\n        finally:\n            try:\n                b.signal(b.SIGALRM, self.handler)\n            finally:\n                fault = None\n                try:\n                    now = self.clock.now()\n                except BaseException as error:\n                    # An invalid clock cannot justify preserving future time.\n                    fault, now = error, self.outer_deadline or self.start\n                remaining = max(0, self.outer_deadline - now) if self.outer_deadline else 0\n                remaining = min(self.prior_ns, remaining)\n                b.setitimer(b.ITIMER_REAL, remaining / NANO, self.interval)\n                if fault is not None:\n                    raise fault\n                if self.outer_deadline is not None and remaining == 0:\n                    self._mark_timeout()\n                    raise PhaseTimeout(\'existing outer timer exhausted\')\n\n    def __exit__(self, kind, error, traceback):\n        try:\n            if self.clock.now() >= self.deadline:\n                self._mark_timeout()\n                if error is None:\n                    raise PhaseTimeout(\'host phase deadline expired\')\n        finally:\n            self._restore()\n\n\nclass Lease:\n    def __init__(self, name, spec, clock, backend, report):\n        self.name, self.spec, self.clock, self.backend = name, spec, clock, backend\n        self.report, self.records = report, 0\n        self.failed, self.closed, self.active = False, False, False\n        self.io_used_ns = 0\n\n    def _timeout(self):\n        self.failed = True\n\n    def _emit(self, event, **values):\n        need(self.records < 64, \'bounded phase timing DATA record count exceeded\')\n        self.records += 1\n        row = dict(schema=1, role=\'HOST_PHASE_TIMING_DATA_ONLY\', phase=self.name,\n                   event=event, ordinal=self.records, monotonic_ns=self.clock.now(),\n                   acceptance=False, clock_domain=\'HOST_MONOTONIC_NS\', **values)\n        need(len(json.dumps(row, allow_nan=False, separators=(\',\', \':\')).encode()) <= 2048,\n             \'bounded phase timing DATA required\')\n        if self.report is not None:\n            self.report(row)\n\n    def _check(self):\n        need(not self.closed, \'phase lease already closed\')\n        if self.failed or self.clock.now() >= self.deadline:\n            self.failed = True\n            raise PhaseTimeout(\'host phase lease exhausted\')\n\n    def admit(self, name, seconds, retirement, *, tail=0):\n        """Return the full requested cap; never silently clip a child."""\n        label(name)\n        need(integer(seconds, positive=True) and integer(retirement) and integer(tail),\n             \'strict bounded child/retirement/tail seconds required\')\n        self._check()\n        remaining = self.deadline - self.clock.now()\n        reserved = ((retirement + tail + self.spec.fixed_tail_seconds) * NANO\n                    + max(0, self.spec.local_io_seconds * NANO - self.io_used_ns))\n        need(seconds * NANO + reserved <= remaining,\n             \'full child, retirement and remaining fixed/local-I/O tail do not fit\')\n        self._emit(\'child_admitted\', label=name, requested_seconds=seconds,\n                   retirement_seconds=retirement, extra_tail_seconds=tail,\n                   reserved_tail_ns=reserved)\n        self._check()\n        need(seconds * NANO + reserved <= self.deadline - self.clock.now(),\n             \'admission callback exhausted child reservation\')\n        return seconds\n\n    @contextmanager\n    def child(self, name, seconds, retirement, *, tail=0):\n        need(not self.active, \'child/local-I/O contexts must be sequential\')\n        self.admit(name, seconds, retirement, tail=tail)\n        self.active = True\n        try:\n            with _Alarm(self.clock, self.backend, seconds * NANO,\n                        (retirement + tail + self.spec.fixed_tail_seconds) * NANO\n                        + max(0, self.spec.local_io_seconds * NANO - self.io_used_ns),\n                        self._timeout):\n                yield seconds\n            self._check()\n        except BaseException:\n            self.failed = True\n            raise\n        finally:\n            self.active = False\n\n    @contextmanager\n    def local_io(self, name):\n        """Bound all synchronous local work by one aggregate per-phase pool."""\n        label(name)\n        self._check()\n        need(not self.active, \'child/local-I/O contexts must be sequential\')\n        available = self.spec.local_io_seconds * NANO - self.io_used_ns\n        need(available > 0 and available + self.spec.fixed_tail_seconds * NANO <=\n             self.deadline - self.clock.now(), \'complete remaining local-I/O pool must fit\')\n        self.active = True\n        started = self.clock.now()\n        try:\n            with _Alarm(self.clock, self.backend, available,\n                        self.spec.fixed_tail_seconds * NANO, self._timeout):\n                yield\n            self._check()\n        except BaseException:\n            self.failed = True\n            raise\n        finally:\n            self.io_used_ns += max(0, self.clock.now() - started)\n            self.active = False\n\n\n@contextmanager\ndef phase(policy, name, *, report=None, outer_tail=0,\n          _clock_ns=time.monotonic_ns, _signal=signal):\n    """Start a new relative phase. Private backend arguments are MODEL seams."""\n    policy = validate_policy(policy)\n    spec = policy.spec(name)\n    need(report is None or callable(report), \'timing DATA callback required\')\n    need(integer(outer_tail), \'strict bounded outer tail required\')\n    clock = _Clock(_clock_ns)\n    lease = Lease(name, spec, clock, _signal, report)\n    try:\n        with _Alarm(clock, _signal, spec.seconds * NANO, outer_tail * NANO,\n                    lease._timeout) as alarm:\n            lease.started_ns, lease.deadline = alarm.start, alarm.deadline\n            try:\n                lease._emit(\'begin\', cap_seconds=spec.seconds,\n                            local_io_seconds=spec.local_io_seconds,\n                            fixed_tail_seconds=spec.fixed_tail_seconds)\n                lease._check()\n                yield lease\n                lease._check()\n            except BaseException:\n                lease.failed = True\n                raise\n            finally:\n                lease._emit(\'end\', status=\'FAILED\' if lease.failed else \'EXIT_PENDING_TIMER_RESTORATION\',\n                            elapsed_ns=clock.now() - lease.started_ns,\n                            local_io_used_ns=lease.io_used_ns)\n    finally:\n        lease.closed = True\n'
_POSITIVE_RUNTIME_RENDERER=b'# SPDX-License-Identifier: MIT\n"""Finite reversible transform of the four trusted Source676 runtime bodies.\n\nOnly parses DATA. Never imports/executes an input runtime or starts an actor.\nPhase capacities are a proposed host admission profile, not proof of guest fit.\n"""\nimport ast\nimport hashlib\nimport textwrap\n\nEXPECTED = {\n    \'minimal-generic4k\': (20362, \'ad5c6532b4fb574e4271c7415ae9dd5b071c328ebc6b33e6c31e1f9a46b50cfb\'),\n    \'minimal-generic16k\': (21067, \'5e666ff31f1c9ccbff826a92ed83118c6d8dcea5247802515ee6450b1a8856ac\'),\n    \'overlay-generic4k\': (20362, \'b4c5670eb02da7436cd6ba63eb6f8192acddc1c0bdd363cd41adfb2eb4acac14\'),\n    \'overlay-generic16k\': (21067, \'ec1b99c34513672130b42c9c57181d828888004494b3fa3222a60233ef8b8e13\'),\n}\nPOLICY = dict(schema=1, phases={\n    \'prep\': dict(seconds=1850, local_io_seconds=100, fixed_tail_seconds=0),\n    \'vm\': dict(seconds=4120, local_io_seconds=110, fixed_tail_seconds=0),\n    \'contract\': dict(seconds=150, local_io_seconds=20, fixed_tail_seconds=0),\n    \'cleanup\': dict(seconds=460, local_io_seconds=30, fixed_tail_seconds=0),\n})\n\n\ndef need(ok, why):\n    if not ok:\n        raise ValueError(why)\n\n\ndef pin(raw):\n    return len(raw), hashlib.sha256(raw).hexdigest()\n\n\ndef _wrap(body, name):\n    return ("        with phase(POSITIVE_RUNTIME_POLICY, " + repr(name)\n            + ", report=positive_timing_DATA.append) as positive_lease:\\n"\n            + textwrap.indent(body, \'    \'))\n\n\ndef rows(raw, clock_body):\n    """Return ordered, exact-one-occurrence byte-invertible text seams."""\n    need(type(raw) is bytes and pin(raw) in EXPECTED.values(), \'exact trusted Source676 runtime required\')\n    need(type(clock_body) is bytes and 0 < len(clock_body) <= 65536,\n         \'bounded Source-owned clock helper bytes required\')\n    helper = clock_body.decode()\n    tree = ast.parse(helper)\n    names = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}\n    need({\'phase\', \'validate_policy\', \'PositiveDeadline\', \'Lease\'} <= names\n         and not any(isinstance(n, ast.If) for n in tree.body), \'inline pure clock helper required\')\n    text = raw.decode()\n    seams = []\n\n    def change(before, after):\n        nonlocal text\n        need(before != after and text.count(before) == 1, \'one runtime seam: \' + before[:90])\n        text = text.replace(before, after, 1)\n        seams.append((before, after))\n\n    addition = (helper.rstrip() + \'\\n\\nPOSITIVE_RUNTIME_POLICY = validate_policy(\'\n                + repr(POLICY) + \')\\n\\n\')\n    change(\'def main():\', addition + \'def main():\')\n    change("    qmp = None\\n", "    positive_timing_DATA = []\\n"\n           "    report[\'positive_host_timing_DATA\'] = positive_timing_DATA\\n    qmp = None\\n")\n    change(\'    signal.setitimer(signal.ITIMER_REAL, 4010)\',\n           \'    # The selected relative phase clocks replace the inherited4010 alarm.\')\n    change("        report[\'commands\'].append({\'argv\': argv, \'log\': label + \'.log\'})",\n           "        positive_lease.admit(label, seconds, 10)\\n"\n           "        report[\'commands\'].append({\'argv\': argv, \'log\': label + \'.log\'})")\n    change(\'    def text_command(argv):\\n\',\n           "    def text_command(argv):\\n        positive_lease.admit(\'text-command\', 30, 5)\\n")\n\n    prep_start = text.index("        require(text_command([\'docker\', \'info\'")\n    vm_start = text.index("        active = common.LoggedProcess(cmd, out / \'guest.log\'")\n    contract_start = text.index("        report[\'gui_contract\'] = verify_result")\n    except_start = text.index(\'    except Exception as error:\\n\', contract_start)\n    body = text[prep_start:except_start]\n    prep = text[prep_start:vm_start]\n    vm = text[vm_start:contract_start]\n    contract = text[contract_start:except_start]\n    need(vm.count(\'deadline = time.monotonic() + 3560\') == 1, \'one selected VM loop\')\n    vm = vm.replace(\'deadline = time.monotonic() + 3560\',\n                    \'deadline = time.monotonic() + 3820\', 1)\n    change(body, _wrap(prep, \'prep\') + _wrap(vm, \'vm\') + _wrap(contract, \'contract\'))\n    change(\'    except Exception as error:\\n        report.update(error_type=\',\n           "    except BaseException as error:\\n        report[\'status\'] = \'FAIL\'\\n"\n           \'        report.update(error_type=\')\n\n    cleanup_start = text.index(\'        if qmp is not None:\\n\', text.index(\'    finally:\\n        signal.setitimer\'))\n    write_start = text.index("        (out / \'runtime.json\').write_text", cleanup_start)\n    restore_start = text.index(\'        for sig, handler in previous.items(): signal.signal(sig, handler)\', write_start)\n    restore_end = text.index(\'\\n\', restore_start) + 1\n    cleanup = text[cleanup_start:write_start]\n    writes = text[write_start:restore_start]\n    restore = text[restore_start:restore_end]\n    before = text[cleanup_start:restore_end]\n    launch = \'                done = subprocess.run(argv, env=dict(os.environ), stdout=subprocess.PIPE,\'\n    need(cleanup.count(launch) == 1, \'one unchanged cleanup command launch\')\n    cleanup = cleanup.replace(launch,\n        "                positive_lease.admit(\'cleanup-command\', 30, 5)\\n" + launch, 1)\n    after = ("        try:\\n"\n             "            with phase(POSITIVE_RUNTIME_POLICY, \'cleanup\', report=positive_timing_DATA.append) as positive_lease:\\n"\n             + textwrap.indent(cleanup, \'        \')\n             + "        except BaseException as positive_cleanup_error:\\n"\n               "            report[\'status\'] = \'FAIL_CLEANUP\'\\n"\n               "            report[\'positive_cleanup_error_DATA\'] = dict(error_type=type(positive_cleanup_error).__name__[:64], reason=str(positive_cleanup_error)[:512], acceptance=False)\\n"\n               "        finally:\\n"\n               "            try:\\n" + textwrap.indent(writes, \'        \')\n             + "            finally:\\n" + textwrap.indent(restore, \'        \'))\n    change(before, after)\n    ast.parse(text)\n    need(inverse(text.encode(), seams) == raw, \'entire original runtime inverse\')\n    return seams\n\n\ndef transform(raw, clock_body):\n    result = raw.decode()\n    for before, after in rows(raw, clock_body):\n        need(result.count(before) == 1, \'runtime seam drift\')\n        result = result.replace(before, after, 1)\n    ast.parse(result)\n    return result.encode()\n\n\ndef inverse(raw, seams):\n    need(type(raw) is bytes and type(seams) in (list, tuple), \'runtime inverse DATA required\')\n    result = raw.decode()\n    for before, after in reversed(seams):\n        need(result.count(after) == 1, \'exact whole runtime inverse seam\')\n        result = result.replace(after, before, 1)\n    restored = result.encode()\n    need(pin(restored) in EXPECTED.values(), \'inverse must join complete trusted Source676 runtime\')\n    return restored\n'
POSITIVE_PROFILE={'acceptance': False, 'actual': None, 'bootstrap_child_seconds': [300, 30, 30, 90, 90, 30, 60, 30, 1200], 'bootstrap_cleanup_seconds': 180, 'bootstrap_legacy_child_seconds': [1800, 120, 120, 600, 600, 120, 930, 120, 5400], 'bootstrap_shell_retirement_seconds': 210, 'bootstrap_shell_seconds': 2550, 'bootstrap_step_minutes': 47, 'bootstrap_total_seconds': 2520, 'bootstrap_work_seconds': 2340, 'case': 'minimal-generic4k', 'guest_service_seconds': 3460, 'guest_unit_start_seconds': 3580, 'guest_unit_stop_seconds': 120, 'gui_shell_retirement_seconds': 600, 'gui_shell_seconds': 11000, 'gui_step_minutes': 194, 'job_minutes': 360, 'native_control_slack_seconds': 20, 'native_entry_and_finally_seconds': 320, 'native_fit': 'NOT_ESTABLISHED', 'native_seconds': 10980, 'ordered_cleanup_producer_child_seconds': 240, 'ordered_cleanup_receipt_seconds': 30, 'ordered_cleanup_retirement_seconds': 10, 'ordered_cleanup_seconds': 450, 'ordered_cleanup_source_and_local_seconds': 180, 'ordered_cleanup_step_minutes': 8, 'owner_post_seconds': 100, 'owner_pre_seconds': 100, 'owner_retirement_seconds': 480, 'owner_work_seconds': 6880, 'positive_program_startup_seconds': 20, 'prepare_seconds': 3280, 'profile': 'GUI607_POSITIVE_PHASES_V1', 'runtime_child_seconds': 6680, 'runtime_entry_seconds': 100, 'runtime_phase_total_seconds': 6580, 'runtime_phases': {'cleanup': {'fixed_tail_seconds': 0, 'local_io_seconds': 30, 'seconds': 460}, 'contract': {'fixed_tail_seconds': 0, 'local_io_seconds': 20, 'seconds': 150}, 'prep': {'fixed_tail_seconds': 0, 'local_io_seconds': 100, 'seconds': 1850}, 'vm': {'fixed_tail_seconds': 0, 'local_io_seconds': 110, 'seconds': 4120}}, 'schema': 1, 'vm_loop_seconds': 3820}
def _positive_helper607():
 import importlib.util,sys
 name='_positive607_host_clock_'+str(id(object()));s=importlib.util.spec_from_file_location(name,HERE/'presecret_control.py');m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def _positive_owner_text607(raw):
 import textwrap
 text=raw.decode();tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef));outer=next(n for n in node.body if isinstance(n,ast.Try));lines=text.splitlines(keepends=True)
 prefix=''.join(lines[node.lineno:outer.lineno-1]);body=''.join(lines[outer.lineno-1:outer.finalbody[0].lineno-2]);cleanup=''.join(lines[outer.finalbody[0].lineno-1:node.end_lineno]).rstrip()+'\n';need(body.endswith('    finally:\n')is False,'try body source boundary')
 # Keep original try body and finally body literally, changing only indentation.
 trybody=''.join(lines[outer.body[0].lineno-1:outer.finalbody[0].lineno-2])
 trybody=trybody.replace("        child=common.LoggedProcess(","        _positive_lease.admit('runtime-full-child',6680,0)\n        child=common.LoggedProcess(",1)
 source=lines[0]+"    _positive_rows=[];_positive_context=_positive_clock_owner.phase(_positive_owner_policy,'vm',report=_positive_rows.append,outer_tail=500)\n    _positive_lease=_positive_context.__enter__()\n    try:\n"+textwrap.indent(prefix,'    ')+"        try:\n"+textwrap.indent(trybody,'    ')+"        finally:\n            try:\n                _positive_context.__exit__(*sys.exc_info())\n            finally:\n                with _positive_clock_owner.phase(_positive_owner_policy,'cleanup',report=_positive_rows.append):\n"+textwrap.indent(cleanup,'            ')+"    finally:\n        if not _positive_lease.closed:_positive_context.__exit__(*sys.exc_info())\n        if 'fd'in locals()and Path(out).is_dir():(Path(out)/'positive-owner-clock.json').write_bytes(C.enc(dict(profile='GUI607_POSITIVE_PHASES_V1',timing_DATA=_positive_rows,acceptance=False)))\n"
 ast.parse(source);return source.encode()

_positive_apply_parent607=apply
def apply(out):
 result=_positive_apply_parent607(out);out=Path(out);module=types.ModuleType('_source_positive_runtime_renderer');exec(compile(_POSITIVE_RUNTIME_RENDERER,'<Source-owned-positive-runtime-renderer>','exec'),vars(module));p=out/'desktop574_runtime.py';before=p.read_bytes();after=module.transform(before,_POSITIVE_CLOCK_BODY);p.write_bytes(after)
 fixture=out/'desktop574_fixture.sh';old=fixture.read_bytes();new=edited(old,[('TimeoutStartSec=3460','TimeoutStartSec=3580\nTimeoutStopSec=120')]);fixture.write_bytes(new);(out/'positive-budget-profile.json').write_bytes(enc(POSITIVE_PROFILE));return dict(result,positive_runtime=dict(before=pin(before),after=pin(after)),positive_unit=dict(before=pin(old),after=pin(new)))

_positive_factory_parent607=factory
def factory(original):
 held=_positive_factory_parent607(original);space=dict(vars(held));original_seal=held.seal
 def positive_seal(out,*args,**kwargs):
  value=original_seal(out,*args,**kwargs);value['positive_budget_profile']=POSITIVE_PROFILE;(Path(out)/'current606-proof.json').write_bytes(enc(value));return value
 space['seal']=positive_seal;space['emit']=types.FunctionType(held.emit.__code__,space,held.emit.__name__,held.emit.__defaults__,held.emit.__closure__);space['emit'].__kwdefaults__=held.emit.__kwdefaults__;need(space['emit'].__globals__['seal']is positive_seal,'executing positive seal binding');module=types.ModuleType('_positive607_factory');vars(module).update(space);return module
