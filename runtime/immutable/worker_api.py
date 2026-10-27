"""Explicit immutable-source API; original mutable copier/lifetime code is held."""
from contextlib import contextmanager
from pathlib import Path
import os,types
import inputs,mount_proxy
P,C,_,_=inputs.broker()

def clone(function,**replacements):
 value=types.FunctionType(function.__code__,dict(function.__globals__,**replacements),function.__name__,function.__defaults__,function.__closure__);value.__kwdefaults__=function.__kwdefaults__;return value

DESCRIPTOR_QUERY_PROFILE={'name': 'GNU_IMMUTABLE_PRIVATE_DESCRIPTOR_QUERY_V1', 'query': 'SOURCE_HELD_STATX_MNT_ID_OR_ORIGINAL_FDINFO', 'observations': 'FULL_FRESH_ORIGINAL', 'mount_identity_cache': False, 'native_timeout_fit': 'NOT_ESTABLISHED'}
def descriptor_api(api):
 # Whole original source code objects; only private descriptor-query globals differ.
 original_roots=api['roots'];aux_copy=api['copy'];caps=api['caps']
 query=aux_copy._isolated(Path('/source/scripts/ci/expanded600-installer-vm/observer600.py'),'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607')
 roots=types.SimpleNamespace(**vars(original_roots));roots._mount_id=query._mount600(original_roots._mount_id)
 roots.observe=clone(original_roots.observe,_mount_id=roots._mount_id)
 # Auxiliary Readers and their descriptor parent/root checks otherwise retain
 # the old full_root global through a separate measure_copy namespace.
 aux=aux_copy.aux;walk_space=dict(vars(aux.copy),roots=roots)
 for name in ('_parent','_root_check','_source_alias'):
  function=getattr(aux.copy,name)
  walk_space[name]=contextmanager(clone(function.__wrapped__,**walk_space)) if name=='_parent' else clone(function,**walk_space)
 walk=types.SimpleNamespace(**walk_space);aux_space=dict(vars(aux),roots=roots,copy=walk)
 methods={name:clone(value,**aux_space) if isinstance(value,types.FunctionType) else value for name,value in vars(aux.Reader).items() if name not in ('__dict__','__weakref__')}
 aux_space['Reader']=type('_ImmutableDescriptorReader',(),methods)
 for name in ('checkpoint','load_comparator'):aux_space[name]=clone(getattr(aux,name),**aux_space)
 checkpoint=types.SimpleNamespace(**aux_space)
 copy_api=types.SimpleNamespace(**vars(aux_copy));copy_api.aux=checkpoint
 copy_api._copy_binding=clone(aux_copy._copy_binding,roots=roots,aux=checkpoint)
 # Retain every original capability graph/attribute/hash/identity scan afresh.
 cap_space=dict(vars(caps),_mount=query._mount600(caps._mount))
 for name in ('_scan','observe','restore'):cap_space[name]=clone(getattr(caps,name),**cap_space)
 capability=types.SimpleNamespace(**cap_space)
 return dict(api,roots=roots,copy=copy_api,caps=capability)


_OPERATION_LABELS = ('SOURCE_OBSERVATION', 'TARGET_OBSERVATION', 'TARGET_CAPABILITIES', 'TARGET_AUXILIARY', 'COPY_DATA', 'SOURCE_ROOT_CHECK', 'SOURCE_PARENT', 'LIFETIME_ENTER', 'LIFETIME_BODY', 'LIFETIME_EXIT', 'CONTEXT_LIMITS', 'CONTEXT_ADAPTER')
def operation(label, call, *args, **kwargs):
 P.need(label in _OPERATION_LABELS, 'fixed source-owned operation label')
 try:return call(*args, **kwargs)
 except BaseException:
  validation_failure('OP_'+label)
  raise

def bind(api,channel,guest):
 api=descriptor_api(api)
 original_roots=api['roots'];aux=api['copy'];facade=types.SimpleNamespace(**vars(original_roots))
 def source(limits):return operation('SOURCE_OBSERVATION',channel.source,limits)
 def observe(root,*args,**kwargs):
  if Path(root)==Path('/held'):
   P.need(not args and set(kwargs)<={'limits','hardlinks'}and kwargs.get('hardlinks')=='generic-development-internal','exact immutable original observe operands');return source(kwargs['limits'])['observation']
  return operation('TARGET_OBSERVATION',original_roots.observe,root,*args,**kwargs)
 facade.observe=observe;api=dict(api,roots=facade)
 caps=types.SimpleNamespace(**vars(api['caps']));original_caps=caps.observe
 def capobserve(root,nodes,limits):
  if Path(root)==Path('/held'):
   value=source(limits);P.need(nodes==value['nodes'],'whole immutable nodes/capability join');return value['capabilities']
  return operation('TARGET_CAPABILITIES',original_caps,root,nodes,limits)
 caps.observe=capobserve;api['caps']=caps
 checkpoint=types.SimpleNamespace(**vars(aux.aux));original_checkpoint=checkpoint.checkpoint
 def check(root,observation,limits):
  if Path(root)==Path('/held'):
   value=source(limits);P.need(observation==value['observation'],'whole immutable observation/aux join');return value['auxiliary']
  return operation('TARGET_AUXILIARY',original_checkpoint,root,observation,limits)
 checkpoint.checkpoint=check
 binding=clone(aux._copy_binding,roots=facade,aux=checkpoint)
 def copy_data(source_root,target,*,limits,hardlinks='generic-development-internal'):
  P.need(Path(source_root)==Path('/held')and Path(target)in(Path('/work/pristine/root'),Path('/work/modified/root'))and hardlinks=='generic-development-internal'and not limits.allow_cross_device,'new exact separate-device copy purpose')
  copy_started=__import__('time').monotonic_ns();initial=source(limits);module=binding(limits);parent_graph=immutable_nodes_bind(module,source_root,initial['nodes']);old_parent=module._parent;old_check=module._root_check;checks=[1];R=descriptor_reader(api,limits)
  def scope_check():
   current=source(limits);parent=Path(target).parent;info=parent.lstat()
   P.need(current['nodes']==initial['nodes']and info.st_uid==0 and info.st_dev!=channel.pinned['root_identity'][0]and not os.statvfs(parent).f_flag&os.ST_RDONLY,'immutable source and disjoint owned writable target');checks[0]+=1
  @contextmanager
  def parent(root,path,mount,identities,subject,expected=None):
   if P.stable(os.fstat(root))==channel.pinned['root_identity']:
    P.need(mount==channel.pinned['source_mount']and parent_graph(expected)is expected,'exact authenticated source parent graph')
    detail_stage='SOURCE_PARENT_ENTER'
    try:
     with R.lookup_parent(root,path,mount,subject,expected)as value:
      detail_stage='COPY_BODY'
      yield value
      detail_stage='SOURCE_PARENT_EXIT'
    except BaseException as error:
     copy_failure_detail(detail_stage,error,copy_started,subject,channel.nonce)
     validation_failure('OP_SOURCE_PARENT')
     raise
   else:
    with old_parent(root,path,mount,identities,subject,expected)as value:yield value
  def root_check(*args,**kwargs):operation('SOURCE_ROOT_CHECK',old_check,*args,**kwargs);scope_check()
  module._parent=parent;module._root_check=root_check
  try:result=operation('COPY_DATA',module.copy_data,source_root,target,limits=limits,hardlinks=hardlinks)
  except BaseException as error:
   copy_failure_detail('COPY_DATA',error,copy_started,limits,channel.nonce)
   raise
  scope_check();P.need(checks[0]==7,'all original root checkpoints plus final scope check')
  result.update(scope='EXPLICIT_IMMUTABLE_SOURCE_SEPARATE_DEVICE_FULL_COPY',copy_byte_identical_before_initialization=True,transaction_acceptance='NOT ESTABLISHED',gnu_bind_scope=dict(purpose='GNU_VERITY_COPY_SCOPE_V1',checkpoints=checks[0],original_copier_sha256=aux.COPY_SHA256,lifetime_sha256=aux.LIFETIME_SHA256,map_index_sha256=channel.pinned['index']['sha256']))
  return result
 def copied_root(source_root,workspace,**kwargs):
  module=aux._isolated(aux.disposable_copy.__file__,aux.LIFETIME_SHA256);module.measure_copy=types.SimpleNamespace(copy_data=copy_data)
  # Whole lifetime/cleanup body and120-second budget; fresh descriptor mount query.
  module.roots=types.SimpleNamespace(**dict(vars(module.roots),_mount_id=api['roots']._mount_id))
  @contextmanager
  def observed():
   detail_started=__import__('time').monotonic_ns();phase='LIFETIME_ENTER'
   try:
    with module.copied_root(source_root,workspace,**kwargs)as value:
     phase='LIFETIME_BODY'
     yield value
     phase='LIFETIME_EXIT'
   except BaseException as error:
    copy_failure_detail(phase,error,detail_started,kwargs.get('limits'),channel.nonce)
    validation_failure('OP_'+phase)
    raise
  return observed()
 def receipt(value,case):
  P.need(case in('pristine','modified')and set(value)=={'purpose','checkpoints','original_copier_sha256','lifetime_sha256','map_index_sha256'}and value==dict(purpose='GNU_VERITY_COPY_SCOPE_V1',checkpoints=7,original_copier_sha256=aux.COPY_SHA256,lifetime_sha256=aux.LIFETIME_SHA256,map_index_sha256=channel.pinned['index']['sha256']),'new complete immutable copy receipt; old bind proof never substituted');return value
 scope=types.SimpleNamespace(copied_root=copied_root,receipt=receipt);oldbridge=api['capabilities'];bridge=types.SimpleNamespace(**vars(oldbridge));original_context=contextmanager(clone(oldbridge.copied_root.__wrapped__,scope=scope));bridge.records=clone(oldbridge.records,scope=scope)
 def context(api,source_root,workspace,index,evidence=None,**kwargs):
  # Whole held CI2400 accounting and per-observation/restore600 windows.
  budget=operation('CONTEXT_LIMITS',validation_limits,guest,kwargs['limits']);kwargs['limits']=budget
  return original_context(operation('CONTEXT_ADAPTER',guest._copy_context_api,api,budget),source_root,workspace,index,evidence=evidence,**kwargs)
 bridge.copied_root=context;api['capabilities']=bridge;api['proc_probe']=mount_proxy.Proxy(channel);return api

# Explicit TEST-only copied-root observation capacity; never product timeouts.
WORKER_VALIDATION_PROFILE={'name': 'GNU_IMMUTABLE_WORKER_VALIDATION_1200_7200_V1', 'observation_seconds': 1200, 'copy_context_seconds': 7200, 'old_600_2400_fit': 'NOT_ESTABLISHED', 'owner_ceiling': 10500, 'qemu_ceiling': 10800, 'old_1200_4800_fit': 'NOT_ESTABLISHED', 'current_1200_7200_fit': 'NOT_ESTABLISHED', 'shared_capacity_reserved': False}
_VALIDATION_LABELS=tuple('SNAPSHOT_'+case.upper()+'_'+phase.upper().replace('-','_')for case in('pristine','modified')for phase in('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'))+('COPY_SELECTED_OBSERVE','COPY_COPIED_TREE','COPY_CAPABILITY_RESTORE','COPY_COPY_DATA')
_VALIDATION_LABELS+=tuple('OP_'+name for name in _OPERATION_LABELS)
_validation_writes=0

def validation_failure(label):
 global _validation_writes
 # Exception-only fixed literals, no message/path/identity/time serialization.
 try:
  if type(label)is not str or label not in _VALIDATION_LABELS or _validation_writes>=8:return
  _validation_writes+=1;os.write(2,b'GNU_WORKER_FAILURE_DATA '+label.encode('ascii')+b'\n')
 except BaseException:pass

def validation_limits(guest,original):
 import ast
 text=Path(guest.__file__).read_text();tree=ast.parse(text)
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_copy_context_limits'];P.need(len(nodes)==1,'one whole trusted copy-context function')
 before=ast.get_source_segment(text,nodes[0]);after=before
 pairs=(('<=600:', '<=1200:'),('original.deadline+1800','original.deadline+6000'),("'PARENT2400'","'PARENT7200'"),("'WINDOW600'","'WINDOW1200'"),('time.monotonic()+600','time.monotonic()+1200'))
 # The extension appears twice (diagnostic arithmetic and actual deadline).
 for old,new in dict(pairs).items():
  count=2 if old in('original.deadline+1800',"'PARENT2400'","'WINDOW600'")else 1
  P.need(after.count(old)==count,'finite worker capacity source seam');after=after.replace(old,new)
 old='            except BaseException:\n                if not state[\'failed\']:emit(state,\'failure\',state[\'expiry\'])'
 new='            except BaseException:\n                try:validation_failure(\'COPY_\'+operation)\n                except BaseException:pass\n                if not state[\'failed\']:emit(state,\'failure\',state[\'expiry\'])'
 P.need(after.count(old)==1,'one exception-only copy diagnostic seam');after=after.replace(old,new)
 restored=after.replace(new,old)
 for old,new in reversed(tuple(dict(pairs).items())):restored=restored.replace(new,old)
 P.need(restored==before,'entire original copy-context function inverse')
 space=dict(vars(guest),validation_failure=validation_failure);exec(compile(after,guest.__file__,'exec'),space)
 return space['_copy_context_limits'](original)

def install_validation(module):
 original_limits=module.limits;original_snapshot=module.snapshot
 def limits(api,seconds=1200):return original_limits(api,seconds)
 def snapshot(api,root,label):
  try:return original_snapshot(api,root,label)
  except BaseException:
   if type(label)is str:validation_failure('SNAPSHOT_'+label.upper().replace('-','_'))
   raise
 module.limits=limits;module.snapshot=snapshot

"""Private source-parent globals; original lookup/open/identity bodies remain whole."""
def descriptor_reader(api, limits):
 original=C.reader()
 query=api['copy']._isolated(Path('/source/scripts/ci/expanded600-installer-vm/observer600.py'),'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607')
 # The held query does a real statx on EVERY call, cross-checks the first
 # against the original fdinfo API, and falls back to that API if unavailable.
 def fallback(fd, subject):return original.mount_id(fd)
 fresh=query._mount600(fallback)
 def mount(fd):return fresh(fd,limits)
 # Reuse only the process libc handle/function; NEVER an opened directory or
 # mount/result. Keep the whole original openat2 ABI/path/syscall body active.
 libc=original.ctypes.CDLL(None,use_errno=True)
 syscall=libc.syscall
 def library(name,**kwargs):
  P.need(name is None and kwargs=={'use_errno':True},'exact original process libc operand')
  return libc
 c_api=types.SimpleNamespace(**vars(original.ctypes));c_api.CDLL=library
 opener=clone(original.open_beneath,ctypes=c_api)
 reader=types.SimpleNamespace(**vars(original))
 reader.mount_id=mount
 reader.lookup_parent=contextmanager(clone(original.lookup_parent.__wrapped__,mount_id=mount,open_beneath=opener))
 return reader

"""Fixed public exception categories only; no paths, argv or error text."""
_COPY_DETAIL_STAGES=('SOURCE_PARENT_ENTER','COPY_BODY','SOURCE_PARENT_EXIT','COPY_DATA','LIFETIME_ENTER','LIFETIME_BODY','LIFETIME_EXIT')
_COPY_DETAIL_CAUSES=('ROOT_OBSERVATION_DEADLINE','CAPACITY_REFUSAL','FILE_CONTENT_REFUSAL','IDENTITY_OR_MOUNT_REFUSAL','OS_NO_SPACE','OS_IO','OS_FILESYSTEM_REFUSAL','OS_OTHER','OTHER_VALUE','INTERRUPTED','OTHER')
_COPY_DETAIL_EXCEPTIONS=('ValueError','OSError','MemoryError','KeyboardInterrupt','SystemExit','RuntimeError','Other')
_copy_detail_writes=0
def copy_detail_validate(v,nonce):
 import re
 if type(v)is not dict or set(v)!={'schema','nonce','ordinal','stage','cause','exception','errno','elapsed_ns','shared_remaining_ns','acceptance'}:raise ValueError('fixed copy failure DATA keys')
 if v['schema']!=1 or type(v['schema'])is not int or v['nonce']!=nonce or type(nonce)is not str or re.fullmatch('[a-f0-9]{32}',nonce)is None or v['acceptance']is not False:raise ValueError('fixed copy failure DATA identity')
 if type(v['ordinal'])is not int or not 1<=v['ordinal']<=8 or v['stage']not in _COPY_DETAIL_STAGES or v['cause']not in _COPY_DETAIL_CAUSES or v['exception']not in _COPY_DETAIL_EXCEPTIONS:raise ValueError('fixed copy failure DATA enums')
 if type(v['elapsed_ns'])is not int or not 0<=v['elapsed_ns']<=10800*10**9:raise ValueError('bounded actual copy elapsed')
 if v['shared_remaining_ns']is not None and(type(v['shared_remaining_ns'])is not int or not -10800*10**9<=v['shared_remaining_ns']<=10800*10**9):raise ValueError('bounded actual shared remaining')
 if v['errno']is not None and(type(v['errno'])is not int or not 1<=v['errno']<=4095):raise ValueError('bounded public errno')
 return v
def copy_failure_detail(stage,error,started,limits,nonce):
 # Only exceptional paths read a clock or inspect an error. Unknown/private
 # messages stay UNKNOWN by finite category and are never serialized or hashed.
 global _copy_detail_writes
 try:
  import errno,json,math,os,time
  if _copy_detail_writes>=8:return
  kind=next((name for cls,name in((OSError,'OSError'),(ValueError,'ValueError'),(MemoryError,'MemoryError'),(KeyboardInterrupt,'KeyboardInterrupt'),(SystemExit,'SystemExit'),(RuntimeError,'RuntimeError'))if isinstance(error,cls)),'Other')
  number=error.errno if isinstance(error,OSError)and type(error.errno)is int and 1<=error.errno<=4095 else None
  cause='OTHER'
  if isinstance(error,ValueError):
   message=error.args[0]if len(error.args)==1 and type(error.args[0])is str else None
   messages={
    'root observation deadline':'ROOT_OBSERVATION_DEADLINE',
    'insufficient or unknown filesystem free inode count':'CAPACITY_REFUSAL',
    'insufficient future transaction bytes/inodes':'CAPACITY_REFUSAL',
    'copy source content drift':'FILE_CONTENT_REFUSAL','growing copy source':'FILE_CONTENT_REFUSAL',
    'copy write made no progress':'FILE_CONTENT_REFUSAL',
    'source parent metadata differs':'IDENTITY_OR_MOUNT_REFUSAL','source parent rebound':'IDENTITY_OR_MOUNT_REFUSAL',
    'fresh source mount crossing':'IDENTITY_OR_MOUNT_REFUSAL','copy metadata differs':'IDENTITY_OR_MOUNT_REFUSAL',
    'copy source group differs':'IDENTITY_OR_MOUNT_REFUSAL','copy source group drift':'IDENTITY_OR_MOUNT_REFUSAL',
    'copy anchor drift':'IDENTITY_OR_MOUNT_REFUSAL','copy source alias drift':'IDENTITY_OR_MOUNT_REFUSAL',
    'copy destination alias drift':'IDENTITY_OR_MOUNT_REFUSAL','copy mount crossing':'IDENTITY_OR_MOUNT_REFUSAL'}
   cause=messages.get(message,'OTHER_VALUE')
  elif isinstance(error,OSError):cause='OS_NO_SPACE'if number==errno.ENOSPC else'OS_IO'if number==errno.EIO else'OS_FILESYSTEM_REFUSAL'if number in(errno.ENOENT,errno.ENOTDIR,errno.ELOOP,errno.EXDEV,errno.EACCES,errno.EPERM)else'OS_OTHER'
  elif isinstance(error,(KeyboardInterrupt,SystemExit)):cause='INTERRUPTED'
  now=time.monotonic_ns();remaining=None;deadline=getattr(limits,'deadline',None)
  if type(deadline)in(int,float)and math.isfinite(deadline):remaining=int(deadline*10**9)-now
  value=dict(schema=1,nonce=nonce,ordinal=_copy_detail_writes+1,stage=stage,cause=cause,exception=kind,errno=number,elapsed_ns=now-started,shared_remaining_ns=remaining,acceptance=False)
  copy_detail_validate(value,nonce);raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
  if len(raw)>768:return
  _copy_detail_writes+=1;os.write(2,b'GNU_COPY_FAILURE_DETAIL '+raw+b'\n')
 except BaseException:pass # Optional DATA never replaces the original exception.

"""Private readonly copy-loop nodes; every original observation stays fresh."""
from pathlib import Path
from types import MappingProxyType, SimpleNamespace


def immutable_nodes_seal(nodes):
    if type(nodes) is not dict:
        raise ValueError('ordinary complete source nodes required')
    frozen = {}
    for name, node in nodes.items():
        if type(name) is not str or type(node) is not dict:
            raise ValueError('ordinary source node record required')
        if any(type(key) is not str or type(value) not in (str, int, bool, type(None))
               for key, value in node.items()):
            raise ValueError('source node values must be immutable scalars')
        frozen[name] = MappingProxyType(dict(node))
    return MappingProxyType(frozen)


def immutable_nodes_bind(module, source, initial):
    """Keep original full guards, expose a private immutable copy-loop map."""
    source = Path(source)
    expected = immutable_nodes_seal(initial)
    original = module.roots
    observations = []
    selected = []

    def observe(root, **kwargs):
        value = original.observe(root, **kwargs)
        if Path(root) == source:
            observations.append(value)
        return value

    def eligible(observation):
        nodes = original.require_eligible(observation)
        if any(observation is value for value in observations):
            if nodes != expected:
                raise ValueError('whole immutable source graph changed')
            # Original eligibility still sees the original ordinary dictionaries.
            # Copy-loop rows have no writable aliases to those dictionaries.
            selected.append(expected)
            return expected
        return nodes

    def parent_graph(nodes):
        if not selected or nodes is not expected:
            raise ValueError('exact privately sealed source graph required')
        return nodes

    module.roots = SimpleNamespace(**dict(vars(original), observe=observe, require_eligible=eligible))
    return parent_graph

# ORIGINAL_SIGNATURE__ORIGINAL_SIG
_ORIGINAL_SIG_BODY=b'# SPDX-License-Identifier: MIT\n"""Required original ALARM signature restore; unsigned candidate policy stays separate.\n\nNo import-time actors. Runtime callers supply the existing bounded runner and a\nPID1-established current clock. This helper never adjusts time or edits a DB.\n"""\nimport base64\nimport contextlib\nimport ctypes\nimport hashlib\nimport json\nimport math\nimport os\nfrom pathlib import Path\nimport re\nimport stat\nimport time\nimport types\n\nPACKAGE = \'glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz\'\nPACKAGE_PIN = dict(bytes=9676568, sha256=\'8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b\')\nSIGNATURE_PIN = dict(bytes=566, sha256=\'82501115482ffeb93cce58cbc36372d917159f9dd60e3b98fd465e94e16c2103\')\nFINGERPRINT = \'68B3537F39A313B3E574D06777193F152BDBE6A6\'\nSIGNATURE_CREATED = 1779031879\nKEYRING_COMMIT = \'29432c01130efc4ad297dfe8f487d5b79cbaf8e9\'\nPUBLIC_KEY_BASE64 = \'LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptUUlOQkZMYkJQTUJFQUROQjJYQ2hKUXBsUXdiQWNsOHdraHNQWk9vekdoeFVZTytCVkVGNXZLanhjTnplUjU3CmNqajF2ZVN3NGFNbUV2MDNNa0JIaTlLeXlrMndLVWtGSHVUeDREQTVaeG5UdCsyU2NFZXpFRmNtRW9Mc1JZaWQKZVEzNXRZV2FGanBqWkRMYlI0YnAwRXVtQ2k4enZ4d1FoWGwxeTRtUlp0QkNYOHo0b3RkZ1hrOGRCVVNKSnNIZwpKc21Sb2J6TnJCREdFcjU1bk5iVDg4QnhWY0czOWlkRWIvVk9PcVMyNHJvZ05KdmtRVWRSd211OEJHYlNXSS9JCmFMQjBXYzNjTUVNWUNmNVRqRXdTOUhzU3ZVT21kV0U2UldpYnBuYVFwOS9DQzJQSGpQMVFuWGJ5M2IxdEE0bk4KbTNJa1A4SHF3cGVJclNMM2hYU0dLTW4zcjhEL1NpbDFrZlUxVTVubGwweWsxaEZvQWZWSzRBV0V2Y1hIcXkzQgp3RFlhMWl5aWlxR3htTlJ5aUs2OEVabGMyMHVHakcvR3NOSngrL3RBcVdUT1c4c0pKcnArWUdULzA3dUgyaVJQCml2aldBZXRnaWg2eGxtYmJrc2tLbTRoUUkrc296V0ZPYlF6UGU5UjFsTkxmbmNHWHh4T1dra3ZHbGJkWlZYWW4KUFNLZjZkRitIK2xaTGpTdmhSem5UbHorak0vT3UvOWJtemYwa3ZKdDZmT0k0YVI4WmVzZVhFSmZ4cEEwQmRieAphcmpQVXJQajlYVkx1NzViRlhNemVSSUVXM3pMZDlPaUhBbnhmTGxtL1dEd2MwellqSkl5VTBWL0tWaFl4N0txCm1ObEQ1enBnNGdJaCtuNTNPcFNaUHNMQ1d4d2EvNXk4dzhITE9FcFpSQi9ONm9jbXpJU1NpcVdVbHdBUkFRQUIKdERaQmNtTm9JRXhwYm5WNElFRlNUU0JDZFdsc1pDQlRlWE4wWlcwZ1BHSjFhV3hrWlhKQVlYSmphR3hwYm5WNApZWEp0TG05eVp6NkpBamNFRXdFS0FDRUZBbExiQlBNQ0d3TUZDd2tJQndNRkZRb0pDQXNGRmdJREFRQUNIZ0VDCkY0QUFDZ2tRZHhrL0ZTdmI1cWFKYkEvL1F2L3JUNStIRlFJT3pETHdNclgrQTd2OC9vanEvMjFHejNUeTgrRVIKeXZadnRnME9hWDVDWWRqN3JWTmdzcHdTTlVnZ1lQVEt5dUM3b29FWG8yU3dMT0JNR2t1OWs2d3lkem9pcFhubgpRWkNZcVZQaSttK2FqYlJ2ZzhBZTdUREF0cmF1U3hqZW92SHBDb3ZnYVdWbkJrN0ZlNjJBblNlNm5VR0xZWGdCCkw3Tk9ZVGI5eUg4VG1LQXM3dmFVTEFWM1dMdFFja2lWYWQrMVJ3UmxFcU5vdmV5ZXBqR0V0KzFGT2Z0UlBlemQKRUgzTkNaYjB0Wk9HalB4ajFPUVdZL1RFNGdmcHB2ajhsclNZMWhFUDZVM29nbjR2Njk5eXhBZ1ZWMzFJbnR0ZwpDWWNjSkpQSUtwWGdFYS81SWt0eHFwN0NpU3VCeEJxYmpzUmdqU2t6Mk5CNWZjTFdrN2RhQ3hkV1MzaktnR09RCnNoYnd0OWxOQWVPRjBUSHFtM2NJZTNKQVA3NkEvY08wZk9oMHZMMHpoMXdIbERxSVBZRzRKWHVCejlxTDlTb1UKcnVlVnh1bzJvcXk3aU5xRXAybnVQbDRRdzRYRzRYR0Y5VzByUFBHUy9pRGNDS0pOeVRvNU9QR1VYU1B1TEJRUgpDcTZKYUt6ZTlpTEJkSEhYTkZTQ2FkWmlNRFNpVlhOblRXRnROYWFnRFRFZ1V2RGJMTGd0cWx4Wm5EY0VSUkg1CjFoV01XUmFLcmdGcC9PRWEyTVJSd1AvWEJnN2haaUhqQkVVU0VWd1lUMlp6bXN5N1QwdVhYdTlMRHR1NHFuSHAKK2pOSmFZUG9SSWhubFFQbzZsQm92QTRyZ3o3a09kTVVQUVpSTVBDZ2o2QVc4Z25kemk1Mi9pMk5NUnc3NUJpTQpObEM1QWcwRVV0c0U4d0VRQU5OUWs4Y1pGWUVhcm5XaTBET05jRnBGNnJ2Nk1WM0kxc3J0SlFOaUZXbG1sblVXCjl3V2dDZGNsQUFaT29saFUwanFjTmlXUUtxbWVUL1BJRXhrNjlMMWJTcFIxdDVUaXNITGhjU25rOGFqVUVuZ0gKaUdNeXd3SVF3SmI4a0NSZ3l0VXd4UTVsN0Eya2llaDJ2RnU1ZmZudmt3bXhoUHgvdldLSFlNdnRiUGZLQy9KVQpQQUNzZUxhY1RQaERSQ2cvSFZJYnYzSkljRTZlSHRuSGxsaVRZd1BaMXdpS3FWTk01MWQ0TjdBTjJLOHpVTU9kCldCRHBubk1YODl4N25DTWdFMEY0b0Q2cHEvaHM5Vi9jVFJ3TUx0ZWhlY0xISHhhc1k1ZXV1OFlPUWpOamlNZm4KSFZ3ZGV1bEFDUE9mQXlISUZtTWY0NHM0d2JicjdtWmRHWElmNlhMZU82SXdUQ3dJSkdhMkpsNzZzL0orNWRYUApDQkgzTTFWdzlGWW1qVlB4UzN0VmVNa3lYS2NXT1RXSU5ZMkQzbXk2L2RFSTZObXJLZGMzSVVqay9LZ3BtbmVWCk1Kcmk5Z3Q3dFV5LzBVSGxOTmJyeVJqeVFMOVJubHFBVWlHcWVWSU5RZ2hwWFphdnEwWkl5YnFTTEtDazIwdG8KQjhtcWlUWE83UTRnRWVBa29RanpaY0ZxWHNtV0RVRTZiTXJqcWxudWE4SG9UYUt0YVhtcnh5S1pmcGc4dTlzMwowSkVES0EybW51ZFZ1N0hmM21TM3BWUXpIOG9NYlNkSENBdmlkVHMySjRxakVaVnlNbGIxRHlaOXVaV04yUzFJCjR2NmdSczlHY3RUTzdsc0tNZ1R4ckl3UGloYWgrd1JURlQ0Z1lCMnRhU0d1M2JGZWxiak0zOXVLRkV3L0FCRUIKQUFHSkFoOEVHQUVLQUFrRkFsTGJCUE1DR3d3QUNna1FkeGsvRlN2YjVxWlgvZy8vZXBxcnR1ZnNTK2FVY0R0YQo3NjdTTWYrUDdLQW5aaXRSQ2t4YlV2OTlqd2srRXBZbEJjandZbXB4S0hJWmZyN1l0U2VtY3RLQzhEQzNNN0xrCk9heWZuVUFLK0dKZHdRRmFXN3pZM1k2aTc5Qmo5Zk92Y21HeVVuZlFyem5EYU4xSXMxdXJqaDJCTW9DSEttbSsKYUxqVTU4ZFBhMTYyNEdweittazJ0MWVjQVlSMVA2OHdHT0JjQnhUcTVuMkdDSmJta21kd1ZEa3RCd2FuT0RKMQo3SEY1cVZ4QitEOHV4cCtTMjdoY1N2TVpLOTFNOXpUNmUyOFdjRVIwa1lqaGxOemI2aGg5MVZzRllNemJ0R1Y4CnN1OHNYdjhSM21lS1JDRHBVKzNKMzJCNk9QNEJPNHpvamdwaUZnU1JlNGtrU0l4eTUvWnF5R3VjTGpaNlEyMkMKTlBOTXVxK3hWamdmTHZVNDlWVk1HOWRwYTcyMTZNeHZWNEJBd3VWMUd4Qyt4TEo1U0pqZEVFRTloSEdPdXRnQQpuWEVxQWFyVy82RXBObTBwRjNnY3lrRFpyUFQzL05RZ0lUNjdjek42TmU2QWpQYlRsSmxhNmgzTHhLSUVrRWFBCnkvYnlhWkxvUHVSNDJCZjBrMDBJbWZ4VDRiNWFhN1UvMXdGWjlTQ1RodWI0MXRpK1JYU0x1TXVSQW00VG1ndDcKWitHT1JEQ0ppQTRobnJZVlliclZXZGNRZzRVREkrajdURVdoelB1M3JBby9rbGVKRVYzdUl2aXM2UE9mVnRBNgpPMjhaVkRYeGd3RXplc29xY20zanBVb2Ezc0lrdkxXUkRseCttNHRGcVhiL2pSSGowbEQyaVR2Y0lBQ2pBTURuCmZ4Nnk4K0Ewa0JpYUFtY1kwMVUvdXBZWGVIcz0KPUFJZ0QKLS0tLS1FTkQgUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLQo=\'\nTRUST_DATA = {\n    \'archlinuxarm.gpg\': base64.b64decode(PUBLIC_KEY_BASE64, validate=True),\n    \'archlinuxarm-trusted\': b\'68B3537F39A313B3E574D06777193F152BDBE6A6:4:\\n\',\n    \'archlinuxarm-revoked\': b\'\',\n}\nTRUST_PINS = {\n    \'archlinuxarm.gpg\': dict(bytes=3098, sha256=\'6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f\'),\n    \'archlinuxarm-trusted\': dict(bytes=44, sha256=\'f2a7250f2a2b77542f82f4219b2bae7895f27b3dcfdf350b497e2be306af776d\'),\n    \'archlinuxarm-revoked\': dict(bytes=0, sha256=\'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\'),\n}\nGPG_CONF = ("no-default-keyring\\nkeyring pubring.gpg\\ntrust-model pgp\\ntrusted-key " + FINGERPRINT +\n            "\\nno-auto-key-retrieve\\nno-auto-key-import\\nauto-key-locate clear\\ndisable-dirmngr\\nno-autostart\\n").encode()\nSTATUS_CAP = 65536\n\n\ndef need(ok, why):\n    if not ok:\n        raise ValueError(why)\n\n\ndef pin(raw):\n    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())\n\n\ndef encoded(value):\n    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + \'\\n\').encode()\n\n\ndef ordinary(path):\n    path = Path(path)\n    need(path.is_absolute() and path == path.resolve() and\n         not any(p.is_symlink() for p in (path, *path.parents)), \'canonical ordinary original input\')\n    return path\n\n\ndef identity(info):\n    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,\n            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n\n\n@contextlib.contextmanager\ndef exact_file(path, expected):\n    path = ordinary(path)\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)\n    try:\n        before = os.fstat(fd)\n        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and\n             before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o022 and\n             before.st_size == expected[\'bytes\'], \'exact ordinary held input extent/owner/mode\')\n        digest = hashlib.sha256(); size = 0\n        while True:\n            raw = os.read(fd, 1024**2)\n            if not raw:\n                break\n            size += len(raw); need(size <= expected[\'bytes\'], \'bounded original input\')\n            digest.update(raw)\n        need(dict(bytes=size, sha256=digest.hexdigest()) == expected and\n             identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), \'whole original input FD/path/hash\')\n        yield path\n        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), \'original input held through verification/load\')\n    finally:\n        os.close(fd)\n\n\ndef fresh_file(path, raw):\n    path = ordinary(path)\n    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)\n    with os.fdopen(fd, \'wb\') as stream:\n        os.fchmod(stream.fileno(), 0o600)\n        need(stream.write(raw) == len(raw), \'whole private trust file\')\n        stream.flush(); os.fsync(stream.fileno())\n\n\ndef public_keyring():\n    # The locked .gpg input is armored; GPG\'s legacy keyring uses binary packets.\n    raw = TRUST_DATA[\'archlinuxarm.gpg\']\n    need(pin(raw) == TRUST_PINS[\'archlinuxarm.gpg\'], \'exact upstream armored public key\')\n    lines = raw.decode(\'ascii\').splitlines()\n    need(lines[0] == \'-----BEGIN PGP PUBLIC KEY BLOCK-----\' and lines[1] == \'\' and\n         lines[-1] == \'-----END PGP PUBLIC KEY BLOCK-----\' and\n         lines[-2].startswith(\'=\') and len(lines[-2]) == 5, \'complete canonical upstream public armor\')\n    text = \'\'.join(lines[2:-2]); body = base64.b64decode(text, validate=True)\n    need(base64.b64encode(body).decode(\'ascii\') == text, \'canonical upstream public key packets\')\n    crc = 0xB704CE\n    for octet in body:\n        crc ^= octet << 16\n        for _ in range(8):\n            crc <<= 1\n            if crc & 0x1000000: crc ^= 0x1864CFB\n    need(base64.b64decode(lines[-2][1:], validate=True) == (crc & 0xFFFFFF).to_bytes(3, \'big\'), \'upstream public armor CRC\')\n    return body\n\n\ndef public_packets(raw):\n    # Only GnuPG\'s local tag12 trust/cache packets may vary; cryptographic\n    # packets stay byteexact to the original source-pinned upstream public key.\n    need(type(raw) is bytes and 0 < len(raw) <= 65536, \'bounded private public keyring\')\n    offset = 0; packets = []; local = 0\n    while offset < len(raw):\n        start = offset; header = raw[offset]; offset += 1\n        need(header & 0x80, \'complete OpenPGP public packet header\')\n        if header & 0x40:\n            tag = header & 0x3F; need(offset < len(raw), \'public packet length\')\n            length = raw[offset]; offset += 1\n            if 192 <= length <= 223:\n                need(offset < len(raw), \'two-octet public packet length\'); length = ((length - 192) << 8) + raw[offset] + 192; offset += 1\n            elif length == 255:\n                need(offset + 4 <= len(raw), \'four-octet public packet length\'); length = int.from_bytes(raw[offset:offset+4], \'big\'); offset += 4\n            else: need(length < 224, \'no partial public keyring packets\')\n        else:\n            tag = (header >> 2) & 15; kind = header & 3\n            need(kind != 3, \'no indeterminate public keyring packets\'); size = (1, 2, 4)[kind]\n            need(offset + size <= len(raw), \'old-format public packet length\'); length = int.from_bytes(raw[offset:offset+size], \'big\'); offset += size\n        need(offset + length <= len(raw), \'complete bounded public keyring packet\'); offset += length\n        if tag == 12:\n            local += 1; need(local <= 16 and length <= 4096, \'bounded GnuPG local trust/cache packets\')\n        else: packets.append(raw[start:offset])\n    return b\'\'.join(packets)\n\n\ndef trust_files():\n    need(set(TRUST_DATA) == set(TRUST_PINS) and all(pin(raw) == TRUST_PINS[name]\n         for name, raw in TRUST_DATA.items()), \'embedded exact original upstream public trust data\')\n    policy = dict(status=\'SOURCE_EXPLICIT_ORIGINAL_UPSTREAM_PUBLIC_TRUST_ONLY\', fingerprint=FINGERPRINT,\n                  upstream_keyring_commit=KEYRING_COMMIT, original_files=TRUST_PINS,\n                  trust_model=\'pgp\', trusted_key_source=\'EXPLICIT_UPSTREAM_MASTER_NOT_DYNAMIC_SIGNATURE_ISSUER\',\n                  secret_keys=False, candidate_TEST_keys=False, acceptance=False)\n    return {\'pubring.gpg\': public_keyring(),\n            \'archlinuxarm.gpg\': TRUST_DATA[\'archlinuxarm.gpg\'],\n            \'archlinuxarm-trusted\': TRUST_DATA[\'archlinuxarm-trusted\'],\n            \'archlinuxarm-revoked\': TRUST_DATA[\'archlinuxarm-revoked\'],\n            \'gpg.conf\': GPG_CONF, \'source-trust.json\': encoded(policy)}\n\n\ndef private_dir(path):\n    path = ordinary(path); info = path.lstat()\n    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and\n         stat.S_IMODE(info.st_mode) == 0o700, \'owned private0700 trust directory\')\n    return path\n\n\ndef prepare_home(work):\n    work = private_dir(work); home = work / \'original-upstream-gnupg\'\n    need(not os.path.lexists(home), \'fresh original upstream trust home; no overwrite/retry\')\n    home.mkdir(mode=0o700); home.chmod(0o700)\n    for name, raw in trust_files().items():\n        fresh_file(home / name, raw)\n    check_home(home)\n    return home\n\n\ndef check_home(home):\n    home = private_dir(home); expected = trust_files(); allowed = set(expected) | {\'trustdb.gpg\', \'pubring.gpg~\', \'random_seed\'}\n    need({p.name for p in home.iterdir()} <= allowed, \'public trust cache only; no secret keys/agents/keyboxd\')\n    for path in home.iterdir():\n        info = path.lstat()\n        need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1 and\n             info.st_uid == os.geteuid() and not info.st_mode & 0o077 and 0 <= info.st_size <= 1024**2,\n             \'ordinary bounded private public-trust cache only\')\n    for name, raw in expected.items():\n        if name == \'pubring.gpg\':\n            path = home / name; fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)\n            try:\n                before = os.fstat(fd); need(0 < before.st_size <= 65536, \'bounded actual public keyring\')\n                value = os.read(fd, before.st_size + 1)\n                need(len(value) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), \'stable entire public keyring FD/path\')\n                need(public_packets(value) == public_keyring(), \'all original public cryptographic key packets byteexact\')\n            finally: os.close(fd)\n        else:\n            with exact_file(home / name, pin(raw)): pass\n    return home\n\n\ndef current_time(now=None):\n    value = time.time() if now is None else now\n    need(type(value) in (int, float) and math.isfinite(value) and\n         SIGNATURE_CREATED <= value <= 2**53, \'current clock must follow original signature; PID1 trusted-current handoff required\')\n    return value\n\n\ndef guest_clock(selection):\n    clock = selection.get(\'trusted_clock\')\n    fields = {\'schema\', \'status\', \'source_sha\', \'ref\', \'run_id\', \'nonce\', \'native_epoch_ns\',\n              \'native_monotonic_ns\', \'guest_before_ns\', \'guest_after_ns\', \'guest_monotonic_ns\', \'clock_set\'}\n    need(type(clock) is dict and set(clock) == fields and type(clock[\'schema\']) is int and\n         clock[\'schema\'] == 1 and clock[\'status\'] == \'PASS_GUEST_REALTIME_HANDOFF\' and\n         clock[\'source_sha\'] == selection.get(\'source_sha\') and clock[\'nonce\'] == selection.get(\'nonce\') and\n         type(clock[\'ref\']) is str and re.fullmatch(\'codex/[a-z0-9-]+\', clock[\'ref\']) and type(clock[\'run_id\']) is int and\n         0 < clock[\'run_id\'] < 2**63 and type(clock[\'clock_set\']) is bool,\n         \'exact PID1-established original-source current-time receipt\')\n    for name in (\'native_epoch_ns\', \'native_monotonic_ns\', \'guest_before_ns\', \'guest_after_ns\', \'guest_monotonic_ns\'):\n        need(type(clock[name]) is int and 0 <= clock[name] < 2**64, \'typed bounded trusted-clock nanoseconds\')\n    now = time.time_ns()\n    need(clock[\'native_epoch_ns\'] >= SIGNATURE_CREATED * 10**9 and\n         clock[\'native_epoch_ns\'] <= clock[\'guest_after_ns\'] <= now and\n         now - clock[\'guest_after_ns\'] <= 10801 * 10**9 and\n         clock[\'guest_after_ns\'] - clock[\'native_epoch_ns\'] <= 10801 * 10**9,\n         \'fresh inherited real current guest clock; never signature-time substitution\')\n    return clock\n\n\ndef parse_status(stdout, returncode=0, now=None):\n    now = current_time(now)\n    need(type(returncode) is int and returncode == 0 and type(stdout) is bytes and\n         0 < len(stdout) <= STATUS_CAP, \'bounded successful original signature status\')\n    text = stdout.decode(\'utf-8\', \'strict\'); rows = []\n    allowed = {\'NEWSIG\', \'KEY_CONSIDERED\', \'SIG_ID\', \'GOODSIG\', \'VALIDSIG\',\n               \'TRUST_FULLY\', \'TRUST_ULTIMATE\', \'VERIFICATION_COMPLIANCE_MODE\'}\n    for line in text.splitlines():\n        need(line.startswith(\'[GNUPG:] \') and len(line.encode()) <= 4096, \'closed GPG status-fd records\')\n        fields = line[9:].split(); need(fields and fields[0] in allowed, \'unknown/bad/expired/revoked/time-invalid signature status\')\n        rows.append(fields)\n    need(0 < len(rows) <= 32, \'bounded GPG status count\')\n    good = [row for row in rows if row[0] == \'GOODSIG\']; valid = [row for row in rows if row[0] == \'VALIDSIG\']\n    trusted = [row for row in rows if row[0] in (\'TRUST_FULLY\', \'TRUST_ULTIMATE\')]\n    need(len(good) == len(valid) == len(trusted) == 1 and len(good[0]) >= 3 and\n         good[0][1] == FINGERPRINT[-16:], \'one exact original signer and full trust\')\n    row = valid[0]\n    need(len(row) == 11 and row[1] == row[-1] == FINGERPRINT and row[2] == \'2026-05-17\' and\n         row[3:] == [str(SIGNATURE_CREATED), \'0\', \'4\', \'0\', \'1\', \'8\', \'00\', FINGERPRINT],\n         \'one exact pinned original signature creation/expiry/algorithm/fingerprint\')\n    need(SIGNATURE_CREATED <= now and trusted[0][1:] in ([\'0\', \'pgp\'], [\'0\', \'classic\']), \'ordinary current-time PGP full/ultimate trust\')\n    for row in rows:\n        if row[0] == \'KEY_CONSIDERED\':\n            need(len(row) == 3 and row[1] == FINGERPRINT and row[2] in (\'0\', \'1\'), \'only original upstream considered key\')\n        elif row[0] == \'SIG_ID\':\n            need(len(row) == 4 and row[2:] == [\'2026-05-17\', str(SIGNATURE_CREATED)], \'same original signature timestamp\')\n    return dict(status=\'PASS_REQUIRED_ORIGINAL_UPSTREAM_SIGNATURE\', signer=FINGERPRINT,\n                signature_created=SIGNATURE_CREATED, signature_expires=0,\n                trust=trusted[0][0], status_pin=pin(stdout), acceptance=False)\n\n\ndef call(run, argv):\n    need(callable(run), \'existing bounded source-owned runner required\')\n    result = run(argv, seconds=30, cap=STATUS_CAP)\n    need(type(result) in (tuple, list) and len(result) == 3, \'bounded runner returns exit/stdout/stderr\')\n    code, out, err = result\n    need(type(code) is int and type(out) is type(err) is bytes and len(out) + len(err) <= STATUS_CAP,\n         \'bounded complete GPG streams\')\n    return code, out, err\n\n\ndef verify_original(archive, signature, home, run=None, now=None):\n    archive, signature = ordinary(archive), ordinary(signature); home = check_home(home)\n    need(archive.name == PACKAGE and signature == archive.with_name(PACKAGE + \'.sig\'), \'exact adjacent original detached signature\')\n    current_time(now)\n    with exact_file(archive, PACKAGE_PIN), exact_file(signature, SIGNATURE_PIN):\n        argv = [\'/usr/bin/gpg\', \'--batch\', \'--no-autostart\', \'--homedir\', str(home),\n                \'--no-auto-key-retrieve\', \'--auto-key-locate\', \'clear\', \'--disable-dirmngr\',\n                \'--status-fd\', \'1\', \'--verify\', str(signature), str(archive)]\n        code, stdout, stderr = call(run, argv)\n        checked = parse_status(stdout, code, now)\n        check_home(home)\n    return dict(checked, archive=PACKAGE_PIN, signature=SIGNATURE_PIN, stderr_pin=pin(stderr))\n\n\ndef bind_validation(alpm):\n    function = getattr(alpm, \'alpm_pkg_get_validation\', None)\n    if function is None:\n        function = alpm.lib.alpm_pkg_get_validation\n        function.restype = ctypes.c_int; function.argtypes = (ctypes.c_void_p,)\n        alpm.alpm_pkg_get_validation = function\n    return function\n\n\ndef load_signed_original(alpm, archive, signature, home, run=None, now=None):\n    archive, signature = ordinary(archive), ordinary(signature); home = check_home(home)\n    with exact_file(archive, PACKAGE_PIN), exact_file(signature, SIGNATURE_PIN):\n        verify_original(archive, signature, home, run=run, now=now)\n        alpm.ok(alpm.alpm_option_set_gpgdir(alpm.handle, os.fsencode(home)), \'set exact private upstream gpgdir\')\n        loaded = ctypes.c_void_p()\n        try:\n            alpm.ok(alpm.alpm_pkg_load(alpm.handle, os.fsencode(archive), 1, 1, ctypes.byref(loaded)), \'required original upstream signed package load\')\n            need(loaded.value is not None and bind_validation(alpm)(loaded) == 8, \'actual loaded original package PGP validation bit only\')\n            check_home(home)\n        except BaseException:\n            if loaded.value is not None:\n                free = alpm.lib.alpm_pkg_free\n                free.restype = ctypes.c_int; free.argtypes = (ctypes.c_void_p,)\n                free(loaded)\n            raise\n    return loaded\n\n\ndef wrap_alpm(api, index, selection, work, run=None, diagnostic_root=None):\n    """Return an API view; only exact original-glibc loads become required-signed."""\n    need(type(api) is dict and type(index) is dict and type(selection) is dict, \'explicit lifecycle input and actual selection\')\n    work = private_dir(work); held = index.get(\'held\')\n    need(type(held) is dict and set(held) == {\'path\', \'bytes\', \'sha256\'} and\n         {k: held[k] for k in (\'bytes\', \'sha256\')} == PACKAGE_PIN and type(held[\'path\']) is str and\n         not held[\'path\'].startswith(\'/\') and all(p not in (\'\', \'.\', \'..\') for p in held[\'path\'].split(\'/\')) and\n         Path(held[\'path\']).name == PACKAGE, \'exact source-bound held original input\')\n    archive = ordinary(Path(\'/inputs\') / held[\'path\']); signature = archive.with_name(PACKAGE + \'.sig\')\n    need(type(selection.get(\'source_sha\')) is str and re.fullmatch(\'[a-f0-9]{40}\', selection[\'source_sha\']) and\n         type(selection.get(\'nonce\')) is str and re.fullmatch(\'[a-f0-9]{32}\', selection[\'nonce\']), \'actual original source/nonce selection\')\n    candidates = index.get(\'archives\')\n    need(type(candidates) is dict and set(candidates) == {\'a\', \'b\'}, \'separate source-bound unsigned candidate TEST archives\')\n    candidate_paths = {}\n    for row in candidates.values():\n        need(type(row) is dict and set(row) == {\'path\', \'bytes\', \'sha256\'} and\n             type(row[\'bytes\']) is int and 0 < row[\'bytes\'] <= 256 * 1024**2 and\n             type(row[\'sha256\']) is str and re.fullmatch(\'[a-f0-9]{64}\', row[\'sha256\']) and\n             type(row.get(\'path\')) is str and not row[\'path\'].startswith(\'/\') and\n             all(p not in (\'\', \'.\', \'..\') for p in row[\'path\'].split(\'/\')), \'ordinary separate candidate TEST path\')\n        path = ordinary(Path(\'/inputs\') / row[\'path\'])\n        need(path != archive and path.name != PACKAGE, \'original upstream archive is never an unsigned candidate\')\n        candidate_paths[path] = {k: row[k] for k in (\'bytes\', \'sha256\')}\n    need(candidates[\'a\'][\'bytes\'] == candidates[\'b\'][\'bytes\'] and\n         candidates[\'a\'][\'sha256\'] == candidates[\'b\'][\'sha256\'], \'held byte-identical candidate TEST pair\')\n    guest_clock(selection); current_time()\n    existing = work / \'original-upstream-gnupg\'\n    home = check_home(existing) if os.path.lexists(existing) else prepare_home(work)\n    original = api[\'roots\'].Alpm\n    diagnostic = dict(case=None, events=[])\n    def record(event):\n        case = diagnostic[\'case\']\n        if diagnostic_root is None or case not in (\'pristine\', \'modified\'): return\n        root = private_dir(Path(diagnostic_root)); path = root / (case + \'-original-signature.log\')\n        diagnostic[\'events\'].append(event)\n        need(len(diagnostic[\'events\']) <= 12, \'bounded original signature diagnostic event count\')\n        value = dict(schema=1,status=\'ORIGINAL_SIGNATURE_DIAGNOSTIC_DATA_ONLY\',case=case,\n                     source_sha=selection[\'source_sha\'],nonce=selection[\'nonce\'],clock=selection[\'trusted_clock\'],\n                     events=diagnostic[\'events\'],acceptance=False,Root_acceptance=None)\n        raw = encoded(value); need(len(raw) <= 65536, \'bounded original signature diagnostics\')\n        flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC\n        flags |= os.O_EXCL | os.O_CREAT if not os.path.lexists(path) else 0\n        fd = os.open(path, flags, 0o600)\n        try:\n            info = os.fstat(fd)\n            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and\n                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536, \'owned fixed signature diagnostic file\')\n            os.ftruncate(fd, 0); need(os.write(fd, raw) == len(raw), \'whole signature diagnostic write\'); os.fsync(fd)\n        finally: os.close(fd)\n    if run is None:\n        def run(argv, seconds=30, cap=STATUS_CAP):\n            row, out, err, error = api[\'runtime\'].run_command(argv, work,\n                dict(PATH=\'/usr/bin:/bin\', LANG=\'C\', LC_ALL=\'C\', HOME=str(home), TMPDIR=str(work), PYTHONDONTWRITEBYTECODE=\'1\'), seconds, cap)\n            need(error is None and type(row) is dict and row.get(\'group_absence_verified\') is True and\n                 type(row.get(\'exit_code\')) is int and type(row.get(\'seconds\')) in (int, float) and\n                 0 <= row[\'seconds\'] < seconds, \'original supervised GPG exit/retirement/time bounds\')\n            def stream(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),prefix_base64=base64.b64encode(raw[:4096]).decode(\'ascii\'),truncated=len(raw)>4096)\n            record(dict(phase=\'BOUNDED_OFFLINE_GPG_VERIFY\',exit=row[\'exit_code\'],group_absence_verified=True,stdout=stream(out),stderr=stream(err)))\n            return row[\'exit_code\'], out, err\n\n    class SignedOriginal:\n        def __init__(self, instance):\n            object.__setattr__(self, \'_instance\', instance)\n        def __getattr__(self, name):\n            return getattr(self._instance, name)\n        def __setattr__(self, name, value):\n            setattr(self._instance, name, value)\n        def alpm_pkg_load(self, handle, path, full, level, pointer):\n            name = Path(os.fsdecode(path))\n            if name != archive:\n                need(name in candidate_paths and handle == self._instance.handle and type(full) is int and full == 1 and type(level) is int and level == 0,\n                     \'only exact separate unsigned candidate TEST policy remains unchanged\')\n                with exact_file(name, candidate_paths[name]):\n                    return self._instance.alpm_pkg_load(handle, path, full, level, pointer)\n            need(handle == self._instance.handle and type(full) is int and full == 1 and type(level) is int and level == 0, \'exact existing original load call before signed specialization\')\n            guest_clock(selection)\n            try: loaded = load_signed_original(self._instance, archive, signature, home, run=run)\n            except BaseException as error:\n                record(dict(phase=\'SIGNED_ORIGINAL_LOAD_REFUSED\',error_type=type(error).__name__,error=str(error)[:512]));raise\n            record(dict(phase=\'SIGNED_ORIGINAL_LOAD_PGP_VALIDATION\',required_siglevel=1,actual_validation=8))\n            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = loaded\n            return 0\n\n    def factory(*args, **kwargs):\n        root = Path(args[0]) if args else Path(kwargs.get(\'root\', \'/\'))\n        if root in (Path(\'/work/pristine/root\'), Path(\'/work/modified/root\')):\n            case = root.parent.name\n            if diagnostic[\'case\'] != case: diagnostic.update(case=case,events=[])\n        return SignedOriginal(original(*args, **kwargs))\n\n    roots = types.SimpleNamespace(**dict(vars(api[\'roots\']), Alpm=factory))\n    return dict(api, roots=roots)\n'
_ORIGINAL_SIG_PIN={'bytes': 26986, 'sha256': 'afd21a0e89d73df5efc0a2218991097351d9f6e195653b09f96de9ea3bca03f3'}
import types as _original_signature_types
_ORIGINAL_SIG=_original_signature_types.ModuleType('<SOURCE_OWNED__ORIGINAL_SIG>')
if {'bytes':len(_ORIGINAL_SIG_BODY),'sha256':__import__('hashlib').sha256(_ORIGINAL_SIG_BODY).hexdigest()}!=_ORIGINAL_SIG_PIN:raise ValueError('whole original signature helper')
exec(compile(_ORIGINAL_SIG_BODY,'<SOURCE_OWNED__ORIGINAL_SIG>','exec'),vars(_ORIGINAL_SIG))

# ORIGINAL_SIGNATURE__ORIGINAL_CLOCK
_ORIGINAL_CLOCK_BODY=b'# SPDX-License-Identifier: MIT\n"""Same-run host realtime handoff; only dedicated guest PID1 may set a clock."""\nimport base64,json,os,re,stat,time\nfrom pathlib import Path\nMARKER=\'caa_gnu_original_clock=\'\nMIN_EPOCH_NS=1779031879*10**9\nMAX_STARTUP_NS=1200*10**9\nFIELDS={\'schema\',\'source_sha\',\'ref\',\'run_id\',\'nonce\',\'native_epoch_ns\',\'native_monotonic_ns\'}\ndef need(ok,why):\n if not ok:raise ValueError(why)\ndef encode(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False).encode(\'ascii\')\ndef pairs(rows):\n v={}\n for k,x in rows:need(k not in v,\'duplicate original-clock field\');v[k]=x\n return v\ndef decode(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,\'finite original clock\'))\ndef identity(v):\n need(type(v)is dict and set(v)==FIELDS and type(v[\'schema\'])is int and v[\'schema\']==1,\'complete native clock handoff\')\n need(type(v[\'source_sha\'])is str and re.fullmatch(\'[a-f0-9]{40}\',v[\'source_sha\'])and type(v[\'ref\'])is str and re.fullmatch(\'codex/[a-z0-9-]+\',v[\'ref\'])and type(v[\'run_id\'])is int and 0<v[\'run_id\']<2**63 and type(v[\'nonce\'])is str and re.fullmatch(\'[a-f0-9]{32}\',v[\'nonce\']),\'same-run clock selectors\')\n need(type(v[\'native_epoch_ns\'])is int and MIN_EPOCH_NS<=v[\'native_epoch_ns\']<2**63 and type(v[\'native_monotonic_ns\'])is int and 0<v[\'native_monotonic_ns\']<2**63,\'bounded fresh native clock sample\')\n return v\n\ndef host_argv(argv,volume):\n """Called immediately before the original supervised QEMU launch, never SOURCE."""\n need(type(argv)is list and argv and argv[0]==\'/usr/bin/qemu-system-aarch64\'and argv.count(\'-append\')==1 and all(type(x)is str for x in argv),\'one unchanged native QEMU cmdline\')\n path=Path(volume).parent.parent/\'selection.json\';need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),\'same native owner selection\')\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)\n try:\n  before=os.fstat(fd);stat_identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns)\n  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and 0<before.st_size<=65536,\'ordinary bounded native selection\')\n  raw=bytearray()\n  while len(raw)<=before.st_size:\n   part=os.read(fd,min(65536,before.st_size-len(raw)+1))\n   if not part:break\n   raw.extend(part)\n  need(len(raw)==before.st_size and stat_identity(before)==stat_identity(os.fstat(fd))==stat_identity(path.lstat()),\'native selection stable FD/path through clock sample\')\n  selected=decode(bytes(raw))\n finally:os.close(fd)\n source=os.environ.get(\'SOURCE_SHA\');need(source==os.environ.get(\'WORKFLOW_SHA\')==selected[\'source_sha\'],\'native source/workflow clock identity\')\n run=os.environ.get(\'GITHUB_RUN_ID\',\'\');need(run.isdecimal(),\'native genuine run clock identity\')\n v=identity(dict(schema=1,source_sha=source,ref=os.environ.get(\'GITHUB_REF_NAME\'),run_id=int(run),nonce=selected[\'nonce\'],native_epoch_ns=time.time_ns(),native_monotonic_ns=time.monotonic_ns()))\n token=base64.urlsafe_b64encode(encode(v)).decode(\'ascii\');need(len(token)<=1024,\'bounded native clock kernel token\')\n out=list(argv);index=out.index(\'-append\')+1;need(index<len(out)and not any(s.startswith(MARKER)for s in out[index].split()),\'native clock operand cannot be preselected\');out[index]+=\' \'+MARKER+token\n need(len(out[index].encode())<=65536,\'bounded full native clock cmdline\')\n return out\n\ndef guest_handoff(value,selected,cmdline=None):\n """Validate Source-selected nonce/run before setting this guest\'s REALTIME only."""\n need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine==\'aarch64\'and os.sysconf(\'SC_PAGE_SIZE\')==16384,\'dedicated real16K aarch64 root PID1 only; never host or worker clock\')\n line=Path(\'/proc/cmdline\').read_text()if cmdline is None else cmdline\n need(type(line)is str and len(line.encode())<=65536 and line.split().count(\'caa_gnu_immutable_runtime=1\')==1,\'one actual immutable guest clock purpose\')\n tokens=[s[len(MARKER):]for s in line.split()if s.startswith(MARKER)];need(len(tokens)==1 and len(tokens[0])<=1024,\'one same-run native clock token\')\n try:raw=base64.b64decode(tokens[0],altchars=b\'-_\',validate=True)\n except ValueError:raise ValueError(\'canonical native clock base64\')from None\n need(base64.urlsafe_b64encode(raw).decode()==tokens[0],\'canonical native clock encoding\');v=identity(decode(raw));need(encode(v)==raw,\'canonical source-owned native clock record\')\n need(v[\'source_sha\']==value[\'actual_source\']==selected[\'source_sha\']and v[\'ref\']==value[\'actual_ref\']and str(v[\'run_id\'])==str(value[\'actual_run\'])and v[\'nonce\']==selected[\'nonce\']==value[\'broker\'][\'nonce\']==value[\'bootstrap\'][\'nonce\'],\'clock same actual source/ref/run/fresh original nonce\')\n monotonic=time.monotonic_ns();need(0<monotonic<=MAX_STARTUP_NS,\'guest clock handoff before original1200-second cold-start window\')\n before=time.time_ns();target=v[\'native_epoch_ns\']+monotonic\n need(before<=target+MAX_STARTUP_NS,\'guest future clock is refused, never rewound to hide expiry\')\n changed=before<target\n if changed:time.clock_settime_ns(time.CLOCK_REALTIME,target)\n after=time.time_ns();need(target<=after<=target+MAX_STARTUP_NS and after>=before,\'guest realtime readback and forward-only handoff\')\n return dict(schema=1,status=\'PASS_GUEST_REALTIME_HANDOFF\',source_sha=v[\'source_sha\'],ref=v[\'ref\'],run_id=v[\'run_id\'],nonce=v[\'nonce\'],native_epoch_ns=v[\'native_epoch_ns\'],native_monotonic_ns=v[\'native_monotonic_ns\'],guest_before_ns=before,guest_after_ns=after,guest_monotonic_ns=monotonic,clock_set=changed)\n\ndef pack_receipt(v):\n raw=encode(v);need(len(raw)<=2048,\'bounded PID1 clock receipt\');return base64.urlsafe_b64encode(raw).decode(\'ascii\')\ndef unpack_receipt(text):\n need(type(text)is str and 0<len(text)<=4096,\'explicit PID1 clock environment handoff\')\n raw=base64.b64decode(text,altchars=b\'-_\',validate=True);need(base64.urlsafe_b64encode(raw).decode()==text and len(raw)<=2048,\'canonical bounded PID1 clock receipt\');v=decode(raw);need(encode(v)==raw,\'canonical PID1 clock receipt\');return v\n'
_ORIGINAL_CLOCK_PIN={'bytes': 6095, 'sha256': '83ca8d7d132ea7e84fc9dd427628cefa74ddde51727f7564a1923cc6380bc75a'}
import types as _original_signature_types
_ORIGINAL_CLOCK=_original_signature_types.ModuleType('<SOURCE_OWNED__ORIGINAL_CLOCK>')
if {'bytes':len(_ORIGINAL_CLOCK_BODY),'sha256':__import__('hashlib').sha256(_ORIGINAL_CLOCK_BODY).hexdigest()}!=_ORIGINAL_CLOCK_PIN:raise ValueError('whole original signature helper')
exec(compile(_ORIGINAL_CLOCK_BODY,'<SOURCE_OWNED__ORIGINAL_CLOCK>','exec'),vars(_ORIGINAL_CLOCK))

_ORIGINAL_TRUST_CONTEXT=None
def install_original_signature_context(text,nonce):
 global _ORIGINAL_TRUST_CONTEXT
 receipt=_ORIGINAL_CLOCK.unpack_receipt(text)
 selection=dict(nonce=nonce,source_sha=receipt['source_sha'],trusted_clock=receipt)
 _ORIGINAL_SIG.guest_clock(selection);_ORIGINAL_TRUST_CONTEXT=selection
_ORIGINAL_SIGNATURE_PARENT_BIND=bind
def bind(api,channel,guest):
 value=_ORIGINAL_SIGNATURE_PARENT_BIND(api,channel,guest)
 P.need(_ORIGINAL_TRUST_CONTEXT is not None,'PID1 current clock required before lifecycle helpers')
 selection=guest.C.decode(guest.C.read('/debian-maintained-installed16k/selection.json'))
 P.need(selection['nonce']==_ORIGINAL_TRUST_CONTEXT['nonce']and selection['source_sha']==_ORIGINAL_TRUST_CONTEXT['source_sha'],'same actual original signature context')
 raw=guest.C.read('/inputs/lifecycle-input.json',2*1024**2)
 P.need(guest.C.sha(raw)==selection['input_index_sha256'],'same signed-restore input index')
 index=__import__('json').loads(raw);work=Path('/tmp/original-signature-work')
 if not work.exists():work.mkdir(mode=0o700)
 return _ORIGINAL_SIG.wrap_alpm(value,index,_ORIGINAL_TRUST_CONTEXT,work,diagnostic_root=Path('/out'))
