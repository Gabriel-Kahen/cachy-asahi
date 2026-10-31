# SPDX-License-Identifier: MIT
"""Private Apps bindings of the exact proven descriptor statx/fdinfo query."""
import functools,hashlib,json,os,re,time,types
from contextlib import contextmanager

PINS={
 'scripts/update/aux_checkpoint.py':(18456,'d51179ca24c981bafd817d7db082c0ceb3b2f5deb922004bfe97d1e2007edda7'),
 'scripts/update/measure_copy.py':(25734,'e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b'),
 'scripts/ci/expanded600-installer-vm/observer600.py':(2784,'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607'),
 'scripts/update/full_root.py':(35970,'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'),
 'scripts/update/aux_copy.py':(3736,'bff93c029e21f9fce0868c80566396984443c8d3438264fac8a91c985175f05b'),
 'scripts/apps/file_capabilities.py':(13562,'498a3beec0327b9335dcd6d80ed5919fa2edebebd3284e9ee8b97770328e26a2'),
 'scripts/apps/full574_copy.py':(7799,'33d49316c28dee344e78e17d7e7ffa409c9d7ad09bb48a82651f7d44f1cb61a0')}
MAX_PHASES=96;_phases=0

def emit(stage,event,error=None):
    global _phases
    if _phases>=MAX_PHASES:return
    _phases+=1
    value=dict(schema_version=1,seq=_phases,stage=stage,event=event,monotonic_ns=time.monotonic_ns())
    if error is not None:
        value['error_type']=type(error).__name__
        reason=str(error).partition(':')[0]
        value['error_reason']=reason if type(error) is ValueError and (reason=='root observation deadline' or re.fullmatch(r'aux-checkpoint-[a-z0-9-]{1,96}',reason)) else 'OTHER_REDACTED'
    if _phases==MAX_PHASES:value.update(stage='diagnostic-limit',event='FURTHER_PHASE_RECORDS_OMITTED')
    raw=('APPS574_PHASE '+json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>512:raise ValueError('Apps phase record bound')
    if os.write(2,raw)!=len(raw):raise ValueError('Apps phase record short write')

def traced(stage):
    def decorate(function):
        @functools.wraps(function)
        def call(*args,**kwargs):
            emit(stage,'BEGIN')
            try:value=function(*args,**kwargs)
            except BaseException as error:emit(stage,'FAIL',error);raise
            emit(stage,'END');return value
        return call
    return decorate

def clone(function,namespace):
    value=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
    value.__kwdefaults__=function.__kwdefaults__;return value

def bind(root,roots,caps,copy_scope,aux_copy,read):
    """No shared-module/global mutation, query memoization or traversal shortcut."""
    raw={}
    for name,(size,pin) in PINS.items():
        data=read(root/name)
        if len(data)!=size or hashlib.sha256(data).hexdigest()!=pin:raise ValueError('Apps statx exact source pin differs: '+name)
        raw[name]=data
    helper=types.ModuleType('_apps574_proven_mount_query')
    exec(compile(raw['scripts/ci/expanded600-installer-vm/observer600.py'],str(root/'scripts/ci/expanded600-installer-vm/observer600.py'),'exec'),helper.__dict__)
    facade=types.SimpleNamespace(**vars(roots))
    facade._mount_id=helper._mount600(roots._mount_id)
    facade.observe=traced('tree-observe')(lambda path,**kwargs:helper._observer600(roots,path,**kwargs))
    # Auxiliary reads previously retained the slow fdinfo query through two
    # separate namespaces. Clone the exact Reader/descriptor bodies, never
    # their observations, so every original live check and hash runs afresh.
    aux=aux_copy.aux
    walk_space=dict(vars(aux.copy),roots=facade)
    for name in ('_parent','_root_check','_source_alias'):
        original=getattr(aux.copy,name)
        walk_space[name]=contextmanager(clone(original.__wrapped__,walk_space)) if name=='_parent' else clone(original,walk_space)
    walk_facade=types.SimpleNamespace(**walk_space)
    aux_space=dict(vars(aux),roots=facade,copy=walk_facade)
    methods={name:clone(value,aux_space) if isinstance(value,types.FunctionType) else value
             for name,value in vars(aux.Reader).items() if name not in ('__dict__','__weakref__')}
    aux_space['Reader']=type('_Apps574AuxReader',(),methods)
    for name in ('checkpoint','load_comparator'):
        aux_space[name]=clone(getattr(aux,name),aux_space)
    aux_facade=types.SimpleNamespace(**aux_space)
    # These original functions share one private dictionary so restore's full
    # before/mutate/after scans all use the fresh descriptor query. All graph,
    # attribute, hash, identity and hardlink functions remain the originals.
    cap_space=dict(vars(caps),_mount=helper._mount600(caps._mount))
    for name in ('_scan','observe','restore'):cap_space[name]=clone(getattr(caps,name),cap_space)
    cap_space['_scan']=traced('capability-scan')(cap_space['_scan'])
    cap_facade=types.SimpleNamespace(**cap_space)
    # The exact copier binding creates its existing link/aux facade from this
    # private roots view. Its original source pin and algorithms are unchanged.
    copy_space=dict(vars(aux_copy),roots=facade,aux=aux_facade)
    copy_facade=types.SimpleNamespace(**vars(aux_copy))
    copy_facade._copy_binding=clone(aux_copy._copy_binding,copy_space)
    proof_space=dict(vars(copy_scope),roots=facade,aux_copy=copy_facade)
    proof_facade=types.SimpleNamespace(**vars(copy_scope))
    proof_facade.copy_data=traced('copy-data')(clone(copy_scope.copy_data,proof_space))
    receipt=dict(scope='PRIVATE_APPS_DESCRIPTOR_QUERY_BINDINGS_ONLY',sources={n:dict(bytes=s,sha256=p) for n,(s,p) in PINS.items()},query='EXACT_OBSERVER600_STATX_MNT_ID_WITH_ORIGINAL_FDINFO_FALLBACK',identity_policy='FRESH_EVERY_DESCRIPTOR_FIRST_RESULT_CROSSCHECK_NO_MOUNT_ID_CACHE',auxiliary='EXACT_READER_AND_DESCRIPTOR_BODIES_PRIVATE_FRESH_QUERY_ONLY',budgets='UNCHANGED',performance='NOT_MEASURED')
    return types.SimpleNamespace(roots=facade,caps=cap_facade,copy_scope=proof_facade,aux=aux_facade,receipt=receipt)
