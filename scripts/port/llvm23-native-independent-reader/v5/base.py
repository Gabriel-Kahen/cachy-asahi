# SPDX-License-Identifier: MIT
"""Whole-pinned passive Reader4 bridge; never imports Source or artifact code."""
import hashlib,importlib.util,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PINS={'reader.py':'c4c738fd3260990babe0a814b597c1930c203aeaf7994b3d70d9738bf00431bf','base.py':'d879c2716c1035d85ce601eb1d0c469fdbf7ce9d4d20881d1e6785d02c75fb65','pins.json':'7c45abc5ef57898cdd725c55cc1d4e39df1b59f480d131331e0b4114a4f6aa43'}
_held={}
for name,sha in PINS.items():
 p=HERE.parent/'v4'/name
 if p.is_symlink():raise ValueError('held Reader4 alias')
 body=p.read_bytes()
 if hashlib.sha256(body).hexdigest()!=sha:raise ValueError('whole held Reader4 dependency '+name)
 _held[name]=body
def compiled(name,path,body,additions=None):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 if additions:module.__dict__.update(additions)
 exec(compile(body,str(path),'exec'),module.__dict__);return module
_base4=compiled('llvm5_held_base4',HERE.parent/'v4/base.py',_held['base.py'])
_loader=b"spec=importlib.util.spec_from_file_location('llvm_v4_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);v=B.v"
_reader4,_wiring=_base4.projected(_held['reader.py'],[(_loader,b'B=__held_base;v=B.v')],'trusted base wiring')
old=compiled('llvm5_held_reader4',HERE.parent/'v4/reader.py',_reader4,{'__held_base':_base4})
# Each inherited function resolves to a separate new passive global namespace.
v=types.ModuleType('llvm5_cloned_passive_predicates');v.__dict__.update(old.v.__dict__)
for name,value in list(v.__dict__.items()):
 if isinstance(value,types.FunctionType)and value.__globals__ is old.v.__dict__:
  clone=types.FunctionType(value.__code__,v.__dict__,value.__name__,value.__defaults__,value.__closure__);clone.__kwdefaults__=value.__kwdefaults__;v.__dict__[name]=clone
parent_pins=old.v.decode(_held['pins.json'])
projection_proof=dict(trusted_closure=PINS,trusted_wiring=_wiring,Source_or_artifact_code_imports=False,inherited_actual_tuple_projection=False,cloned_passive_globals=True)


def install(specification,namespace):
    """Only literal trusted Reader rewiring, with exact byte inverse proofs."""
    command_raw=old.B.function_bytes(old.B._closure['v2/reader.py'],'commands')
    commands,proof=old.B.projected(command_raw,[
        (b"row = load(data/(name+'.json'));natural(row['lifecycle'])",b"row = load(data/receipt_names[name]);natural(row['lifecycle'])"),
        (b"load(data/(name+'.json'))['argv']",b"load(data/receipt_names[name])['argv']"),
        (b"data/'tools.json'",b"data/fact_names['tools']"),
        (b"data/'tool-owners.log'",b"data/log_names['tool-owners']"),
        (b"safe_name(row['log']) == name+'.log'",b"safe_name(row['log']) == log_names[name]"),
    ],'command receipts')
    v.receipt_names=dict(specification['command_receipts']);v.fact_names=dict(specification['facts']);v.log_names=dict(specification['command_logs']);v.verified_namespace=namespace
    exec(compile(commands,'<held-command-filenames-only>','exec'),v.__dict__)
    replay_raw=old.B.function_bytes(old.B._closure['v2/reader.py'],'replay')
    replay,replay_proof=old.B.projected(replay_raw,[(b"observed = load(data/'runtime.json');runtime(observed)",b"verified_namespace(data,result);observed = load(data/fact_names['runtime']);runtime(observed)")],'runtime facts')
    exec(compile(replay,'<held-runtime-facts-filename-only>','exec'),v.__dict__)
    if v.replay.__globals__ is not v.__dict__ or v.commands.__globals__ is not v.__dict__:raise ValueError('cloned replay globals must include the new strict command guard')
    return dict(commands=proof,replay=replay_proof,actual_tuple_projection=False)
