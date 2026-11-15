# SPDX-License-Identifier: MIT
"""Exact v5 passive ancestors and reversible Source/generator/name projections."""
import ast,hashlib,importlib.util,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;V5=HERE.parents[3]/'scripts/port/perl5423-xs-consumer/native_adapter/independent_reader/v5'
PINS={'reader.py': 'af07f6cfbbc192821818c9ed7f33db320e3ea7a929ae67ef604422ea969703d9', 'base.py': 'a85e90180c4cc92eba4e44382252ac06a54d8f55171583709a6d45c21788b231', 'adapters.py': '989107860241f03d344c87e8cd4bbb2fb893f669d78da24eced4b93d360411c9', 'producer.py': 'b97fa01c240ddec838334c585543908f904e5ccf7305d1730e3d17207e69e50c'}
def raw5(name):
 p=V5/name
 if p.is_symlink()or not p.is_file()or p.stat().st_size>128*1024:raise ValueError('ordinary fixed v5 passive dependency')
 raw=p.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=PINS[name]:raise ValueError('whole frozen v5 passive dependency changed')
 return raw
def parent_module(name):
 body=raw5(name+'.py');spec=importlib.util.spec_from_file_location('xs_v6_frozen_v5_'+name,V5/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(body,str(V5/(name+'.py')),'exec'),m.__dict__);return m
parent=parent_module('reader');ancestor=parent.B;d=parent.d;previous=ancestor.previous
raw=ancestor.raw;load=ancestor.load;substitute=ancestor.substitute;source_projection=ancestor.source_projection;daemon_classifier=ancestor.daemon_classifier;compiler=ancestor.compiler

def source5(leaves,b):
 body=raw5('reader.py');nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='source'];d.need(len(nodes)==1,'one frozen v5 Source predicate');text=ast.get_source_segment(body.decode(),nodes[0]).encode()
 projected=substitute(text,[(b"raw=d.read(root,'source-map.json',d.MIB)",b"raw=root['source-map.json'][0]"),(b'names=d.inventory(root,316,96*d.MIB)',b'names=set(root)'),(b'body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode)',b'body,mode=root[name]')]);ns=dict(vars(parent));exec(compile(projected,'<local-frozen-v5-Source-DATA-projection>','exec'),ns);return ns['source'](leaves,b)

def original(*args):
 body=raw('v2/reader.py');nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='original'];d.need(len(nodes)==1,'one frozen Original predicate');text=ast.get_source_segment(body.decode(),nodes[0]).encode();projected=substitute(text,[(b'perl5423-native-xs-v2-',b'perl5423-native-xs-v6-')]);ns=dict(vars(previous),d=d);exec(compile(projected,'<local-passive-v6-Original-name>','exec'),ns);return ns['original'](*args)

def producer_projection(body):
 return substitute(body,[(b"NATIVE_SHA='1db474ed81295c3604212998617bb44c1ed0339c224d63f61b06768cef6bde4f'",b"NATIVE_SHA='c492eb1b7175407d20a78305d8d1d499c67960d3b295aeea5ae206b9222d04cd'")])

def inner():
 body=producer_projection(raw5('producer.py'));p=V5/'producer.py';spec=importlib.util.spec_from_file_location('xs_v6_generator_bound_passive_producer',p);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(body,str(p),'exec'),m.__dict__);return m
