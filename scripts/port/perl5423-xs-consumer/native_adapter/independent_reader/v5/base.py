# SPDX-License-Identifier: MIT
"""Pinned passive v4 ancestors; Source and artifact Python remain DATA."""
import ast,hashlib,importlib.util,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;V4=HERE.parent/'v4'
PINS={'base.py': '87234b41005f79230d93b9c312393e68176c280ab98c231b37ea0d5b90c3c725', 'reader.py': 'c911f7251b49a61348ae47f78416988101b74dd291d902aea8539105e4d09bc9', 'compiler.py': 'e2e732d684268ac5d453750599fd8dd7b5a615aa184b5ccba70432edf527f292', 'adapters.py': '9e2af339d95c32e7a3b0fd01fd95564dd7fa0d7eb0aaec40bdcae425d321eba6'}
def raw4(name):
 p=V4/name
 if p.is_symlink()or not p.is_file()or p.stat().st_size>128*1024:raise ValueError('ordinary fixed passive v4 dependency')
 b=p.read_bytes()
 if hashlib.sha256(b).hexdigest()!=PINS[name]:raise ValueError('whole frozen v4 passive dependency changed')
 return b
def parent_module(name):
 body=raw4(name+'.py');spec=importlib.util.spec_from_file_location('xs_v5_frozen_v4_'+name,V4/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(body,str(V4/(name+'.py')),'exec'),m.__dict__);return m
parent=parent_module('reader');ancestor=parent.B;d=parent.d;previous=ancestor.previous
raw=ancestor.raw;load=ancestor.load;substitute=ancestor.substitute;source_projection=ancestor.source_projection;daemon_classifier=ancestor.daemon_classifier
compiler=parent_module('compiler')
def source4(leaves,b):
 body=raw4('reader.py');tree=ast.parse(body);node=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='source'];d.need(len(node)==1,'one frozen v4 Source predicate');text=ast.get_source_segment(body.decode(),node[0]).encode()
 projected=substitute(text,[(b"raw=d.read(root,'source-map.json',d.MIB)",b"raw=root['source-map.json'][0]"),(b'names=d.inventory(root,311,96*d.MIB)',b'names=set(root)'),(b'body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode)',b'body,mode=root[name]')]);ns=dict(vars(parent));exec(compile(projected,'<local-frozen-v4-Source-DATA-projection>','exec'),ns);return ns['source'](leaves,b)
def original(*args):
 body=raw('v2/reader.py');tree=ast.parse(body);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='original'];d.need(len(nodes)==1,'one frozen Original predicate');text=ast.get_source_segment(body.decode(),nodes[0]).encode();projected=substitute(text,[(b'perl5423-native-xs-v2-',b'perl5423-native-xs-v5-')]);ns=dict(vars(previous),d=d);exec(compile(projected,'<local-passive-v5-Original-name>','exec'),ns);return ns['original'](*args)
def inner():
 p=HERE/'producer.py';body=d.read(HERE,'producer.py',128*1024);d.need(hashlib.sha256(body).hexdigest()=='b97fa01c240ddec838334c585543908f904e5ccf7305d1730e3d17207e69e50c','whole local v5 producer predicate');spec=importlib.util.spec_from_file_location('xs_v5_passive_producer',p);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(body,str(p),'exec'),m.__dict__);return m
