# SPDX-License-Identifier: MIT
"""Pinned passive6, exact Source-leaf projection and new generator/name literals."""
import ast,hashlib,importlib.util,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;V6=HERE.parent/'v6'
PINS={'reader.py': 'bcfdbb702523449ca939a391a757030956f1230363f091c3337d2f77030dc29f', 'base.py': '1f38953e81316b9a7cda46fdeedaf27249b757d4ba152c28a0821727dfb49eb0', 'adapters.py': 'b5072640d36db792a56f87e07754daa8dd96a379f5fff3741bffb1c2fa871e60', 'delta.py': '84a51154a1274056704e99abda67bcd8054e2a4060c3d0356cf2551413d79c3f', 'producer_fixture.py': '143d9fef5efdc1ffdaee180d9e1c1155db6ef9eb7a6cbe6bee39c870e036e25f'}
def raw6(name):
 p=V6/name
 if p.is_symlink()or not p.is_file()or p.stat().st_size>128*1024:raise ValueError('ordinary fixed passive6 dependency')
 body=p.read_bytes()
 if hashlib.sha256(body).hexdigest()!=PINS[name]:raise ValueError('whole frozen passive6 dependency changed')
 return body
for name in PINS:raw6(name)
spec=importlib.util.spec_from_file_location('xs_v7_frozen_v6_reader',V6/'reader.py');parent=importlib.util.module_from_spec(spec);spec.loader.exec_module(parent)
ancestor=parent.B;d=parent.d;previous=ancestor.previous;compiler=ancestor.compiler
raw=ancestor.raw;load=ancestor.load;substitute=ancestor.substitute;daemon_classifier=ancestor.daemon_classifier
OLD_NATIVE='c492eb1b7175407d20a78305d8d1d499c67960d3b295aeea5ae206b9222d04cd'
NEW_NATIVE='f23631b845da27abbff36ba31c5f0825b54ce767553feacf68562362ecd734b3'
def source6(leaves,b):
 body=raw6('reader.py');nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='source'];d.need(len(nodes)==1,'one frozen passive6 Source predicate');text=ast.get_source_segment(body.decode(),nodes[0]).encode()
 projected=substitute(text,[(b"raw=d.read(root,'source-map.json',d.MIB)",b"raw=root['source-map.json'][0]"),(b'names=d.inventory(root,321,96*d.MIB)',b'names=set(root)'),(b'body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode)',b'body,mode=root[name]')]);ns=dict(vars(parent));exec(compile(projected,'<local-frozen6-Source-leaf-DATA-only>','exec'),ns);return ns['source'](leaves,b)
def original(*args):
 body=raw('v2/reader.py');nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='original'];d.need(len(nodes)==1,'one frozen Original predicate');text=ast.get_source_segment(body.decode(),nodes[0]).encode();projected=substitute(text,[(b'perl5423-native-xs-v2-',b'perl5423-native-xs-v7-')]);ns=dict(vars(previous),d=d);exec(compile(projected,'<local-passive7-Original-name-only>','exec'),ns);return ns['original'](*args)
def producer_projection(body):
 return substitute(body,[(b"NATIVE_SHA='1db474ed81295c3604212998617bb44c1ed0339c224d63f61b06768cef6bde4f'",("NATIVE_SHA='"+NEW_NATIVE+"'").encode())])
def inner():
 body=producer_projection(ancestor.raw5('producer.py'));p=ancestor.V5/'producer.py';s=importlib.util.spec_from_file_location('xs_v7_generator_bound_passive_producer',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;exec(compile(body,str(p),'exec'),m.__dict__);return m
