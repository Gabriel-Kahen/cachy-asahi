# SPDX-License-Identifier: MIT
"""Frozen repository DATA predicates and finite reversible in-memory projections."""
import ast,hashlib,importlib.util,sys,os
from pathlib import Path
HERE=Path(__file__).resolve().parent;V3=HERE.parent/'v3'
if 'CACHY_XS_V3_READER_BASE'in os.environ:raise ValueError('fixed local passive dependency layout; ambient override refused')
PINS={'base.py':'fd03989b283137dfa1d10a703ba6593ecf743dba859c24baa8e2deb7b7687403','reader.py':'474c55dab21f9fcc178e2bbb04d3bf02d8b2fbe8f7d21d56ee60b6033a866ee0','adapters.py':'3cfc17f7ef76cbd5a48973a350a0c45aa486b07c0c0496ee498e98fed47b49e6','compiler.py':'6d2541919c5c9dfd2d573b7f3544d62c1f4d04a567b82e8e561ce51672515438'}
def raw3(name):
 p=V3/name
 if p.is_symlink()or not p.is_file()or p.stat().st_size>128*1024:raise ValueError('ordinary bounded frozen v3 predicate')
 body=p.read_bytes()
 if hashlib.sha256(body).hexdigest()!=PINS[name]:raise ValueError('whole frozen v3 predicate changed: '+name)
 return body
for name in PINS:raw3(name)
def parent_module(name):
 spec=importlib.util.spec_from_file_location('xs_v4_frozen_v3_'+name,V3/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;exec(compile(raw3(name+'.py'),str(V3/(name+'.py')),'exec'),m.__dict__);return m
parent=parent_module('reader');ancestor=parent.B;d=parent.d;previous=ancestor.previous
raw=ancestor.raw;load=ancestor.load

def substitute(body,seams):
 original=body
 for old,new in seams:
  if body.count(old)!=1:raise ValueError('exact finite passive projection seam required')
  body=body.replace(old,new)
 for old,new in reversed(seams):
  if body.count(new)!=1:raise ValueError('unambiguous projection inverse required')
  body=body.replace(new,old)
 if body!=original:raise ValueError('whole passive projection inverse differs')
 for old,new in seams:body=body.replace(old,new)
 return body

def source_projection(version):
 body=raw3('reader.py')if version==3 else raw('v2/reader.py');tree=ast.parse(body);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='source']
 if len(nodes)!=1:raise ValueError('one frozen passive Source predicate')
 text=ast.get_source_segment(body.decode(),nodes[0]).encode()
 if version==3:
  seams=[(b"raw=d.read(root,'source-map.json',d.MIB)",b"raw=root['source-map.json'][0]"),(b'names=d.inventory(root,305,96*d.MIB,ignore_git=True)',b'names=set(root)'),(b'body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode)',b'body,mode=root[name]')]
 elif version==2:
  seams=[(b"raw = d.read(root, 'source-map.json', d.MIB)",b"raw = root['source-map.json'][0]"),(b'names = d.inventory(root, 298, 96*d.MIB, ignore_git=True)',b'names = set(root)'),(b'body = d.read(root, name, 64*d.MIB)\n        mode = stat.S_IMODE((Path(root) / name).stat().st_mode)',b'body, mode = root[name]')]
 else:raise ValueError('only exact frozen v3/v2 Source projection')
 result=substitute(text,seams);namespace=dict(vars(parent if version==3 else previous),d=d)
 exec(compile(result,'<frozen-passive-Source-leaves-projection>','exec'),namespace)
 return namespace['source'],dict(before_sha256=hashlib.sha256(text).hexdigest(),after_sha256=hashlib.sha256(result).hexdigest(),seams=len(seams),inverse='EXACT_ORIGINAL_FUNCTION_BYTES')

def original(*args):
 body=raw('v2/reader.py');tree=ast.parse(body);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='original']
 if len(nodes)!=1:raise ValueError('one frozen Original predicate')
 text=ast.get_source_segment(body.decode(),nodes[0]).encode();result=substitute(text,[(b'perl5423-native-xs-v2-',b'perl5423-native-xs-v4-')]);namespace=dict(vars(previous),d=d);exec(compile(result,'<frozen-passive-v4-Original-name>','exec'),namespace);return namespace['original'](*args)

def daemon_classifier(root,m,io):
 # The Source body remains DATA; execute only this local reviewed predicate copy.
 io.need(io.pin(io.read(root,'held/hosted/reader.py',io.MIB))==dict(bytes=m['files']['held/hosted/reader.py']['bytes'],sha256='1415ef32702c7c99a1275e40a02b8d8ae693f0c4e0eff0e32d5dd1205ecd8de2'),'exact held passive-classifier DATA body')
 p=HERE/'daemon.py';body=p.read_bytes();io.need(not p.is_symlink()and hashlib.sha256(body).hexdigest()=='d3ef121cda81481343e8df2ee899c2b7453d23970fe1f4945b4e6e61ed1618bf','whole local daemon DATA predicates')
 spec=importlib.util.spec_from_file_location('xs_v4_local_daemon',p);module=importlib.util.module_from_spec(spec);exec(compile(body,str(p),'exec'),module.__dict__);return module
