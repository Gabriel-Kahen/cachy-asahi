# SPDX-License-Identifier: MIT
"""Explicit source-only Setup240 stdout custody/codec route; all old routes held."""
import importlib.util,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_current607_prior_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
PROFILE={'bytes': 476325, 'sha256': '382ff71985a58441173315aef91aa0c4022c3d82c1f2626e0612e62ec15089e1'}
NAME='installed_codec842'
def normalized(path):
 path=F.ordinary(path);F.need(path==path.resolve(),'canonical normalized input/output required');return path

def closed(root,wanted):
 root=normalized(root);actual=F.files(root);expected={''}
 for n in wanted:expected.update(q.as_posix()if str(q)!='.'else''for q in Path(n).parents)
 dirs={''}|{p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_dir()and p.relative_to(root).parts[0]!='.git'}
 F.need(actual==wanted and dirs==expected,'whole closed codec source/support including directories');return{n:F.read(root/n)for n in wanted}

def inputs():
 import json
 F.need(not __import__('sys').flags.optimize,'optimized source guards refused');raw=F.read(HERE/'installed-codec842-profile.json');F.need(F.pin(raw)==PROFILE,'whole hardpinned installed codec profile');p=json.loads(raw)
 F.need(p['profile']==NAME and p['actual']is None and(len(p['before']),len(p['after']),len(p['held']),len(p['payload']))==(840,842,834,8),'finite six-changed/two-added codec source')
 F.need({n:w for n,w in p['before'].items()if p['after'].get(n)==w}==p['held']and {n:w for n,w in p['after'].items()if p['before'].get(n)!=w}==p['payload'],'whole834 held/six changed/two added')
 return p,closed(HERE/'installed-codec842',p['payload'])

def emit(source,output,authorization=None):
 source,output=map(normalized,(source,output));F.need(not os.path.lexists(output)and output.parent.is_dir(),'fresh codec source output')
 for root in(source,HERE):F.need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint source/factory/output')
 if authorization is not None:
  authorization=normalized(authorization);F.need(not os.path.lexists(authorization)and authorization.parent.is_dir()and all(not authorization.is_relative_to(root)for root in(source,HERE,output)),'fresh codec authorization outside every input/output')
 p,payload=inputs();bodies=closed(source,p['before']);bodies.update(payload);F.need({n:F.pin(b)for n,b in bodies.items()}==p['after'],'whole842 before any output')
 proof=__import__('json').loads(bodies['latest/implementation/installed-codec-successor.json']);F.need(all(proof[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'NULL actual source/ref/run and acceptance')
 closed(source,p['before']);output.mkdir(mode=0o700)
 for n,b in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(b)
 closed(output,p['after']);closed(source,p['before'])
 return dict(status='SOURCE_ONLY_EXACT842_ORIGINAL_INSTALLED_STDOUT_CODEC',files=p['after'],expected_fixture_source=p['source_after'],source=None,ref=None,actual=None,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
