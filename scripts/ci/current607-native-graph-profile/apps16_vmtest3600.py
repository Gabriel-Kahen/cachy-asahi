# SPDX-License-Identifier: MIT
"""Explicit exact849→853 VM TEST factory; no actor, mutable basis or artifact import."""
import ast,base64,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_vmtest_held_apps16_factory',HERE/'apps16_849.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A);F=A.F
PROFILE={'bytes': 1481247, 'sha256': '90e3b3418d138c79898805c1452e84a3be282e80f2926877d7297e7d7cfaa5dc'}
I='latest/implementation/';MF='latest/source-manifest.json';GUARD=I+'latest_guard.py';PROOF=I+'validation-capacity-parent.json';WFS=('.github/workflows/native-arm-current607-latest-tools.yml','.github/workflows/native-arm-build.yml');MARKER='\n# BEGIN_EXPLICIT_VM_TEST_COMPONENT3600\n'
pin,need,closed,normalized=F.pin,F.need,A.closed,A.normalized

def inputs():
 need(not __import__('sys').flags.optimize,'optimized source guards refused');raw=F.read(HERE/'apps16-vmtest3600-profile.json');need(pin(raw)==PROFILE,'whole hardpinned explicit VM TEST profile');p=json.loads(raw);need(p['profile']=='apps16_vmtest3600'and p['default']is False and p['actual']is None and p['source_before']=='c64cee1167d2ff81f1de0128f57c275819e32868'and p['source_after']=='67e8155840f9851bff3b8acb2cd6de6a622515c4','fixed genuine source849→853 identities');raw=F.read(HERE/'apps16-vmtest3600-maps.json');need(pin(raw)==p['maps'],'whole fixed known/NULL source maps');maps=json.loads(raw);need({n:len(v)for n,v in maps.items()}==dict(before=849,unbound_before=849,selected=853,unbound=853),'exact whole849/853 variants');payload=closed(HERE/'apps16-vmtest3600',p['payload']);need(p['proof']['edits']['next/test_source.py'][0][1].encode()==payload['entry.fragment'],'exact readable source-entry payload');need(p['clocks']==dict(consumer=4200,owner=6600,component=3600,transaction=90,fixture=100,real_module_suite=240,cleanup=60)and all(p[n]=='NOT_ESTABLISHED'for n in('outer4200_fit','owner6600_fit','old2400_fit'))and p['performance']=='NOT_CLAIMED'and p['M2_performance']=='NOT_RUN'and p['passive_caps']==dict(source=300,strict=900,failure=900,collector=900),'only component TEST capacity; all other clocks/frontiers fixed');return p,maps,payload

def null_base(before,maps):
 bodies=dict(before);name=I+'apps16-inputs.json';value=json.loads(bodies[name]);need(value['selection']is not None,'genuine selected849 input');value['selection']=None;bodies[name]=F.encoded(value);name=I+'apps16-successor.json';old=pin(bodies[name]);proof=json.loads(bodies[name]);proof['helpers'][I+'apps16-inputs.json']=pin(bodies[I+'apps16-inputs.json']);bodies[name]=F.encoded(proof);guard=bodies[GUARD];oldfooter=A.footer(name,old).encode();newfooter=A.footer(name,pin(bodies[name])).encode();need(guard.count(oldfooter)==1,'one exact old849 source guard footer');bodies[GUARD]=guard.replace(oldfooter,newfooter,1);mf=json.loads(bodies[MF]);mf['files']={n:pin(b)for n,b in bodies.items()if n not in{MF,*WFS}};bodies[MF]=F.encoded(mf)
 for n in WFS:
  stamp=maps['before'][MF]['sha256'].encode();need(bodies[n].count(stamp)==1,'one exact NULL849 manifest stamp');bodies[n]=bodies[n].replace(stamp,pin(bodies[MF])['sha256'].encode(),1)
 need({n:pin(b)for n,b in bodies.items()}==maps['unbound_before'],'whole exact original frozen NULL849 before capacity changes');return bodies

def render(source,null=False):
 need(type(null)is bool,'literal NULL choice');p,maps,payload=inputs();source=normalized(source);before=closed(source,maps['before']);base=null_base(before,maps)if null else before;bodies=dict(base);proof=dict(p['proof']);original=maps['unbound_before'if null else'before'];proof.update(before=original,known_parent=maps['before'],null_parent=maps['unbound_before'],null=null)
 for n,edits in proof['edits'].items():
  text=bodies[n].decode()
  for old,new in edits:need(text.count(old)==1,'one exact shared TEST capacity/entry seam '+n);text=text.replace(old,new,1)
  back=text
  for old,new in reversed(edits):need(back.count(new)==1,'one full old849 source inverse');back=back.replace(new,old,1)
  need(back.encode()==base[n],'all original source body outside exact finite edits');bodies[n]=text.encode()
 for n,src in[(I+'validation_capacity.py','validation_capacity.py'),(I+'validation-capacity-profile.json','profile.json'),('next/tests/test_validation_capacity.py','test_emitted.py')]:bodies[n]=payload[src]
 changed={*proof['edits'],GUARD,MF,*WFS};proof['before_bodies']={n:base64.b64encode(base[n]).decode()for n in sorted(changed)};proof['helpers']={n:pin(bodies[n])for n in sorted(set(proof['edits'])|set(proof['added'])-{PROOF})};bodies[PROOF]=F.encoded(proof);footer='def verify():\n import validation_capacity\n return validation_capacity.verify(ROOT, '+repr(PROOF)+', '+repr(pin(bodies[PROOF]))+')\n';bodies[GUARD]+=MARKER.encode()+footer.encode();mf=json.loads(bodies[MF]);mf['VM_TEST_capacity']=json.loads(payload['profile.json']);mf['files']={n:pin(b)for n,b in bodies.items()if n not in{MF,*WFS}};bodies[MF]=F.encoded(mf)
 for n in WFS:
  stamp=original[MF]['sha256'].encode();need(bodies[n].count(stamp)==1,'one manifest stamp, all original outer workflow clocks held');bodies[n]=bodies[n].replace(stamp,pin(bodies[MF])['sha256'].encode(),1)
 expected=maps['unbound'if null else'selected'];need({n:pin(b)for n,b in bodies.items()}==expected and len(changed)==7 and len(proof['added'])==4 and sum(expected.get(n)==w for n,w in original.items())==842,'entire exact853:842 held/7 changed/4 added')
 for n,b in bodies.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 closed(source,maps['before']);need(inputs()==(p,maps,payload),'fresh fixed profile/payload revalidation before output');return bodies,p,maps

def emit(source,output,authorization,null=False):
 source,output,authorization=map(normalized,(source,output,authorization));need(not os.path.lexists(output)and not os.path.lexists(authorization)and output.parent.is_dir()and authorization.parent.is_dir(),'fresh ordinary output/authorization before writes')
 for target in(output,authorization):
  for root in(source,HERE):need(not target.is_relative_to(root)and not root.is_relative_to(target),'disjoint source/factory/output/authorization')
 need(not output.is_relative_to(authorization)and not authorization.is_relative_to(output),'mutually disjoint output/authorization');bodies,p,maps=render(source,null);output.mkdir(mode=0o700)
 for n,b in sorted(bodies.items()):q=output/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
 expected=maps['unbound'if null else'selected'];closed(output,expected);return dict(status='SOURCE_ONLY_EXACT853_VM_TEST3600_OUTER_FIT_NOT_ESTABLISHED',files=expected,expected_fixture_source=p['source_after'],source=None,ref=None,actual=None,null_selection=null,old2400_fit='NOT_ESTABLISHED',outer4200_fit='NOT_ESTABLISHED',owner6600_fit='NOT_ESTABLISHED',performance='NOT_CLAIMED',M2_performance='NOT_RUN',native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
