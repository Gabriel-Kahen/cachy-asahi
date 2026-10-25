# SPDX-License-Identifier: MIT
"""Portable finite public43→journal44 factory. No actors or native acceptance."""
import ast,base64,hashlib,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 25580, 'sha256': 'aa00350f4d56aca1a6f60b760d18c12afbb6f06f9c2d058ca84e9fc2f7a6cd1e'}
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')
def canonical(api,path):
 path=Path(path).absolute();api['need'](path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary journal input/output path');return path

def operands(api):
 read,pin,need,source=(api[k]for k in('read','pin','need','source'));need(not sys.flags.optimize,'ordinary source guards required');raw=read(HERE/'journal-acl1200-profile.json');need(pin(raw)==PROFILE,'whole hardpinned journal44 profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_JOURNAL44_FROM_PUBLIC43'and p['actual']is None and p['acceptance']is False and p['parent']['source']=='386454785b19612f4aa1889f81878feb8ee5c0f6'and p['result']['source']=='15a41fda11ac9ffa0ae4a7a53697d5f63a913a57','exact public43/journal44 source identities')
 need(len(p['parent']['files'])==43 and len(p['result']['files'])==44 and len(p['held'])==35 and{n:w for n,w in p['parent']['files'].items()if p['result']['files'].get(n)==w}==p['held']and p['graph_seconds']==1200 and p['old600fit']=='NOT_ESTABLISHED'and p['M2performance']=='NOT_RUN'and p['native_acceptance']=='NOT_ISSUED','whole source maps and honest VM validation profile')
 text=read(HERE/'prepare.py').decode();tree=ast.parse(text);functions={n.name:pin(ast.get_source_segment(text,n).encode())for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in p['held_factory_functions']};need(functions==p['held_factory_functions']and len(functions)==31,'all31 preexisting factory functions held')
 main=ast.get_source_segment(text,next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main'))
 for before,after in reversed(p['main_edits']):need(main.count(after)==1,'one additive main inverse');main=main.replace(after,before,1)
 need(pin(main.encode())==p['old_main'],'entire old main body restored');return p,source(HERE/'journal-acl1200-payload',p['payload'])

def compose(api,before,p,payload):
 need,pin,enc=(api[k]for k in('need','pin','encoded'));need({n:pin(b)for n,b in before.items()}==p['parent']['files'],'entire immutable public43 substrate only');bodies=dict(before);seams={}
 for name,rows in json.loads(payload['edits.json']).items():
  edits=[(before['LICENSE'].decode(),before['LICENSE'].decode()+p['license_notice']+payload['LICENSE.LGPL2.1'].decode())]if name=='LICENSE'else[tuple(row)for row in rows];text=bodies[name].decode()
  for old,new in edits:need(text.count(old)==1,'one exact source44 operand '+name);text=text.replace(old,new,1)
  bodies[name]=text.encode();seams[name]=edits
 runtime=payload['runtime.py.in'].decode();need(runtime.count('@DECLARATIONS@')==1,'one exact journal declaration operand');declarations={n:payload['declarations/'+n]for n in p['declaration_order']};runtime=runtime.replace('@DECLARATIONS@',repr(declarations),1);template=runtime+payload['guard.py.in'].decode();seals={n:base64.b64encode(before[n]).decode()for n in('source-manifest.json',*WORKFLOWS)}
 for marker,value in(('@PARENT@',repr(p['parent']['files'])),('@EDITS@',repr(seams)),('@SEALS@',repr(seals))):need(template.count(marker)==1,'one complete source guard operand');template=template.replace(marker,value,1)
 digest=hashlib.sha256(template.encode()).hexdigest();need(template.count("\nTEMPLATE_SHA='@SELF@'\n")==1,'one whole source44 self seal');bodies['journal_acl.py']=template.replace("TEMPLATE_SHA='@SELF@'",'TEMPLATE_SHA='+repr(digest),1).encode();bodies['source-manifest.json']=enc(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(b)for n,b in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(bodies['source-manifest.json'])['sha256'].encode())
 for name in WORKFLOWS:bodies[name]=workflow
 need({n:pin(b)for n,b in bodies.items()}==p['result']['files'],'entire exact published journal44 namespace before writes')
 scope={};exec(compile(bodies['journal_acl.py'],'trusted_journal44_policy.py','exec'),scope);need(scope['inverse'](bodies)==before,'entire44→43 byte inverse')
 for name,raw in bodies.items():
  if name.endswith('.py'):ast.parse(raw,filename=name)
 return bodies

def inputs(api,predecessor):
 need=api['need'];predecessor=canonical(api,predecessor);p,payload=operands(api);before=api['source'](predecessor,p['parent']['files']);bodies=compose(api,before,p,payload)
 need(api['source'](predecessor,p['parent']['files'])==before and operands(api)==(p,payload),'fresh whole public43/support revalidation before writes');return p,bodies

def result(p,unbound=False):
 if type(unbound)is not bool:raise ValueError('literal unbound receipt choice')
 return dict(status='SOURCE_ONLY_EXACT_JOURNAL44_NOT_NATIVE_ACCEPTANCE',files=44,source=None if unbound else p['result']['source'],ref=None if unbound else p['result']['ref'],context_source=None if unbound else p['parent']['source'],expected_fixture_source=p['result']['source'],actual=None,run=None,acceptance=False,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',graph_seconds=1200,old600fit='NOT_ESTABLISHED',M2performance='NOT_RUN',typed_journal_schema='MANDATORY_ACCESS_AND_DEFAULT_MAPS',old_closed_schema_held=False)

def emit(api,predecessor,output,unbound=False,authorization=None):
 need,enc=(api[k]for k in('need','encoded'));need(type(unbound)is bool,'literal unbound choice');predecessor=canonical(api,predecessor);output=canonical(api,output);receipt=canonical(api,authorization)if authorization is not None else None
 for path in(output,receipt):
  if path is None:continue
  need(not os.path.lexists(path)and path.parent.is_dir()and not path.is_relative_to(HERE)and not HERE.is_relative_to(path)and not path.is_relative_to(predecessor)and not predecessor.is_relative_to(path),'fresh output/receipt disjoint from factory and public substrate')
 need(receipt is None or(not output.is_relative_to(receipt)and not receipt.is_relative_to(output)),'mutually disjoint output and receipt')
 p,bodies=inputs(api,predecessor);output.mkdir(mode=0o700)
 for name,raw in sorted(bodies.items()):
  path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need(api['source'](output,p['result']['files'])==bodies,'entire exact emitted journal44');value=result(p,unbound)
 if receipt is not None:
  with receipt.open('xb')as stream:stream.write(enc(value))
 return value
