# SPDX-License-Identifier: MIT
"""Readable whole41 lexical allocation successor; no actors or native credit."""
import ast,base64,hashlib,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':24253,'sha256':'06956dc5fa25982a2c96d9310517196bcc6fa48d540b83ea7fae6c4987703464'}
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')
def operands(api):
 need,pin,read,source=(api[k]for k in('need','pin','read','source'));need(not sys.flags.optimize,'ordinary source guards required');raw=read(HERE/'observer-profile.json');need(pin(raw)==PROFILE,'whole hardpinned observer profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_OBSERVER_EFFICIENT_CORE41_FACTORY'and p['source_before']=='29a60eeaf45fad954ffa0932c8559192a911c298'and p['source_after']=='0be46ae9f59561f042b32b1de0b1fd54c7a26999'and p['actual']is None and p['acceptance']is False,'exact published source-only observer identities');need(len(p['before'])==len(p['after'])==41 and len(p['held'])==37 and {n:w for n,w in p['before'].items()if p['after'].get(n)==w}==p['held']and p['root_cap']==600,'whole37 held/four changed with root600 held');text=read(HERE/'prepare.py').decode();functions={n.name:pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name in p['held_factory_functions']};need(functions==p['held_factory_functions']and len(functions)==28,'every prior28 pre-main function body held');return p,source(HERE/'observer-payload',p['payload'])

def inputs(api):
 need,pin,enc=(api[k]for k in('need','pin','encoded'));p,payload=operands(api);parent,before=api['tpm_acl_inputs']();need({n:pin(b)for n,b in before.items()}==p['before']and parent['source_after']==p['source_before'],'entire exact typed-ACL41 parent before successor');lexical=payload['lexical.py.in'].decode();text=before['acl_policy.py'].decode();c=p['constants']
 for old,new in((c['CAPTURE_BEFORE'],c['CAPTURE_AFTER']),(c['ROOT_BEFORE'],c['ROOT_AFTER']),('def install(observer,raw,root,nodes,label):',lexical+'def install(observer,raw,root,nodes,label):')):
  need(text.count(old)==1,'one lexical observer production seam');text=text.replace(old,new,1)
 tail=payload['guard.py.in'].decode();seals={n:base64.b64encode(before[n]).decode()for n in('source-manifest.json',*WORKFLOWS)}
 for marker,value in(('@SOURCE41@',repr(p['before'])),('@SEALS41@',repr(seals)),('@LEXICAL@',repr(lexical)),('@BEFORE@',repr(c['CAPTURE_BEFORE'])),('@AFTER@',repr(c['CAPTURE_AFTER'])),('@ROOT_BEFORE@',repr(c['ROOT_BEFORE'])),('@ROOT_AFTER@',repr(c['ROOT_AFTER']))):
  need(tail.count(marker)==1,'one whole-body inverse marker');tail=tail.replace(marker,value,1)
 text+=tail;sha=hashlib.sha256(text.encode()).hexdigest();need(text.count("\nOBSERVER_TEMPLATE_SHA = '@SELF@'\n")==1,'one normalized entire helper self seal');text=text.replace("OBSERVER_TEMPLATE_SHA = '@SELF@'",'OBSERVER_TEMPLATE_SHA = '+repr(sha),1);bodies=dict(before,**{'acl_policy.py':text.encode()});bodies['source-manifest.json']=enc(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(b)for n,b in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(bodies['source-manifest.json'])['sha256'].encode())
 for n in WORKFLOWS:bodies[n]=workflow
 need({n:pin(b)for n,b in bodies.items()}==p['after'],'whole exact published observer41 before writes');scope={};exec(compile(bodies['acl_policy.py'],'trusted_observer_policy.py','exec'),scope);need(scope['published41'](bodies)==before,'entire41 inverse before any writes')
 # No observation or private actor occurs here; source bodies and template inputs are reread before writes.
 _,again=api['tpm_acl_inputs']();need(again==before and operands(api)==(p,payload),'fresh complete parent/support revalidation');return p,bodies

def result(p,unbound=False):
 if type(unbound)is not bool:raise ValueError('explicit boolean receipt choice')
 return dict(status='SOURCE_ONLY_EXACT_OBSERVER_EFFICIENT_CORE41_NOT_NATIVE_ACCEPTANCE',files=41,source=None if unbound else p['source_after'],ref=None if unbound else p['ref_after'],expected_fixture_source=p['source_after'],context_source=None if unbound else p['source_before'],actual=None,run=None,acceptance=False,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',old_closed_schema_held=False,typed_ACL_schema_held=True,native_hotspot='UNKNOWN',native_fit='UNKNOWN',root_cap=600)

def emit(api,output,unbound=False,authorization=None):
 need,ordinary,source,enc=(api[k]for k in('need','ordinary','source','encoded'));need(type(unbound)is bool,'explicit boolean receipt choice');output=ordinary(output);authorization=None if authorization is None else ordinary(authorization)
 for path in(output,*(()if authorization is None else(authorization,))):need(path==path.resolve()and path.parent.is_dir()and not os.path.lexists(path)and not path.is_relative_to(HERE)and not HERE.is_relative_to(path),'fresh canonical ordinary output/authorization outside factory')
 if authorization is not None:need(not authorization.is_relative_to(output)and not output.is_relative_to(authorization),'disjoint output/authorization before writes')
 p,bodies=inputs(api);value=result(p,unbound);output.mkdir(mode=0o700)
 for n,b in sorted(bodies.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True)
  with q.open('xb')as stream:stream.write(b)
 need(source(output,p['after'])==bodies,'whole exact emitted observer41')
 if authorization is not None:
  with authorization.open('xb')as stream:stream.write(enc(value))
 return value
