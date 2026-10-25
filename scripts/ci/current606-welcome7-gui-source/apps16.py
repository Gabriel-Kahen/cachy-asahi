# SPDX-License-Identifier: MIT
"""Exact finite Apps14→Apps16 source option; no current GUI authority."""
import ast,base64,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 522707, 'sha256': '6204b5ab5d67ab27f0c861aeeb12496dfd1371dcda8ec0685404916e8f113cd1'}
WF='.github/workflows/native-arm-current606-welcome8-gui.yml';ALIAS='.github/workflows/native-arm-build.yml'
RENAMES={n:n.replace('apps14','apps16')for n in('apps14_common.py','apps14_inputs.py','apps14-selection.json','apps14-recipe-map.json','apps14-parent.json','factory/apps14_runtime.py','factory/apps14-installed-profile.json','factory/apps14_diagnostic.py')}
def inputs(api):
 need,pin,read,files=(api[k]for k in('need','pin','ordinary','files'));need(not sys.flags.optimize,'source assertions required');raw=read(HERE/'apps16-profile.json');need(pin(raw)==PROFILE,'whole pinned Apps16 profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_GUI561_APPS16_OPTION_NOT_NATIVE'and p['actual']is None and p['limits']==dict(GUI_CLI=35,inventory=30,fresh_scans=2),'finite source-only profile and original clocks');raw=read(HERE/'apps16-maps.json');need(pin(raw)==p['maps'],'whole source maps');maps=json.loads(raw);need(len(maps['before'])==len(maps['selected'])==len(maps['unbound'])==561,'three complete561 maps');payload=files((HERE/'apps16-payload').absolute());need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole readable used Apps16 payload')
 sources=dict(parent='601195b401668f92cec35772f1ad4c3eb00e6d21',output='d34854151f578547c2f64f46d14f5d9129bf2d66',carrier='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11',recipe='a32501a76b79b65d175c8eefc2b4f741ec0388e5',native='135b8fb21941d0ea27da7d34b1fc7b9eb0939ee8')
 for k,w in sources.items():
  c,g=p['custody'][k]['publication'],p['custody'][k]['git'];need(c['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and g['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and c['source']==g['source']==w and c['ref']==g['ref']and c['files']==c['git_joins']==len(g['files'])and c['actual']==c['hardware']=='NOT_RUN'and c['release']=='NOT_ADMITTED','whole genuine historical source/Git custody '+k)
 need(p['custody']['parent']['git']['files']==maps['before']and p['custody']['output']['git']['files']==maps['selected']and p['parent_context']==dict(publication=p['custody']['parent']['publication'],authorization=maps['before'],git=p['custody']['parent']['git'],metadata=p['parent_context']['metadata']),'whole561 parent/result publication context');s=p['selection'];q=s['selection'];need(s['status']=='ROOT_BOUND_ACCEPTED_APPS16_INPUTS_ONLY_NO_GUI_AUTHORITY'and s['actual_source']is s['actual_ref']is s['actual_run']is q['actual']is None and q['source']==sources['carrier']and q['files']==p['custody']['carrier']['git']['files']and len(q['files'])==94 and q['recipe_source']==sources['recipe']and q['pair_source']==sources['native']and q['pair_ref']=='codex/apps16-pair-native-v1'and q['pair_run']==40170377974 and q['package']==dict(name='cachy-asahi-apps',version='0.1.0-16',archive='cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz',size=29664,sha256='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'),'only genuine Apps16 accepted input, never GUI authority');need(json.loads(payload['apps16-recipe-map.json'])==p['custody']['recipe']['git']['files'],'whole original42 recipe');return p,maps,payload

def canonical(api,path):
 p=Path(path).absolute();api['need'](str(p)==os.path.normpath(str(p))and '..'not in p.parts and not any(q.is_symlink()for q in(p,*p.parents)),'canonical ordinary path before disjointness');return p

def render(api,predecessor,unbound=False,carrier=None):
 need,pin,enc,files=(api[k]for k in('need','pin','encoded','files'));predecessor=canonical(api,predecessor);p,maps,payload=inputs(api);before=files(predecessor);need({n:pin(b)for n,b in before.items()}==maps['before'],'whole genuine561 cleanup predecessor');out=dict(before);value=p['null_selection']if unbound else p['selection'];s=value['selection']
 if unbound:need(carrier is None,'NULL route cannot retain carrier authority')
 else:
  need(carrier is not None,'explicit complete accepted Apps16 carrier94 required');carrier=canonical(api,carrier);need({n:pin(b)for n,b in files(carrier).items()}==p['custody']['carrier']['git']['files'],'whole accepted Apps16 carrier94 filesystem before output')
  record=s['qualified_record'];need(record['source']=='b011fb72b8055cd1d3c5c08227839847a83ef6c5'and record['files']==p['custody']['record']['git']['files']and len(record['files'])==22 and record['acceptance']==s['acceptance'],'whole qualified22 original decision input-only join')
 def once(t,a,b):need(t.count(a)==1,'one exact Apps16 source operand '+a[:90]);return t.replace(a,b,1)
 def roles(t):return t.replace('Apps14','Apps16').replace('APPS14','APPS16').replace('apps14','apps16')
 for a,b in RENAMES.items():out[b]=out.pop(a)
 for n in('input606.py','native.py','factory/factory.py','factory/current_products.py'):out[n]=roles(out[n].decode()).encode()
 out.update(payload)
 if s is not None:
  text=out['apps16_common.py'].decode()
  for n,v in [('PAIR',s['pair_source']),('PAIR_REF',s['pair_ref']),('RUN',s['pair_run'])]:text=once(text,n+'=None',n+'='+repr(v))
  out['apps16_common.py']=text.encode()
 out['apps16-selection.json']=enc(value);row=dict(name='cachy-asahi-apps',version='0.1.0-16',archive='cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz',size=None,sha256=None)if unbound else s['package'];req=json.loads(out['input-policy33.json']);need(req['packages']['cachy-asahi-apps']['version']=='0.1.0-14','one exact old Apps14 operand');req['packages']['cachy-asahi-apps']=row;out['input-policy33.json']=enc(req)
 oldhash=pin(out['factory/expected606.lock'])['sha256'];out['factory/expected606.lock']=once(out['factory/expected606.lock'].decode(),'cachy-asahi-apps 0.1.0-14\n','cachy-asahi-apps 0.1.0-16\n').encode();newhash=pin(out['factory/expected606.lock'])['sha256'];out['factory/install606.py']=once(out['factory/install606.py'].decode(),oldhash,newhash).encode();profile=json.loads(out['factory/profile.json']);profile['versions']['cachy-asahi-apps']='0.1.0-16';profile['native_archives']['cachy-asahi-apps']=None if unbound else dict(bytes=row['size'],sha256=row['sha256']);profile['expected606']=pin(out['factory/expected606.lock']);out['factory/profile.json']=enc(profile)
 out[WF]=once(roles(out[WF].decode()),'9fc95ae7694bfb67d8d1e8065303a5b1770b4b55','UNBOUND_APPS16_ACCEPTED_CARRIER_DO_NOT_DISPATCH'if unbound else s['source']).encode();out[ALIAS]=out[WF];changed={n for n in before if n not in out or out[n]!=before[n]}|{'source-manifest.json','apps14-parent.json'};out['apps16-parent.json']=enc(dict(source=p['custody']['parent']['publication']['source'],ref='codex/welcome8-gui-failure-cleanup-v1',actual=None,files=maps['before'],before_bodies={n:base64.b64encode(before[n]).decode()for n in sorted(changed)},context=p['parent_context']));out['source-manifest.json']=enc(dict(status='SOURCE_ONLY_CURRENT606_WELCOME8_APPS16_NO_NEW_GUI_ACCEPTANCE',files={n:pin(b)for n,b in sorted(out.items())if n!='source-manifest.json'},actual_source=None,actual_ref=None,actual_run=None));need({n:pin(b)for n,b in out.items()}==maps['unbound'if unbound else'selected'],'whole exact561 equality before output');need(sum(n in out and before[n]==out[n]for n in before)==541 and out[WF]==out[ALIAS],'all541 held and both workflow aliases byteequal')
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 return out

def emit(api,predecessor,output,unbound=False,carrier=None):
 # Reject noncanonical spellings and aliases BEFORE lexical ancestry comparison.
 predecessor=canonical(api,predecessor);output=canonical(api,output);need=api['need'];need(predecessor.is_dir()and not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary Apps16 output');need(not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'source output outside maintained factory');
 if carrier is not None:
  carrier=canonical(api,carrier);need(not output.is_relative_to(carrier)and not carrier.is_relative_to(output),'source output outside carrier input')
 result=render(api,predecessor,unbound,carrier);output.mkdir(mode=0o700)
 for n,b in sorted(result.items()):p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 need({n:api['pin'](b)for n,b in api['files'](output).items()}=={n:api['pin'](b)for n,b in result.items()},'whole emitted561 equality');return dict(status='SOURCE_ONLY_EXACT561_APPS16_UNBOUND_NOT_DISPATCHABLE'if unbound else'SOURCE_ONLY_EXACT561_APPS16_INPUTS_NOT_GUI_ACCEPTANCE',files=561,source=None if unbound else'd34854151f578547c2f64f46d14f5d9129bf2d66',previous_source='601195b401668f92cec35772f1ad4c3eb00e6d21',actual=None,native_GUI='NOT_RUN',hardware='NOT_RUN',default='UNCHANGED540')
