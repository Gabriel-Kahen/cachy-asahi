# SPDX-License-Identifier: MIT
"""Exact finite Apps13→Apps14 source option; no current GUI authority."""
import ast,base64,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':510072,'sha256':'217ea87b675b25212e81411ee61ad85734b4539900986ff84f4806d9df19b32c'}
WF='.github/workflows/native-arm-current606-welcome8-gui.yml';ALIAS='.github/workflows/native-arm-build.yml'
RENAMES={n:n.replace('apps13','apps14')for n in('apps13_common.py','apps13_inputs.py','apps13-selection.json','apps13-recipe-map.json','apps13-parent.json','factory/apps13_runtime.py','factory/apps13-installed-profile.json','factory/apps13_diagnostic.py')}
def inputs(api):
 need,pin,read,files=(api[k]for k in('need','pin','ordinary','files'));need(not sys.flags.optimize,'source assertions required');raw=read(HERE/'apps14-profile.json');need(pin(raw)==PROFILE,'whole pinned Apps14 profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_GUI559_APPS14_OPTION_NOT_NATIVE'and p['actual']is None and p['limits']==dict(GUI_CLI=35,inventory=30,fresh_scans=2),'finite source-only profile and original clocks');raw=read(HERE/'apps14-maps.json');need(pin(raw)==p['maps'],'whole source maps');maps=json.loads(raw);need(len(maps['before'])==len(maps['selected'])==len(maps['unbound'])==559,'three complete559 maps');payload=files((HERE/'apps14-payload').absolute());need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole readable used Apps14 payload')
 sources=dict(parent='a0c8eb9ccb2994cf2f7156a6e66bfc9715b9e464',output='803ed9c5c0357162ef9868bf6f82d37936ba7842',carrier='9fc95ae7694bfb67d8d1e8065303a5b1770b4b55',recipe='2e58341f6fa25de5167fd8a59566b3dd7f066fe3',native='5bbf9b2078d67d5543d01a849144fbd5696fa677')
 for k,w in sources.items():
  c,g=p['custody'][k]['publication'],p['custody'][k]['git'];need(c['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and g['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and c['source']==g['source']==w and c['ref']==g['ref']and c['files']==c['git_joins']==len(g['files'])and c['actual']==c['hardware']=='NOT_RUN'and c['release']=='NOT_ADMITTED','whole genuine historical source/Git custody '+k)
 need(p['custody']['parent']['git']['files']==maps['before']and p['custody']['output']['git']['files']==maps['selected']and p['parent_context']==dict(publication=p['custody']['parent']['publication'],authorization=maps['before'],git=p['custody']['parent']['git']),'whole559 parent/result publication context');s=p['selection'];q=s['selection'];need(s['status']=='ROOT_BOUND_ACCEPTED_APPS14_INPUTS_ONLY_NO_GUI_AUTHORITY'and s['actual_source']is s['actual_ref']is s['actual_run']is q['actual']is None and q['source']==sources['carrier']and q['files']==p['custody']['carrier']['git']['files']and len(q['files'])==94 and q['recipe_source']==sources['recipe']and q['pair_source']==sources['native']and q['pair_ref']=='codex/apps14-pair-native-v1'and q['pair_run']==39788418793 and q['package']==dict(name='cachy-asahi-apps',version='0.1.0-14',archive='cachy-asahi-apps-0.1.0-14-any.pkg.tar.xz',size=28636,sha256='afd8b4c8f948aa4041383eaaf1b88f90934c7a5262e645e67f306b5d43d33b65'),'only genuine Apps14 accepted input, never GUI authority');need(json.loads(payload['apps14-recipe-map.json'])==p['custody']['recipe']['git']['files'],'whole original42 recipe');return p,maps,payload

def canonical(api,path):
 p=Path(path).absolute();api['need'](str(p)==os.path.normpath(str(p))and '..'not in p.parts and not any(q.is_symlink()for q in(p,*p.parents)),'canonical ordinary path before disjointness');return p

def render(api,predecessor,unbound=False):
 need,pin,enc,files=(api[k]for k in('need','pin','encoded','files'));predecessor=canonical(api,predecessor);p,maps,payload=inputs(api);before=files(predecessor);need({n:pin(b)for n,b in before.items()}==maps['before'],'whole genuine559 Apps13 predecessor');out=dict(before);value=p['null_selection']if unbound else p['selection'];s=value['selection']
 def once(t,a,b):need(t.count(a)==1,'one exact Apps14 source operand '+a[:90]);return t.replace(a,b,1)
 def roles(t):return t.replace('Apps13','Apps14').replace('APPS13','APPS14').replace('apps13','apps14')
 for a,b in RENAMES.items():out[b]=out.pop(a)
 for n in('input606.py','native.py','factory/factory.py','factory/current_products.py'):out[n]=roles(out[n].decode()).encode()
 out.update(payload)
 if s is not None:
  text=out['apps14_common.py'].decode()
  for n,v in [('PAIR',s['pair_source']),('PAIR_REF',s['pair_ref']),('RUN',s['pair_run'])]:text=once(text,n+'=None',n+'='+repr(v))
  out['apps14_common.py']=text.encode()
 out['apps14-selection.json']=enc(value);row=dict(name='cachy-asahi-apps',version='0.1.0-14',archive='cachy-asahi-apps-0.1.0-14-any.pkg.tar.xz',size=None,sha256=None)if unbound else s['package'];req=json.loads(out['input-policy33.json']);need(req['packages']['cachy-asahi-apps']['version']=='0.1.0-13','one exact old Apps13 operand');req['packages']['cachy-asahi-apps']=row;out['input-policy33.json']=enc(req)
 oldhash=pin(out['factory/expected606.lock'])['sha256'];out['factory/expected606.lock']=once(out['factory/expected606.lock'].decode(),'cachy-asahi-apps 0.1.0-13\n','cachy-asahi-apps 0.1.0-14\n').encode();newhash=pin(out['factory/expected606.lock'])['sha256'];out['factory/install606.py']=once(out['factory/install606.py'].decode(),oldhash,newhash).encode();profile=json.loads(out['factory/profile.json']);profile['versions']['cachy-asahi-apps']='0.1.0-14';profile['native_archives']['cachy-asahi-apps']=None if unbound else dict(bytes=row['size'],sha256=row['sha256']);profile['expected606']=pin(out['factory/expected606.lock']);out['factory/profile.json']=enc(profile)
 out[WF]=once(roles(out[WF].decode()),'d96be268f3b24af6e94cfbf662c131303d22931c','UNBOUND_APPS14_ACCEPTED_CARRIER_DO_NOT_DISPATCH'if unbound else s['source']).encode();out[ALIAS]=out[WF];changed={n for n in before if n not in out or out[n]!=before[n]}|{'source-manifest.json','apps13-parent.json'};out['apps14-parent.json']=enc(dict(source=p['custody']['parent']['publication']['source'],actual=None,files=maps['before'],before_bodies={n:base64.b64encode(before[n]).decode()for n in sorted(changed)},context=p['parent_context']));out['source-manifest.json']=enc(dict(status='SOURCE_ONLY_CURRENT606_WELCOME8_APPS14_NO_NEW_GUI_ACCEPTANCE',files={n:pin(b)for n,b in sorted(out.items())if n!='source-manifest.json'},actual_source=None,actual_ref=None,actual_run=None));need({n:pin(b)for n,b in out.items()}==maps['unbound'if unbound else'selected'],'whole exact559 equality before output');need(sum(n in out and before[n]==out[n]for n in before)==539 and out[WF]==out[ALIAS],'all539 held and both workflow aliases byteequal')
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 return out

def emit(api,predecessor,output,unbound=False):
 # Reject noncanonical spellings and aliases BEFORE lexical ancestry comparison.
 predecessor=canonical(api,predecessor);output=canonical(api,output);need=api['need'];need(predecessor.is_dir()and not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary Apps14 output');result=render(api,predecessor,unbound);output.mkdir(mode=0o700)
 for n,b in sorted(result.items()):p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 need({n:api['pin'](b)for n,b in api['files'](output).items()}=={n:api['pin'](b)for n,b in result.items()},'whole emitted559 equality');return dict(status='SOURCE_ONLY_EXACT559_APPS14_UNBOUND_NOT_DISPATCHABLE'if unbound else'SOURCE_ONLY_EXACT559_APPS14_INPUTS_NOT_GUI_ACCEPTANCE',files=559,source=None if unbound else'803ed9c5c0357162ef9868bf6f82d37936ba7842',previous_source='a0c8eb9ccb2994cf2f7156a6e66bfc9715b9e464',actual=None,native_GUI='NOT_RUN',hardware='NOT_RUN',default='UNCHANGED540')
