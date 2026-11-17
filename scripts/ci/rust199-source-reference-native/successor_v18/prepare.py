#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Exact signed build-dependency Source successor; HOLD without complete inputs."""
import argparse,ast,hashlib,importlib.util,json,resource
from pathlib import Path
HERE=Path(__file__).resolve().parent
helper=HERE.parent/'filesystem.py'
if hashlib.sha256(helper.read_bytes()).hexdigest()!='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':raise ValueError('held filesystem helper differs')
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fs=module('v18_source_filesystem',helper);fs.MAX_FILES=512
D=module('v18_exact_source_delta',HERE/'delta.py')
PARENT=dict(files=367,bytes=43757093,tree='f846369139e03239d500cb737092b5eeb358c260',map_sha256='189430cae42422e8f50d8de38a41976d87a8b4a0fcec527a3949d6031eccc2f6')
ACTUAL=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
SCOPE='RUST199_SIGNED_BUILD_DEPENDENCY_SUCCESSOR_V18';MARKER='signed-build-dependencies-v18.json';ARCHIVE='previous-v17/'
REPLACED=set(D.PATCHES)

def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def identity(files):return dict(files=len(files),bytes=sum(len(raw)for raw,mode in files.values()),tree=fs.tree(files),map_sha256=fs.pin(files['source-map.json'][0])['sha256'])
def capture(root):
 files=fs.snapshot(root);fs.need(identity(files)==PARENT,'whole genuine367 parent bytes/modes/tree/map');fs.need(fs.decode(files['source-map.json'][0])['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'complete367 parent namespace');return files

def payload():
 files=fs.snapshot(HERE/'payload');fs.need('hosted/build-dependencies.json'in files,'HOLD: compatible signed dependency closure unavailable')
 raw,mode=files['hosted/build-dependencies.json'];p=fs.decode(raw)
 fs.need(type(p.get('schema'))is int and p['schema']==18 and p.get('status')=='PINNED_SIGNED_ALARM_BUILD_DEPENDENCIES_DATA_ONLY'and p.get('actual')==dict.fromkeys(('source','ref','run','job','image','Root_acceptance','native_acceptance')),'unissued signed build dependency DATA policy')
 declarations=[n for n in ast.parse(files['hosted/build_dependencies.py'][0]).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='POLICY_PIN'for t in n.targets)]
 fs.need(len(declarations)==1 and ast.literal_eval(declarations[0].value)==fs.pin(raw),'whole concrete policy pin; no unavailable or substituted input')
 validator=module('v18_closed_dependency_policy',HERE/'payload/hosted/build_dependencies.py');validator.validate_policy(p)
 rows=p.get('packages');fs.need(type(rows)is list and 1<=len(rows)<=8 and any(r.get('name')=='libgit2'for r in rows),'finite complete missing dependency closure')
 added={'hosted/build_dependencies.py','hosted/build-dependencies.json'}
 for row in rows:
  filename=row['filename'];fs.relative(filename)
  for name,pin in(('build-dependencies/'+filename,row['archive']),('build-dependencies/'+filename+'.sig',row['signature'])):
   fs.need(name not in added and name in files and files[name][1]==0o644 and fs.pin(files[name][0])==pin,'exact original signed dependency input bytes/mode');added.add(name)
  for name,pin in validator.provenance_inputs(row).items():
   fs.relative(name);fs.need(name not in added and name in files and files[name][1]==0o644 and fs.pin(files[name][0])==pin,'exact retained official recipe/source license bytes/mode');added.add(name)
  validator.audit_archive(HERE/'payload/build-dependencies'/filename,row)
 fs.need(set(files)==REPLACED|added and all(mode==0o644 for raw,mode in files.values()),'complete exact finite dependency payload namespace')
 return files,added

def check_delta(before,files):
 fs.need({n:files[n]for n in REPLACED}==D.render_leaves(before),'only exact signed context and actual qualification joins change operationally')

def render(before):
 fs.need(identity(before)==PARENT,'exact367 parent only');new,added=payload();check_delta(before,new)
 fs.need(not added&set(before)and MARKER not in before and not any(n.startswith(ARCHIVE)for n in before),'fresh versioned dependency namespace')
 files=dict(before);changes={}
 for name in sorted(REPLACED|{'source-map.json'}):files[ARCHIVE+name]=before[name]
 for name,row in new.items():changes[name]=dict(before=fs.descriptors({name:before[name]})[name]if name in before else None,after=fs.descriptors({name:row})[name]);files[name]=row
 marker=dict(schema=18,scope=SCOPE,parent=PARENT,kernel_preentry_required=True,manifest_observed_timings_preserved=True,signed_build_dependencies=True,changes=changes,added=sorted(added),archives=sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),recipe_changed=False,resources_changed=False,authority_changed=False,workflows_changed=False,HTTP_changed=False,signed349_changed=False,makepkg_dependency_checks_preserved=True,holds_preserved=True,unadmitted=True,Root_grants=None,dispatch=None,actual=ACTUAL)
 files[MARKER]=(encode(marker),0o644);old=fs.decode(before['source-map.json'][0]);old['files']=fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'});files['source-map.json']=(encode(old),0o644)
 fs.need(undo(files)==before,'complete byte/mode inverse to367');fs.need(all(files[n]==row for n,row in before.items()if n not in REPLACED|{'source-map.json'}),'all recipe/actor-entry/trust/resources/authority/holds unchanged');return files

def undo(files):
 new,added=payload();m=fs.decode(files[MARKER][0]);leaves=REPLACED|added
 fs.need(m['schema']==18 and m['scope']==SCOPE and m['parent']==PARENT and m['kernel_preentry_required']is True and m['manifest_observed_timings_preserved']is True and m['signed_build_dependencies']is True and m['makepkg_dependency_checks_preserved']is True and m['holds_preserved']is True and m['unadmitted']is True and m['Root_grants']is m['dispatch']is None and m['actual']==ACTUAL and all(m[k]is False for k in('recipe_changed','resources_changed','authority_changed','workflows_changed','HTTP_changed','signed349_changed'))and set(m['changes'])==leaves and m['added']==sorted(added)and m['archives']==sorted(ARCHIVE+n for n in REPLACED|{'source-map.json'}),'complete unissued exact dependency inverse marker')
 old_map=files[ARCHIVE+'source-map.json'];fs.need(fs.pin(old_map[0])['sha256']==PARENT['map_sha256'],'whole archived367 map');old=fs.decode(old_map[0]);expected=set(old['files'])|{'source-map.json'};extra={MARKER}|added|{ARCHIVE+n for n in REPLACED|{'source-map.json'}}
 fs.need(set(files)==expected|extra,'closed complete successor namespace');current=fs.decode(files['source-map.json'][0]);fs.need(current['actual']==ACTUAL and current['files']==fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'whole current dependency Source map')
 restored={n:r for n,r in files.items()if n not in extra}
 for n in leaves:
  fs.need(files[n]==new[n]and fs.descriptors({n:files[n]})[n]==m['changes'][n]['after'],'exact dependency replacement/addition')
  if n in REPLACED:restored[n]=files[ARCHIVE+n]
 restored['source-map.json']=old_map;fs.need(identity(restored)==PARENT and old['files']==fs.descriptors({n:r for n,r in restored.items()if n!='source-map.json'}),'all367 original leaves restored');return restored

def inputs():return fs.descriptors({n:r for n,r in fs.snapshot(HERE).items()if n not in('constructor-profile.json','prospective.DATA.json','development-seal.DATA.json')})
def construct(parent,output,expected):
 parent,output=map(fs.absolute,(parent,output));payload();fs.need((HERE/'constructor-profile.json').is_file(),'HOLD: no exact reviewed constructor profile');raw=fs.read(HERE/'constructor-profile.json')[0];fs.need(fs.pin(raw)['sha256']==expected,'external whole constructor profile pin');p=fs.decode(raw)
 fs.need(p['schema']==18 and p['scope']==SCOPE and p['parent']==PARENT and p['actual']==ACTUAL and p['Root_review']is p['accepted']is None and p['unadmitted']is True and p['constructor_files']==inputs(),'complete exact unissued constructor closure')
 fs.need(not any(output.is_relative_to(x)or x.is_relative_to(output)for x in(parent,HERE)),'fresh disjoint Source DATA output');files=render(capture(parent));result=identity(files);fs.need(all(p[k]==v for k,v in result.items()),'whole profiled successor identity');fs.publish(files,output);return dict(schema=18,status=SCOPE,unadmitted=True,actual=ACTUAL,native='NOT RUN',**result)
if __name__=='__main__':
 resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2);p=argparse.ArgumentParser(description=__doc__)
 for k in('parent','output'):p.add_argument('--'+k,type=Path,required=True)
 p.add_argument('--profile-sha256',required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output,a.profile_sha256),sort_keys=True))
