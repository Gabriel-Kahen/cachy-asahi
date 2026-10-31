# SPDX-License-Identifier: MIT
"""Explicit complete GUI559→561 failed-resource cleanup source route; no actors."""
import ast,base64,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 300564, 'sha256': '1992a0179ab8f8b932aff6c682f8b90e993cc08d4f228a4cfea98d14ec587ee1'}

def canonical(api,path):
 path=Path(path).absolute();api['need'](path==path.resolve()and not any(q.is_symlink()for q in(path,*path.parents)),'canonical ordinary input/output before disjointness');return path

def inputs(api):
 read,pin,need=(api[k]for k in('ordinary','pin','need'));raw=read(HERE/'failure-cleanup-profile.json');need(pin(raw)==PROFILE,'whole failure-cleanup profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_GUI_FAILURE_CLEANUP561'and p['actual']is None and p['before_source']=='803ed9c5c0357162ef9868bf6f82d37936ba7842'and p['after_source']=='601195b401668f92cec35772f1ad4c3eb00e6d21'and p['after_ref']=='codex/welcome8-gui-failure-cleanup-v1','exact genuine cleanup source identity')
 need((len(p['before']),len(p['after']),len(p['held']),len(p['payload']))==(559,561,553,6)and {n:w for n,w in p['before'].items()if p['after'].get(n)==w}==p['held'],'whole553 held and finite cleanup-only operands');payload=api['files'](canonical(api,HERE/'failure-cleanup-payload'));need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole readable used cleanup payload');return p,payload

def emit(api,parent,output):
 parent=canonical(api,parent);output=canonical(api,output);need,pin,files,enc=(api[k]for k in('need','pin','files','encoded'));need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(parent)and not parent.is_relative_to(output)and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary source/factory disjoint output before writes');p,payload=inputs(api);before=files(parent);need({n:pin(b)for n,b in before.items()}==p['before'],'whole genuine559 before cleanup output');result=dict(before);result.update(payload);ctx=dict(publication=p['parent_publication'],authorization=p['before'],git=dict(p['parent_git'],files=p['before']));result['failure-cleanup-parent.json']=enc(dict(source=p['before_source'],ref='codex/welcome8-apps14-gui-v1',actual=None,files=p['before'],before_bodies={n:base64.b64encode(before[n]).decode()for n in p['before_bodies']},context=ctx));manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in sorted(result.items())if n!='source-manifest.json'};need(manifest['actual_source']is manifest['actual_ref']is manifest['actual_run']is None,'source actual authority remains NULL');result['source-manifest.json']=enc(manifest);need({n:pin(b)for n,b in result.items()}==p['after'],'whole exact561 before any output')
 for n,b in result.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 need({n:pin(b)for n,b in files(parent).items()}==p['before'],'fresh whole parent revalidation before writes');output.mkdir(mode=0o700)
 for n,b in sorted(result.items()):q=output/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
 need({n:pin(b)for n,b in files(output).items()}==p['after'],'whole emitted561 equality');return dict(status='SOURCE_ONLY_GUI_FAILURE_CLEANUP561_NO_GUI_ACCEPTANCE',files=561,source=p['after_source'],ref=p['after_ref'],actual_source=None,actual_ref=None,actual_run=None,positive15='UNCHANGED',failure_retirement='SEPARATE_RESOURCE_PROOF_ONLY',default='UNCHANGED540')
