#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Audit the reviewed finite command list in the exact selected rootfs DATA."""
import argparse,importlib.util,json,re
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def resolve(nodes,selected,path):
 visited=[]
 for _ in range(16):
  if path not in selected or path not in nodes or path in visited:raise ValueError('missing/linked-loop selected tool: '+path)
  visited.append(path);node=nodes[path]
  if node['type']=='0':
   if not node['mode']&0o111:raise ValueError('selected tool is not executable: '+path)
   return {'path':path,'mode':node['mode'],'resolution':visited}
  if node['type']not in ('1','2'):raise ValueError('selected tool is not regular/link: '+path)
  target=PurePosixPath(node['link']);parts=[]
  components=target.parts[1:]if target.is_absolute()else((*PurePosixPath(path).parent.parts,*target.parts)if node['type']=='2'else target.parts)
  for part in components:
   if part in ('','.'):continue
   if part=='..':
    if not parts:raise ValueError('tool link escapes guest root')
    parts.pop()
   else:parts.append(part)
  path='/'.join(parts)
 raise ValueError('tool link depth')


def verify(rootfs,base,closure):
 I=load('project_tool_inputs',HERE/'inputs.py');_,reference,_=I.reference();review=json.loads((HERE/'tools.lock.json').read_text())
 for name,ref in review['reviewed_source'].items():I.checked(HERE/name,ref)
 # The command inventory is manually source-audited and bound to those exact
 # scripts. Future new commands require a new explicit inventory review.
 match=re.search(r'^BASE_TOOLS=\(([^\n]+)\)$',(HERE/'guest-runtime.sh').read_text(),re.M)
 if not match or match[1].split()!=review['baseline_tools']:raise ValueError('fixed tool guard/review differs')
 D=load('project_rootfs_reader',reference/'inspect_inputs.py');S=load('project_rootfs_selector',reference/'select_guest.py')
 index=D.rootfs(rootfs);selection=S.select(index)
 actual=sorted((row['name'],row['version'])for row in selection['packages']);wanted=sorted((row['name'],row['version'])for row in base['base_packages'])
 if len(actual)!=111 or actual!=wanted:raise ValueError('tool audit requires exact selected111 namespace')
 selected=set(selection['paths']);facts={};owners={}
 for row in selection['packages']:
  files=index['packages'][row['directory']]['files'].get('FILES',[])
  for path in files:owners.setdefault(path.rstrip('/'),[]).append(row['name']+'='+row['version'])
 for tool in review['baseline_tools']:
  value=resolve(index['nodes'],selected,'usr/bin/'+tool);value['owners']=owners[value['path']];facts[tool]=value
 post={}
 for tool,package in review['post_install_tools'].items():
  payload=closure['packages'][package]['payload'];value=resolve(payload,set(payload),'usr/bin/'+tool);value['owner']=package;post[tool]=value
 return {'schema_version':1,'reviewed_source':review['reviewed_source'],'rootfs':index['rootfs'],'baseline_packages':111,'baseline_tools':facts,'post_install_tools':post,'command_review':'manual finite command inventory, source hashes bound; builtins/functions enumerated separately','builtins_and_functions':review['builtins_and_functions'],'guest_execution':'NOT RUN'}


if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rootfs',type=Path,required=True);p.add_argument('--base',type=Path,required=True);p.add_argument('--materials',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 I=load('project_tool_cli_inputs',HERE/'inputs.py');base=json.loads((a.base/'prepared.json').read_text());result=verify(a.rootfs,base,I.closure(a.materials,base))
 with a.output.open('x')as out:json.dump(result,out,indent=2,sort_keys=True);out.write('\n')
 print(json.dumps({'baseline_tools':len(result['baseline_tools']),'post_install_tools':len(result['post_install_tools']),'guest_execution':'NOT RUN'}))
