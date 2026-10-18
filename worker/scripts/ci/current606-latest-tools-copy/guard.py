# SPDX-License-Identifier: MIT
"""Exactly two selected packages; complete protection for every other604 row."""
import copy,re
import contract as C
NAMES={'apps':'cachy-asahi-apps','welcome':'cachy-asahi-welcome'}
BASE={'apps':'0.1.0-6','welcome':'0.1.0-4'}
VERSIONS={'apps':{'0.1.0-6','0.1.0-7',None},'welcome':{'0.1.0-4','0.1.0-5',None}}
DYNAMIC=('filesystem_free_bytes','filesystem_free_inodes')

def observation(value):
 C.need(type(value)is dict and value.get('complete')is True and type(value.get('nodes'))is dict and len(value['nodes'])<=C.BOUNDS['max_nodes'],'complete bounded graph')
 C.need(type(value.get('unsupported_counts'))is dict and type(value.get('unsupported'))is list,'explicit unsupported rows');result=copy.deepcopy(value)
 for n in DYNAMIC:
  v=result['footprint'].pop(n);C.need(v is None or type(v)is int and v>=0,'explicit dynamic capacity scalar')
 return result
def same_source(before,after):C.need(observation(before)==observation(after),'complete source606 graph changed');return True
def package_inventory(rows):
 import roles
 return roles.load('apps')['guard'].package_inventory(rows)
def inventory(rows,expected,versions=None):
 versions=BASE if versions is None else versions
 C.need(type(versions)is dict and set(versions)==set(BASE)and type(expected)is dict and len(expected)==606 and all(expected.get(NAMES[k])==v for k,v in BASE.items()),'exact606 original Apps6/Welcome4 inventory')
 C.need(all(v in VERSIONS[k]for k,v in versions.items())and sum(v is None for v in versions.values())<=1,'never remove both selected packages')
 target=dict(expected)
 for k,v in versions.items():
  if v is None:target.pop(NAMES[k])
  else:target[NAMES[k]]=v
 C.need(rows==target and len(rows)in(605,606),'complete other604/current selected package inventory');return target
def selected_paths(paths):
 import roles
 return roles.load('apps')['guard'].selected_paths(paths)
def selected(name,paths):
 return name in paths or any(name==d or name.startswith(d+'/')for d in DATABASES)
DATABASES=tuple('var/lib/pacman/local/'+NAMES[k]+'-'+v for k in BASE for v in VERSIONS[k]if v is not None)
def target(before,after,paths):
 paths=selected_paths(sorted(paths));a,b=before['nodes'],after['nodes']
 for n in a.keys()|b.keys():
  left,right=a.get(n),b.get(n)
  if selected(n,paths):
   if left and right and left.get('type')==right.get('type')=='directory':C.need(left==right,'selected directory metadata changed')
  else:C.need(left==right,'protected604/unowned/rawDB changed')
 for value in(before,after):
  C.need(value.get('complete')is True and value.get('unsupported_counts')==before.get('unsupported_counts'),'complete target observation')
  for group in value.get('hardlink_groups',{}).values():
   flags=[selected(n,paths)for n in group['members']];C.need(not any(flags)or all(flags),'selected/protected cross hardlink')
 return True
def fixed_maprefs(value):
 import roles
 return roles.load('apps')['guard'].fixed_maprefs(value)
