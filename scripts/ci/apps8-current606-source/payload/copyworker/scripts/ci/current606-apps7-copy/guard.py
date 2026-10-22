# SPDX-License-Identifier: MIT
"""Complete source comparison and explicit selected-Welcome target semantics."""
import copy,os,re,stat
from pathlib import Path
import contract as C
DYNAMIC=('filesystem_free_bytes','filesystem_free_inodes')
NAME='cachy-asahi-apps';DB='var/lib/pacman/local'

def observation(value):
 C.need(type(value)is dict and value.get('complete')is True and type(value.get('nodes'))is dict and len(value['nodes'])<=C.BOUNDS['max_nodes'],'complete bounded source graph')
 C.need(type(value.get('unsupported_counts'))is dict and type(value.get('unsupported'))is list,'explicit unsupported inventory')
 # Absolute aliases and ldconfig remain checked by the original selected copier.
 # This comparator grants no eligibility and cannot remove unsupported rows.
 # The source observer emits tuples; its authenticated JSON map encodes them
 # as arrays. Canonicalize ONLY this declared sequence, retaining every member,
 # ordering/cardinality and every other graph/metadata field for full equality.
 groups=value.get('hardlink_groups',{})
 C.need(type(groups)is dict and len(groups)<=C.BOUNDS['max_nodes'],'bounded source hardlink groups')
 for key,group in groups.items():
  C.need(type(key)is str and type(group)is dict,'source hardlink group shape')
  members=group.get('members');nlink=group.get('nlink')
  C.need(type(members)in(list,tuple)and type(nlink)is int and 2<=nlink<=C.BOUNDS['max_nodes']and len(members)==nlink,'source hardlink member cardinality')
  C.need(all(type(n)is str for n in members)and list(members)==sorted(set(members))and key==members[0],'source hardlink member order/identity')
 result=copy.deepcopy(value)
 for group in result.get('hardlink_groups',{}).values():group['members']=tuple(group['members'])
 footprint=result['footprint']
 for name in DYNAMIC:
  C.need(name in footprint and(footprint[name]is None or type(footprint[name])is int and footprint[name]>=0),'explicit fresh filesystem capacity counter')
  del footprint[name]
 return result

def same_source(before,after):
 C.need(observation(before)==observation(after),'complete source graph/hardlinks/auxiliary/metadata changed')
 return True

def inventory(rows,expected,version='0.1.0-6'):
 C.need(type(rows)is dict and type(expected)is dict and len(expected)==606 and expected.get(NAME)=='0.1.0-6','genuine606 baseline package map')
 target=dict(expected)
 if version is None:del target[NAME]
 else:C.need(version in('0.1.0-6','0.1.0-7','0.1.0-8'),'only selected Welcome4/5');target[NAME]=version
 C.need(rows==target and len(rows)==(605 if version is None else 606),'all other605 packages protected')
 return target

def selected_paths(paths):
 C.need(type(paths)is list and 0<len(paths)<=100000 and len(paths)==len(set(paths)),'complete selected archive path set')
 for name in paths:
  C.need(type(name)is str and name and not name.startswith('/')and Path(name).as_posix()==name and not{'.','..'}&set(name.split('/')),'contained selected archive path')
  C.need(not name.startswith(('home/','root/','etc/pacman.d/gnupg/'))and name!=DB and not name.startswith(DB+'/'),'selected payload cannot authorize user/trust/database change')
 return set(paths)

def target_failure(before,after,selected):
 """Existing logical maps only; never content, authority or a second FS scan."""
 try:
  import hashlib,json,sys
  C.need(type(before)is dict and type(after)is dict and max(len(before),len(after))<=C.BOUNDS['max_nodes'],'bounded existing target maps')
  first=None;count=0;categories={'PROTECTED_RAW_DB':0,'PROTECTED_PAYLOAD_OR_UNOWNED':0}
  for name in before.keys()|after.keys():
   if selected(name)or before.get(name)==after.get(name):continue
   C.need(type(name)is str and len(name)<=4096,'bounded original target key');count+=1;first=name if first is None or name<first else first
   categories['PROTECTED_RAW_DB'if name==DB or name.startswith(DB+'/')else'PROTECTED_PAYLOAD_OR_UNOWNED']+=1
  C.need(first is not None,'protected mismatch only')
  left,right=before.get(first),after.get(first);C.need(all(v is None or type(v)is dict for v in(left,right)),'original node metadata')
  fields=sorted(k for k in(left or{}).keys()|(right or{}).keys()if(left or{}).get(k)!=(right or{}).get(k))
  C.need(all(type(k)is str and len(k)<=64 for k in fields),'bounded source node fields')
  def pin(value):
   if value is None:return None
   raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode();C.need(len(raw)<=32768,'bounded node pin');return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  value=dict(schema_version=1,status='PROTECTED_TARGET_MISMATCH_DATA_NOT_ACCEPTANCE',scope='SOURCE_ENFORCED_OTHER605_AND_UNOWNED_LOGICAL_NODES_RAW_DB',different_nodes=count,categories=categories,first_key=first[:256],first_key_truncated=len(first)>256,first_key_sha256=hashlib.sha256(first.encode()).hexdigest(),first_category='PROTECTED_RAW_DB'if first==DB or first.startswith(DB+'/')else'PROTECTED_PAYLOAD_OR_UNOWNED',kind='MISSING'if right is None else'EXTRA'if left is None else'CHANGED',fields=fields[:16],fields_omitted=max(0,len(fields)-16),before=pin(left),after=pin(right),content='NOT_EXPORTED',private_maps='NOT_EXPORTED_OR_INDEPENDENTLY_REPLAYED',acceptance_authority=False,cleanup_authority=False)
  raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False);C.need(len(raw.encode())<=4096,'bounded target mismatch DATA');sys.stderr.write('CURRENT606_TARGET_FAILURE '+raw+'\n');sys.stderr.flush()
 except Exception:pass # Only DATA can be lost; original need is re-raised.

def target(before,after,*,old_paths,new_paths,old_database,new_database):
 """Protect every nonselected row, including unknown/unowned files and DBs.

 Only selected payload paths and one fully supplied selected ALPM record tree
 may differ. Shared parent directories keep type/mode/uid/gid and all graph
 fields; root observation does not contain directory mtimes. No blanket DB,
 /etc, user, trust, cache, symlink or hardlink exemption is introduced.
 """
 a,b=before['nodes'],after['nodes'];selected=selected_paths(old_paths)|selected_paths(new_paths)
 dbs=[]
 for name in(old_database,new_database):
  if name is None:continue
  C.need(type(name)is str and re.fullmatch(r'var/lib/pacman/local/cachy-asahi-apps-0\.1\.0-[678]',name),'exact selected DB directory')
  dbs.append(name)
 def selected_node(name):return name in selected or any(name==d or name.startswith(d+'/')for d in dbs)
 for name in a.keys()|b.keys():
  left,right=a.get(name),b.get(name)
  if selected_node(name):
   # A shared directory is never a selected package-owned content waiver.
   if left and right and left.get('type')==right.get('type')=='directory':C.need(left==right,'selected directory metadata changed')
   continue
  try:C.need(left==right,'protected605/unowned node or raw DB changed')
  except ValueError:
   target_failure(a,b,selected_node)
   raise
 for label,value in(('before',before),('after',after)):
  C.need(value.get('complete')is True and value.get('unsupported_counts')==before.get('unsupported_counts'),'complete target observation required: '+label)
 # Selected hardlinks must not escape into the protected graph.
 for value in(before,after):
  for group in value.get('hardlink_groups',{}).values():
   members=group['members'];flags=[selected_node(n)for n in members]
   C.need(not any(flags)or all(flags),'selected/protected cross hardlink refused')
 return True

def fixed_maprefs(value):
 C.need(type(value)is dict and set(value)==set(C.MAPS),'four exact private map refs')
 total=0
 for name,row in value.items():
  C.need(type(row)is dict and set(row)=={'path','bytes','sha256'}and row['path']==str(C.PROOF_ROOT/(name.replace('_','-')+'.json')),'fixed private map path')
  C.need(type(row['bytes'])is int and 0<row['bytes']<=C.MAP_BYTES and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded private map pin');total+=row['bytes']
 C.need(total<=C.ALL_MAP_BYTES,'aggregate private map byte bound')
 return value


def package_inventory(rows):
 C.need(type(rows)is list and len(rows)==606,'complete original606 database rows')
 inventory={}
 for row in rows:
  C.need(type(row)is dict and set(row)=={'name','version','arch','depend','provides','conflict','files'},'original database API row')
  C.need(type(row['name'])is str and re.fullmatch('[a-z0-9][a-z0-9+_.-]{0,127}',row['name'])and row['name']not in inventory and type(row['version'])is str and 0<len(row['version'])<=128 and not any(c.isspace()for c in row['version']),'exact distinct package identity')
  C.need(row['arch']in('aarch64','any')and all(type(row[k])is list and len(row[k])<=100000 and all(type(v)is str for v in row[k])for k in('depend','provides','conflict','files')),'complete bounded ownership/dependency arrays')
  inventory[row['name']]=row['version']
 return inventory
