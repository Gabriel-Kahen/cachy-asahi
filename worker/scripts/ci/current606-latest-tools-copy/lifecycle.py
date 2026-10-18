# SPDX-License-Identifier: MIT
"""One finite joint flow; never change Runtime1 or remove both selected tools."""
import contract as C,guard as G,physical
PHASES=(('baseline',None,None),('apps7','apps','0.1.0-7'),('joint-latest','welcome','0.1.0-5'),('same-apps7','apps','0.1.0-7'),('same-welcome5','welcome','0.1.0-5'),('remove-apps7','apps',None),('reinstall-apps7','apps','0.1.0-7'),('remove-welcome5','welcome',None),('reinstall-welcome5','welcome','0.1.0-5'),('restore-original4','welcome','0.1.0-4'),('restore-original6','apps','0.1.0-6'))

def operands(plans,apis):
 C.need(type(plans)is dict and set(plans)=={'apps','welcome'},'two exact archive-derived plans')
 a,w=plans['apps'],plans['welcome'];apps=apis['apps']['lifecycle'].operands(a['original6'],a['new7'],original606_manifest=a['original606_manifest']);welcome=apis['welcome']['lifecycle'].operands(w['original4'],w['new5'],original604_manifest=w['original604_manifest'])
 C.need(a['original6']['source_record']['original_manifest']==w['original4']['source_record']['original_manifest'],'both original restore operands from SAME actual producer604 manifest')
 C.need(a['original6']['signer']==w['original4']['signer']==w['new5']['signer'],'same producer TEST signer for original6/4 and freshly built5')
 return {'apps':apps,'welcome':welcome}

def readback(initial,current,*,expected,versions,products,paths):
 G.inventory(current['inventory'],expected,versions);G.target(initial['observation'],current['observation'],paths)
 physical.protected(initial['physical'],current['physical'],initial['observation']['nodes'],current['observation']['nodes'],lambda n:G.selected(n,paths),lock_witness=current.get('lock_parent'))
 C.need({n:v for n,v in initial['capabilities'].items()if n not in paths}=={n:v for n,v in current['capabilities'].items()if n not in paths}and not any(n in current['capabilities']for n in paths),'all protected604 capabilities; selected tools add none')
 nodes=current['observation']['nodes']
 for role,version in versions.items():
  dirs=C.APPS_DIRS if role=='apps'else C.WELCOME_DIRS;files=C.APPS_FILES if role=='apps'else C.WELCOME_FILES
  if version is None:C.need(not any(n in nodes for n in(*dirs,*files)),'removed selected tool remains');continue
  for n in dirs:C.need(nodes.get(n)==dict(type='directory',mode=0o755,uid=0,gid=0),'selected exclusive directory metadata')
  for n,w in products[role][version]['payload'].items():
   r=nodes.get(n);C.need(r and r['type']=='file'and r['uid']==r['gid']==0 and r.get('bytes')==w['size']and all(r.get(k)==w[k]for k in('mode','sha256')),'exact selected archive payload')
  C.need(current['selected_database_validated'].get(role)is True,'complete current selected DB required')
 return dict(count=len(current['inventory']),versions=dict(versions),other604='FULL_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPS_PROTECTED',source606='UNCHANGED_SEPARATE_READBACK_REQUIRED',selected_db='COMPLETE_CURRENT_ALPM_NOT_HISTORICAL_INODE')

def step_preserved(previous,current,active,apis):
 """Protect all nonactive605 against the immediately preceding full readback."""
 C.need(active in G.BASE,'one exact active transaction role')
 name=G.NAMES[active];before=previous['inventory'];after=current['inventory']
 other=lambda rows:{n:v for n,v in rows.items()if n!=name}
 C.need(len(other(before))==605 and other(before)==other(after),'per-step exact inactive605 package versions')
 paths=set(C.APPS_FILES)|set(C.APPS_DIRS)if active=='apps'else set(C.WELCOME_FILES)|set(C.WELCOME_DIRS)
 def database(rows):
  version=rows.get(name)
  return None if version is None else 'var/lib/pacman/local/'+name+'-'+version
 databases=[d for d in(database(before),database(after))if d is not None]
 def selected(n):return n in paths or any(n==d or n.startswith(d+'/')for d in databases)
 apis[active]['guard'].target(previous['observation'],current['observation'],old_paths=sorted(paths),new_paths=sorted(paths),old_database=database(before),new_database=database(after))
 physical.protected(previous['physical'],current['physical'],previous['observation']['nodes'],current['observation']['nodes'],selected,lock_witness=current.get('lock_parent'))
 C.need({n:v for n,v in previous['capabilities'].items()if not selected(n)}=={n:v for n,v in current['capabilities'].items()if not selected(n)},'per-step exact inactive605 capabilities')
 return dict(status='PASS_PREVIOUS_TO_CURRENT_OTHER605',active=active,protected_packages=605,inventory='EXACT_OTHER605',nodes_raw_db='EXACT_ALL_NONSELECTED',physical='FULL_INODE_HARDLINK_WITH_SELECTED_PARENT_AND_LOCK_WITNESSES',capabilities='EXACT_ALL_NONSELECTED',scope='SOURCE_ENFORCED_PRIVATE_MAPS_NOT_EXPORTED')

def exercise(*,expected,plans,apis,observe,transact,fixtures,source_unchanged):
 products=operands(plans,apis);versions=dict(G.BASE);initial=observe(versions);G.inventory(initial['inventory'],expected);previous=initial;events=[]
 paths=set(C.APPS_FILES)|set(C.WELCOME_FILES)|set(C.APPS_DIRS)|set(C.WELCOME_DIRS)
 for phase,role,version in PHASES:
  if role is not None:
   tx=transact(phase,role,previous['inventory'],None if version is None else products[role][version]);C.need(tx['returncode']==0 and tx['direct_child_reaped']is True and tx['group_retired']is True,'real selected child retirement before readback');versions[role]=version
  current=observe(versions);event=readback(initial,current,expected=expected,versions=versions,products=products,paths=paths);event['step605']='NOT_RUN_BASELINE'if role is None else step_preserved(previous,current,role,apis);event['transaction']='NOT_RUN_BASELINE'if role is None else dict(selected=role,**tx)
  checks=fixtures(phase,versions,products);required={k for k,v in versions.items()if v is not None};C.need(set(checks)==required,'both installed selected tools required')
  for k,value in checks.items():
   C.need(value.get('zero_capabilities')is True and value.get('NNP')==1 and set(value.get('homes',{}))=={'fresh','existing'},'ordinary zero-cap/NNP checks in both homes')
   want=dict(CLI=2,inventory_count=len(current['inventory']),installed_controls='NOT_RUN_ORIGINAL15_REQUIRES606_DOMAIN'if len(current['inventory'])==605 else 15 if versions[k]=='0.1.0-7'else 0)if k=='apps'else dict(CLI=5,report=12 if versions[k]=='0.1.0-5'else 8)
   C.need(value['homes']=={h:want for h in('fresh','existing')},'full actual selected tool assertions/counts')
  event['fixtures']=checks;event['Apps606_fixture']='REQUIRED'if'apps'in required and len(current['inventory'])==606 else'NOT_RUN_REMOVED_OR_TRANSIENT605';current=observe(versions);readback(initial,current,expected=expected,versions=versions,products=products,paths=paths)
  C.need(source_unchanged()is True,'complete original source606 changed');events.append(dict(phase=phase,**event));previous=current
 return dict(status='JOINT_LATEST_COPY_COMPLETED_REQUIRES_OUTER_DISPOSAL',events=events,counts=[r['count']for r in events],restoration='EXACT_SAME_PRODUCER_ORIGINAL4_AND_ORIGINAL6_PAYLOAD_CURRENT_DB',Runtime1='PROTECTED_NO_TRANSACTION',hardware='NOT_RUN',release='NOT_ADMITTED')
