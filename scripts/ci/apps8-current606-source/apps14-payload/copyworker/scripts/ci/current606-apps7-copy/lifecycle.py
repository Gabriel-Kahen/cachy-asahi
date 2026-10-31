# SPDX-License-Identifier: MIT
"""Finite copied606 Welcome protocol; original source606 lifecycle stays outside."""
import hashlib
import contract as C,guard as G,physical
NAME='cachy-asahi-apps'
PHASES=(('baseline6','0.1.0-6'),('upgrade7','0.1.0-7'),('upgrade14','0.1.0-14'),('same-version14','0.1.0-14'),('remove14',None),('reinstall14','0.1.0-14'),('restore7','0.1.0-7'),('restore-original6','0.1.0-6'))

def operands(original6,new7,new14,*,original606_manifest):
 """Version alone never authorizes restoration; exact old manifest row joins."""
 C.need(type(original606_manifest)is dict and original606_manifest.get(NAME)==original6.get('source_record'),'exact ORIGINAL604 Welcome4 archive/signature/payload/provenance row required')
 C.need(original6['source_record']['sha256']==original6['sha256']and original6['source_record']['payload']==original6['payload']and original6['source_record']['version']==original6['version'],'exact original6 row/archive/payload identity')
 C.need(original6['sha256']=='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'and new7['sha256']=='23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39'and new7['signer']=='DA8AD638E79414E661656E4C23132CAA1000DA38','exact original6/native7 public archive and signer identities')
 C.need(original6['version']=='0.1.0-6'and new7['version']=='0.1.0-7'and original6['sha256']!=new7['sha256'],'distinct original6/candidate7 archive identities')
 C.need(len(original6['payload'])==len(new7['payload'])==8 and set(original6['payload'])==set(new7['payload'])==C.APPS_FILES,'whole same owned Welcome payload path set')
 C.need(new14['version']=='0.1.0-14'and type(C.APPS14_PAIR)is dict and set(C.APPS14_PAIR)=={'bytes','sha256'}and new14['sha256']==C.APPS14_PAIR['sha256']and new14['bytes']==C.APPS14_PAIR['bytes'] and len(new14['payload'])==8 and set(new14['payload'])==C.APPS_FILES,'exact independently accepted Apps14 whole archive/payload')
 C.need(__import__('re').fullmatch('[A-F0-9]{40}',new14['signer'])and new14['signer']not in(original6['signer'],new7['signer']),'fresh distinct owned TEST signer for Apps14')
 return {'0.1.0-6':original6,'0.1.0-7':new7,'0.1.0-14':new14}

def selected(name,paths):
 return name in paths or name in('var/lib/pacman/local/cachy-asahi-apps-0.1.0-6','var/lib/pacman/local/cachy-asahi-apps-0.1.0-7','var/lib/pacman/local/cachy-asahi-apps-0.1.0-14')or name.startswith(('var/lib/pacman/local/cachy-asahi-apps-0.1.0-6/','var/lib/pacman/local/cachy-asahi-apps-0.1.0-7/','var/lib/pacman/local/cachy-asahi-apps-0.1.0-14/'))

def verify_readback(baseline,after,*,expected,version,products,physical_before,physical_after,caps_before,caps_after):
 """Readback DATA is produced by trusted full observers, never transaction stdout."""
 G.inventory(after['inventory'],expected,version);paths=set(products['0.1.0-6']['payload'])|set(products['0.1.0-7']['payload'])|set(C.APPS_DIRS)
 G.target(baseline['observation'],after['observation'],old_paths=sorted(paths),new_paths=sorted(paths),old_database='var/lib/pacman/local/cachy-asahi-apps-0.1.0-6',new_database='var/lib/pacman/local/cachy-asahi-apps-'+(version or '0.1.0-14'))
 physical.protected(physical_before,physical_after,baseline['observation']['nodes'],after['observation']['nodes'],lambda n:selected(n,paths),lock_witness=after.get('lock_parent'))
 C.need({n:v for n,v in caps_before.items()if n not in paths}=={n:v for n,v in caps_after.items()if n not in paths}and not any(n in caps_after for n in paths),'all protected capabilities held; Welcome adds no capabilities')
 nodes=after['observation']['nodes']
 if version is None:C.need(not any(n in nodes for n in paths),'removed selected payload remains')
 else:
  row=products[version]
  for name in C.APPS_DIRS:
   C.need(nodes.get(name)==dict(type='directory',mode=0o755,uid=0,gid=0),'exact selected exclusive directory readback')
  for name,wanted in row['payload'].items():
   value=nodes.get(name);C.need(value is not None and value['type']=='file'and value['uid']==value['gid']==0 and value.get('bytes')==wanted['size']and all(value.get(k)==wanted[k]for k in('mode','sha256')),'exact selected archive payload readback')
  C.need(after.get('selected_database_validated')is True,'full selected current DB validation required from trusted readback')
 return dict(count=605 if version is None else 606,selected_version=version,other605='FULL_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPS_PROTECTED',selected_db='ABSENT'if version is None else'CURRENT_NORMAL_ALPM_NOT_HISTORICAL_INODE',source606='UNCHANGED_SEPARATE_READBACK_REQUIRED')

def exercise(*,expected,original6,new7,new14,original606_manifest,observe,transact,fixtures,source_unchanged):
 """The closed worker binds these callables to exact trusted source APIs.

 No exported code or arbitrary fixture/callback supplied by runtime data is
 imported. Every step requires independent full readback and source proof.
 """
 products=operands(original6,new7,new14,original606_manifest=original606_manifest);initial=observe();G.inventory(initial['inventory'],expected)
 events=[];previous=initial
 for phase,version in PHASES:
  if phase!='baseline6':
   result=transact(phase,previous['inventory'],None if version is None else products[version]);C.need(result['direct_child_reaped']is True and result['group_retired']is True and result['returncode']==0,'real transaction retirement before readback')
  current=observe()
  event=verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  event['transaction']='NOT_RUN_BASELINE'if phase=='baseline6'else result
  if version is not None:
   checks=fixtures(phase,version,products[version]);C.need(checks.get('homes')=={'fresh':{'CLI':2,'inventory_count':606,'installed_controls':15 if version in('0.1.0-7','0.1.0-14')else 0},'existing':{'CLI':2,'inventory_count':606,'installed_controls':15 if version in('0.1.0-7','0.1.0-14')else 0}}and checks.get('zero_capabilities')is True and checks.get('NNP')==1,'actual installed CLI/readonly inventory/source fixtures in both ordinary homes')
   event['fixtures']=checks
   current=observe();verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  C.need(source_unchanged()is True,'complete original source606 changed');events.append(dict(phase=phase,**event));previous=current
 return dict(status='COPY_PROTOCOL_COMPLETED_REQUIRES_OUTER_ORDERED_DISPOSAL',counts=[606,606,606,606,605,606,606,606],events=events,restoration='EXACT_ORIGINAL6_ARCHIVE_PAYLOAD_CURRENT_ALPM_DB',hardware='NOT_RUN',release='NOT_ADMITTED')
