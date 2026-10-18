# SPDX-License-Identifier: MIT
"""Finite copied606 Welcome protocol; original source606 lifecycle stays outside."""
import hashlib
import contract as C,guard as G,physical
NAME='cachy-asahi-welcome'
PHASES=(('baseline4','0.1.0-4'),('upgrade5','0.1.0-5'),('remove5',None),('reinstall5','0.1.0-5'),('restore-original4','0.1.0-4'))

def operands(original4,new5,*,original604_manifest):
 """Version alone never authorizes restoration; exact old manifest row joins."""
 C.need(type(original604_manifest)is dict and original604_manifest.get(NAME)==original4.get('source_record'),'exact ORIGINAL604 Welcome4 archive/signature/payload/provenance row required')
 C.need(original4['source_record']['sha256']==original4['sha256']and original4['source_record']['payload']==original4['payload']and original4['source_record']['version']==original4['version'],'exact original4 row/archive/payload identity')
 C.need(original4['version']=='0.1.0-4'and new5['version']=='0.1.0-5'and original4['sha256']!=new5['sha256'],'distinct original4/candidate5 archive identities')
 C.need(len(original4['payload'])==len(new5['payload'])==9 and set(original4['payload'])==set(new5['payload'])==C.WELCOME_FILES,'whole same owned Welcome payload path set')
 return {'0.1.0-4':original4,'0.1.0-5':new5}

def selected(name,paths):
 return name in paths or name in('var/lib/pacman/local/cachy-asahi-welcome-0.1.0-4','var/lib/pacman/local/cachy-asahi-welcome-0.1.0-5')or name.startswith(('var/lib/pacman/local/cachy-asahi-welcome-0.1.0-4/','var/lib/pacman/local/cachy-asahi-welcome-0.1.0-5/'))

def verify_readback(baseline,after,*,expected,version,products,physical_before,physical_after,caps_before,caps_after):
 """Readback DATA is produced by trusted full observers, never transaction stdout."""
 G.inventory(after['inventory'],expected,version);paths=set(products['0.1.0-4']['payload'])|set(products['0.1.0-5']['payload'])|set(C.WELCOME_DIRS)
 G.target(baseline['observation'],after['observation'],old_paths=sorted(paths),new_paths=sorted(paths),old_database='var/lib/pacman/local/cachy-asahi-welcome-0.1.0-4',new_database='var/lib/pacman/local/cachy-asahi-welcome-0.1.0-5')
 physical.protected(physical_before,physical_after,baseline['observation']['nodes'],after['observation']['nodes'],lambda n:selected(n,paths),lock_witness=after.get('lock_parent'))
 C.need({n:v for n,v in caps_before.items()if n not in paths}=={n:v for n,v in caps_after.items()if n not in paths}and not any(n in caps_after for n in paths),'all protected capabilities held; Welcome adds no capabilities')
 nodes=after['observation']['nodes']
 if version is None:C.need(not any(n in nodes for n in paths),'removed selected payload remains')
 else:
  row=products[version]
  for name in C.WELCOME_DIRS:
   C.need(nodes.get(name)==dict(type='directory',mode=0o755,uid=0,gid=0),'exact selected exclusive directory readback')
  for name,wanted in row['payload'].items():
   value=nodes.get(name);C.need(value is not None and value['type']=='file'and value['uid']==value['gid']==0 and value.get('bytes')==wanted['size']and all(value.get(k)==wanted[k]for k in('mode','sha256')),'exact selected archive payload readback')
  C.need(after.get('selected_database_validated')is True,'full selected current DB validation required from trusted readback')
 return dict(count=605 if version is None else 606,selected_version=version,other605='FULL_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPS_PROTECTED',selected_db='ABSENT'if version is None else'CURRENT_NORMAL_ALPM_NOT_HISTORICAL_INODE',source606='UNCHANGED_SEPARATE_READBACK_REQUIRED')

def exercise(*,expected,original4,new5,original604_manifest,observe,transact,fixtures,source_unchanged):
 """The closed worker binds these callables to exact trusted source APIs.

 No exported code or arbitrary fixture/callback supplied by runtime data is
 imported. Every step requires independent full readback and source proof.
 """
 products=operands(original4,new5,original604_manifest=original604_manifest);initial=observe();G.inventory(initial['inventory'],expected)
 events=[];previous=initial
 for phase,version in PHASES:
  if phase!='baseline4':
   result=transact(phase,previous['inventory'],None if version is None else products[version]);C.need(result['direct_child_reaped']is True and result['group_retired']is True and result['returncode']==0,'real transaction retirement before readback')
  current=observe()
  event=verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  event['transaction']='NOT_RUN_BASELINE'if phase=='baseline4'else result
  if version is not None:
   checks=fixtures(phase,version,products[version]);C.need(checks.get('root_guard')=='PASS'and checks.get('homes')=={'fresh':{'CLI':5,'report':8 if version=='0.1.0-4'else 12},'existing':{'CLI':5,'report':8 if version=='0.1.0-4'else 12}}and checks.get('zero_capabilities')is True and checks.get('NNP')==1,'all real original root/ordinary fixture assertions required')
   event['fixtures']=checks
   current=observe();verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  C.need(source_unchanged()is True,'complete original source606 changed');events.append(dict(phase=phase,**event));previous=current
 return dict(status='COPY_PROTOCOL_COMPLETED_REQUIRES_OUTER_ORDERED_DISPOSAL',counts=[606,606,605,606,606],events=events,restoration='EXACT_ORIGINAL4_ARCHIVE_PAYLOAD_CURRENT_ALPM_DB',hardware='NOT_RUN',release='NOT_ADMITTED')
