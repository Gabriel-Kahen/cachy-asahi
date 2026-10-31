# SPDX-License-Identifier: MIT
"""Finite copied606 Welcome protocol; original source606 lifecycle stays outside."""
import hashlib
import contract as C,guard as G,physical
NAME='cachy-asahi-setup'
PHASES=(('baseline5', '0.1.0-5'), ('install6', '0.1.0-6'), ('same-version6', '0.1.0-6'), ('rollback5', '0.1.0-5'), ('forward6', '0.1.0-6'), ('remove6', None), ('reinstall6', '0.1.0-6'), ('restore-original5', '0.1.0-5'))

def operands(original1,new2,*,original606_manifest):
 """Version alone never authorizes restoration; exact old manifest row joins."""
 C.need(type(original606_manifest)is dict and original606_manifest.get(NAME)==original1.get('source_record'),'exact ORIGINAL604 Welcome4 archive/signature/payload/provenance row required')
 C.need(original1['source_record']['sha256']==original1['sha256']and original1['source_record']['payload']==original1['payload']and original1['source_record']['version']==original1['version'],'exact original1 row/archive/payload identity')
 C.need(original1['sha256']=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'and new2['sha256']=='a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8'and new2['signer']==original1['signer'],'exact original1/native7 public archive and signer identities')
 C.need(original1['version']=='0.1.0-5'and new2['version']=='0.1.0-6'and original1['sha256']!=new2['sha256'],'distinct original1/candidate7 archive identities')
 C.need(len(original1['payload'])==len(new2['payload'])==6 and set(original1['payload'])==set(new2['payload'])==C.DOCTOR_FILES,'whole same owned Welcome payload path set')
 return {'0.1.0-5':original1,'0.1.0-6':new2}

def selected(name,paths):
 return name in paths or name in('var/lib/pacman/local/cachy-asahi-setup-0.1.0-5','var/lib/pacman/local/cachy-asahi-setup-0.1.0-6')or name.startswith(('var/lib/pacman/local/cachy-asahi-setup-0.1.0-5/','var/lib/pacman/local/cachy-asahi-setup-0.1.0-6/'))

def verify_readback(baseline,after,*,expected,version,products,physical_before,physical_after,caps_before,caps_after):
 """Readback DATA is produced by trusted full observers, never transaction stdout."""
 G.inventory(after['inventory'],expected,version);paths=set(products['0.1.0-5']['payload'])|set(products['0.1.0-6']['payload'])|set(C.DOCTOR_DIRS)
 G.target(baseline['observation'],after['observation'],old_paths=sorted(paths),new_paths=sorted(paths),old_database='var/lib/pacman/local/cachy-asahi-setup-0.1.0-5',new_database='var/lib/pacman/local/cachy-asahi-setup-0.1.0-6')
 physical.protected(physical_before,physical_after,baseline['observation']['nodes'],after['observation']['nodes'],lambda n:selected(n,paths),lock_witness=after.get('lock_parent'))
 C.need({n:v for n,v in caps_before.items()if n not in paths}=={n:v for n,v in caps_after.items()if n not in paths}and not any(n in caps_after for n in paths),'all protected capabilities held; Welcome adds no capabilities')
 nodes=after['observation']['nodes']
 if version is None:C.need(not any(n in nodes for n in paths),'removed selected payload remains')
 else:
  row=products[version]
  for name in C.DOCTOR_DIRS:
   C.need(nodes.get(name)==dict(type='directory',mode=0o755,uid=0,gid=0),'exact selected exclusive directory readback')
  for name,wanted in row['payload'].items():
   value=nodes.get(name);C.need(value is not None and value['type']=='file'and value['uid']==value['gid']==0 and value.get('bytes')==wanted['size']and all(value.get(k)==wanted[k]for k in('mode','sha256')),'exact selected archive payload readback')
  C.need(after.get('selected_database_validated')is True,'full selected current DB validation required from trusted readback')
 return dict(count=605 if version is None else 606,selected_version=version,other605='FULL_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPS_PROTECTED',selected_db='ABSENT'if version is None else'CURRENT_NORMAL_ALPM_NOT_HISTORICAL_INODE',source606='UNCHANGED_SEPARATE_READBACK_REQUIRED')

def exercise(*,expected,original1,new2,original606_manifest,observe,transact,fixtures,source_unchanged):
 """The closed worker binds these callables to exact trusted source APIs.

 No exported code or arbitrary fixture/callback supplied by runtime data is
 imported. Every step requires independent full readback and source proof.
 """
 products=operands(original1,new2,original606_manifest=original606_manifest);initial=observe();G.inventory(initial['inventory'],expected)
 events=[];previous=initial
 for phase,version in PHASES:
  if phase!='baseline5':
   result=transact(phase,previous['inventory'],None if version is None else products[version]);C.need(result['direct_child_reaped']is True and result['group_retired']is True and result['returncode']==0,'real transaction retirement before readback')
  current=observe()
  event=verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  event['transaction']='NOT_RUN_BASELINE'if phase=='baseline5'else result
  if version is not None:
   checks=fixtures(phase,version,products[version]);C.need(checks.get('homes')=={'fresh':{'CLI':4,'inventory_count':606,'installed_controls':6 if version=='0.1.0-6'else 0},'existing':{'CLI':4,'inventory_count':606,'installed_controls':6 if version=='0.1.0-6'else 0}}and checks.get('zero_capabilities')is True and checks.get('NNP')==1,'actual installed CLI/readonly inventory/source fixtures in both ordinary homes')
   event['fixtures']=checks
   current=observe();verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  C.need(source_unchanged()is True,'complete original source606 changed');events.append(dict(phase=phase,**event));previous=current
 return dict(status='COPY_PROTOCOL_COMPLETED_REQUIRES_OUTER_ORDERED_DISPOSAL',counts=[606,606,606,606,606,605,606,606],events=events,restoration='EXACT_ORIGINAL1_ARCHIVE_PAYLOAD_CURRENT_ALPM_DB',hardware='NOT_RUN',release='NOT_ADMITTED',full606_real_shell='NOT_RUN_DEVICE_FREE_COPY',Apps7_coexistence='NOT_RUN_BASELINE_APPS6',fixture_scope='ACTUAL_INSTALLED_HELPER_PRIVATE_PYTHON_RECOVERY_ONLY')
