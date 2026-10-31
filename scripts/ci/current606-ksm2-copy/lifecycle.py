# SPDX-License-Identifier: MIT
"""Finite copied606 Welcome protocol; original source606 lifecycle stays outside."""
import hashlib
import contract as C,guard as G,physical
NAME='cachy-asahi-ksmctl'
PHASES=(('baseline1','0.1.0-1'),('upgrade2','0.1.0-2'),('same-version2','0.1.0-2'),('remove2',None),('reinstall2','0.1.0-2'),('restore-original1','0.1.0-1'))

def operands(original1,new2,*,original606_manifest):
 """Version alone never authorizes restoration; exact old manifest row joins."""
 C.need(type(original606_manifest)is dict and original606_manifest.get(NAME)==original1.get('source_record'),'exact ORIGINAL606 KSM1 archive/signature/payload/provenance row required')
 C.need(original1['source_record']['sha256']==original1['sha256']and original1['source_record']['payload']==original1['payload']and original1['source_record']['version']==original1['version'],'exact original1 row/archive/payload identity')
 C.need(original1['version']=='0.1.0-1'and new2['version']=='0.1.0-2'and original1['sha256']!=new2['sha256'],'distinct original1/candidate2 archive identities')
 C.need(new2['sha256']=='bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f','exact Root-native KSM2 archive')
 C.need(set(original1['payload'])==C.OLD_FILES and set(new2['payload'])==C.KSM_FILES,'whole versioned KSM owned payload sets')
 return {'0.1.0-1':original1,'0.1.0-2':new2}

def selected(name,paths):
 return name in paths or name in('var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-1','var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-2')or name.startswith(('var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-1/','var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-2/'))

def verify_readback(baseline,after,*,expected,version,products,physical_before,physical_after,caps_before,caps_after):
 """Readback DATA is produced by trusted full observers, never transaction stdout."""
 G.inventory(after['inventory'],expected,version);paths=set(products['0.1.0-1']['payload'])|set(products['0.1.0-2']['payload'])|set(C.KSM_DIRS)
 G.target(baseline['observation'],after['observation'],old_paths=sorted(paths),new_paths=sorted(paths),old_database='var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-1',new_database='var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-2')
 physical.protected(physical_before,physical_after,baseline['observation']['nodes'],after['observation']['nodes'],lambda n:selected(n,paths),lock_witness=after.get('lock_parent'))
 C.need({n:v for n,v in caps_before.items()if n not in paths}=={n:v for n,v in caps_after.items()if n not in paths}and not any(n in caps_after for n in paths),'all protected capabilities held; KSM adds no capabilities')
 nodes=after['observation']['nodes']
 if version is None:C.need(not any(n in nodes for n in paths),'removed selected payload remains')
 else:
  row=products[version]
  C.need({n for n in paths if n in nodes}==set(row['payload'])|set(C.KSM_DIRS),'no absent-version selected payload may survive')
  for name in C.KSM_DIRS:
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
 with C.phase('baseline-capture'):
  products=operands(original1,new2,original606_manifest=original606_manifest);initial=observe();G.inventory(initial['inventory'],expected)
 events=[];previous=initial
 for phase,version in PHASES:
  if phase!='baseline1':
   with C.phase(phase+'.transaction'):
    result=transact(phase,previous['inventory'],None if version is None else products[version]);C.need(result['direct_child_reaped']is True and result['group_retired']is True and result['returncode']==0,'real transaction retirement before readback')
  with C.phase(phase+'.readback'):
   current=observe()
   event=verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  event['transaction']='NOT_RUN_BASELINE'if phase=='baseline1'else result
  if version is not None:
   with C.phase(phase+'.fixtures'):
    checks=fixtures(phase,version,products[version]);C.need(checks.get('homes')=={'fresh':{'CLI':4 if version=='0.1.0-2'else 2,'installed_controls':44 if version=='0.1.0-2'else 18,'live_kernel_write':'NOT_RUN'},'existing':{'CLI':4 if version=='0.1.0-2'else 2,'installed_controls':44 if version=='0.1.0-2'else 18,'live_kernel_write':'NOT_RUN'}}and checks.get('zero_capabilities')is True and checks.get('NNP')==1,'actual installed CLI/readonly inventory/source fixtures in both ordinary homes')
   event['fixtures']=checks
   with C.phase(phase+'.post-fixture-readback'):
    current=observe();verify_readback(initial,current,expected=expected,version=version,products=products,physical_before=initial['physical'],physical_after=current['physical'],caps_before=initial['capabilities'],caps_after=current['capabilities'])
  with C.phase(phase+'.source-proof'):
   C.need(source_unchanged()is True,'complete original source606 changed');events.append(dict(phase=phase,**event));previous=current
 return dict(status='COPY_PROTOCOL_COMPLETED_REQUIRES_OUTER_ORDERED_DISPOSAL',counts=[606,606,606,605,606,606],events=events,restoration='EXACT_ORIGINAL1_ARCHIVE_PAYLOAD_CURRENT_ALPM_DB',hardware='NOT_RUN',release='NOT_ADMITTED')
