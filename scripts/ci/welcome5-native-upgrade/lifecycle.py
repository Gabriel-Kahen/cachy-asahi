#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two signed Welcome versions: install4, upgrade5, remove, reinstall5, remove."""
import json,os,pwd,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I

def main():
 C=I.load('welcome5_upgrade_contract','/runner/contract.py');L,driver=I.apis();I.guard(L,'lifecycle')
 base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes());actual='cachy-asahi-welcome'
 L.need(len(base)==574 and L.inventory()==base and set(products)==set(C.NAMES)and actual not in base,'exact574 and two absent same-name roles required')
 control=json.loads(Path('/inputs/control.json').read_bytes());pacman=I.pacman(L,control['signer']);query=pacman[:-2]
 state=I.base_state(L,driver);base_digest=I.preserve_base(L,state);archives={}
 for role,row in products.items():
  path=Path('/inputs')/row['archive'];L.need(C.PACKAGE==actual and path.parent==Path('/inputs')and path.is_file()and not path.is_symlink()and L.sha(path)==row['sha256']and set(row['payload'])==set(C.files(role))and row['version']==('0.1.0-4'if role==C.NAMES[0]else'0.1.0-5'),'exact signed role/version/archive input required');archives[role]=str(path)
 L.need(len(set(archives.values()))==2,'baseline/candidate archives must be distinct')
 account=pwd.getpwnam('alarm');homes=[];events=[];output_pins={};trust=Path('/etc/pacman.d/gnupg');trust_before=L.snapshot(trust)
 for kind in('fresh','existing'):
  home=Path('/tmp')/('welcome-upgrade-home-'+kind);home.mkdir(mode=0o700)
  if kind=='existing':
   for relative in('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
    path=home/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('preserve '+relative+'\n');path.chmod(0o600)
   (home/'.config/alias').symlink_to('cachy-asahi/preferences')
  output=Path('/tmp')/('welcome-upgrade-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_text('preserve outside\n');session=L.session_paths(home,output)
  for path in(home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes.append((home,L.snapshot(home),output,L.entry(output/'outside'),session))
 def user(home,session,argv):
  environment=L.user_environment(home,session);return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in environment.items()),*argv],timeout=70)
 def preserve():
  L.need(I.preserve_base(L,state)==base_digest and L.snapshot(trust)==trust_before,'original574 payload/rawDB/production trust changed')
  for home,before,output,outside,_ in homes:L.preservation_check(home,before,output,outside)
  L.need(all(L.entry(path)==pin for path,pin in output_pins.items()),'earlier user fixture receipt changed')
 def installed(phase,role):
  row=products[role];L.need(L.inventory()==base|{actual:row['version']},'exact575 selected-version inventory required');I.payloads(L,{actual:row});L.command(query+['-Dk']);observations=[]
  root_work=Path('/tmp')/('welcome-root-'+phase);root_work.mkdir(mode=0o700)
  root_assertion=json.loads(L.command(['/usr/bin/python3','-I','-B','/runner/fixture_checks.py','--root-guard',str(root_work),role],timeout=70))
  L.need(root_assertion['status']=='PASS_ORIGINAL_ROOT_REFUSAL_ASSERTION'and root_assertion['recipe_role']==role,'root guard must execute')
  for home,_,output,_,session in homes:
   work=output/phase;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
   receipt=json.loads(user(home,session,['/usr/bin/python3','-I','-B','/runner/fixture_checks.py',str(work),role]));receipt['home']=home.name;observations.append(receipt);
   for path in work.rglob('*'):
    if path.is_file():output_pins[path]=L.entry(path)
  preserve();events.append(dict(phase=phase,count=575,package_name=actual,version=row['version'],recipe_role=role,base574_preserved=True,user_preserved=True,production_trust_preserved=True,root_guard=root_assertion,observations=observations))
 def absent(phase):
  L.need(L.inventory()==base,'exact original574 inventory not restored')
  for row in products.values():
   for relative in row['payload']:L.need(not os.path.lexists(Path('/')/relative),'removed Welcome payload remains')
  preserve();events.append(dict(phase=phase,count=574,base574_preserved=True,user_preserved=True,production_trust_preserved=True,payloads_absent=True))
 for phase,role in(('install-v4',C.NAMES[0]),('upgrade-v4-to-v5',C.NAMES[1])):L.command(pacman+['-U',archives[role]],timeout=90);installed(phase,role)
 L.command(pacman+['-R',actual],timeout=90);absent('remove-v5')
 L.command(pacman+['-U',archives[C.NAMES[1]]],timeout=90);installed('reinstall-v5',C.NAMES[1])
 L.command(pacman+['-R',actual],timeout=90);absent('final-remove-v5')
 result=dict(status='PASS_WELCOME5_UPGRADE_SIGNED_DISPLAYLESS_LIFECYCLE',base_count=574,installed_count=575,base574_preserved=True,base_manifest_sha256=base_digest,user_preserved=True,production_trust_preserved=True,signatures='REQUIRED_EPHEMERAL_TEST_ONLY',signer=control['signer'],architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),events=events,GUI='NOT_RUN',live_DNS='NOT_RUN',actual_16k_execution='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,sort_keys=True)+'\n');L.command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])

if __name__=='__main__':main()
