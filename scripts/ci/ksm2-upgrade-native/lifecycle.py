#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real signed same-name upgrade in owned native root; no actual ksmctl writes."""
import json,os,pwd,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I
BASE='cachy-asahi-ksmctl';NEW=BASE+'2'
def main():
 C=I.load('ksm2_contract','/runner/contract.py');L,driver=I.apis();I.guard(L,'lifecycle');base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
 L.need(len(base)==574 and L.inventory()==base and set(products)=={BASE,NEW}and BASE not in base,'exact574 and absent single package')
 L.need(not os.path.lexists('/var/lib/cachy-asahi-ksm-experiments'),'live state absent before package installation');control=json.loads(Path('/inputs/control.json').read_bytes());system=dict(pacman=L.entry(Path('/etc/pacman.conf')),trust=L.snapshot(Path('/etc/pacman.d')));pacman=I.pacman(L,control['signer']);query=pacman[:-2];state=I.base_state(L,driver);base_digest=I.preserve_base(L,state);archives={}
 for role,row in products.items():
  p=Path('/inputs')/row['archive'];L.need(p.parent==Path('/inputs')and p.is_file()and not p.is_symlink()and L.sha(p)==row['sha256']and set(row['payload'])==set(C.files(role))and row['version']==('0.1.0-1'if role==BASE else'0.1.0-2'),'exact signed version/source/payload');archives[role]=str(p)
 account=pwd.getpwnam('alarm');homes=[];events=[];receipts={}
 for kind in('fresh','existing'):
  home=Path('/tmp')/('ksm2-home-'+kind);home.mkdir(mode=0o700)
  if kind=='existing':
   for name in('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
    p=home/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('preserve '+name+'\n');p.chmod(0o600)
   (home/'.config/alias').symlink_to('cachy-asahi/preferences')
  output=Path('/tmp')/('ksm2-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_text('preserve outside\n');session=L.session_paths(home,output)
  for p in(home,*home.rglob('*'),output,*output.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes.append((home,L.snapshot(home),output,L.entry(output/'outside'),session))
 def preserve():
  L.need(not os.path.lexists('/var/lib/cachy-asahi-ksm-experiments'),'native software fixtures must never create live management state')
  L.need(I.preserve_base(L,state)==base_digest,'all original574 payload/raw database rows preserved')
  L.need(system==dict(pacman=L.entry(Path('/etc/pacman.conf')),trust=L.snapshot(Path('/etc/pacman.d'))),'original system pacman/trust changed')
  for home,before,output,outside,_ in homes:L.preservation_check(home,before,output,outside)
  L.need(all(L.entry(p)==row for p,row in receipts.items()),'earlier private receipt changed')
 def installed(phase,role):
  row=products[role];L.need(L.inventory()==base|{BASE:row['version']},'same package exact575/version required');I.payloads(L,{BASE:row});L.command(query+['-Dk']);observations=[]
  for home,_,output,_,session in homes:
   argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in L.user_environment(home,session).items()),'/usr/bin/python3','-I','-B','/runner/fixture_checks.py',role,str(output),phase]
   r=json.loads(L.command(argv,timeout=70));r['home']=home.name;observations.append(r);receipts[output/(phase+'-receipt.json')]=L.entry(output/(phase+'-receipt.json'))
  preserve();events.append(dict(phase=phase,version=row['version'],count=575,base574_preserved=True,user_preserved=True,system_trust_preserved=True,fixture_receipts_preserved=True,observations=observations))
 def absent(phase):
  L.need(L.inventory()==base,'original574 inventory not restored')
  for p in products[NEW]['payload']:L.need(not os.path.lexists(Path('/')/p),'removed package payload remains')
  preserve();events.append(dict(phase=phase,version=None,count=574,base574_preserved=True,user_preserved=True,system_trust_preserved=True,fixture_receipts_preserved=True,payloads_absent=True))
 L.command(pacman+['-U',archives[BASE]],timeout=90);installed('install-v1',BASE)
 L.command(pacman+['-U',archives[NEW]],timeout=90);installed('upgrade-v2',NEW)
 L.command(pacman+['-R',BASE],timeout=90);absent('remove')
 L.command(pacman+['-U',archives[NEW]],timeout=90);installed('reinstall-v2',NEW)
 L.command(pacman+['-R',BASE],timeout=90);absent('final-remove')
 result=dict(status='PASS_KSM2_SIGNED_UPGRADE_PRIVATE_LIFECYCLE',base_count=574,installed_count=575,base574_preserved=True,base_manifest_sha256=base_digest,user_preserved=True,system_trust_preserved=True,fixture_receipts_preserved=True,signatures='REQUIRED_EPHEMERAL_TEST_ONLY',signer=control['signer'],architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),events=events,live_kernel_write='NOT_RUN',live_store='NOT_CREATED',hardware='NOT_RUN',release='NOT_ADMITTED');C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,sort_keys=True)+'\n');L.command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])
if __name__=='__main__':main()
