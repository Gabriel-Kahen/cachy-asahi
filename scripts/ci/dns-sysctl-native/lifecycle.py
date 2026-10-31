#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signed disposable install/reinstall/remove; installed code, private fixtures only."""
import json,os,pwd,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I

def main():
 C=I.load('dns_sysctl_contract','/runner/contract.py');L,driver=I.apis();I.guard(L,'lifecycle')
 base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
 L.need(len(base)==574 and L.inventory()==base and set(products)==set(C.NAMES)and not set(products)&base.keys(),'exact574/two absent tools required')
 control=json.loads(Path('/inputs/control.json').read_bytes());pacman=I.pacman(L,control['signer']);query=pacman[:-2]
 state=I.base_state(L,driver);base_digest=I.preserve_base(L,state);archives=[]
 for name,row in products.items():
  path=Path('/inputs')/row['archive'];L.need(path.parent==Path('/inputs')and path.is_file()and not path.is_symlink()and L.sha(path)==row['sha256']and set(row['payload'])==set(C.files(name)),'accepted signed archive/payload input required');archives.append(str(path))
 selected={name:row['version']for name,row in products.items()};account=pwd.getpwnam('alarm');homes=[];events=[];output_pins={}
 for kind in('fresh','existing'):
  home=Path('/tmp')/('dns-sysctl-home-'+kind);home.mkdir(mode=0o700)
  if kind=='existing':
   for relative in('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
    path=home/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('preserve '+relative+'\n');path.chmod(0o600)
   (home/'.config/alias').symlink_to('cachy-asahi/preferences')
  output=Path('/tmp')/('dns-sysctl-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_text('preserve outside\n');session=L.session_paths(home,output)
  for path in(home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes.append((home,L.snapshot(home),output,L.entry(output/'outside'),session))
 def user(home,session,argv):
  environment=L.user_environment(home,session)
  return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in environment.items()),*argv],timeout=70)
 def preserve():
  L.need(I.preserve_base(L,state)==base_digest,'original574 payload/database changed')
  for home,before,output,outside,_ in homes:L.preservation_check(home,before,output,outside)
  L.need(all(L.entry(path)==pin for path,pin in output_pins.items()),'earlier private fixture receipt changed')
 def installed(phase):
  L.need(L.inventory()==base|selected,'exact576 installed inventory differs');I.payloads(L,products);L.command(query+['-Dk']);observations=[]
  for home,_,output,_,session in homes:
   work=output/phase;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
   receipt=json.loads(user(home,session,['/usr/bin/python3','-I','-B','/runner/fixture_checks.py',str(work)]))
   receipt['home']=home.name;observations.append(receipt)
   output_pins[work/'receipt.json']=L.entry(work/'receipt.json')
  preserve();events.append(dict(phase=phase,count=576,base574_preserved=True,user_preserved=True,observations=observations))
 def absent(phase):
  L.need(L.inventory()==base,'exact original574 inventory not restored')
  for row in products.values():
   for relative in row['payload']:L.need(not os.path.lexists(Path('/')/relative),'removed tool payload remains')
  preserve();events.append(dict(phase=phase,count=574,base574_preserved=True,user_preserved=True,payloads_absent=True))
 for phase in('install','same-version-reinstall'):L.command(pacman+['-U',*archives],timeout=90);installed(phase)
 L.command(pacman+['-R',*reversed(C.NAMES)],timeout=90);absent('remove')
 L.command(pacman+['-U',*archives],timeout=90);installed('reinstall-after-removal')
 L.command(pacman+['-R',*reversed(C.NAMES)],timeout=90);absent('final-remove')
 result=dict(status='PASS_DNS_SYSCTL_SIGNED_PRIVATE_LIFECYCLE',base_count=574,installed_count=576,base574_preserved=True,base_manifest_sha256=base_digest,user_preserved=True,signatures='REQUIRED_EPHEMERAL_TEST_ONLY',signer=control['signer'],architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),events=events,live_DNS='NOT_RUN',host_sysctl_mutation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,sort_keys=True)+'\n');L.command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])

if __name__=='__main__':main()
