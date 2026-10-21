# SPDX-License-Identifier: MIT
"""Real signed additions inside the genuine already-installed604 consumer."""
import hashlib,json,os,pwd,sys
from pathlib import Path

def exercise(g,s):
 C=g['C'];run=g['run'];inventory=g['inventory'];base=s['after'];pacman=s['pacman'];home=s['home'];rows=json.loads(Path('/tools606/products.json').read_bytes());policy=json.loads(Path('/tools606/tools-policy.json').read_bytes());need=C.need
 need(len(base)==604 and inventory()==base and set(rows)=={'cachy-asahi-dns2','cachy-asahi-sysctl2'},'genuine actual604 must precede606')
 expected=base|{r['name']:r['version']for r in rows.values()};need(len(expected)==606 and not({r['name']for r in rows.values()}&base.keys()),'exact two absent additions')
 need(C.inventory_bytes(expected)==Path('/runner/expected606.lock').read_bytes(),'exact606 lock bytes')
 L=C.load('606_original_user_api',Path('/runner/accepted/lifecycle.py'));I=C.load('606_narrow604_inventory',Path('/runner/installed604.py'));driver=C.load('606_original_root_database',Path('/runner/accepted/root_upgrade.py'))
 state=I.base_state(L,driver);need({r['name']:r['version']for r in state['packages']}==base,'complete actual604 snapshot');base_digest=I.preserve_base(L,state);system=dict(pacman=g['node'](Path('/etc/pacman.conf')),trust=g['tree'](Path('/etc/pacman.d')));users=g['tree'](Path('/home'))|g['tree'](Path('/root'));configs={k:v for k,v in g['tree'](Path('/etc')).items()if k!='/etc/ld.so.cache'}
 paths=[]
 for role,row in rows.items():
  p=Path('/tools606')/row['archive'];need(p.parent==Path('/tools606')and not p.is_symlink()and C.sha(p)==row['sha256']and p.stat().st_size==row['bytes']and row['name']==policy['products'][role]['package_name']and row['version']=='0.1.0-2'and row['signer']==s['original']['preparation']['signer_roles']['ephemeral_TEST'],'exact signed new package selection')
  sig=Path('/tools606')/row['signature'];need(sig==p.with_name(p.name+'.sig')and dict(bytes=sig.stat().st_size,sha256=C.sha(sig))==row['signature_pin'],'exact detached signature')
  g['verify_signature'](['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'],p,sig,row['signer']);meta=g['metadata'](p);need(meta.get('pkgname')==[row['name']]and meta.get('pkgver')==[row['version']]and meta.get('arch')==['any']and not any(meta.get(k)for k in('conflict','replaces','backup','install')),'script-only metadata; no replacements/hooks/config')
  for name in row['payload']:need(g['node'](Path('/')/name)['type']=='absent','new installed path must be absent')
  paths.append(str(p))
 account=pwd.getpwnam('alarm');homes=[];receipts={};events=[];ld=[];previous_ld=s['previous_ld'];previous_aux=s['previous_aux'];audio=s['audio'];adapter=s['adapter'];audio_rows=s['audio_rows']
 for kind in('fresh','existing'):
  h=Path('/tmp')/('606-home-'+kind);h.mkdir(mode=0o700)
  if kind=='existing':
   p=h/'.config/retained';p.parent.mkdir();p.write_text('retained606\n');(h/'.zshrc').write_text('retained shell\n')
  out=Path('/tmp')/('606-output-'+kind);out.mkdir(mode=0o700);(out/'outside').write_text('unchanged\n');session=L.session_paths(h,out)
  for p in(h,*h.rglob('*'),out,*out.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes.append((h,L.snapshot(h),out,L.entry(out/'outside'),session))
 def preservation(want):
  need(inventory()==want,'exact actual604/606 inventory');db=driver.database(Path('/'),max_packages=606);need({r['name']:r['version']for r in db}==want,'full actual606 database');seen={}
  for r in db:
   for p in r['files']:need(p not in seen,'606 ownership overlap');seen[p]=r['name']
  need({p:g['node'](Path(p))for p in s['database_parents']}==s['database_parents'],'original ALPM parent metadata changed');need(I.preserve_base(L,state)==base_digest,'all604 original payload/inode/rawDB preserved');need(system==dict(pacman=g['node'](Path('/etc/pacman.conf')),trust=g['tree'](Path('/etc/pacman.d'))),'system trust/pacman changed');need(users==g['tree'](Path('/home'))|g['tree'](Path('/root'))and configs=={k:v for k,v in g['tree'](Path('/etc')).items()if k!='/etc/ld.so.cache'},'all existing604 user/config state preserved')
  for h,b,out,outside,_ in homes:L.preservation_check(h,b,out,outside)
  need(all(L.entry(p)==v for p,v in receipts.items()),'prior private receipt changed');run(pacman+['-Dk']);deps=sorted({d for r in db for d in r['depend']});run(pacman+['-T',*deps])
 def checkpoint(label,want):
  nonlocal previous_ld,previous_aux
  preservation(want);state_ld=audio.ld_state(adapter,audio_rows);data,_,_=audio.ld_aux_read(state_ld);transition=audio.aux_order.compare(previous_aux,data)
  for field in('helper','configs','aliases','scan','targets','mapping','generator','caches'):
   left,right=previous_ld[field],state_ld[field]
   if field=='caches':left={p:{k:v for k,v in n.items()if k!='sha256'}for p,n in left.items()};right={p:{k:v for k,v in n.items()if k!='sha256'}for p,n in right.items()}
   need(left==right,'606 ldconfig recorded state changed: '+field)
  raw=C.encoded(state_ld);(g['OUT']/('tools606-ld-'+label+'.json')).write_bytes(raw);(g['OUT']/('tools606-aux-'+label+'.bin')).write_bytes(data);ld.append(dict(phase=label,state_sha256=hashlib.sha256(raw).hexdigest(),aux_sha256=hashlib.sha256(data).hexdigest(),transition=transition,helper_exit='NOT_OBSERVED'));previous_ld,previous_aux=state_ld,data
 def installed(label):
  I.payloads(L,{r['name']:r for r in rows.values()});observed=[]
  for h,_,out,_,session in homes:
   r=json.loads(run(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in L.user_environment(h,session).items()),'/usr/bin/python3','-I','-B','/runner/fixture606.py',str(out),label]));need(r['status']=='PASS_BOTH606_INSTALLED_PRIVATE_FIXTURES'and r['phase']==label,'ordinary606 suites');r['home']=h.name;observed.append(r);receipts[out/(label+'-receipt.json')]=L.entry(out/(label+'-receipt.json'))
  checkpoint(label,expected);events.append(dict(phase=label,count=606,all604_preserved=True,user_preserved=True,trust_preserved=True,signatures=True,ownership=True,dependencies=True,observations=observed))
 def install(label):
  printed=run(pacman+['--noconfirm','-U','--print','--print-format','%n %v',*paths]);need(dict(r.split()for r in printed.splitlines())=={r['name']:r['version']for r in rows.values()},'exact two-package normal preflight');run(pacman+['--noconfirm','--noscriptlet','-U',*paths]);installed(label)
 def remove(label):
  run(pacman+['--noconfirm','--noscriptlet','-R',*sorted(r['name']for r in rows.values())]);need(all(not os.path.lexists(Path('/')/p)for r in rows.values()for p in r['payload']),'removed new payload remains');checkpoint(label,base);events.append(dict(phase=label,count=604,all604_preserved=True,user_preserved=True,trust_preserved=True,payloads_absent=True))
 checkpoint('baseline604',base);install('install606');install('same-version606');remove('remove604');install('reinstall606');remove('final604')
 result=dict(status='PASS_SIGNED604_TO606_PRIVATE_LIFECYCLE',base_count=604,installed_count=606,restored_count=604,base604_state_sha256=base_digest,events=events,ldconfig=ld,live_NM='NOT_RUN',kernel_mutation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');(g['OUT']/'tools606.json').write_bytes(C.encoded(result));s['report']['tools606']=result
 return previous_ld,previous_aux
