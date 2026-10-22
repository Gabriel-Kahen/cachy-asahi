# SPDX-License-Identifier: MIT
"""Exact33 accepted/raw inputs plus fresh native original-policy TEST signatures."""
import hashlib,importlib.util,json,math,os,re,shutil,subprocess,sys,time
from pathlib import Path
import admission as A
HERE=Path(__file__).resolve().parent
ALARM='68B3537F39A313B3E574D06777193F152BDBE6A6'
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def tick(deadline):A.need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'original source-owned input preparation deadline')
def prepare(root,carrier,bootstrap,base,out,deadline,welcome8,apps8):
 root,carrier,bootstrap,base,out=(Path(p).absolute()for p in(root,carrier,bootstrap,base,out));A.prove(root);tick(deadline)
 A.need(os.uname().machine=='aarch64'and os.getuid()>0 and os.environ.get('GITHUB_ACTIONS')=='true','fresh native input signing only')
 profile=A.obj(root/'incoming-carrier-profile.json');A.need(re.fullmatch('[a-f0-9]{40}',profile['source']or'')and profile['actual']is None,'Root published exact incoming carrier required')
 sys.path.insert(0,str(root/'factory/retained-helpers'));L=load('_native606_incoming_source_proof',root/'factory/retained-helpers/legacy_prefill.py');external=L.prove(carrier,carrier/'.git',profile,deadline)
 welcome_profile=A.obj(root/'welcome8-carrier-profile.json');welcome_external=L.prove(welcome8,welcome8/'.git',welcome_profile,deadline);A.need(welcome_external['tree']==welcome_profile['tree'],'entire exact Welcome8 carrier source tree');welcome_index=A.obj(welcome8/'index.json');A.need(welcome_index['source']=='23e1205414dc74c577f1ee61baf0ee661ed5e678'and welcome_index['run']==39591889512 and welcome_index['native_GUI']==welcome_index['installed']=='NOT_RUN','accepted native pair is inputs only, no GUI authority')
 import apps8_inputs
 apps8_input=apps8_inputs.prepare(root,apps8,deadline)
 req=A.obj(carrier/'required33.json')['packages'];A.need(req['cachy-asahi-apps']['version']=='0.1.0-7','whole original Apps7 incoming operand');req['cachy-asahi-apps']=apps8_input['row'];A.need(req['cachy-asahi-welcome']['version']=='0.1.0-7','exact original incoming Welcome7 operand');req['cachy-asahi-welcome']=A.obj(root/'input-policy33.json')['packages']['cachy-asahi-welcome'];old=A.obj(carrier/'provenance/target604-manifest.json');base_inputs=A.obj(root/'original/scripts/ci/maintained-desktop574-inputs.json');expected=dict(r.split()for r in(root/'factory/expected606.lock').read_text().splitlines());before={r['name']:r['version']for r in base_inputs['packages']}
 A.need(len(req)==33 and set(before)-set(expected)=={'libfdk-aac'}and {n:r['version']for n,r in req.items()}=={n:v for n,v in expected.items()if n not in before},'exact573held/33incoming/one original FDK removal graph')
 raw_index=A.obj(carrier/'index.json');build=A.obj(bootstrap/'result.json');A.need(build['status']=='PASS_EXACT_TWO_BOOTSTRAP_ARCHIVE_BODIES_ORIGINAL_BUILDERS'and build['base_image']==A.obj(base/'report.json')['image']and build['required']==raw_index['native_build_required'],'two exact original native bootstrap bodies, original builder inventories and matching ownership')
 checks=load('_gui606_original_package_inspector',root/'original/scripts/checks/package_checks.py');sources={}
 for n,row in req.items():
  tick(deadline);name=Path(row['archive']).name;p=apps8_input['archive']if n=='cachy-asahi-apps'else(welcome8/welcome_index['archive']['path'])if n=='cachy-asahi-welcome'else((carrier/'packages'/name)if name in raw_index['packages_by_filename']else(bootstrap/'packages'/name));A.need(A.pin(A.read(p,96*1024**2))==dict(bytes=row['size'],sha256=row['sha256']),'exact historical archive body required '+n);report=checks.package(p);m=report['metadata']['.PKGINFO'];A.need(m['pkgname']==[n]and m['pkgver']==[row['version']]and m['arch'][0]in('any','aarch64'),'full exact archive package metadata');sources[n]=(p,report)
  if n=='cachy-asahi-apps':apps8_inputs.payload(report,root)
 A.need(not out.exists()and out.parent.is_dir(),'fresh owned signed606 output');out.mkdir(mode=0o700);(out/'packages').mkdir();(out/'keys').mkdir();private=out.parent/'gui606-private';A.need(not private.exists(),'fresh source-owned private signer directory');private.mkdir(mode=0o700)
 signer=None;verifier=None;retired=False
 try:
  sign=load('_whole_original_TEST_composition_signer',root/'support/native-composition.py');V=load('_whole_original_public_signature_verifier',root/'support/native-producer.py')
  keyrow=next(r for r in base_inputs['keyring_files']if r['filename']=='archlinuxarm.gpg');key=base/'context/keys/archlinuxarm.gpg';A.need(A.pin(A.read(key))==dict(bytes=keyrow['size'],sha256=keyrow['sha256']),'original exact upstream public key');shutil.copyfile(key,out/'keys/archlinuxarm.gpg')
  rows=[];to_sign=[]
  for row in base_inputs['packages']:
   if row['name']=='libfdk-aac':continue
   for suffix,size,sha in [('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])]:
    src=base/'context/deps'/(row['filename']+suffix);A.need(A.pin(A.read(src,256*1024**2))==dict(bytes=size,sha256=sha),'whole original573 archive/signature identity');shutil.copyfile(src,out/'packages'/src.name)
   rows.append(dict(name=row['name'],version=row['version'],archive='packages/'+row['filename'],size=row['size'],sha256=row['sha256'],signature='packages/'+row['filename']+'.sig',signature_size=row['signature_size'],signature_sha256=row['signature_sha256'],signer=ALARM))
  for n,(p,report)in sources.items():
   row=req[n];target=out/'packages'/p.name;shutil.copyfile(p,target);r=dict(name=n,version=row['version'],archive='packages/'+p.name,size=row['size'],sha256=row['sha256'],signature='packages/'+p.name+'.sig',signer=ALARM if row.get('signer')==ALARM else None);rows.append(r)
   if r['signer']==ALARM:
    sig=carrier/'upstream-signatures'/(p.name+'.sig');A.need(A.pin(A.read(sig))==dict(bytes=row['signature_size'],sha256=row['signature_sha256']),'exact original official detached signature');shutil.copyfile(sig,target.with_name(target.name+'.sig'))
   else:to_sign.append(target)
  tick(deadline);A.need(len(rows)==606 and len(to_sign)==28,'exact573 upstream plus original5 upstream/28 TEST incoming');signer=sign.sign(out/'keys',private,to_sign)
  for row in rows:
   if row['signer']is None:row['signer']=signer
   sig=out/row['signature'];row.update(signature_size=sig.stat().st_size,signature_sha256=A.pin(A.read(sig))['sha256'])
  verifier=V.PublicVerifier(private/'public-verifier',[out/'keys/archlinuxarm.gpg',out/'keys/TEST-public.asc']);streams={}
  for row in rows:
   tick(deadline);result=subprocess.run(verifier.argv+['--status-fd=1','--verify',str(out/row['signature']),str(out/row['archive'])],capture_output=True,text=True,timeout=min(30,max(.01,deadline-time.monotonic())),check=True);V.valid_signer(result.stdout,row['signer']);A.need(len(result.stdout)+len(result.stderr)<=65536 and not re.search(r'\[GNUPG:\] (KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYREVOKED|NO_PUBKEY)(?: |\n|$)',result.stdout),'full current original GPG expiry/revocation/status gate');streams[row['name']]=dict(stdout=A.pin(result.stdout.encode()),stderr=A.pin(result.stderr.encode()),returncode=0)
  verifier.close();verifier=None
  subprocess.run(['gpgconf','--homedir',str(private/'test-signing'),'--kill','all'],check=True,capture_output=True,timeout=15);shutil.rmtree(private);A.need(not private.exists(),'owned private key/agent retirement');retired=True
  origins={}
  plan=dict(status='SOURCE_OWNED_EXACT606_GUI_INPUT_PLAN_NO_NATIVE_GUI_AUTHORITY',source_carrier=external,welcome8_carrier=welcome_external,apps8_carrier=apps8_input['proof'],required=req,bootstrap=build,signature_streams=streams,signer_roles=dict(ephemeral_TEST=signer,upstream_ALARM=ALARM),private_retired=True,actual_source=None,actual_ref=None,actual_run=None)
  for name,value in [('original604-manifest.json',old),('original-tools606-products.json',A.obj(carrier/'provenance/products.json')),('original-latest-input-plan.json',plan)]:raw=A.enc(value);(out/name).write_bytes(raw);origins[name]=A.pin(raw)
  builder=(base/'installed-packages.lock').read_bytes();A.need(A.pin(builder)['sha256']=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac','original574 builder inventory');(out/'builder-packages.lock').write_bytes(builder);shutil.copyfile(root/'factory/expected606.lock',out/'expected-installed.lock');keys=[dict(path='keys/'+n,size=(out/'keys'/n).stat().st_size,sha256=A.pin(A.read(out/'keys'/n))['sha256'])for n in('TEST-public.asc','archlinuxarm.gpg')]
  manifest=dict(schema_version=1,status='READY_SIGNED_CURRENT606_WELCOME8',packages=sorted(rows,key=lambda r:r['name']),expected_lock=dict(path='expected-installed.lock',sha256=A.pin((root/'factory/expected606.lock').read_bytes())['sha256']),builder_lock=dict(path='builder-packages.lock',size=len(builder),sha256=A.pin(builder)['sha256']),keyrings=keys,preparation=dict(signer_roles=plan['signer_roles'],archive_count=606,compressed_archive_bytes=sum(r['size']for r in rows)),original_input_pins=origins)
  (out/'manifest.json').write_bytes(A.enc(manifest));return dict(status='READY_EXACT_SIGNED606_INPUTS_NO_GUI_AUTHORITY',manifest=A.pin(A.read(out/'manifest.json')),input_plan=A.pin(A.read(out/'original-latest-input-plan.json')),private_retired=True)
 finally:
  if verifier is not None:verifier.close()
  if not retired and private.exists():
   (out/'private-retirement-refusal.json').write_bytes(A.enc(dict(status='UNCERTAIN_SIGNER_RETIREMENT_PRESERVE_PRODUCER',path=str(private))))
