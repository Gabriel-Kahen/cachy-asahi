#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New TEST assets from already public originals; separate nativeGUI precondition."""
import argparse,ast,hashlib,importlib.util,json,os,re,shutil,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
CARRIER='77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90'
INDEX=dict(path='index.json',bytes=34490,sha256='4e6a8fb3285a53dacd2ce06348b40238b32256df40ecc8b5e07a93fb5b0310b6')
CONTRACT='scripts/ci/expanded604-current-management-managed16k/contract.py'
VERSIONS={'cachy-asahi-welcome':'0.1.0-4','cachy-asahi-doctor':'0.1.0-1','cachy-asahi-orphans':'0.1.0-2'}
PROFILES={'minimal':'39014808038','overlay':'39014822190'}
PURPOSE='FRESH_TEST_SIGNED_EXACT_PUBLIC_WELCOME4_GUI_ARCHIVES_NOT_HISTORICAL_CAPTURE_INPUTS'

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def relative(n):need(type(n)is str and n and not n.startswith('/') and '\\' not in n and all(x not in ('','.','..') for x in n.split('/')) and all(32<=ord(c)<127 for c in n),'ordinary relative input');return n
def read(p,cap=16*1024**2):
 p=Path(p);need(not any(x.is_symlink() for x in (p,*p.parents)),'no input alias');a=p.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=cap,'bounded ordinary singlelink input');raw=p.read_bytes();b=p.stat();identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns);need(identity(a)==identity(b) and len(raw)==a.st_size,'input drift');return raw
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def row(p):r=read(p);return dict(bytes=len(r),sha256=sha(r))
def checked(root,ref,cap=16*1024**2):
 need(type(ref)is dict and set(ref)=={'path','bytes','sha256'} and type(ref['bytes'])is int and 0<ref['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',ref['sha256'] or ''),'bounded exact input reference');p=Path(root)/relative(ref['path']);raw=read(p,cap);need(dict(bytes=len(raw),sha256=sha(raw))=={k:ref[k] for k in ('bytes','sha256')},'exact input hash differs: '+ref['path']);return p

def source(root):
 need(not sys.flags.optimize,'unoptimized original signer assertions required');pins=obj(read(HERE/'source-pins.json'))['files'];need(len(pins)==12,'finite12 source helpers/recipe/license identities')
 for n,pin in pins.items():checked(root,dict(path=n,**pin))
 tree=ast.parse(read(Path(root)/CONTRACT));values=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='ARCHIVES' for x in n.targets)];need(len(values)==1,'one tracked archive contract');return ast.literal_eval(values[0])
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def inspect(root,packet):
 """Readonly data proof only; no Git, sign, native acceptance or unpublished inputs."""
 archives=source(root);index=obj(read(checked(packet,INDEX),65536));need(index['candidate_source']=='0b74d8ecea4f152bda4adfbd9bee488890db4363' and index['native_source']=='3c06dad15dec0dbfe47d5f064a9c56ce76f59756' and index['native_run']==39002929704 and index['GUI']=='FAIL_NOT_ACCEPTED','public nativepair/CLI authority stays separate from GUI')
 refs=index['evidence']['files'];need(type(refs)is list and len(refs)==97,'exact original97-file public evidence closure');byname={r['path']:r for r in refs};need(len(byname)==len(refs),'no repeated public evidence paths');total=0
 for ref in refs:total+=checked(packet,ref).stat().st_size
 need(total<=16*1024**2 and {p.relative_to(packet).as_posix() for p in Path(packet).rglob('*') if p.is_file()}==set(byname)|{'index.json'},'finite closed existing public packet')
 decision=obj(read(checked(packet,index['decision'])));need(decision['status']=='ROOT_ACCEPTED_WELCOME4_NATIVE_PAIR_AND_SIGNED_INSTALLED_CLI_ONLY' and decision['source_sha']==index['native_source'] and decision['run_id']==index['native_run'],'public Root nativepair authority')
 checks=load('_public_gui_archive_checks',Path(root)/'scripts/checks/package_checks.py');products={};licenses={};origins={}
 for name,(size,digest) in archives.items():
  arch='aarch64' if name=='cachy-asahi-welcome' else 'any';filename=name+'-'+VERSIONS[name]+'-'+arch+'.pkg.tar.xz';key='signed/'+filename;ref=byname[key];path=checked(packet,ref);need(ref['bytes']==size and ref['sha256']==digest,'exact tracked GUI archive bytes')
  public=decision['packages'][name];need(public['version']==VERSIONS[name] and public['archives']=={s:dict(bytes=size,sha256=digest) for s in ('a','b')} and public['comparison']['status']=='contents-reproduced' and not public['comparison']['errors'],'original independently accepted pair identity')
  report=checks.package(path);need(not report['errors'] and report['metadata']['.PKGINFO']['pkgname']==[name] and report['metadata']['.PKGINFO']['pkgver']==[VERSIONS[name]] and report['metadata']['.PKGINFO']['license']==['MIT'] and report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[row(Path(root)/'packages/tools'/name/'PKGBUILD')['sha256']],'public archive metadata/recipe/license binding')
  need(set(report['elf'])==({'usr/bin/'+name} if name=='cachy-asahi-welcome' else set()),'same nativeELF/script product traits')
  payload={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')};licenses[name]={}
  for leaf in ('LICENSE','NOTICE'):
   n='usr/share/licenses/'+name+'/'+leaf;r=payload[n];expected=row(Path(root)/'packages/tools'/name/leaf);need(r['type']=='0' and r['uid']==r['gid']==0 and r['sha256']==expected['sha256'] and r['size']==expected['bytes'],'exact public embedded license/notice');licenses[name][leaf]=expected
  if name in index['packages']:
   accepted=index['packages'][name];need(accepted['payload']==payload and accepted['version']==VERSIONS[name],'unchanged original pair payload')
   for side in ('a','b'):need(row(checked(packet,accepted['files'][side]))==dict(bytes=size,sha256=digest),'genuine two public pair archives')
  products[name]=dict(archive=filename,version=VERSIONS[name],sha256=digest,payload=payload);origins[name]=ref
 return dict(status='DATA_ONLY_EXACT_PUBLIC_GUI_ARCHIVES_AVAILABLE',public_carrier=CARRIER,index=INDEX,public_native_decision=index['decision'],public_file_count=98,public_bytes=total+INDEX['bytes'],archives={n:dict(bytes=r[0],sha256=r[1]) for n,r in archives.items()},products=products,origins=origins,licenses=licenses,GUI_authority='NOT_PROVIDED_BY_PUBLIC_NATIVE_PACKET',historical_GUI_assets='NOT_READ_OR_REUSED',signature_generation='NOT_RUN',generic16k='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def gui_component(doc,archives):
 need(doc.get('status')=='ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI_INDEPENDENT_PROFILES' and doc.get('authority_kind')=='DERIVED_ROOT_ACCEPTED_NATIVE_GUI_COMPONENT_FACTS' and doc.get('asset_binding')=='NO_HISTORICAL_GUI_ASSET_PACKET_INCLUDED_NEW_PUBLIC_ASSET_ROUTE_REQUIRED','separate sanitized Root GUI component authority required')
 need('run_id' not in doc and doc.get('profile_runs')==PROFILES and doc.get('profiles')==['minimal','overlay'] and doc.get('source_sha')=='e0b03524745de71aa3ab2ebe16a2cfa979553442' and doc.get('source_manifest_sha256')=='c0708d6b5d2292b6be1b8eb700f375049415e683875ac915b3e61a1ac8d86720','original distinct two-profile source/run identities')
 need(doc.get('frames')==24 and doc.get('management_operations_per_profile')==17 and doc.get('doctor_lifetime')=='PASS_ACTUAL_CHILD_WAIT_RELEASE_AND_FIXED_PARENT' and doc.get('gui_contract')==doc.get('cleanup')=='PASS' and doc.get('candidate_source')=='0b74d8ecea4f152bda4adfbd9bee488890db4363' and doc.get('archives')==archives and all(doc.get(n.removeprefix('cachy-asahi-')+'_version')==v for n,v in VERSIONS.items()),'complete unchanged24-frame/17-operation/lifetime/archive contract')
 expected={profile:dict(run_id=run,closed_public_members=299,direct_child_wait=0,doctor_release='RELEASED',frames=12,gui_cleanup_steps=14,operations=17,owned_consumer_cleanup_count=8,source_joins=267,terminal_exit=0) for profile,run in PROFILES.items()}
 need(doc.get('profile_results')==expected,'all ten original finite profile outcome/count fields required')
 need(doc.get('hardware')=='NOT_RUN' and doc.get('release')=='NOT_ADMITTED' and doc.get('runtime')=='GENERIC_ARM64_4096_SOFTWARE_QEMU_GUI' and doc.get('installed16k')=='NOT_ACCEPTED' and doc.get('source_preservation')=='PASS' and doc.get('payload_database_user_trust_preservation')=='PASS_SOURCE_OWNED_ACTUAL_CHECKS' and doc.get('visual_review')=='PASS_ALL24_ORIGINAL_FIRST_FRAMES_AND_FOUR_FULL_RESOLUTION_MANAGEMENT_FRAMES','nativeGUI never16K/M2 or historical asset transfer')
 need(doc.get('original_root_decision_sha256')=='ee8e444831efeab0c904531373b40533fe3585ad248aabdc300eceaf49239790' and doc.get('qualifications')==[
  'Two distinct owned runs share one exact source/workflow and identical three candidate archive/payload identities',
  'Separate native CLI lifecycle and generic GUI results; physical Apple input/graphics/audio/suspend/recovery not run',
  'Original source-enforced TEST signature checks; no new cryptographic verification claimed by passive replay',
  'Private full-root maps are not exported; original full preservation checks and bounded retained summaries are replayed',
  'Owned teardown observations are retained originals, not fresh live re-observation',
  'No expired GNU/source-authority or maintained-provider admission transfers'],'exact original decision and all six qualifications required');return doc

def authorize(root,packet,authority_root,policy):
 v=obj(read(policy,65536));need(v.get('status')=='ROOT_BOUND_PUBLIC_ARCHIVES_AND_SEPARATE_GUI_COMPONENT' and v.get('public_carrier')==CARRIER and re.fullmatch('[0-9a-f]{40}',v.get('gui_authority_carrier') or '') and v.get('gui_authority') is not None,'UNBOUND: no output/key/signature generation')
 facts=inspect(root,packet)
 def revision(p):
  value=subprocess.check_output(['git','-C',str(p),'rev-parse','HEAD'],timeout=10,text=True);need(len(value)<=128,'bounded actual carrier identity');return value.strip()
 need(Path(packet).name=='payload' and revision(Path(packet).parent)==CARRIER and revision(authority_root)==v['gui_authority_carrier'],'exact existing public and new component carrier checkouts')
 doc=obj(read(checked(authority_root,v['gui_authority'],65536),65536));gui_component(doc,facts['archives']);need(v.get('source_manifest_sha256')==doc['source_manifest_sha256'],'exact Root GUI source manifest binding');return facts,doc,v

def asset_directory(root,binding,source_root):
 """Original9-file asset checker; only the explicit NEW purpose differs."""
 raw=read(Path(source_root)/CONTRACT);node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='assets');text=ast.get_source_segment(raw.decode(),node);old="'ACTUAL_CURRENT_WELCOME4_GUI_PUBLIC_INPUTS'";need(text.count(old)==1,'one exact asset purpose anchor');text=text.replace(old,repr(PURPOSE));space=dict(Path=Path,need=need,json_read=lambda p,cap=4*1024**2:obj(read(p,cap)),checked=checked,VERSIONS=VERSIONS,ARCHIVES=source(source_root));exec(compile(text,'<finite-new-public-GUI-asset-purpose>','exec'),space);directory=space['assets'](root,binding);files=obj(read(checked(root,binding['assets_index'],1024**2),1024**2))['files'];need({p.name for p in directory.iterdir()}==set(files) and all(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 for p in directory.iterdir()),'closed9 actual fresh asset directory');return directory

def destinations(root,packet,authority_root,output,signing_work):
 output=Path(output).absolute();work=Path(signing_work).absolute();originals=[Path(p).absolute() for p in (root,packet,authority_root)]
 pairs=[(output,work)]+[(p,q) for p in (output,work) for q in originals]
 need(os.getuid()==os.geteuid()>0 and not output.exists() and not work.exists() and output.parent.is_dir() and work.parent.is_dir() and not any(p.is_symlink() for p in (output,work,*output.parents,*work.parents)) and all(not a.is_relative_to(b) and not b.is_relative_to(a) for a,b in pairs),'fresh disjoint ordinary-owned public output/private TEST work, outside source/input/authority')
 return output,work

def prepare(root,packet,authority_root,policy,output,signing_work):
 facts,authority,policy_value=authorize(root,packet,authority_root,policy);output,work=destinations(root,packet,authority_root,output,signing_work)
 output.mkdir(mode=0o700);work.mkdir(mode=0o700);assets=output/'assets';assets.mkdir(mode=0o700)
 for name,ref in facts['origins'].items():shutil.copyfile(checked(packet,ref),assets/facts['products'][name]['archive'])
 (assets/'products.json').write_bytes(encoded(facts['products']));raw=read(Path(root)/'scripts/ci/full-development-composition/run.py');node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='sign');space=dict(subprocess=subprocess,re=re);exec(compile(ast.Module(body=[node],type_ignores=[]),'<exact-original-ephemeral-TEST-signer>','exec'),space)
 try:
  signer=space['sign'](assets,work,[assets/r['archive'] for r in facts['products'].values()]);need(re.fullmatch('[0-9A-F]{40}',signer),'fresh original TEST signer fingerprint');(assets/'control.json').write_bytes(encoded(dict(signer=signer)))
 finally:
  if (work/'test-signing').exists():subprocess.run(['gpgconf','--homedir',str(work/'test-signing'),'--kill','all'],capture_output=True,check=True,timeout=20);shutil.rmtree(work/'test-signing')
  work.rmdir()
 files={p.name:row(p) for p in assets.iterdir()};need(len(files)==9,'exact fresh three signatures/key/control/products and3 original archives');index=dict(schema_version=1,purpose=PURPOSE,files=files);(output/'index.json').write_bytes(encoded(index));binding=dict(asset_root='assets',assets_index=dict(path='index.json',**row(output/'index.json')));asset_directory(output,binding,root)
 after=inspect(root,packet);need(after==facts,'original public packet unchanged');receipt=dict(status='PREPARED_NEW_TEST_ASSETS_NOT_HISTORICAL_GUI_INPUTS',binding=binding,originals=facts,authority_sha256=policy_value['gui_authority']['sha256'],signer=signer,TEST_key_cleanup='PASS_ORIGINAL_GPGCONF_THEN_PRIVATE_HOME_REMOVED',signatures='FRESH_EPHEMERAL_TEST_ONLY_NOT_HISTORICAL_CAPTURE',generic16k='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');(output/'provenance.json').write_bytes(encoded(receipt));return receipt

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('inspect','prepare'))
 for n in ('source','packet'):p.add_argument('--'+n,type=Path,required=True)
 for n in ('authority-root','policy','output','signing-work'):p.add_argument('--'+n,type=Path)
 a=p.parse_args()
 if a.action=='inspect':value=inspect(a.source,a.packet)
 else:
  need(all(getattr(a,n) is not None for n in ('authority_root','policy','output','signing_work')),'explicit authority/policy/fresh private/public paths');value=prepare(a.source,a.packet,a.authority_root,a.policy,a.output,a.signing_work)
 print(encoded(value).decode(),end='')
