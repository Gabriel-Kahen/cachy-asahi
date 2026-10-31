# SPDX-License-Identifier: MIT
"""Exact public pair data inspection; never invent raw575 pacman-Q lock bytes."""
import hashlib,importlib.util,json,os,shutil,sys
from pathlib import Path
from types import SimpleNamespace
NAME='cachy-asahi-apps';VERSION='0.1.0-6';SOURCE='c5481ad6bfd1539ab9a289bc9541133b979858f7'
PACKAGE='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7';BUILD='66c46d4645fa443d23df0e97765905555fe5bc2607787dca3f30ee2084cf597f'
BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5';AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
SCOPE='PUBLIC_ROOT_PAIR_AUTHORITY_PROVENANCE_AND_COMPLETE_BUILDINFO_NOT_RAW_Q_LOCK_REPLAY'
def need(v,w):
 if not v:raise ValueError(w)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def utility(source):
 H=load('_public_pair_regular_inputs',Path(source)/'scripts/ci/management-tools-generic16k/contract.py')
 def checked(root,row,cap=16*1024**2):
  H.need(row['bytes']<=cap,'bounded public reference');H.checked(root,row);return Path(root)/row['path']
 def scoped(name,path,aliases):
  missing=object();saved={k:sys.modules.get(k,missing) for k in aliases}
  try:sys.modules.update(aliases);return load(name,path)
  finally:
   for k,v in saved.items():
    if v is missing:sys.modules.pop(k,None)
    else:sys.modules[k]=v
 return SimpleNamespace(need=need,safe=H.safe,checked=checked,read=lambda p:json.loads(H.read(p)),load=load,scoped_load=scoped)
def inspect_public(source,packet,authority,binding,api):
 C=utility(source);helper=load('_public_pair_exact_validator',Path(source)/'scripts/ci/expanded604-apps6-public-pairs/apps_inputs.py');normalized=helper.validate(C,Path(source),Path(packet),binding,api.checks,api.build,Path(authority));index=json.loads((Path(packet)/'index.json').read_bytes());row=index['packages'][NAME];need(row['native_source']==SOURCE and row['native_run']=='39027622244' and row['version']==VERSION and row['qualification']=='NATIVE_PAIR_ONLY','exact original public Apps6 pair identity')
 records=[];reports=[]
 for side in ('a','b'):
  p=C.checked(packet,row['files'][side]);report=api.checks.package(p);record=C.read(C.checked(packet,row['provenance'][side]));installed=report['metadata']['.BUILDINFO']['installed'];need(len(installed)==len(set(installed))==575 and record['expected_packages_sha256']==BUILD and record['recipe_inputs']['PKGBUILD']==row['source_files']['PKGBUILD']['sha256'],'complete actual BUILDINFO/provenance join');records.append(record);reports.append(report)
 evidence=dict(schema_version=1,scope=SCOPE,raw_pacman_Q_lock='NOT_PRESENT_NOT_FABRICATED',expected_pacman_Q_sha256=BUILD,package_sha256=PACKAGE,native_source=SOURCE,native_run=39027622244,qualification='NATIVE_PAIR_ONLY',original_pair_decision=row['decision'],independent_byte_case=binding['byte_case_decision'],builds=[dict(provenance=row['provenance'][side],BUILDINFO_installed=reports[i]['metadata']['.BUILDINFO']['installed'],BUILDINFO_installed_sha256=hashlib.sha256(encoded(reports[i]['metadata']['.BUILDINFO']['installed'])).hexdigest()) for i,side in enumerate(('a','b'))])
 return row,reports,records,evidence

def stage(C,root,target,binding,authority,implementation):
 checks=C.load('_public_stage_package_checks',Path(implementation)/'scripts/checks/package_checks.py');api=SimpleNamespace(checks=checks,build=C.scoped('_public_stage_build',Path(implementation)/'scripts/build/build.py',{'package_checks':checks}))
 row,reports,records,evidence=inspect_public(implementation,root,authority,binding,api);need(not target.exists() and target.parent.is_dir() and not any(p.is_symlink() for p in (target,*target.parents)),'fresh owned public pair stage');target.mkdir(mode=0o700)
 def copy(path,name):
  dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(path,dest)
 for path in Path(root).rglob('*'):
  if path.is_file():copy(path,'packet/'+path.relative_to(root).as_posix())
 helper=load('_public_stage_identity',Path(implementation)/'scripts/ci/expanded604-apps6-public-pairs/apps_inputs.py');copy(Path(authority)/helper.DECISION['path'],'authority/'+helper.DECISION['path'])
 for side in ('a','b'):
  copy(Path(root)/row['files'][side]['path'],'public/packages/'+NAME+'-'+side+'/'+NAME+'-'+VERSION+'-any.pkg.tar.xz');copy(Path(root)/row['provenance'][side]['path'],'public/runtime/'+NAME+'-'+side+'/provenance.json')
 for n,ref in row['source_files'].items():copy(Path(root)/ref['path'],'public/source/'+NAME+'/'+n)
 (target/'public-build-evidence.json').write_bytes(encoded(evidence));return target

def locks(root):
 folder=Path(root)/'scripts/ci/full-development-composition';paths=[folder/n for n in ('expected-updater-v2.lock','expected-setup4-v2.lock')];need([sha(p) for p in paths]==[BEFORE,AFTER],'exact Apps5→6 full604 locks');before,after=[dict(line.split() for line in p.read_text().splitlines()) for p in paths];need(len(before)==len(after)==604 and before[NAME]=='0.1.0-5' and after==before|{NAME:VERSION} and before['cachy-asahi-setup']==after['cachy-asahi-setup']=='0.1.0-5','Apps only; other603 unchanged');return *paths,before,after

def inspect_package(args,api):
 pair=Path(args.setup4_pair);source=Path(args.source_root);binding=json.loads(Path(__file__).with_name('apps6-binding.json').read_bytes());row,reports,records,evidence=inspect_public(source,pair/'packet',pair/'authority',binding,api);need(json.loads((pair/'public-build-evidence.json').read_bytes())==evidence,'exact complete public build evidence')
 archive=pair/'public/packages'/ (NAME+'-a')/(NAME+'-'+VERSION+'-any.pkg.tar.xz');native=pair/'public/runtime'/(NAME+'-a')/'provenance.json';need(Path(args.package)==archive and Path(args.provenance)==native and sha(archive)==row['files']['a']['sha256']==PACKAGE and sha(native)==row['provenance']['a']['sha256'],'exact byte-identical public selected archive/provenance copies')
 product=json.loads(Path(__file__).with_name('apps6-product.json').read_bytes())
 for n,r in product['source_files'].items():need(sha(pair/'public/source'/NAME/n)==r['sha256'],'current selected source product bytes')
 payload=api.composition.payload(reports[0]);wanted={'/'+p:(product['source_files'][n]['sha256'],mode) for p,(n,mode) in product['payload'].items()};need(len(payload)==8 and {r['path'] for r in payload}==set(wanted) and all(r['type']=='file' and (r['sha256'],r['mode'])==wanted[r['path']] for r in payload),'all8 exact current source-bound selected payload leaves')
 return SimpleNamespace(pair=pair,retained=archive,report=reports[0],payload=payload,package=archive,native=native,native_record=records[0],build_evidence=pair/'public-build-evidence.json')
