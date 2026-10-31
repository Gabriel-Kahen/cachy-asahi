# SPDX-License-Identifier: MIT
"""Source-pinned Apps6 pair inspector; never execute retained package/source bytes."""
import hashlib,json,os,re,stat
from pathlib import Path
from types import SimpleNamespace
NAME='cachy-asahi-apps';VERSION='0.1.0-6'
SOURCE='ec135f26326158591e6d25d5f670083d5306b071';RUN=39029873349
PACKAGE='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'
RECIPE='aa4d6ed7865aab606a55e7de94e50d6966f47f7b926a39efd4b3f64eec403778';BUILD='66c46d4645fa443d23df0e97765905555fe5bc2607787dca3f30ee2084cf597f'
DECISION='106d47fb1de4df5646c42d3b1ab95754ea2cd0871164d24f23425259166ab3c5'
STATUS='ROOT_ACCEPTED_APPS6_NATIVE_PAIRS_INSTALLED_LIFECYCLE_AND_SIGNED_SYNTHETIC_REPAIR'
BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5';AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def relative(n):
 need(type(n) is str and n and not n.startswith('/') and '\\' not in n and '\x00' not in n and all(v not in ('','.','..') for v in n.split('/')),'safe packet path');return n

def member(root,row):
 need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=96*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'bounded exact packet reference')
 p=root/relative(row['path']);need(not any(n.is_symlink() for n in (p,*p.parents)),'ordinary packet path');s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==row['bytes'],'single-link packet file')
 identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mode,x.st_nlink,x.st_mtime_ns,x.st_ctime_ns)
 with p.open('rb') as f:
  need(identity(os.fstat(f.fileno()))==identity(s),'packet open identity');raw=f.read(row['bytes']+1);need(identity(os.fstat(f.fileno()))==identity(s),'packet changed while read')
 need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'] and identity(p.lstat())==identity(s),'packet byte/hash/identity differs');return p

def references(v):
 result={}
 def visit(x):
  if type(x) is dict:
   if set(x)=={'path','bytes','sha256'}:
    n=relative(x['path']);need(n not in result or result[n]==x,'conflicting packet ref');result[n]=x
   else:
    for y in x.values():visit(y)
  elif type(x) is list:
   for y in x:visit(y)
 visit(v);need(len(result)==222 and sum(r['bytes'] for r in result.values())<=64*1024**2,'exact223 complete native packet cap');return result

def packet(root,binding):
 root=Path(root);need(binding.get('status')==STATUS and binding.get('native_source')==SOURCE and binding.get('native_run')==RUN and binding.get('root_decision_sha256')==DECISION and re.fullmatch('[0-9a-f]{40}',binding.get('carrier_source') or ''),'source-bound native pair authority remains UNBOUND')
 index=json.loads(member(root,binding['index']).read_bytes());need(index['kind']=='ROOT_ACCEPTED_APPS6_COMPLETE_NATIVE_PUBLIC_INPUTS' and index['native_source']==SOURCE and index['native_run']==RUN and index['attempt']==1,'exact Apps6 original index')
 refs=references(index);paths={n:member(root,r) for n,r in refs.items()};nodes=list(root.rglob('*'));need(len(nodes)<=512 and all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes),'bounded ordinary packet nodes');need({p.relative_to(root).as_posix() for p in nodes if p.is_file()}==set(refs)|{binding['index']['path']},'closed exact packet files')
 parents={p.as_posix() for n in set(refs)|{binding['index']['path']} for p in Path(n).parents if p.as_posix()!='.'};need(all(p.is_file() or p.relative_to(root).as_posix() in parents for p in nodes),'no unreferenced packet directories')
 d=paths[index['root_decision']['path']];decision=json.loads(d.read_bytes());need(sha(d)==DECISION and decision['status']==STATUS and decision['source']==SOURCE and decision['run']==RUN and decision['attempt']==1,'original Root Apps6 authority')
 return index,paths

def locks(root):
 folder=Path(root)/'scripts/ci/full-development-composition';paths=[folder/n for n in ('expected-updater-v2.lock','expected-setup4-v2.lock')];need([sha(p) for p in paths]==[BEFORE,AFTER],'exact Apps5→6 full604 locks');before,after=[dict(line.split() for line in p.read_text().splitlines()) for p in paths];need(len(before)==len(after)==604 and before[NAME]=='0.1.0-5' and after==before|{NAME:VERSION} and before['cachy-asahi-setup']==after['cachy-asahi-setup']=='0.1.0-5','Apps only; other603 unchanged');return *paths,before,after

def inspect_package(args,api):
 pair=Path(args.setup4_pair);binding=json.loads(Path(__file__).with_name('apps6-binding.json').read_bytes());index,paths=packet(pair,binding);product=json.loads(Path(__file__).with_name('apps6-product.json').read_bytes());files=index['files'];source=pair/'public/source'/NAME
 for n,row in product['source_files'].items():need(member(source,dict(path=n,**row)).read_bytes()==paths[files['source/'+NAME+'/'+n]['path']].read_bytes(),'exact source product/native payload binding')
 reports=[];records=[]
 for side in ('a','b'):
  archive=pair/('public/packages/'+NAME+'-'+side)/(NAME+'-'+VERSION+'-any.pkg.tar.xz');native=pair/('public/runtime/'+NAME+'-'+side);record=json.loads((native/'provenance.json').read_bytes())
  need(archive.stat().st_size==22876 and sha(archive)==PACKAGE and record['status']=='built-package-static-pass' and record['mode']=='native' and record['expected_packages_sha256']==BUILD and sha(native/'expected-packages.lock')==BUILD and len((native/'expected-packages.lock').read_text().splitlines())==575 and record['artifacts']=={archive.name:PACKAGE} and record['recipe_inputs']['PKGBUILD']==RECIPE,'actual Apps6 native pair provenance')
  env=(native/'artifacts/environment.txt').read_text().splitlines();argv=record['command'];need(len(env)>2 and ' aarch64 GNU/Linux' in env[0] and env[1]=='4096' and '--platform=linux/arm64' in argv and '--network=none' in argv and '--read-only' in argv and record['image']==record['image_id'],'actual ordinary native offline pair')
  for n,digest in record['recipe_inputs'].items():need('/' not in n and n not in ('.','..') and sha(source/n)==digest,'original native source hashes')
  report=api.checks.package(archive);need(not report['errors'] and report['sha256']==PACKAGE and not api.build.bind_artifact(api.checks.metadata((source/'.SRCINFO').read_text()),report,RECIPE),'Apps6 PKGINFO/BUILDINFO/source binding')
  pkg=report['metadata']['.PKGINFO'];need(pkg['pkgname']==[NAME] and pkg['pkgver']==[VERSION] and pkg['license']==['MIT'] and pkg.get('url')==['https://github.com/Gabriel-Kahen/cachy-asahi'] and sorted(pkg['depend'])==sorted(['python>=3.11','gnupg','libarchive','pacman','cachy-asahi-repository-runtime=0.1.0-1']) and not pkg.get('provides') and not pkg.get('conflict'),'exact Apps6 dependency identity')
  payload=api.composition.payload(report);wanted={'/'+p:(product['source_files'][n]['sha256'],mode) for p,(n,mode) in product['payload'].items()};need(len(payload)==8 and {r['path'] for r in payload}==set(wanted),'exact8 source-bound Apps6 payloads')
  for r in payload:need(r['type']=='file' and (r['sha256'],r['mode'])==wanted[r['path']],'Apps6 source/payload differs')
  reports.append((archive,report,payload));records.append(record)
 need(records[0]['clean_environment_id']!=records[1]['clean_environment_id'],'two distinct native builders');archive,report,payload=reports[0];native=pair/'public/runtime'/ (NAME+'-a')/'provenance.json';need(Path(args.package)==archive and Path(args.provenance)==native,'exact first accepted archive/provenance')
 return SimpleNamespace(pair=pair,retained=archive,report=report,payload=payload,package=archive,native=native,native_record=records[0],build_lock=native.parent/'expected-packages.lock')
