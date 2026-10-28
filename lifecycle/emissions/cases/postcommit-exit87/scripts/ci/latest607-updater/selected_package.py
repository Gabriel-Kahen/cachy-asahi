# SPDX-License-Identifier: MIT
"""Source-bound accepted Apps16 archive/provenance; no installed-state authority."""
import hashlib,json,os,stat
from pathlib import Path
from types import SimpleNamespace
NAME='cachy-asahi-apps';VERSION='0.1.0-16';SHA='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary selected16 input');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=cap,'bounded selected16 input');b=p.read_bytes();t=p.lstat();need(len(b)==s.st_size and(s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns)==(t.st_dev,t.st_ino,t.st_mtime_ns,t.st_ctime_ns),'stable complete selected16 input');return b
def descriptor():
 return json.loads(read(Path(__file__).with_name('selected-input.json')))
def locks(root):
 p=descriptor();folder=Path(root)/'scripts/ci/full-development-composition';paths=[folder/n for n in('expected-updater-v2.lock','expected-setup4-v2.lock')];values=[]
 for path,key in zip(paths,('before','after')):
  b=read(path);need(pin(b)==p[key],'whole607 selected lock');pairs=[line.split()for line in b.decode('ascii').splitlines()];need(len(pairs)==607 and all(len(r)==2 for r in pairs)and len(dict(pairs))==607,'complete duplicate-free607 inventory');values.append(dict(pairs))
 before,after=values;need(before[NAME]=='0.1.0-6'and after==dict(before,**{NAME:VERSION})and before['cachy-asahi-setup']=='0.1.0-6','only Apps6 to16 with all606 fixed');return *paths,before,after

def inspect_package(args,api):
 p=descriptor();pair=Path(args.setup4_pair);archive=pair/'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz';native=pair/'public/runtime/cachy-asahi-apps-a/provenance.json';need(Path(args.package)==archive and Path(args.provenance)==native and pin(read(archive))==p['archive']==dict(bytes=29664,sha256=SHA),'exact selected16 archive and native operands')
 reports=[];records=[]
 for side in('a','b'):
  pkg=pair/('public/packages/cachy-asahi-apps-'+side)/(NAME+'-'+VERSION+'-any.pkg.tar.xz');provenance=pair/('public/runtime/cachy-asahi-apps-'+side)/'provenance.json';need(pin(read(pkg))==p['archive']and pin(read(provenance))==p['provenance'][side],'both exact source-bound native package/provenance bodies');report=api.checks.package(pkg);record=json.loads(read(provenance));need(not report['errors']and report['sha256']==SHA and report['metadata']==p['metadata'],'whole accepted Apps16 package metadata');need(record['artifacts']=={NAME+'-'+VERSION+'-any.pkg.tar.xz':SHA}and record['expected_packages_sha256']==p['build_inventory_sha256']and record['recipe_inputs']['PKGBUILD']==p['recipe_sha256'],'exact actual original native archive/BUILDINFO/recipe provenance');reports.append(report);records.append(record)
 
 for side in('a','b'):
  need(pin(read(pair/('public/runtime/cachy-asahi-apps-'+side)/'expected-packages.lock'))==p['build_evidence']['raw_pacman_Q_pin'],'both genuine original575 native input locks')
 need(reports[0]==reports[1],'complete accepted pair report equality');payload=api.composition.payload(reports[0]);wanted=p['payload'];need(len(payload)==8 and{r['path']:r for r in payload}==wanted,'all8 exact source-bound Apps16 payloads')
 for n,w in p['source_files'].items():need(pin(read(pair/'public/source'/NAME/n))==w,'complete Apps16 installed source/product input '+n)
 evidence=pair/'public-build-evidence.json';need(json.loads(read(evidence))==p['build_evidence'],'whole original native input evidence, no invented pacman-Q lock');return SimpleNamespace(pair=pair,retained=archive,report=reports[0],payload=payload,package=archive,native=native,native_record=records[0],build_evidence=evidence)
