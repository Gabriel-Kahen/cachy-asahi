#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Map an explicit ARM package inventory to cached Arch advisory DATA offline."""
import argparse
from collections import Counter,defaultdict
from datetime import datetime,timezone
import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path

URL='https://security.archlinux.org/issues/all.json'
CAP=8*1024**2
NAME=re.compile(r'[A-Za-z0-9@._+-]{1,128}\Z')
VERSION=re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~:-]{0,255}\Z')
FULL_VERSION=re.compile(r'.+-[0-9]+(?:\.[0-9]+)*\Z')

class Error(ValueError):pass
def need(ok,message):
 if not ok:raise Error(message)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(items):
  result={}
  for name,value in items:need(name not in result,'duplicate JSON key: '+name);result[name]=value
  return result
 def invalid(_):raise Error('noninteger or nonfinite JSON number')
 need(0<len(raw)<=CAP,'bounded nonempty JSON input');return json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
def read(path):
 path=path.absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'input paths must be ordinary, without symlinks')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as stream:
  a=os.fstat(stream.fileno());need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<a.st_size<=CAP,'bounded ordinary single-link input');raw=stream.read(CAP+1);b=os.fstat(stream.fileno())
 identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(identity(a)==identity(b)==identity(path.stat(follow_symlinks=False))and len(raw)==a.st_size,'input changed while reading');return raw

def inventory(value):
 # Same list/{name,version,arch,provides} shape as scripts/checks/dependencies.py.
 need(type(value)is list and 0<len(value)<=20000,'explicit nonempty supported package inventory list');seen=set()
 for item in value:
  need(type(item)is dict and {'name','version','arch'}<=set(item),'inventory requires binary name/version/arch')
  name,version=item['name'],item['version'];need(type(name)is str and NAME.fullmatch(name)and name not in seen,'unique valid binary package name');seen.add(name)
  need(item['arch']in('aarch64','any')and type(version)is str and VERSION.fullmatch(version),'explicit ARM/any package with bounded version')
  for field in('pkgbase','origin'):
   if field in item:need(type(item[field])is str and 0<len(item[field])<=512 and item[field].isprintable(),'bounded optional inventory '+field)
  if 'provides'in item:need(type(item['provides'])is list and len(item['provides'])<=256 and all(type(p)is str and p.isprintable()and len(p)<=512 for p in item['provides']),'bounded provides metadata')
 return value

def advisories(value):
 need(type(value)is list and 0<len(value)<=20000,'nonempty complete tracker JSON group list');seen=set();index=defaultdict(list)
 for group in value:
  need(type(group)is dict and {'name','packages','status','severity','type','affected','fixed','issues','advisories'}<=set(group),'unsupported tracker group format')
  name=group['name'];need(type(name)is str and re.fullmatch(r'AVG-[0-9]{1,8}',name)and name not in seen,'unique valid tracker group');seen.add(name)
  packages=group['packages'];need(type(packages)is list and 0<len(packages)<=256 and all(type(n)is str and NAME.fullmatch(n)for n in packages)and len(set(packages))==len(packages),'finite exact tracker binary package names')
  for field in('affected','fixed'):need(group[field]is None or type(group[field])is str and VERSION.fullmatch(group[field]),'tracker '+field+' version must be explicit or null')
  for field in('status','severity','type'):need(type(group[field])is str and 0<len(group[field])<=256 and group[field].isprintable(),'bounded tracker '+field)
  for field,pattern in [('issues',r'CVE-[0-9]{4}-[0-9]{4,}'),('advisories',r'ASA-[0-9]{6}-[0-9]+')]:
   rows=group[field];need(type(rows)is list and len(rows)<=1024 and all(type(n)is str and re.fullmatch(pattern,n)for n in rows),'supported finite tracker '+field)
  for package in packages:index[package].append(group)
 return index

def utc(value):
 need(type(value)is str and len(value)<=40 and value.endswith('Z'),'explicit UTC timestamp ending Z')
 try:result=datetime.fromisoformat(value[:-1]+'+00:00')
 except ValueError as error:raise Error('invalid UTC timestamp')from error
 need(result.tzinfo==timezone.utc,'UTC timestamp required');return result

def provenance(value,raw,now,max_age_hours):
 need(type(value)is dict and value.get('url')==URL and all(value.get(k)==v for k,v in pin(raw).items()),'cache provenance URL/bytes/hash must match original tracker input')
 fetched=utc(value.get('retrieved_at'));age=(now-fetched).total_seconds();need(age>=0,'cache retrieval time is in the future')
 return dict(url=URL,retrieved_at=value['retrieved_at'],age_seconds=int(age),max_age_hours=max_age_hours,cache_stale=age>max_age_hours*3600,tracker_update_time='UNKNOWN_NOT_IN_THIS_FEED',tracker_completeness='UNKNOWN',action='Refresh the official JSON cache over HTTPS and preserve this prior report before rerunning.'if age>max_age_hours*3600 else'Review tracker/upstream coverage separately; recent retrieval does not prove current or complete advisory data.',origin_verification='OPERATOR_PROVENANCE_RECORD_NOT_A_SIGNED_ADVISORY_ATTESTATION')

def compare(left,right):
 # The same real Arch comparator used by the existing dependency/cache tools.
 try:r=subprocess.run(['/usr/bin/vercmp',left,right],capture_output=True,text=True,check=True,timeout=5,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
 except(OSError,subprocess.SubprocessError)as error:raise Error('Arch /usr/bin/vercmp unavailable or failed; no replacement version ordering')from error
 need(re.fullmatch(r'-?[0-9]+\s*',r.stdout)is not None,'unexpected vercmp output');value=int(r.stdout);return(value>0)-(value<0)

def report(items,groups,cache,as_of,compare_versions=compare):
 index=advisories(groups);rows=[]
 for item in sorted(inventory(items),key=lambda v:v['name']):
  findings=[]
  for group in sorted(index.get(item['name'],[]),key=lambda g:int(g['name'][4:]),reverse=True):
   affected,fixed=group['affected'],group['fixed'];relation='UNKNOWN_NO_ARCH_FIXED_VERSION';action='Review the linked CVEs and selected ARM source/patches; the tracker provides no Arch fixed package version.'
   if fixed is not None:
    if not FULL_VERSION.fullmatch(item['version'])or not FULL_VERSION.fullmatch(fixed):relation='UNKNOWN_INCOMPLETE_PACKAGE_VERSION';action='Supply the complete epoch:pkgver-pkgrel tuple before comparing the selected package with the Arch fixed reference.'
    elif compare_versions(item['version'],fixed)<0:relation='BELOW_ARCH_FIXED_REFERENCE';action=f"Inspect the selected ARM source and patches for these CVEs; obtain or build an authenticated ARM package with the required fixes. Arch reference: {fixed}; ARM fixed availability is unknown."
    else:relation='AT_OR_ABOVE_ARCH_FIXED_REFERENCE';action='Verify that the selected ARM source/build contains the advisory fixes; version ordering alone does not prove ARM mitigation.'
   finding={k:group[k]for k in('name','severity','type','issues','advisories')};finding.update(arch_status=group['status'],arch_affected_version=affected,arch_fixed_version=fixed,url='https://security.archlinux.org/'+group['name'],version_relation=relation,action=action,arm_applicability='UNKNOWN',arm_fixed_version='UNKNOWN');findings.append(finding)
  if not findings:state='UNKNOWN_NO_TRACKER_MATCH';action='Review upstream/security sources for this exact binary package. Source pkgbase and virtual provides were not used as advisory aliases; absence from this cache is not evidence of safety.'
  elif any(f['version_relation']!='AT_OR_ABOVE_ARCH_FIXED_REFERENCE'for f in findings):state='REVIEW_REQUIRED';action='Review the advisory-specific actions below with the selected ARM source and package maintainer.'
  else:state='ARCH_REFERENCES_MET_ARM_UNVERIFIED';action='Confirm ARM patch/build correspondence for the listed advisories; retain independent ARM mitigation evidence.'
  rows.append(dict(name=item['name'],version=item['version'],arch=item['arch'],origin=item.get('origin','UNKNOWN_OPERATOR_NOT_SUPPLIED'),pkgbase=item.get('pkgbase'),matching_basis='EXACT_BINARY_PACKAGE_NAME_ONLY',status=state,action=action,arm_security_status='UNKNOWN',findings=findings))
 return dict(schema_version=1,status='OFFLINE_ADVISORY_REVIEW_REPORT_NOT_SECURITY_ACCEPTANCE',as_of=as_of,cache=cache,scope='ONLY_EXPLICITLY_SUPPLIED_SUPPORTED_ARM_INVENTORY',arm_security_status='UNKNOWN',system_coverage='UNKNOWN_NOT_DISCOVERED',inventory_packages=len(rows),tracker_groups=len(groups),summary=dict(Counter(row['status']for row in rows)),limitations=['Arch tracker package versions are Arch references, not ALARM/Asahi fixed-version attestations.','Name and version equality do not establish shared source, patches, build configuration or exploitability.','Missing matches, unknown statuses, stale caches and newly downloaded old data never establish unaffectedness.','This monitor does not discover installed packages, inspect transitive dependencies, install updates or contact any service.'],packages=rows)

def text_report(value):
 lines=['ARM advisory review: security status UNKNOWN',f"As of {value['as_of']}; packages supplied: {value['inventory_packages']}; tracker groups: {value['tracker_groups']}",f"Cache retrieved: {value['cache']['retrieved_at']}; stale: {value['cache']['cache_stale']}; tracker completeness/update time: UNKNOWN",value['cache']['action'],'']
 for row in value['packages']:
  lines.extend([f"{row['name']} {row['version']} [{row['arch']}] — {row['status']}",row['action']])
  for finding in row['findings']:lines.extend([f"  {finding['name']} | {finding['severity']} | Arch status {finding['arch_status']} | {finding['version_relation']}",f"  Arch affected reference: {finding['arch_affected_version']}; Arch fixed reference: {finding['arch_fixed_version']}; ARM fixed: UNKNOWN",'  '+', '.join(finding['issues']),'  '+finding['url'],'  '+finding['action']])
  lines.append('')
 return '\n'.join(lines)+'\n'

def run(a):
 need(type(a.max_age_hours)is int and 1<=a.max_age_hours<=24*365,'bounded cache age setting')
 originals={n:read(p)for n,p in [('inventory.json',a.inventory),('advisories.json',a.advisories),('provenance.json',a.provenance)]}
 now=datetime.now(timezone.utc)if a.as_of is None else utc(a.as_of);as_of=now.isoformat().replace('+00:00','Z');groups=decode(originals['advisories.json']);cache=provenance(decode(originals['provenance.json']),originals['advisories.json'],now,a.max_age_hours);value=report(decode(originals['inventory.json']),groups,cache,as_of);value['inputs']={n:pin(raw)for n,raw in originals.items()}
 out=a.output.absolute();need(not out.exists()and not any(p.is_symlink()for p in(out,*out.parents))and out.parent.is_dir(),'fresh ordinary report directory required')
 out.mkdir(mode=0o700)
 for name,raw in dict(originals,**{'report.json':encoded(value),'report.txt':text_report(value).encode()}).items():
  fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as stream:stream.write(raw)
 return value

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 for name in('inventory','advisories','provenance','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--max-age-hours',type=int,default=24);p.add_argument('--as-of',help='UTC report time for reproducible offline replay; defaults to current UTC');a=p.parse_args(argv)
 try:value=run(a)
 except(OSError,ValueError,TypeError,KeyError,RecursionError)as error:print('advisory monitor: '+str(error),file=sys.stderr);return 2
 print(json.dumps(dict(output=str(a.output.absolute()),summary=value['summary'],cache_stale=value['cache']['cache_stale'],arm_security_status='UNKNOWN'),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
