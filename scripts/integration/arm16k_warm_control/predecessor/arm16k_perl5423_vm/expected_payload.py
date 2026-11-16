# SPDX-License-Identifier: MIT
"""Exact passive ABI input projection; observations and Root/runtime acceptance stay separate."""
import base64,hashlib,importlib.util,json,posixpath
from pathlib import Path
HERE=Path(__file__).resolve().parent
KIND='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1'
PINS={
 'seal.json':dict(bytes=2621,sha256='bef60067b67633c64e9eab447b9de7bae0dc21c7d4f9b3265c592a15a7987e24'),
 'expected-runtime-providers.json':dict(bytes=40826,sha256='35de58576441fbd5857f21cbbafdeb72b98dd6b8daee86d42aa4ceeaf33da75d'),
 'namespace.json':dict(bytes=922949,sha256='bc90b3ce90efdd84cd046af0c231c1cd79e3f26decc91747fd8d3f02958b1366'),
 'packages.json':dict(bytes=35326,sha256='948eefbf8ac116ea3192244eef7643803e0b7ba8b5d9da87e3e2c2f5b7827736')}
NULLS=('actual_guest_ALPM_owner','actual_guest_file_sha256','actual_guest_namespace','Root_runtime_certificate')


def module(n):
 s=importlib.util.spec_from_file_location('perl_expected_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def load_data(path,pin):
 K=module('contracts');K.need(K.pin(path,2*1024**2)==pin,'exact Root-selected expected ABI DATA bytes')
 def unique(items):
  out={}
  for k,v in items:K.need(k not in out,'unique expected DATA keys');out[k]=v
  return out
 raw=Path(path).read_bytes();K.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==pin,'stable expected ABI DATA')
 return json.loads(raw,object_pairs_hook=unique,parse_float=lambda v:(_ for _ in ()).throw(ValueError('integer expected DATA only')),parse_constant=lambda v:(_ for _ in ()).throw(ValueError('finite expected DATA')))


def resolve(path,aliases):
 K=module('contracts');K.guest_path(path);seen=set()
 for _ in range(32):
  K.need(path not in seen,'expected alias cycle');seen.add(path);parts=path.split('/')[1:]
  for i in range(1,len(parts)+1):
   prefix='/'+('/'.join(parts[:i]))
   if prefix in aliases:
    t=aliases[prefix]['target'];path=posixpath.normpath(posixpath.join(t if t.startswith('/')else posixpath.join(posixpath.dirname(prefix),t),*parts[i:]));K.guest_path(path);break
  else:return path
 raise ValueError('expected alias depth bound')


def validate(value):
 K=module('contracts');K.keys(value,('kind','source_pins','rows','aliases','actual_guest_hashes','actual_guest_ownership','Root_runtime_certificate','runtime_acceptance'),'expected payload inputs')
 K.need(value['kind']=='EXPECTED_PACKAGE_PAYLOAD_INPUTS_ONLY' and value['source_pins']==PINS and value['runtime_acceptance']is False and all(value[n]is None for n in('actual_guest_hashes','actual_guest_ownership','Root_runtime_certificate')),'archive expectations confer no guest/Root/runtime certificate')
 K.need(type(value['rows'])is list and len(value['rows'])==81,'exact81 immutable expected provider rows')
 original=dict(rows=value['rows'],scope='EXPECTED_PACKAGE_ARCHIVE_MEMBERS_ONLY_NOT_GUEST_OBSERVATIONS')
 raw=(json.dumps(original,sort_keys=True,separators=(',',':'))+'\n').encode()
 K.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==PINS['expected-runtime-providers.json'],'all exact81 expected provider rows')
 paths=set();packages={}
 for row in value['rows']:
  K.need(all(row[n]is None for n in NULLS),'no actual guest fields fabricated from archive DATA');p=K.guest_path(row['expected_path']);K.need(p not in paths,'unique expected ELF path');paths.add(p)
  owner=row['expected_package'];v=row['expected_package_version'];K.need(owner not in packages or packages[owner]==v,'one expected package version');packages[owner]=v
  K.need(K.positive(row['expected_member_bytes']) and K.sha(row['expected_member_sha256']) and K.sha(row['package_archive_sha256']),'bounded exact expected member/archive hashes')
 for path,row in value['aliases'].items():
  K.guest_path(path);K.keys(row,('target','owner','version','mode','uid','gid'),'expected alias input')
  K.need(type(row['target'])is str and row['target'] and not any(c in row['target']for c in '\0\t\r\n ') and row['mode']==0o777 and row['uid']==row['gid']==0 and type(row['owner'])is str and type(row['version'])is str,'literal safe expected alias')
 K.need(value['aliases'].get('/lib')==dict(target='usr/lib',owner='filesystem',version='2025.10.12-1',mode=0o777,uid=0,gid=0),'exact expected filesystem /lib alias')
 for row in value['rows']:
  for lookup in row['expected_lookup_paths']:
   p='/'+lookup.lstrip('/');K.need(resolve(p,value['aliases'])==row['expected_path'],'every original lookup resolves to the selected expected member')
 return value


def from_packet(directory):
 """Read only four known DATA leaves; never import any packet Python code."""
 K=module('contracts');directory=K.ordinary(directory);parts={n:load_data(directory/n,p)for n,p in PINS.items()}
 seal=parts['seal.json'];K.need(seal['scope']=='EXPECTED_PACKAGE_PAYLOAD_DYNAMIC_ABI_DATA_ONLY' and all(seal['files'][n]==p for n,p in PINS.items()if n!='seal.json'),'final immutable ABI packet join')
 rows=parts['expected-runtime-providers.json']['rows'];ns=parts['namespace.json'];pkgs=parts['packages.json'];aliases={}
 needed={p.lstrip('/')for row in rows for p in row['expected_lookup_paths']}
 for path,row in ns.items():
  if row['type']!='2' or not any(p==path or p.startswith(path+'/')for p in needed):continue
  owner=row['package'];aliases['/'+path]=dict(target=row['link'],owner=owner,version=pkgs[owner]['metadata']['pkgver'][0],mode=row['mode'],uid=row['uid'],gid=row['gid'])
 value=dict(kind='EXPECTED_PACKAGE_PAYLOAD_INPUTS_ONLY',source_pins=PINS,rows=rows,aliases=aliases,actual_guest_hashes=None,actual_guest_ownership=None,Root_runtime_certificate=None,runtime_acceptance=False)
 return validate(value)


def join_runtime(value,runtime,baseline):
 K=module('contracts');validate(value)
 for row in value['rows']:
  p=row['expected_path'];owner=row['expected_package'];files=runtime['baseline_files']if owner!='perl'and owner in baseline else runtime['files'];found=files.get(p,{})
  K.need(found.get('owner')==owner and found.get('version')==row['expected_package_version'] and found.get('bytes')==row['expected_member_bytes'] and found.get('sha256')==row['expected_member_sha256'] and found.get('resolved')==p,'expected ABI row joins exact runtime input phase: '+p)
  if owner!='perl'and owner in baseline:K.need(baseline.get(owner)==row['expected_package_version'],'expected provider version joins actual baseline inventory')
 for row in value['aliases'].values():
  if row['owner']!='perl'and row['owner']in baseline:K.need(baseline.get(row['owner'])==row['version'],'expected alias owner joins baseline inventory')


def observe(value,scan,inventory):
 """Compare real readonly baseline namespace before preparation or ALPM."""
 K,I=module('contracts'),module('image');validate(value);owned=I.owners(scan,inventory);observed={};aliases={}
 for row in value['rows']:
  owner=row['expected_package']
  if owner=='perl'or owner not in inventory:continue
  p=row['expected_path'];n=scan['nodes'].get(p.lstrip('/'),{})
  K.need(inventory.get(owner)==row['expected_package_version'] and n.get('type')=='file' and n.get('size')==row['expected_member_bytes'] and n.get('sha256')==row['expected_member_sha256'] and n.get('uid')==n.get('gid')==0 and owner in owned.get(p.lstrip('/'),{}).get('owners',[]),'actual raw provider bytes/ownership differ from expectation: '+p)
  observed[p]=dict(bytes=n['size'],sha256=n['sha256'],mode=n['mode'],uid=n['uid'],gid=n['gid'],owner=owner,version=inventory[owner])
 for p,row in value['aliases'].items():
  if row['owner']=='perl'or row['owner']not in inventory:continue
  n=scan['nodes'].get(p.lstrip('/'),{})
  K.need(n.get('type')=='symlink' and base64.b64decode(n['target_b64'],validate=True).decode()==row['target'] and all(n.get(k)==row[k]for k in('mode','uid','gid')) and row['owner']in owned.get(p.lstrip('/'),{}).get('owners',[]) and inventory.get(row['owner'])==row['version'],'actual raw alias/ownership differs from expectation: '+p);aliases[p]=row
 return dict(status='OBSERVED_READONLY_BASELINE_ABI_PROVIDERS_MATCH_EXPECTED_INPUTS_ONLY',files=observed,aliases=aliases,Root_runtime_certificate=None,crypto_verification=None,VM=None,runtime_acceptance=False)
