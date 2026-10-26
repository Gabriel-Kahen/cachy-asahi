# SPDX-License-Identifier: MIT
"""Public659 pairs + independent accepted native byte case; never raw223 authority."""
import hashlib,json,re,sys,tempfile,types
from pathlib import Path
NAME='cachy-asahi-apps';VERSION='0.1.0-6'
STATUS='ROOT_BOUND_PUBLIC_CURRENT4_PAIRS_AND_NATIVE_BYTECASE'
KIND='PUBLIC659_PAIRS_PLUS_INDEPENDENT_NATIVE574_REPAIR_BYTES_ONLY'
PACKET='65950a7e3ca82d97e21a65556844dab1cfd1a7f7'
INDEX=dict(path='index.json',bytes=55737,sha256='782fd76c06831786cb74df396f195e8f5f8832e04b668c44bdadd802d1cb268b')
AUTHORITY='1b04c762fdbf8a2e623b939b2e832bc0c084abf1'
DECISION=dict(path='payload/repair-bytes-root-decision.json',bytes=1481,sha256='f8e106a882b7fc9b553c8a399f6d9296d17d77f9aadbdcf46135b090f88b4157')
VERSIONS={'cachy-asahi-apps':'0.1.0-6','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2','cachy-asahi-repository-runtime':'0.1.0-1'}
LOCKS={n:('66c46d4645fa443d23df0e97765905555fe5bc2607787dca3f30ee2084cf597f' if n==NAME else 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac') for n in VERSIONS}

def require(C,binding,*,published=True):
 C.need(type(binding)is dict and set(binding)=={'status','authority_kind','carrier_source','index','authority_source','byte_case_decision'} and binding.get('status')==STATUS and binding['authority_kind']==KIND and binding['carrier_source']==PACKET and binding['index']==INDEX and binding['authority_source']==AUTHORITY and binding['byte_case_decision']==DECISION,'UNBOUND public pair/native byte-case composition authority; original223 status is not accepted')
 return binding

def validate(C,source,root,binding,checks,bind,authority_root,*,published=True):
 require(C,binding,published=published)
 authority=C.read(C.checked(Path(authority_root),DECISION,65536));wanted=dict(status='ROOT_ACCEPTED_NATIVE_FULL574_SIGNED_REPAIR_CASE',case='repair-bytes',source_sha='5051663cf191e40bdbb3b03e2d62748f69b6afb1',run_id=39037387719,source_manifest_sha256='636baf21fa537ca813b7403b1bc6afb920404d974236bd52d8c1cdf479477ba9',packet_source=PACKET,counts=[578,575,574],committed_transactions=4,readonly_inspection='PASS_AUTHENTICATED_NONCOMMIT_BEFORE_PINS',zero_commit_refusals=3,strict_inspect_refusals=1,cleanup='PASS',hardware='NOT_RUN',VM='NOT_RUN',release='NOT_ADMITTED')
 C.need(all(authority.get(k)==v for k,v in wanted.items()) and authority['aggregate']=='NOT_ADMITTED_REPAIR_MISSING_CASE_PENDING','exact accepted public native byte case; no aggregate/VM credit')
 def raw(path,cap=16*1024**2):
  path=C.safe(Path(path).absolute());s=path.stat();C.need(path.is_file() and s.st_nlink==1 and s.st_size<=cap,'ordinary bounded trusted source');return path.read_bytes()
 def sha(data):return hashlib.sha256(data).hexdigest()
 def decode(data):
  def pairs(rows):
   result={}
   for k,v in rows:C.need(k not in result,'duplicate packet JSON key');result[k]=v
   return result
  return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _:C.need(False,'finite JSON'))
 # Reuse the exact505 packet-policy derivative and the original closed/payload reader.
 facade=types.SimpleNamespace(load=C.load,read=raw,checked=lambda p,r:raw(C.checked(p,r)),decode=decode,sha=sha,need=C.need,policy=lambda:dict(packet_index=INDEX))
 factory=C.load('public659_packet_policy',Path(__file__).with_name('pair_packet.py'));api=factory.module(facade,source);value=api.packet(root);payload,origins=api.package_payload(root,value,checks);proof={};reports={};clean=[]
 for name,row in value['packages'].items():
  source_hashes={}
  for n,ref in row['source_files'].items():
   data=raw(C.checked(root,ref));C.need(raw(source/'packages/tools'/name/n)==data,'public/current recipe source differs: '+name+'/'+n);source_hashes[n]=sha(data)
  with tempfile.TemporaryDirectory(prefix='public659-recipe-') as directory:
   staged=Path(directory)
   for n,ref in row['source_files'].items():(staged/n).write_bytes(raw(C.checked(root,ref)))
   recipe=checks.recipe(staged/'PKGBUILD')
  pair=[];builds=[]
  for side in ('a','b'):
   path=C.checked(root,row['files'][side]);report=checks.package(path);C.need(not bind.bind_artifact(recipe['metadata'],report,source_hashes['PKGBUILD']),'complete public PKGINFO/dependency/BUILDINFO recipe binding');pair.append(report)
   p=C.read(C.checked(root,row['provenance'][side]));valid=C.read(C.checked(root,row['validation'][side]));installed=report['metadata']['.BUILDINFO']['installed']
   C.need(p['mode']=='native' and p['status']=='built-package-static-pass' and p['expected_packages_sha256']==LOCKS[name] and p['recipe_inputs']==source_hashes and p['recipe_metadata']==recipe['metadata'] and valid['errors']==[] and len(installed)==(575 if name==NAME else 574) and len(set(installed))==len(installed),'actual provenance/complete BUILDINFO/check inventory')
   C.need(re.fullmatch('cachy-asahi-product-[0-9a-f]{32}',p['clean_environment_id']) and re.fullmatch('sha256:[0-9a-f]{64}',p['image_id']),'actual distinct native build identity');clean.append(p['clean_environment_id']);builds.append(dict(native_environment=p['clean_environment_id'],expected_pacman_Q_lock_sha256=p['expected_packages_sha256'],BUILDINFO_installed_entries=len(installed),BUILDINFO_installed_list_sha256=sha(json.dumps(installed,sort_keys=True,indent=2).encode()+b'\n')))
  C.need(pair[0]['members']==pair[1]['members'] and pair[0]['metadata']==pair[1]['metadata'],'same original public pair payload and full metadata');reports[name]=(row,recipe,pair[0]);proof[name]=dict(version=row['version'],archive={k:row['files']['a'][k] for k in ('bytes','sha256')},native_source=row['native_source'],native_run=row['native_run'],pair_qualification=row['qualification'],builds=builds)
 C.need(len(clean)==len(set(clean))==8 and len(payload)==25,'eight distinct native builds/complete current4 payload')
 row,recipe,report=reports[NAME];reader=C.scoped_load('public659_normalization',source/'scripts/ci/expanded604-composition/inputs.py',{'contract':C})
 result=reader.normalized(NAME,dict(row,metadata=recipe['metadata'],sources=row['source_files'],acceptance=row['decision'],qualification=KIND,public_pair_inputs=proof,independent_native_byte_case=dict(source=AUTHORITY,decision=DECISION),expected_build_lock_scope='PROVENANCE_AND_ORIGINAL_ROOT_PAIR_AUTHORITY_NOT_RECONSTRUCTED_Q_LOCK_BYTES'),root,report)
 return result
