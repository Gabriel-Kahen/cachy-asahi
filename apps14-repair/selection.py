# SPDX-License-Identifier: MIT
"""Apps-only accepted-input substitution; original Runtime/cache/orphans remain exact."""
import base64,contextlib,copy,hashlib,importlib.util,json,stat,sys,tarfile,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
NAME='cachy-asahi-apps';PREFIX='APPS14_CARRIER/'
NATIVE='scripts/ci/apps7-full574-repair-native';BRIDGE='scripts/ci/apps7-full574-repair16k'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def proof(root=ROOT):
 root=Path(root);p=json.loads((root/'apps14-repair/successor.json').read_bytes());before=p['before'];need(len(before)==235,'whole original Apps13 source235 required')
 for name,row in p['after'].items():need(pin((root/name).read_bytes())==row,'selected source drift: '+name)
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in p['before_bodies']else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==v for n,v in before.items()),'complete210 inverse')
 return p,bodies
@contextlib.contextmanager
def original(root=ROOT):
 _,bodies=proof(root);saved,path=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='apps14-held210-')as tmp:
   old=Path(tmp)/'source';old.mkdir(mode=0o700)
   for n,raw in bodies.items():p=old/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
   C=load(old/BRIDGE/'contract.py','_apps14_whole_original210_contract')
   yield old,C
 finally:
  sys.path[:]=path
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
def authority(root=ROOT):return load(Path(root)/'apps14-repair/carrier.py','_apps14_repair_carrier').policy()
def carrier(root=ROOT):return Path(root).absolute().parent/'apps14-native-pair'
def checked(root,row,*,carrier_root=None):
 """Only the explicit new carrier namespace, never arbitrary external paths."""
 root=Path(root);p=authority(root);n=row['path'];need(n.startswith(PREFIX),'explicit Apps14 carrier namespace');n=n[len(PREFIX):]
 common=load(root/'apps14-repair/contract_common.py','_apps14_repair_common');common.member(n);need(n in p['files']and{key:row[key]for key in('bytes','sha256')}==p['files'][n],'source-bound Apps14 carrier reference')
 raw=common.read((Path(carrier_root)if carrier_root is not None else carrier(root))/n,16*1024**2);need(pin(raw)==p['files'][n],'whole Apps14 carrier body');return raw

def merge(old_packet,old_payload,old_origins,new_row,new_payload):
 need(set(old_packet['packages'])=={NAME,'cachy-asahi-repository-runtime','cachy-asahi-cache','cachy-asahi-orphans'},'whole original four-pair packet')
 need(old_packet['packages'][NAME]['version']=='0.1.0-7'and new_row['version']=='0.1.0-14','explicit7-to11 input selection')
 need(old_packet['packages']['cachy-asahi-repository-runtime']['version']=='0.1.0-1','held original Runtime1')
 old_names={n for n,owner in old_origins.items()if owner==NAME};need(old_names==set(new_payload)and len(old_names)==8,'same complete eight selected payload paths')
 result=copy.deepcopy(old_packet);result['packages'][NAME]=copy.deepcopy(new_row);result['apps14_input_scope']='ORIGINAL_THREE_PAIRS_HELD_ONLY_APPS_REPLACED_NOT_REPAIR_ACCEPTANCE'
 payload={n:v for n,v in old_payload.items()if n not in old_names}|new_payload;origins=dict(old_origins)
 helper=json.loads(new_payload['usr/lib/cachy-asahi-apps/helper-pins.json'][1])['files'];prefix='usr/share/cachy-asahi/repository-runtime/'
 actual={n[len(prefix):]:pin(v[1])for n,v in payload.items()if n.startswith(prefix)};need(actual==helper,'Apps14 requires the exact held Runtime1 helpers')
 need(all(result['packages'][n]==old_packet['packages'][n]for n in result['packages']if n!=NAME),'no Runtime/cache/orphans authority substitution')
 return result,payload,origins

def inputs(root,packet_root,*,carrier_root=None,git_dir=None):
 """Verify the old four pairs normally, then add independently accepted Apps14."""
 root=Path(root);profile=authority(root);new_carrier=Path(carrier_root).absolute()if carrier_root is not None else carrier(root)
 with original(root)as(old,C):
  C.gate(old,'repair-bytes')
  predecessor=load(old/'apps13-repair/selection.py','_apps14_whole13_then12_then210')
  with predecessor.original(old)as(parent12,P):
   legacy12=predecessor.load(parent12/'apps12-repair/selection.py','_apps14_original12_then210')
   with legacy12.original(parent12)as(legacy,L):
    native,_=L.gate(legacy,'repair-bytes');old_packet,old_payload,old_origins=native.inputs(legacy,packet_root)
 M=load(root/'apps14-repair/carrier.py','_apps14_repair_checked_carrier');fact=M.inspect(new_carrier,git_dir=git_dir);report=fact['report'];index=json.loads((new_carrier/'index.json').read_bytes())
 payload_map={'usr/bin/cachy-asahi-apps':'cachy-asahi-apps','usr/lib/cachy-asahi-apps/apps.py':'apps.py','usr/lib/cachy-asahi-apps/inventory.py':'inventory.py','usr/lib/cachy-asahi-apps/helper-pins.json':'helper-pins.json','usr/share/doc/cachy-asahi-apps/README.md':'README.md','usr/share/doc/cachy-asahi-apps/source-provenance.json':'source-provenance.json','usr/share/licenses/cachy-asahi-apps/LICENSE':'LICENSE','usr/share/licenses/cachy-asahi-apps/NOTICE':'NOTICE'}
 need(not report['review']and not report['elf']and report['sha256']==profile['archive']['sha256']and report['metadata']['.PKGINFO']['license']==['MIT'],'original strict any/MIT/data package policy')
 members={n:v for n,v in report['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};need(set(members)==set(payload_map),'complete selected Apps14 payload')
 recipe_prefix='recipe-source/packages/tools/cachy-asahi-apps14/';recipe={n[len(recipe_prefix):]:dict(path=PREFIX+n,**v)for n,v in profile['files'].items()if n.startswith(recipe_prefix)};need(len(recipe)==17,'whole17 selected recipe')
 new_payload={};payload_rows={}
 with tarfile.open(fact['archive'],'r:xz')as archive:
  for n,file in payload_map.items():
   info=members[n];raw=checked(root,recipe[file],carrier_root=new_carrier);need(info['type']=='0'and info['uid']==info['gid']==0 and info['mode']==(0o755 if n=='usr/bin/cachy-asahi-apps'else 0o644)and info['size']==len(raw)and info['sha256']==pin(raw)['sha256'],'complete selected source/mode/owner payload')
   matches=[m for m in archive.getmembers()if m.name.removeprefix('./')==n];need(len(matches)==1 and archive.extractfile(matches[0]).read()==raw,'actual signed native archive payload bytes')
   new_payload[n]=(info['mode'],raw);payload_rows[n]=dict(source=file,mode=info['mode'])
 ref=lambda n:dict(path=PREFIX+n,**profile['files'][n])
 new_row=dict(version='0.1.0-14',native_source=profile['native_source'],native_run=str(profile['native_run']),qualification='ROOT_ACCEPTED_PAIR_AND_FINITE_INSTALLED_LIFECYCLE_NOT_REPAIR',decision=ref(index['acceptance']),comparison=ref('native/runtime/cachy-asahi-apps-comparison.json'),files={s:dict(row,path=PREFIX+row['path'])for s,row in zip(('a','b'),index['archives'])},checks={s:ref('native/runtime/cachy-asahi-apps-'+s+'/build.log')for s in('a','b')},check_markers=['Ran 45 tests','Ran 24 tests','Ran 8 tests','OK'],source_files=recipe,payload=payload_rows)
 merged,payload,origins=merge(old_packet,old_payload,old_origins,new_row,new_payload)
 merged['apps14_original_packet']=copy.deepcopy(old_packet)
 merged['apps14_authority']=dict(profile=profile,proof=fact['proof'],scope='INPUT_ONLY_NOT_REPAIR_ACCEPTANCE')
 merged['apps14_closed_inputs']=[ref(n)for n in sorted(profile['files'])]
 return merged,payload,origins

def gate(root,case,C):
 authority(root)
 with original(root)as(old,held):_,binding=held.gate(old,case)
 native=C.load('selected_apps14_native_contract',Path(root)/NATIVE/'contract.py');native.source(root)
 return native,binding

def decisions(root,case,path,C):
 native,binding=gate(root,case,C)
 with original(root)as(old,held):_,accepted,_=held.decisions(old,case,path)
 # Existing Apps7 cases qualify the unchanged mechanism only, not this Apps14 case.
 return native,accepted,binding

def source_only(root=ROOT):
 p,_=proof(root)
 with original(root)as(old,C):
  for case in C.CASES:C.gate(old,case)
 return dict(status='SOURCE_ONLY_APPS14_REPAIR_REQUIRES_NEW_PAIR_AND_BOTH_NEW_CASES',parent=235,original210=210,source_files=sum(q.is_file()and'.git'not in q.relative_to(root).parts for q in Path(root).rglob('*')),authority=None,actual=None)
