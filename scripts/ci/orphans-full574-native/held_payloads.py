# SPDX-License-Identifier: MIT
"""Fixture-only, exact held native archive payload facade; no new authority."""
import copy,re,types
from pathlib import Path
LANE='scripts/ci/orphans-full574-native'
PROOF='held-payloads.json'

def nodes(C,packet,inputs,archive_parser):
 C.need(type(packet['packages']) is dict and set(packet['packages'])==set(C.VERSIONS),'exact four held native packages required');result={};archives={};seen=set()
 for name,row in packet['packages'].items():
  ref=row['files']['a'];basename=Path(ref['path']).name
  C.need(row['version']==C.VERSIONS[name] and basename.endswith('.pkg.tar.xz') and basename not in seen and 0<ref['bytes']<=2*1024**2,'exact held package identity/archive bound required');seen.add(basename)
  raw=C.checked(inputs,dict(ref,path='archives/'+basename));actual=archive_parser.archive_payload(raw)
  files={n:v for n,v in actual.items() if v['type']=='file'};C.need(set(files)==set(row['payload']) and 1<=len(files)<=32,'complete held native payload paths required')
  expected={}
  for n,payload in row['payload'].items():
   C.need(n.startswith('usr/') and all(p not in ('','.','..') for p in n.split('/')) and '\\' not in n and payload['source'] in row['source_files'],'original held payload source association required')
   source=row['source_files'][payload['source']];C.need(payload['mode'] in (0o644,0o755),'original data/script payload mode required')
   expected[n]=dict(type='file',mode=payload['mode'],uid=0,gid=0,bytes=source['bytes'],sha256=source['sha256'])
   for parent in Path(n).parents:
    if parent.as_posix()!='.':expected.setdefault(parent.as_posix(),dict(type='directory',mode=0o755,uid=0,gid=0))
  C.need(actual==expected,'held archive/source/ownership/complete directory payload differs')
  result[name]=actual;archives[name]=dict(version=row['version'],archive=ref,payload_sha256=C.sha(C.encoded(actual)))
 return result,archives

def rules(C,root):
 base='packages/tools/cachy-asahi-orphans/';info=C.read(root/(base+'.SRCINFO')).decode();version=[]
 for key in ('pkgver','pkgrel'):
  values=re.findall(r'^\s*'+key+r' = ([^\s]+)$',info,re.M);C.need(len(values)==1,'one pinned inspector source version required');version.append(values[0])
 C.need('-'.join(version)=='0.1.0-2','current separately pinned Orphans2 readonly inspector required')
 return dict(version='-'.join(version),files={n:C.ref(root,root/(base+n)) for n in ('.SRCINFO','PKGBUILD','cachy-asahi-orphans','protection-floor.json')},scope='SOURCE_RULE_INSPECTOR_NOT_HELD_PACKAGE_VERSION_OR_NEW_BUILD')

def read(C,root,inputs=Path('/inputs')):
 C.source(root);binding=C.policy();index=dict(binding['packet_index'],path='native-index.json');raw=C.checked(inputs,index);packet=C.decode(raw)
 parser=C.load('held_native_archive_parser',root/'scripts/install/local_transaction.py');payloads,archives=nodes(C,packet,inputs,parser)
 expected=dict(status='EXACT_AUTHENTICATED_HELD_NATIVE_FOUR_PAYLOADS',packet_source=binding['packet_source'],packet_index=binding['packet_index'],held_candidates=archives,payloads=payloads,readonly_rules=rules(C,root))
 C.need(C.decode(C.read(inputs/PROOF,256*1024))==expected,'complete held payload proof/index/archive/source join differs');return expected

def publish(C,root,inputs,packet,payload,origins):
 C.source(root);raw=C.checked(inputs,dict(C.policy()['packet_index'],path='native-index.json'));C.need(C.decode(raw)==packet,'validated packet and flattened held index differ')
 parser=C.load('held_native_publish_parser',root/'scripts/install/local_transaction.py');actual,archives=nodes(C,packet,inputs,parser)
 for name in C.VERSIONS:
  expected={n:dict(type='file',mode=mode,uid=0,gid=0,bytes=len(raw),sha256=C.sha(raw)) for n,(mode,raw) in payload.items() if origins[n]==name}
  for n in tuple(expected):
   for parent in Path(n).parents:
    if parent.as_posix()!='.':expected.setdefault(parent.as_posix(),dict(type='directory',mode=0o755,uid=0,gid=0))
  C.need(expected==actual[name],'all four fully validated native byte payloads must agree before any actor')
 value=dict(status='EXACT_AUTHENTICATED_HELD_NATIVE_FOUR_PAYLOADS',packet_source=C.policy()['packet_source'],packet_index=C.policy()['packet_index'],held_candidates=archives,payloads=actual,readonly_rules=rules(C,root))
 C.need(not (inputs/PROOF).exists() and len(C.encoded(value))<=256*1024,'fresh finite held payload proof required');C.save(inputs/PROOF,value);(inputs/PROOF).chmod(0o644)
 C.need(read(C,root,inputs)==value,'held proof publication differs');return packet

def clone(function,changes):
 # Byte-identical function code and an isolated globals copy, never a shared
 # module/global patch. Original helpers and their source bytes stay untouched.
 result=types.FunctionType(function.__code__,dict(function.__globals__,**changes),function.__name__,function.__defaults__,function.__closure__);result.__kwdefaults__=function.__kwdefaults__;return result

def facade(C,root,original,inputs=Path('/inputs')):
 def current():return copy.deepcopy(read(C,root,inputs)['payloads'])
 class HeldAdapter(original.Adapter):pass
 HeldAdapter.__init__=clone(original.Adapter.__init__,dict(current_payloads=current))
 return types.SimpleNamespace(**(dict(vars(original))|dict(current_payloads=current,Adapter=HeldAdapter,connect=clone(original.connect,dict(Adapter=HeldAdapter)))))

def configure(T,C,root,inputs=Path('/inputs')):
 read(C,root,inputs) # All four held archives/index/proof agree before backend guard/commit.
 original=T.load;path=root/'scripts/apps/full574_closure.py'
 def load(name,source):
  module=original(name,source)
  return facade(C,root,module,inputs) if Path(source)==path else module
 T.load=load
 return T

def supervisor(T,old_path,new_prefix):
 original=T.SUP
 def run(argv,**kwargs):
  argv=list(argv)
  if len(argv)>3 and argv[3]==str(old_path):argv=argv[:3]+list(map(str,new_prefix))+argv[4:]
  return original.run(argv,**kwargs)
 T.SUP=types.SimpleNamespace(run=run)

def calls(H,C):
 original=H.backend
 def backend(*args,**kwargs):
  argv=original(*args,**kwargs);C.need(argv[:4]==['/usr/bin/python3','-I','-B','/source/scripts/apps/transaction.py'],'exact original backend invocation required')
  argv[3]='/source/'+LANE+'/fixture_backend.py';return argv
 H.backend=backend
