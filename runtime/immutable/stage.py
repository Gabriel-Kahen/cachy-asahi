"""Offline explicit new-purpose stage; never runs unless genuine inputs bound."""
import importlib.util,os,re,shutil,sys,types,time
from pathlib import Path
import inputs,factory,runtime_policy as contract
P,C,_,_=inputs.broker()

def original_images():
 root=inputs.D.parent/'gnu-verity-bootstrap-development-20261018'
 # Only exact imports are rebound to pinned original modules; bodies held.
 common_path=root/'common.py';common=types.ModuleType('_runtime_stage_common');common.__file__=str(common_path);exec(compile(common_path.read_bytes(),str(common_path),'exec'),vars(common))
 def module(name,replacements,anchors):
  path=root/name;raw=path.read_bytes();value=types.ModuleType('_runtime_stage_'+Path(name).stem);space=vars(value);space.update(__file__=str(path),**replacements)
  for a in anchors:P.need(raw.count(a)==1,'one explicit original offline import');raw=raw.replace(a,b'')
  exec(compile(raw,str(path),'exec'),space);return value
 snapshot=module('source_snapshot.py',dict(C=common),(b'import common as C\n',));recovery=module('recovery.py',dict(C=common),(b'import common as C\n',))
 path=root/'borrowed/verity_image.py';spec=importlib.util.spec_from_file_location('_runtime_stage_verity',path);V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
 path=root/'images.py';raw=path.read_bytes();raw=raw.replace(b'import common as C,recovery,source_snapshot\n',b'').replace(b'from borrowed import verity_image as V\n',b'')
 # Bytes/tuples of the COMPLETE aux map must survive native→guest serialization.
 for old,new in((b'C.encoded(before)',b'P.encode(P.pack(before))'),(b'C.encoded(after)',b'P.encode(P.pack(after))')):
  P.need(raw.count(old)==2,'exact two original map write/hash anchors');raw=raw.replace(old,new)
 space=dict(__name__='_runtime_original_images',__file__=str(path),C=common,P=P,recovery=recovery,source_snapshot=snapshot,V=V);exec(compile(raw,str(path),'exec'),space);return types.SimpleNamespace(**space)

def execute(boot,volume,held,index,bundle,value):
 contract.gate(value,preparing=True);factory.check(bundle);P.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE')=='1','same bounded native offline prepare actor only')
 selected=P.decode(contract.read(Path('/selection/selection.json'),1024**2));P.need(selected['source_sha']==value['actual_source']and re.fullmatch('[a-f0-9]{32}',selected['nonce']),'original actual source and fresh owner-generated nonce');value=__import__('copy').deepcopy(value);value['broker']['nonce']=selected['nonce'];value['bootstrap']['nonce']=selected['nonce']
 P.need(len(index['source_capabilities'])<=4096 and len(index['base_lock'])>0,'original complete native input index')
 image=original_images();api,modules=C.source_api();F=modules['full_root'];budget=F.Limits(deadline=time.monotonic()+600,max_packages=574,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)
 def snapshot(root,limits):
  v=api['observe'](modules,root,limits);v['auxiliary']=modules['aux_checkpoint'].checkpoint(root,v['observation'],limits)
  P.need(__import__('hashlib').sha256(__import__('json').dumps(v['nodes'],sort_keys=True).encode()).hexdigest()==index['source_nodes_sha256']and v['capabilities']==index['source_capabilities'],'same original574 payload/rawDB/fullcap native index');return v
 out=Path('/out/immutable-media');P.need(not out.exists()and shutil.disk_usage('/out').free>=16*1024**3,'new8GiB source+hash/staging within original48GiB reserve, no raise');receipt=image.prepare(held,out,snapshot=snapshot,limits=budget)
 # Bind ACTUAL trusted-preparer map/image receipts; no Root acceptance is issued.
 value=__import__('copy').deepcopy(value);value['native_map']=receipt['original_snapshot'];value['source_image_receipt']=P.pin((out/'source-image.json').read_bytes());v=receipt['format'];value['broker']['verity']=dict(data_blocks=v['data_blocks'],root_hash=v['root_hash'],salt=v['salt'],data_device=None,hash_device=None)
 for name in('image','tree'):
  value['bootstrap'][name]=dict(bytes=v['data']['bytes'],sha256=v['data']['sha256'])if name=='image'else dict(bytes=v['tree']['bytes'],sha256=v['tree']['sha256'],data_blocks=v['data_blocks'],root_hash=v['root_hash'],salt=v['salt'])
 value['bootstrap']['snapshot']=receipt['original_snapshot']
 # Existing volume/held remains unchanged; new source is independent readonly.
 for top in bundle.iterdir():
  if top.name=='runtime-source.json':continue
  P.need(top.is_dir()and not top.is_symlink()and not(boot/top.name).exists(),'fresh owned runtime source namespace');shutil.copytree(top,boot/top.name,symlinks=False)
 compat=boot/'installed16k';P.need(not compat.exists(),'fresh fixed source-only fence namespace');compat.mkdir(mode=0o755);sandbox=Path('/debian-maintained-installed16k/sandbox.py');held=P.decode((inputs.D.parent/'gnu-verity-bootstrap-development-20261018/runtime-pins.json').read_bytes())['/installed16k/sandbox.py'];P.need(P.pin(sandbox.read_bytes())==held,'identical whole old/current sandbox filter source');(compat/'sandbox.py').write_bytes(sandbox.read_bytes())
 policy=boot/'immutable/policy.json';policy.write_bytes(P.encode(value))
 # Exactly two source-metadata rows disclose new-purpose private authority binding.
 broker_pins=boot/'gnu-immutable-source-broker-development-20261018/input-pins.json';before=broker_pins.read_bytes();selected=P.decode(before);P.need(selected['accepted_authorities']is None,'genuine NULL default authority basis');selected['accepted_authorities']={n:value['broker'][n]for n in('source_authority','kernel_authority','producer_retirement','native_readback')};broker_pins.write_bytes(P.encode(selected))
 pins=boot/'immutable/source-pins.json';rows=P.decode(pins.read_bytes());key='gnu-immutable-source-broker-development-20261018/input-pins.json';P.need(rows['files'][key]==P.pin(before),'one exact source authority binding inverse');rows['files'][key]=P.pin(broker_pins.read_bytes());pins.write_bytes(P.encode(rows));(boot/'immutable/private-binding-proof.json').write_bytes(P.encode(dict(purpose='GNU_IMMUTABLE_RUNTIME_V1',authority='SOURCE_ENFORCED_RUNTIME_BINDING_NOT_ROOT_ACCEPTANCE',changed_source_metadata={key:dict(before=P.pin(before),after=P.pin(broker_pins.read_bytes()))},native_map=value['native_map'],image_receipt=value['source_image_receipt'])))
 for directory in('immutable-inputs','broker-authorities'):
  P.need(not(boot/directory).exists(),'fresh private prerequisite namespace');shutil.copytree(Path('/runtime-selection')/directory,boot/directory,symlinks=False)
 (boot/'immutable-inputs/native_map.json').write_bytes((out/'source-before.json').read_bytes());(boot/'immutable-inputs/source_image_receipt.json').write_bytes((out/'source-image.json').read_bytes())
 (boot/'immutable/runtime-source-before-private-binding.json').write_bytes((bundle/'runtime-source.json').read_bytes())
 return dict(status='OFFLINE_NEW_PURPOSE_SOURCE_AND_PRIVATE_INPUTS_STAGED_NOT_BOOTED',source=receipt['format']['data'],tree=receipt['format']['tree'],native_map=receipt['original_snapshot'],source_bytes=8*1024**3,hash_bytes_max=128*1024**2,budgets='ORIGINAL_PREPARE2400_TOOL900_OBSERVE600_UNCHANGED')
