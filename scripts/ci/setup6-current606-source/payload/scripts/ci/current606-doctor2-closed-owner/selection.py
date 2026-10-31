# SPDX-License-Identifier: MIT
"""Finite source-owned actor admission; input decisions are data, never code."""
import base64,hashlib,json,re
PURPOSE='CURRENT606_SETUP6_CLOSED_NATIVE'
NATIVE='f3a30f2049f57d9f3cb2433fbd59af51d4cc5720'
APPS='1dc9ecfee51145ba9cc43a95cc45bee97faed8b9'
PAIR_SOURCE='02734c705565868b0b964c48399a4f659fc6f271'
PAIR_INDEX={'bytes': 83411, 'sha256': 'fb86de7fad44c50d84ae9ebb44e8dd150abbeae84bffc16058bcf7e68da510e2'}
DOCTOR='141ba835bb632483342c6a7f0246c7fe0f2bc5c3'
DOCTOR_PACKET='24f8d8ed9de7f4ea1aedcc9624110e553204b36c'
DOCTOR_INDEX={'bytes': 140641, 'sha256': '741c5a86b66d0189c0de78a660fa6b7c83c9feca37623db1bf28389c1c9a4237'}
MANIFEST={'bytes': 45796, 'sha256': '09dae54c10f76d1a7b0bedd012f82aa513f5cc93102ad4ef5e6406dfee8bdd74'}
LOCK='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
CAPS={'capture':('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID'),'finalizer':('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP'),'copy-worker8':('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID','SYS_CHROOT','SETFCAP')}
MASKS={'capture':0xdb,'finalizer':0x8000001b,'copy-worker8':0x800400db}
CAPS['dispose']=CAPS['finalizer'];MASKS['dispose']=MASKS['finalizer']
LIMITS=dict(seconds=600,max_packages=606,max_nodes=200000,max_bytes=6*1024**3,max_file_bytes=1024**3,max_package_files=100000,max_depth=128)

def need(ok,message):
 if not ok:raise ValueError(message)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate decision/selection key');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite decision'))
def lease(value):
 need(type(value)is dict and set(value)=={'identity','uid','gid','mode'},'finite source-owned directory lease')
 need(type(value['identity'])is list and len(value['identity'])==2 and all(type(n)is int and n>=0 for n in value['identity']),'directory device/inode lease')
 need(type(value['uid'])is int and value['uid']>0 and type(value['gid'])is int and value['gid']>0 and value['mode']==0o700,'ordinary caller-owned0700 directory lease')
 return value
def retired(value,role,nonce):
 need(type(value)is dict and set(value)=={'nonce','prior_consumers_absent','processes','containers'} and value['nonce']==nonce and value['prior_consumers_absent']is True,'source-owned actual retirement context')
 processes=value['processes'];containers=value['containers'];need(type(processes)is list and 1<=len(processes)<=3,'finite original/finalizer/worker process observations')
 phases=[p.get('phase')for p in processes];need(phases==['original606','finalize','worker'][:len(phases)],'exact retired phase prefix')
 for p in processes:
  need(set(p)=={'phase','pid','returncode','direct_child_reaped','group_absent'} and type(p['pid'])is int and p['pid']>1 and p['direct_child_reaped']is True and p['group_absent']is True,'direct process reap and group absence')
  need(p['returncode']==0 or role=='dispose','failed phase authorizes only disposal')
 need(processes[0]['returncode']==0 or role=='dispose','original606 failure authorizes only disposal')
 need(role!='finalizer' or phases==['original606'],'finalizer after original retirement')
 need(role!='copy-worker8' or phases==['original606','finalize'],'worker after successful finalizer retirement')
 need(type(containers)is list and len(containers)==4+len(processes),'exact four original606 builders and phase consumers')
 ids=set();names=set()
 for row in containers:
  need(type(row)is dict and set(row)=={'name','status','id'} and row['status']=='PASS_ABSENCE_VERIFIED' and re.fullmatch('cachy-asahi-[a-z0-9-]{1,100}',row['name']or'') and re.fullmatch('[0-9a-f]{64}',row['id']or''),'whole held image/label/ID-checked actor absence')
  need(row['id']not in ids and row['name']not in names,'distinct retired actors');ids.add(row['id']);names.add(row['name'])
 need(len(encoded(value))<=65536,'bounded actual retirement context');return value
def decision(selected):
 # This structural gate runs before source, mount, archive, actor or output IO.
 need(type(selected)is dict and set(selected)=={'source','run','decision_source','decision_path','decision_pin','decision_base64'},'finite Root current606 selection')
 need(selected['source']==NATIVE and selected['run']==39106953257 and selected['decision_source']=='02d28b794c1a297171d82b5718fd98cddacbfa48' and re.fullmatch('[0-9a-f]{40}',selected['decision_source']or''),'current606 Root authority NULL/UNBOUND')
 need(selected['decision_pin']=={'bytes': 658, 'sha256': 'c828d76d4198c6db4626a7d85d7c351344a6ad3f4b11ded53c5be00211d1021d'} and selected['decision_path']=='decisions/current606-native.json','whole published finite606 Root decision pin/path')
 path=selected['decision_path'];need(type(path)is str and re.fullmatch(r'decisions/[a-z0-9-]+\.json',path),'fixed relative Root decision data role')
 row=selected['decision_pin'];need(type(row)is dict and set(row)=={'bytes','sha256'} and type(row['bytes'])is int and 0<row['bytes']<=65536 and re.fullmatch('[0-9a-f]{64}',row['sha256']or''),'bounded Root decision pin')
 text=selected['decision_base64'];need(type(text)is str and len(text)<=87384,'bounded Root decision bytes')
 try:raw=base64.b64decode(text,validate=True)
 except(ValueError,TypeError)as e:raise ValueError('invalid Root decision encoding')from e
 need(pin(raw)==row and base64.b64encode(raw).decode()==text,'exact Root selected decision bytes');d=decode(raw)
 required={'status','source','run_id','source_manifest','package_count','expected606_sha256','transitions','installed_controls','full604_preserved','cleanup','hardware','release'}
 need(type(d)is dict and set(d)==required,'finite606 Root decision fields')
 need(d['status']=='ROOT_ACCEPTED_NATIVE606_DNS2_SYSCTL2_RETAINED_SCOPE' and d['source']==NATIVE and d['run_id']==selected['run'] and d['package_count']==606 and d['expected606_sha256']==LOCK,'exact native606 source/run/inventory decision')
 mf=d['source_manifest'];need(mf==MANIFEST,'exact263 native606 source manifest decision pin')
 need(d['transitions']==[606,606,604,606,604] and d['installed_controls']=={'ordinary_homes':2,'dns2':27,'sysctl2':28} and d['full604_preserved']is True and d['cleanup']=='PASS' and d['hardware']=='NOT_RUN' and d['release']=='NOT_ADMITTED','full original606 scope and retirement required')
 return d

def verify_actor(selection,role,nonce):
 need(not __import__('sys').flags.optimize,'optimized actor guards refused')
 need(type(selection)is dict and selection.get('schema_version')==1 and selection.get('purpose')==PURPOSE,'fixed closed owner selection purpose')
 need(role in CAPS and selection.get('status')=='ROOT_BOUND_CURRENT606_SETUP6_INPUTS','closed owner/current606 selection NULL/UNBOUND')
 need(all(selection.get(k)is None for k in('actual_source','actual_ref','actual_run')),'source selection creates no new actual authority')
 need(selection.get('doctor_source')==DOCTOR and selection.get('doctor_packet_source')==DOCTOR_PACKET and selection.get('doctor_packet_index')==DOCTOR_INDEX,'exact accepted Doctor2 native DATA selection')
 d=decision(selection.get('current606'))
 need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce) and selection.get('nonce')==nonce,'independent exact actor nonce')
 need(selection.get('expected606_sha256')==LOCK,'exact complete606 lock')
 source=selection.get('source_manifest606');need(source==d['source_manifest'],'accepted606 source manifest exact join')
 apps=selection.get('apps_source');need(apps==APPS,'whole Apps7 native source required')
 need(selection.get('native_pair_source')==PAIR_SOURCE and selection.get('native_pair_index')==PAIR_INDEX,'whole public192 native pair source/index')
 result=dict(purpose=PURPOSE,nonce=nonce,source_native=d['source'],source_run=d['run_id'],expected606_sha256=LOCK,decision_pin=selection['current606']['decision_pin'],caps=CAPS[role],mask=MASKS[role],limits=dict(LIMITS))
 result['measurement']=lease(selection.get('measurement'));result['output']=lease(selection.get('output'))
 need(result['measurement']['identity']!=result['output']['identity'],'distinct owned measurement/output directories')
 if role!='capture':result['retirement']=retired(selection.get('retirement'),role,nonce)
 if role=='finalizer':
  receipt=selection.get('capture_receipt');need(type(receipt)is dict and receipt.get('status')=='CAPTURED_NOT_FINALIZED' and receipt.get('nonce')==nonce and receipt.get('source_native')==NATIVE and receipt.get('source_run')==d['run_id'],'actual capture receipt required before finalizer')
  need(len(encoded(receipt))<=65536,'bounded source capture receipt');result['capture_receipt']=receipt
 return result
