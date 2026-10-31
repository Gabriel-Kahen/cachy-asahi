# SPDX-License-Identifier: MIT
"""Exact accepted Apps6 public evidence; no fetch, signing or package actors."""
import hashlib,io,json,re,stat,sys,zipfile
from pathlib import Path
NAME='cachy-asahi-apps';VERSION='0.1.0-6';SOURCE='ec135f26326158591e6d25d5f670083d5306b071';RUN=39029873349
STATUS='ROOT_ACCEPTED_APPS6_NATIVE_PAIRS_INSTALLED_LIFECYCLE_AND_SIGNED_SYNTHETIC_REPAIR'
DECISION='106d47fb1de4df5646c42d3b1ab95754ea2cd0871164d24f23425259166ab3c5'
ARCHIVE=dict(bytes=22876,sha256='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7')
ORIGINAL={'artifact.zip':dict(bytes=649853,sha256='1ad9bde48146b661f3df74cbd0748d5af727411d00b8775a319a219281d351f0'),'logs.zip':dict(bytes=95318,sha256='f2dcc9a33b1c80cecfb3c04563fedf59215dc58725aa769e097f273843996c68')}
MANIFEST='af9faae6073bc1332d1250bdd70635825086a4d09bc68bb0ba9b49a4898f9396';WORKFLOW='75cb6857c3578b9b21b994d1ad87fbbce24bfbf8808bddd50b236b45a4c5de45'
LANE='scripts/ci/apps6-native-reinstall'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def require(C,binding,*,published=True):
 C.need(binding.get('status')==STATUS and binding.get('native_source')==SOURCE and binding.get('native_run')==RUN and binding.get('root_decision_sha256')==DECISION,'Apps6 native installed authority remains UNBOUND before actors')
 if published:C.need(re.fullmatch('[0-9a-f]{40}',binding.get('carrier_source') or '') and binding['carrier_source']!=SOURCE,'new immutable Apps6 carrier remains UNBOUND')
 C.ref(binding.get('index'),4*1024**2);return binding

def native(C,root):
 """Original87 exact source operands, importing only pinned local definitions."""
 root=C.safe(root.absolute());path=C.safe(root/LANE/'source-manifest.json');info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=4*1024**2,'ordinary bounded native source manifest');raw=path.read_bytes();C.need(pin(raw)['sha256']==MANIFEST,'exact native Apps6 source manifest');manifest=json.loads(raw);C.need(len(manifest['files'])==84,'exact native84 source rows')
 for name,row in manifest['files'].items():C.checked(root,dict(path=name,**row))
 for name in ('native-arm-build.yml','native-arm-apps6-reinstall.yml'):
  path=C.safe(root/'.github/workflows'/name);info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=1024**2 and C.sha(path)==WORKFLOW,'exact ordinary native registered/dedicated workflow')
 keys=('adapter','contract','rules','repair');missing=object();saved={k:sys.modules.get(k,missing) for k in keys};paths=sys.path[:]
 try:
  for k in keys:sys.modules.pop(k,None)
  sys.path.insert(0,str(root/LANE));api=C.load('apps6_original_native_contract',root/LANE/'contract.py');api.verify_source(root);return api
 finally:
  sys.path[:]=paths
  for k,v in saved.items():
   if v is missing:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def validate(C,source,root,binding,checks,bind,native_source,*,published=True):
 require(C,binding,published=published);index=C.read(C.checked(root,binding['index']));C.need(index.get('schema_version')==1 and index.get('kind')=='ROOT_ACCEPTED_APPS6_COMPLETE_NATIVE_PUBLIC_INPUTS' and index.get('native_source')==SOURCE and index.get('native_run')==RUN and index.get('attempt')==1,'exact new Apps6 input index')
 reader=C.scoped_load('apps6_original_reference_reader',source/'scripts/ci/expanded604-composition/inputs.py',{'contract':C});refs=reader.references(index);C.need(len(refs)<=256 and sum(r['bytes'] for r in refs.values())<=64*1024**2,'finite Apps6 public packet')
 paths={n:reader.source_ref(root,r) for n,r in refs.items()};nodes=[]
 for path in root.rglob('*'):
  nodes.append(path);C.need(len(nodes)<=512 and not path.is_symlink() and (path.is_dir() or path.is_file()),'ordinary bounded Apps6 carrier')
 C.need({p.relative_to(root).as_posix() for p in nodes if p.is_file()}==set(refs)|{binding['index']['path']},'closed Apps6 packet files')
 parents={q.as_posix() for n in set(refs)|{binding['index']['path']} for q in Path(n).parents if q.as_posix()!='.'};C.need(all(p.is_file() or p.relative_to(root).as_posix() in parents for p in nodes),'no unreferenced packet directories')
 decision=C.read(paths[index['root_decision']['path']]);C.need(C.sha(paths[index['root_decision']['path']])==DECISION and decision['status']==STATUS and decision['source']==SOURCE and decision['run']==RUN and decision['attempt']==1 and decision['root_git_source_joins']==87 and decision['root_passive_replay']=='COMPLETE_VERIFY_POPEN_BLOCKED_EXACT_FACT_EQUALITY' and decision['hardware']=='NOT_RUN' and decision['release_admission'] is False,'exact new Root installed/native decision')
 originals=index['originals'];C.need(set(originals)=={'run.json','artifacts.json','collection.json','artifact.zip','logs.zip'},'original API/transport closure')
 for name,row in ORIGINAL.items():C.need({k:originals[name][k] for k in ('bytes','sha256')}==row,'exact accepted original ZIP identity')
 run=C.read(paths[originals['run.json']['path']]);C.need(run['id']==RUN and run['head_sha']==SOURCE and run['run_attempt']==1 and run['status']=='completed' and run['conclusion']=='success','original successful native attempt required')
 collection=C.read(paths[originals['collection.json']['path']]);C.need(collection==ORIGINAL,'original ZIP collection pins')
 artifacts=C.read(paths[originals['artifacts.json']['path']]);C.need(artifacts['total_count']==len(artifacts['artifacts'])==1,'one exact native public artifact');artifact=artifacts['artifacts'][0];C.need(not artifact['expired'] and artifact['size_in_bytes']==ORIGINAL['artifact.zip']['bytes'] and artifact.get('digest') in (None,'sha256:'+ORIGINAL['artifact.zip']['sha256']),'original artifact size/digest')
 files={}
 with zipfile.ZipFile(paths[originals['artifact.zip']['path']]) as archive:
  entries=archive.infolist();C.need(len(entries)==216 and len({i.filename for i in entries})==216 and sum(i.file_size for i in entries)<=192*1024**2,'original216 native public closure')
  for info in entries:
   n=C.relative(info.filename);kind=stat.S_IFMT(info.external_attr>>16);C.need(not info.is_dir() and not info.flag_bits&1 and kind in (0,stat.S_IFREG) and info.file_size<=96*1024**2,'ordinary original native ZIP member');files[n]=archive.read(info)
 C.need(set(index['files'])==set(files),'all original native public members retained')
 for name,raw in files.items():C.need(paths[index['files'][name]['path']].read_bytes()==raw,'retained original public byte equality')
 retention=json.loads(files['retention.json']);C.need(set(retention['files'])|{'retention.json'}==set(files) and not retention['errors'] and retention['status']=='PASS_NATIVE_APPS6_PAIR_AND_SIGNED_REPAIR_CANDIDATE','original complete native retainer')
 for name,row in retention['files'].items():C.need(pin(files[name])==row,'original retainer hash')
 C.need(sum(len(files[n]) for n in retention['files'])==retention['bytes'],'original retainer byte total');proof=json.loads(files['source-proof.json']);C.need(proof['status']=='SOURCE_PROOF_PASS' and proof['source_sha']==proof['workflow_sha']==SOURCE and str(proof['run_id'])==str(RUN) and str(proof['run_attempt'])=='1' and proof['source_files']==84,'native original source/run proof')
 api=native(C,Path(native_source));life=json.loads(files['runtime/lifecycle.json']);api.validate_lifecycle(life);C.need(life==json.loads(files['runtime/report.json'])['lifecycle'],'raw native lifecycle parent join')
 raw=json.loads(files['signed-repair/result.json']);observed=json.loads(files['signed-repair/native-result.json']);C.need(observed==life['repair'] and observed==dict(raw,native_aarch64='EXECUTED_SIGNED_SYNTHETIC_COPY_ONLY',installed_apps=VERSION,input_source_sha256=hashlib.sha256(files['repair-source.json']).hexdigest()),'actual installed/native repair authority')
 for i,t in enumerate(raw['transactions']):C.need(json.loads(files[f'signed-repair/worker-{i}.stdout'])==t and hashlib.sha256(files[f'signed-repair/plan-{i}.json']).hexdigest()==t['plan_sha256'],'all five original raw workers/plans')
 pub=files['signed-repair/publication.json'];C.need(hashlib.sha256(pub).hexdigest()==decision['repair_publication']['receipt_sha256'] and json.loads(pub)['complete'] is True,'original complete publication joins Root decision')
 product=api.row(NAME);recipe=api.recipe(Path(native_source),NAME);reports=[];pairs={}
 for n,row in product['source_files'].items():C.need(files['source/'+NAME+'/'+n]==(Path(native_source)/'packages/tools'/NAME/n).read_bytes()==(source/'packages/tools'/NAME/n).read_bytes(),'selected Apps6 current/native source/license bytes')
 for side in ('a','b'):
  names=[n for n in files if n.startswith('packages/'+NAME+'-'+side+'/')];C.need(len(names)==1,'one original Apps6 archive per side');n=names[0];ref=index['files'][n];C.need(pin(files[n])==ARCHIVE=={k:decision['products'][NAME][k] for k in ('bytes','sha256')},'Root accepted Apps6 pair bytes');report=checks.package(paths[ref['path']]);C.need(not bind.bind_artifact(recipe['metadata'],report,recipe['input_sha256']['PKGBUILD']),'Apps6 PKGINFO/BUILDINFO binding');api.payload(report,Path(native_source),NAME);api.check_log(paths[index['files']['runtime/'+NAME+'-'+side+'/build.log']['path']],NAME);reports.append(report);pairs[side]=ref
 C.need(reports[0]['members']==reports[1]['members'] and reports[0]['metadata']==reports[1]['metadata'],'native Apps6 pair payload/BUILDINFO equality')
 cleaner=C.scoped_load('apps6_original_cleanup',source/'scripts/ci/management-tools-generic16k/contract.py',{});cleaner.cleanup_proof(json.loads(files['ordered-cleanup.json']))
 sources={n:index['files']['source/'+NAME+'/'+n] for n in product['source_files']}
 return reader.normalized(NAME,dict(version=VERSION,native_source=SOURCE,native_run=RUN,qualification=STATUS,files=pairs,source_files=sources,sources=sources,metadata=recipe['metadata'],acceptance=index['root_decision']),root,reports[0])
