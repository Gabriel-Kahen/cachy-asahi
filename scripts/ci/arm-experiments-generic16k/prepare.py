# SPDX-License-Identifier: MIT
"""Select exact retained final artifacts/corpus; never build or execute them."""
import hashlib,json,stat,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
BUNDLES={'ARM-C01':'9195b3feaed061012600fac707a61f5b0f4c769894240a2c5742de99e784e573','ARM-C02':'018d87e9037611b5fe85c4476aaab9a21dd29beacfad784c3fa0f36d7d3b4e54','ARM-C03':'80a6d4d420260f308780f2867b36665255c0685360d656f1b9ccd41fb4f2f3b2','ARM-C04':'b78cdadff4d63fb9bf69a1a33c3c4ff0a342756cc80385b790e851fe2b53182c'}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def relative(name):
 need(type(name) is str and name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and '\\' not in name,'closed original input path');return name
def read(path,cap):
 need(not any(p.is_symlink() for p in (path,*path.parents)) and path.is_file() and path.stat().st_size<=cap,'bounded ordinary input');raw=path.read_bytes();need(len(raw)<=cap,'input byte bound');return raw
def select(root,experiment,generic):
 index=json.loads(read(HERE/'retained-inputs.json',128*1024));need(experiment in BUNDLES and set(index['experiments'])==set(BUNDLES),'four exact original experiment identities');entry=index['experiments'][experiment];bundle=entry['bundle'];raw=read(root/relative(bundle['path']),8*1024**2);need(pin(raw)=={k:bundle[k] for k in ('bytes','sha256')} and bundle['sha256']==BUNDLES[experiment],'exact accepted retained output bundle')
 manifest=json.loads(read(root/relative(entry['archive_manifest']['path']),128*1024));need(pin(read(root/entry['archive_manifest']['path'],128*1024))=={k:entry['archive_manifest'][k] for k in ('bytes','sha256')},'original archive manifest pin')
 selected={};allnames=set();total=0
 with tarfile.open(root/bundle['path'],'r:gz') as archive:
  for member in archive:
   name=relative(member.name);need(member.isfile() and name not in allnames and len(allnames)<256 and member.size<=4*1024**2,'bounded regular original members');allnames.add(name);total+=member.size;need(total<=16*1024**2,'original output total');data=archive.extractfile(member).read(member.size+1);need(len(data)==member.size and hashlib.sha256(data).hexdigest()==manifest['files'][name],'original complete member hash')
   if name in entry['selected']:need(pin(data)==entry['selected'][name],'exact final selected file');selected[name]=data
 need(allnames==set(manifest['files']) and set(selected)==set(entry['selected']) and len(selected)==30,'closed original final selection')
 elf={}
 for build in entry['builds']:
  for name in ('minigzip','strict-gzip','example'):
   key=build+'/'+name;interpreter,needed,loads=generic.elf(selected[key]);need(interpreter=='/lib/ld-linux-aarch64.so.1' and set(needed)<={'libc.so.6','ld-linux-aarch64.so.1','libm.so.6'} and loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'ordinary interpreter/16K PT_LOAD/finite libraries');elf[key]=dict(interpreter=interpreter,needed=needed)
 corpus=json.loads(selected['corpus/manifest.json']);need(len(corpus['files'])==9,'original nine corpus members')
 for row in corpus['files']:need(pin(selected['corpus/'+relative(row['path'])])=={k:row[k] for k in ('bytes','sha256')},'corpus original hash')
 files={'experiments/'+name:(stat.S_IFREG|(0o555 if name in elf else 0o444),data) for name,data in selected.items()}
 receipt=dict(experiment=experiment,original_run=entry['run'],bundle=bundle,builds=entry['builds'],files={n:pin(v[1]) for n,v in files.items()},elf=elf,corpus=corpus,status='EXACT_RETAINED_INPUTS_PREPARED_NOT_EXECUTED',hardware='NOT_RUN',performance='NOT_MEASURED',installation='NOT_RUN')
 return files,receipt

def closure(files,receipt):
 for row in receipt['elf'].values():
  need(row['interpreter'].lstrip('/') in files,'ordinary loader absent from verified bootstrap')
  for soname in row['needed']:need(any(p+soname in files for p in ('usr/lib/','lib/')),'needed runtime library absent')
