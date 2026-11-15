#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent retained-result joins then exact pinned existing passive Reader."""
import argparse,ctypes,hashlib,importlib.util,json,os,re,stat,sys,time,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent

def local(name):
 s=importlib.util.spec_from_file_location('retained_reader_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
S=local('source');R=local('retention');F=local('fence');D=S.D
SOURCE='445b37a9475a4e92804954f4f0e3d0ac84cd9511';REF='refs/heads/codex/native-arm-perl5423-installed-lifecycle-v1-20261115-r3'
OP='perl5423-installed-lifecycle-native-v1'
PASSIVE={'hosted/reader.py':'c25379514eb494c4a1541aebb102e47c3897b6c27183b69d7bfa210ad07e8be2','hosted/capsule.py':'354ce106cc89bba186f4d9f62fddb10c55b86632a07ebd53a63ea22784d99b34','hosted/image_probe.py':'a8962c92041a5beb7b6adfd27a6bad64d15d3e62bbb9cad3f6e8ed6940fd55ba'}

def checked(row,cap=16*D.MIB):
 D.need(type(row)is dict and set(row)=={'path','bytes','sha256'},'exact external reference row');b=D.read(row['path'],cap);D.need(D.pin(b)=={k:row[k]for k in('bytes','sha256')},'whole external reference');return b

def binding(value):
 D.need(set(value)=={'schema','scope','binding','Original','artifact_metadata','materialization','root_admission'},'exact independent Root input envelope');D.need(value['schema']==1 and value['scope']=='ROOT_AUTHENTICATED_RETAINED_PERL_INSTALLED_OUTPUT_DATA_ONLY','Root caller authentication is required external premise');b=value['binding']
 expected={'scope','operation','source','ref','run','job','approval','source_map_sha256','image','producer_report_sha256'}
 D.need(type(b)is dict and set(b)==expected and b['scope']=='ROOT_AUTHENTICATED_PERL_INSTALLED_LIFECYCLE_DATA_READER_ONLY'and SOURCE is not None and REF is not None and b['source']==SOURCE and b['ref']==REF and b['source']not in('b4079a8a478afb0df8e634b555b3d2955a97bb9b','71246ca38e58f9f410d1f3eea15f5ddf174bb1bf')and re.fullmatch('[0-9a-f]{40}',b['source'])and b['operation']==OP and b['source_map_sha256']==S.MAP and all(type(b[k])is str and re.fullmatch('[1-9][0-9]{0,19}',b[k])for k in('run','job'))and all(re.fullmatch('[0-9a-f]{64}',b[k]or'')for k in('approval','producer_report_sha256'))and re.fullmatch('sha256:[0-9a-f]{64}',b['image']or''),'exact newly published Source/ref/run/job/admission; NULL and old failure refuse');return b

def original(envelope,evidence,b):
 row=envelope['Original'];D.need(0<row['bytes']<=256*D.MIB,'bounded opaque Original');p=Path(row['path']);D.need(p.is_absolute()and p==p.resolve()and not p.is_symlink()and p.is_file()and p.stat().st_nlink==1 and p.stat().st_size==row['bytes'],'ordinary unchanged Original');before=p.stat()
 with p.open('rb')as f:D.need(hashlib.file_digest(f,'sha256').hexdigest()==row['sha256'],'exact Root Original whole SHA')
 meta=D.decode(checked(envelope['artifact_metadata']));D.need(meta['id']>0 and meta['size_in_bytes']==row['bytes']and meta['digest']=='sha256:'+row['sha256']and meta['name']==OP+'-'+b['run']+'-1'and meta['expired']is False and str(meta['workflow_run']['id'])==b['run']and meta['workflow_run']['head_sha']==b['source']and meta['workflow_run']['head_branch']==b['ref'].removeprefix('refs/heads/'),'actual artifact Source/ref/run/body joins')
 receipt=D.decode(checked(envelope['materialization'],8*D.MIB));rows=receipt['files'];D.need(receipt['issuer']=='Root'and receipt['source_unchanged']is True and receipt['source_ZIP']=={k:row[k]for k in('bytes','sha256')}and receipt['Reader_calls']==receipt['network_GETs']==0 and 1<=len(rows)<=4096 and sum(v['bytes']for v in rows.values())==receipt['uncompressed_bytes']<=512*D.MIB,'complete faithful Root materialization')
 found=set();dirs=set();total=0
 for base,children,names in os.walk(evidence,followlinks=False):
  for n in children:q=Path(base)/n;D.need(not q.is_symlink(),'decoded directory alias');dirs.add(str(q.relative_to(evidence)))
  for n in names:
   q=Path(base)/n;name=D.relative(str(q.relative_to(evidence)));D.need(name in rows,'unmapped evidence');v=rows[name];raw=D.read(q,64*D.MIB);total+=len(raw);D.need(dict(**D.pin(raw),mode=stat.S_IMODE(q.stat().st_mode))==v and total<=512*D.MIB,'faithful complete evidence body/mode');found.add(name)
 D.need(found==set(rows)and dirs=={str(p)for n in rows for p in Path(n).parents if str(p)!='.'},'whole evidence namespace')
 with zipfile.ZipFile(p)as z:
  members=z.infolist();D.need(len(members)<=4096 and not z.comment,'finite Original ZIP');seen=set();decoded=0
  for item in members:
   D.need(not item.flag_bits&1 and item.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),'ordinary unencrypted ZIP compression')
   if item.is_dir():D.need(item.filename.rstrip('/')in dirs,'declared ordinary ZIP directory');continue
   name=D.relative(item.filename);D.need(name in rows and name not in seen and item.file_size<=64*D.MIB and stat.S_IFMT(item.external_attr>>16)in(0,stat.S_IFREG),'ordinary unique Original member');h=hashlib.sha256();size=0
   with z.open(item)as stream:
    while block:=stream.read(65536):h.update(block);size+=len(block);D.need(size<=64*D.MIB,'member stream bound')
   decoded+=size;D.need(size==rows[name]['bytes']and h.hexdigest()==rows[name]['sha256']and stat.S_IMODE(item.external_attr>>16)==rows[name]['mode']and decoded<=512*D.MIB,'raw Original member CRC/hash/mode joins faithful DATA');seen.add(name)
 D.need(seen==set(rows),'complete ZIP membership');after=p.stat();D.need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'unchanged opaque Original');return rows

def delegate(root,evidence,output,binding_path,binding_sha,files,contract,inner,envelope,evidence_rows):
 D.need(not output.exists()and output.is_absolute()and output==output.resolve()and output.parent.stat().st_uid==os.getuid()and not output.parent.stat().st_mode&0o022 and not any(p.is_symlink()for p in(output.parent,*output.parents)),'fresh owned private exact Reader/capsule output')
 D.need(not output.is_relative_to(root)and not root.is_relative_to(output)and not output.is_relative_to(evidence)and not evidence.is_relative_to(output),'disjoint fresh output')
 code={str(root/n):files[n][0]for n in [*PASSIVE,'hosted/common.py']}
 for n,h in PASSIVE.items():D.need(D.pin(code[str(root/n)])['sha256']==h,'whole frozen hosted passive Reader')
 destination=output/'lifecycle-inputs'
 for n in('read_result.py','common.py'):
  D.need(inner[n][0]==files['lifecycle-code/'+n][0],'same capsule/core passive bytes');code[str(destination/n)]=inner[n][0]
 writes={str(destination/n):v['mode']for n,v in contract['capsule']['members'].items()};writes[str(output/'hosted-reader.json')]=0o600
 reads={str(root/n)for n in files}|{str(evidence/n)for n in evidence_rows}|{str(binding_path)}
 dirs={str(root),str(evidence),str(output),str(destination)}|{str(p)for n in reads|set(writes)for p in Path(n).parents if p.is_relative_to(root)or p.is_relative_to(evidence)or p.is_relative_to(destination)}
 guard=F.Fence(reads,code,writes,dirs)
 with guard:
  spec=guard.spec('Root_exact_retained_output_hosted_reader',root/'hosted/reader.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);result=m.review(binding_path,binding_sha,evidence,output)
 D.need(not guard.denied,'zero denied passive calls');return result

def review(a):
 D.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info>=(3,11),'isolated unoptimized Python3.11+ passive Reader');raw=D.read(a.binding,2*D.MIB);D.need(D.pin(raw)['sha256']==a.binding_sha256,'external whole Root envelope pin');envelope=D.decode(raw);b=binding(envelope);root=Path(a.source_root);evidence=Path(a.evidence);output=Path(a.output)
 files,contract,inner=S.review(root);rows=original(envelope,evidence,b);admission=D.decode(checked(envelope['root_admission']));D.need(D.pin(checked(envelope['root_admission']))['sha256']==b['approval']and admission['source']==b['source']and admission['ref']==b['ref']and admission['operation']==OP and admission['source_map_sha256']==S.MAP,'actual same Source/ref/approval admission')
 def get(name,cap=16*D.MIB):D.need(name in rows,'declared Original evidence');return D.read(evidence/name,cap)
 retained=R.review(get,b,contract,D.decode(files['lifecycle-code/domain.json'][0]));D.need(get('binding.json')and D.decode(get('binding.json'))==dict({k:v for k,v in b.items()if k not in('scope','image','producer_report_sha256')},component_map_sha256=D.pin(files['lifecycle-code-map.json'][0])['sha256']),'actual outer job binding')
 # Existing hosted Reader expects only its established inner binding JSON shape.
 # The separately supplied Root envelope's exact nested bytes are written to one
 # fresh Root-owned output sibling by the caller, never synthesized from evidence.
 nested=Path(a.hosted_binding);nested_raw=D.read(nested,2*D.MIB);D.need(D.pin(nested_raw)['sha256']==a.hosted_binding_sha256 and D.decode(nested_raw)==b,'external exact hosted binding projection')
 result=delegate(root,evidence,output,nested,a.hosted_binding_sha256,files,contract,inner,envelope,rows)
 D.need(S.review(root)[0]==files,'Source pre/post continuity');original(envelope,evidence,b)
 return dict(schema=1,status='PASS_INDEPENDENT_RETAINED_OUTPUT_AND_PINNED_LIFECYCLE_DATA_ONLY',binding=b,retention=retained,lifecycle_consistency=result,Root_authentication=False,Root_decision=None,acceptance=False,full_uninstall='NOT_RUN',native16K='NOT_RUN',M2='NOT_RUN',performance='NOT_RUN',release='NOT_ACCEPTED')
if __name__=='__main__':
 os.umask(0o077);p=argparse.ArgumentParser(description=__doc__)
 for n in('binding','binding-sha256','hosted-binding','hosted-binding-sha256','source-root','evidence','output'):p.add_argument('--'+n,required=True)
 try:print(json.dumps(review(p.parse_args()),sort_keys=True,indent=2))
 except(ValueError,KeyError,TypeError,OSError,RuntimeError,zipfile.BadZipFile)as e:print(json.dumps(dict(status='REFUSED_RETAINED_OUTPUT_DATA',reason=type(e).__name__+': '+str(e)[:1800],acceptance=False,Root_decision=None)));raise SystemExit(2)
