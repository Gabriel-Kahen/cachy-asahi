#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize first caa3 staged16K inputs only after explicit Root decisions.

Passive bytes/pure validators only. No Git, crypto, compiler, package or runtime
actor. Root must independently supply and authorize the two acceptance inputs.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,shutil,stat,sys,tempfile,types,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
RUN=38994309021;SOURCE='78dfd3bbd85a61a84dda2dfc601796ee89edfd5f'
PACKAGE='cachy-asahi-glibc-gnu-provider-2.43.caa3-1-aarch64.pkg.tar.xz'
HELD='glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz'
HELD_SHA='8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b'
GATE='scripts/ci/glibc-debian-maintained-lifecycle/candidate_gate.py'
PHASE='scripts/ci/glibc-debian-maintained-system16k/phase_gate.py'
OWNER='scripts/ci/glibc-gnu-provider-lifecycle/common.py'
NORMAL='scripts/ci/glibc-gnu-provider/normal_clients.py'
SYSTEM='scripts/ci/glibc-gnu-provider-system16k/common.py'
CLIENTS=('smoke-normal','exec-child','plugin.so');MiB=1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'))
def safe(n):
 need(type(n) is str and 0<len(n)<=1024 and not n.startswith('/') and '\\' not in n and not any(ord(c)<32 for c in n) and all(p not in ('','.','..') for p in n.split('/')),'closed relative path required');return n
def read(p,cap=2*MiB):
 p=Path(p).absolute();need(not any(x.is_symlink() for x in (p,*p.parents)),'ordinary unaliased path required');s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded single-link regular input required');raw=p.read_bytes();need(len(raw)==s.st_size,'input changed during read');return raw
def exact(row,raw):need(type(row) is dict and type(row.get('bytes')) is int and {k:row.get(k) for k in ('bytes','sha256')}==pin(raw),'exact byte reference differs')
def reference(n,raw):return dict(path=safe(n),**pin(raw))

def helpers(repo):
 pins=obj(read(HERE/'source-pins.json'))['files'];cache={}
 for n,row in pins.items():exact(row,read(repo/safe(n),2*MiB))
 def load(root,n):
  need(root==repo and n in pins,'finite pinned pure helper required')
  if n not in cache:
   raw=read(repo/n,2*MiB);exact(pins[n],raw)
   if n==NORMAL:
    # Prevent an ambient module named provider_stage from supplying the parser.
    sys.modules['provider_stage']=load(repo,'scripts/ci/glibc-gnu-provider/provider_stage.py')
   spec=importlib.util.spec_from_file_location('staged_packet_'+hashlib.sha256(n.encode()).hexdigest()[:20],repo/n);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);cache[n]=m
  return cache[n]
 return load,pins

def decisions(pair,normal,G,artifact,retention,probes,compiles):
 for row in (pair,normal):
  G.identity(row.get('candidate'));need(row.get('run_id')==RUN and row.get('source_sha')==SOURCE and row.get('artifact_sha256')==artifact and row.get('retention_sha256')==retention,'explicit Root decision joins exact new original run/export')
 need(pair.get('status')=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and pair.get('hardware')=='NOT_RUN' and pair.get('provider_pkgbuild_sha256')==G.EXPECTED['pkgbuild_sha256'] and re.fullmatch('[0-9a-f]{64}',str(pair.get('archive_sha256',''))),'Root accepted new caa3 pair required')
 need(normal.get('status')=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and normal.get('files')==probes and normal.get('compile_receipts')==compiles and normal.get('normal_source_sha256')=='a766bc7cd31cce18fe7e564432de4e4b63db49763608ae70ef8fab61cd29116c','Root accepted exact new original normal probes/13-command receipts required')
 need(not {'private16k','private16k_archive_sha256'}&(pair.keys()|normal.keys()),'no prior/private16K prerequisites permitted')

class Original:
 def __init__(self,path):
  self.z=zipfile.ZipFile(path)
  try:self.inspect()
  except BaseException:self.z.close();raise
 def inspect(self):
  self.files={};rows=self.z.infolist();need(len(rows)<1500 and len({r.filename for r in rows})==len(rows),'closed bounded original ZIP')
  total=0
  for r in rows:
   safe(r.filename.rstrip('/'));need(not r.flag_bits&1 and stat.S_IFMT(r.external_attr>>16) in (0,stat.S_IFREG,stat.S_IFDIR),'ordinary unencrypted ZIP members')
   if r.is_dir():continue
   total+=r.file_size;need(r.file_size<=256*MiB and total<=770*MiB,'bounded original ZIP');self.files[r.filename]=r
  self.retention=self.get('retention.json',2*MiB);v=obj(self.retention)
  need(v['status']=='PASS_UNSELECTED_MAINTAINED_DEBIAN_PROVIDER_NATIVE_PAIR_EVIDENCE' and v['errors']==[] and set(v['files'])==set(self.files)-{'retention.json'},'original successful closed retained evidence required')
  self.records=v['files'];count=0
  for n,row in v['files'].items():
   r=self.files[n];need(row['bytes']==r.file_size and type(row['truncated']) is bool and type(row['source_bytes']) is int and row['source_bytes']>=row['bytes'] and row['truncated']==(row['source_bytes']>row['bytes']),'honest retained/source counts');h=hashlib.sha256()
   with self.z.open(r) as f:
    while block:=f.read(1024*1024):h.update(block)
   need(h.hexdigest()==row['sha256'],'original retained member digest differs');count+=r.file_size
  need(v['total_bytes']==count,'retained aggregate differs')
 def get(self,n,cap):
  safe(n);need(n in self.files and self.files[n].file_size<=cap,'required bounded original member missing')
  if hasattr(self,'records') and n!='retention.json':need(self.records[n]['truncated'] is False,'selected packet proofs must be complete')
  raw=self.z.read(self.files[n]);need(len(raw)==self.files[n].file_size,'ZIP member size differs');return raw
 def close(self):self.z.close()

def normal_checks(repo,load,root,probes,receipts):
 # Reuse the exact original normal_receipt function, including normal.validate,
 # without importing the system controller or calling its binding/actor code.
 raw=read(repo/SYSTEM);node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='normal_receipt')
 C=types.SimpleNamespace(SOURCE=repo,load=load,need=need,Path=Path,sys=sys,decode=obj,read=read,CLIENTS=CLIENTS)
 def ref(base,row,cap=256*MiB):
  raw=read(base/safe(row['path']),cap);exact(row,raw);return base/row['path']
 C.ref=ref;scope=vars(C);exec(compile(ast.Module(body=[node],type_ignores=[]),SYSTEM,'exec'),scope)
 for value in receipts.values():scope['normal_receipt'](value,root,probes)


def prepare(a):
 need(not sys.flags.optimize,'unoptimized parser required');repo=a.repo.absolute();output=a.output.absolute()
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output parent required')
 # Explicit decisions are required before large input reads or any output.
 pair_raw=read(a.pair_decision);normal_raw=read(a.normal_decision);pair=obj(pair_raw);normal=obj(normal_raw)
 load,pins=helpers(repo);G=load(repo,GATE);G.identity(pair.get('candidate'));G.identity(normal.get('candidate'))
 need(pair.get('status')=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and normal.get('status')=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES','UNBOUND: explicit Root new pair and normal decisions required')
 collected={n:read(a.collection/n,770*MiB if n=='artifact.zip' else 32*MiB) for n in ('run.json','artifacts.json','collection.json','artifact.zip')};run=obj(collected['run.json']);collection=obj(collected['collection.json']);listing=obj(collected['artifacts.json'])
 need(run['id']==RUN and run['head_sha']==SOURCE and run['run_attempt']==1 and run['event']=='workflow_dispatch' and run['status']=='completed' and run['conclusion']=='success','actual new successful first native attempt required');exact(collection['artifact.zip'],collected['artifact.zip'])
 need(listing['total_count']==1 and len(listing['artifacts'])==1,'one original artifact API row');row=listing['artifacts'][0];need(row['workflow_run']['id']==RUN and row['workflow_run']['head_sha']==SOURCE and row['expired'] is False and row['size_in_bytes']==len(collected['artifact.zip']) and row.get('digest') in (None,'sha256:'+pin(collected['artifact.zip'])['sha256']) and row['name']=='glibc-debian-maintained-provider-'+str(RUN)+'-1','original API/source/archive digest join')
 original=Original(a.collection/'artifact.zip')
 try:
  names=[f'packages/{s}/{PACKAGE}' for s in ('a','b')]+[f'runtime/{s}/normal-clients/bin/{n}' for s in ('a','b') for n in CLIENTS]+[f'runtime/{s}/normal-clients/receipt.json' for s in ('a','b')]+['source-proof.json','runtime/result.json','retention.json']
  files={n:original.get(n,256*MiB if n.startswith('packages/') else 4*MiB) for n in names}
 finally:original.close()
 proof=obj(files['source-proof.json']);result=obj(files['runtime/result.json'])
 need(proof['status']=='SOURCE_PROOF_PASS_NEW_MAINTAINED_DEBIAN_PAIR' and proof['source_sha']==proof['workflow_sha']==SOURCE and str(proof['run_id'])==str(RUN) and str(proof['run_attempt'])=='1' and proof['debian_source_sha']==G.EXPECTED['source_packet_ref'] and proof['old_GNU_pair']=='NOT_REUSED','actual original new candidate source proof')
 need(result['status']=='PASS_UNSELECTED_NATIVE_PAIR' and result['package_version']==G.EXPECTED['version'] and result['source_bundle_preserved'] is True and result['frozen_sources_preserved'] is True and result['archive_bytes_reproduced'] is True and result['normal_client_bytes_reproduced'] is True and [r['side'] for r in result['builds']]==['a','b'],'actual original preserved/reproduced new pair result')
 probes={n:reference('runtime/a/normal-clients/bin/'+n,files['runtime/a/normal-clients/bin/'+n]) for n in CLIENTS};compiles={s:reference(f'runtime/{s}/normal-clients/receipt.json',files[f'runtime/{s}/normal-clients/receipt.json']) for s in ('a','b')}
 decisions(pair,normal,G,pin(collected['artifact.zip'])['sha256'],pin(files['retention.json'])['sha256'],probes,compiles)
 need(files[f'packages/a/{PACKAGE}']==files[f'packages/b/{PACKAGE}'] and pin(files[f'packages/a/{PACKAGE}'])['sha256']==pair['archive_sha256'],'actual identical pair archives join Root decision')
 for n in CLIENTS:need(files['runtime/a/normal-clients/bin/'+n]==files['runtime/b/normal-clients/bin/'+n],'actual independently compiled probe pair differs')
 authority=read(a.authority,65536);need(pin(authority)==dict(bytes=15506,sha256=G.EXPECTED['authority_sha256']),'exact source-only authority required');held=read(a.held,256*MiB);need(a.held.name==HELD and pin(held)['sha256']==HELD_SHA,'exact original held rollback required')
 files.update({'acceptance/provider-pair.json':pair_raw,'acceptance/normal-probes.json':normal_raw,'acceptance/source-authority.json':authority,'rollback/'+HELD:held});files.update({'collected/'+n:raw for n,raw in collected.items() if n!='artifact.zip'})
 index=dict(schema_version=1,status='ROOT_ACCEPTED_PROVIDER_STAGED16K_INPUTS',candidate=G.EXPECTED,source_authority=reference('acceptance/source-authority.json',authority),provider_pair=reference('acceptance/provider-pair.json',pair_raw),probe_receipt=reference('acceptance/normal-probes.json',normal_raw),archives={s:reference(f'packages/{s}/{PACKAGE}',files[f'packages/{s}/{PACKAGE}']) for s in ('a','b')},probes=probes,held=reference('rollback/'+HELD,held),provider_pkgbuild_sha256=G.EXPECTED['pkgbuild_sha256'])
 files['source-map.json']=encoded(dict(run_id=RUN,source_sha=SOURCE,original_artifact=pin(collected['artifact.zip']),members={n:dict(member=n,**pin(files[n])) for n in names},pinned_helpers=pins,scope='FIRST_STAGED16K_INPUTS_ONLY_NO_PRIOR16K_OR_INSTALLATION_CREDIT'))
 index['files']={n:pin(raw) for n,raw in sorted(files.items())};need(8<=len(files)<=256 and all(0<len(v)<=256*MiB for v in files.values()) and sum(map(len,files.values()))<=512*MiB,'original staged packet finite bounds')
 temporary=Path(tempfile.mkdtemp(prefix='.'+output.name+'-',dir=output.parent))
 try:
  for n,raw in files.items():
   p=temporary/safe(n);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o755 if '/normal-clients/bin/' in n else 0o600);exact(index['files'][n],read(p,256*MiB))
  owner=load(repo,OWNER)
  def ref(base,row,cap=256*MiB):
   need(index['files'].get(row['path'])=={k:row[k] for k in ('bytes','sha256')},'complete immutable reference closure');return owner.ref(base,row,cap)
  C=types.SimpleNamespace(SOURCE=repo,load=load,read=read,ref=ref)
  load(repo,PHASE).validate(C,temporary,index)
  normal_checks(repo,load,temporary,probes,{s:obj(files[compiles[s]['path']]) for s in ('a','b')})
  (temporary/'packet.json').write_bytes(encoded(index))
  output.mkdir(mode=0o700);reservation=output.stat()
  try:os.rename(temporary,output)
  except BaseException:
   if output.exists() and output.stat().st_ino==reservation.st_ino and not any(output.iterdir()):output.rmdir()
   raise
 except BaseException:
  if temporary.exists():shutil.rmtree(temporary)
  raise
 return dict(status='PREPARED_EXPLICIT_ROOT_ACCEPTED_FIRST_STAGED16K_INPUTS',packet=pin(encoded(index)),files=len(files),bytes=sum(map(len,files.values())),native_run=RUN,source_sha=SOURCE,generic16k='NOT_RUN',installation='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('repo','collection','pair-decision','normal-decision','authority','held','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 try:value=prepare(a);code=0
 except Exception as e:value=dict(status='UNBOUND_OR_REFUSED_NO_PACKET_PUBLISHED',error=str(e)[:1024]);code=1
 print(json.dumps(value,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
