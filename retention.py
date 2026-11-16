# SPDX-License-Identifier: MIT
"""Closed, bounded ordinary DATA export from the verification copy only."""
import hashlib,importlib.util,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PREFIX='var/lib/arm16k-perl5423-vm/'
MANIFEST='retained-data-manifest.json'
MAX_FILE=16*1024**2
MANIFEST_CAP=64*1024

def module(n):
 s=importlib.util.spec_from_file_location('perl_retention_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def receipt_names(runtime):
 required=set('base.lock final.lock installed.lock dependencies.log install.log database-installed.log database-final.log added.paths exclusive.paths before-alpm-provider-observation.tsv pacman-log-before pacman-log-prefix pacman-log-after ownertrust import.log secret.log keys.log ownertrust.log signature.log gpg-stop.log sync.log summary.env'.split())
 required.update(stage+'.'+suffix for stage in('before','after')for suffix in('paths','meta','meta-equality','hash','db','db-normalized','xattr','dbmeta','dbxattr','cache'))
 required.update(stage+'.'+suffix for stage in('user-before','user-current')for suffix in('meta','hash','xattr'))
 if runtime['rollback']['mode']=='REMOVE':required.add('remove.log')
 else:
  required.update('old-perl.lock recovered-perl.lock rollback.log rollback-signature.log'.split())
  required.update(stage+'.perl-desc.'+suffix for stage in('before','after')for suffix in('normalized','raw'))
 if runtime['dependency_transaction']:
  required.update('dependency-requires.log dependency-install.log dependencies.lock dependency-added.paths dependency-remove.log dependency-exclusive.paths official-public-observation.tsv official-ownertrust'.split())
  required.update('official-'+n+'.log'for n in('source-import','selected-export','import-stop','import','secret','keys','ownertrust','signature','stop'))
 if runtime['restoration_allowances']['pacman_log_before']is None:required.add('pacman-log-before.absent')
 pairs=[{n+'.saved',n+'.absent'}for n in('_etc_ld.so.cache','_var_cache_ldconfig_aux-cache')]
 return required,pairs,{'ldconfig-directory.absent'}

def select(nodes,runtime,limits):
 K=module('contracts');P=module('proof');required,pairs,optional=receipt_names(runtime)
 results=set(P.LOGS)|{'outputs.sha256','summary.env','before-alpm-provider-observation.tsv'}
 results.update(str(i)+'.elf'for i,p in enumerate(sorted(p for p in runtime['elfs']if runtime['files'][p]['owner']=='perl')))
 selected={}
 for group in('results','receipts'):
  prefix=PREFIX+group+'/'
  root=nodes.get(PREFIX+group,{})
  K.need(root.get('type')=='directory'and root.get('uid')==root.get('gid')==0 and root.get('mode')==0o700,'private ordinary guest DATA directory')
  rows={n[len(prefix):]:r for n,r in nodes.items()if n.startswith(prefix)}
  names=set(rows)
  if group=='results':K.need(names==results,'exact durable result membership')
  else:
   K.need(required<=names and names<=required|optional|set().union(*pairs),'exact reviewed receipt allowlist')
   K.need(all(len(names&pair)==1 for pair in pairs),'one saved/absent receipt per cache path')
  K.need(len(rows)<=128,'bounded flat DATA count')
  for name,row in rows.items():
   K.need('/'not in name and row.get('type')=='file'and row.get('links')==1 and row.get('uid')==row.get('gid')==0 and row.get('mode')in(0o600,0o644),'ordinary root-owned single-link nonexecutable guest DATA')
   cap=MAX_FILE
   if name=='pacman-log-after':cap=min(24*1024**2,(runtime['restoration_allowances']['pacman_log_before']or{'bytes':0})['bytes']+limits['log_bytes'])
   if name.endswith('.log'):cap=min(cap,limits['log_bytes'])
   K.need(type(row.get('size'))is int and 0<=row['size']<=cap,'bounded selected DATA file')
   if name.endswith('.absent'):K.need(row['size']==0,'empty absence marker')
   selected[group+'/'+name]=row
 K.need(sum(r['size']for r in selected.values())+MANIFEST_CAP<=min(limits['guest_output_cap_bytes'],limits['logs_cap_bytes']),'combined results/receipts/manifest byte budget')
 return dict(sorted(selected.items()))

def export(reader,nodes,output,runtime,limits,packet,case_pin,guard):
 K=module('contracts');selected=select(nodes,runtime,limits)
 manifest=dict(schema=1,nonce=packet['nonce'],case_packet=case_pin,Source_lock=packet['Source_lock'],files={})
 for group in('results','receipts'):(output/group).mkdir(mode=0o700)
 for name,row in selected.items():
  guard();fields,data=reader.inode(row['inode'])
  K.need(all(fields.get(k)==row[k]for k in('inode','type','mode','uid','gid','size','links')),'selected inode identity stable')
  path=output/name;digest=hashlib.sha256();size=0
  with path.open('xb')as stream:
   path.chmod(0o600)
   for block in reader.chunks(fields,data):
    guard();size+=len(block);K.need(size<=row['size'],'selected stream byte bound');digest.update(block);stream.write(block)
  K.need(size==row['size']and digest.hexdigest()==row['sha256'],'selected stream exact bytes/hash')
  manifest['files'][name]=dict(bytes=size,sha256=digest.hexdigest(),mode=0o600)
 body=K.canonical(manifest);K.need(len(body)<=MANIFEST_CAP,'finite retained manifest')
 path=output/MANIFEST
 with path.open('xb')as stream:path.chmod(0o600);stream.write(body)
 return dict(manifest=K.pin(path),files=len(selected),bytes=sum(r['size']for r in selected.values()),VM_acceptance=None,Root_acceptance=None)

def verify(output,reference,runtime,packet,case_pin,limits):
 K=module('contracts');path=output/MANIFEST;K.need(K.pin(path,MANIFEST_CAP)==reference['manifest'],'retained manifest pin')
 value=K.load(path);K.keys(value,('schema','nonce','case_packet','Source_lock','files'),'retained manifest')
 K.need(value['schema']==1 and value['nonce']==packet['nonce']and value['case_packet']==case_pin and value['Source_lock']==packet['Source_lock'],'retained manifest case/Source/nonce joins')
 synthetic={}
 for group in('results','receipts'):
  root=K.ordinary(output/group);info=root.lstat();K.need(stat.S_ISDIR(info.st_mode)and stat.S_IMODE(info.st_mode)==0o700,'private host DATA directory')
  synthetic[PREFIX+group]=dict(type='directory',uid=0,gid=0,mode=0o700)
  names={p.name for p in root.iterdir()};K.need(names=={n.split('/')[1]for n in value['files']if n.startswith(group+'/')},'host retained membership')
  for name in names:
   relative=group+'/'+name;row=value['files'][relative];K.keys(row,('bytes','sha256','mode'),'retained file')
   p=K.ordinary(root/name);st=p.lstat();K.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==row['mode']==0o600 and K.pin(p,24*1024**2)=={k:row[k]for k in('bytes','sha256')},'ordinary exact retained host DATA')
   synthetic[PREFIX+relative]=dict(type='file',links=1,uid=0,gid=0,mode=0o600,size=st.st_size)
 selected=select(synthetic,runtime,limits)
 K.need(set(selected)==set(value['files'])and len(selected)==reference['files']and sum(r['size']for r in selected.values())==reference['bytes'],'complete retained manifest totals')
 return value
