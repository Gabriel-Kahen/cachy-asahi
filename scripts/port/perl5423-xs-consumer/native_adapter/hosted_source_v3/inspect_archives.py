#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Three exact retained archives as DATA: no extraction, tool execution or network."""
import argparse,hashlib,json,tarfile,time
from pathlib import Path
EXPECTED={
 'gcc':('gcc-16.1.1+r12+g301eb08fa2c5-1-aarch64.pkg.tar.xz',46558316,'067a2aa64f5c7e626e3910fed6fd1f173a1fd9eb6bebaebdd7a7f5be58e170c4','9cd5a11f7c87273ada4fd3ceb8e16b83bd04c9af71bee0eb5055c1be207c958b'),
 'binutils':('binutils-2.46+r70+g155188ea10a7-1-aarch64.pkg.tar.xz',7845808,'1acb6074f546ee662f29937897ab80bd87b0dcdd66c714381e8488d79cd53fcc','0b9331d39529b34f3b0d15f7ea6f1949fa027b7dba9ea504be1621aa3ba429b9'),
 'make':('make-4.4.1-3-aarch64.pkg.tar.xz',497124,'c5c8b56bfbacd875d72823f10c910747714730c4180994d94a176c89ecea1e06','bcb341f5a70946b44ecd7693a2ec8dd01f28bf941f5ca409df95460ed7ad6f2a')}
SELECTED={'gcc':{'usr/bin/aarch64-unknown-linux-gnu-gcc','usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/cc1','usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/collect2','usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/lto-wrapper'},'binutils':{'usr/bin/as','usr/bin/ld'},'make':{'usr/bin/make'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(body):return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
def inspect(path,name):
 filename,size,sha,sig=EXPECTED[name];need(path.name==filename and path.is_file()and not path.is_symlink()and path.stat().st_size==size,'exact retained archive name/size')
 with path.open('rb')as f:need(hashlib.file_digest(f,'sha256').hexdigest()==sha,'exact archive SHA')
 signature=path.with_name(filename+'.sig');need(signature.is_file()and not signature.is_symlink()and signature.stat().st_size==566,'bounded ordinary signature DATA');need(pin(signature.read_bytes())==dict(bytes=566,sha256=sig),'exact retained detached signature bytes')
 rows={};payload={};licenses={};metadata=None;total=0;deadline=time.monotonic()+30
 with tarfile.open(path,'r|xz')as tree:
  for m in tree:
   need(time.monotonic()<deadline and len(rows)<8192,'bounded archive DATA scan');n=m.name.removeprefix('./').rstrip('/');need(n and not n.startswith('/')and all(x not in ('','.','..')for x in n.split('/'))and n not in rows and m.uid==m.gid==0 and not m.sparse,'ordinary exact unique package namespace')
   total+=m.size;need(0<=m.size<=64*1024**2 and total<=384*1024**2,'bounded decoded package DATA');row=dict(type=m.type.decode(),mode=m.mode,link=m.linkname);rows[n]=row
   if n in SELECTED[name]or n=='.PKGINFO'or n.startswith('usr/share/licenses/')and m.isfile():
    need(m.isfile(),'selected package leaf must be regular');body=tree.extractfile(m).read(64*1024**2+1);need(len(body)==m.size,'whole selected leaf');d=dict(**pin(body),mode=m.mode)
    if n in SELECTED[name]:
     need(body[:7]==b'\x7fELF\x02\x01\x01'and int.from_bytes(body[18:20],'little')==183,'actual selected AArch64 ELF64 DATA header');payload[n]=d
    elif n=='.PKGINFO':metadata=body
    else:licenses[n]=d
 need(set(payload)==SELECTED[name]and metadata is not None,'complete fixed selected package leaves')
 meta={}
 for line in metadata.decode().splitlines():
  if line and not line.startswith('#'):k,v=line.split(' = ',1);meta.setdefault(k,[]).append(v)
 version={'gcc':'16.1.1+r12+g301eb08fa2c5-1','binutils':'2.46+r70+g155188ea10a7-1','make':'4.4.1-3'}[name]
 need(meta['pkgname']==[name]and meta['pkgver']==[version]and meta['arch']==['aarch64'],'actual exact package metadata identity')
 for n,row in payload.items():
  group=sorted(k for k,v in rows.items()if k==n or v['type']=='1'and v['link'].removeprefix('./')==n);row['aliases']=['/'+v for v in group]
 symlinks={n:r['link']for n,r in rows.items()if r['type']=='2'and n in ['usr/bin/cc','usr/bin/aarch64-linux-gnu-gcc']}
 return dict(archive=dict(filename=filename,bytes=size,sha256=sha),signature=dict(bytes=566,sha256=sig),metadata=meta,PKGINFO=pin(metadata),payload=payload,symlinks=symlinks,license_payloads=licenses,headers=len(rows),decoded_member_bytes=total)
def compose(gcc,binutils,make):
 archives={n:inspect(p,n)for n,p in [('gcc',gcc),('binutils',binutils),('make',make)]};payload={p:r for a in archives.values()for p,r in a['payload'].items()}
 return dict(schema=1,kind='EXACT_SIGNED349_GCC_PRIVATE_DRIVER_V3',driver_source='/usr/bin/aarch64-unknown-linux-gnu-gcc',driver_target='/usr/bin/cachy-asahi-xs-gcc',payload={'/'+n:r for n,r in payload.items()},symlinks={'/'+n:t for a in archives.values()for n,t in a['symlinks'].items()},archives=archives,helper_prefix='/usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/',toolchain_paths={'cc':'/usr/bin/cachy-asahi-xs-gcc','ld':'/usr/bin/cachy-asahi-xs-gcc','make':'/usr/bin/make'},authority='DATA pins only; future fresh signed349 bootstrap/signature checks and distinct Root image qualification required',source_legal_freshness_native_M2_release='NOT ACCEPTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ['gcc','binutils','make','output']:p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();body=(json.dumps(compose(a.gcc,a.binutils,a.make),sort_keys=True,indent=2)+'\n').encode()
 with a.output.open('xb')as f:f.write(body)
 print(json.dumps(pin(body)))
