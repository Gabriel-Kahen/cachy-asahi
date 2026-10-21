"""Finite new-purpose gating; never promotes legacy source/kernel authority."""
from pathlib import Path
import hashlib,json,os,re,stat
import inputs
P,C,_,_=inputs.broker()
BOUNDS=dict(observer=600,copy=2400,cleanup=120,worker=10500,QEMU=10800,memory_mib=4096,CPUs=2)
def read(path,cap):
 path=Path(path);P.need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary exact input path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);P.need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=cap,'bounded singlelink input');raw=bytearray()
  while len(raw)<s.st_size:
   b=os.read(fd,min(1024**2,s.st_size-len(raw)));P.need(bool(b),'complete input');raw.extend(b)
  P.need(P.stable(s)==P.stable(os.fstat(fd))==P.stable(path.lstat()),'input identity drift');return bytes(raw)
 finally:os.close(fd)
def gate(value,*,preparing=False):
 template=P.decode((inputs.D/'policy.json').read_bytes());P.need(set(value)==set(template)and value['purpose']=='GNU_IMMUTABLE_RUNTIME_V1'and value['bounds']==BOUNDS,'exact new-purpose policy/held budgets')
 for n in('actual_source','actual_ref','actual_run','kernel_build_decision','kernel_boot_decision','source_decision','producer_retirement','bootstrap','broker')+(()if preparing else('native_map','source_image_receipt')):P.need(value[n]is not None,'NULL genuine prerequisite: '+n)
 P.need(re.fullmatch('[0-9a-f]{40}',value['actual_source'])and re.fullmatch('codex/[a-z0-9-]+',value['actual_ref'])and re.fullmatch('[1-9][0-9]{0,19}',value['actual_run']),'genuine exact actual identity')
 for n in('kernel_build_decision','kernel_boot_decision','source_decision','producer_retirement','native_map','source_image_receipt'):
  if preparing and n in('native_map','source_image_receipt'):continue
  row=value[n];P.need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=256*1024**2 and re.fullmatch('[a-f0-9]{64}',row['sha256']),'whole private document pin '+n)
 selected=P.decode((inputs.D/'qualification-pins.json').read_bytes());P.need(selected['purpose']==value['purpose'],'source-owned qualification purpose')
 for n in('actual_source','actual_ref','actual_run','kernel_build_decision','kernel_boot_decision','source_decision','producer_retirement'):P.need(selected[n]is not None and selected[n]==value[n],'source-owned accepted prerequisite UNSUPPLIED: '+n)
 P.need(selected['broker_authorities']is not None and selected['kernel_artifact']is not None,'genuine broker/artifact input authority UNSUPPLIED')
 b=value['broker'];P.need(type(b)is dict and set(b)=={'purpose','nonce','source_authority','kernel_authority','producer_retirement','native_readback','verity'}and b['purpose']==P.PURPOSE and re.fullmatch('[a-f0-9]{32}',b.get('nonce')or''),'exact new-purpose broker custody')
 for n in('source_authority','kernel_authority','producer_retirement','native_readback'):
  row=b[n];P.need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=4*1024**2 and re.fullmatch('[a-f0-9]{64}',row['sha256']),'exact private broker source authority '+n)
 P.need(selected['broker_authorities']=={n:b[n]for n in('source_authority','kernel_authority','producer_retirement','native_readback')},'same source-selected broker authorities')
 if not preparing:
  w=b['verity'];P.need(type(w)is dict and set(w)=={'data_blocks','root_hash','salt','data_device','hash_device'}and w['data_device']is None and w['hash_device']is None,'physical block IDs must come from actual PID1 ioctls, never guessed')
  for n in('root_hash','salt'):P.need(re.fullmatch('[a-f0-9]{64}',w[n]),'whole source-owned verity digest')
  P.need(w['data_blocks']==2*1024**2,'exact existing8GiB source')
 return value

def private(value,name,cap):
 raw=read(Path('/immutable-inputs')/(name+'.json'),cap);P.need(P.pin(raw)==value[name],'exact private prerequisite '+name);return P.unpack(P.decode(raw))
