# SPDX-License-Identifier: MIT
"""Passive output/ELF review; modeled DATA success grants no VM acceptance."""
import hashlib,importlib.util,stat,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
LOGS=tuple(n+'.log'for n in ('version','functional','corelist','json','perldoc','podtext','podcheck','prove','sha','splain','paths'))
FUNCTIONAL=b'PERL5423_FUNCTIONAL_OK\nDB_FILE=ROUNDTRIP\nGDBM=ROUNDTRIP\nZLIB=ROUNDTRIP\nBZIP2=ROUNDTRIP\nTHREADS=JOIN_SHARED\nLIBPERL=SHARED\n'

def module(n):
 s=importlib.util.spec_from_file_location('perl_proof_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def inventory_hash(inv):return hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inv.items())).encode()).hexdigest()


def elf(raw):
 K=module('contracts')
 K.need(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==183 and struct.unpack_from('<H',raw,16)[0]in(2,3),'linked LE AArch64 ELF64')
 offset=struct.unpack_from('<Q',raw,32)[0];width,count=struct.unpack_from('<HH',raw,54)
 K.need(width==56 and 0<count<=1024 and offset+width*count<=len(raw),'ELF program header bound')
 segments=[struct.unpack_from('<IIQQQQQQ',raw,offset+i*width)for i in range(count)];loads=[r for r in segments if r[0]==1]
 K.need(loads and all(r[2]+r[5]<=len(raw) and r[5]<=r[6] and r[7]>=16384 and r[7]&(r[7]-1)==0 and r[2]%16384==r[3]%16384 and r[2]%r[7]==r[3]%r[7] for r in loads),'actual 16K load geometry')
 return dict(machine=183,LOAD_segments=len(loads),minimum_alignment=min(r[7]for r in loads))


def outputs(directory,fields,inventory,runtime,nonce,epoch,now,byte_cap):
 K=module('contracts');P=module('protocol');P.validate(fields,inventory_hash(inventory),epoch,now,runtime['rollback']['local_database_policy'])
 root=K.ordinary(directory);elf_paths=[p for p in sorted(runtime['elfs'])if runtime['files'][p]['owner']=='perl']
 expected_elf={str(i)+'.elf':p for i,p in enumerate(elf_paths)}
 names=set(LOGS)|set(expected_elf)|{'outputs.sha256','summary.env','before-alpm-provider-observation.tsv'}
 K.need({p.name for p in root.iterdir()}==names,'complete durable ELF/log/restoration set')
 total=0;observed={}
 for name in sorted(names):
  p=root/name;info=p.lstat();K.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not info.st_mode&0o022,'ordinary single-link readonly extracted DATA')
  total+=info.st_size;K.need(total<=byte_cap,'complete durable DATA cap');observed[name]=K.pin(p,byte_cap)
 K.need((root/'functional.log').read_bytes()==FUNCTIONAL and observed['functional.log']['sha256']==fields['FUNCTIONAL_SHA256'],'actual full functional output')
 K.need((root/'version.log').read_bytes()==b'v5.42.3\n' and (root/'paths.log').read_bytes()==b'/usr/lib/perl5/5.42/core_perl/CORE/libperl.so\n','exact actual interpreter/shared-library paths')
 manifest=''.join(str(i)+'.elf\t'+p+'\t'+runtime['files'][p]['sha256']+'\n'for i,p in enumerate(elf_paths)).encode()
 K.need(hashlib.sha256(manifest).hexdigest()==fields['ELF_MANIFEST_SHA256'],'Root runtime ELF selection join')
 elfs={}
 for name,path in expected_elf.items():
  K.need(observed[name]['sha256']==runtime['files'][path]['sha256'],'retained installed ELF bytes join complete certificate')
  elfs[path]=elf((root/name).read_bytes())
 # GNU sha256sum sorts each glob independently: *.elf before *.log.
 expected=''.join(observed[n]['sha256']+'  '+n+'\n'for n in sorted(expected_elf)+sorted(LOGS)+['before-alpm-provider-observation.tsv']).encode()
 K.need((root/'outputs.sha256').read_bytes()==expected,'exact Root durable hash set')
 pre=[]
 if runtime['kind']=='ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1':
  for r in runtime['expected_payload']['rows']:
   if r['expected_package']!='perl'and r['expected_package']in inventory:pre.append('\t'.join((r['expected_path'],str(r['expected_member_bytes']),r['expected_member_sha256'],r['expected_package'],r['expected_package_version']))+'\n')
  for p,r in sorted(runtime['expected_payload']['aliases'].items()):
   if r['owner']!='perl'and r['owner']in inventory:pre.append('\t'.join((p,r['target'],r['owner'],r['version']))+'\n')
 K.need((root/'before-alpm-provider-observation.tsv').read_bytes()==''.join(pre).encode(),'durable actual pre-ALPM provider/alias receipt differs from explicit expected phase')
 K.need(P.frame((root/'summary.env').read_bytes(),nonce,'RESTORED')==fields,'serial/disk restoration receipt join')
 return dict(status='PASS_DURABLE_PERL5423_DATA_ONLY',files=observed,ELF16K=elfs,VM_acceptance=None,Root_acceptance=None,native_acceptance=False)
