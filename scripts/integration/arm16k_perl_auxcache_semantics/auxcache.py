# SPDX-License-Identifier: MIT
"""Strict pure pinned-glibc auxcache2.0 AArch64LP64LE semantic projection.

Only byte input is consumed. SONAMEs are binary-safe DATA, never filesystem paths.
No current guest guard, provider qualification or Root acceptance is issued here.
"""
import base64,hashlib,struct
ABI='AAPCS64_LP64_LITTLE_ENDIAN'
MAGIC=b'glibc-ld.so.auxcache-2.0'
HEADER_BYTES=32
ENTRY_BYTES=48
DEFINED_ENTRY_BYTES=44
CAP=1048576
MAX_ENTRIES=4096
MAX_SONAME=4096
FLAG_AARCH64_LIBC6=0x0a03
ISA_MASK=0x3ff
CANONICAL_MAGIC=b'CACHY_GLIBC8362_AUX_DEFINED_FIELDS_V1\0'


def need(ok,why):
 if not ok:raise ValueError(why)
def pin(blob):return dict(bytes=len(blob),sha256=hashlib.sha256(blob).hexdigest())
def b64(blob):return base64.b64encode(blob).decode('ascii')

def decode(blob,*,abi=ABI):
 need(abi==ABI,'explicit pinned AArch64LP64 little-endian profile only; no architecture inference')
 need(type(blob)is bytes and HEADER_BYTES+1<=len(blob)<=CAP,'bounded auxiliary byte input')
 magic,count,length=struct.unpack_from('<24sII',blob)
 need(magic==MAGIC,'exact primary2.0 magic/version; unknown formats refuse')
 need(count<=MAX_ENTRIES and 1<=length<=CAP,'finite declared entry/string counts')
 table=HEADER_BYTES+ENTRY_BYTES*count
 need(table+length==len(blob),'exact48-byte entry geometry and complete file extent; no trailing bytes')
 strings=blob[table:];need(strings[0]==0,'offset0 is the distinct NULL SONAME sentinel')
 # The pinned writer emits one separate terminated segment per non-NULL name.
 # Reader offsets may relocate those segments; no suffix alias, overlap or junk
 # is accepted. Equal names still have distinct serialized segments/members.
 segments={};cursor=1
 while cursor<length:
  end=strings.find(b'\0',cursor)
  need(end>=cursor and end-cursor<=MAX_SONAME,'bounded complete string segment termination')
  segments[cursor]=strings[cursor:end];cursor=end+1
 need(cursor==length,'complete string extent')
 entries=[];identities=set();references=set();padding=bytearray();layout=[]
 for index in range(count):
  offset=HEADER_BYTES+index*ENTRY_BYTES
  ino,ctime,size,device,flags,name_index,isa,unused=struct.unpack_from('<QQQQiII4s',blob,offset)
  need(flags==FLAG_AARCH64_LIBC6,'unsupported auxiliary architecture/library flags; never mask semantic bits')
  need(isa<=ISA_MASK,'unsupported ISA field bits; every supported bit is preserved')
  identity=(ino,ctime,size,device)
  need(identity not in identities,'duplicate full stat identity; pinned insert routine aborts duplicates');identities.add(identity)
  if name_index==0:name=None
  else:
   need(name_index in segments and name_index not in references,'whole nonoverlapping uniquely referenced SONAME segment')
   references.add(name_index);name=b64(segments[name_index])
  entries.append(dict(inode=ino,ctime=ctime,size=size,device=device,flags=flags,isa_level=isa,soname_b64=name))
  padding.extend(unused);layout.append(dict(record_offset=offset,soname_offset=name_index,padding_sha256=pin(unused)['sha256']))
 need(references==set(segments),'all serialized string segments referenced exactly once; no hidden/trailing membership')
 return dict(kind='PARSED_PINNED_GLIBC_AUXCACHE_2_0_V1',abi=ABI,body=pin(blob),entries=entries,count=count,string_bytes=length,layout=layout,opaque_padding=pin(bytes(padding)),selection='UNSELECTED',Root_acceptance=None,lifecycle_acceptance=None)


def canonical_bytes(parsed):
 need(type(parsed)is dict and parsed.get('kind')=='PARSED_PINNED_GLIBC_AUXCACHE_2_0_V1'and parsed.get('abi')==ABI,'strict decoded profile required')
 entries=parsed.get('entries');need(type(entries)is list and type(parsed.get('count'))is int and len(entries)==parsed.get('count')<=MAX_ENTRIES,'exact decoded member count')
 records=[];identities=set()
 for e in entries:
  need(type(e)is dict and set(e)=={'inode','ctime','size','device','flags','isa_level','soname_b64'},'all and only defined semantic fields')
  need(all(type(e[k])is int and 0<=e[k]<2**64 for k in('inode','ctime','size','device')),'full unsigned64 stat fields, no coercion/truncation')
  need(type(e['flags'])is int and e['flags']==FLAG_AARCH64_LIBC6 and type(e['isa_level'])is int and 0<=e['isa_level']<=ISA_MASK,'exact full supported flags/ISA fields')
  identity=tuple(e[k]for k in('inode','ctime','size','device'));need(identity not in identities,'no canonical member deduplication');identities.add(identity)
  name=e['soname_b64'];raw=None
  if name is not None:
   need(type(name)is str,'binary-safe full SONAME or distinct NULL');raw=base64.b64decode(name,validate=True);need(len(raw)<=MAX_SONAME and b'\0'not in raw and b64(raw)==name,'canonical exact full SONAME bytes')
  # NULL and non-NULL empty name use distinct lengths; no name shortening,
  # numeric version folding, device/inode remapping or clock normalization.
  record=struct.pack('<QQQQiII',*identity,e['flags'],e['isa_level'],0xffffffff if raw is None else len(raw))+(b''if raw is None else raw)
  records.append((identity,record))
 records.sort(key=lambda row:row[0])
 return CANONICAL_MAGIC+struct.pack('<I',len(records))+b''.join(record for _,record in records)


def normalize(blob,*,abi=ABI):
 parsed=decode(blob,abi=abi);canonical=canonical_bytes(parsed)
 return dict(kind='NORMALIZED_AUX_DEFINED_FIELDS_DATA_ONLY_V1',abi=ABI,body=parsed['body'],defined_fields=pin(canonical),count=parsed['count'],entries=parsed['entries'],opaque_padding=parsed['opaque_padding'],normalizes_only=['four_AAPCS64_tail_padding_bytes','record_bucket_order','string_segment_offsets_order'],selection='UNSELECTED',Root_acceptance=None,lifecycle_acceptance=None),canonical


def compare(before,after,*,abi=ABI):
 left,l=normalize(before,abi=abi);right,r=normalize(after,abi=abi)
 def keyed(value):return {tuple(e[k]for k in('inode','ctime','size','device')):e for e in value['entries']}
 a=keyed(left);b=keyed(right);common=set(a)&set(b)
 changed=[dict(identity=dict(zip(('inode','ctime','size','device'),key)),before=a[key],after=b[key])for key in sorted(common)if a[key]!=b[key]]
 return dict(kind='AUX_DEFINED_FIELDS_COMPARISON_ONLY_V1',status='DEFINED_FIELDS_EQUAL_DATA_ONLY'if l==r else'DEFINED_FIELDS_DIFFER_DATA_ONLY',defined_fields_equal=l==r,raw_bytes_equal=before==after,before=dict(body=left['body'],defined_fields=left['defined_fields'],count=left['count']),after=dict(body=right['body'],defined_fields=right['defined_fields'],count=right['count']),removed=[a[k]for k in sorted(set(a)-set(b))],added=[b[k]for k in sorted(set(b)-set(a))],changed=changed,selection='UNSELECTED',holds=['actual_failed_predicate_not_proven','independent_provider_and_stat_identity_qualification_required','typed_metadata_xattrs_and_original_guard_checks_required','Root_future_source_selection_required'],actual_cause=None,Root_acceptance=None,lifecycle_acceptance=None)
