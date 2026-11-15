# SPDX-License-Identifier: MIT
"""Fixed GTK/old+new GLib ELF DATA join; never run a loader or package code."""
import hashlib,re,struct,tarfile,time
from pathlib import Path
LIBRARIES=re.compile(r'usr/lib/lib(?:glib|gobject|gmodule|gthread|gio|girepository)-2\.0\.so\..+')
def symbols(raw):
 assert raw[:6]==b'\x7fELF\x02\x01'and struct.unpack_from('<H',raw,18)[0]==183
 offset=struct.unpack_from('<Q',raw,40)[0];size,count=struct.unpack_from('<HH',raw,58);assert size==64 and 0<count<65535 and offset+size*count<=len(raw)
 sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+i*size)for i in range(count)];defined=set();required=set()
 for section in sections:
  if section[1]!=11:continue
  start,length,link,entry=section[4],section[5],section[6],section[9];assert entry==24 and length%24==0 and length//24<100000 and start+length<=len(raw)and link<count
  strings=sections[link];base,n=strings[4:6];assert base+n<=len(raw);table=raw[base:base+n]
  for pos in range(start,start+length,24):
   name,info,other,index,_,_=struct.unpack_from('<IBBHQQ',raw,pos);assert name<n;end=table.find(b'\0',name);assert end>=0 and end-name<4096;text=table[name:end].decode('ascii');bind=info>>4
   if not text or bind not in [1,2]:continue
   assert index!=65535
   if index==0 and bind==1:required.add(text)
   elif index!=0 and other&3 in [0,3]:defined.add(text)
 return defined,required

def scan(path,reference,E,gtk=False):
 assert path.is_file()and not path.is_symlink()and path.stat().st_size==reference['bytes']<=64*1024**2
 with path.open('rb')as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==reference['sha256']
 deadline=time.monotonic()+60;total=0;providers={};exports=set();requires=set();shapes={};seen=set()
 with tarfile.open(path,'r|*')as archive:
  for count,member in enumerate(archive):
   assert time.monotonic()<deadline and count<20000;name=member.name.removeprefix('./').rstrip('/');assert name not in seen and not name.startswith('/')and '..'not in Path(name).parts;seen.add(name);total+=member.size;assert total<=256*1024**2 and member.size<=32*1024**2
   if not member.isfile():continue
   with archive.extractfile(member)as stream:raw=stream.read(32*1024**2+1)
   assert len(raw)==member.size
   shape=E.parse_elf(raw)
   if shape is not None:
    assert shape['machine']==183 and shape['class']==64 and not shape['insufficient_declared_16K_alignment']and shape['static_16K_observation']=='load-congruence-observed';shapes[name]=shape
   if (gtk and re.fullmatch(r'usr/lib/libgtk-4\.so\.1\..+',name))or(not gtk and LIBRARIES.fullmatch(name)):
    defined,undefined=symbols(raw);providers[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'SONAME':shape['soname'],'NEEDED':shape['needed']};exports|=defined;requires|={n for n in undefined if n.startswith('g_')}
 assert len(providers)==(1 if gtk else 6)
 return providers,exports,requires,shapes

def check(old,new,gtk,facts,gtk_reference,E):
 before,old_exports,_,old_shapes=scan(old,facts['old']['archive'],E);after,new_exports,_,new_shapes=scan(new,facts['new']['archive'],E);gtk_leaves,_,required,_=scan(gtk,gtk_reference,E,True)
 for role,rows in [('old',before),('new',after)]:
  assert rows=={n:{k:r[k]for k in ['bytes','sha256','SONAME','NEEDED']}for n,r in facts[role]['providers'].items()}
 assert {r['SONAME']for r in before.values()}=={r['SONAME']for r in after.values()}and not old_exports-new_exports
 assert required==set(facts['GTK_GLib_strong_requirements'])and not required-new_exports
 assert {'g_timeout_source_new_ns','g_markup_parse_context_get_attribute_position'}<=new_exports and not({'g_timeout_source_new_ns','g_markup_parse_context_get_attribute_position'}&old_exports)
 return {'status':'PASS_FIXED_GTK_GLIB_SYMBOL_AND_16K_DATA_ONLY','old_provider_count':6,'new_provider_count':6,'GTK_GLib_strong_requirements':len(required),'old_ELF_count':len(old_shapes),'new_ELF_count':len(new_shapes),'missing_GLib_symbols':[],'old_exports_lost':[],'transitive_symbol_versions_runtime':'NOT RUN'}
