# SPDX-License-Identifier: MIT
# Pinned glibc8362 auxcache2.0 AArch64LP64LE. Hex bytes, never numeric U64.
function fail(s) { print "AUXCACHE_REFUSED " s > "/dev/stderr"; failed=1; exit 2 }
function take(p,n) { return substr(hex,2*p+1,2*n) }
function byte(p) { return take(p,1) }
function u32(p, i,v) { v=0;for(i=3;i>=0;i--)v=256*v+strtonum("0x" byte(p+i));return v }
function be64(p, i,v) { v="";for(i=7;i>=0;i--)v=v byte(p+i);return v }
function le32(v, i,s) { s="";for(i=0;i<4;i++){s=s sprintf("%02x",v%256);v=int(v/256)};return s }
function emit(s, i) { for(i=1;i<=length(s);i+=2)printf "%c",strtonum("0x" substr(s,i,2)) }
BEGIN { hex="";failed=0 }
{
 line=$0;gsub(/[ \t]/,"",line)
 if(line !~ /^[0-9a-f]*$/ || length(line)%2 || length(line)>8192)fail("hex stream")
 if(length(hex)+length(line)>2097152)fail("byte cap")
 hex=hex line
}
END {
 if(failed)exit 2
 bytes=length(hex)/2
 if(bytes<33 || bytes>1048576)fail("bounded input")
 if(take(0,24)!="676c6962632d6c642e736f2e61757863616368652d322e30")fail("magic/version")
 count=u32(24);len=u32(28);table=32+48*count
 if(count>4096 || len<1 || len>1048576 || table+len!=bytes)fail("48-byte geometry/extent")
 if(byte(table)!="00")fail("NULL sentinel")
 cursor=1;segments=0
 while(cursor<len){
  start=cursor
  while(cursor<len && byte(table+cursor)!="00")cursor++
  if(cursor>=len || cursor-start>4096)fail("whole terminated SONAME")
  names[start]=take(table+start,cursor-start);segments++;cursor++
 }
 used=0
 for(i=0;i<count;i++){
  p=32+48*i
  # Prefix forces string comparison even for all-decimal hexadecimal keys.
  key="u" be64(p) be64(p+8) be64(p+16) be64(p+24)
  if(key in records)fail("duplicate full U64 identity")
  if(take(p+32,4)!="030a0000")fail("architecture/library flags")
  isa=u32(p+40);if(isa>1023)fail("ISA bits")
  offset=u32(p+36)
  if(offset==0){name="";name_len="ffffffff"}
  else{
   if(!(offset in names) || offset in refs)fail("whole unique SONAME offset")
   refs[offset]=1;used++;name=names[offset];name_len=le32(length(name)/2)
  }
  # Excludes only 4 ABI tail-padding bytes, table order and name offsets.
  records[key]=take(p,36) take(p+40,4) name_len name
 }
 if(used!=segments)fail("unreferenced string membership")
 n=asorti(records,keys,"@ind_str_asc")
 if(n!=count)fail("exact member count")
 # Exact host4bf08 CANONICAL_MAGIC + LE32 count + sorted defined records.
 emit("43414348595f474c494243383336325f4155585f444546494e45445f4649454c44535f563100")
 emit(le32(count))
 for(i=1;i<=n;i++)emit(records[keys[i]])
}
