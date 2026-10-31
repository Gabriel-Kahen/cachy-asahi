# SPDX-License-Identifier: MIT
"""Finite public certificate DATA/time parser, never cryptographic verification."""
import base64,hashlib
def packets(raw):
 i=0
 while i<len(raw):
  start=i;first=raw[i];i+=1;assert first&128
  if first&64:
   tag=first&63;n=raw[i];i+=1
   if n<192:size=n
   elif n<=223:size=((n-192)<<8)+raw[i]+192;i+=1
   elif n==255:size=int.from_bytes(raw[i:i+4],'big');i+=4
   else:raise ValueError('partial packet not accepted for finite public certificate')
  else:
   tag=(first>>2)&15;kind=first&3;assert kind!=3;count=(1,2,4)[kind];size=int.from_bytes(raw[i:i+count],'big');i+=count
  assert 0<=size<=65536 and i+size<=len(raw);yield tag,raw[i:i+size];i+=size
 assert i==len(raw)

def subpackets(raw):
 i=0;out=[]
 while i<len(raw):
  n=raw[i];i+=1
  if n<192:size=n
  elif n<255:size=((n-192)<<8)+raw[i]+192;i+=1
  else:size=int.from_bytes(raw[i:i+4],'big');i+=4
  assert size>0 and i+size<=len(raw);out.append((raw[i]&127,raw[i+1:i+size]));i+=size
 return out

def certificate(armored):
 if type(armored)is not bytes or not(0<len(armored)<=65536)or b'BEGIN PGP PUBLIC KEY BLOCK'not in armored or b'PRIVATE KEY'in armored:raise ValueError('finite public certificate only')
 lines=armored.splitlines();start=lines.index(b'');raw=base64.b64decode(b''.join(v for v in lines[start+1:]if v and not v.startswith((b'=',b'-'))),validate=True);ps=list(packets(raw))
 if any(tag in(5,7)for tag,_ in ps):raise ValueError('private packet refused')
 keys=[v for tag,v in ps if tag==6]
 if len(keys)!=1 or keys[0][0]!=4:raise ValueError('one v4 primary signing key required')
 key=keys[0];created=int.from_bytes(key[1:5],'big');fingerprint=hashlib.sha1(b'\x99'+len(key).to_bytes(2,'big')+key).hexdigest().upper();records=[]
 for tag,s in ps:
  if tag!=2 or len(s)<6 or s[0]!=4 or s[1]not in(0x10,0x11,0x12,0x13,0x1f):continue
  hlen=int.from_bytes(s[4:6],'big');rows=subpackets(s[6:6+hlen]);times=[int.from_bytes(v,'big')for t,v in rows if t==2 and len(v)==4];expiry=[int.from_bytes(v,'big')for t,v in rows if t==9 and len(v)==4]
  if len(times)==len(expiry)==1 and expiry[0]>0:records.append((times[0],expiry[0]))
 if not records:raise ValueError('explicit finite signed expiration metadata required')
 latest=max(v[0]for v in records);expires={created+v[1]for v in records if v[0]==latest}
 if len(expires)!=1:raise ValueError('ambiguous latest self-signature expiry')
 return dict(fingerprint=fingerprint,created=created,expires=expires.pop(),self_signature_epoch=latest,scope='PUBLIC_PACKET_DATA_CRYPTO_NOT_REVERIFIED')
