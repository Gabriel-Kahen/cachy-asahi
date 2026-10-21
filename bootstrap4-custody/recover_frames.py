"""Read only six retained original log ZIPs; decode bounded frames, recover exact6 bodies."""
import base64,hashlib,io,json,re,tarfile,zipfile
from pathlib import Path
D=Path(__file__).resolve().parent;DEV=D.parent;GUI=DEV/'current606-welcome7-gui-native-development-20261021';required=json.loads((GUI/'incoming33-recovery.json').read_bytes())['missing'];wanted={v['sha256']:(name,v)for name,v in required.items()};OUT=D/'recovered';OUT.mkdir(exist_ok=True);frames={};containers=[];matches={}
def need(v,why):
 if not v:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def inspect(raw,source,label):
 row=pin(raw);key=row['sha256']
 if key in frames:frames[key]['sources'].append(source);return
 f=dict(label=label,pin=row,sources=[source],members=[],package_candidates=[]);frames[key]=f
 try:t=tarfile.open(fileobj=io.BytesIO(raw),mode='r:*')
 except tarfile.ReadError:
  f['format']='NOT_TAR';return
 total=0
 with t:
  for m in t:
   total+=m.size;need(total<=512*1024**2 and m.size<=128*1024**2,'bounded tar closure')
   f['members'].append(dict(name=m.name,bytes=m.size,type=m.type.decode(errors='replace')))
   if not m.isfile()or not(m.name.endswith('.pkg.tar.xz')or m.name.endswith('.pkg.tar.zst')):continue
   body=t.extractfile(m).read();need(len(body)==m.size,'complete package body');p=pin(body);f['package_candidates'].append(dict(path=m.name,**p))
   if p['sha256']in wanted:
    name,expected=wanted[p['sha256']];need(len(body)==expected['size'],'exact required size');out=OUT/name
    if out.exists():need(out.read_bytes()==body,'same exact recovered bytes')
    else:out.write_bytes(body)
    matches.setdefault(name,dict(required=expected,pin=p,path=str(out),custody=[]))['custody'].append(dict(frame=key,member=m.name,source=source))
 f['expanded_member_bytes']=total
roots=['desktop-run38763443973','desktop-canonical-run38767488680','updater-real-check-run38776212071','tools-run38765227491','full-composition-run38774794165','full-composition-lifecycle-run38780072830']
start=re.compile(rb'CACHY_ASAHI_EVIDENCE_BEGIN ([a-z0-9-]+) sha256=([0-9a-f]{64}) bytes=([0-9]+)$');timestamp=re.compile(rb'^\d{4}-\d\d-\d\dT[^ ]+Z ')
for root in roots:
 p=DEV/root/'logs.zip';zrow=dict(path=str(p),pin=pin(p.read_bytes()),members=[]);containers.append(zrow)
 with zipfile.ZipFile(p)as z:
  need(sum(i.file_size for i in z.infolist())<=128*1024**2,'bounded original ZIP')
  for info in z.infolist():
   need(info.file_size<=64*1024**2,'bounded original log');body=z.read(info);zrow['members'].append(dict(name=info.filename,bytes=info.file_size,CRC=info.CRC,pin=pin(body)));active=None;parts=[]
   for rawline in body.splitlines():
    line=timestamp.sub(b'',rawline.removeprefix(b'\xef\xbb\xbf'),count=1);m=start.fullmatch(line)
    if m:
     need(active is None,'no nested evidence frame');label,sha,size=m.groups();active=(label,sha.decode(),int(size));parts=[];encoded_total=0;need(int(size)<=32*1024**2,'bounded exact frame');continue
    if active is None:continue
    label,sha,size=active
    if line==b'CACHY_ASAHI_EVIDENCE_END '+label:
     if b'signer'not in label:
      raw=base64.b64decode(b''.join(parts),validate=True);need(len(raw)==size and pin(raw)['sha256']==sha,'whole original frame length/hash');inspect(raw,dict(zip=str(p),member=info.filename,CRC=info.CRC),label.decode())
     active=None;parts=[];continue
    if b'signer'not in label:need(re.fullmatch(rb'[A-Za-z0-9+/=]+',line)is not None,'exact base64 frame line '+root+' '+info.filename+' '+label.decode()+' '+repr(line[:120]));parts.append(line);encoded_total+=len(line);need(encoded_total<=44*1024**2,'bounded frame encoded bytes')
   need(active is None,'complete closed frame')
p=DEV/'tools-run38765227491/tools-evidence.tar.gz';inspect(p.read_bytes(),dict(path=str(p)), 'standalone-tools-evidence')
save(D/'frame-custody.json',dict(status='LOCAL_ORIGINAL_FRAMES_CRC_HASH_VERIFIED',containers=containers,frames=frames,signer_frames='NOT_DECODED_NOT_READ_NO_KEYS',source_policy=pin((GUI/'incoming33-recovery.json').read_bytes())))
save(D/'recovery.json',dict(status='EXACT_RAW_BODY_RECOVERY_ONLY_NOT_AUTHENTICATED',required=required,recovered=matches,missing={n:r for n,r in required.items()if n not in matches},native='NOT_RUN',keys='NOT_USED'))
print(json.dumps(dict(frames=len(frames),package_candidates=sum(len(v['package_candidates'])for v in frames.values()),recovered=list(matches),missing=[n for n in required if n not in matches])))
