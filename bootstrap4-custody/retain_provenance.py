"""Retain only source/build metadata for four already recovered original bodies; no keys."""
import base64,hashlib,io,json,re,tarfile,zipfile
from pathlib import Path
D=Path(__file__).resolve().parent;R=json.loads((D/'recovery.json').read_bytes());F=json.loads((D/'frame-custody.json').read_bytes())['frames'];cache={};rows={}
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def frame(c):
 key=c['frame']
 if key in cache:return cache[key]
 s=c['source'];p=Path(s['zip'])
 with zipfile.ZipFile(p)as z:
  i=z.getinfo(s['member']);assert i.CRC==s['CRC'];lines=z.read(i).splitlines()
 chunks=[];active=False
 for raw in lines:
  line=re.sub(rb'^\d{4}-\d\d-\d\dT[^ ]+Z ',b'',raw.removeprefix(b'\xef\xbb\xbf'))
  if line.startswith(b'CACHY_ASAHI_EVIDENCE_BEGIN ')and key.encode()in line:active=True;continue
  if not active:continue
  if line.startswith(b'CACHY_ASAHI_EVIDENCE_END '):break
  assert re.fullmatch(rb'[A-Za-z0-9+/=]+',line);chunks.append(line)
 body=base64.b64decode(b''.join(chunks),validate=True);assert pin(body)==F[key]['pin'];cache[key]=body;return body
for name,row in R['recovered'].items():
 c=next((x for x in row['custody']if 'desktop-canonical'in x['source'].get('zip','')and'/artifacts/'in x['member']),row['custody'][0]);prefix=c['member'].split('/artifacts/')[0];out=D/'provenance'/row['required']['name'];out.mkdir(parents=True);kept={}
 with tarfile.open(fileobj=io.BytesIO(frame(c)))as t:
  for suffix in('provenance.json','inputs/PKGBUILD','inputs/.SRCINFO','artifacts/generated.SRCINFO','artifacts/packages.lock','expected-packages.lock','artifacts/config.sha256','artifacts/environment.txt','artifacts/makepkg.conf','artifacts/pacman.conf','build.log'):
   path=prefix+'/'+suffix
   try:m=t.getmember(path)
   except KeyError:continue
   assert m.isfile()and m.size<=1024**2;raw=t.extractfile(m).read();p=out/suffix;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);kept[suffix]=dict(member=path,**pin(raw))
 body=(D/'recovered'/name).read_bytes();assert pin(body)==row['pin'];pkg={}
 with tarfile.open(fileobj=io.BytesIO(body))as t:
  for member in('.PKGINFO','.BUILDINFO'):
   raw=t.extractfile(member).read();(out/member).write_bytes(raw);values={}
   for line in raw.decode().splitlines():
    if ' = 'in line:
     k,v=line.split(' = ',1);values.setdefault(k,[]).append(v)
   pkg[member]=dict(pin=pin(raw),fields={k:values.get(k)for k in('pkgname','pkgver','pkgarch','pkgbuild_sha256sum','builddate','builddir')})
   if member=='.BUILDINFO':assert values['pkgbuild_sha256sum']==[kept['inputs/PKGBUILD']['sha256']]
 rows[name]=dict(raw=row['pin'],custody=c,metadata=kept,package_metadata=pkg)
save(D/'source-index-provenance.json',dict(status='EXACT_FOUR_RAW_AND_ORIGINAL_RECIPE_BUILDINFO_JOIN',packages=rows,keys='NOT_READ_NOT_USED'))
print('PASS four exact raw PKGBUILD/BUILDINFO joins; original source/provenance retained')
