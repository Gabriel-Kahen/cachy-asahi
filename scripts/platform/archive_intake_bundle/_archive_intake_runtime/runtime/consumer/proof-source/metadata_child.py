"""Signed xz archive metadata as data. No extraction, script or payload execution."""
import ast,hashlib,json,lzma,os,re,stat,sys,tarfile,time
from pathlib import Path
BASE=Path(__file__).absolute().parent
archive=Path(sys.argv[1]);expected=json.loads(sys.argv[2]);pin=sys.argv[3]
assert archive.parent==BASE/'cache' and archive.name in ('networkmanager-1.58.1-1-aarch64.pkg.tar.xz','perl-5.42.2-2-aarch64.pkg.tar.xz')
info=archive.lstat();assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
with archive.open('rb') as src:assert hashlib.file_digest(src,'sha256').hexdigest()==pin
raw=(BASE/'capture/package_checks.py').read_bytes();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='metadata');env={'re':re};exec(compile(ast.Module(body=[node],type_ignores=[]),str(BASE/'capture/package_checks.py'),'exec'),env)
class Counted:
 def __init__(self,src):self.src=src;self.bytes=0
 def read(self,n):
  assert type(n) is int and 0<=n<=1024**2
  data=self.src.read(n);self.bytes+=len(data);assert self.bytes<=128*1024**2;return data
found={};started=time.monotonic();count=0
with lzma.open(archive,'rb') as xz:
 counted=Counted(xz)
 with tarfile.open(fileobj=counted,mode='r|') as tar:
  for member in tar:
   count+=1;assert count<=100000 and time.monotonic()-started<100
   name=member.name.removeprefix('./')
   if name not in ('.PKGINFO','.BUILDINFO'):continue
   assert name not in found and member.isfile() and 0<member.size<=256*1024
   stream=tar.extractfile(member);data=stream.read(member.size+1);assert len(data)==member.size
   fields=env['metadata'](data.decode('utf-8'));found[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'fields':fields}
assert set(found)=={'.PKGINFO','.BUILDINFO'}
pkg,bld=found['.PKGINFO']['fields'],found['.BUILDINFO']['fields']
assert all(pkg.get(k)==[v] for k,v in [('pkgname',expected['name']),('pkgver',expected['version']),('arch',expected['arch'])])
assert all(bld.get(k)==[v] for k,v in [('pkgname',expected['name']),('pkgver',expected['version']),('pkgarch',expected['arch']),('format','2')])
assert len(bld.get('pkgbuild_sha256sum',[]))==1 and re.fullmatch('[0-9a-f]{64}',bld['pkgbuild_sha256sum'][0])
print(json.dumps({'status':'PASS_SIGNED_METADATA_EXACT_TUPLE','identity':expected,'metadata':found,'archive_members_scanned':count,'decoded_bytes_read':counted.bytes,'payload_extracted_executed':False,'full_payload_correspondence_accepted':False},sort_keys=True))
