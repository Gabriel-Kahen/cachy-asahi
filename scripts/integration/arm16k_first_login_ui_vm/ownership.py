# SPDX-License-Identifier: MIT
"""Fixture-only pinned ownership DATA, sanitized live Qkk diagnostics and syncfs."""
import ctypes, errno, gzip, hashlib, json, os, re, stat, tarfile, time
from pathlib import Path, PurePosixPath
CATEGORIES={'File type mismatch':'type-mismatch','UID mismatch':'uid-mismatch','GID mismatch':'gid-mismatch','Permissions mismatch':'mode-mismatch','Symlink path mismatch':'link-mismatch','Modification time mismatch':'mtime-mismatch','Size mismatch':'size-mismatch','SHA256 checksum mismatch':'sha256-mismatch','MD5 checksum mismatch':'md5-mismatch','No such file or directory':'missing-path','Permission denied':'permission-refusal'}
LABELS=set(CATEGORIES.values())|{'missing-mtree'}

def sha(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def allowed(path):
    p=PurePosixPath(path)
    return (path.startswith(('/usr/','/etc/','/var/','/opt/'))and len(path)<=1024 and '..'not in p.parts and not any(ord(c)<32 or ord(c)==127 for c in path)and path not in ['/etc/shadow','/etc/gshadow']and not path.startswith(('/etc/ssh/','/usr/share/pacman/keyrings/'))and not any(v in p.parts for v in ['gnupg','private-keys-v1.d'])and not path.endswith(('.key','.pem','.gpg','.asc')))

def mtree(data):
    if len(data)>1024**2:raise ValueError('mtree-size-refusal')
    plain=gzip.decompress(data)
    if len(plain)>16*1024**2:raise ValueError('mtree-expanded-size-refusal')
    defaults={};result={}
    for line in plain.decode().splitlines():
        if not line or line.startswith('#'):continue
        fields=line.split()
        if fields[0]=='/set':defaults.update(dict(v.split('=',1)for v in fields[1:]));continue
        if fields[0]=='/unset':defaults={};continue
        name=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),fields[0]);attrs={**defaults,**dict(v.split('=',1)for v in fields[1:]if'='in v)}
        if not name.startswith('./'):continue
        path='/'+name[2:]
        if not allowed(path):continue
        row={'type':attrs.get('type')}
        for key in ['uid','gid','size']:
            if key in attrs:row[key]=int(attrs[key])
        if'mode'in attrs:row['mode']=int(attrs['mode'],8)
        if'time'in attrs:
            sec,_,fraction=attrs['time'].partition('.');row['mtime_ns']=int(sec)*10**9+int((fraction+'0'*9)[:9])
        if'sha256digest'in attrs:row['sha256']=attrs['sha256digest']
        if'link'in attrs:row['link_target_sha256']=hashlib.sha256(re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),attrs['link']).encode()).hexdigest()
        result[path]=row
    return result

def build_index(packages,rows,destination):
    """Read exact local archives as DATA; no sourcing/extraction/build/execute."""
    destination.mkdir();records=[]
    for row in rows:
        path=packages/row['filename'];assert sha(path)==row['sha256']
        with tarfile.open(path,'r:*')as archive:
            members=archive.getmembers();member=next(m for m in members if m.name=='.MTREE');assert member.isfile()and member.size<=1024**2
            compressed=archive.extractfile(member).read();tree=mtree(compressed)
            records.append({'package':row['name'],'path':'/var/lib/pacman/local/'+row['name']+'-'+row['version']+'/mtree','archive':{'type':'file','size':len(compressed),'sha256':hashlib.sha256(compressed).hexdigest()},'mtree':None})
            for member in members:
                path='/'+member.name.removeprefix('./').rstrip('/')
                if not allowed(path)or not(member.isfile()or member.isdir()or member.issym()or member.islnk()):continue
                ref={'type':'file'if member.isfile()or member.islnk()else'dir'if member.isdir()else'link','uid':member.uid,'gid':member.gid,'mode':member.mode,'mtime_ns':int(member.mtime*10**9)}
                if member.isfile()or member.islnk():
                    stream=archive.extractfile(member);ref['sha256']=hashlib.file_digest(stream,'sha256').hexdigest();ref['size']=stream.tell()
                if member.issym():ref['link_target_sha256']=hashlib.sha256(member.linkname.encode()).hexdigest()
                records.append({'package':row['name'],'path':path,'archive':ref,'mtree':tree.get(path)})
    shards=[];batch=[];size=2
    for row in records:
        encoded=json.dumps(row,separators=(',',':'))
        if batch and size+len(encoded)+1>512*1024:
            shards.append(_shard(destination,batch,len(shards)));batch=[];size=2
        batch.append(row);size+=len(encoded)+1
    if batch:shards.append(_shard(destination,batch,len(shards)))
    return {'schema_version':1,'package_count':len(rows),'record_count':len(records),'shards':shards}

def _shard(directory,rows,index):
    path=directory/('ownership-'+str(index).zfill(3)+'.json');path.write_text(json.dumps(rows,separators=(',',':'))+'\n');assert path.stat().st_size<=1024**2
    return {'filename':path.name,'bytes':path.stat().st_size,'sha256':sha(path)}

def load_index(directory,descriptor,packages):
    assert descriptor['schema_version']==1 and descriptor['package_count']==len(packages) and 0<len(packages)<=172 and len(descriptor['shards'])<=128
    result={};count=0
    for row in descriptor['shards']:
        assert re.fullmatch(r'ownership-[0-9]{3}\.json',row['filename']);path=directory/row['filename'];assert not path.is_symlink()and path.stat().st_size==row['bytes']<=1024**2 and sha(path)==row['sha256']
        for item in json.loads(path.read_text()):
            assert item['package']in packages and allowed(item['path']);key=(item['package'],item['path']);assert key not in result;result[key]=item;count+=1
    assert count==descriptor['record_count'];return result

def observe(path,root=Path('/'),deadline=None):
    """No symlink-parent traversal; metadata/hash only, never file contents out."""
    assert allowed(path);directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY);row={'state':'read-refusal'}
    try:
        for name in PurePosixPath(path).parts[1:-1]:
            newer=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);os.close(directory);directory=newer
        name=PurePosixPath(path).name;s=os.stat(name,dir_fd=directory,follow_symlinks=False)
        row={'state':'observed','type':'file'if stat.S_ISREG(s.st_mode)else'link'if stat.S_ISLNK(s.st_mode)else'dir'if stat.S_ISDIR(s.st_mode)else'other','uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'size':s.st_size,'mtime_ns':s.st_mtime_ns}
        if stat.S_ISLNK(s.st_mode):row['link_target_sha256']=hashlib.sha256(os.readlink(name,dir_fd=directory).encode()).hexdigest()
        if stat.S_ISREG(s.st_mode)and s.st_size<=512*1024**2:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            try:
                before=os.fstat(fd);digest=hashlib.sha256();count=0
                while chunk:=os.read(fd,65536):
                    if deadline is not None and time.monotonic()>=deadline:row['state']='hash-time-bound';return row
                    count+=len(chunk)
                    if count>512*1024**2:row['state']='hash-byte-bound';return row
                    digest.update(chunk)
                after=os.fstat(fd)
                identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
                if identity(s)!=identity(before)or identity(before)!=identity(after):row['state']='changed-file';return row
                row.update(sha256=digest.hexdigest(),hashed_bytes=count)
            finally:os.close(fd)
        return row
    except FileNotFoundError:return {'state':'missing-path'}
    except OSError:return {'state':'read-refusal'}
    finally:os.close(directory)

def analyze(stdout,stderr,exit,index,root=Path('/')):
    assert len(stdout)+len(stderr)<=1024**2
    warnings=[];unknown=[];summaries=0;altered=0;warning_count=0;unknown_count=0;deadline=time.monotonic()+10
    packages={p for p,_ in index}
    for stream,raw in [('stdout',stdout),('stderr',stderr)]:
        for line in raw.splitlines():
            if not line.strip():continue
            try:text=line.decode('utf-8')
            except UnicodeDecodeError:text=''
            match=re.fullmatch(r'([^:]+): ([0-9]+) total files, ([0-9]+) altered files?',text)
            if match and match[1]in packages:summaries+=1;altered+=int(match[3]);continue
            clean=text.removeprefix('warning: ');match=re.fullmatch(r'([^:]+): (/.+) \(([^()]*)\)',clean);item=None;category=None
            if match and(match[1],match[2])in index and match[3]in CATEGORIES:item=index[(match[1],match[2])];category=CATEGORIES[match[3]]
            missing=re.fullmatch(r'([^:]+): no mtree file',clean)
            if missing and missing[1]in packages:
                item=next((v for(k,p),v in index.items()if k==missing[1]and p.startswith('/var/lib/pacman/local/')and p.endswith('/mtree')),None);category='missing-mtree'
            if item is not None:
                warning_count+=1
                if len(warnings)<64:warnings.append({'package':item['package'],'path':item['path'],'category':category,'expected_archive':item['archive'],'expected_mtree':item['mtree'],'actual':observe(item['path'],root,deadline)})
                continue
            unknown_count+=1
            if len(unknown)<32:unknown.append({'stream':stream,'bytes':len(line),'sha256':hashlib.sha256(line).hexdigest()})
    return {'exit':exit,'warning_count':warning_count,'unknown_count':unknown_count,'summary_count':summaries,'altered_file_count':altered,'warnings':warnings,'unknown':unknown,'truncated_warning_count':warning_count-len(warnings),'truncated_unknown_count':unknown_count-len(unknown),'HOLD':exit!=0 or warning_count>0 or unknown_count>0 or altered>0}

def persist(writer,value):
    for i,row in enumerate(value['warnings']):writer.write('ownership-warning-'+str(i).zfill(3)+'.json',{'schema_version':1,'nonce':writer.nonce,'stage':writer.stage,**row})
    for i,row in enumerate(value['unknown']):writer.write('ownership-unknown-'+str(i).zfill(3)+'.json',{'schema_version':1,'nonce':writer.nonce,'stage':writer.stage,**row})
    summary={k:v for k,v in value.items()if k not in ['warnings','unknown']};writer.write('ownership-summary.json',{'schema_version':1,'nonce':writer.nonce,'stage':writer.stage,**summary})

def _syncfs(fd):
    libc=ctypes.CDLL(None,use_errno=True);function=libc.syncfs;function.argtypes=[ctypes.c_int];function.restype=ctypes.c_int
    if function(fd)!=0:raise OSError(ctypes.get_errno(),'owned-filesystem-syncfs-refusal')

def sync_filesystem(root=Path('/'),primitive=None):
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:(_syncfs if primitive is None else primitive)(fd)
    finally:os.close(fd)

def signal_after_sync(sync,signal):
    sync();signal()
