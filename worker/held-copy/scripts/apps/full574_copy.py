# SPDX-License-Identifier: MIT
"""Apps-only proof for the owner's same-device /seed and /work bind mounts."""
import hashlib,os,re,stat,types
from pathlib import Path,PurePosixPath
import aux_copy
import full_root as roots

SOURCE=Path('/seed');WORK=Path('/work')
ANCHOR=b"        need(src_info.st_dev!=parent_info.st_dev or src_mount==parent_mount,'ambiguous copy bind scope')"
REPLACEMENT=b'        _apps_scope(src,parent,source,target.parent,src_mount,parent_mount,limits)'
need=aux_copy.aux.need

def _mountinfo(limits):
    limits.tick()
    with Path('/proc/self/mountinfo').open('rb') as stream:raw=stream.read(4*1024**2+1)
    need(len(raw)<=4*1024**2,'Apps mount inventory byte bound')
    return raw

def _path(raw):
    need(raw and len(raw)<=4096 and all(32<c<127 for c in raw) and b'\\' not in raw,'Apps mount path encoding')
    value=PurePosixPath(raw.decode('ascii'))
    need(value.is_absolute() and value.as_posix().encode()==raw and '..' not in value.parts,'Apps canonical mount path')
    return value

def _rows(raw,source_mount,work_mount,device):
    lines=raw.splitlines();need(0<len(lines)<=32768,'Apps mount inventory row bound')
    rows={};points=[]
    for line in lines:
        fields=line.split();need(len(fields)>=10 and len(line)<=16384 and fields[0].isdigit() and int(fields[0])>0,'Apps mount inventory row')
        identity=int(fields[0]);need(identity not in rows,'Apps duplicate mount identity');rows[identity]=fields
        if fields[4] in (bytes(SOURCE),bytes(WORK)) or fields[4].startswith((bytes(SOURCE)+b'/',bytes(WORK)+b'/')):points.append(fields[4])
    need(points.count(bytes(SOURCE))==points.count(bytes(WORK))==1 and len(points)==2,'Apps exact unshadowed bind mounts required')
    selected=[]
    for identity,point,access in ((source_mount,SOURCE,b'ro'),(work_mount,WORK,b'rw')):
        fields=rows.get(identity,[])
        need(fields and fields.count(b'-')==1,'Apps current descriptor mount row required')
        separator=fields.index(b'-');need(separator>=6 and len(fields)==separator+4,'Apps mount row fields')
        need(fields[1].isdigit() and int(fields[1])>0 and re.fullmatch(rb'[0-9]+:[0-9]+',fields[2]) and
             tuple(map(int,fields[2].split(b':')))==device and fields[4]==bytes(point),'Apps descriptor device/mountpoint differs')
        flags=fields[5].split(b',');need(access in flags and ({b'ro',b'rw'}-{access}).isdisjoint(flags),'Apps source readonly/work writable required')
        root=_path(fields[3]);_path(fields[4])
        selected.append(dict(mount_id=identity,device=list(device),root=str(root),point=str(point),row_sha256=hashlib.sha256(b' '.join(fields)).hexdigest()))
    a,b=(PurePosixPath(r['root']) for r in selected)
    need(not a.is_relative_to(b) and not b.is_relative_to(a),'Apps backing bind roots overlap')
    # Same device and filesystem/source; never equate or normalize mount IDs.
    left,right=(rows[n] for n in (source_mount,work_mount))
    need(source_mount!=work_mount and left[left.index(b'-')+1:left.index(b'-')+3]==right[right.index(b'-')+1:right.index(b'-')+3], 'Apps distinct bind views of one filesystem required')
    return selected

def _stable(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid]

class Scope:
    def __init__(self,held):self.held=held;self.before=None;self.checks=0
    def start(self,src,parent,source,destination,src_mount,parent_mount,limits):
        need(self.before is None and source==SOURCE and destination in (WORK/'main',WORK/'interrupted'),'Apps fixed leased copy locations required')
        self.source,self.destination,self.limits=source,destination,limits
        self.src=os.dup(src);self.held.append(self.src)
        self.parent=os.dup(parent);self.held.append(self.parent)
        self.mounts=src_mount,parent_mount
        self.before=self.read();self.checks=1
    def read(self):
        limits=self.limits;limits.tick()
        source,parent=os.fstat(self.src),os.fstat(self.parent)
        need(source.st_dev==parent.st_dev and (source.st_dev,source.st_ino)!=(parent.st_dev,parent.st_ino),'Apps same-device distinct bind directories required')
        need(source.st_uid==parent.st_uid==os.geteuid() and not stat.S_IMODE(parent.st_mode)&0o022,'Apps owned private copy directories required')
        need(os.fstatvfs(self.src).f_flag&os.ST_RDONLY and not os.fstatvfs(self.parent).f_flag&os.ST_RDONLY,'Apps readonly source/writable copy mount required')
        with aux_copy.measure_copy._descriptors() as opened:
            for path,held in ((self.source,self.src),(self.destination,self.parent)):
                fd=roots._open_root(path);opened.append(fd)
                need(roots._identity(os.fstat(fd))==roots._identity(os.fstat(held)),'Apps named/held copy root differs')
                need(roots._mount_id(fd,limits)==roots._mount_id(held,limits)==self.mounts[0 if held==self.src else 1],'Apps copy root mount drift')
            work=roots._open_root(WORK);opened.append(work);work_info=os.fstat(work)
            need(roots._mount_id(work,limits)==self.mounts[1] and work_info.st_dev==parent.st_dev and work_info.st_uid==os.geteuid() and not stat.S_IMODE(work_info.st_mode)&0o022,'Apps exact owned work mount required')
            rows=_rows(_mountinfo(limits),*self.mounts,(os.major(source.st_dev),os.minor(source.st_dev)))
            value=dict(status='PROVED_DISJOINT_READONLY_SOURCE_AND_OWNED_WORK_BIND_ROOTS',source=str(self.source),destination_parent=str(self.destination),mounts=rows,source_identity=list(roots._identity(source)),parent_identity=_stable(parent),work_identity=_stable(work_info))
        return value
    def check(self):
        need(self.before is not None and self.read()==self.before,'Apps copy mount scope changed');self.checks+=1

def copy_data(source,target,*,limits,hardlinks='generic-development-internal'):
    """The unchanged selected copier, except one byte-bound bind-scope predicate."""
    need(hardlinks=='generic-development-internal' and not limits.allow_cross_device,'complete-selected-copy-scope')
    module=aux_copy._copy_binding(limits)
    # Read with the existing nofollow, bounded, identity-checked exact-source pin.
    with aux_copy.measure_copy._descriptors() as held:
        original=Path(aux_copy.measure_copy.__file__)
        fd=os.open(original,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);held.append(fd);info=os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=512*1024,'Apps copier source shape')
        raw=os.read(fd,info.st_size+1)
        need(len(raw)==info.st_size and roots._identity(info)==roots._identity(os.fstat(fd))==roots._identity(original.lstat()) and hashlib.sha256(raw).hexdigest()==aux_copy.COPY_SHA256 and raw.count(ANCHOR)==1,'Apps exact original copier source required')
        changed=raw.replace(ANCHOR,REPLACEMENT)
        derived=types.ModuleType('_apps574_scoped_copy');derived.__file__=str(original)
        exec(compile(changed,str(original),'exec'),derived.__dict__)
        derived.roots=module.roots;derived._copy_report=module._copy_report
        scope=Scope(held);derived._apps_scope=scope.start
        check=derived._root_check
        def root_check(*args,**kwargs):
            check(*args,**kwargs);scope.check()
        derived._root_check=root_check
        report=derived.copy_data(source,target,limits=limits,hardlinks=hardlinks)
        scope.check()
        report.update(scope='complete-supplied-source-with-selected-links-and-held-auxiliary',copy_byte_identical_before_initialization=True,transaction_acceptance='NOT ESTABLISHED',apps_bind_scope=dict(proof=scope.before,checkpoints=scope.checks,original_copier_sha256=hashlib.sha256(raw).hexdigest(),adapted_copier_sha256=hashlib.sha256(changed).hexdigest()))
        return report
