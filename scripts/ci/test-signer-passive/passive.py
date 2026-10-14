# SPDX-License-Identifier: MIT
"""Passive compiler/header candidates only; no execution or admission API."""
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import struct
import time

FIELDS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SEARCH = ('/usr/lib/aarch64-linux-gnu','/usr/lib','/lib/aarch64-linux-gnu','/lib')
REUSED_SOURCE_SHA256 = '98ee7bb0c1788e465a5d8e709aef766768466d968b7fe68b888bbb9a1b8181a2'


class Refusal(Exception):
    pass


class Cancelled(BaseException):
    pass


def need(value, code):
    if not value: raise Refusal(code)


def live(end):
    need(type(end) in (int,float) and math.isfinite(end) and time.monotonic()<end,'deadline')


def identity(info):
    return [getattr(info,k) for k in FIELDS]


def inventory_diagnostic(requested,canonical,directory,node,row,endpoint):
    """Bounded facts from the already-observed no-follow inventory row."""
    import json
    live(endpoint)
    paths=[str(p) for p in (requested,canonical,directory,node)]
    for text in paths:
        need(str(Path(text))==text,'inventory-diagnostic-path');path_ok(Path(text))
    need(Path(paths[3]).parent==Path(paths[2]) and
         (paths[2]==paths[1] or Path(paths[1]) in Path(paths[2]).parents),
         'inventory-diagnostic-containment')
    values=identity(row)
    need(all(type(v) is int and v>=0 for v in values),'inventory-diagnostic-identity')
    mode=row.st_mode
    kind=('directory' if stat.S_ISDIR(mode) else 'regular' if stat.S_ISREG(mode)
          else 'symlink' if stat.S_ISLNK(mode) else 'other')
    terms=[term for term,failed in (('uid',row.st_uid!=0),('gid',row.st_gid!=0),
           ('write-bits',not stat.S_ISLNK(mode) and bool(mode&0o022))) if failed]
    need(bool(terms),'inventory-diagnostic-terms')
    facts=dict(schema_version=1,purpose='SIGNER_PASSIVE_INVENTORY_DIAGNOSTIC_V1',
               request_path=paths[0],canonical=paths[1],directory_path=paths[2],
               node_path=paths[3],identity=values,node_kind=kind,failed_terms=terms)
    need(len(json.dumps(facts,sort_keys=True,separators=(',',':')).encode('ascii'))<=8192,
         'inventory-diagnostic-size')
    live(endpoint)
    return facts


def path_ok(path):
    text=str(path)
    need(path.is_absolute() and len(text)<=1024 and len(path.parts)<=32
        and '..' not in path.parts and all(32<=ord(c)<127 for c in text),'path')
    need(text=='/' or text=='/usr' or any(text==root or text.startswith(root+'/') for root in ('/usr/bin','/usr/lib','/usr/libexec','/usr/include','/lib')),'path-scope')


class NativeIO:
    """Bounded root-only path observations; never execute or load a tool."""
    def __init__(self):self.nodes=0;self.bytes_read=0
    def charge(self,end):
        live(end);self.nodes+=1;need(self.nodes<=65536,'node-limit')
    def metadata(self,path,end):
        self.charge(end);return path.lstat()
    def resolve(self,path,end):
        path=Path(path);path_ok(path);aliases=[];parents={}
        for turn in range(17):
            current=Path('/');changed=False
            for part in path.parts[1:]:
                parent=self.metadata(current,end)
                need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==parent.st_gid==0
                    and not parent.st_mode & 0o022,'ancestor')
                key=str(current);value=identity(parent)
                need(key not in parents or parents[key]==value,'ancestor-drift');parents[key]=value
                current=current/part;info=self.metadata(current,end)
                if stat.S_ISLNK(info.st_mode):
                    need(info.st_uid==info.st_gid==0 and info.st_nlink==1 and 0<info.st_size<=256,'alias')
                    target=os.readlink(current);need(type(target) is str and len(target)<=256
                        and '..' not in Path(target).parts,'alias')
                    need(identity(info)==identity(self.metadata(current,end)),'alias-drift')
                    tail=path.relative_to(current).parts
                    expanded=(Path(target) if target.startswith('/') else current.parent/target).joinpath(*tail)
                    aliases.append({'path':str(current),'target':target,'identity':identity(info)})
                    path=Path(os.path.normpath(expanded));path_ok(path);changed=True;break
            if not changed:return current,aliases,[{'path':p,'identity':v} for p,v in sorted(parents.items())]
        raise Refusal('alias-limit')
    def sample(self,path,end):
        try:canonical,aliases,ancestors=self.resolve(path,end)
        except FileNotFoundError:return None
        before=self.metadata(canonical,end)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
            and stat.S_IMODE(before.st_mode) in (0o644,0o755) and 0<before.st_size<=64*1024**2,'file')
        handles=[];held=[];error=None;result=None
        try:
            for item in ancestors:
                parent=Path(item['path']);info=self.metadata(parent,end)
                need(item['identity']==identity(info),'ancestor-drift')
                parentfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
                handles.append(parentfd);held.append((parent,parentfd,item['identity']))
                need(item['identity']==identity(os.fstat(parentfd)),'ancestor-open-drift')
            fd=os.open(canonical,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);handles.append(fd)
            opened=os.fstat(fd);need(identity(before)==identity(opened),'open-drift')
            body=bytearray()
            while chunk:=os.read(fd,min(65536,before.st_size+1-len(body))):
                live(end);self.bytes_read+=len(chunk);need(self.bytes_read<=512*1024**2,'read-work-limit')
                body.extend(chunk);need(len(body)<=before.st_size,'file-limit')
            need(len(body)==before.st_size and identity(before)==identity(os.fstat(fd))
                ==identity(self.metadata(canonical,end)),'file-drift')
            for parent,parentfd,expected in held:
                need(expected==identity(os.fstat(parentfd))==identity(self.metadata(parent,end)),'ancestor-drift')
            for item in aliases:
                need(item['identity']==identity(self.metadata(Path(item['path']),end))
                    and os.readlink(item['path'])==item['target'],'alias-drift')
            raw=bytes(body)
            result={'canonical':str(canonical),'body':raw,'row':{'bytes':len(raw),'mode':stat.S_IMODE(before.st_mode),
                'sha256':hashlib.sha256(raw).hexdigest()},'identity':identity(before),'aliases':aliases,'ancestors':ancestors}
        except BaseException as fault:error=fault
        finally:
            for handle in reversed(handles):
                try:os.close(handle)
                except BaseException as fault:
                    cancel=lambda e:isinstance(e,(KeyboardInterrupt,Cancelled))
                    if error is None or (cancel(fault) and not cancel(error)):error=fault
        if error is not None:raise error
        return result


def elf_dependencies(raw):
    """Finite ELF64 linkage declarations; dynamic search overrides are refused."""
    need(raw[:6]==b'\x7fELF\x02\x01','elf-ident')
    need(len(raw)>=64,'elf-header-size')
    header=struct.unpack_from('<HHIQQQIHHHHHH',raw,16)
    need(header[1]==183,'elf-machine')
    need(header[8]==56,'elf-phentsize')
    need(0<header[9]<=128,'elf-phnum')
    loads=[];dynamic=None;interpreter=None
    for i in range(header[9]):
        offset=header[4]+i*56;need(offset+56<=len(raw),'elf-phdr-bounds')
        kind,flags,pos,address,physical,size,memory,align=struct.unpack_from('<IIQQQQQQ',raw,offset)
        need(pos+size<=len(raw),'elf-segment-bounds')
        if kind==1:loads.append((address,pos,size))
        if kind==2:dynamic=(pos,size)
        if kind==3:
            body=raw[pos:pos+size];need(body.endswith(b'\0'),'elf-interpreter-termination')
            need(b'\0' not in body[:-1],'elf-interpreter-interior-nul')
            interpreter=body[:-1].decode('ascii')
    wanted=[];table=None;length=None
    if dynamic:
        need(dynamic[1]<=65536,'elf-deps-dynamic-size')
        need(dynamic[1]%16==0,'elf-dynamic-stride')
        for pos in range(dynamic[0],dynamic[0]+dynamic[1],16):
            tag,value=struct.unpack_from('<qQ',raw,pos)
            if tag==0:break
            if tag==1:wanted.append(value)
            elif tag==5:table=value
            elif tag==10:length=value
            elif tag in (15,29):raise ValueError('signer-tool-search-override')
        need(len(wanted)<=32,'elf-needed-count')
        need(table is not None,'elf-strtab-missing')
        need(length is not None,'elf-strsz-missing')
        need(length<=2*1024**2,'elf-strtab-cap')
    names=[]
    if wanted:
        matches=[pos+table-address for address,pos,size in loads if address<=table and table+length<=address+size]
        need(len(matches)==1,'elf-strtab-load-match');start=matches[0]
        for index in wanted:
            need(index<length,'elf-needed-offset')
            stop=raw.find(b'\0',start+index,start+length)
            need(stop!=-1,'elf-needed-termination')
            name=raw[start+index:stop].decode('ascii')
            need(re.fullmatch('[A-Za-z0-9_.+-]{1,128}',name),'elf-needed-name');names.append(name)
    return interpreter,names


def linkage(raw):
    need(type(raw) is bytes,'elf-input-type')
    need(len(raw)>=64,'elf-header-size')
    header=struct.unpack_from('<HHIQQQIHHHHHH',raw,16)
    need(raw[:6]==b'\x7fELF\x02\x01','elf-ident')
    need(header[1]==183,'elf-machine')
    need(header[8]==56,'elf-phentsize')
    need(0<header[9]<=128,'elf-phnum')
    dynamic=[];interpreter=[]
    for index in range(header[9]):
        offset=header[4]+index*56;need(offset+56<=len(raw),'elf-phdr-bounds')
        kind,flags,pos,address,physical,size,memory,align=struct.unpack_from('<IIQQQQQQ',raw,offset)
        need(pos+size<=len(raw),'elf-segment-bounds')
        if kind==2:dynamic.append((pos,size))
        if kind==3:interpreter.append((pos,size))
    need(len(dynamic)<=1,'elf-dynamic-segment-count')
    need(len(interpreter)<=1,'elf-interpreter-segment-count')
    if interpreter:need(1<interpreter[0][1]<=1024,'elf-interpreter-size')
    if dynamic:
        pos,size=dynamic[0];need(0<size<=65536,'elf-dynamic-size')
        need(size%16==0,'elf-dynamic-stride')
        tags=[];terminated=False
        for offset in range(pos,pos+size,16):
            tag,value=struct.unpack_from('<qQ',raw,offset)
            if tag==0:terminated=True;break
            tags.append(tag)
        need(terminated,'elf-dynamic-unterminated')
        need(tags.count(5)==1,'elf-strtab-tag-count')
        need(tags.count(10)==1,'elf-strsz-tag-count')
    result=elf_dependencies(raw)
    need(len(result[1])==len(set(result[1])),'elf-needed-duplicate')
    return result


def elf_diagnostic(raw,request_path,item,endpoint):
    """Bounded facts from this sampled byte buffer only; no I/O or admission."""
    import json
    live(endpoint);path_ok(Path(request_path));path_ok(Path(item['canonical']))
    need(type(raw) is bytes and 0<len(raw)<=64*1024**2,'diagnostic-raw-bound')
    row=item['row'];meta=item['identity']
    need(type(row) is dict and set(row)=={'bytes','mode','sha256'} and row['bytes']==len(raw)
         and row['mode'] in (0o644,0o755) and type(row['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(meta) is list and len(meta)==9
         and all(type(n) is int and 0<=n<2**64 for n in meta) and
         meta[2]==stat.S_IFREG|row['mode'] and meta[3]==meta[4]==0 and meta[5]==1
         and meta[6]==len(raw),'diagnostic-sample-binding')
    facts=dict(schema_version=1,purpose='SIGNER_PASSIVE_ELF_DIAGNOSTIC_V1',request_path=request_path,
        canonical=item['canonical'],row=dict(row),identity=list(meta),
        header_hex=raw[:64].hex() if raw[:4]==b'\x7fELF' else None,header=None,
        phdr_count=None,phdrs_scanned=0,phdrs_truncated=False,phdr_bounds_ok=None,segments=[],dynamic=None)
    if raw[:6]==b'\x7fELF\x02\x01' and len(raw)>=64:
        names=('e_type','e_machine','e_version','e_entry','e_phoff','e_shoff','e_flags','e_ehsize',
               'e_phentsize','e_phnum','e_shentsize','e_shnum','e_shstrndx')
        header=dict(zip(names,struct.unpack_from('<HHIQQQIHHHHHH',raw,16)))
        facts['header']=header;count=header['e_phnum'];facts['phdr_count']=count
        facts['phdrs_truncated']=count>0;loads=[];dynamics=[]
        if header['e_phentsize']==56:
            start=header['e_phoff'];facts['phdr_bounds_ok']=start+count*56<=len(raw)
            available=max(0,len(raw)-start)//56
            for index in range(min(count,128,available)):
                live(endpoint)
                fields=struct.unpack_from('<IIQQQQQQ',raw,start+index*56)
                kind,flags,pos,address,physical,size,memory,align=fields
                if index<16:
                    facts['segments'].append(dict(index=index,p_type=kind,p_flags=flags,p_offset=pos,
                        p_vaddr=address,p_paddr=physical,p_filesz=size,p_memsz=memory,p_align=align))
                if kind==1:loads.append((address,pos,size))
                if kind==2:dynamics.append((pos,size))
                facts['phdrs_scanned']+=1
            facts['phdrs_truncated']=count!=len(facts['segments'])
            if dynamics:
                pos,size=dynamics[0]
                metrics=dict(segment_count=len(dynamics),bytes=size,tags_scanned=0,terminated=False,
                    needed_count=0,strtab_address=None,strtab_bytes=None,strtab_count=0,strsz_count=0,
                    load_match_count=None,truncated=False,bounds_ok=pos+size<=len(raw),search_override=False)
                available=max(0,len(raw)-pos)//16
                for index in range(min(4096,size//16,available)):
                    live(endpoint);tag,value=struct.unpack_from('<qQ',raw,pos+index*16)
                    metrics['tags_scanned']+=1
                    if tag==0:metrics['terminated']=True;break
                    if tag==1:metrics['needed_count']+=1
                    elif tag==5:metrics['strtab_address']=value;metrics['strtab_count']+=1
                    elif tag==10:metrics['strtab_bytes']=value;metrics['strsz_count']+=1
                    elif tag in (15,29):metrics['search_override']=True
                table,length=metrics['strtab_address'],metrics['strtab_bytes']
                if table is not None and length is not None:
                    metrics['load_match_count']=sum(address<=table and table+length<=address+length_in_file
                        for address,offset,length_in_file in loads)
                metrics['truncated']=(len(dynamics)>1 or count>facts['phdrs_scanned'] or
                    not metrics['bounds_ok'] or size%16!=0 or
                    not metrics['terminated'] and metrics['tags_scanned']<size//16)
                facts['dynamic']=metrics
    live(endpoint)
    encoded=json.dumps(facts,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    while len(encoded)>8192 and facts['segments']:
        live(endpoint);facts['segments'].pop();facts['phdrs_truncated']=True
        encoded=json.dumps(facts,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(len(encoded)<=8192,'diagnostic-output-bound');live(endpoint)
    return facts


class PassiveIO(NativeIO):
    def gcc_directories(self,end):
        return self._gcc_version_directories('/usr/lib/gcc/aarch64-linux-gnu',end)

    def gcc_helper_directories(self,end):
        return self._gcc_version_directories('/usr/libexec/gcc/aarch64-linux-gnu',end,optional=True)

    def _gcc_version_directories(self,root,end,*,optional=False):
        """Shallow held snapshot for exactly the two fixed GCC layout roots."""
        need(root in ('/usr/lib/gcc/aarch64-linux-gnu','/usr/libexec/gcc/aarch64-linux-gnu'),
             'gcc-layout-fixed-root')
        requested=Path(root)
        try:canonical,aliases,ancestors=self.resolve(requested,end)
        except FileNotFoundError:
            if optional:return None
            raise
        need(canonical==requested,'gcc-discovery-canonical')
        before=self.metadata(canonical,end)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
             and not before.st_mode&0o022,'gcc-discovery-root')
        handles=[];held_ancestors=[];children=[];error=None;result=None
        def hold(path,expected,*,parentfd=None,name=None):
            self.charge(end)
            fd=os.open(path if parentfd is None else name,
                       os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,
                       **({} if parentfd is None else {'dir_fd':parentfd}))
            handles.append((fd,path,expected,parentfd,name))
            need(identity(os.fstat(fd))==expected,'gcc-discovery-open-drift')
            return fd
        try:
            for item in ancestors:
                path=Path(item['path'])
                fd=hold(path,item['identity'])
                held_ancestors.append((path,fd,item['identity']))
            expected=identity(before);rootfd=hold(canonical,expected)
            self.charge(end);names=os.listdir(rootfd)
            need(len(names)<=32 and len(names)==len(set(names)) and all(type(name) is str and
                 re.fullmatch(r'[1-9][0-9]{0,2}(?:\.[0-9]{1,3}){0,2}',name) for name in names),
                 'gcc-discovery-version-names')
            names=sorted(names)
            for name in names:
                path=canonical/name;path_ok(path);self.charge(end)
                info=os.stat(name,dir_fd=rootfd,follow_symlinks=False)
                need(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0
                     and not info.st_mode&0o022,'gcc-discovery-version-directory')
                child_identity=identity(info)
                fd=hold(path,child_identity,parentfd=rootfd,name=name)
                children.append((path,fd,child_identity,name))
            self.charge(end)
            need(names==sorted(os.listdir(rootfd)) and expected==identity(os.fstat(rootfd))
                 ==identity(self.metadata(canonical,end)),'gcc-discovery-root-drift')
            for path,fd,child_identity,name in children:
                self.charge(end)
                need(child_identity==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=rootfd,
                     follow_symlinks=False)),'gcc-discovery-version-drift')
            for path,fd,ancestor_identity in held_ancestors:
                need(ancestor_identity==identity(os.fstat(fd))==identity(self.metadata(path,end)),
                     'gcc-discovery-ancestor-drift')
            for item in aliases:
                need(item['identity']==identity(self.metadata(Path(item['path']),end)) and
                     os.readlink(item['path'])==item['target'],'gcc-discovery-alias-drift')
            result={'canonical':str(canonical),'aliases':aliases,'ancestors':ancestors,'identity':expected,
                    'directories':[{'path':str(path),'identity':child_identity}
                                   for path,fd,child_identity,name in children]}
            live(end)
        except BaseException as fault:error=fault
        finally:
            for fd,path,expected,parentfd,name in reversed(handles):
                try:
                    # Cleanup still attempts held ownership after deadline; no
                    # late observation can be accepted. Never retry an FD number.
                    named=os.stat(path if parentfd is None else name,
                                  follow_symlinks=False,**({} if parentfd is None else {'dir_fd':parentfd}))
                    need(expected==identity(os.fstat(fd))==identity(named),'gcc-discovery-close-drift')
                    os.close(fd);live(end)
                except BaseException as fault:
                    cancel=lambda e:isinstance(e,(KeyboardInterrupt,Cancelled))
                    if error is None or (cancel(fault) and not cancel(error)):error=fault
        if error is not None:raise error
        live(end)
        return result

    def inventory(self, requested, end):
        """Held root-owned directory tree; never follow interior directory aliases."""
        try:canonical, aliases, ancestors = self.resolve(requested, end)
        except FileNotFoundError:return None
        before = self.metadata(canonical, end)
        need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
             and not before.st_mode&0o022, 'inventory-directory')
        handles=[]; held_ancestors=[]; directory_names={}; directories=[]; entries=[]; error=None; result=None
        def hold(path, expected, *, parentfd=None, name=None):
            self.charge(end)
            fd=os.open(path if parentfd is None else name,
                       os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,
                       **({} if parentfd is None else {'dir_fd':parentfd}))
            handles.append(fd)
            need(identity(os.fstat(fd))==expected,'inventory-open-drift')
            return fd
        try:
            for item in ancestors:
                fd=hold(Path(item['path']),item['identity'])
                held_ancestors.append((Path(item['path']),fd,item['identity']))
            rootfd=hold(canonical,identity(before))
            queue=[(canonical,rootfd,identity(before))]; at=0
            while at<len(queue):
                path,fd,expected=queue[at];at+=1
                self.charge(end)
                names=os.listdir(fd)
                need(len(names)<=8192 and len(entries)+len(names)<=8192,'inventory-count')
                need(len(names)==len(set(names)) and all(type(n) is str and n not in ('.','..')
                     and '/' not in n and 0<len(n)<=255 and all(32<=ord(c)<127 for c in n)
                     for n in names),'inventory-names')
                names=sorted(names);directory_names[str(path)]=names
                for name in names:
                    child=path/name;path_ok(child);self.charge(end)
                    row=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    try:
                        need(row.st_uid==row.st_gid==0 and
                             (stat.S_ISLNK(row.st_mode) or not row.st_mode&0o022),'inventory-owner')
                    except Refusal as fault:
                        diagnostic=None;diagnostic_cancelled=False
                        try:diagnostic=inventory_diagnostic(requested,canonical,path,child,row,end)
                        except BaseException as problem:
                            diagnostic_cancelled=isinstance(problem,(KeyboardInterrupt,Cancelled))
                        try:
                            fault.inventory_diagnostic=diagnostic
                            fault.inventory_diagnostic_cancelled=diagnostic_cancelled
                        except BaseException as problem:
                            if isinstance(problem,(KeyboardInterrupt,Cancelled)):
                                try:fault.inventory_diagnostic_cancelled=True
                                except BaseException:pass
                        raise
                    node={'path':str(child),'identity':identity(row)};entries.append(node)
                    if stat.S_ISDIR(row.st_mode):
                        need(len(queue)<1024,'inventory-directory-count')
                        childfd=hold(child,identity(row),parentfd=fd,name=name)
                        queue.append((child,childfd,identity(row)))
                    else:need(stat.S_ISREG(row.st_mode) or stat.S_ISLNK(row.st_mode),'inventory-leaf-kind')
                self.charge(end)
                need(names==sorted(os.listdir(fd)) and expected==identity(os.fstat(fd))
                     ==identity(self.metadata(path,end)),'inventory-directory-drift')
                directories.append({'path':str(path),'identity':expected,'names':names})
            for path,fd,expected in queue:
                self.charge(end)
                need(expected==identity(os.fstat(fd))==identity(self.metadata(path,end))
                     and directory_names[str(path)]==sorted(os.listdir(fd)),
                     'inventory-directory-drift')
            for path,fd,expected in held_ancestors:
                need(expected==identity(os.fstat(fd))==identity(self.metadata(path,end)),
                     'inventory-ancestor-drift')
            for item in aliases:
                need(item['identity']==identity(self.metadata(Path(item['path']),end))
                     and os.readlink(item['path'])==item['target'],'inventory-alias-drift')
            leaves=[item['path'] for item in entries if not stat.S_ISDIR(item['identity'][2])]
            result={'canonical':str(canonical),'aliases':aliases,'ancestors':ancestors,
                    'directories':directories,'entries':entries,'leaves':sorted(leaves)}
            live(end)
        except BaseException as fault:error=fault
        finally:
            for fd in reversed(handles):
                try:os.close(fd)
                except BaseException as fault:
                    if error is None:error=fault
                    elif isinstance(error,Refusal) and error.args==('inventory-owner',) and isinstance(fault,(KeyboardInterrupt,Cancelled)):
                        try:error.inventory_diagnostic_cancelled=True
                        except BaseException:pass
        if error is not None:raise error
        return result


def observe_candidate(io, *, gcc_directory, context, endpoint):
    """Return metadata candidates. Root selects tools and driver/loader policy later."""
    live(endpoint)
    need(type(gcc_directory) is str and gcc_directory=='CURRENT_DEFAULT_GCC','gcc-directory-policy')
    need(type(context) is dict and set(context)=={'source_commit','workflow_commit','run_id',
         'run_attempt','machine','uid'} and context['machine']=='aarch64'
         and type(context['uid']) is int and context['uid']>0
         and type(context['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',context['source_commit'])
         and context['workflow_commit']==context['source_commit']
         and type(context['run_id']) is str and re.fullmatch('[1-9][0-9]{0,19}',context['run_id'])
         and type(context['run_attempt']) is str and re.fullmatch('[1-9][0-9]{0,9}',context['run_attempt']),
         'observation-context')
    rows={}; observed={}; requests={}; inventories={}; roles={}; headers=set(); pending=[]; total=0
    def sample(path, kind, required=True):
        nonlocal total
        live(endpoint);path_ok(Path(path))
        need(len(requests)<16384 or path in requests,'request-count')
        if path in requests:
            item=requests[path]
            need(item is not None or not required,'missing-file')
            if item is not None:need(kind=='PLUGIN' or rows[item['canonical']]['kind']==kind,'row-kind-conflict')
            return item
        item=io.sample(path,endpoint)
        if item is None:
            need(not required,'missing-file');requests[path]=None;return None
        canonical=item['canonical'];path_ok(Path(canonical))
        raw=item['body'];row=item['row']
        if kind=='PLUGIN':kind='ELF' if raw[:4]==b'\x7fELF' else 'DATA'
        need(type(raw) is bytes and row=={'bytes':len(raw),'mode':row['mode'],
             'sha256':hashlib.sha256(raw).hexdigest()} and row['mode'] in (0o644,0o755)
             and 0<len(raw)<=64*1024**2,'candidate-row')
        if canonical in rows:
            need(rows[canonical]=={**row,'kind':kind} and observed[canonical]['identity']==item['identity'],
                 'canonical-drift')
        else:
            need(len(rows)<8192,'row-count');total+=len(raw);need(total<=256*1024**2,'body-total')
            rows[canonical]={**row,'kind':kind}
            observed[canonical]={k:v for k,v in item.items() if k!='body'}
            if kind=='ELF':
                try:interpreter,needed=linkage(raw)
                except BaseException as error:
                    diagnostic=None;diagnostic_cancelled=isinstance(error,(KeyboardInterrupt,Cancelled))
                    try:diagnostic=elf_diagnostic(raw,path,item,endpoint)
                    except BaseException as problem:
                        diagnostic_cancelled|=isinstance(problem,(KeyboardInterrupt,Cancelled))
                    # Built-in parser errors have an owned attribute dictionary;
                    # metadata failure cannot replace their original exception.
                    try:
                        error.elf_diagnostic_cancelled=diagnostic_cancelled
                        error.elf_diagnostic=diagnostic
                    except BaseException as problem:
                        if isinstance(problem,(KeyboardInterrupt,Cancelled)):
                            try:error.elf_diagnostic_cancelled=True
                            except BaseException:pass
                    raise
                observed[canonical].update(interpreter=interpreter,needed=needed,resolved={})
                pending.append(canonical)
            elif kind=='HEADER':headers.add(canonical)
        safe={k:v for k,v in item.items() if k!='body'};requests[path]=safe
        return safe
    live(endpoint);gcc_discovery=io.gcc_directories(endpoint)
    live(endpoint);helper_discovery=io.gcc_helper_directories(endpoint)
    root='/usr/lib/gcc/aarch64-linux-gnu';helper_root='/usr/libexec/gcc/aarch64-linux-gnu'
    def discovery_paths(snapshot,expected_root):
        need(type(snapshot) is dict and set(snapshot)=={'canonical','aliases','ancestors','identity',
             'directories'} and snapshot['canonical']==expected_root and type(snapshot['directories']) is list
             and len(snapshot['directories'])<=32 and type(snapshot['aliases']) is list
             and type(snapshot['ancestors']) is list,'gcc-discovery-shape')
        paths=[]
        for item in [{'path':expected_root,'identity':snapshot['identity']}]+snapshot['directories']:
            need(type(item) is dict and set(item)=={'path','identity'} and type(item['path']) is str and
                 type(item['identity']) is list and len(item['identity'])==len(FIELDS) and
                 all(type(value) is int for value in item['identity']) and stat.S_ISDIR(item['identity'][2])
                 and item['identity'][3]==item['identity'][4]==0 and not item['identity'][2]&0o022,
                 'gcc-discovery-directory-row')
            if item['path']!=expected_root:
                need(str(Path(item['path']))==item['path'] and Path(item['path']).parent==Path(expected_root)
                     and re.fullmatch(r'[1-9][0-9]{0,2}(?:\.[0-9]{1,3}){0,2}',Path(item['path']).name),
                     'gcc-discovery-version-path')
                paths.append(item['path'])
        need(paths==sorted(set(paths)) and len(paths)==len(snapshot['directories']),
             'gcc-discovery-complete-order')
        return paths
    paths=discovery_paths(gcc_discovery,root)
    helper_paths=[] if helper_discovery is None else discovery_paths(helper_discovery,helper_root)
    need(len(paths)+len(helper_paths)<=32,'gcc-layout-version-count')
    driver=sample('/usr/bin/gcc','ELF')
    match=re.fullmatch(r'/usr/bin/(?:aarch64-linux-gnu-)?gcc-([1-9][0-9]{0,2})',driver['canonical'])
    need(match is not None,'gcc-default-driver-version')
    major=match.group(1)
    matches=[path for path in paths if Path(path).name.split('.')[0]==major]
    need(len(matches)==1,'gcc-default-version-unique')
    gcc_directory=matches[0]
    helper_roots=sorted([gcc_directory]+[path for path in helper_paths if Path(path).name.split('.')[0]==major])
    def discovery_join(snapshot,directory,witnesses):
        chosen=next(item for item in snapshot['directories'] if item['path']==directory)
        for witness in snapshot['ancestors']+[{'path':snapshot['canonical'],'identity':snapshot['identity']},chosen]:
            need(type(witness) is dict and set(witness)=={'path','identity'},'gcc-discovery-ancestor-row')
            bound=[item for item in witnesses if item['path']==witness['path']]
            need(len(bound)==1 and bound[0]['identity']==witness['identity'],'gcc-layout-ancestor-binding')
    for role,path in {'gcc':'/usr/bin/gcc','as':'/usr/bin/as','ld':'/usr/bin/ld',
                      'readelf':'/usr/bin/readelf','objdump':'/usr/bin/objdump',
                      'python_candidate':'/usr/bin/python3'}.items():
        item=sample(path,'ELF');need(item['row']['mode']==0o755,'tool-mode');roles[role]=item['canonical']
    for role in ('cc1','cc1plus','collect2','lto-wrapper'):
        positives={}
        allowed={directory+'/'+role for directory in helper_roots}
        for directory in helper_roots:
            item=sample(directory+'/'+role,'ELF',False)
            if item is None:continue
            need(item['canonical'] in allowed and item['row']['mode']==0o755,'gcc-helper-canonical-path')
            positives[item['canonical']]=item
        need(len(positives)<=1 and (bool(positives) or role not in ('cc1','cc1plus')),
             'gcc-helper-'+role+'-ambiguous-or-missing')
        item=None if not positives else next(iter(positives.values()))
        roles[role]=None if item is None else item['canonical']
        if item is not None:
            directory=str(Path(item['canonical']).parent)
            snapshot=gcc_discovery if directory==gcc_directory else helper_discovery
            discovery_join(snapshot,directory,item['ancestors'])
    item=sample(gcc_directory+'/specs','DATA',False)
    roles['specs']=None if item is None else item['canonical']
    roots=[(gcc_directory+'/include','HEADER',True),(gcc_directory+'/include-fixed','HEADER',False),
           ('/usr/include/aarch64-linux-gnu/asm','HEADER',True),
           ('/usr/include/linux','HEADER',True),('/usr/include/asm-generic','HEADER',True),
           (gcc_directory+'/plugin','PLUGIN',False)]
    for path,kind,required in roots:
        live(endpoint);item=io.inventory(path,endpoint)
        need(item is not None or not required,'missing-inventory')
        if item is not None:
            leaves=item['leaves']
            need(type(leaves) is list and len(leaves)<=8192 and leaves==sorted(set(leaves)),
                 'inventory-leaves')
            for leaf in leaves:
                need(type(leaf) is str and Path(leaf).is_relative_to(Path(item['canonical'])),
                     'inventory-leaf-scope')
                sample(leaf,kind)
        if path==gcc_directory+'/include':
            discovery_join(gcc_discovery,gcc_directory,item['ancestors'])
        inventories[path]=item
    def resolve(name):
        matches={}
        for directory in SEARCH:
            item=sample(directory+'/'+name,'ELF',False)
            if item is not None:matches[item['canonical']]=item
        need(len(matches)==1,'dependency-ambiguous-or-missing')
        return next(iter(matches))
    index=0
    while index<len(pending):
        live(endpoint);name=pending[index];index+=1;item=observed[name]
        if item['interpreter']:
            item['resolved']['PT_INTERP']=sample(item['interpreter'],'ELF')['canonical']
        for needed in item['needed']:item['resolved'][needed]=resolve(needed)
    for name,item in requests.items():
        live(endpoint);fresh=io.sample(name,endpoint)
        if item is None:need(fresh is None,'negative-witness-drift')
        else:
            need(fresh is not None and {k:v for k,v in fresh.items() if k!='body'}==item
                 and hashlib.sha256(fresh['body']).hexdigest()==item['row']['sha256'],
                 'final-file-drift')
    for name,item in inventories.items():
        live(endpoint);need(io.inventory(name,endpoint)==item,'final-inventory-drift')
    live(endpoint);need(io.gcc_directories(endpoint)==gcc_discovery,'final-gcc-discovery-drift')
    live(endpoint);need(io.gcc_helper_directories(endpoint)==helper_discovery,'final-gcc-helper-discovery-drift')
    candidate={'schema_version':1,'purpose':'NATIVE_SIGNER_COMPILE_TOOLCHAIN_CANDIDATE_V1',
               'gcc_directory':gcc_directory,'gcc_discovery':gcc_discovery,'helper_discovery':helper_discovery,'roles':roles,'files':rows,'headers':sorted(headers),
               'inventories':inventories,'selected':False,'execution_grant_issued':False}
    evidence={'schema_version':1,'status':'OBSERVED_CANDIDATE_NOT_SELECTED','context':dict(context),
              'observations':observed,'requests':requests,'deadline_at':endpoint,'file_bytes':total,
              'executed_tools':False,'loaded_libraries':False,'compile_allowed':False,
              'driver_helper_specs_correspondence':'UNKNOWN','complete_header_include_correspondence':'UNKNOWN',
              'loader_cache_preload_dlopen_correspondence':'UNKNOWN',
              'privileged_tool_filecap_cgroup_migration_exclusion':'UNKNOWN',
              'inherited_sample_close_cancel_priority':'later cancellation can replace ordinary read fault',
              'source_reuse_sha256':REUSED_SOURCE_SHA256}
    # No publication here; Root inline entry must bind one terminal successful
    # outcome after finalization and invalidate any earlier stdout on late fault.
    import json
    raw=json.dumps({'candidate':candidate,'evidence':evidence},sort_keys=True,
                   separators=(',',':'),allow_nan=False).encode()
    need(len(raw)<=4*1024**2,'candidate-output-budget');live(endpoint)
    return {'candidate':candidate,'evidence':evidence}
