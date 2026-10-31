#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite inert tree/archive correspondence. No image adapter or package execution."""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import hashlib
import json
import lzma
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tarfile
import time

MIB = 1024**2
ARCHIVE, COMPRESSED, DECODED, TOTAL_DECODED = 300_000_000, 2*1024**3, 1024**3, 8*1024**3
FILE, NODES, ARCHIVE_NODES, REPORT, SECONDS = 512*MIB, 500000, 100000, 256*MIB, 1200
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
CONTROL = {'.PKGINFO','.BUILDINFO','.MTREE','.INSTALL'}
HEX = re.compile(r'[0-9a-f]{64}\Z')


def need(value, reason):
    if not value: raise ValueError(reason)


def integer(value, maximum, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def identity(info):
    return [getattr(info,k) for k in FIELDS]


def path(value):
    need(type(value) is str and 0 < len(value) <= 4096 and
         not re.search(r'[\x00-\x1f\x7f]',value) and not value.startswith('/') and
         len(value.split('/'))<=64 and all(x not in ('','.','..') for x in value.split('/')), 'noncanonical-path')
    return value


def package_identity(row):
    need(type(row) is dict and set(row)=={'name','version','arch'}, 'package-identity')
    need(type(row['name']) is str and re.fullmatch(r'[a-z0-9][a-z0-9@+._-]*',row['name']) and
         type(row['version']) is str and 0<len(row['version'])<=256 and
         not re.search(r'[\s/\x00-\x1f\x7f]',row['version']) and type(row['arch']) is str and row['arch'] in ('any','aarch64'), 'package-identity')
    return row


class Budget:
    def __init__(self, deadline):
        need(type(deadline) in (int,float) and math.isfinite(deadline) and
             time.monotonic() < deadline <= time.monotonic()+SECONDS, 'deadline')
        self.end=deadline;self.decoded=self.nodes=self.tree_bytes=0
    def check(self): need(time.monotonic()<self.end,'deadline')
    def node(self):
        self.check();self.nodes+=1;need(self.nodes<=NODES,'node-bound')


def reference(row, maximum):
    need(type(row) is dict and set(row)=={'path','size','sha256','identity'},'reference-schema')
    need(type(row['path']) is str and Path(row['path']).is_absolute() and str(Path(row['path']))==row['path'] and '..' not in Path(row['path']).parts
         and integer(row['size'],maximum,1) and type(row['sha256']) is str and HEX.fullmatch(row['sha256'])
         and type(row['identity']) is list and len(row['identity'])==len(FIELDS)
         and all(integer(v,2**64-1) for v in row['identity']) and row['identity'][6]==row['size'], 'reference-pin')
    return row


def close_owned(fds):
    """Attempt every owned close before releasing cancellation; keep the first cause."""
    original=sys.exc_info()[1];failure=None;previous=None
    try:
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
    except BaseException as error:failure=error
    try:
        for fd in fds:
            if fd is None:continue
            try:os.close(fd)
            except BaseException as error:
                if failure is None:failure=error
    finally:
        if previous is not None:
            try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
            except BaseException as error:
                if failure is None:failure=error
    if original is None and failure is not None:raise failure


@contextmanager
def readable_at(parent, name, budget, expected=None, directory=False, single_link=True, reason='reference-identity'):
    """Validate a no-follow O_PATH inode before opening that owned inode readable."""
    binding=fd=None
    try:
        budget.check();binding=os.open(name,os.O_PATH|os.O_NOFOLLOW,dir_fd=parent);before=os.fstat(binding);budget.check()
        need((stat.S_ISDIR if directory else stat.S_ISREG)(before.st_mode),'ordinary-node')
        need(directory or not single_link or before.st_nlink==1,'reference-hardlink')
        if expected is not None:need(identity(before)==expected,reason)
        budget.check();fd=os.open('/proc/self/fd/'+str(binding),os.O_RDONLY|os.O_NONBLOCK|(os.O_DIRECTORY if directory else 0));budget.check()
        need(identity(os.fstat(fd))==identity(before),reason)
        yield fd,before
        budget.check();need(identity(before)==identity(os.fstat(fd))==identity(os.fstat(binding))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),'tree-node-drift' if reason=='tree-open-drift' else 'node-drift')
    finally:
        close_owned((fd,binding))


@contextmanager
def opened(value, budget, expected=None, directory=False):
    """Hold every ancestor; bind the opened and still-named node, never follow links."""
    value=Path(value);need(value.is_absolute() and '..' not in value.parts,'absolute-path')
    fds=[];ancestors=[]
    try:
        budget.check();fds.append(os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW));budget.check()
        for part in value.parts[1:-1]:
            budget.check();fds.append(os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]));budget.check();ancestors.append((len(fds)-2,part,os.fstat(fds[-1])))
        with readable_at(fds[-1],value.name,budget,expected,directory) as result:yield result
        for parent,name,old in ancestors:
            budget.check();now=os.stat(name,dir_fd=fds[parent],follow_symlinks=False);budget.check()
            need((old.st_dev,old.st_ino,old.st_mode)==(now.st_dev,now.st_ino,now.st_mode),'ancestor-drift')
    finally:
        close_owned(reversed(fds))


def hashed(fd, size, budget, account=False):
    h=hashlib.sha256();count=0
    while True:
        budget.check();b=os.read(fd,min(MIB,size-count+1));budget.check()
        if not b:break
        count+=len(b);need(count<=size,'byte-bound');h.update(b)
        if account:
            budget.tree_bytes+=len(b);need(budget.tree_bytes+budget.decoded<=TOTAL_DECODED,'combined-data-byte-bound')
    need(count==size,'byte-size');return h.hexdigest()


def read_reference(row, maximum, budget):
    reference(row,maximum)
    with opened(row['path'],budget,row['identity']) as (fd,_):
        data=bytearray()
        while True:
            budget.check();b=os.read(fd,min(MIB,row['size']-len(data)+1));budget.check()
            if not b:break
            data.extend(b);need(len(data)<=row['size'],'reference-byte-bound')
        need(len(data)==row['size'] and hashlib.sha256(data).hexdigest()==row['sha256'],'reference-digest')
        return bytes(data)


def decode(raw):
    def pairs(rows):
        out={}
        for k,v in rows: need(k not in out,'duplicate-json');out[k]=v
        return out
    def finite(value):
        need(math.isfinite(float(value)),'nonfinite-json');return float(value)
    return json.loads(raw,object_pairs_hook=pairs,parse_float=finite,
        parse_constant=lambda _:need(False,'nonfinite-json'))


class Counted:
    def __init__(self, stream, budget):
        self.stream,self.budget=stream,budget;self.count=0;self.end=min(budget.end,time.monotonic()+300)
    def read(self,n):
        need(integer(n,MIB),'decoded-read-bound');self.budget.check();need(time.monotonic()<self.end,'archive-deadline')
        need(self.budget.decoded+self.budget.tree_bytes<=TOTAL_DECODED,'combined-data-byte-bound')
        b=self.stream.read(min(n,DECODED-self.count+1,TOTAL_DECODED-self.budget.decoded-self.budget.tree_bytes+1))
        self.count+=len(b);self.budget.decoded+=len(b)
        need(self.count<=DECODED and self.budget.decoded<=TOTAL_DECODED,'decoded-bound')
        need(self.budget.decoded+self.budget.tree_bytes<=TOTAL_DECODED,'combined-data-byte-bound');self.budget.check();return b


def archive_nodes(ref, expected, budget):
    reference(ref,ARCHIVE);package_identity(expected);nodes={};pkginfo=None;members=0
    with opened(ref['path'],budget,ref['identity']) as (fd,before):
        need(hashed(fd,ref['size'],budget)==ref['sha256'],'archive-digest');os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(os.dup(fd),'rb') as source, lzma.LZMAFile(source) as decoded:
            counted=Counted(decoded,budget)
            with tarfile.open(fileobj=counted,mode='r|') as archive:
                for member in archive:
                    budget.node();members+=1;need(members<=ARCHIVE_NODES,'archive-node-bound')
                    name=path(member.name.removeprefix('./').removesuffix('/'))
                    need(name not in nodes and integer(member.uid,2**32-1) and integer(member.gid,2**32-1)
                         and integer(member.mode,0o7777) and integer(member.size,FILE) and member.sparse is None
                         and not any(k.startswith('GNU.sparse.') for k in member.pax_headers),'archive-member')
                    row=dict(type='directory' if member.isdir() else 'file' if member.isfile() else
                             'symlink' if member.issym() else 'hardlink' if member.islnk() else 'unsupported',
                             mode=member.mode,uid=member.uid,gid=member.gid)
                    need(row['type']!='unsupported','archive-type')
                    if member.isfile():
                        h=hashlib.sha256();size=0;control=bytearray()
                        stream=archive.extractfile(member);need(stream is not None,'archive-file')
                        with stream:
                            while True:
                                budget.check();b=stream.read(MIB)
                                if not b:break
                                size+=len(b);need(size<=member.size,'member-byte-bound');h.update(b)
                                if name=='.PKGINFO':control.extend(b);need(len(control)<=MIB,'pkginfo-bound')
                        need(size==member.size,'member-size');row.update(bytes=size,sha256=h.hexdigest())
                        if name=='.PKGINFO':pkginfo=bytes(control)
                    elif member.issym() or member.islnk():
                        need(type(member.linkname) is str and 0<len(member.linkname)<=4096 and
                             not re.search(r'[\x00-\x1f\x7f]',member.linkname),'link-target')
                        row['target']=member.linkname
                        if member.islnk():path(member.linkname.removeprefix('./'))
                    nodes[name]=row
            # Consume trailing expanded data too; tar EOF must not evade work bounds.
            while counted.read(MIB):pass
        need(identity(before)==identity(os.fstat(fd)),'archive-drift')
    need(pkginfo is not None,'pkginfo-missing');fields=defaultdict(list)
    for line in pkginfo.decode('utf-8').splitlines():
        if ' = ' in line:
            k,v=line.split(' = ',1);fields[k].append(v)
    need(all(fields[k]==[expected[n]] for k,n in [('pkgname','name'),('pkgver','version'),('arch','arch')]),'archive-tuple')
    return {n:v for n,v in nodes.items() if n not in CONTROL}


def tree_nodes(root, expected_identity, budget):
    rows={};snapshots={};root=Path(root)
    with opened(root,budget,expected_identity,directory=True) as (base,before):
        need(before.st_uid==os.geteuid() and stat.S_IMODE(before.st_mode)==0o700,'private-tree-root')
        def walk(fd,prefix,depth):
            budget.check();need(depth<=64,'tree-depth');directory=os.fstat(fd);budget.check();names=os.listdir(fd);budget.check()
            need(len(names)<=NODES,'directory-bound')
            for name in sorted(names):
                relative=path(prefix+name);budget.node();old=os.stat(name,dir_fd=fd,follow_symlinks=False);budget.check()
                need(old.st_dev==before.st_dev,'foreign-filesystem')
                kind='file' if stat.S_ISREG(old.st_mode) else 'directory' if stat.S_ISDIR(old.st_mode) else 'symlink' if stat.S_ISLNK(old.st_mode) else 'fifo' if stat.S_ISFIFO(old.st_mode) else 'char-device' if stat.S_ISCHR(old.st_mode) else 'block-device' if stat.S_ISBLK(old.st_mode) else 'socket' if stat.S_ISSOCK(old.st_mode) else 'unknown'
                row=dict(type=kind,mode=stat.S_IMODE(old.st_mode),uid=old.st_uid,gid=old.st_gid,
                         device=old.st_dev,inode=old.st_ino,nlink=old.st_nlink)
                if kind in ('char-device','block-device'):row['rdev']=old.st_rdev
                if kind=='file':
                    need(integer(old.st_size,FILE),'tree-file-bound')
                    with readable_at(fd,name,budget,identity(old),single_link=False,reason='tree-open-drift') as (child,_):
                        row.update(bytes=old.st_size,sha256=hashed(child,old.st_size,budget,True))
                        budget.check();need(identity(os.fstat(child))==identity(old),'tree-read-drift')
                elif kind=='symlink':
                    budget.check();row['target']=os.readlink(name,dir_fd=fd);budget.check();need(len(row['target'])<=4096,'link-target-bound')
                elif kind=='directory':
                    with readable_at(fd,name,budget,identity(old),directory=True,reason='tree-open-drift') as (child,_):walk(child,relative+'/',depth+1)
                budget.check();need(identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==identity(old),'tree-node-drift')
                rows[relative]=row;snapshots[relative]=identity(old)
            need(identity(os.fstat(fd))==identity(directory),'tree-directory-drift')
        walk(base,'',0)
        # Reopen relative to the held root and no-follow every directory after the full scan.
        for relative,expected in snapshots.items():
            budget.check();fds=[];parent=base
            try:
                parts=relative.split('/')
                for part in parts[:-1]:
                    budget.check();child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(child);parent=child;budget.check()
                need(identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False))==expected,'tree-final-drift')
            finally:
                close_owned(reversed(fds))
    return rows


def resolve_link(name,target,rows,budget=None):
    """Resolve solely in the captured namespace, whose root is implicit in rows."""
    parts=[] if target.startswith('/') else name.split('/')[:-1];pending=target.split('/');seen=set();hops=0
    while pending:
        if budget is not None:budget.check()
        part=pending.pop(0)
        if part in ('','.'):continue
        if part=='..':
            if not parts:return None,'ESCAPE'
            parts.pop();continue
        parts.append(part);key='/'.join(parts);node=rows.get(key)
        if node and node['type']=='symlink':
            state=(tuple(parts),tuple(pending))
            if state in seen:return None,'CYCLE'
            seen.add(state);hops+=1
            if hops>40:return None,'HOP_LIMIT'
            link=node['target'];pending=link.split('/')+pending;parts=[] if link.startswith('/') else parts[:-1]
        elif pending and node is None:return key,'MISSING'
        elif pending and node['type']!='directory':return None,'NON_DIRECTORY'
    if budget is not None:budget.check()
    key='/'.join(parts)
    return (key,'RESOLVED') if not key or key in rows else (key,'MISSING')



def node_shape(row, actual=False):
    need(type(row) is dict and type(row.get('type')) is str,'node-schema');kind=row['type']
    allowed={'file','directory','symlink'}|({'fifo','char-device','block-device','socket','unknown'} if actual else {'hardlink'})
    need(kind in allowed,'node-type');keys={'type','mode','uid','gid'}
    if actual:keys|={'device','inode','nlink'}
    if kind=='file':keys|={'bytes','sha256'}
    if kind in ('symlink','hardlink'):keys|={'target'}
    if kind in ('char-device','block-device'):keys|={'rdev'}
    need(set(row)==keys and integer(row['mode'],0o7777) and integer(row['uid'],2**32-1) and integer(row['gid'],2**32-1),'node-metadata')
    if actual:need(integer(row['device'],2**64-1) and integer(row['inode'],2**64-1) and integer(row['nlink'],2**32-1,1),'node-identity')
    if kind=='file':need(integer(row['bytes'],FILE) and type(row['sha256']) is str and HEX.fullmatch(row['sha256']),'node-content')
    if 'target' in keys:need(type(row['target']) is str and 0<len(row['target'])<=4096 and not re.search(r'[\x00-\x1f\x7f]',row['target']),'node-link')
    if kind=='hardlink':path(row['target'].removeprefix('./'))
    if 'rdev' in keys:need(integer(row['rdev'],2**64-1),'node-device')
    return row


def compare(expected, actual, owned, budget=None):
    need(type(expected) is dict and type(actual) is dict and type(owned) is dict and
         0<len(expected)<=261 and sum(len(v) for v in expected.values())+len(actual)<=NODES,'comparison-bound')
    def check():
        if budget is not None:budget.check()
    check()
    problems=[];owners=defaultdict(set);wanted={};links={}
    def fail(kind,name,**details):problems.append(dict(kind=kind,path=name,**details))
    need(set(expected)==set(owned),'ownership-package-set')
    for package,nodes in expected.items():
        check();need(set(nodes)==set(owned[package]),'ownership-archive-set')
        for name,node in nodes.items():
            check();path(name);node_shape(node);owners[name].add(package)
            if name in wanted:
                need(node==wanted[name] and node['type']=='directory','expected-overlap')
            wanted[name]=node
            if node['type']=='hardlink':links[name]=node['target'].removeprefix('./')
    for name,node in actual.items():check();path(name);node_shape(node,True)
    for name in sorted(set(wanted)|set(actual)):
        check();e=wanted.get(name);a=actual.get(name)
        if e is None:fail('UNEXPECTED',name);continue
        if a is None:fail('MISSING',name);continue
        if e['type']=='hardlink':
            target=links[name];seen={name}
            while target in links:
                check();need(target not in seen,'expected-hardlink-cycle');seen.add(target);target=links[target]
            need(target in wanted and wanted[target]['type']=='file','expected-hardlink-target');other=actual.get(target)
            if a['type']!='file' or other is None or other['type']!='file' or (a['device'],a['inode'])!=(other['device'],other['inode']):fail('HARDLINK_RELATION',name,target=target)
            content=wanted[target]
            for k in ('bytes','sha256'):
                check()
                if a.get(k)!=content[k]:fail('HARDLINK_CONTENT',name,field=k)
        elif a['type']!=e['type']:fail('TYPE',name);continue
        for k in ('mode','uid','gid'):
            check()
            if a[k]!=e[k]:fail('METADATA',name,field=k)
        for k in ('bytes','sha256','target'):
            check()
            if k in e and e['type']!='hardlink' and a.get(k)!=e[k]:fail('CONTENT' if k!='target' else 'LINK_TARGET',name,field=k)
        if e['type']=='symlink':
            _,state=resolve_link(name,e['target'],actual,budget)
            if state!='RESOLVED':fail('LINK_'+state,name)
    groups=defaultdict(list)
    for name,node in actual.items():
        check()
        if node['type']=='file':groups[(node['device'],node['inode'])].append(name)
    for names in groups.values():
        check()
        unobserved=False
        for name in names:
            check()
            if actual[name]['nlink']!=len(names):unobserved=True;break
        if unobserved:fail('UNOBSERVED_HARDLINK',names[0])
        if len(names)>1:
            expected_roots=[]
            for name in names:
                check();target=name;seen=set()
                while target in links:
                    check();need(target not in seen,'expected-hardlink-cycle');seen.add(target);target=links[target]
                expected_roots.append(target)
            if len(set(expected_roots))!=1:fail('UNEXPECTED_HARDLINK',names[0])
    projected_owners={}
    for name,packages in sorted(owners.items()):check();projected_owners[name]=sorted(packages)
    check()
    return dict(status='FAIL-correspondence' if problems else 'PASS-inert-tree-correspondence',
        packages=len(expected),expected_paths=len(wanted),observed_paths=len(actual),
        problems=problems,ownership=projected_owners,
        image_issuer_authentication_accepted=False,independent_key_owner_trust_accepted=False,
        installed_payload_verified=False,installation_accepted=False,hardware_accepted=False,
        package_execution=False,system_mutation=False,generated_file_policy='NONE; unexpected/modified nodes remain failures')



def image_ownership(document, inventory, inventory_sha256, image_sha256):
    """Validate retained261 %FILES% metadata only, never infer installed bytes/trust."""
    try:json.dumps([document,inventory],allow_nan=False)
    except (TypeError,ValueError):raise ValueError('image-nonfinite-or-unserializable') from None
    need(type(inventory_sha256) is str and HEX.fullmatch(inventory_sha256) and type(image_sha256) is str and HEX.fullmatch(image_sha256),'image-digest')
    need(type(document) is dict and set(document)=={'schema_version','kind','inventory_sha256','root_image_sha256','packages',
         'empty_filelist_packages','physical_target','hardware_accepted','installed_payload_verified'},'image-ownership-schema')
    need(type(document['schema_version']) is int and document['schema_version']==1 and
         document['kind']=='observed-image-local-file-ownership-metadata' and
         document['inventory_sha256']==inventory_sha256 and document['root_image_sha256']==image_sha256 and
         all(document[k] is False for k in ('physical_target','hardware_accepted','installed_payload_verified')),'image-ownership-binding')
    need(type(inventory) is dict and type(inventory.get('packages')) is list and len(inventory['packages'])==261,'image-inventory-count')
    identities={}
    for row in inventory['packages']:
        need(type(row) is dict and type(row.get('metadata')) is dict,'image-inventory-row');m=row['metadata']
        need(all(type(m.get(k)) is list and len(m[k])==1 and type(m[k][0]) is str for k in ('NAME','VERSION','ARCH')),'image-inventory-tuple')
        ident=package_identity(dict(name=m['NAME'][0],version=m['VERSION'][0],arch=m['ARCH'][0]));need(ident['name'] not in identities,'image-inventory-duplicate');identities[ident['name']]=ident
    need(type(document['packages']) is list and len(document['packages'])==261,'image-ownership-count');result={};empty=[];total=0
    for row in document['packages']:
        need(type(row) is dict and set(row)=={'name','version','directory','bytes','sha256','text','fields','empty_filelist'},'image-ownership-row')
        name=row['name'];need(type(name) is str and name in identities and name not in result and
             row['version']==identities[name]['version'] and row['directory']==name+'-'+identities[name]['version'] and type(row['text']) is str and integer(row['bytes'],MIB) and
             type(row['sha256']) is str and HEX.fullmatch(row['sha256']),'image-ownership-row')
        raw=row['text'].encode();total+=len(raw);need(total<=64*MIB and len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'image-ownership-text')
        fields={};current=None
        for line in row['text'].splitlines():
            if line.startswith('%') and line.endswith('%'):
                current=line[1:-1];need(current not in fields,'image-ownership-duplicate-field');fields[current]=[]
            elif line:
                need(current is not None,'image-ownership-field');fields[current].append(line)
        need(fields==row['fields'] and set(fields)<={'FILES','BACKUP'},'image-ownership-fields')
        files=[path(n.removesuffix('/')) for n in fields.get('FILES',[])];need(len(files)<=NODES and len(set(files))==len(files),'image-ownership-files')
        need(row['empty_filelist'] is (not files),'image-empty-filelist');result[name]=dict(identity=identities[name],files=files)
        if not files:empty.append(name)
    need(sorted(empty)==document['empty_filelist_packages'],'image-empty-package-list')
    return result


def run(contract, root, deadline):
    """Initial source increment accepts explicitly modeled trees only. Baseline gate stays shut."""
    budget=Budget(deadline)
    need(type(contract) is dict and set(contract)=={'schema_version','scope','packages','ownership','tree_identity'},'contract-schema')
    need(type(contract['schema_version']) is int and contract['schema_version']==1 and contract['scope']=='inert-tree-fixture','unapproved-baseline-adapter')
    packages=contract['packages'];need(type(packages) is list and 0<len(packages)<=16,'fixture-package-count')
    total=0;names=set()
    for p in packages:
        need(type(p) is dict and set(p)=={'identity','archive','signature','authentication'},'package-contract')
        package_identity(p['identity']);n=p['identity']['name'];need(n not in names,'duplicate-package');names.add(n)
        reference(p['archive'],ARCHIVE);reference(p['signature'],64*1024);reference(p['authentication'],MIB)
        total+=p['archive']['size'];need(total<=COMPRESSED,'compressed-bound')
    reference(contract['ownership'],64*MIB)
    need(type(contract['tree_identity']) is list and len(contract['tree_identity'])==len(FIELDS) and all(integer(x,2**64-1) for x in contract['tree_identity']),'tree-identity')
    ownership=decode(read_reference(contract['ownership'],64*MIB,budget))
    need(type(ownership) is dict and set(ownership)=={'schema_version','scope','packages'} and type(ownership['schema_version']) is int and ownership['schema_version']==1 and ownership['scope']=='inert-tree-fixture' and type(ownership['packages']) is list,'ownership-schema')
    owned={}
    for row in ownership['packages']:
        need(type(row) is dict and set(row)=={'identity','files'},'ownership-row');package_identity(row['identity']);n=row['identity']['name']
        need(n not in owned and type(row['files']) is list and len(row['files'])<=NODES,'ownership-row');files=[path(x) for x in row['files']];need(len(set(files))==len(files),'duplicate-ownership');owned[n]=files
        need(next((p['identity'] for p in packages if p['identity']['name']==n),None)==row['identity'],'ownership-tuple')
    need(set(owned)==names,'ownership-package-set');expected={}
    for p in packages:
        # Signature/receipt are model bytes here, never cryptographic evidence.
        read_reference(p['signature'],64*1024,budget);auth=decode(read_reference(p['authentication'],MIB,budget))
        need(auth=={'scope':'MODELED-NOT-CRYPTOGRAPHIC','identity':p['identity'],'archive_sha256':p['archive']['sha256'],'signature_sha256':p['signature']['sha256']},'authentication-binding')
        expected[p['identity']['name']]=archive_nodes(p['archive'],p['identity'],budget)
    actual=tree_nodes(root,contract['tree_identity'],budget);budget.check();result=compare(expected,actual,owned,budget);budget.check()
    for ref in [contract['ownership'],*(p[k] for p in packages for k in ('archive','signature','authentication'))]:
        with opened(ref['path'],budget,ref['identity']):pass
    result.update(scope='inert-tree-fixture',archive_signatures_verified_by_helper=False,decoded_bytes=budget.decoded,tree_bytes=budget.tree_bytes,nodes=budget.nodes,image_reader='NOT IMPLEMENTED/NOT RUN; exact root grant pending')
    need(len(json.dumps(result,allow_nan=False).encode())<=REPORT,'report-bound');return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--contract',required=True);p.add_argument('--sha256',required=True);p.add_argument('--tree',required=True);a=p.parse_args()
    try:
        need(type(a.sha256) is str and HEX.fullmatch(a.sha256),'contract-pin');budget=Budget(time.monotonic()+SECONDS);end=budget.end
        with opened(Path(a.contract).absolute(),budget) as (fd,i):
            need(0<i.st_size<=64*MIB,'contract-bound');data=os.read(fd,64*MIB+1);need(len(data)==i.st_size and hashlib.sha256(data).hexdigest()==a.sha256,'contract-pin')
        result=run(decode(data),Path(a.tree).absolute(),end);print(json.dumps(result,sort_keys=True,allow_nan=False));return int(result['status']!='PASS-inert-tree-correspondence')
    except (ValueError,OSError,EOFError,UnicodeError,tarfile.TarError,lzma.LZMAError) as error:
        print(json.dumps({'status':'REFUSED','category':type(error).__name__,'installed_payload_verified':False,'image_reader':'NOT RUN'}));return 1


if __name__=='__main__':sys.exit(main())
