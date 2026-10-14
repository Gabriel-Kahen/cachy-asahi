"""Pure signed-input archive interpretation, bounded reads; no actor execution."""
import io
import os
from pathlib import PurePosixPath
import re
import tarfile
import time

INSTALL_SCRIPTS_ARE_NOT_HOOKS=True

FINGERPRINT='68B3537F39A313B3E574D06777193F152BDBE6A6'


def need(value,code):
    if not value:raise ValueError(code)


def live(end):need(0<time.monotonic()<end,'input-original-deadline')


def objects(inputs):
    need(len(inputs['packages'])==248 and inputs['signer_fingerprint']==FINGERPRINT and
         type(inputs['source_date_epoch'])is int and inputs['source_date_epoch']==1791748800,'maintained-input-profile')
    rows=list(inputs['keyring_files'])
    for item in [inputs['rootfs'],*inputs['packages']]:
        rows.extend([item,{'filename':item['filename']+'.sig','size':item['signature_size'],'sha256':item['signature_sha256']}])
    names=[row['filename']for row in rows]
    need(len(rows)==501 and len(set(names))==501 and sum(row['size']for row in rows)==1531622678,'input501-shape')
    for row in rows:
        need(row['filename']not in {'.','..'}and re.fullmatch('[A-Za-z0-9@+_.:~-]{1,255}',row['filename'])and
             type(row['size'])is int and row['size']>=0 and re.fullmatch('[0-9a-f]{64}',row['sha256']),'input-object-row')
    return rows


def signature(status):
    need(type(status)is bytes and len(status)<=1024**2,'signature-output-cap')
    records=[line.split()[1:]for line in status.decode('utf-8').splitlines()if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','FAILURE','ERROR'}
    need(all(row and row[0]not in bad for row in records),'signature-negative-status')
    valid=[row for row in records if row[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==FINGERPRINT,'signature-primary')
    return {'primary_fingerprint':FINGERPRINT,'validsig_records':1}


class Stream(io.RawIOBase):
    def __init__(self,node,end):self.fd=node[1];self.size=node[2][6];self.position=0;self.end=end
    def readable(self):return True
    def read(self,size=-1):
        live(self.end)
        if self.position==self.size:return b''
        size=min(1024**2,self.size-self.position if size<0 else size,self.size-self.position)
        data=os.pread(self.fd,size,self.position);need(data or size==0,'input-stream-short-read')
        self.position+=len(data);live(self.end);return data


def safe_name(name):
    name=name.removeprefix('./')
    if name in {'','.','/'}:return '.'
    path=PurePosixPath(name)
    need(not path.is_absolute()and '..'not in path.parts and len(name)<=4096 and '\0'not in name,'input-tar-path')
    return str(path)


def link_target(name,target):
    need(type(target)is str and len(target)<=4096 and '\0'not in target,'input-tar-link')
    parts=[]if target.startswith('/')else list(PurePosixPath(name).parent.parts)
    for part in target.split('/'):
        if part in {'','.'}:continue
        if part=='..':need(parts,'input-link-escape');parts.pop()
        else:parts.append(part)
    return '/'.join(parts)or '.'


def fields(text):
    result={}
    for line in text.splitlines():
        if not line or line.startswith('#'):continue
        key,separator,value=line.partition(' = ');need(separator,'package-metadata-line')
        result.setdefault(key,[]).append(value)
    return result


def inspect(node,end,*,rootfs=False,expected=None):
    inventory=[];hooks={};paths=[];seen=set();links={};total=0;metadata=None;buildinfo=None;install=None
    stream=Stream(node,end)
    with tarfile.open(fileobj=stream,mode='r|gz'if rootfs else'r|xz')as archive:
        for member in archive:
            live(end);name=safe_name(member.name)
            need(name not in seen and len(seen)<131072 and len(PurePosixPath(name).parts)<=64,'input-tar-members')
            seen.add(name);paths.append(name)
            need(member.isdir()or member.isfile()or member.issym()or member.islnk(),'input-tar-type')
            need(0<=member.size<=2*1024**3,'input-member-cap');total+=member.size
            need(total<=16*1024**3,'input-expanded-cap')
            if member.issym():links[name]=link_target(name,member.linkname)
            if member.islnk():link_target('.',member.linkname)
            hook=name.startswith(('usr/share/libalpm/hooks/','etc/pacman.d/hooks/'))and name.endswith('.hook')
            desc=rootfs and name.startswith('var/lib/pacman/local/')and name.endswith('/desc')
            read=desc or(not rootfs and name in {'.PKGINFO','.BUILDINFO','.INSTALL'})or hook
            if read:
                need(member.isfile()and member.size<=1024**2,'input-metadata-cap')
                source=archive.extractfile(member)
                with source:raw=source.read(1024**2+1)
                need(len(raw)==member.size,'input-metadata-size');text=raw.decode('utf-8')
                if desc:
                    parsed={}
                    for chunk in text.split('\n\n'):
                        lines=chunk.strip().splitlines()
                        if lines:parsed[lines[0].strip('%')]=lines[1:]
                    inventory.append({key.lower():parsed.get(key,[])for key in('NAME','VERSION','ARCH','LICENSE','DEPENDS','PROVIDES')})
                elif name=='.PKGINFO':metadata=fields(text)
                elif name=='.BUILDINFO':buildinfo=fields(text)
                elif name=='.INSTALL':install=text
                else:hooks[name]=text
    for name in links:
        current=name;visited=set()
        for _ in range(32):
            if current not in links:break
            need(current not in visited,'input-link-cycle');visited.add(current);current=links[current]
        else:raise ValueError('input-link-depth')
    if rootfs:need(inventory,'rootfs-inventory-empty')
    else:
        need(metadata is not None and expected is not None,'package-metadata-missing')
        for target,key in [('pkgname','name'),('pkgver','version'),('arch','arch'),('license','license'),
                           ('depend','depends'),('provides','provides'),('conflict','conflicts'),('replaces','replaces')]:
            value=expected[key];need(sorted(metadata.get(target,[]))==sorted(value if isinstance(value,list)else[value]),'input-package-metadata')
    live(end)
    return {'inventory':inventory,'hooks':hooks,'paths':paths,'metadata':metadata,'buildinfo':buildinfo,'install_scriptlet':install}


def hook_masks(names):
    names=sorted(set(names))
    need(len(names)<=4096 and all(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',name)for name in names),'hook-mask-names')
    return ''.join(name+'\n'for name in names).encode()
