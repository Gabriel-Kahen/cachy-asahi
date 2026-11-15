# SPDX-License-Identifier: MIT
"""Bounded plain-DATA Docker export envelope; never extract an executable Source."""
import io
import re
import tarfile

LIMIT=256*1024**2
FILE_LIMIT=64*1024**2


def need(ok,why):
    if not ok:raise ValueError(why)


def parse(raw):
    need(type(raw) is bytes and 1024<=len(raw)<=LIMIT and len(raw)%512==0,'bounded complete export tar bytes')
    headers=0;ended=False
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            nonlocal headers,ended
            block=archive.fileobj.read(512)
            if block==bytes(512):ended=True
            else:headers+=1;need(headers<=256,'export header bound')
            item=(cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf') else cls.frombuf(block,archive.encoding,archive.errors))
            item.offset=archive.fileobj.tell()-512
            return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0<=self.size<=65536,'export PAX bound');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0<=self.size<=65536,'export long-name bound');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse export refused')
        _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
    out={};total=0;root=False
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:',tarinfo=Info) as archive:
        for item in archive:
            name=item.name.rstrip('/')
            if item.isdir():
                need(name=='output' and not root,'only one export root directory')
                need(item.size==0 and not item.mode&0o7022 and not item.sparse and not any(key.startswith('GNU.sparse') for key in item.pax_headers),'safe empty export root directory')
                root=True;continue
            need(item.isfile() and not item.sparse and not any(key.startswith('GNU.sparse') for key in item.pax_headers) and name.startswith('output/'),'only regular DATA export members')
            name=name[len('output/'):]
            need(re.fullmatch('[A-Za-z0-9._+-]{1,128}',name) and name not in ('.','..') and name not in out,'flat unique output filename')
            need(item.mode in (0o600,0o644) and 0<=item.size<=FILE_LIMIT and len(out)<64,'safe bounded output DATA file')
            body=archive.extractfile(item).read(FILE_LIMIT+1);need(len(body)==item.size,'complete export file')
            total+=len(body);need(total<=LIMIT,'export aggregate byte limit')
            out[name]=(body,item.mode)
        tail=archive.fileobj.read()
        need(ended and len(tail)>=512 and not any(tail),'complete zero-only export tar tail')
    need(root and out,'nonempty complete export root required')
    return out
