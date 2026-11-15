#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite code/DATA Source constructor; never copies raw/archive payloads or boots."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys

HERE=Path(__file__).resolve().parent


def git_tree(files):
    def oid(kind,body):return hashlib.sha1(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body).hexdigest()
    nodes={}
    for name,(raw,mode) in files.items():
        if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('contained Source path required')
        nodes[name]=(oid('blob',raw),mode)
    def visit(prefix):
        children={}
        for name,row in nodes.items():
            if name.startswith(prefix):
                leaf=name[len(prefix):].split('/',1)[0];children[leaf]=row if prefix+leaf==name else None
        body=bytearray()
        for name,row in sorted(children.items(),key=lambda x:(x[0]+('/' if x[1] is None else '')).encode()):
            mode,checksum=('40000',visit(prefix+name+'/')) if row is None else ('100755' if row[1]&0o111 else '100644',row[0])
            body.extend(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(checksum))
        return oid('tree',body)
    return visit('')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-source-construction',action='store_true');p.add_argument('--source-lock-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not(a.allow_source_construction and sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()!=0):p.error('explicit ordinary isolated Source construction required')
    spec=importlib.util.spec_from_file_location('stage0_source_contract',HERE/'contracts.py');K=importlib.util.module_from_spec(spec);spec.loader.exec_module(K)
    lock=K.source();K.need(lock['sha256']==a.source_lock_sha256,'explicit complete Source lock digest required')
    out=K.ordinary(a.output);K.need(not out.exists() and out.parent.is_dir() and out.parent.stat().st_uid==os.getuid() and not out.parent.stat().st_mode&0o022 and HERE not in out.parents and out not in HERE.parents,'fresh disjoint private Source output required')
    data=K.load(HERE/'source.lock.json');names=set(data['files'])|{'source.lock.json'}
    files={n:((HERE/n).read_bytes(),stat.S_IMODE((HERE/n).stat().st_mode)) for n in names}
    K.need(len(files)<=128 and sum(len(raw) for raw,_ in files.values())<=4*1024**2,'finite code/DATA Source bound')
    out.mkdir(mode=0o700);tree=out/'source-tree';tree.mkdir(mode=0o700)
    for name,(raw,mode) in files.items():
        target=tree/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write(raw)
        target.chmod(mode)
    report=dict(schema=1,status='SOURCE_CONSTRUCTED_NOT_PREPARED_OR_BOOTED',source_lock=lock,files=len(files),bytes=sum(len(raw) for raw,_ in files.values()),prospective_tree=git_tree(files),actual=dict(source=None,ref=None,authority=None,prepared=None,attempt=None,VM_boot=None),archives_embedded=False,native16K='UNQUALIFIED',M2='UNQUALIFIED',performance='NOT MEASURED',release='UNQUALIFIED')
    (out/'construction.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return 0


if __name__=='__main__':raise SystemExit(main())
