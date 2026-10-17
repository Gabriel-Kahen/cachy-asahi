# SPDX-License-Identifier: MIT
"""Read-only complete staged-tree ELF/page audit; never execute a payload."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def audit(root,reader):
    root=Path(root);need(root.is_absolute() and root.is_dir() and not root.is_symlink(),'explicit regular tree root required')
    rows=[];assets=[];members=0;total=0;start=time.monotonic()
    def unreadable(error):raise error
    for directory,children,names in os.walk(root,followlinks=False,onerror=unreadable):
        children.sort()
        for name in sorted(names):
            members+=1;need(members<=600000 and time.monotonic()-start<240,'tree audit count/deadline')
            path=Path(directory)/name;info=path.lstat()
            if not stat.S_ISREG(info.st_mode):continue
            with path.open('rb') as stream:
                head=stream.read(64)
                if len(head)<64 or not head.startswith(b'\x7fELF'):continue
                kind,machine=struct.unpack_from('<HH',head,16)
                if kind not in (2,3):continue
                relative=str(path.relative_to(root));need(info.st_size<=256*1024**2,'ELF member bound')
                raw=head+stream.read(256*1024**2)
            need(len(raw)==info.st_size,'ELF changed while reading')
            item=dict(path=relative,bytes=len(raw),sha256=sha(raw),machine=machine)
            # These are executable-format data, not Linux native loader inputs.
            if relative.startswith(('usr/lib/firmware/','usr/lib/modules/','usr/lib/debug/')):
                assets.append(dict(item,classification='FIRMWARE_KERNEL_DEBUG_NOT_USERSPACE'));continue
            if machine==0 and relative.endswith('.go') and relative.startswith(('usr/share/gdb/guile/','usr/lib/guile/')):
                assets.append(dict(item,classification='EM_NONE_VM_BYTECODE_NOT_AARCH64_NATIVE'));continue
            interpreter,needed,loads=reader.elf(raw)
            need(loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'native ELF not16K aligned: '+relative)
            total+=len(raw);need(total<=12*1024**3 and len(rows)<20000,'ELF aggregate bound')
            rows.append(dict(item,interpreter=interpreter,needed=needed,loads=loads))
    need(rows,'nonempty native ELF tree required')
    return dict(schema_version=1,status='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT',root=str(root),ELF=rows,
        non_native_assets=assets,regular_members=members,ELF_bytes=total,seconds=round(time.monotonic()-start,6),
        runtime_execution='NOT_ESTABLISHED_BY_STRUCTURAL_AUDIT',hardware='NOT_RUN')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--reader',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    spec=importlib.util.spec_from_file_location('pinned_elf_reader',a.reader);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    report=audit(a.root,module);raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=16*1024**2,'ELF receipt size')
    with a.output.open('xb') as stream:stream.write(raw)
    print(json.dumps(dict(status=report['status'],ELFs=len(report['ELF']),sha256=sha(raw))))
