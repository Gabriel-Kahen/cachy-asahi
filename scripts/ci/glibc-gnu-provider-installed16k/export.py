#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only debugfs readback after QEMU group retirement; no host filesystem mount."""
import os
from pathlib import Path
import re
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def main():
    C.need(os.getuid()==os.geteuid()==0 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and os.environ.get('CAA_INSTALLED16K_PREPARE')=='1','owned offline export container only')
    C.need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline export')
    files=C.decode(C.read('/selection/guest-files.json'));C.need(len(files)<=256 and sum(r['bytes'] for r in files.values())<=512*1024**2,'bounded export manifest')
    target=Path('/out/guest');C.need(not target.exists(),'fresh public readback');target.mkdir(mode=0o700)
    for name,pin in files.items():
        C.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',name),'closed debugfs filename')
        result=subprocess.run(['/usr/bin/debugfs','-R','dump /out/'+name+' '+str(target/name),'/disks/volume.raw'],stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
        C.need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536,'debugfs command failed');C.ref(target,dict(path=name,**pin),64*1024**2)
        os.chown(target/name,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
    os.chown(target,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))

if __name__=='__main__':main()
