# SPDX-License-Identifier: MIT
"""Fail closed outside the original six-capability owned native consumer."""
import os
from pathlib import Path
import re
import stat
import accepted_inputs as A
need=A.need
pin=A.pin
decode=A.decode
ordinary=A.read
BOUNDS=dict(max_packages=607,max_nodes=200000,max_bytes=6*1024**3,max_file_bytes=1024**3,max_depth=128)

def native_scope(root,keys,log):
    need(Path(root) == Path('/') and Path(log).parent == Path('/out'), 'fixed native root/output only')
    need(os.geteuid() == os.getuid() == 0 and os.uname().machine == 'aarch64' and
         Path('/.dockerenv').is_file() and re.fullmatch('[0-9a-f]{32}',os.environ.get('CACHY_ASAHI_EXPANDED604','')) and
         {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'} and
         not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(), 'original owned offline ARM container only')
    command=Path('/proc/1/cmdline').read_bytes()
    need(command.split(b'\0')[-2] == b'/runner/lifecycle.py', 'original counted native lifecycle PID1 required')
    fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(fields[k],16) == 0xdb for k in ('CapEff','CapPrm','CapBnd')) and
         all(int(fields[k],16) == 0 for k in ('CapInh','CapAmb')) and int(fields['NoNewPrivs']) == 1,
         'whole original six capability/NNP contract')
    keys=Path(keys)
    need(keys.name == 'trust' and keys.parent.parent == Path('/tmp') and keys.parent.name.startswith('expanded604-') and
         not any(p.is_symlink() for p in (keys,*keys.parents)), 'same original ephemeral native verification home')
    info=keys.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         'owned private original TEST verification home')
    null=Path('/dev/null').stat()
    need(stat.S_ISCHR(null.st_mode) and null.st_rdev == os.makedev(1,3), 'proper original container null device')
