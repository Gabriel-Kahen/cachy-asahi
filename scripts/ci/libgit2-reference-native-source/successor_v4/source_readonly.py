# SPDX-License-Identifier: MIT
"""Exact shared Source-RO logic; adapt only the owned daemon cgroup name."""
import hashlib
from pathlib import Path
import stat

SHARED_PIN=dict(bytes=3052,sha256='55c58b6e15a73339f0c901a6d379f468e39e90e81a6602651942f35162a8e9d8')
EDITS=(("'/sys/fs/cgroup/system.slice/cachy-llhttp-reference-'",
        "'/sys/fs/cgroup/system.slice/cachy-libgit2-reference-'"),)

def _need(value,why):
    if not value:raise ValueError(why)

def _pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def project(raw):
    _need(_pin(raw)==SHARED_PIN,'exact immutable shared Source-RO helper')
    text=raw.decode()
    for before,after in EDITS:
        _need(text.count(before)==1 and after not in text,'one exact owned cgroup namespace seam');text=text.replace(before,after)
    inverse=text
    for before,after in reversed(EDITS):
        _need(inverse.count(after)==1,'one exact cgroup namespace inverse');inverse=inverse.replace(after,before)
    _need(inverse.encode()==raw,'whole unchanged Source-RO algorithm inverse');return text.encode()

_path=Path(__file__).with_name('source_readonly_shared.py')
_need(_path==_path.resolve() and not any(p.is_symlink() for p in (_path,*_path.parents)),'ordinary exact helper path')
_before=_path.lstat()
_need(stat.S_ISREG(_before.st_mode) and _before.st_nlink==1 and not _before.st_mode&0o022 and _before.st_size==SHARED_PIN['bytes'],'fixed ordinary shared helper')
_raw=_path.read_bytes();_after=_path.lstat()
_identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
_need(_identity(_before)==_identity(_after),'stable complete shared helper')
exec(compile(project(_raw),str(_path)+'[libgit2 cgroup namespace only]','exec'),globals())
