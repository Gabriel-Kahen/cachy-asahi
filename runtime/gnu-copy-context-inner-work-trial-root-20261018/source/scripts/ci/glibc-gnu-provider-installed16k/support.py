# SPDX-License-Identifier: MIT
"""Finite loader bridge for the unchanged canonical archive-acquisition workflow."""
from pathlib import Path
import contract as C
check_source=C.check_source
need=C.need
sha=C.sha
read=C.read

def load(root,name):
    pins=C.decode(C.read(C.HERE/'dependencies.json'))['files']
    return C.load(name.replace('/','_'),C.ref(Path(root),dict(path=name,**pins[name]),16*1024**2))
