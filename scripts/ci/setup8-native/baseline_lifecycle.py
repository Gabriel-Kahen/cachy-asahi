# SPDX-License-Identifier: MIT
"""Project held Setup7 lifecycle into readonly mounts; preserve all assertions."""
from pathlib import Path
import contract as C


def source(root):
    raw=C.pinned(root,'scripts/ci/setup7-native/lifecycle.py')
    changes=[("Path('/runner/contract.py')","Path('/baseline7/contract.py')",1),
             ("Path('/inputs/products.json')","Path('/inputs/baseline7-products.json')",1),
             ("'/runner/exercise.py'","'/baseline7/exercise.py'",1),
             ("'/runner/recovery_preview.py'","'/baseline7/recovery_preview.py'",1)]
    for old,new,count in changes:
        C.need(raw.count(old)==count,'held baseline lifecycle anchor differs');raw=raw.replace(old,new)
    return raw


def run():
    root=Path('/source')
    scope=dict(__file__='/baseline7/lifecycle.py',__name__='held_setup7_installed_lifecycle')
    exec(compile(source(root),scope['__file__'],'exec'),scope)
    scope['main']()
