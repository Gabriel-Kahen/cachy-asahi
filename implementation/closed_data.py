# SPDX-License-Identifier: MIT
"""Exact ordinary DATA namespace; only a record's top Git admin is ignored."""
import os
from pathlib import Path

def names(root,admin=False):
 root=Path(root);out=set()
 for base,dirs,files in os.walk(root):
  if Path(base)==root and admin:dirs[:]=[n for n in dirs if n!='.git'];files=[n for n in files if n!='.git']
  for n in dirs:
   if n=='.git'or(Path(base)/n).is_symlink():raise ValueError('foreign nested DATA/Git directory alias')
  for n in files:
   p=Path(base)/n
   if n=='.git'or p.is_symlink()or not p.is_file():raise ValueError('foreign nested DATA/Git file alias')
   out.add(p.relative_to(root).as_posix())
 return out
