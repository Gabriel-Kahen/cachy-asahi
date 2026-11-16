# SPDX-License-Identifier: MIT
"""Narrow Source445b normal-ALPM INSTALLDATE normalization; DATA only."""
import hashlib


def normalize_desc(raw):
    if type(raw) is not bytes:raise ValueError('literal ALPM desc bytes required')
    parts=raw.decode('utf-8').splitlines(keepends=True)
    indexes=[i for i,line in enumerate(parts) if line=='%INSTALLDATE%\n']
    if len(indexes)!=1 or indexes[0]+1>=len(parts):raise ValueError('one normal ALPM INSTALLDATE')
    original=parts[indexes[0]+1]
    if not original.endswith('\n') or not original[:-1].isascii() or not original[:-1].isdigit():raise ValueError('one integer transaction date')
    parts[indexes[0]+1]='<NORMAL_ALPM_TRANSACTION_TIME>\n'
    return ''.join(parts).encode(),original[:-1]


def comparison(before,after):
    a,old=normalize_desc(before);b,new=normalize_desc(after)
    if a!=b:raise ValueError('unrelated local database bytes changed')
    return dict(original_install_date=old,final_install_date=new,normalized_sha256=hashlib.sha256(a).hexdigest())
