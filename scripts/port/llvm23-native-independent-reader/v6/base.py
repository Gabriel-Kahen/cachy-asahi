# SPDX-License-Identifier: MIT
"""One exact passive absence-encoding derivation; earlier Readers are frozen."""
import hashlib
import importlib.util
from pathlib import Path

HERE=Path(__file__).resolve().parent
PARENT=HERE.parent/'v5/base.py'
PARENT_SHA='669b3f6b087c43e0ce6128f606d6cb8d5dcd1eb425e87ab2f8e6b643fb0ad42e'
if PARENT.is_symlink()or hashlib.sha256(PARENT.read_bytes()).hexdigest()!=PARENT_SHA:
    raise ValueError('whole trusted passive Reader5 base')
spec=importlib.util.spec_from_file_location('llvm6_held_base5',PARENT)
held=importlib.util.module_from_spec(spec);spec.loader.exec_module(held)
v,old,parent_pins=held.v,held.old,held.parent_pins
before=old.B.function_bytes(old.B._closure['v2/reader.py'],'retirement')
after,absence_proof=old.B.projected(before,[
    (b"not read(evidence/row['stdout']).strip()",
     b"read(evidence/row['stdout']).strip() in (b'', b'[]')")],
    'exact post-removal absent-image stdout encoding')
exec(compile(after,'<trusted-Reader6-retirement-stdout-only>','exec'),v.__dict__)
if v.retirement.__globals__ is not v.__dict__ or v.replay.__globals__ is not v.__dict__:
    raise ValueError('new cloned replay must use exact retirement successor')
projection_proof=dict(held.projection_proof,absent_image_stdout=absence_proof)


def install(specification,namespace):
    proof=held.install(specification,namespace)
    if v.replay.__globals__ is not v.__dict__ or v.replay.__globals__['retirement']is not v.retirement:
        raise ValueError('installed replay must retain new absence predicate')
    return dict(proof,absent_image_stdout=absence_proof)
