#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Exactly five reversible Fish operands over the unchanged pinned carrier."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from types import ModuleType

HERE=Path(__file__).resolve().parent
CORE=(HERE/'native349_carrier.FROZEN.py').read_bytes()
CORE_PIN=dict(bytes=81606,sha256='f4ea405229a60c74a97fc7ce82709a5c92980bf8dd86d6b250d898ae1db252bb')
SEAMS=(
 ("name = 'scripts/ci/llhttp-reference-native-source/owner/data.py'","name = 'scripts/ci/fish-config02-native-source/successor_v2/data.py'"),
 ("'ROOT_LLHTTP_REFERENCE_ADMISSION_JSON'","'ROOT_FISH02_ADMISSION_JSON'"),
 ("'ROOT_LLHTTP_REFERENCE_RUNTIME_JSON'","'ROOT_FISH02_RUNTIME_JSON'"),
 ("root/'held-source/scripts/ci/llhttp-reference-native-source/base/runtime/owned_process.py'","root/'held-source32/scripts/ci/fish-config02-native-source/runtime/owned_process.py'"),
 ("cache.parent.name == 'llhttp-reference-native'","cache.parent.name == 'fish02-native'"))


def project(raw):
    if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=CORE_PIN:raise ValueError('whole frozen strict native349 helper')
    text=raw.decode()
    for before,after in SEAMS:
        if text.count(before)!=1 or after in text:raise ValueError('one exact Fish operand')
        text=text.replace(before,after)
    reverse=text
    for before,after in reversed(SEAMS):reverse=reverse.replace(after,before)
    if reverse.encode()!=raw:raise ValueError('whole unchanged strict helper inverse')
    return text.encode()


N=ModuleType('fish02_exact_carrier_core');N.__file__=str(Path(__file__).resolve());exec(compile(project(CORE),N.__file__,'exec'),N.__dict__)
stage=N.stage
seed=N.seed
project_entry=N.project_entry

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    try:
        result=N.fetch(a.root,a.output)
        print(json.dumps({k:result[k]for k in('status','files','bytes','private_key_absent','accepting')}))
    except BaseException as error:
        print(json.dumps(dict(status='HOLD_FISH02_EXACT_CARRIER',error_class=type(error).__name__,private_key_value_logged=False)))
        raise SystemExit(2)
