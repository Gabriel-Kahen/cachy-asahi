#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain upstream libc test statuses; failures are never converted to skips."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time

STATUSES=('PASS','FAIL','XFAIL','XPASS','UNSUPPORTED','ERROR')

def collect(build,output):
    deadline=time.monotonic()+30;counts=dict.fromkeys(STATUSES,0);rows=[];total=0;errors=[]
    paths=[];visited=0
    for directory,dirs,files in os.walk(build,followlinks=False):
        dirs[:]=[name for name in dirs if not (Path(directory)/name).is_symlink()]
        visited+=len(dirs)+len(files)
        if time.monotonic()>deadline or visited>250000:raise ValueError('test tree bounds')
        paths.extend(Path(directory)/name for name in files if name.endswith('.test-result'))
        if len(paths)>50000:raise ValueError('test count bound')
    for path in sorted(paths):
        if time.monotonic()>deadline:raise ValueError('test report deadline')
        if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:raise ValueError('ordinary bounded test record required')
        raw=path.read_bytes();total+=len(raw)
        if total>16*1024**2:raise ValueError('aggregate test report bound')
        matches=re.findall(r'^(PASS|FAIL|XFAIL|XPASS|UNSUPPORTED|ERROR): (.+)$',raw.decode('utf-8','replace'),re.M)
        if len(matches)!=1:errors.append(str(path.relative_to(build)));continue
        status,name=matches[0];counts[status]+=1
        row=dict(path=str(path.relative_to(build)),status=status,name=name,sha256=hashlib.sha256(raw).hexdigest())
        if status!='PASS':
            diagnostic=path.with_suffix('.out')
            if diagnostic.is_file() and not diagnostic.is_symlink():
                with diagnostic.open('rb') as stream:row['diagnostic']=stream.read(4096).decode('utf-8','replace')
        rows.append(row)
    def exit_code(name):
        raw=(Path(output)/name).read_text().strip()
        if not re.fullmatch(r'[0-9]{1,3}',raw):raise ValueError('actual make exit code required')
        return int(raw)
    check,abi=exit_code('check-exit'),exit_code('abi-exit')
    passed=check==abi==0 and counts['PASS']>0 and not errors and all(counts[k]==0 for k in ('FAIL','XPASS','ERROR'))
    result=dict(schema_version=1,status='PASS_UPSTREAM_APPLICABLE_TESTS' if passed else 'FAIL_UPSTREAM_TESTS',
        check_exit=check,abi_exit=abi,counts=counts,results=rows,malformed=errors,
        unsupported_policy='upstream UNSUPPORTED retained by name/diagnostic; no source tests deleted',hardware='NOT RUN')
    raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
    if len(raw)>32*1024**2:raise ValueError('test receipt byte bound')
    (Path(output)/'upstream-tests.json').write_bytes(raw);return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();raise SystemExit(collect(args.build,args.output)['status']!='PASS_UPSTREAM_APPLICABLE_TESTS')
