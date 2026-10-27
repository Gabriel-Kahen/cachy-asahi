#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact retained574 DATA prefill; caller owns source proof and native actor budget."""
import hashlib,importlib.util,json,os,stat,sys,time
from pathlib import Path
CARRIER='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
LOCK='scripts/ci/maintained-desktop574-inputs.json'
LOCK_SHA='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
HELPER='scripts/ci/retained-build-inputs'
PINS={'LICENSE':'51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7','NOTICE.md':'6a3649fc4e0d0ee18a7399ada57d9fa8c1b8c97232ba46efd5da511c72a74141','carrier-profile.json':'4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c','legacy-prefill-profile.json':'9cc82d4e0947415ecad9d40094a4c0a2709d01be54513e78af8c739fd76fb696','legacy_prefill.py':'05a91a91efd69b3b2e06561f5bbf08bdbb105998d42dbf133e75fd1fe25945ac','prepare.py':'6c688c315cb962c641b8c0b1d9d88f94778d57ae19bcef251e88e49cb4be6316'}
def need(ok,why):
 if not ok:raise ValueError(why)
def ordinary(path):
 path=Path(path).absolute();info=path.lstat();need(not any(p.is_symlink()for p in(path,*path.parents))and stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size<=2*1024**2,'ordinary bounded source file required');return path.read_bytes()
def validate_source(source):
 source=Path(source).absolute();need(hashlib.sha256(ordinary(source/LOCK)).hexdigest()==LOCK_SHA,'exact accepted574 input lock')
 for name,pin in PINS.items():need(hashlib.sha256(ordinary(source/HELPER/name)).hexdigest()==pin,'exact retained helper source: '+name)
 return source
def helper(source):
 directory=source/HELPER;validate_source(source);sys.path.insert(0,str(directory));spec=importlib.util.spec_from_file_location('_offline_kit_exact574_prepare',directory/'prepare.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def prefill(source,carrier,output,deadline,*,loader=helper,clock=time.monotonic):
 """No process, network, package build or native authority: complete DATA then return."""
 source=validate_source(source);carrier=Path(carrier).absolute();output=Path(output).absolute()
 need(type(deadline)in(int,float)and clock()<deadline<=clock()+2300,'bounded original producer deadline')
 need(not any(p.is_symlink()for p in(output,*output.parents))and output.is_dir()and output.stat().st_uid==os.getuid()and stat.S_IMODE(output.stat().st_mode)==0o700,'existing caller-owned private output required')
 value=loader(source).prepare(carrier,output/'context/deps','desktop574',source/LOCK,deadline,carrier/'.git')
 need(value['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'and value['source']==CARRIER and value['mode']=='desktop574'and value['actual']is None and value['receipt']['actual_authority']is False and value['receipt']['cache']['all_previous_inode_metadata_bytes_unchanged']is True,'exact complete DATA receipt and prior cache preservation required');need(clock()<deadline,'original producer budget exhausted')
 path=output/'offline-kit-retained574-inputs.json'
 with path.open('x')as stream:json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
 return value
