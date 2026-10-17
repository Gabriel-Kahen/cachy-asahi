# SPDX-License-Identifier: MIT
"""An independently owned profile is never a completed two-profile GUI trial."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
PROFILES=('minimal','overlay')
GUI='PASS_INSTALLED_WELCOME_SINGLE_PROFILE_GUI_METADATA'
NATIVE='PASS_NATIVE_MANAGEMENT_PAIR_READONLY_LIFECYCLE_AND_SINGLE_PROFILE_GUI'
RETAINED='PASS_NATIVE_SINGLE_PROFILE_METADATA_PIXELS_PENDING_ROOT_REVIEW'
NAMESPACE='scripts/ci/welcome-independent-profile-native'

def need(ok,reason):
    if not ok:raise ValueError(reason)

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def pin(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))

def read(path,cap=2*1024**2):
    path=Path(path).absolute();need(not any(p.is_symlink() for p in (path,*path.parents)),'symlink refused')
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=cap,'bounded ordinary file required')
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def profile(value):need(value in PROFILES,'explicit minimal or overlay profile required');return value

def policy():
    value=read(HERE/'policy.json')
    need(value==dict(schema_version=1,status='ROOT_BOUND_INDEPENDENT_PROFILES',profiles=list(PROFILES),
        candidate_policy_sha256=value.get('candidate_policy_sha256'),scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE') and
        re.fullmatch('[0-9a-f]{64}',value.get('candidate_policy_sha256') or ''),
        'independent profile authority remains UNBOUND until Root binding')
    return value

def files(source,rows):
    need(type(rows) is dict and 1<=len(rows)<=512,'closed source set required')
    for name,row in rows.items():
        p=Path(name);need(not p.is_absolute() and p.parts and '..' not in p.parts,'safe source member required')
        target=source/p;read_info=target.lstat()
        need(not any(x.is_symlink() for x in (target,*target.parents)) and stat.S_ISREG(read_info.st_mode) and read_info.st_nlink==1 and
            type(row) is dict and set(row)=={'bytes','sha256'} and 0<row['bytes']<=16*1024**2 and pin(target)==row,'source pin differs: '+name)

def gate(source,selected,manifest):
    profile(selected);value=policy();pins=read(HERE/'source-pins.json')['files'];files(source,pins)
    need(pin(source/'scripts/ci/welcome-management-native/input-policy.json')['sha256']==value['candidate_policy_sha256'],'candidate authority differs')
    need(manifest.get('schema_version')==1 and manifest.get('status')=='FROZEN_ROOT_INDEPENDENT_PROFILE_SOURCE','frozen independent profile source required')
    required=set(pins)|{NAMESPACE+'/'+p.name for p in HERE.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    need(set(manifest['files'])==required,'complete original plus independent source closure required');files(source,manifest['files'])
    return value

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def binding(proof,selected,manifest_path):
    need(proof.get('profile')==profile(selected) and proof.get('scope')=='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE' and
        proof.get('manifest_sha256')==pin(manifest_path)['sha256'] and
        proof.get('entry_argv')==['--profile',selected],'retained profile/source/argv binding differs')


def profile_argv(argv):
    need(type(argv) is list and len(argv)<=32 and all(type(a) is str and 0<len(a)<=4096 and not any(c in a for c in '\0\r\n') for a in argv),'bounded explicit owner argv required')
    need(argv.count('--profile')==1 and not any(a.startswith('--profile=') for a in argv),'one explicit profile operand required')
    at=argv.index('--profile');need(at+1<len(argv),'profile operand absent');profile(argv[at+1]);return argv[at:at+2]
