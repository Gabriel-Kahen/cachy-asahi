#!/usr/bin/env python3
"""Require current semantic checks after the existing strict native comparator."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

HERE=Path(__file__).resolve().parent
MARKER=b'PASS: noninteractive guard, existing helpers, repeated source, CDPATH-independent relative/absolute paths, mkdir failure preservation, no privileged aliases or universal-variable writes'
def need(value,why):
    if not value:raise ValueError(why)
def read(path,limit):
    need(not path.is_symlink()and stat.S_ISREG(path.stat().st_mode)and path.stat().st_size<=limit,'bounded ordinary pair DATA')
    return path.read_bytes()


def finish(first,second,comparison,image):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image)and first.resolve()!=second.resolve(),'actual immutable image and separate builds')
    reviewed=json.loads((HERE/'reviewed-inputs.json').read_bytes());lock=hashlib.sha256((HERE/'expected349.lock').read_bytes()).hexdigest();records=[];checks=[]
    for root in(first,second):
        record=json.loads(read(root/'provenance.json',4*1024**2));need(record['status']=='built-package-static-pass'and record['exit_code']==0 and record['mode']=='native'and record['image_id']==image and record['recipe_inputs']==reviewed and record['expected_packages_sha256']==lock,'actual successful selected native build')
        logs=[p for p in(root/'artifacts').iterdir()if re.fullmatch(r'cachy-asahi-fish-config-0\.1\.0-2-(?:aarch64|any)-check\.log',p.name)]
        need(len(logs)==1,'one actual current makepkg check-phase log per build')
        raw=read(logs[0],1024**2);need(raw.count(MARKER)==1,'complete current Fish semantic check PASS required; disabled or stale checks refuse')
        records.append(record);checks.append(dict(file=logs[0].name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    need(records[0]['clean_environment_id']and records[0]['clean_environment_id']!=records[1]['clean_environment_id'],'distinct native clean build identities')
    result=json.loads(read(comparison,4*1024**2));need(result['status']=='contents-reproduced'and not result['errors']and len(result['packages'])==1,'complete successful existing strict comparator')
    name,values=next(iter(result['packages'].items()));need(name=='cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz'and all(values[k]is True for k in('installed_contents_equal','pkginfo_equal','buildinfo_equal','bytes_equal')),'current exact package archive/payload/PKGINFO/BUILDINFO all equal')
    for root in (first,second):
        archive_path=root/'artifacts'/name
        need(archive_path.is_file()and not archive_path.is_symlink(),'ordinary Fish XZ archive required after strict comparison')
        with archive_path.open('rb') as archive:
            need(archive.read(6)==b'\xfd7zXZ\x00','actual Fish XZ header required after strict comparison')
    return dict(status='FISH02_NATIVE_PAIR_AND_CHECK_POSTCONDITIONS_PASSED',semantic_checks=checks,image_id=image,builds=2,comparison=result,hardware_status='NOT RUN',Root_acceptance=None)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('first',type=Path);p.add_argument('second',type=Path);p.add_argument('comparison',type=Path);p.add_argument('--image',required=True);a=p.parse_args()
    print(json.dumps(finish(a.first,a.second,a.comparison,a.image),sort_keys=True,indent=2))
