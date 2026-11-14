#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check this candidate's inert source/metadata pins without shell evaluation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import tarfile

COMMIT='7406dfbcc35beed79bf2734e3e7376ead320bd99'
SHA='843306ad54a3006ef7a60ba62932a3a2015cc87d46bd438fd5ac906d952c88d6'
SIZE=13056926


def fields(text):
    result={}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key,value=line.strip().split(' = ',1);result.setdefault(key,[]).append(value)
    return result


def check(root,archive=None):
    data=fields((root/'.SRCINFO').read_text());recipe=(root/'PKGBUILD').read_text()
    assert data['pkgbase']==['networkmanager'] and data['pkgver']==['1.58.1'] and data['pkgrel']==['2.1']
    assert data['pkgname']==['networkmanager','libnm','nm-cloud-setup','networkmanager-docs'] and data['arch']==['aarch64']
    assert 'install' not in data and 'etc/NetworkManager/NetworkManager.conf' in data['backup']
    assert data['source'][0].endswith('/NetworkManager-'+COMMIT+'.tar.gz') and data['sha256sums'][0]==SHA
    for key in ['source','sha256sums','makedepends','checkdepends','options']:
        declared=re.search(r'^'+key+r'=\((.*?)\)',recipe,re.M|re.S)
        assert declared and shlex.split(declared[1])==data[key],key
    assert len(data['source'])==len(data['sha256sums'])==12
    for name,pin in zip(data['source'][1:],data['sha256sums'][1:]):
        path=root/name;assert path.parent==root and path.is_file() and not path.is_symlink(),name
        assert hashlib.sha256(path.read_bytes()).hexdigest()==pin,name
    assert '--no-rebuild --num-processes' not in recipe
    provenance=json.loads((root/'source-provenance.json').read_text());assert provenance['source']['sha256']==SHA
    for name,pin in provenance['upstream_notices'].items():
        assert hashlib.sha256((root/name).read_bytes()).hexdigest()==pin,name
    spec=importlib.util.spec_from_file_location('nm_candidate_profile',root/'check_profile.py');profile=importlib.util.module_from_spec(spec);spec.loader.exec_module(profile)
    value=profile.profile(root/'feature-options.json')
    status='HOLD source archive not supplied'
    if archive:
        archive=archive.resolve(strict=True);assert archive.stat().st_size==SIZE
        with archive.open('rb')as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==SHA
        with tarfile.open(archive)as source:
            prefix='NetworkManager-'+COMMIT+'/'
            for name in provenance['upstream_notices']:
                assert source.extractfile(prefix+name).read(65536)==(root/name).read_bytes(),name
            options=source.extractfile(prefix+'meson_options.txt').read(65536).decode()
            declared=set(re.findall(r"^option\('([^']+)'",options,re.M))|{'b_lto'}
            assert set(value['options'])<=declared
        status='PASS exact source/notice/metadata checks only'
    return {'status':status,'version':'1.58.1-2.1','source_sha256':SHA,'historical_ALARM_correspondence':'UNBOUND','native_ARM':'NOT RUN','hardware':'NOT RUN'}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path);p.add_argument('--recipe',type=Path,default=Path(__file__).resolve().parent);args=p.parse_args()
    print(json.dumps(check(args.recipe,args.archive),sort_keys=True))
