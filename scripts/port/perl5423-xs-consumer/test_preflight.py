#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Few synthetic pin/substitution controls; no Perl or compiler runs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_input_controls',HERE/'preflight.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('actor forbidden in XS DATA controls: '+event)
sys.addaudithook(fence)


def fixture(parent):
    root=parent/'root';root.mkdir(mode=0o700);work=parent/'work';work.mkdir(mode=0o700);source=parent/'source';source.mkdir()
    body=bytearray(64);body[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<H',body,18,62)
    names=['usr/bin/perl',p.CORE+'/perl.h',p.CORE+'/EXTERN.h',p.CORE+'/XSUB.h',p.CORE+'/config.h',p.CORE+'/patchlevel.h',p.CORE+'/libperl.so',p.ARCH+'/Config.pm',p.ARCH+'/Config_heavy.pl',p.PURE+'/ExtUtils/MakeMaker.pm']
    files={}
    for name in names:
        leaf=root/name;leaf.parent.mkdir(parents=True,exist_ok=True);raw=bytes(body) if name in ('usr/bin/perl',p.CORE+'/libperl.so') else b'MODELED candidate DATA\n';leaf.write_bytes(raw);mode=0o755 if name=='usr/bin/perl' else 0o644;leaf.chmod(mode);files[name]=dict(**p.pin(raw),mode=mode)
    def pinned(name,raw,executable=False):
        path=parent/name;path.write_bytes(raw);path.chmod(0o755 if executable else 0o644);return dict(path=str(path),**p.pin(raw))
    archive=pinned('perl-5.42.3-1.3-x86_64.pkg.tar.zst',b'MODELED archive DATA');archive['name']=Path(archive['path']).name
    inputs=dict(schema=1,archive_sha256=archive['sha256'],candidate_recipe_sha256=p.CANDIDATE['recipe_sha256'],files=files);ir=p.encode(inputs);ip=parent/'inputs.json';ip.write_bytes(ir)
    identity=root.stat();a=dict(schema=1,candidate=p.CANDIDATE,target_arch='x86_64',root=dict(path=str(root),kind='extracted',owner_uid=identity.st_uid,device=identity.st_dev,inode=identity.st_ino),archive=archive,inputs_sha256=p.pin(ir)['sha256'],metadata=dict(pkginfo=pinned('PKGINFO',b'pkgname = perl\npkgver = 5.42.3-1.3\narch = x86_64\n'),buildinfo=pinned('BUILDINFO',('pkgver = 5.42.3-1.3\npkgarch = x86_64\npkgbuild_sha256sum = '+p.CANDIDATE['recipe_sha256']+'\n').encode())),inventory=pinned('inventory.lock',b'MODELED inventory\n'),toolchain={k:pinned(k,b'MODELED explicit tool '+k.encode(),True) for k in ('cc','ld','make')},artifact=dict(kind='host',source=None,run=None,job=None))
    for name in p.FIXTURE:
        for base in (source,work):
            leaf=base/name;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(b'MODELED original fixture '+name.encode())
    ap=parent/'admission.json';ap.write_bytes(p.encode(a))
    return a,inputs,work,source,ap,ip


class Pins(unittest.TestCase):
    def test_positive_plan_is_data_only_and_names_candidate_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,inputs,work,source,ap,ip=fixture(Path(tmp))
            with patch.object(p,'HERE',source):result=p.plan(ap,p.pin(ap.read_bytes())['sha256'],ip,p.pin(ip.read_bytes())['sha256'],work)
            self.assertEqual(result['status'],'PREFLIGHT_DATA_ONLY_XS_NOT_RUN');self.assertFalse(result['native_acceptance']);self.assertEqual(result['commands'][0][0],a['root']['path']+'/usr/bin/perl')
            self.assertEqual(result['environment']['LD_LIBRARY_PATH'],a['root']['path']+'/'+p.CORE);self.assertNotIn('PERL5OPT',result['environment']);self.assertEqual(result['commands'][1][0],a['toolchain']['make']['path'])

    def test_null_future_native_selectors_and_wrong_version_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,inputs,work,source,_,_=fixture(Path(tmp))
            for change in (lambda x:x.update(artifact=dict(kind='native',source=None,run=None,job=None)),lambda x:x.update(artifact=dict(kind='native',source='1'*40,run='123',job='456')),lambda x:x.update(candidate=dict(x['candidate'],recipe_sha256='0'*64)),lambda x:x['root'].update(path='/')):
                changed=copy.deepcopy(a);change(changed)
                with patch.object(p,'HERE',source),self.assertRaises(ValueError):p.validate(changed,inputs,work)

    def test_core_header_modification_or_alias_refuses(self):
        for alias in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                a,inputs,work,source,_,_=fixture(Path(tmp));header=Path(a['root']['path'])/p.CORE/'perl.h'
                if alias:header.unlink();header.symlink_to(Path(tmp)/'inventory.lock')
                else:header.write_bytes(b'BASELINE HEADER')
                with patch.object(p,'HERE',source),self.assertRaises(ValueError):p.validate(a,inputs,work)

    def test_foreign_module_and_substituted_compiler_refuse(self):
        for mode in ('module','compiler','metadata'):
            with tempfile.TemporaryDirectory() as tmp:
                a,inputs,work,source,_,_=fixture(Path(tmp))
                if mode=='module':(Path(a['root']['path'])/p.ARCH/'FOREIGN.pm').write_bytes(b'foreign module')
                elif mode=='compiler':Path(a['toolchain']['cc']['path']).write_bytes(b'OTHER COMPILER')
                else:Path(a['metadata']['pkginfo']['path']).write_bytes(b'pkgver = 5.42.3-1.2\n')
                with patch.object(p,'HERE',source),self.assertRaises(ValueError):p.validate(a,inputs,work)

    def test_input_map_or_stage_replacement_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,inputs,work,source,ap,ip=fixture(Path(tmp));ip.write_bytes(p.encode(dict(inputs,archive_sha256='0'*64)))
            with patch.object(p,'HERE',source),self.assertRaises(ValueError):p.plan(ap,p.pin(ap.read_bytes())['sha256'],ip,p.pin(ip.read_bytes())['sha256'],work)
            (work/'Makefile').write_bytes(b'STALE BASELINE OUTPUT')
            with patch.object(p,'HERE',source),self.assertRaises(ValueError):p.validate(a,inputs,work)


if __name__=='__main__':unittest.main(verbosity=2)
