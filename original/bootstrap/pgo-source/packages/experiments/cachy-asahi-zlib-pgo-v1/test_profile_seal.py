# SPDX-License-Identifier: MIT
"""Synthetic profile-byte refusal controls; never decode, build, train or execute."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import profile_seal as S


def binding():
    file=dict(bytes=123,sha256='1'*64)
    tools={name:dict(path='/usr/bin/'+name,resolved_path='/usr/lib/tools/'+name,
        bytes=32*1024**2 if name=='cc1' else 123,sha256='2'*64,version='synthetic identity only')for name in S.TOOLS}
    return dict(source_sha256=S.SOURCE_SHA256,source_files={'adler32.c':file},
        toolchain=dict(target='aarch64-unknown-linux-gnu',tools=tools),isa='armv8-a/generic',build_path='/tmp/build',
        profile_path='/tmp/profile',prefix='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1',
        training=dict(corpus=dict(path='training.bin',bytes=100,sha256='3'*64),
            heldout=dict(path='validation.bin',bytes=101,sha256='4'*64),
            command_plan_sha256='5'*64,results_sha256='6'*64))


class ProfileSealControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='profile-control-',dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.directory=self.root/'profiles';self.directory.mkdir();self.output=self.root/'sealed.json';self.binding=binding()
        # Header-shaped inert bytes only: this is not a valid GCC profile decoder fixture.
        for index,name in enumerate(S.PROFILE_NAMES):
            (self.directory/name).write_bytes(b'adcg*Z9A'+index.to_bytes(4,'little')+b'synthetic-control-data')
        self.enterContext(patch('subprocess.Popen',side_effect=AssertionError('process execution forbidden')))
        self.enterContext(patch('socket.socket',side_effect=AssertionError('network forbidden')))

    def test_complete17_profiles_original_seal_pin_and_no_replace(self):
        report=S.seal(self.directory,self.binding,self.output)
        again=S.verify(self.directory,self.binding,self.output,expected_sha256=report['seal_sha256'])
        self.assertEqual(report,again);self.assertEqual(report['profiles'],17)
        self.assertEqual(report['profile_decoding'],'NOT_ESTABLISHED_BY_HEADER_OR_HASH')
        self.assertEqual(report['native_execution'],'NOT RUN')
        self.assertEqual(self.output.stat().st_mode&0o777,0o400)
        with self.assertRaises(FileExistsError):S.seal(self.directory,self.binding,self.output)

    def test_missing_extra_nonregular_alias_and_hardlink_profiles_refuse(self):
        target=self.directory/S.PROFILE_NAMES[0];raw=target.read_bytes()
        target.unlink()
        with self.assertRaises(ValueError):S.profiles(self.directory)
        target.write_bytes(raw);extra=self.directory/'unexpected.gcda';extra.write_bytes(raw)
        with self.assertRaises(ValueError):S.profiles(self.directory)
        extra.unlink();target.unlink();target.mkdir()
        with self.assertRaises(ValueError):S.profiles(self.directory)
        target.rmdir();origin=self.root/'origin';origin.write_bytes(raw);target.symlink_to(origin)
        with self.assertRaises(OSError):S.profiles(self.directory)
        target.unlink();os.link(origin,target)
        with self.assertRaises(ValueError):S.profiles(self.directory)
        target.unlink();os.mkfifo(target)
        with self.assertRaises(ValueError):S.profiles(self.directory)

    def test_corrupt_short_mixed_version_or_unknown_version_refuse(self):
        target=self.directory/S.PROFILE_NAMES[0];original=target.read_bytes()
        for raw in (b'adcg*Z9A',b'not!'+original[4:],original[:4]+b'*X9A'+original[8:],original[:4]+b'\0'*4+original[8:]):
            target.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):S.profiles(self.directory)
        target.write_bytes(original);self.assertEqual(len(S.profiles(self.directory)[0]),17)

    def test_profile_bytes_mutated_after_seal_refuse(self):
        report=S.seal(self.directory,self.binding,self.output);target=self.directory/S.PROFILE_NAMES[-1]
        raw=target.read_bytes();target.write_bytes(raw[:-1]+b'!')
        with self.assertRaisesRegex(ValueError,'sealed profile bytes'):
            S.verify(self.directory,self.binding,self.output,expected_sha256=report['seal_sha256'])

    def test_source_toolchain_isa_path_training_and_sourcefile_mismatch_refuse(self):
        report=S.seal(self.directory,self.binding,self.output)
        variants=[]
        for key,value in [('source_sha256','7'*64),('isa','native'),('build_path','/tmp/other'),('profile_path','/tmp/other'),('prefix','/usr/lib')]:
            changed=copy.deepcopy(self.binding);changed[key]=value;variants.append(changed)
        for section,key,value in [('toolchain','target','x86_64-linux-gnu'),('training','command_plan_sha256','8'*64),('training','results_sha256','9'*64)]:
            changed=copy.deepcopy(self.binding);changed[section][key]=value;variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['toolchain']['tools']['gcc']['sha256']='a'*64;variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['toolchain']['tools']['cc1']['version']='another compiler';variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['source_files']['adler32.c']['sha256']='b'*64;variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['training']['corpus']['sha256']='c'*64;variants.append(changed)
        for changed in variants:
            with self.subTest(binding=changed),self.assertRaises(ValueError):
                S.verify(self.directory,changed,self.output,expected_sha256=report['seal_sha256'])

    def test_unknown_null_incomplete_or_shared_training_identity_refuse(self):
        variants=[]
        for key in self.binding:
            changed=copy.deepcopy(self.binding);changed[key]=None;variants.append(changed)
            changed=copy.deepcopy(self.binding);del changed[key];variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['actual']=None;variants.append(changed)
        changed=copy.deepcopy(self.binding);del changed['toolchain']['tools']['libgcov.a'];variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['training']['heldout']['sha256']=changed['training']['corpus']['sha256'];variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['training']['heldout']['path']='training.bin';variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['source_files']={'../escape.c':dict(bytes=1,sha256='d'*64)};variants.append(changed)
        changed=copy.deepcopy(self.binding);changed['toolchain']['tools']['gcc']['sha256']='0'*64;variants.append(changed)
        for changed in variants:
            with self.subTest(binding=changed),self.assertRaises(ValueError):S.validate_binding(changed)

    def test_seal_byte_mutation_repin_and_alias_refuse_with_original_hash(self):
        report=S.seal(self.directory,self.binding,self.output);raw=self.output.read_bytes()
        self.output.chmod(0o600);self.output.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):S.verify(self.directory,self.binding,self.output,expected_sha256=report['seal_sha256'])
        self.output.write_bytes(raw)
        value=json.loads(raw);name=S.PROFILE_NAMES[0];target=self.directory/name
        target.write_bytes(target.read_bytes()+b'changed')
        value['payload']['profiles'][name]=S.pin(target.read_bytes())
        value['payload_sha256']=S.sha(S.encoded(value['payload']));self.output.write_bytes(S.encoded(value))
        # A self-hashed receipt is not an authenticity anchor; the original whole pin is required.
        with self.assertRaisesRegex(ValueError,'original whole profile seal'):
            S.verify(self.directory,self.binding,self.output,expected_sha256=report['seal_sha256'])
        alias=self.root/'alias';alias.symlink_to(self.output)
        with self.assertRaises(ValueError):S.verify(self.directory,self.binding,alias)


if __name__=='__main__':unittest.main()
