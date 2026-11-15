# SPDX-License-Identifier: MIT
"""Mode-preserving DATA controls. Never call preparation main or run a tool."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v2_prepare',HERE/'payload/xs/prepare_inputs.py')
prep=importlib.util.module_from_spec(spec);spec.loader.exec_module(prep)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def row(body,mode):return dict(type='file',mode=mode,**pin(body))
def manifest_row(value):return {key:value[key] for key in ('bytes','sha256','mode')}


class Controls(unittest.TestCase):
    def test_exact_reviewed_manifest(self):
        raw=(HERE/'runtime-files.json').read_bytes()
        files=prep.reviewed_manifest(raw,SimpleNamespace(pin=pin,decode=json.loads))
        self.assertEqual(len(files),1870);self.assertEqual(sum(x['bytes'] for x in files.values()),74426813)
        self.assertEqual({mode:sum(x['mode']==mode for x in files.values()) for mode in prep.RUNTIME_MODES},prep.RUNTIME_MODES)

    def test_readonly_module_header_and_executable_modes_preserved(self):
        cases=[('usr/lib/perl5/5.42/core_perl/B.pm',b'# modeled module\n',0o444),
               ('usr/lib/perl5/5.42/core_perl/CORE/perl.h',b'/* modeled header */\n',0o444),
               ('usr/lib/perl5/5.42/core_perl/auto/Model/Model.so',b'\x7fELF modeled non-executed bytes',0o555),
               ('usr/bin/perl',b'modeled executable bytes',0o755),
               ('usr/share/perl5/core_perl/Model.pm',b'modeled module',0o644)]
        with tempfile.TemporaryDirectory() as directory:
            for name,body,mode in cases:
                with self.subTest(mode=oct(mode),name=name):
                    value=row(body,mode);prep.copy_runtime(Path(directory),name,body,value,{name:manifest_row(value)})
                    target=Path(directory)/name;info=target.lstat()
                    self.assertTrue(stat.S_ISREG(info.st_mode));self.assertEqual(info.st_uid,os.getuid());self.assertEqual(info.st_nlink,1)
                    self.assertEqual(stat.S_IMODE(info.st_mode),mode);self.assertEqual(target.read_bytes(),body)

    def test_actual_first_offender_descriptor_now_allowed_without_actor(self):
        name='usr/lib/perl5/5.42/core_perl/B.pm'
        value=dict(type='file',mode=0o444,bytes=31346,sha256='0a8e0afeb5115f039d64d2495675b894000e22fb3e3726c8a85a55ef511108a3')
        self.assertNotIn(value['mode'],(0o644,0o755))  # The failed v1 predicate.
        self.assertEqual(prep.runtime_row(name,value,{name:manifest_row(value)}),manifest_row(value))

    def test_other_modes_and_special_members_refused(self):
        name='usr/lib/perl5/5.42/core_perl/Model.pm'
        for mode in (0o640,0o666,0o777,stat.S_IFREG|0o444):
            with self.subTest(mode=oct(mode)):
                value=row(b'model',mode)
                with self.assertRaisesRegex(ValueError,'Model.pm.*mode='):prep.runtime_row(name,value,{name:manifest_row(value)})
        for kind in ('symlink','hardlink','fifo','device','directory'):
            value=dict(row(b'model',0o444),type=kind)
            with self.subTest(kind=kind),self.assertRaises(ValueError):prep.runtime_row(name,value,{name:manifest_row(value)})

    def test_wrong_byte_hash_mode_and_member_manifest_refused(self):
        name='usr/lib/perl5/5.42/core_perl/Model.pm';value=row(b'model',0o444)
        for key,replacement in (('bytes',6),('sha256','0'*64),('mode',0o644)):
            wrong=manifest_row(value);wrong[key]=replacement
            with self.subTest(key=key),self.assertRaises(ValueError):prep.runtime_row(name,value,{name:wrong})
        with self.assertRaises(ValueError):prep.runtime_row(name,value,{name+'.other':manifest_row(value)})

    def test_whole_manifest_pin_refuses_changed_path_byte_or_mode(self):
        value=json.loads((HERE/'runtime-files.json').read_bytes());name=next(iter(value['files']))
        for key,replacement in (('bytes',value['files'][name]['bytes']+1),('mode',0o666)):
            wrong=copy.deepcopy(value);wrong['files'][name][key]=replacement
            with self.subTest(key=key),self.assertRaises(ValueError):prep.reviewed_manifest(json.dumps(wrong).encode(),SimpleNamespace(pin=pin,decode=json.loads))
        wrong=copy.deepcopy(value);wrong['files']['../escape']=wrong['files'].pop(name)
        with self.assertRaises(ValueError):prep.reviewed_manifest(json.dumps(wrong).encode(),SimpleNamespace(pin=pin,decode=json.loads))

    def test_copy_refuses_wrong_body_before_materializing(self):
        name='usr/lib/perl5/5.42/core_perl/Model.pm';value=row(b'model',0o444)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):prep.copy_runtime(Path(directory),name,b'other',value,{name:manifest_row(value)})
            self.assertEqual(list(Path(directory).iterdir()),[])


if __name__=='__main__':unittest.main()
