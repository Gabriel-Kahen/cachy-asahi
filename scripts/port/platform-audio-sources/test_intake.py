#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Self-contained intake controls. Tiny archive fixtures are synthetic data."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('audio_intake_tests',HERE/'intake.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
PIN='e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8'
RAW=(HERE/'native-inputs.json').read_bytes()


class Intake(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='audio-intake-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_exact_profile_and_current_project_apis(self):
        value=a.profile(RAW,PIN)
        with mock.patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')):
            self.assertEqual(set(a.load_api(value).profiles()),set(a.VERSIONS))
        self.assertEqual({k:v['expected_generic_error_count']for k,v in value['packages'].items()},
                         {'alsa-ucm-conf-asahi':54,'asahi-audio':10,'bankstown':0,'speakersafetyd':5,'triforce-lv2':0})
        self.assertEqual(sum(len(v['compiled_payloads'])for v in value['packages'].values()),3)

    def test_profile_digest_required(self):
        with self.assertRaisesRegex(a.Refused,'PROFILE_PIN'):a.profile(RAW,'0'*64)

    def test_finite_profile_identity_not_extendable(self):
        for edit in (lambda d:d['packages'].pop('bankstown'),
                     lambda d:d['packages']['bankstown'].update(version='1.1.0-5'),
                     lambda d:d['api_files'].pop('scripts/release/source_delivery.py')):
            value=json.loads(RAW);edit(value);raw=a.encoded(value)
            with self.subTest(edit=edit),self.assertRaises(a.Refused):a.profile(raw,a.sha(raw))

    def test_boolean_error_count_refused(self):
        value=json.loads(RAW);value['packages']['bankstown']['expected_generic_error_count']=False;raw=a.encoded(value)
        with self.assertRaisesRegex(a.Refused,'INVALID_NATIVE_ROW'):a.profile(raw,a.sha(raw))

    def test_changed_project_api_refused_before_import(self):
        value=a.profile(RAW,PIN)
        with mock.patch.object(a,'ordinary',return_value=b'raise AssertionError("must not execute")\n'):
            with self.assertRaisesRegex(a.Refused,'PROJECT_API_PIN'):a.load_api(value)

    def test_duplicate_and_noninteger_json_refused(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":1.5}',b'{"x":NaN}',b'[]'):
            with self.subTest(raw=raw),self.assertRaises(a.Refused):a.decode(raw)

    def test_noncanonical_relative_names_refused(self):
        for name in ('.','../x','x/../y','/x','x//y','x\\y','x/',''):
            with self.subTest(name=name),self.assertRaises(a.Refused):a.relative(name)

    def archive(self,entries):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w')as out:
            for name,body in entries:
                info=tarfile.TarInfo(name);info.size=len(body);out.addfile(info,io.BytesIO(body))
        return stream.getvalue()

    def fixture(self):
        body=b'\x7fELF SYNTHETIC DATA ONLY';raw=self.archive([('usr/lib/example.so',body)])
        return raw,dict(archive=dict(filename='synthetic.tar',**a.descriptor(raw)),compiled_payloads={'usr/lib/example.so':a.descriptor(body)})

    def test_native_digest_and_compiled_digest_independent(self):
        raw,row=self.fixture();self.assertEqual(a.native_archive(raw,row),row['compiled_payloads'])
        changed=self.archive([('usr/lib/example.so',b'\x7fELF CHANGED SYNTHETIC DATA')]);row['archive'].update(a.descriptor(changed))
        with self.assertRaisesRegex(a.Refused,'COMPILED_PAYLOAD_PIN'):a.native_archive(changed,row)

    def test_whole_archive_pin_refuses_otherwise_identical_tar(self):
        raw,row=self.fixture()
        with self.assertRaisesRegex(a.Refused,'NATIVE_ARCHIVE_PIN'):a.native_archive(raw+b'\0'*512,row)

    def test_missing_or_duplicate_compiled_member_refused(self):
        _,row=self.fixture()
        for entries in ([],[('usr/lib/example.so',b'\x7fELF SYNTHETIC DATA ONLY')]*2):
            raw=self.archive(entries);row['archive'].update(a.descriptor(raw))
            with self.subTest(entries=entries),self.assertRaises(a.Refused):a.native_archive(raw,row)

    def test_ordinary_refuses_aliases_special_and_oversized_files(self):
        path=self.root/'plain';path.write_bytes(b'abc')
        self.assertEqual(a.ordinary(path),b'abc')
        alias=self.root/'alias';alias.symlink_to(path)
        with self.assertRaisesRegex(a.Refused,'ALIASED'):a.ordinary(alias)
        alias.unlink();os.link(path,alias)
        with self.assertRaisesRegex(a.Refused,'UNSAFE'):a.ordinary(path)
        alias.unlink()
        with self.assertRaisesRegex(a.Refused,'OVERSIZED'):a.ordinary(path,2)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaisesRegex(a.Refused,'UNSAFE'):a.ordinary(fifo)

    def private_file(self,name='nested/leaf'):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(b'data');path.chmod(0o600);return path

    def test_exact_private_namespace(self):
        self.private_file();self.assertEqual(a.files(self.root),{'nested/leaf':b'data'})

    def test_extra_empty_directory_refused(self):
        self.private_file();(self.root/'extra').mkdir(mode=0o700)
        with self.assertRaisesRegex(a.Refused,'EMPTY_HANDOFF'):a.files(self.root)

    def test_public_mode_refused(self):
        path=self.private_file();path.chmod(0o644)
        with self.assertRaisesRegex(a.Refused,'FILE_TYPE_OR_MODE'):a.files(self.root)

    def test_handoff_link_refused(self):
        path=self.private_file();(self.root/'alias').symlink_to(path)
        with self.assertRaises(a.Refused):a.files(self.root)

    def test_aggregate_byte_limit(self):
        self.private_file()
        with mock.patch.object(a,'MAX_TOTAL',3),self.assertRaisesRegex(a.Refused,'BYTE_LIMIT'):a.files(self.root)

    def test_missing_archive_binding_and_changed_guard_count_refused(self):
        row=a.profile(RAW,PIN)['packages']['alsa-ucm-conf-asahi']
        saved=dict(archive_binding=None)
        with self.assertRaisesRegex(a.Refused,'BOUND_NATIVE_ASSOCIATION'):a.package_record('alsa-ucm-conf-asahi',row,saved,b'x')
        saved['archive_binding']=dict(archive_sha256=row['archive']['sha256'],archive_bytes=row['archive']['bytes'],generic_guard_errors=[])
        with self.assertRaisesRegex(a.Refused,'BOUND_NATIVE_ASSOCIATION'):a.package_record('alsa-ucm-conf-asahi',row,saved,b'x')

    def test_no_acceptance_promotion(self):
        value=a.profile(RAW,PIN);manifest=a.expected_manifest(value,PIN,'0'*40,{}, {'relative/file':b'bytes'})
        for name in ('legal_acceptance','complete_corresponding_source_accepted','payload_execution','native_build_replayed'):
            self.assertIs(manifest[name],False)
        self.assertEqual(manifest['signature_authentication'],'NOT_PERFORMED')
        self.assertEqual(manifest['compiled_source_correspondence'],'NOT_ESTABLISHED')
        self.assertNotIn(str(self.root),a.encoded(manifest).decode())

    def test_direct_python_entry_requires_isolation(self):
        result=subprocess.run([sys.executable,'-B',str(HERE/'intake.py'),'--help'],cwd='/',capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertIn('isolated mode',result.stderr)

    def test_cli_refusal_does_not_emit_operator_paths(self):
        private=self.root/'private-operator-input'
        result=subprocess.run([sys.executable,'-I','-B',str(HERE/'intake.py'),'verify','--handoff',str(private),
            '--index-sha256','0'*64,'--profile-sha256',PIN],cwd='/',capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertEqual(result.stderr,'')
        self.assertNotIn(str(private),result.stdout)
        self.assertEqual(json.loads(result.stdout)['status'],'REFUSED_PLATFORM_AUDIO_SOURCE_HANDOFF')


if __name__=='__main__':unittest.main(verbosity=2)
