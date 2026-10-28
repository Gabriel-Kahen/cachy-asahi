# SPDX-License-Identifier: MIT
"""Passive guest source/plan controls; every process, file and codec actor is mocked."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib_pgo_guest as G


def expected(role):
    prefix=G.PREFIXES[role]
    return dict(schema=1,role=role,variant=G.VARIANTS[role],prefix=prefix,publication_source='1'*40,source_sha256=G.SOURCE_SHA,
        programs={name:dict(path=prefix+'/bin/'+name,bytes=10,sha256='2'*64)for name in G.PROGRAMS},
        profile_seal='NOT_APPLICABLE_BASELINE'if role=='baseline'else dict(path=prefix+'/build/profile-seal.json',bytes=500,sha256='3'*64,binding_sha256='4'*64))


class FakeDecoder:
    eof=True;unused_data=b'';unconsumed_tail=b''
    def decompress(self,raw,cap):
        if not raw.startswith(b'CONTROL_ONLY:'):raise ValueError('synthetic codec fixture only')
        return raw[len(b'CONTROL_ONLY:'):]


class FakeRunner:
    """No processes or codecs: recognizable framing and expected plaintext only."""
    def __init__(self):self.rows=[]
    def run(self,label,argv,**kwargs):
        self.rows.append(dict(label=label,argv=argv,expected=kwargs.get('expected',0)))
        if label.startswith('probe-'):
            role=label[len('probe-'):]
            return G.canonical(dict(status='PASS',variant=G.VARIANTS[role],prefix=G.PREFIXES[role],zlib='1.3.2',source_sha256=G.SOURCE_SHA,roundtrips=21,negative_checks=42))
        if label.endswith('-encode'):return b'CONTROL_ONLY:'+kwargs['data']
        if '-decode-'in label:return kwargs['data'][len(b'CONTROL_ONLY:'):]
        if label.startswith('reject-'):
            assert kwargs['expected']==2;return G.reference()[0]
        raise AssertionError(label)


class GuestControls(unittest.TestCase):
    def native(self,**overrides):
        values=dict(system='Linux',machine='aarch64',page=16384,uid=1000,euid=1000,marker='1');values.update(overrides)
        stack=[patch.object(G.platform,'system',return_value=values['system']),patch.object(G.platform,'machine',return_value=values['machine']),
            patch.object(G.os,'sysconf',return_value=values['page']),patch.object(G.os,'getuid',return_value=values['uid']),patch.object(G.os,'geteuid',return_value=values['euid']),
            patch.dict(G.os.environ,{'CACHY_ASAHI_PGO_GENERIC16K':values['marker']})]
        for context in stack:self.enterContext(context)

    def test_explicit_native_ordinary_16k_guard_and_no_default_execution(self):
        self.native();G.guard(True)
        with self.assertRaises(ValueError):G.guard(False)
        for function,value in((G.os.sysconf,4096),(G.os.geteuid,0),(G.platform.machine,'x86_64')):
            function.return_value=value
            with self.assertRaises(ValueError):G.guard(True)
            function.return_value=16384 if function is G.os.sysconf else(1000 if function is G.os.geteuid else'aarch64')
        with patch.dict(G.os.environ,{'CACHY_ASAHI_PGO_GENERIC16K':''}),self.assertRaises(ValueError):G.guard(True)

    def test_manifest_closed_pins_roles_prefix_and_missing_profile_refuse(self):
        for role in G.PREFIXES:
            value=expected(role)
            with patch.object(G,'read',return_value=G.canonical(value)):
                parsed,_=G.manifest('/external/root-controlled-manifest',role);self.assertEqual(parsed,value)
        for field,value in(('publication_source',None),('prefix','/usr/lib'),('source_sha256','0'*64),('profile_seal',None),('schema',True)):
            bad=expected('candidate');bad[field]=value
            with self.subTest(field=field),patch.object(G,'read',return_value=G.canonical(bad)),self.assertRaises(ValueError):G.manifest('/external/control','candidate')
        bad=expected('baseline');bad['programs']['probe']['sha256']='0'*64
        with patch.object(G,'read',return_value=G.canonical(bad)),self.assertRaises(ValueError):G.manifest('/external/control','baseline')
        with patch.object(G,'read',side_effect=FileNotFoundError('missing expected manifest')),self.assertRaises(OSError):G.manifest('/missing','candidate')
        with patch.object(Path,'is_symlink',return_value=True),self.assertRaisesRegex(ValueError,'aliases'):G.read('/external/alias')

    def test_installed_file_hash_source_and_profile_mismatch_refuse(self):
        source=b'CONTROL_ONLY_SOURCE';program=b'CONTROL_ONLY_EXECUTABLE'
        with patch.object(G,'SOURCE_SHA',G.sha(source)),patch.object(G,'SOURCE_BYTES',len(source)):
            value=expected('baseline')
            for row in value['programs'].values():row.update(G.pin(program))
            def read(path,cap=0):return source if str(path).endswith('zlib-1.3.2.tar.gz')else program
            with patch.object(G,'read',side_effect=read),patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=0o100755)):
                G.installed(value)
                bad=copy.deepcopy(value);bad['programs']['probe']['sha256']='4'*64
                with self.assertRaises(ValueError):G.installed(bad)
            candidate=expected('candidate')
            for row in candidate['programs'].values():row.update(G.pin(program))
            with patch.object(G,'read',side_effect=read),patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=0o100755)),self.assertRaises(ValueError):G.installed(candidate)
            binding=dict(source_sha256=G.SOURCE_SHA,isa='armv8-a/generic',prefix=G.PREFIXES['candidate'],build_path='/tmp/build',profile_path='/tmp/profile')
            payload=dict(schema_version=1,purpose='frozen-zlib-pgo-profile-v1',binding=binding,binding_sha256=G.sha(G.canonical(binding)),profiles={},gcda_version_hex='CONTROL_ONLY')
            def envelope():return G.canonical(dict(payload=payload,payload_sha256=G.sha(G.canonical(payload))))
            sealed=envelope();candidate['profile_seal'].update(G.pin(sealed),binding_sha256=payload['binding_sha256'])
            def sealed_read(path,cap=0):
                return sealed if str(path).endswith('profile-seal.json')else read(path,cap)
            with patch.object(G,'read',side_effect=sealed_read),patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=0o100755)):
                G.installed(candidate)
                # Re-pin an internally consistent but wrong-source profile: the fixed source rule must still refuse.
                binding['source_sha256']='7'*64;payload['binding_sha256']=G.sha(G.canonical(binding));sealed=envelope();candidate['profile_seal'].update(G.pin(sealed),binding_sha256=payload['binding_sha256'])
                with self.assertRaisesRegex(ValueError,'profile pinned source'):G.installed(candidate)

    def test_finite_plan_keeps_every_case_level_variant_and_refusal(self):
        plan=G.workload_plan();self.assertEqual(len(plan),134)
        self.assertEqual(len({r['label']for r in plan}),134)
        self.assertEqual(sum(r['label'].endswith('-encode')for r in plan),42)
        self.assertEqual(sum('-decode-'in r['label']for r in plan),84)
        self.assertEqual(sum(r['expected']==2 for r in plan),6)
        self.assertEqual([len(v)for v in G.corpus()],[0,1,114688,262144,16383,16384,16385])
        self.assertTrue(all(r['argv'][0].startswith(tuple(G.PREFIXES.values()))for r in plan))
        self.assertTrue(all(r['argv'][0].endswith('/bin/strict-gzip')for r in plan if r['expected']==2))

    def test_mocked_complete_workload_counts_and_wrong_plaintext_refuses(self):
        runner=FakeRunner()
        with patch.object(G.zlib,'decompressobj',return_value=FakeDecoder()):report=G.workload(runner)
        self.assertEqual(report['counts'],dict(encodes=42,cross_decodes=84,python_decodes=42,strict_rejections=6,installed_probes=2))
        self.assertEqual(len(runner.rows),134);self.assertEqual(len(report['observations']),42)
        class Bad(FakeRunner):
            def run(self,label,argv,**kwargs):return b''if'-decode-'in label else super().run(label,argv,**kwargs)
        with patch.object(G.zlib,'decompressobj',return_value=FakeDecoder()),self.assertRaisesRegex(ValueError,'cross-variant'):G.workload(Bad())

    def test_mocked_invalid_stream_exit2_alone_cannot_replace_plaintext(self):
        class Bad(FakeRunner):
            def run(self,label,argv,**kwargs):return b''if label.startswith('reject-')else super().run(label,argv,**kwargs)
        with patch.object(G.zlib,'decompressobj',return_value=FakeDecoder()),self.assertRaisesRegex(ValueError,'complete reference plaintext'):G.workload(Bad())

    def test_4k_or_missing_manifest_precedes_output_and_runner(self):
        with patch.object(G,'guard',side_effect=ValueError('actual 4K refused')),patch.object(G,'manifest')as manifest,patch.object(Path,'mkdir')as mkdir,patch.object(G,'supervisor')as supervisor:
            with self.assertRaises(ValueError):G.run('/b','/c','/out',execute=True)
            manifest.assert_not_called();mkdir.assert_not_called();supervisor.assert_not_called()
        with patch.object(G,'guard'),patch.object(G,'manifest',side_effect=FileNotFoundError('missing expected manifest')),patch.object(Path,'mkdir')as mkdir,patch.object(G,'supervisor')as supervisor:
            with self.assertRaises(OSError):G.run('/b','/c','/out',execute=True)
            mkdir.assert_not_called();supervisor.assert_not_called()


if __name__=='__main__':unittest.main()
