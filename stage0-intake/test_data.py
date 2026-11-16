# SPDX-License-Identifier: MIT
"""Author-owned DATA parser controls; no publisher binaries or installers run."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

audit = module('audit')
join = module('join')


class DataTests(unittest.TestCase):
    def test_archive_paths_cannot_escape_or_hide_control_bytes(self):
        self.assertEqual(audit.safe_name('root/a/b', 'root'), 'root/a/b')
        for name in ['/root/a', 'root/../a', 'other/a', 'root/a\nb', 'root/a\\b']:
            with self.assertRaises(ValueError):
                audit.safe_name(name, 'root')

    def test_elf_program_header_size_and_16k_condition(self):
        data = bytearray(256)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 256, 256, 65536)
        elf = audit.elf_headers(data, 256)
        self.assertEqual(elf['machine'], 183)
        self.assertTrue(audit.alignment_16k(elf))
        elf['program_headers'][0]['align'] = 4096
        self.assertFalse(audit.alignment_16k(elf))
        elf['program_headers'][0].update(align=65536, offset=4096)
        self.assertFalse(audit.alignment_16k(elf))
        struct.pack_into('<H', data, 54, 0)
        with self.assertRaisesRegex(ValueError, 'program headers'):
            audit.elf_headers(data, 256)

    def test_dynamic_needed_rpath_and_runpath_remain_distinct(self):
        strings = b'libfixture.so\0RPATH_ONLY\0RUNPATH_ONLY\0'
        first = strings.index(b'RPATH_ONLY')
        second = strings.index(b'RUNPATH_ONLY')
        prefix = bytearray(512)
        prefix[256:256+len(strings)] = strings
        dynamic = b''.join(struct.pack('<qQ', tag, value) for tag, value in [(5,256),(10,len(strings)),(1,0),(15,first),(29,second),(0,0)])
        elf = {'program_headers': [{'type':1,'vaddr':0,'offset':0,'filesz':512,'align':65536},{'type':2}]}
        self.assertIsNone(audit.dynamic_metadata(elf, {'dynamic':dynamic}, prefix))
        self.assertEqual(elf['needed'], ['libfixture.so'])
        self.assertEqual(elf['rpath'], ['RPATH_ONLY'])
        self.assertEqual(elf['runpath'], ['RUNPATH_ONLY'])
        elf = {'program_headers': [{'type':1,'vaddr':0,'offset':0,'filesz':260,'align':65536},{'type':2}]}
        with self.assertRaisesRegex(ValueError, 'mapped segment'):
            audit.dynamic_metadata(elf, {'dynamic':dynamic}, prefix)

    def test_stream_capture_range_boundaries(self):
        result = b''.join(audit.overlap(chunk, offset, 2, 7) for offset, chunk in [(0,b'abc'),(3,b'def'),(6,b'ghi')])
        self.assertEqual(result, b'cdefg')

    def test_manifest_reports_missing_and_uncovered_payload(self):
        rows = [{'path':'root/tool/bin','kind':'dir'},{'path':'root/tool/bin/one','kind':'file'}]
        text = {'root/tool/manifest.in':b'dir:bin\n'}
        result = audit.manifest_audit(rows,text,'root','tool')
        self.assertEqual(result['missing_or_wrong_kind'], [])
        self.assertEqual(result['uncovered_payload_members'], [])
        text['root/tool/manifest.in'] = b'file:missing\n'
        result = audit.manifest_audit(rows,text,'root','tool')
        self.assertEqual(result['missing_or_wrong_kind'], ['file:missing'])
        self.assertEqual(result['uncovered_payload_members'], ['bin/one'])

    def test_model_collision_and_filesystem_digest_crosscheck(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'lib').mkdir(mode=0o755)
            (root/'lib/file').write_bytes(b'DATA only')
            (root/'lib/file').chmod(0o644)
            filehash = hashlib.sha256(b'DATA only').hexdigest()
            rows = [{'path':'root/tool/lib','kind':'dir','mode':0o755},{'path':'root/tool/lib/file','kind':'file','mode':0o644,'sha256':filehash}]
            nodes, observed = join.model_join([('root','tool',rows)])
            expected = hashlib.sha256((json.dumps(['lib','dir',0o755,''],separators=(',',':'))+'\n'+json.dumps(['lib/file','file',0o644,filehash],separators=(',',':'))+'\n').encode()).hexdigest()
            self.assertEqual(observed, expected)
            self.assertEqual(len(nodes), 2)
            changed = dict(rows[1],sha256='f'*64)
            with self.assertRaisesRegex(ValueError, 'collision'):
                join.model_join([('root','tool',rows),('root','tool',[changed])])

    def test_actual_records_keep_qualification_held(self):
        facts = json.loads((HERE/'data-admission.json').read_bytes())
        self.assertEqual(facts['compatibility'], 'UNQUALIFIED')
        self.assertEqual(facts['publisher_execution'], 0)
        self.assertFalse(facts['existing_candidate_selector_and_admission_example_changed'])
        self.assertEqual(sum(r['ELF_regular_files'] for r in facts['archives'].values()),14)
        self.assertEqual(sum(r['nested_ar_files_not_audited'] for r in facts['archives'].values()),33)
        self.assertTrue(all(r['status']=='UNRESOLVED' for r in facts['holds_preserved']['original_binary_recipe_correspondence'].values()))


if __name__ == '__main__':
    unittest.main()
