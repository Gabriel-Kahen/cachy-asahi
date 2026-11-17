# SPDX-License-Identifier: MIT
"""Bounded DATA/refusal controls; no operational actors or synthetic native credit."""
import gzip
import fnmatch
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('local_source79_controls', HERE/'reconstruct.py')
R = importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
sys.addaudithook(R.no_actors)


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='source79-local-data-controls-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def tiny(self, raw):
        body = gzip.compress(raw, mtime=0)
        path = self.root/'model.json.gz';path.write_bytes(body)
        return path, R.pin(body), R.pin(raw)

    def test_genuine_retained_catalog_whole_bytes_and_header(self):
        lock = R.json.loads(R.read(HERE/'inputs.lock.json', R.LOCK_PIN))
        selected = lock['catalog'];compressed = selected['compressed']
        source = HERE/compressed['member'];out = self.root/'catalog.json'
        R.decode_catalog(source,{k:compressed[k]for k in('bytes','sha256')},selected['raw'],out)
        with out.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        self.assertEqual(dict(bytes=out.stat().st_size,sha256=digest),selected['raw'])
        header=source.read_bytes()[:10]
        self.assertEqual(header[4:8],b'\0'*4);self.assertFalse(header[3]&8)

    def test_compressed_drift_refuses_before_output(self):
        path, compressed, raw = self.tiny(b'MODEL DATA\n')
        path.write_bytes(path.read_bytes()[:-1]+b'X')
        out=self.root/'never'
        with self.assertRaises(ValueError):R.decode_catalog(path,compressed,raw,out)
        self.assertFalse(out.exists())

    def test_expanded_byte_bound_refuses(self):
        path,compressed,_=self.tiny(b'MODEL'*1000)
        out=self.root/'bounded'
        with self.assertRaisesRegex(ValueError,'DECOMPRESSION_BOUND'):
            R.decode_catalog(path,compressed,R.pin(b'M'),out)
        self.assertLessEqual(out.stat().st_size,1)

    def test_raw_whole_hash_cannot_be_substituted(self):
        path,compressed,raw=self.tiny(b'MODEL DATA\n')
        out=self.root/'partial'
        with self.assertRaisesRegex(ValueError,'WHOLE_RETAINED_CATALOG_PIN'):
            R.decode_catalog(path,compressed,dict(raw,sha256='0'*64),out)
        self.assertFalse((self.root/'reconstruction.DATA.json').exists())

    def test_alias_hardlink_and_mode_refuse(self):
        path=self.root/'ordinary';path.write_bytes(b'MODEL')
        expected=R.pin(b'MODEL')
        link=self.root/'alias';link.symlink_to(path)
        with self.assertRaises(ValueError):R.read(link,expected)
        link.unlink();R.os.link(path,link)
        with self.assertRaises(ValueError):R.read(path,expected)
        link.unlink();path.chmod(0o600)
        with self.assertRaises(ValueError):R.read(path,expected)

    def test_existing_destination_is_not_adopted(self):
        out=self.root/'output';out.mkdir();sentinel=out/'keep';sentinel.write_bytes(b'KEEP')
        with self.assertRaisesRegex(ValueError,'FRESH_DISJOINT'):
            R.reconstruct(repo=HERE.parents[2],output=out)
        self.assertEqual(sentinel.read_bytes(),b'KEEP')

    def test_both_automatic_events_watch_every_pinned_operand(self):
        repo=HERE.parents[2]
        lock=R.json.loads(R.read(HERE/'inputs.lock.json',R.LOCK_PIN))
        mapping=R.json.loads((repo/lock['source72_map']['member']).read_bytes())
        virtual={'inputs/catalog333.DATA.json','inputs/prospective477.expected.DATA.lock',
                 'inputs/stages/baseline349.expected.lock'}
        operands=(set(mapping['files'])-virtual)|set(lock['helpers'])|{
            lock['source72_map']['member'],lock['baseline_alias']['member'],
            'scripts/ci/bankstown-qt3-source79-local-data/inputs/catalog333.DATA.json.gz',
            '.github/workflows/native-arm-bankstown-qt3-hosted-v1.yml'}
        paths={'pull_request':[],'push':[]};event=None
        for line in (repo/'.github/workflows/bankstown-qt3-hosted-source-data.yml').read_text().splitlines():
            if line.startswith('  ')and not line.startswith('   ')and line.endswith(':'):
                event=line.strip()[:-1]
            if event in paths and line.startswith("      - '"):
                paths[event].append(line.strip()[3:-1])
        for event,patterns in paths.items():
            missing=sorted(n for n in operands if not any(fnmatch.fnmatchcase(n,p)for p in patterns))
            self.assertEqual(missing,[],event)

    def test_actor_events_refuse_without_entering_actor(self):
        for event in ('subprocess.Popen','socket.connect','ctypes.dlopen','fcntl.flock'):
            with self.subTest(event=event),self.assertRaisesRegex(ValueError,'ACTOR_FREE'):
                sys.audit(event,None)


if __name__ == '__main__':
    unittest.main()
