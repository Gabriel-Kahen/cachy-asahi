"""New source-only filesystem controls; no network, Docker, GPG, build or archive execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'scripts/maintenance/source_cache.py').is_file())
spec=importlib.util.spec_from_file_location('local_import',HERE/'import_source.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
FIXTURE=ROOT/'tests/fixtures/offline-build-v2-c01';CATALOG=FIXTURE/'inputs/source-inputs.json';CAT_SHA=hashlib.sha256(CATALOG.read_bytes()).hexdigest();ARCHIVE=ROOT/'scripts/ci/source-carriers/zlib-1.3.2/zlib-1.3.2.tar.gz';ID='zlib-1.3.2'
EVENTS=[]
def deny(event,args):
    if event.startswith(('socket.','subprocess.','os.exec','os.fork','os.spawn','os.posix_spawn'))or event=='os.system':
        EVENTS.append(event);raise AssertionError('source-only test forbids actors/network')
sys.addaudithook(deny)

class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.cache=self.root/'cache';M.library(ROOT).initialize(self.cache)
    def run_import(self,source=ARCHIVE,**kwargs):
        return M.import_source(self.cache,CATALOG,CAT_SHA,ID,source,repo_root=ROOT,**kwargs)
    def empty(self):
        for name in ('objects','receipts','.partial'):self.assertEqual(list((self.cache/name).iterdir()),[])
    def local(self):
        p=self.root/'source.tar.gz';shutil.copyfile(ARCHIVE,p);p.chmod(0o600);return p
    def test_missing_command_repro_then_real_retained_import_and_offline_consumer(self):
        c=M.library(ROOT)
        with self.assertRaisesRegex(ValueError,'offline source object missing'):c.run(self.cache,CATALOG,CAT_SHA,[ID],offline=True)
        result=self.run_import();self.assertEqual(result['source_kind'],'local_archive');self.assertEqual(result['network_fetches'],0)
        verified=c.run(self.cache,CATALOG,CAT_SHA,[ID],offline=True);self.assertEqual(verified['sources'][0]['status'],'verified')
        receipt=json.loads((self.cache/result['import_receipt']['path']).read_bytes());self.assertEqual(receipt['source_kind'],'local_archive');self.assertFalse(receipt['source_execution']);self.assertNotIn('http_status',receipt)
        sys.path.insert(0,str(ROOT/'scripts/build'))
        import source_materials
        planpath=FIXTURE/'baseline-source-plan.json';plan=json.loads(planpath.read_bytes());catalog=json.loads(CATALOG.read_bytes());row=catalog['sources'][0]
        # Explicit reviewed-report DATA fixture, not recipe execution/build proof.
        report={'errors':[],'input_sha256':plan['recipe_inputs'],'metadata':{'source':[plan['sources'][0]['source']],'sha256sums':[row['material']['sha256']]}}
        prepared=source_materials.prepare(report,planpath,hashlib.sha256(planpath.read_bytes()).hexdigest(),CATALOG,self.cache)
        source_materials.stage(prepared,self.root/'staged')
        self.assertEqual((self.root/'staged/srcdest/zlib-1.3.2.tar.gz').read_bytes(),ARCHIVE.read_bytes());self.assertEqual(EVENTS,[])
    def test_cli_success_and_alarm_restoration(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):code=M.main(['--cache',str(self.cache),'--inputs',str(CATALOG),'--inputs-sha256',CAT_SHA,'--id',ID,'--local-archive',str(ARCHIVE)],repo_root=ROOT)
        self.assertEqual(code,0);self.assertEqual(json.loads(output.getvalue())['status'],'IMPORTED_VERIFIED_LOCAL_SOURCE');self.assertEqual(M.signal.getitimer(M.signal.ITIMER_REAL),(0.0,0.0))
    def test_missing_and_tampered_source_refuse_before_cache_writes(self):
        with self.assertRaises(OSError):self.run_import(self.root/'missing')
        self.empty();source=self.local();raw=bytearray(source.read_bytes());raw[-1]^=1;source.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'checksum mismatch'):self.run_import(source)
        self.empty();self.assertEqual(source.read_bytes(),raw)
    def test_truncated_and_oversized_source_refuse(self):
        source=self.local()
        for raw in (ARCHIVE.read_bytes()[:-1],ARCHIVE.read_bytes()+b'x'):
            source.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'exact-size'):self.run_import(source)
            self.empty()
    def test_symlink_hardlink_fifo_and_executable_inputs_refuse(self):
        source=self.local();alias=self.root/'alias';alias.symlink_to(source)
        with self.assertRaises(ValueError):self.run_import(alias)
        alias.unlink();os.link(source,alias)
        with self.assertRaises(ValueError):self.run_import(source)
        alias.unlink();source.chmod(0o700)
        with self.assertRaises(ValueError):self.run_import(source)
        source.unlink();os.mkfifo(source)
        with self.assertRaises(ValueError):self.run_import(source)
        self.empty()
    def test_catalog_notice_or_selected_id_drift_refuses(self):
        with self.assertRaises(ValueError):M.import_source(self.cache,CATALOG,'0'*64,ID,ARCHIVE,repo_root=ROOT)
        with self.assertRaises(ValueError):M.import_source(self.cache,CATALOG,CAT_SHA,'unknown',ARCHIVE,repo_root=ROOT)
        catalog=self.root/'catalog';shutil.copytree(CATALOG.parent,catalog);notice=catalog/'notices/LICENSE.zlib';notice.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'license evidence'):M.import_source(self.cache,catalog/'source-inputs.json',CAT_SHA,ID,ARCHIVE,repo_root=ROOT)
        self.empty()
    def test_budget_and_existing_outer_deadline_are_enforced(self):
        with self.assertRaises(ValueError):self.run_import(maximum=1)
        ticks=iter((0,2))
        with self.assertRaisesRegex(ValueError,'deadline'):self.run_import(seconds=1,clock=lambda:next(ticks))
        for seconds in (float('nan'),float('inf'),0,601,True):
            with self.assertRaises(ValueError):self.run_import(seconds=seconds)
        self.empty()
    def test_cache_hit_still_validates_selected_local_file(self):
        self.run_import();source=self.local();raw=bytearray(source.read_bytes());raw[-1]^=1;source.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'checksum mismatch'):self.run_import(source)
        self.assertEqual(len(list((self.cache/'objects').iterdir())),1)
    def test_mid_copy_source_mutation_cleans_partial_without_publication(self):
        source=self.local();c=M.library(ROOT);original=c.write_all;first=[True]
        def write(fd,raw):
            original(fd,raw)
            if first[0]:
                first[0]=False
                with source.open('r+b')as changed:changed.write(b'x')
        c.write_all=write
        with patch.object(M,'library',return_value=c),self.assertRaises(ValueError):self.run_import(source)
        self.empty()
    def test_existing_bad_object_or_provenance_is_preserved(self):
        result=self.run_import();obj=next((self.cache/'objects').iterdir());obj.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.run_import()
        self.assertEqual(obj.read_bytes(),b'changed');self.assertEqual(list((self.cache/'.partial').iterdir()),[])
        obj.write_bytes(ARCHIVE.read_bytes());receipt=self.cache/result['import_receipt']['path'];receipt.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.run_import()
        self.assertEqual(receipt.read_bytes(),b'changed')
    def test_repeated_import_reuses_deterministic_receipts_without_duplicate_objects(self):
        first=self.run_import();second=self.run_import();self.assertEqual(first['import_receipt'],second['import_receipt']);self.assertEqual(len(list((self.cache/'objects').iterdir())),1);self.assertEqual(len(list((self.cache/'receipts').iterdir())),2);self.assertEqual(list((self.cache/'.partial').iterdir()),[])
    def test_normal_https_module_transport_is_not_mutated(self):
        original=M.library(ROOT);transport=original.transport;self.run_import();self.assertIs(original.transport,transport);self.assertEqual(EVENTS,[])

if __name__=='__main__':unittest.main(verbosity=2)
