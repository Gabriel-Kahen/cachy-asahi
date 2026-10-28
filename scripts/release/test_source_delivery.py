#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Tiny original synthetic data; no archive/source/crypto/native actor executes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('source_delivery', HERE/'source_delivery.py')
sd = importlib.util.module_from_spec(spec); spec.loader.exec_module(sd)
TEMP = HERE.parents[2]/'notes/helper/tmp'
TEMP.mkdir(parents=True, exist_ok=True)


def encode(value):
    return (json.dumps(value, sort_keys=True)+'\n').encode()


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEMP)
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.bodies = {}
        self.package = dict(name='original-demo',version='1.0-1',arch='any',sha256='a'*64)
        self.record = dict(package=self.package,recipe_key='PKGBUILD',review_status='INCOMPLETE synthetic existing review')
        self.record['bundle'] = self.material('bundle.tar', b'opaque original synthetic source bundle\n')
        self.record['notices'] = [self.material('NOTICE', b'Original fixture MIT notice\n')]
        self.record['recipe'] = self.material('PKGBUILD', b'# Original MIT synthetic recipe; never executed\n')
        self.record['source_map'] = self.material('source-map.json', encode({'PKGBUILD':self.record['recipe']['sha256']}))
        self.record['authorization'] = self.material('existing-review.txt', b'Existing synthetic review: source and license gaps remain. No new approval.\n')
        self.index = dict(schema_version=1,purpose='release-source-delivery',synthetic=True,packages=[self.record])
        self.refresh_index()
        self.provenance = dict(recipe_sha256=self.record['recipe']['sha256'])
        self.packages = [dict(self.package,provenance='provenance/original-demo.json')]
        self.specification = dict(synthetic=True,policy={'selected_packages':['original-demo']},
            source_delivery=dict(schema_version=1,index=self.index_ref),evidence=self.evidence())

    def material(self, eid, raw):
        self.bodies[eid] = raw; (self.root/eid).write_bytes(raw)
        return dict(id=eid,path=eid,sha256=sd.digest(raw),bytes=len(raw))

    def refresh_index(self):
        raw = encode(self.index); self.bodies['index.json'] = raw; (self.root/'index.json').write_bytes(raw)
        self.index_ref = dict(id='index.json',path='index.json',sha256=sd.digest(raw))

    def evidence(self):
        return [self.index_ref]+[{k:r[k] for k in ('id','path','sha256')} for r in sd.materials(self.record)]

    def read(self, eid, limit):
        raw = self.bodies[eid]; self.assertLessEqual(len(raw),limit); return raw

    def provenance_read(self, package):
        self.assertEqual(package,self.packages[0]); return self.provenance

    def verify(self, specification=None):
        return sd.verify_associations(specification or self.specification,self.packages,self.read,self.provenance_read)

    def change(self, role, value):
        row = self.record[role]; raw = encode(value); self.bodies[row['id']] = raw
        row.update(sha256=sd.digest(raw),bytes=len(raw)); (self.root/row['path']).write_bytes(raw)
        self.refresh_index(); self.specification['source_delivery']['index'] = self.index_ref
        self.specification['evidence'] = self.evidence()

    def test_assemble_and_recipient_actual_associations(self):
        rows = sd.assemble(self.root,self.index_ref,self.packages,['original-demo'],True,self.provenance_read)
        self.assertEqual(rows,self.evidence()); self.assertEqual(self.verify(),self.index)

    def test_absent_opt_in_is_none_without_reads(self):
        self.assertIsNone(sd.verify_associations({},[],lambda *a:self.fail('unexpected read'),lambda *a:self.fail('unexpected provenance')))

    def test_export_exact_selected_files_receipt_modes(self):
        output = self.root/'export'; receipt = sd.export_package(self.record,self.read,output,'b'*64)
        expected = {r['id'] for r in sd.materials(self.record)}|{sd.RECEIPT}
        self.assertEqual(set(p.name for p in output.iterdir()),expected)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in output.iterdir()))
        self.assertEqual(receipt,json.loads((output/sd.RECEIPT).read_text()))
        self.assertEqual(receipt['release_sha256'],'b'*64)
        self.assertNotIn(b'release_sha256',self.bodies['existing-review.txt'])
        self.assertEqual(receipt['review_status'],self.record['review_status'])
        self.assertIs(receipt['source_completeness_accepted'],False)
        self.assertIs(receipt['legal_acceptance'],False)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(sd.Error):sd.decode(b'{"x":1,"x":2}')

    def test_wrong_closed_fields_refused(self):
        self.index['extra'] = True; self.refresh_index(); self.specification['source_delivery']['index'] = self.index_ref
        self.specification['evidence'] = self.evidence()
        with self.assertRaises(sd.Error):self.verify()

    def test_missing_selected_package_refused(self):
        self.index['packages'] = []; self.refresh_index(); self.specification['source_delivery']['index'] = self.index_ref
        self.specification['evidence'][0] = self.index_ref
        with self.assertRaises(sd.Error):self.verify()

    def test_wrong_package_artifact_refused(self):
        self.packages[0]['sha256'] = 'c'*64
        with self.assertRaises(sd.Error):self.verify()

    def test_duplicate_material_id_refused(self):
        self.record['notices'][0]['id'] = 'bundle.tar'
        with self.assertRaises(sd.Error):sd.materials(self.record)

    def test_reserved_receipt_id_refused(self):
        self.record['recipe']['id'] = sd.RECEIPT
        with self.assertRaises(sd.Error):sd.materials(self.record)

    def test_wrong_provenance_recipe_refused(self):
        self.provenance['recipe_sha256'] = 'c'*64
        with self.assertRaises(sd.Error):self.verify()

    def test_source_map_recipe_value_refused(self):
        self.change('source_map',{'PKGBUILD':'c'*64})
        with self.assertRaises(sd.Error):self.verify()

    def test_source_map_nested_value_refused(self):
        self.change('source_map',{'PKGBUILD':{'sha256':self.record['recipe']['sha256']}})
        with self.assertRaises(sd.Error):self.verify()

    def test_empty_review_status_refused(self):
        self.record['review_status']='  '
        with self.assertRaises(sd.Error):sd.materials(self.record)

    def test_existing_review_is_opaque_without_approval_schema(self):
        # Existing failure/unknown review labels are retained, never elevated.
        for status in ('FAIL', 'UNKNOWN', 'NOT RUN'):
            self.record['review_status']=status
            self.refresh_index();self.specification['source_delivery']['index']=self.index_ref
            self.specification['evidence']=self.evidence()
            self.assertEqual(self.verify()['packages'][0]['review_status'],status)
        output=self.root/'opaque-review'
        result=sd.export_package(self.record,self.read,output,'b'*64)
        self.assertEqual((output/'existing-review.txt').read_bytes(),self.bodies['existing-review.txt'])
        self.assertIs(result['legal_acceptance'],False)
        self.assertIs(result['source_completeness_accepted'],False)

    def test_existing_review_byte_tamper_refused(self):
        self.bodies['existing-review.txt']+=b'tamper'
        with self.assertRaises(sd.Error):self.verify()

    def test_missing_evidence_descriptor_refused_before_material_read(self):
        self.specification['evidence'] = [self.index_ref]
        called=[]
        def read(eid,limit):called.append(eid);return self.read(eid,limit)
        with self.assertRaises(sd.Error):sd.verify_associations(self.specification,self.packages,read,self.provenance_read)
        self.assertEqual(called,['index.json'])

    def test_duplicate_or_foreign_evidence_descriptor_refused(self):
        self.specification['evidence'].append(self.index_ref)
        with self.assertRaises(sd.Error):self.verify()
        self.specification['evidence'] = self.evidence(); self.specification['evidence'][1]['path'] = 'foreign'
        with self.assertRaises(sd.Error):self.verify()

    def test_recipient_never_follows_input_path(self):
        for row in sd.materials(self.record):row['path']='publisher-only/'+row['id']
        self.refresh_index(); self.specification['source_delivery']['index']=self.index_ref;self.specification['evidence']=self.evidence()
        self.assertEqual(self.verify(),self.index)
        sd.export_package(self.record,self.read,self.root/'recipient','b'*64)

    def test_unsafe_input_relative_paths_refused(self):
        for path in ('../escape','/absolute','a//b','a/./b','a/../b','a\\b'):
            with self.subTest(path=path),self.assertRaises(sd.Error):sd.relative(path)

    def test_regular_reader_symlink_hardlink_fifo_parent_refusals(self):
        raw=self.root/'NOTICE'
        for kind in ('symlink','hardlink','fifo','parent'):
            with self.subTest(kind=kind):
                target=self.root/kind
                if kind=='symlink':target.symlink_to(raw)
                elif kind=='hardlink':os.link(raw,target)
                elif kind=='fifo':os.mkfifo(target)
                else:target.symlink_to(self.root,target_is_directory=True);target=target/'PKGBUILD'
                with self.assertRaises((sd.Error,OSError)):sd.read_file(target,1024)
                if kind=='hardlink':(self.root/kind).unlink()

    def test_reader_zero_and_byte_cap(self):
        leaf=self.root/'empty';leaf.write_bytes(b'');self.assertEqual(sd.read_file(leaf,0),b'')
        with self.assertRaises(sd.Error):sd.read_file(self.root/'NOTICE',1)
        with self.assertRaises(sd.Error):sd.decode(b' '* (sd.MAX_JSON+1))

    def test_caps_before_material_reads(self):
        # Lower the constants for a causal bounded test; no large fixture allocation.
        with patch.object(sd,'MAX_TOTAL',1),self.assertRaises(sd.Error):self.verify()
        with patch.object(sd,'MAX_FILES',2),self.assertRaises(sd.Error):self.verify()
        self.record['bundle']['bytes']=sd.MAX_FILE+1
        with self.assertRaises(sd.Error):sd.materials(self.record)

    def test_existing_output_is_never_changed(self):
        for kind in ('directory','file','symlink'):
            output=self.root/('existing-'+kind)
            if kind=='directory':output.mkdir()
            elif kind=='file':output.write_bytes(b'keep')
            else:output.symlink_to(self.root,target_is_directory=True)
            with self.assertRaises(FileExistsError):sd.export_package(self.record,self.read,output,'b'*64)
            self.assertTrue(output.exists())
            if kind=='file':self.assertEqual(output.read_bytes(),b'keep')

    def test_export_changed_read_removes_only_owned_output(self):
        output=self.root/'failed-export'; sibling=self.root/'keep';sibling.write_bytes(b'keep')
        def read(eid,limit):
            return b'corrupt' if output.exists() and eid=='NOTICE' else self.read(eid,limit)
        with self.assertRaises(sd.Error):sd.export_package(self.record,read,output,'b'*64)
        self.assertFalse(output.exists());self.assertEqual(sibling.read_bytes(),b'keep')

    def test_missing_provenance_record_refused(self):
        with self.assertRaises(sd.Error):
            sd.verify_associations(self.specification,self.packages,self.read,lambda package:None)

    def test_partial_write_primary_survives_close_failure(self):
        output=self.root/'failed-write';primary=OSError('first-write');real_close=os.close
        entered=[];raised_close=[]
        def write(fd,raw):
            entered.append(True);raise primary
        def close(fd):
            real_close(fd)
            if entered and not raised_close:
                raised_close.append(True);raise OSError('second-close')
        with patch.object(sd.os,'write',side_effect=write),patch.object(sd.os,'close',side_effect=close):
            with self.assertRaises(OSError)as raised:
                sd.export_package(self.record,self.read,output,'b'*64)
        self.assertIs(raised.exception,primary);self.assertTrue(entered);self.assertTrue(raised_close)
        self.assertIn('source-delivery close uncertainty: OSError',primary.__notes__)
        self.assertFalse(output.exists())

    def test_empty_required_material_roles_refused(self):
        for role in ('bundle','recipe','notices'):
            with self.subTest(role=role):
                record=copy.deepcopy(self.record)
                row=record['notices'][0] if role=='notices' else record[role]
                row.update(bytes=0,sha256=sd.digest(b''))
                with self.assertRaises(sd.Error):sd.materials(record)

    def late_parent_close(self, refuse_reopen):
        output=self.root/'late-close';cwd=self.root/'cwd';cwd.mkdir()
        sentinel=cwd/'bundle.tar';sentinel.write_bytes(b'untouched CWD sentinel')
        primary=OSError('late-parent-close');real_close=os.close;real_directory=sd.directory
        root_identity=(self.root.stat().st_dev,self.root.stat().st_ino);triggered=[]
        def close(fd):
            info=os.fstat(fd);match=(info.st_dev,info.st_ino)==root_identity
            real_close(fd)
            if match and (output/sd.RECEIPT).exists() and not triggered:
                triggered.append(True);raise primary
        def directory(path):
            if triggered and refuse_reopen:raise OSError('cleanup-reopen-failed')
            return real_directory(path)
        saved=Path.cwd();os.chdir(cwd)
        try:
            with patch.object(sd.os,'close',side_effect=close),patch.object(sd,'directory',side_effect=directory):
                with self.assertRaises(OSError)as raised:sd.export_package(self.record,self.read,output,'b'*64)
            self.assertIs(raised.exception,primary);self.assertTrue(triggered)
            self.assertEqual(sentinel.read_bytes(),b'untouched CWD sentinel')
            self.assertEqual(output.exists(),refuse_reopen)
        finally:os.chdir(saved)

    def test_late_parent_close_reopens_only_owned_directory_for_cleanup(self):
        self.late_parent_close(False)

    def test_late_parent_close_reopen_failure_never_unlinks_cwd(self):
        self.late_parent_close(True)

    def test_traversal_parent_close_failure_closes_new_owned_child(self):
        real_open=os.open;real_close=os.close
        for mode in ('directory','local'):
            with self.subTest(mode=mode):
                deep=self.root/'deep';deep.mkdir(exist_ok=True);(deep/'leaf').write_bytes(b'value')
                opened=[];triggered=[]
                root_info=self.root.stat()
                def opened_fd(*args,**kwargs):
                    fd=real_open(*args,**kwargs);opened.append(fd);return fd
                def close(fd):
                    info=os.fstat(fd)
                    target=mode=='directory' or (info.st_dev,info.st_ino)==(root_info.st_dev,root_info.st_ino)
                    real_close(fd)
                    if target and not triggered:triggered.append(True);raise OSError('parent-close-consumed')
                with patch.object(sd.os,'open',side_effect=opened_fd),patch.object(sd.os,'close',side_effect=close):
                    with self.assertRaises(OSError):
                        if mode=='directory':sd.directory(self.root)
                        else:sd.local_read(self.root,'deep/leaf',64)
                self.assertTrue(triggered)
                for fd in set(opened):
                    with self.assertRaises(OSError):os.fstat(fd)

    def test_output_symlink_parent_refused_without_creation(self):
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):sd.export_package(self.record,self.read,alias/'export','b'*64)
        self.assertFalse((self.root/'export').exists())


if __name__=='__main__':
    unittest.main()
