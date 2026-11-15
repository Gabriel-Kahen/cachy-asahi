#!/usr/bin/env python3
"""Synthetic inert-file custody controls; never access the sealed348 materials."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('ui172_materialize_under_test',HERE/'materialize.py')
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class MaterializeControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ui172-materialize-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.source=self.root/'source';self.source.mkdir(mode=0o700)
        self.original=self.source/'original';self.original.write_bytes(b'original')
        self.original.chmod(0o755)
        self.row={'filename':'fixture.pkg.tar.xz','source_path':str(self.original),
                  'pin':{'bytes':8,'sha256':hashlib.sha256(b'original').hexdigest()}}
        self.rows=[self.row]
        self.dest=self.root/'destination'
        self.deadline=time.monotonic()+10
        self.budget={k:0 for k in ('file_bytes','read_bytes','source_read_bytes','destination_read_bytes')}

    def stage(self):return M.stage(self.rows,self.dest,self.budget,self.deadline)

    def plan(self):
        return {'kind':'UI172_RETAINED_MATERIALS_PLAN_DATA_ONLY',
                'copy_or_archive_reads_performed':False,'files':copy.deepcopy(self.rows)}

    def test_happy_copy_hash_modes_exact_membership_and_unchanged_source(self):
        before=M.identity(self.original.stat())
        result=self.stage()
        self.assertEqual(result['status'],'PASS_COMPLETE_MATERIAL_BYTES_DATA_ONLY')
        self.assertEqual(set(p.name for p in self.dest.iterdir()),{self.row['filename']})
        target=self.dest/self.row['filename']
        self.assertEqual(target.read_bytes(),b'original')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o644)
        self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode),0o700)
        self.assertEqual(target.stat().st_uid,os.geteuid())
        self.assertEqual(M.identity(self.original.stat()),before)
        record=result['completed'][0]
        self.assertEqual(record['source_identity_before_after'],before)
        self.assertEqual(record['destination_identity'],M.identity(target.stat()))
        self.assertEqual(record['full_source_and_destination_hash'],'PASS')
        self.assertEqual(self.budget,{'file_bytes':8,'read_bytes':16,'source_read_bytes':8,'destination_read_bytes':8})

    def test_existing_directory_and_final_symlink_refuse_without_mutation(self):
        self.dest.mkdir(mode=0o700)
        preserved=self.dest/'existing';preserved.write_bytes(b'preserved')
        self.assertEqual(self.stage()['status'],'HOLD_PARTIAL_OR_REFUSED_DATA_COPY')
        self.assertEqual(preserved.read_bytes(),b'preserved')
        preserved.unlink();self.dest.rmdir()
        self.dest.symlink_to(self.source,target_is_directory=True)
        self.assertEqual(self.stage()['status'],'HOLD_PARTIAL_OR_REFUSED_DATA_COPY')
        self.assertTrue(self.dest.is_symlink())
        self.assertEqual(self.original.read_bytes(),b'original')
        self.assertEqual(self.budget['read_bytes'],0)

    def test_missing_source_leaf_link_parent_link_and_fifo_are_missing(self):
        fifo=self.source/'fifo';os.mkfifo(fifo)
        leaf=self.source/'leaf-link';leaf.symlink_to(self.original)
        parent=self.root/'parent-link';parent.symlink_to(self.source,target_is_directory=True)
        for path in [self.source/'missing',leaf,parent/'original',fifo]:
            with self.subTest(path=path):
                row={**self.row,'source_path':str(path)}
                found,missing=M.preflight([row],self.deadline)
                self.assertEqual(found,{})
                self.assertEqual(len(missing),1)
                result=M.stage([row],self.dest,self.budget,self.deadline)
                self.assertEqual(result['status'],'HOLD_PARTIAL_OR_REFUSED_DATA_COPY')
                self.assertFalse(self.dest.exists())
        self.assertEqual(self.budget['read_bytes'],0)

    def test_same_length_sha_tamper_charged_and_partial_preserved(self):
        self.original.write_bytes(b'changed!')
        result=self.stage()
        self.assertEqual(result['status'],'HOLD_PARTIAL_OR_REFUSED_DATA_COPY')
        self.assertIn('SHA256/identity',result['reason'])
        self.assertEqual(result['completed'],[])
        self.assertEqual(self.budget,{'file_bytes':8,'read_bytes':8,'source_read_bytes':8,'destination_read_bytes':0})
        self.assertEqual((self.dest/self.row['filename']).read_bytes(),b'changed!')

    def test_partial_os_reads_and_short_os_writes_still_copy_exactly(self):
        read,write=M.os.read,M.os.write
        with patch.object(M.os,'read',side_effect=lambda fd,size:read(fd,min(size,2))), \
             patch.object(M.os,'write',side_effect=lambda fd,body:write(fd,body[:1])):
            result=self.stage()
        self.assertEqual(result['status'],'PASS_COMPLETE_MATERIAL_BYTES_DATA_ONLY')
        self.assertEqual(self.budget['read_bytes'],16)
        self.assertEqual((self.dest/self.row['filename']).read_bytes(),b'original')

    def test_truncated_read_and_zero_write_refuse_without_success_record(self):
        read=M.os.read
        calls=0
        def truncated(fd,size):
            nonlocal calls
            calls+=1
            return read(fd,2) if calls==1 else b''
        with patch.object(M.os,'read',side_effect=truncated):
            result=self.stage()
        self.assertIn('truncated source',result['reason'])
        self.assertEqual(result['completed'],[])
        self.assertEqual(self.budget['file_bytes'],8)
        self.assertEqual(self.budget['read_bytes'],2)
        self.assertEqual((self.dest/self.row['filename']).read_bytes(),b'or')
        other=self.root/'zero-write'
        with patch.object(M.os,'write',return_value=0):
            result=M.stage(self.rows,other,self.budget,self.deadline)
        self.assertIn('short destination write',result['reason'])
        self.assertEqual(result['completed'],[])

    def test_source_mode_identity_mutation_during_read_refused(self):
        read=M.read
        def mutate(fd,size,budget,deadline,category):
            body=read(fd,size,budget,deadline,category)
            if category=='source_read_bytes':self.original.chmod(0o700)
            return body
        with patch.object(M,'read',side_effect=mutate):result=self.stage()
        self.assertIn('SHA256/identity',result['reason'])
        self.assertEqual(result['completed'],[])
        self.assertEqual(self.budget['source_read_bytes'],8)

    def test_source_replacement_after_preflight_and_existing_leaf_refused(self):
        found,missing=M.preflight(self.rows,self.deadline)
        self.assertFalse(missing)
        replacement=self.source/'replacement';replacement.write_bytes(b'original');replacement.replace(self.original)
        self.dest.mkdir(mode=0o700)
        directory=os.open(self.dest,M.DIRFLAGS)
        try:
            with self.assertRaisesRegex(M.Refused,'changed after preflight'):
                M.copy_one(self.row,directory,self.dest,found[self.row['filename']],self.budget,self.deadline)
            self.assertEqual(self.budget['file_bytes'],0)
            found,_=M.preflight(self.rows,self.deadline)
            target=self.dest/self.row['filename'];target.symlink_to(self.original)
            with self.assertRaises(FileExistsError):
                M.copy_one(self.row,directory,self.dest,found[self.row['filename']],self.budget,self.deadline)
            self.assertTrue(target.is_symlink())
            self.assertEqual(self.budget['file_bytes'],8)
            self.assertEqual(self.budget['read_bytes'],0)
        finally:os.close(directory)

    def test_destination_observed_hash_corruption_is_hold(self):
        read=M.read
        def corrupt(fd,size,budget,deadline,category):
            body=read(fd,size,budget,deadline,category)
            return b'X'+body[1:] if category=='destination_read_bytes' and body else body
        with patch.object(M,'read',side_effect=corrupt):result=self.stage()
        self.assertIn('destination full SHA256/identity',result['reason'])
        self.assertEqual(result['completed'],[])
        self.assertEqual(self.budget['read_bytes'],16)

    def test_read_io_file_set_and_deadline_caps(self):
        with patch.object(M,'READ_LIMIT',7):result=self.stage()
        self.assertIn('read-I/O cap',result['reason'])
        self.assertEqual(self.budget['file_bytes'],8)
        self.assertEqual(self.budget['read_bytes'],0)
        with patch.object(M,'FILE_LIMIT',7):
            result=M.stage(self.rows,self.root/'file-cap',{k:0 for k in self.budget},self.deadline)
        self.assertIn('copied file-set cap',result['reason'])
        expired=self.root/'expired'
        result=M.stage(self.rows,expired,{k:0 for k in self.budget},time.monotonic()-1)
        self.assertIn('deadline',result['reason'])
        self.assertFalse(expired.exists())

    def test_plan_seal_count_names_paths_types_and_sum_caps(self):
        rows,total=M.validate_plan(self.plan(),count=1)
        self.assertEqual(total,8);self.assertEqual(rows,self.rows)
        mutations=[
            lambda p:p.__setitem__('kind','wrong'),
            lambda p:p.__setitem__('copy_or_archive_reads_performed',True),
            lambda p:p['files'].append(copy.deepcopy(p['files'][0])),
            lambda p:p['files'][0].__setitem__('filename','../escape'),
            lambda p:p['files'][0].__setitem__('filename','.'),
            lambda p:p['files'][0].__setitem__('source_path','relative/file'),
            lambda p:p['files'][0]['pin'].__setitem__('bytes',True),
            lambda p:p['files'][0]['pin'].__setitem__('bytes',0),
            lambda p:p['files'][0]['pin'].__setitem__('bytes',64*1024**2+1),
            lambda p:p['files'][0]['pin'].__setitem__('sha256','G'*64),
        ]
        for mutate in mutations:
            plan=self.plan();mutate(plan)
            with self.subTest(mutation=mutate),self.assertRaises(M.Refused):M.validate_plan(plan,count=1)
        plan=self.plan();plan['files'].append(copy.deepcopy(plan['files'][0]))
        with self.assertRaisesRegex(M.Refused,'unique flat'):M.validate_plan(plan,count=2)
        with patch.object(M,'FILE_LIMIT',7),self.assertRaisesRegex(M.Refused,'planned file-set'):M.validate_plan(self.plan(),count=1)

    def test_signature_keyring_and_template_specific_caps(self):
        for name,cap in [('fixture.pkg.tar.xz.sig',65536),('official-public.gpg',65536),
                         ('cachy-asahi-fish-config-fixture.pkg.tar.zst',1024**2),
                         ('cachy-asahi-zsh-config-fixture.pkg.tar.zst',1024**2)]:
            plan=self.plan();plan['files'][0]['filename']=name;plan['files'][0]['pin']['bytes']=cap
            with self.subTest(name=name):
                M.validate_plan(plan,count=1)
                plan['files'][0]['pin']['bytes']=cap+1
                with self.assertRaisesRegex(M.Refused,'per-object'):M.validate_plan(plan,count=1)


if __name__=='__main__':unittest.main()
