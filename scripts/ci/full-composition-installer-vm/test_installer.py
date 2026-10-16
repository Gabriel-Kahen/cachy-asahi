#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert profile, archive and receipt controls; no ALPM/GPG/VM/mount actors."""
import copy
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest

HERE=Path(__file__).resolve().parent
CODE=HERE.parents[2]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module; spec.loader.exec_module(module); return module


p=load('profile',HERE/'profile.py')
w=load('_full_installer_test_worker',HERE/'installer.py')
stream=load('_full_installer_test_stream',CODE/'scripts/update/archive_stream.py')


def limits(**change):
    values=dict(compressed_bytes=1024**2,total_compressed_bytes=2*1024**2,decoded_bytes=4*1024**2,
                members=100,file_bytes=1024**2,window_bytes=16*1024**2,deadline=time.monotonic()+30)
    values.update(change); return stream.Limits(**values)


def archive_bytes(rows):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as tar:
        for name,kind,data in rows:
            row=tarfile.TarInfo(name); row.mode=0o755 if kind=='directory' else 0o644
            row.uid=row.gid=0
            if kind=='file': row.size=len(data); tar.addfile(row,io.BytesIO(data)); continue
            if kind=='directory': row.type=tarfile.DIRTYPE
            elif kind=='symlink': row.type=tarfile.SYMTYPE; row.linkname=data
            elif kind=='hardlink': row.type=tarfile.LNKTYPE; row.linkname=data
            elif kind=='fifo': row.type=tarfile.FIFOTYPE
            tar.addfile(row)
    return gzip.compress(output.getvalue())


class ArchiveControls(unittest.TestCase):
    def inspect(self,rows,**bounds):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'package.tar.gz'; path.write_bytes(archive_bytes(rows))
            accounting=dict(bytes=0,nodes=0,compressed_bytes=0)
            value=p.archive(path,stream,limits(**bounds),accounting)
            self.assertGreater(accounting['bytes'],0); return value
    def test_literal_absolute_symlink_and_regular_hash(self):
        rows,groups=self.inspect([('usr','directory',None),('usr/a','file',b'data'),('alias','symlink','/usr/a')])
        self.assertEqual(rows['alias']['target'],'/usr/a')
        self.assertEqual(rows['usr/a']['sha256'],hashlib.sha256(b'data').hexdigest()); self.assertEqual(groups,[])
    def test_closed_forward_hardlinks_and_chain(self):
        rows,groups=self.inspect([('a','hardlink','b'),('b','hardlink','c'),('c','file',b'payload')])
        self.assertEqual(groups,[['a','b','c']]); self.assertEqual(rows['a'],rows['c'])
    def test_open_hardlink_refused(self):
        with self.assertRaisesRegex(ValueError,'archived regular'): self.inspect([('a','hardlink','missing')])
    def test_hardlink_cycle_refused(self):
        with self.assertRaisesRegex(ValueError,'cycle'): self.inspect([('a','hardlink','b'),('b','hardlink','a')])
    def test_special_node_refused(self):
        with self.assertRaisesRegex(ValueError,'special'): self.inspect([('a','fifo',None)])
    def test_parent_traversal_refused(self):
        with self.assertRaisesRegex(ValueError,'canonical'): self.inspect([('../a','file',b'x')])
    def test_duplicate_member_refused(self):
        with self.assertRaisesRegex(ValueError,'duplicate'): self.inspect([('a','file',b'a'),('a','file',b'b')])
    def test_decoded_limit_refused(self):
        with self.assertRaisesRegex(ValueError,'decoded byte'): self.inspect([('a','file',b'x'*20000)],decoded_bytes=4096)
    def test_file_limit_refused(self):
        with self.assertRaisesRegex(ValueError,'file byte'): self.inspect([('a','file',b'x'*10)],file_bytes=5)
    def test_member_limit_refused(self):
        with self.assertRaisesRegex(ValueError,'member limit'): self.inspect([('a','file',b'a'),('b','file',b'b')],members=1)
    def test_trailing_compressed_frame_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'p.gz'; data=archive_bytes([('a','file',b'a')]); path.write_bytes(data+data)
            with self.assertRaisesRegex(ValueError,'concatenated'): p.archive(path,stream,limits(),dict(bytes=0,nodes=0,compressed_bytes=0))
    def test_expired_deadline_refused(self):
        with self.assertRaisesRegex(ValueError,'deadline'): self.inspect([('a','file',b'x')],deadline=time.monotonic()-1)


class ProfileControls(unittest.TestCase):
    def test_duplicate_and_nonfinite_json_refused(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError): p.decode(raw)
    def test_input_pin_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); target=root/'input'; target.write_bytes(b'data')
            row=p.reference(target); target.write_bytes(b'evil')
            with self.assertRaisesRegex(ValueError,'input bytes'): p.checked(root,'input',row)
    def test_symlink_and_hardlink_inputs_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); target=root/'input'; target.write_bytes(b'data'); row=p.reference(target)
            (root/'alias').symlink_to('input')
            with self.assertRaisesRegex(ValueError,'ordinary'): p.checked(root,'alias',row)
            os.link(target,root/'other')
            with self.assertRaisesRegex(ValueError,'type'): p.checked(root,'input',row)
    def test_declared_oversize_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'input').write_bytes(b'data')
            with self.assertRaisesRegex(ValueError,'size'): p.checked(root,'input',dict(bytes=100,sha256='0'*64),maximum=10)
    def test_lock_requires_unique_exact_count(self):
        self.assertEqual(p.lock(b'a 1\nb 2\n',2),{'a':'1','b':'2'})
        for raw in (b'a 1\na 2\n',b'a 1\n',b'../a 1\nb 2\n'):
            with self.assertRaises(ValueError): p.lock(raw,2)
    def test_local_environment_cannot_enter_vm_route(self):
        if os.uname().machine!='aarch64' or os.getuid()!=23001:
            with self.assertRaisesRegex(ValueError,'ordinary generic4K'): w.ordinary_preflight()
    def test_exact_sealed_spec_directory_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fd=os.memfd_create('control',os.MFD_ALLOW_SEALING)
            directory=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY)
            try:
                os.write(fd,b'{}'); fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
                argv=w.fd_transfer(['/usr/bin/unshare','--spec',str(fd),'--evidence',str(directory)],(fd,directory))
                refs=json.loads(argv[6])
                self.assertEqual([r['kind'] for r in refs],['sealed','directory'])
                self.assertEqual(refs[0]['identity'],[os.fstat(fd).st_dev,os.fstat(fd).st_ino])
                self.assertEqual(argv[-4:],['--spec','SPEC_FD','--evidence','EVIDENCE_FD'])
            finally: os.close(fd); os.close(directory)
    def test_transfer_refuses_nonsealed_or_duplicate_fd(self):
        fd=os.memfd_create('control',os.MFD_ALLOW_SEALING)
        try:
            with self.assertRaisesRegex(ValueError,'pair'): w.fd_transfer(['x',str(fd)],(fd,fd))
            with tempfile.TemporaryDirectory() as temporary:
                directory=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    with self.assertRaisesRegex(ValueError,'shape/seal'):
                        w.fd_transfer(['x',str(fd),str(directory)],(fd,directory))
                finally: os.close(directory)
        finally: os.close(fd)
    def test_unsealed_engine_spec_refused_before_input_or_actor(self):
        descriptor=os.memfd_create('control',os.MFD_ALLOW_SEALING)
        try:
            with self.assertRaisesRegex(ValueError,'sealed'): w.engine(descriptor,'0'*64,descriptor)
        finally: os.close(descriptor)


class PayloadControls(unittest.TestCase):
    def fixture(self):
        nodes={'usr/a':dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='0'*64)}
        observed=copy.deepcopy(nodes)
        for name,data in w.FIXTURES.items():
            observed[name]=dict(type='file',mode=0o600,uid=0,gid=0,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        return dict(complete=True,unsupported_counts={},nodes=observed,hardlink_groups={}),dict(nodes=nodes,hardlinks=[])
    def test_payload_and_declared_user_fixtures_pass(self):
        observation,payload=self.fixture(); self.assertTrue(w.compare_payload(observation,payload))
    def test_preservation_mutation_fails(self):
        observation,payload=self.fixture(); observation['nodes'][next(iter(w.FIXTURES))]['sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'preservation'): w.compare_payload(observation,payload)
    def test_unowned_unexpected_output_fails(self):
        observation,payload=self.fixture(); observation['nodes']['etc/other']=dict(type='file')
        with self.assertRaisesRegex(ValueError,'unexpected'): w.compare_payload(observation,payload)
    def test_undeclared_empty_directory_fails(self):
        observation,payload=self.fixture(); observation['nodes']['etc/other']=dict(type='directory')
        with self.assertRaisesRegex(ValueError,'unexpected installed directory'): w.compare_payload(observation,payload)
    def test_unexpected_database_file_fails(self):
        observation,payload=self.fixture(); observation['nodes']['var/lib/pacman/local/evil']=dict(type='file')
        with self.assertRaisesRegex(ValueError,'unexpected'): w.compare_payload(observation,payload)
    def test_open_or_changed_hardlink_group_fails(self):
        observation,payload=self.fixture(); observation['hardlink_groups']={'a':{'members':['usr/a','other']}}
        with self.assertRaisesRegex(ValueError,'hardlink'): w.compare_payload(observation,payload)
    def test_unknown_observation_or_incomplete_fails(self):
        for field,value in (('complete',False),('unsupported_counts',{'cross-device':1})):
            observation,payload=self.fixture(); observation[field]=value
            with self.assertRaisesRegex(ValueError,'observation'): w.compare_payload(observation,payload)


if __name__=='__main__': unittest.main()
