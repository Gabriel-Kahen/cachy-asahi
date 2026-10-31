"""Storage admission source controls; real statvfs, inert package actors."""
import ast
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import common as C,adapter,page_mode,storage_source


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def body(name,raw):
    import types
    module=types.ModuleType(name);module.__file__=str(HERE/(name+'.py'));exec(compile(raw,module.__file__,'exec'),module.__dict__);return module
def runtime(mode):
    raw=adapter.transform(C.read(C.ROOT/'parent604/installer.py'),'installer.py')[0]
    return page_mode.transform(raw,'installer.py')if mode=='generic16k'else raw
p=load('profile',C.ROOT/'parent604/profile.py')
load('numeric_vm',C.ROOT/'parent604/numeric_vm.py')
w=body('_storage_installer',runtime('generic4k'))
GIB=1024**3


def filesystem(**changes):
    return NS(**(dict(f_bsize=4096,f_frsize=4096,f_bavail=4*GIB//4096,f_favail=500000,f_flag=0)|changes))


def tiny_files(count=150000):
    return {'usr/share/tiny/'+str(i):dict(type='file',bytes=1) for i in range(count)}


class CapacityControls(unittest.TestCase):
    def test_old_apparent_byte_guard_accepts_underallocated_small_files_new_guard_refuses(self):
        nodes=tiny_files();fs=filesystem(f_bavail=560*1024**2//4096)
        old=sum(n.get('bytes',0) for n in nodes.values())+512*1024**2
        self.assertGreaterEqual(fs.f_bavail*fs.f_frsize,old)
        self.assertGreaterEqual(fs.f_favail,len(nodes)+10000)
        row=w.capacity_requirements(nodes,fs)
        self.assertGreater(row['required_bytes'],row['free_bytes'])
        self.assertGreater(row['rounded_file_bytes'],row['free_bytes'])
        with patch.object(w.os,'statvfs',return_value=fs),self.assertRaisesRegex(ValueError,'measured target capacity insufficient'):
            w.target_capacity(Path('/inert-target'),nodes,{})

    def test_both_space_and_inode_boundaries_preserve_original_margins(self):
        nodes={'file':dict(type='file',bytes=4096)}
        row=w.capacity_requirements(nodes,filesystem())
        fs=filesystem(f_bavail=row['required_bytes']//4096,f_favail=row['required_inodes'])
        with patch.object(w.os,'statvfs',return_value=fs):
            self.assertEqual(w.target_capacity(Path('/inert-target'),nodes,{})['reserve_bytes'],512*1024**2)
        for change in (dict(f_bavail=fs.f_bavail-1),dict(f_favail=fs.f_favail-1)):
            with patch.object(w.os,'statvfs',return_value=NS(**(vars(fs)|change))),self.assertRaisesRegex(ValueError,'capacity insufficient'):
                w.target_capacity(Path('/inert-target'),nodes,{})
        self.assertGreaterEqual(row['required_inodes'],len(nodes)+10000)

    def test_filesystem_fragments_define_free_bytes_io_blocks_define_conservative_rounding(self):
        nodes={'file':dict(type='file',bytes=4097)}
        row=w.capacity_requirements(nodes,filesystem(f_bsize=16384,f_frsize=4096,f_bavail=300000))
        self.assertEqual(row['allocation_unit_bytes'],16384)
        self.assertEqual(row['free_bytes'],300000*4096)
        self.assertEqual(row['rounded_file_bytes'],16384)
        row=w.capacity_requirements(nodes,filesystem(f_bsize=4096,f_frsize=16384))
        self.assertEqual(row['allocation_unit_bytes'],16384)

    def test_implicit_parents_empty_files_unicode_links_and_hardlink_aliases_are_conservative(self):
        nodes={'a/b/empty':dict(type='file',bytes=0),'alias':dict(type='file',bytes=0),
               'link':dict(type='symlink',target='é'*409), 'declared':dict(type='directory')}
        row=w.capacity_requirements(nodes,filesystem())
        self.assertEqual(row['rounded_file_bytes'],0)
        self.assertGreaterEqual(row['symlink_estimate_bytes'],len(('é'*409).encode())+1)
        self.assertGreater(row['directory_estimate_bytes'],len(nodes)*4096)
        self.assertGreaterEqual(row['required_inodes'],len(nodes)+10000)
        self.assertFalse(row['capacity_reserved'])

    def test_unknown_or_readonly_filesystem_metrics_fail_closed(self):
        for field in ('f_bsize','f_frsize','f_bavail','f_favail','f_flag'):
            for value in (None,True,-1,2**63):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                    w.capacity_requirements({},filesystem(**{field:value}))
        for field in ('f_bsize','f_frsize'):
            with self.assertRaises(ValueError):w.capacity_requirements({},filesystem(**{field:0}))
        with self.assertRaisesRegex(ValueError,'read-only'):
            w.capacity_requirements({},filesystem(f_flag=os.ST_RDONLY))

    def test_malformed_payload_and_file_parent_overlap_refuse(self):
        for name in ('','/absolute','a/../b','a//b','./a','a/','a\0b',1):
            with self.subTest(name=name),self.assertRaises(ValueError):
                w.capacity_requirements({name:dict(type='file',bytes=1)},filesystem())
        for row in ({},dict(type='device'),dict(type='hardlink'),dict(type='file',bytes=True),
                    dict(type='file',bytes=-1),dict(type='file',bytes=GIB+1),
                    dict(type='symlink',target=''),dict(type='symlink',target='a\0b')):
            with self.subTest(row=row),self.assertRaises(ValueError):
                w.capacity_requirements({'a':row},filesystem())
        with self.assertRaisesRegex(ValueError,'parent'):
            w.capacity_requirements({'a':dict(type='file',bytes=0),'a/b':dict(type='file',bytes=0)},filesystem())
        with self.assertRaisesRegex(ValueError,'byte bound'):
            w.capacity_requirements({str(i):dict(type='file',bytes=GIB)for i in range(7)},filesystem())

    def test_actual_target_statvfs_is_observed_without_page_size_or_evidence_path_substitution(self):
        with tempfile.TemporaryDirectory(dir=C.ROOT.parent)as td:
            root=Path(td);observed=os.statvfs(root)
            row=w.capacity_requirements({'small':dict(type='file',bytes=1)},observed)
            self.assertEqual(row['allocation_unit_bytes'],max(observed.f_bsize,observed.f_frsize))
            report={}
            if row['free_bytes']>=row['required_bytes'] and row['free_inodes']>=row['required_inodes']:
                self.assertEqual(w.target_capacity(root,{'small':dict(type='file',bytes=1)},report)['required_bytes'],row['required_bytes'])
            else:
                with self.assertRaisesRegex(ValueError,'capacity insufficient'):
                    w.target_capacity(root,{'small':dict(type='file',bytes=1)},report)
                self.assertIn('capacity',report)
            self.assertFalse(list(root.iterdir()))
        root=Path('/specific-target')
        with patch.object(w.os,'statvfs',return_value=filesystem())as call:
            w.target_capacity(root,{},{})
        call.assert_called_once_with(root)
        with patch.object(w.os,'statvfs',side_effect=OSError('unavailable')),self.assertRaises(OSError):
            w.target_capacity(root,{},{})

    def test_proposal_changes_only_helpers_and_the_actual_capacity_statement(self):
        old=storage_source.before_files();ctx=storage_source.context(storage_source.scan(C.ROOT)[0])
        self.assertEqual({n:C.pin(b)for n,b in old.items()},ctx['files'])
        changed=C.read(C.ROOT/'parent604/installer.py')
        restored=storage_source.one(storage_source.one(changed,ctx['helper'],''),ctx['capacity_after'],ctx['capacity_before'])
        self.assertEqual(restored,old['parent604/installer.py'])
        row=w.capacity_requirements({},filesystem())
        self.assertEqual(sorted(row),C.profile()['storage_admission']['fields'])
        self.assertEqual(C.profile()['clocks'],ctx['clocks'])

    def exercise_engine_failure(self,worker):
        # Exercise the real engine function. Namespace/authentication/ALPM actors
        # are inert controls; no native transaction or hardware execution occurs.
        w=worker
        with tempfile.TemporaryDirectory(dir=C.ROOT.parent)as td:
            root=Path(td);evidence_path=root/'evidence';evidence_path.mkdir();workspace=root/'workspace';workspace.mkdir()
            saved=[];evidence=NS(path=evidence_path,save=lambda name,row:saved.append(copy.deepcopy(row)),close=Mock())
            runner=NS(run=Mock(side_effect=AssertionError('NO_AUTHENTICATION_ACTOR')))
            base=NS(OWNED_OUTPUT=evidence,isolate=Mock(return_value=workspace),reduce_capabilities=Mock(),
                    environment=lambda **kw:kw,runtime=lambda:NS(Runner=lambda *args:runner))
            roots=NS(Alpm=Mock(side_effect=AssertionError('NO_PACKAGE_ACTOR')))
            nonce='0'*32;spec=dict(profile_sha256='f'*64,nonce=nonce,deadline=time.monotonic()+60)
            raw=json.dumps(spec).encode();fd=os.memfd_create('inert-capacity-spec',os.MFD_ALLOW_SEALING)
            try:
                # Bundled3.12 omits the symbolic constants; these are the real
                # Linux UAPI commands, not mocked seal results or relaxed checks.
                os.write(fd,raw);fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15)
                self.assertEqual(fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))&15,15)
                with patch.object(w,'checked_inputs',return_value=(dict(nonce=nonce),{},dict(packages=[]),dict(nodes=tiny_files(10000)))), \
                     patch.object(w,'source_modules',return_value=(roots,base,None,None)), \
                     patch.object(w.p,'sha',return_value='f'*64), \
                     patch.object(w.fcntl,'F_GET_SEALS',getattr(fcntl,'F_GET_SEALS',1034),create=True), \
                     patch.object(w.os,'statvfs',return_value=filesystem(f_bavail=30*1024**2//4096)):
                    result=w.engine(fd,hashlib.sha256(raw).hexdigest(),123)
                self.assertEqual(result,1);self.assertEqual(saved[-1]['status'],'FAIL')
                self.assertIn('capacity insufficient',saved[-1]['error'])
                self.assertGreater(saved[-1]['capacity']['rounded_file_bytes'],saved[-1]['capacity']['free_bytes'])
                self.assertFalse(saved[-1]['commit_started']);self.assertFalse(saved[-1]['committed'])
                roots.Alpm.assert_not_called();runner.run.assert_not_called();evidence.close.assert_called_once()
            finally:
                try:os.close(fd)
                except OSError:pass

    def test_actual_engine_low_space_failure_precedes_authentication_and_alpm_creation(self):
        for mode in ('generic4k','generic16k'):
            with self.subTest(mode=mode):self.exercise_engine_failure(body('_capacity_engine_'+mode,runtime(mode)))

    def test_current607_bodies_keep_the_same_helpers_and_selected_abi_origins(self):
        helpers=None
        for mode,origin in (('generic4k','base'),('generic16k','roots.installer')):
            raw=runtime(mode);nodes=ast.parse(raw)
            actual={n.name:ast.dump(n)for n in nodes.body if isinstance(n,ast.FunctionDef)and n.name in ('capacity_requirements','target_capacity')}
            if helpers is None:helpers=actual
            self.assertEqual(actual,helpers)
            self.assertEqual(raw.count(('details='+origin+'.Ptr(); alpm.ok(alpm.alpm_trans_').encode()),2)
            self.assertIn(b'package_count=607',raw)


if __name__=='__main__':unittest.main(verbosity=2)
