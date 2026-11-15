# SPDX-License-Identifier: MIT
"""Owned temporary DATA/pure-predicate controls; no producer/actor role import."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
s = importlib.util.spec_from_file_location('retention_v3_edits_controls', HERE/'edits.py')
E = importlib.util.module_from_spec(s)
s.loader.exec_module(E)
ACTOR = (HERE/'data/parent-actor.py.txt').read_bytes()
PRODUCER = (HERE/'data/parent-producer.py.txt').read_bytes()


def need(ok, why):
    if not ok:
        raise ValueError(why)


def selected(body, names):
    functions = [n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef) and n.name in names]
    scope = dict(C=SimpleNamespace(need=need), Path=Path, os=os, stat=stat, io=io, tarfile=tarfile)
    exec(compile(ast.Module(body=functions,type_ignores=[]),'<pure-retention-controls>','exec'),scope)
    return scope


class Controls(unittest.TestCase):
    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name in ('subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open'):
            stack.enter_context(patch(name,side_effect=AssertionError('operational boundary fenced'),create=name=='os.pidfd_open'))
        self.result = selected(E.actor(ACTOR),{'retained_result'})['retained_result']

    def test_exact_parent_bodies_and_complete_edit_inverse(self):
        self.assertEqual((len(ACTOR),hashlib.sha256(ACTOR).hexdigest()),
            (24697,'ce920ce825f28f0d175576b00fbb2ebd4529f92f6aabdc32ce2124e8a1f69058'))
        self.assertEqual((len(PRODUCER),hashlib.sha256(PRODUCER).hexdigest()),
            (14879,'4c6db02555123c1878da8610fdf807e4f82ad6b8a3cf20257dc11aec73a01c24'))
        self.assertEqual(E.actor_inverse(E.actor(ACTOR)),ACTOR)
        self.assertEqual(E.producer_inverse(E.producer(PRODUCER)),PRODUCER)

    def test_fresh_owned_temporary_layer_model_and_same_result_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)/'cachy-asahi-perl-lifecycle'
            out = self.result(parent,os.getuid(),os.getgid())
            self.assertEqual(out.name,'result')
            for path in (parent,out):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
                self.assertEqual((path.stat().st_uid,path.stat().st_gid),(os.getuid(),os.getgid()))
                self.assertEqual(path.stat().st_dev,Path(directory).stat().st_dev)
            (out/'report.json').write_text('{"fixture":"not an actor result"}\n')
            self.assertEqual(json.loads((out/'report.json').read_bytes())['fixture'],'not an actor result')

    def test_existing_directory_file_symlink_or_dangling_link_refuses_without_mutation(self):
        for kind in ('directory','file','symlink','dangling'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root/'cachy-asahi-perl-lifecycle'
                target = root/'unrelated'
                target.write_bytes(b'preserve')
                if kind=='directory':
                    parent.mkdir();(parent/'sentinel').write_bytes(b'preserve')
                elif kind=='file':parent.write_bytes(b'preserve')
                else:parent.symlink_to(target if kind=='symlink'else root/'absent')
                before = parent.lstat()
                with self.assertRaises(ValueError):self.result(parent,os.getuid(),os.getgid())
                self.assertEqual((before.st_dev,before.st_ino,before.st_mode),(parent.lstat().st_dev,parent.lstat().st_ino,parent.lstat().st_mode))
                self.assertEqual(target.read_bytes(),b'preserve')

    def test_atomic_creation_refuses_race_without_reusing_or_removing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)/'cachy-asahi-perl-lifecycle'
            original = Path.mkdir
            def race(path,*args,**kwargs):
                if path==parent:path.write_bytes(b'appeared after absence check')
                return original(path,*args,**kwargs)
            with patch.object(Path,'mkdir',race),self.assertRaises(FileExistsError):
                self.result(parent,os.getuid(),os.getgid())
            self.assertEqual(parent.read_bytes(),b'appeared after absence check')

    def test_wrong_owner_group_mode_or_filesystem_refuses(self):
        for kind in ('uid','gid','mode','device'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)/'cachy-asahi-perl-lifecycle'
                uid,gid = os.getuid(),os.getgid()
                if kind=='uid':uid+=1
                if kind=='gid':gid+=1
                original_mkdir,original_stat = Path.mkdir,Path.stat
                def mkdir(path,*args,**kwargs):
                    original_mkdir(path,*args,**kwargs)
                    if kind=='mode'and path==parent:path.chmod(0o755)
                def stats(path,*args,**kwargs):
                    info=original_stat(path,*args,**kwargs)
                    return SimpleNamespace(st_dev=info.st_dev+1)if kind=='device'and path==parent.parent else info
                with patch.object(Path,'mkdir',mkdir),patch.object(Path,'stat',stats),self.assertRaises(ValueError):
                    self.result(parent,uid,gid)

    def test_native_call_is_fixed_root_path_and_uid_gid_zero_before_commands(self):
        body=E.actor(ACTOR).decode();tree=ast.parse(body)
        execute=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='execute')
        calls=[n for n in ast.walk(execute)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='retained_result']
        self.assertEqual(len(calls),1)
        self.assertEqual(ast.literal_eval(calls[0].args[0].args[0]),E.RESULT_PARENT)
        self.assertEqual([ast.literal_eval(x)for x in calls[0].args[1:]],[0,0])
        self.assertLess(body.index(E.ACTOR_NEW.decode()),body.index("run('user-edits'"))
        self.assertIn("report['retained_output']",body)

    def test_all_other_actor_and_producer_functions_unchanged(self):
        functions=lambda b:{n.name:ast.dump(n)for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
        old,new=functions(ACTOR),functions(E.actor(ACTOR))
        self.assertEqual(set(new)-set(old),{'retained_result'})
        for name in set(old)-{'execute'}:self.assertEqual(old[name],new[name],name)
        old,new=functions(PRODUCER),functions(E.producer(PRODUCER))
        for name in set(old)-{'execute'}:self.assertEqual(old[name],new[name],name)
        self.assertIn("int(status['CapEff'].strip(), 16) == 0x800400cb",E.actor(ACTOR).decode())
        self.assertIn("int(status['CapPrm'].strip(), 16) == 0x800400cb",E.actor(ACTOR).decode())

    def test_export_path_matches_and_old_tmpfs_path_is_not_used(self):
        actor=E.actor(ACTOR);producer=E.producer(PRODUCER)
        self.assertNotIn(E.ACTOR_OLD,actor);self.assertNotIn(E.PRODUCER_OLD,producer)
        self.assertIn(E.RESULT_PARENT.encode(),actor);self.assertIn(E.RESULT_PATH.encode(),producer)
        self.assertIn(b"cap=64*1024**2",producer)
        self.assertIn(b"output / 'data/report.json',16*1024**2",producer)
        self.assertIn(b"/work/baseline.conf",actor)
        self.assertIn(b"/work/pacman.conf",actor)

    def test_same_bounded_tar_result_ABI(self):
        unpack=selected(E.producer(PRODUCER),{'unpack'})['unpack']
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:')as tar:
            body=b'{"fixture":"not a runtime result"}\n'
            item=tarfile.TarInfo('result/report.json');item.size=len(body);tar.addfile(item,io.BytesIO(body))
        with tempfile.TemporaryDirectory()as directory:
            unpack(stream.getvalue(),Path(directory))
            self.assertEqual((Path(directory)/'report.json').read_bytes(),body)
        for name,kind in [('wrong/report.json',tarfile.REGTYPE),('result/../escape',tarfile.REGTYPE),('result/link',tarfile.SYMTYPE)]:
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w:')as tar:
                item=tarfile.TarInfo(name);item.type=kind
                if kind==tarfile.SYMTYPE:item.linkname='/outside'
                tar.addfile(item)
            with tempfile.TemporaryDirectory()as directory,self.assertRaises(ValueError):unpack(stream.getvalue(),Path(directory))

    def test_producer_requires_exact_retained_output_proof(self):
        tree=ast.parse(E.producer(PRODUCER))
        gate=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and len(n.args)==2
                  and isinstance(n.args[1],ast.Constant)and n.args[1].value=='complete same-Source successful actual lifecycle')
        predicate=compile(ast.Expression(gate.args[0]),'<pure-retention-gate>','eval')
        proof=dict(parent=E.RESULT_PARENT,path=E.RESULT_PATH,uid=0,gid=0,mode=0o700,
                   storage='OWNED_CONTAINER_WRITABLE_LAYER',parent_absent_before_entry=True,
                   same_filesystem_as_parent_root=True)
        actor=dict(first_failure=None,status='PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE',
                   source_map_sha256='a'*64,admission_sha256='b'*64,cleanup=dict(failures=[]),retained_output=proof)
        scope=dict(run=SimpleNamespace(returncode=0),row=dict(State=dict(ExitCode=0)),actor=actor,
                   args=SimpleNamespace(source_map_sha256='a'*64,admission_sha256='b'*64))
        self.assertTrue(eval(predicate,scope))
        for key,value in [('parent','/work'),('path','/work/result'),('uid',1),('gid',1),('mode',0o755),
                          ('storage','TMPFS'),('parent_absent_before_entry',False),
                          ('same_filesystem_as_parent_root',False),('extra',True)]:
            actor['retained_output']=dict(proof,**{key:value})
            with self.subTest(key=key):self.assertFalse(eval(predicate,scope))
        del actor['retained_output']
        with self.assertRaises(KeyError):eval(predicate,scope)

    def test_wrong_or_repeated_source_edit_refuses(self):
        for body in (ACTOR.replace(E.ACTOR_OLD,b'wrong'),E.actor(ACTOR)):
            with self.assertRaises(ValueError):E.actor(body)
        for body in (PRODUCER.replace(E.PRODUCER_OLD,b'wrong'),E.producer(PRODUCER)):
            with self.assertRaises(ValueError):E.producer(body)

if __name__=='__main__':unittest.main()
