"""Concrete constructor and durable-journal failures; no target/native actor."""
import ast
import errno
import importlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

P=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(P/'overlay/native'))
A=importlib.import_module('security_recovery_adapter')
J=importlib.import_module('security_recovery_journal')
O=importlib.import_module('security_interruption_owner')
B=dict(source='a'*40,ref='refs/heads/codex/unbound-create-failure',run='9000000000141',attempt=1,
       map_sha256='b'*64,token='c'*24)


class ProductionWiringFailures(unittest.TestCase):
    def test_real_production_constructor_receives_exact_existing_runner(self):
        with tempfile.TemporaryDirectory()as directory:
            runner=O.OwnedProcessRunner(directory)
            with patch.object(A.NativeCommandAdapter,'_setup')as setup:
                A.NativeCommandAdapter(123,{},object(),object(),journal='unbound-journal',runner=runner)
                self.assertIs(setup.call_args.args[4],runner)
                self.assertEqual(setup.call_args.args[5:],('unbound-journal',False))
                setup.reset_mock()
                with self.assertRaises(ValueError):
                    A.NativeCommandAdapter(123,{},object(),object(),journal='unbound-journal',runner=object())
                setup.assert_not_called()
                with self.assertRaises(TypeError):
                    A.NativeCommandAdapter(123,{},object(),object(),journal='unbound-journal')
                setup.assert_not_called()
    def test_episode_reuses_one_private_runner_and_counter_for_all_commands(self):
        native=ast.parse((P/'overlay/native/security_recovery_native.py').read_bytes())
        constructors=[n for n in ast.walk(native)if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Name)and n.func.id=='OwnedProcessRunner']
        self.assertEqual(len(constructors),1)
        self.assertEqual([ast.unparse(a)for a in constructors[0].args],["PREFIX / 'owned'"])
        assignments=[n for n in ast.walk(native)if isinstance(n,ast.Assign)
            and n.value is constructors[0]]
        self.assertEqual([ast.unparse(t)for t in assignments[0].targets],['self.runner'])
        adapters=[n for n in ast.walk(native)if isinstance(n,ast.Call)
            and isinstance(n.func,ast.Name)and n.func.id=='NativeCommandAdapter']
        self.assertEqual(len(adapters),1)
        self.assertEqual([ast.unparse(k.value)for k in adapters[0].keywords if k.arg=='runner'],['self.runner'])
        methods=[n for n in ast.walk(native)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)
            and n.func.attr in ('run','interrupt')]
        self.assertEqual(sorted(ast.unparse(n.func)for n in methods),['self.runner.interrupt','self.runner.run'])
        # Owned output stems increase on the same instance; no new counter is
        # constructed between warm, compile, interruption and recovery commands.
        owner=ast.parse((P/'overlay/native/security_interruption_owner.py').read_bytes())
        execute=next(n for n in ast.walk(owner)if isinstance(n,ast.FunctionDef)and n.name=='_execute')
        self.assertTrue(any(isinstance(n,ast.AugAssign)and ast.unparse(n.target)=='self.counter'
            and isinstance(n.op,ast.Add)and ast.literal_eval(n.value)==1 for n in ast.walk(execute)))
    def test_every_journal_post_open_initialization_failure_closes_descriptors(self):
        real_open,real_fchmod,real_fsync,real_write=os.open,os.fchmod,os.fsync,os.write
        for stage in ('fchmod','parent-open','parent-fsync','created-write','created-fsync'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory()as directory:
                target=Path(directory)/'journal.jsonl';opened=[];sync_calls=[]
                def open_fd(path,flags,*args,**kwargs):
                    if stage=='parent-open'and flags&os.O_DIRECTORY:raise OSError(errno.EIO,'injected directory open')
                    fd=real_open(path,flags,*args,**kwargs);opened.append(fd);return fd
                def chmod_fd(fd,mode):
                    if stage=='fchmod':raise OSError(errno.EIO,'injected fchmod')
                    return real_fchmod(fd,mode)
                def sync_fd(fd):
                    sync_calls.append(fd)
                    if stage=='parent-fsync'and len(sync_calls)==1 or stage=='created-fsync'and len(sync_calls)==2:
                        raise OSError(errno.EIO,'injected fsync')
                    return real_fsync(fd)
                def write_fd(fd,raw):
                    if stage=='created-write':raise OSError(errno.EIO,'injected append')
                    return real_write(fd,raw)
                with patch.object(J.os,'open',open_fd),patch.object(J.os,'fchmod',chmod_fd),\
                     patch.object(J.os,'fsync',sync_fd),patch.object(J.os,'write',write_fd):
                    with self.assertRaises(OSError):J.Journal.create(target,B)
                self.assertTrue(opened);self.assertTrue(target.is_file())
                for fd in opened:
                    with self.assertRaises(OSError)as caught:os.fstat(fd)
                    self.assertEqual(caught.exception.errno,errno.EBADF)
                with self.assertRaises(FileExistsError):J.Journal.create(target,B)
                try:loaded=J.load(target,B)
                except ValueError:pass  # Empty/partial create is uncertain DATA.
                else:
                    self.assertFalse(loaded['complete']);self.assertFalse(loaded['resume_allowed'])
    def test_append_fsync_failure_breaks_writer_without_phase_advance_or_retry(self):
        with tempfile.TemporaryDirectory()as directory:
            target=Path(directory)/'journal.jsonl'
            with J.Journal.create(target,B)as journal:
                with patch.object(J.os,'fsync',side_effect=OSError(errno.EIO,'injected append fsync')):
                    with self.assertRaises(OSError):journal.append('BASELINE_RECORDED',{})
                self.assertTrue(journal.broken);self.assertEqual(journal.phase,'CREATED')
                with self.assertRaises(ValueError):journal.append('BASELINE_RECORDED',{})
                with self.assertRaises(ValueError):journal.append('FAILED',{'retry':False})
            with self.assertRaises(FileExistsError):J.Journal.create(target,B)
            self.assertFalse(J.load(target,B)['resume_allowed'])

if __name__=='__main__':unittest.main(verbosity=2)
