# SPDX-License-Identifier: MIT
"""Real temporary copy/disposal recovery; namespace and inventory are models only.

No namespace, authentication, ALPM, full574, native ARM or M2 acceptance.
"""
from contextlib import ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
spec=importlib.util.spec_from_file_location('prepare_copy_recovery_backend',ROOT/'scripts/apps/transaction.py')
T=importlib.util.module_from_spec(spec);sys.modules[spec.name]=T;spec.loader.exec_module(T)


class Recovery(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='repair-copy-preparation-',dir=os.environ.get('APPS_COPY_RECOVERY_WORK'))
        self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name);self.base.chmod(0o700)
        space=os.statvfs(self.base)
        self.filesystem=dict(parent=str(self.base.parent),available_bytes=space.f_bavail*space.f_frsize,
                             available_inodes=space.f_favail,capacity_checker='ORIGINAL_UNCHANGED')
        self.source=self.base/'seed';self.workspace=self.base/'copy';self.root=self.workspace/'root'
        for name in('var/lib/pacman/local/fixture-1-1','home/user','etc/pacman.d','usr/share/fixture'):
            (self.source/name).mkdir(parents=True,exist_ok=True)
        for name,data in(
            ('var/lib/pacman/local/ALPM_DB_VERSION',b'9\n'),
            ('var/lib/pacman/local/fixture-1-1/desc',b'%NAME%\nfixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n'),
            ('var/lib/pacman/local/fixture-1-1/files',b'%FILES%\nusr/share/fixture/payload\n\n'),
            ('home/user/note',b'preserved private fixture user bytes\n'),
            ('etc/pacman.d/public',b'preserved inert fixture trust bytes\n'),
            ('usr/share/fixture/payload',b'fixture payload only\n'*64)):
            path=self.source/name;path.write_bytes(data);path.chmod(0o644)
        os.link(self.source/'usr/share/fixture/payload',self.source/'usr/share/fixture/alias')
        (self.source/'usr/share/fixture/link').symlink_to('payload')
        self.before=T.observe(self.source,T.limits())
        self.source_state=self.state(self.source)
        self.args=types.SimpleNamespace(source=str(self.source),workspace=str(self.workspace))
        self.inventory=dict(packages=[dict(name='fixture',version='1-1')])
        self.inventory_calls=[];self.events=[]
        def collect(path,*args):
            self.assertIn(path,(self.source/T.DB,self.root/T.DB))
            self.inventory_calls.append(path)
            return copy.deepcopy(self.inventory)
        app=types.SimpleNamespace(inventory_reader=lambda:types.SimpleNamespace(collect=collect),package=lambda row,r:dict(row))
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(T,'environment_guard',return_value='79'*16))
        original_private=T.I.private
        def private(path,uid):
            self.assertEqual(uid,0)
            return original_private(path,os.getuid())
        self.stack.enter_context(patch.object(T.I,'private',side_effect=private))
        self.stack.enter_context(patch.object(T,'app_source',return_value=(app,None,None)))
        self.alpm=self.stack.enter_context(patch.object(T.F,'Alpm',side_effect=AssertionError('ALPM forbidden')))
        self.commit=self.stack.enter_context(patch.object(T,'commit',side_effect=AssertionError('commit forbidden')))
        self.copy=self.stack.enter_context(patch.object(T.COPY,'copy_data',wraps=T.COPY.copy_data))
        self.dispose=self.stack.enter_context(patch.object(T,'dispose',wraps=T.dispose))

    def state(self,root):
        result={}
        for path in(root,*sorted(root.rglob('*'))):
            info=path.lstat()
            result[path.relative_to(root).as_posix()]=dict(
                identity=(info.st_dev,info.st_ino),mode=info.st_mode,uid=info.st_uid,gid=info.st_gid,
                nlink=info.st_nlink,size=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns,
                data=os.readlink(path)if path.is_symlink()else path.read_bytes()if path.is_file()else None)
        return result

    def assert_source_held(self):
        self.assertEqual(T.observe(self.source,T.limits())['nodes'],self.before['nodes'])
        self.assertEqual(self.state(self.source),self.source_state)
        self.alpm.assert_not_called();self.commit.assert_not_called()

    def assert_disposed(self,identity):
        self.copy.assert_called_once()
        self.dispose.assert_called_once_with(self.workspace,identity)
        self.assertFalse(self.workspace.exists())
        self.assert_source_held()
        print(json.dumps(dict(test=self._testMethodName,scope='SOURCE_TEMP_ONLY_NAMESPACE_AND_INVENTORY_MODELED',
              events=self.events,fixture_filesystem=self.filesystem,
              real_copier_calls=self.copy.call_count,real_dispose_calls=self.dispose.call_count,
              disposed_owned_inode=identity,workspace_absent=True,source_full_nodes_bytes_identities_held=True,
              ALPM='NOT_RUN',native='NOT_RUN',hardware='NOT_RUN'),sort_keys=True))

    def successful_preparation_and_disposal(self):
        result=T.prepare_copy(self.args)
        self.assertEqual(result['status'],'OWNED_COPY_PREPARED')
        self.assertEqual(result['transaction'],'NOT_RUN');self.assertEqual(result['hardware'],'NOT_RUN')
        self.assertTrue(result['source_preserved'])
        self.assertEqual(T.observe(self.root,T.limits())['nodes'],self.before['nodes'])
        raw=(self.workspace/T.MARKER).read_bytes();owner=json.loads(raw)
        self.assertEqual(T.sha(raw),result['ownership_sha256'])
        self.assertEqual(owner['workspace'],T.inode(self.workspace));self.assertEqual(owner['root'],T.inode(self.root))
        self.assertEqual(owner['source_tree_sha256'],T.sha(T.encoded(self.before['nodes'])))
        self.assertEqual(owner['purpose'],T.PURPOSE);self.assertEqual(owner['token'],'79'*16)
        self.assertTrue(owner['copy']['copy_complete'])
        self.events.append(dict(phase='PREPARED_REAL_COPY',nodes=len(self.before['nodes']),copy_complete=True))
        self.assertEqual(result['before'],T.pins(T.observe(self.root,T.limits()),self.inventory))
        self.assertEqual((self.workspace/T.LOCK).read_bytes(),b'')
        for name in(T.MARKER,T.LOCK):
            info=(self.workspace/name).lstat()
            self.assertEqual(stat.S_IMODE(info.st_mode),0o600);self.assertEqual(info.st_nlink,1)
        self.assertEqual(self.inventory_calls,[self.source/T.DB,self.root/T.DB])
        self.dispose.assert_not_called();self.assert_source_held()
        identity=T.inode(self.workspace);T.dispose(self.workspace,identity)
        self.assert_disposed(identity)

    def test_success_actual_markers_exact_copy_and_explicit_real_disposal(self):
        self.successful_preparation_and_disposal()

    def marker_failure(self,name,error):
        original_fsync=os.fsync;injected=[];identities=[]
        def fsync(fd):
            path=self.workspace/name
            if path.exists()and T.inode(path)==[os.fstat(fd).st_dev,os.fstat(fd).st_ino]:
                self.assertEqual(T.observe(self.root,T.limits())['nodes'],self.before['nodes'])
                self.assertEqual(self.inventory_calls,[self.source/T.DB,self.root/T.DB])
                self.copy.assert_called_once()
                self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
                self.assertEqual(os.fstat(fd).st_nlink,1)
                self.assertEqual(os.lseek(fd,0,os.SEEK_CUR),path.stat().st_size)
                marker=json.loads((self.workspace/T.MARKER).read_bytes())
                self.assertTrue(marker['copy']['copy_complete'])
                self.assertEqual(marker['root'],T.inode(self.root))
                self.events.append(dict(phase='FSYNC_INJECTED_AFTER_COMPLETE_REAL_COPY',marker=name,
                                        fd_inode=[os.fstat(fd).st_dev,os.fstat(fd).st_ino],
                                        root_nodes_equal_source=True,copy_complete=True))
                if name==T.MARKER:self.assertFalse((self.workspace/T.LOCK).exists())
                else:
                    self.assertEqual(path.read_bytes(),b'')
                    self.assertEqual(marker['workspace'],T.inode(self.workspace))
                injected.append(name);identities.append(T.inode(self.workspace));raise error
            return original_fsync(fd)
        with patch.object(os,'fsync',side_effect=fsync),self.assertRaises(type(error))as caught:
            T.prepare_copy(self.args)
        self.assertIs(caught.exception,error);self.assertEqual(injected,[name])
        self.assert_disposed(identities[0])

    def test_marker_fsync_oserror_after_real_complete_copy_disposes(self):
        self.marker_failure(T.MARKER,OSError('injected ownership marker fsync failure'))
        # Failed preparation was fully disposed; no package commit was attempted.
        self.copy.reset_mock();self.dispose.reset_mock();self.inventory_calls.clear()
        self.events.append(dict(phase='EXPLICIT_FRESH_PREPARATION_AFTER_FAILED_COPY_DISPOSED',same_workspace_path=True))
        self.successful_preparation_and_disposal()

    def test_lock_fsync_oserror_after_real_complete_copy_disposes(self):
        self.marker_failure(T.LOCK,OSError('injected lock marker fsync failure'))

    def test_lock_fsync_keyboard_interrupt_disposes_without_positive_result(self):
        self.marker_failure(T.LOCK,KeyboardInterrupt('injected lock fsync interruption'))

    def test_partial_real_copy_write_keyboard_interrupt_disposes(self):
        original_write=os.write;error=KeyboardInterrupt('injected partial real copier write')
        partial=[];identities=[]
        def write(fd,data):
            self.assertFalse(partial,'only the interrupted first write may occur')
            path=Path(os.readlink('/proc/self/fd/'+str(fd)))
            self.assertTrue(path.is_relative_to(self.root));self.assertGreater(len(data),1)
            count=original_write(fd,data[:max(1,len(data)//2)])
            self.assertGreater(count,0);self.assertLess(os.fstat(fd).st_size,len(data))
            self.assertEqual(path.read_bytes(),bytes(data[:count]))
            self.assertFalse((self.workspace/T.MARKER).exists())
            self.events.append(dict(phase='INTERRUPTED_ACTUAL_COPIER_WRITE',written=count,
                                    requested=len(data),partial_destination_exists=True,ownership_marker_absent=True))
            partial.append((str(path),count,len(data)));identities.append(T.inode(self.workspace))
            raise error
        with patch.object(os,'write',side_effect=write),self.assertRaises(KeyboardInterrupt)as caught:
            T.prepare_copy(self.args)
        self.assertIs(caught.exception,error);self.assertEqual(len(partial),1)
        self.assertEqual(self.inventory_calls,[self.source/T.DB])
        self.assert_disposed(identities[0])


if __name__=='__main__':unittest.main(verbosity=2)
