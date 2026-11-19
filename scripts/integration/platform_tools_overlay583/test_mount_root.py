# SPDX-License-Identifier: MIT
"""Fenced source controls. Native mount calls are inert doubles."""
from base64 import b64encode
from contextlib import redirect_stderr
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def deny(event, _args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in (
            'os.exec','os.fork','os.forkpty','os.kill','os.killpg','os.posix_spawn','os.system'):
        raise AssertionError('native actor forbidden in source control: '+event)


sys.addaudithook(deny)
sys.path.insert(0, str(HERE))
import mount_root as G
import namespace_failure as T
from project_mount_root import GUEST, ORIGINAL, TARGET, pin, project, encoded, HANDOFF
from tempfile import TemporaryDirectory
NONCE = 'ab'*16
PARENT, OWNER = 'mnt:[40]', 'mnt:[50]'
DIRS = {'':(33,15),'proc':(34,1),'dev':(35,1),'sys':(36,1),'run':(37,1)}


def mounts(target, *, bad=False):
    if target:
        return ('1 0 9:8 / / ro - ext4 boot ro\n'
                '5 1 9:5 / /trial-code ro,nosuid,nodev,noexec - ext4 inputs ro\n'
                '6 1 9:6 / /trial-work rw,nosuid,nodev - ext4 scratch rw\n'
                + api_rows('/trial-work/target',6))
    return ('8 0 9:6 /target / rw,nosuid,nodev - ext4 scratch rw\n'
            + api_rows('',8)+(('1 8 9:8 / /boot-still-here ro - ext4 boot ro\n') if bad else ''))


def api_rows(path, parent):
    return ''.join(f'{i} {parent} 23:{i} / {path}/{role} rw,nosuid,noexec - {kind} {kind} rw\n'
                   for i,(role,kind) in enumerate(G.API_MOUNTS.items(),10))


def receipt(**values):
    return dict(dict(exit=1,reaped=True,output_complete=True,ownership='REAPED',
                     group_census='EMPTY_TWICE',timeout=False,signals=[],error=None),**values)


class FakeKernel:
    def __init__(self, *, fail=None, bad=False, wrong_target=False, escaped=False):
        self.trace=[]
        self.fail, self.bad = fail,bad
        self.wrong_target, self.escaped = wrong_target,escaped
        self.in_private,self.detached=False,False
        self.proc = SimpleNamespace(pid_one=PARENT, self_mnt=PARENT)

    def libc_call(self, label, action=lambda:None):
        def apply(*args):
            self.trace.append((label,args))
            if self.fail==label:
                return -1
            action()
            return 0
        return apply

    def libc(self):
        def private():
            self.in_private=True
            self.proc.self_mnt=OWNER
        def detach():
            self.detached=True
        return SimpleNamespace(unshare=self.libc_call('unshare',private),mount=self.libc_call('mount'),
                               syscall=self.libc_call('pivot_root'),umount2=self.libc_call('umount2',detach))

    def path(self, value):
        path = Path(value)
        mock=SimpleNamespace(read_text=lambda:mounts(not self.detached,bad=self.bad))
        if path==Path('/proc/self/mountinfo'):
            return mock
        if path==Path('/proc/cmdline'):
            return SimpleNamespace(read_text=lambda:'cachy_overlay583_nonce='+NONCE)
        if path==Path('/sys/class/net'):
            return SimpleNamespace(iterdir=lambda:iter((Path('/lo'),)))
        return path

    def execute(self):
        def lookup(path):
            return self.proc.pid_one if path=='/proc/1/ns/mnt' else self.proc.self_mnt
        def directory(path):
            self.trace.append(('chdir',path))
        def execve(*args):
            self.trace.append(('execve',args))
        def identity(path):
            return DIRS[path.name if path.name in G.API_MOUNTS else '']
        def stat_path(path):
            return SimpleNamespace(st_dev=11 if path==Path('/') or self.wrong_target and path==G.TARGET else 33)
        def resolved(path, **_):
            return Path('/foreign') if self.escaped and path==G.TARGET else path
        libc=self.libc()
        fake_ctypes=SimpleNamespace(CDLL=lambda *_args,**_kw:libc,c_int=int,c_char_p=bytes,c_long=int,
                                    c_ulong=int,get_errno=lambda:1)
        fake_os=SimpleNamespace(getuid=lambda:0,geteuid=lambda:0,uname=lambda:SimpleNamespace(machine='aarch64'),
                                sysconf=lambda _:16384,readlink=lookup,chdir=directory,execve=execve,
                                fsencode=lambda path:str(path).encode())
        fake_sys=SimpleNamespace(executable=G.STOCK_PYTHON,flags=SimpleNamespace(isolated=True),
                                 dont_write_bytecode=True,stderr=sys.stderr)
        out=StringIO()
        with (patch.dict(sys.modules,{'ctypes':fake_ctypes}),patch.object(G,'os',fake_os),
              patch.object(G,'sys',fake_sys),patch.object(G,'Path',self.path),
              patch.object(G,'__file__','/trial-code/first-login/guest.py'),patch.object(G,'identity',identity),
              patch.object(Path,'resolve',resolved),patch.object(Path,'is_dir',lambda _:True),
              patch.object(Path,'stat',stat_path),redirect_stderr(out)):
            fake_sys.stderr=out
            G.enter_private_root(NONCE)
        return out.getvalue().encode()


class Controls(unittest.TestCase):
    def test_guest_owner_pivots_private_clone_and_execs_unchanged_runuser(self):
        k=FakeKernel()
        raw=k.execute()
        self.assertEqual([item[0] for item in k.trace],
                         ['unshare','mount','mount','chdir','pivot_root','umount2','chdir','execve'])
        self.assertEqual(k.trace[0][1],(0x20000,))
        self.assertEqual(k.trace[1][1],(None,b'/',None,0x44000,None))
        target=b'/trial-work/target'
        self.assertEqual(k.trace[2][1],(target,target,None,0x5000,None))
        self.assertEqual(k.trace[4][1],(41,b'.',b'.'))
        self.assertEqual(k.trace[5][1],(b'.',2))
        self.assertEqual(k.trace[-1][1],('/usr/bin/runuser',[
            '/usr/bin/runuser','-u','caa-platform-v2-guest','--','/usr/bin/env','-i',
            'PATH=/usr/bin:/bin','LC_ALL=C','TZ=UTC','HOME=/run/caa-platform-tools-v2-overlay583/home',
            '/usr/bin/python3','-I','-B','/run/caa-platform-tools-v2-overlay583/target.py',NONCE,
        ],{'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'}))
        self.assertEqual(G.journey_root_evidence(raw,NONCE,required=True)['owner'],OWNER)

    def test_mount_failure_and_old_root_visibility_never_enter_runuser(self):
        for k in (FakeKernel(fail='unshare'),FakeKernel(fail='pivot_root'),FakeKernel(fail='umount2'),FakeKernel(bad=True)):
            with self.subTest(k=k.fail),self.assertRaises((OSError,ValueError)):
                k.execute()
            self.assertNotIn('execve',[item[0] for item in k.trace])

    def test_private_root_join_and_failure_marker(self):
        mount=FakeKernel().execute()
        ordinary=b64encode(json.dumps(dict(ns=dict(mnt=OWNER))).encode()).decode()
        output=json.dumps(dict(commands=dict(ordinary=dict(output=ordinary)))).encode()
        self.assertEqual(G.journey_observations(output,mount,NONCE,0)['root']['owner'],OWNER)
        for bad in (b'',mount+mount,mount.replace(PARENT.encode(),OWNER.encode()),mount.replace(NONCE.encode(),b'0'*32)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                G.journey_observations(output,bad,NONCE,0)
        with self.assertRaises(ValueError):
            other=output.replace(ordinary.encode(),b64encode(b'{"ns":{"mnt":"mnt:[4]"}}'))
            G.journey_observations(other,mount,NONCE,0)
        failure=T.namespace_hold(b'bwrap: Failed to mount /PRIVATE: Operation not permitted\n',receipt())
        marker=T.NAMESPACE_HOLD_MARKER.encode()+json.dumps(failure,sort_keys=True,separators=(',',':')).encode()+b'\n'
        self.assertEqual(G.journey_observations(b'',mount+marker,NONCE,1)['namespace_hold'],failure)
        for bad in (marker,mount+marker+marker):
            with self.assertRaises(ValueError):
                G.journey_observations(b'',bad,NONCE,1)

    def test_diagnostic_only_on_complete_natural_nonzero(self):
        private=b"bwrap: Can't mount /PRIVATE: Operation not permitted\n"
        result=T.namespace_hold(private,receipt())
        self.assertEqual(result,dict(bytes=len(private),sha256=sha256(private).hexdigest(),exit=1,
                                     reason='BWRAP_MOUNT_PERMISSION'))
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(T.namespace_hold(b'bwrap: No permissions to create a new namespace, known suffix\n',
                                          receipt())['reason'],'BWRAP_USER_NAMESPACE_PERMISSION')
        self.assertEqual(T.namespace_hold(b'other bytes\n'+private,receipt())['reason'],'UNCLASSIFIED')
        for fields in (dict(output_complete=False),dict(reaped=False),dict(timeout=True),dict(signals=[9]),
                       dict(group_census='PARTIAL'),dict(exit=-9),dict(exit=0),dict(error='held')):
            self.assertIsNone(T.namespace_hold(private,receipt(**fields)))

    def test_wrong_device_and_symlink_target_never_open_mount_namespace(self):
        for k in (FakeKernel(wrong_target=True),FakeKernel(escaped=True)):
            with self.assertRaisesRegex(ValueError,'exact owned offline'):
                k.execute()
            self.assertEqual(k.trace,[])

    def test_boot_root_and_api_mounts_must_have_exact_protected_geometry(self):
        valid = mounts(True)
        self.assertEqual(G.root_snapshot(G.mount_rows(valid),G.TARGET),1)
        for changed in (
                valid.replace('/ / ro - ext4','/ / rw - ext4'),
                valid.replace('rw,nosuid,noexec - proc','rw,nosuid - proc'),
                valid.replace('/trial-work/target/proc','/another-target/proc'),
                valid.replace('1 0 9:8','1 6 9:8'),
        ):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                G.root_snapshot(G.mount_rows(changed),G.TARGET)

    def test_projector_refuses_rewritten_or_wrongly_pinned_source(self):
        with TemporaryDirectory() as location:
            stage = Path(location)
            source = stage/'source'/GUEST
            source.parent.mkdir(parents=True)
            source.write_bytes(b'raise AssertionError("never import selected source")\n')
            changed = pin(source.read_bytes())
            self.assertNotEqual(changed['sha256'], ORIGINAL[GUEST])
            raw = encoded(dict(kind=HANDOFF,source={GUEST:changed,TARGET:changed}))
            (stage/'HANDOFF.DATA.json').write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'Exact sealed Platform Tools'):
                project(stage,'0'*64)
            with self.assertRaisesRegex(ValueError,'Unexpected predecessor source'):
                project(stage,pin(raw)['sha256'])


if __name__=='__main__':
    unittest.main()
