#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Owned HOST-only root/.ssh absence/metadata controls; no real SSH or guest state.

Only guest/root-ssh.sh functions execute, projected into MODEL scratch. Shell
body-reading tools reject every target descendant. Private MODEL bytes are
created and checked by this fixture, never by the restoration helper.
"""
import errno
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
SOURCE=(HERE/'guest/root-ssh.sh').read_text()
NONCE='a'*32
ATIME=1785933514000000000
MTIME=1794708503123456789
SENTINEL=b'MODEL_PRIVATE_SENTINEL_BODY_MUST_NOT_BE_READ_BY_HELPER\x00\n'


def limits():
    for name,cap in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,8),
                     (resource.RLIMIT_AS,192*1024**2),(resource.RLIMIT_FSIZE,32*1024**2),
                     (resource.RLIMIT_NOFILE,64)):
        resource.setrlimit(name,(cap,cap))


def fence(event,args):
    if event=='subprocess.Popen':
        if args[0]!='/usr/bin/bash' or args[1][:3]!=['/usr/bin/bash','--noprofile','--norc']:
            raise AssertionError('only finite owned HOST Bash may execute')
    elif event.startswith(('socket.','ctypes.','os.exec','os.fork','os.posix_spawn','fcntl.'))or event=='os.system':
        raise AssertionError('HOST root SSH fixture fence: '+event)
sys.addaudithook(fence)


class Fixture:
    def __init__(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='perl-root-SSH-MODEL-HOST-')
        self.top=Path(self.tmp.name)
        self.root=self.top/'root';self.root.mkdir(mode=0o700)
        self.builder=self.top/'builder';self.builder.mkdir(mode=0o700)
        (self.builder/'MODEL-builder-file').write_bytes(b'HOST builder baseline\n')
        (self.root/'.config').mkdir(mode=0o700)
        self.ssh=self.root/'.ssh'
        self.baseline=self.root/'MODEL-baseline.profile';self.baseline.write_bytes(b'HOST baseline file\n');self.baseline.chmod(0o600)
        self.data=self.top/'case';self.data.mkdir(mode=0o700)
        self.cache=self.data/'cache';self.cache.mkdir(mode=0o700)
        self.run_dir=self.top/'run';self.run_dir.mkdir(mode=0o700)
        self.context=self.data/'preboot-context.json';self.context.write_bytes(b'{"MODEL":"source/case/nonce/baseline provenance tested independently"}\n');self.context.chmod(0o644)
        self.descriptor=self.data/'root-ssh-preboot.tsv'
        self.cmdline=self.top/'cmdline'
        self.reference=self.cache/'root-ssh-parent.reference'
        self.original=None
        self.stamp()

    def close(self):self.tmp.cleanup()

    def stamp(self,mtime=MTIME):
        os.utime(self.root,ns=(ATIME,mtime));self.original=self.root.stat()
        row=self.original
        lines=[f'PERL5423_ROOT_SSH_PREBOOT_V1 {NONCE} {hashlib.sha256(self.context.read_bytes()).hexdigest()}',
               f'P root {row.st_ino} {row.st_nlink} {mtime//10**9} {mtime%10**9}',
               'A root/.ssh d 700 0']
        self.descriptor.write_text('\n'.join(lines)+'\n');self.descriptor.chmod(0o600)
        self.bind()

    def bind(self):
        self.cmdline.write_text('arm16k_perl5423_vm_root_ssh_sha256='+hashlib.sha256(self.descriptor.read_bytes()).hexdigest()+'\n')

    def early_empty(self):self.ssh.mkdir(mode=0o700);self.ssh.chmod(0o700);return self

    def secret(self,*,nested=False):
        if not self.ssh.exists():self.early_empty()
        target=self.ssh/'MODEL-private-key'
        if nested:
            (self.ssh/'MODEL-subdir').mkdir(mode=0o700)
            target=self.ssh/'MODEL-subdir/MODEL-private-key'
        target.write_bytes(SENTINEL);target.chmod(0o600)
        return target

    def run(self,body,*,before='',snapshot=False):
        uid,gid=os.getuid(),os.getgid();text=SOURCE
        replacements=[('/proc/cmdline','"$MODEL_CMDLINE"'),('/root','"$MODEL_ROOT"'),('0:0',f'{uid}:{gid}')]
        for old,new in replacements:
            if old not in text or new in text:raise AssertionError('fixed root SSH HOST projection seam: '+old)
            if old=='/root':text=re.sub(r'/root(?=$|[ /"\'\n])',lambda _:new,text)
            elif old=='0:0':text=re.sub(r'(?<![0-9])0:0(?![0-9])',lambda _:new,text)
            else:text=text.replace(old,new)
        inverse=text
        for old,new in reversed(replacements):inverse=inverse.replace(new,old)
        if inverse!=SOURCE:raise AssertionError('root SSH full projection inverse')
        script='set -Eeuo pipefail\numask 077\nD=$1\nO=$2\nS=$O/root\nmkdir -m700 "$S"\nnonce='+NONCE+'\n'
        script+='file_sha() { local value;value=$(sha256sum -- "$1");printf %s "${value%% *}"; }\n'
        # No helper may read the body of any MODEL .ssh descendant. The empty
        # target directory itself may have its public inode/xattrs inspected.
        script+='''private_operand_guard() {
 local operand
 for operand in "$@";do
  if [[ $operand == "$MODEL_ROOT/.ssh/"* ]];then printf BAD_PRIVATE_BODY_READ >&2;exit 97;fi
 done
}
cat() { private_operand_guard "$@";command cat "$@"; }
head() { private_operand_guard "$@";command head "$@"; }
sha256sum() { private_operand_guard "$@";command sha256sum "$@"; }
cp() { private_operand_guard "$@";command cp "$@"; }
base64() { private_operand_guard "$@";command base64 "$@"; }
'''
        if snapshot:
            root_source=(HERE/'guest/root.sh').read_text()
            start=root_source.index('user_snapshot() (\n')
            end=root_source.index('\nassert_users() {',start)
            snapshot_source=root_source[start:end]
            snapshot_source=snapshot_source.replace('/home/builder','"$MODEL_BUILDER"')
            snapshot_source=re.sub(r'/root(?=$|[ /"\'\n])',lambda _:'"$MODEL_ROOT"',snapshot_source)
            text+='\n'+snapshot_source
        script+=text+'\n'+before+'\n'+body
        result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script,'HOST-root-SSH',str(self.data),str(self.run_dir)],
                              cwd=self.top,env=dict(PATH=str(self.top/'bin')+':/usr/bin:/bin',HOME=str(self.top),LC_ALL='C',TZ='UTC',MODEL_ROOT=str(self.root),MODEL_CMDLINE=str(self.cmdline),MODEL_BUILDER=str(self.builder)),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,preexec_fn=limits)
        if max(len(result.stdout),len(result.stderr))>1048576:raise AssertionError('bounded root SSH helper output')
        if b'BAD_PRIVATE_BODY_READ'in result.stdout+result.stderr:raise AssertionError('helper attempted to read private MODEL body')
        if SENTINEL in result.stdout+result.stderr:raise AssertionError('helper exposed private MODEL body')
        return result

    def assert_baseline(self,test):
        actual=self.root.stat();old=self.original
        test.assertEqual((actual.st_ino,actual.st_mode,actual.st_uid,actual.st_gid,actual.st_nlink,actual.st_mtime_ns),
                         (old.st_ino,old.st_mode,old.st_uid,old.st_gid,old.st_nlink,old.st_mtime_ns))
        test.assertFalse(self.ssh.exists()or self.ssh.is_symlink())
        test.assertFalse(self.reference.exists()or self.reference.is_symlink())
        test.assertEqual(self.baseline.read_bytes(),b'HOST baseline file\n')
        test.assertTrue((self.root/'.config').is_dir())


class Controls(unittest.TestCase):
    def fixture(self,*,early=False):
        f=Fixture();self.addCleanup(f.close)
        if early:f.early_empty()
        return f

    def refuses(self,f,mutation,*,capture_first=True,operation='root_ssh_restore'):
        body=('root_ssh_capture\nprintf CAPTURED\\n\n'if capture_first else'')+mutation+'\n'+operation+'\nprintf BAD_SUCCESS\n'
        result=f.run(body)
        self.assertNotEqual(result.returncode,0,result.stderr.decode());self.assertNotIn(b'BAD_SUCCESS',result.stdout)
        if capture_first:self.assertIn(b'CAPTURED',result.stdout,result.stderr.decode())
        return result

    def test_early_created_empty_directory_is_removed_with_exact_parent_recovery(self):
        f=self.fixture(early=True)
        self.assertEqual(f.root.stat().st_nlink,f.original.st_nlink+1)
        result=f.run('root_ssh_capture\nroot_ssh_guard\nroot_ssh_restore\n')
        self.assertEqual(result.returncode,0,result.stderr.decode());f.assert_baseline(self)

    def test_late_created_empty_directory_is_removed_with_exact_parent_recovery(self):
        f=self.fixture()
        result=f.run('root_ssh_capture\nroot_ssh_guard\nmkdir -m700 "$MODEL_ROOT/.ssh"\nroot_ssh_restore\n')
        self.assertEqual(result.returncode,0,result.stderr.decode());f.assert_baseline(self)

    def test_absent_throughout_is_preserved_and_reference_removed(self):
        f=self.fixture();result=f.run('root_ssh_capture\nroot_ssh_guard\nroot_ssh_restore\n')
        self.assertEqual(result.returncode,0,result.stderr.decode());f.assert_baseline(self)

    def test_initial_nonempty_target_is_refused_without_private_body_reads(self):
        for nested in(False,True):
            with self.subTest(nested=nested):
                f=self.fixture();secret=f.secret(nested=nested)
                self.refuses(f,'',capture_first=False,operation='root_ssh_capture')
                self.assertEqual(secret.read_bytes(),SENTINEL)

    def test_late_nonempty_target_is_refused_without_private_body_reads(self):
        f=self.fixture()
        result=self.refuses(f,'mkdir -m700 "$MODEL_ROOT/.ssh";printf "MODEL_PRIVATE_SENTINEL_BODY_MUST_NOT_BE_READ_BY_HELPER" > "$MODEL_ROOT/.ssh/MODEL-late-secret"')
        self.assertTrue((f.ssh/'MODEL-late-secret').exists());self.assertTrue(f.ssh.is_dir())

    def test_guard_refuses_new_file_or_subdirectory_without_private_body_reads(self):
        for mutation in('printf MODEL_PRIVATE > "$MODEL_ROOT/.ssh/MODEL-secret"','mkdir -m700 "$MODEL_ROOT/.ssh/MODEL-subdir"'):
            with self.subTest(mutation=mutation):
                f=self.fixture(early=True);self.refuses(f,mutation,operation='root_ssh_guard')
                self.assertTrue(f.ssh.is_dir())

    def test_initial_target_type_alias_and_mode_refusals(self):
        for kind in('file','symlink','dangling','mode'):
            with self.subTest(kind=kind):
                f=self.fixture()
                if kind=='file':f.ssh.write_bytes(SENTINEL);f.ssh.chmod(0o600)
                elif kind=='symlink':f.ssh.symlink_to(f.root/'.config')
                elif kind=='dangling':f.ssh.symlink_to(f.top/'absent')
                else:f.early_empty();f.ssh.chmod(0o755)
                self.refuses(f,'',capture_first=False,operation='root_ssh_capture')

    def test_held_target_inode_replacement_or_alias_refuses(self):
        for mutation in('mv "$MODEL_ROOT/.ssh" "$D/original-target";mkdir -m700 "$MODEL_ROOT/.ssh"',
                         'mv "$MODEL_ROOT/.ssh" "$D/original-target";ln -s "$D/original-target" "$MODEL_ROOT/.ssh"'):
            with self.subTest(mutation=mutation):self.refuses(self.fixture(early=True),mutation,operation='root_ssh_guard')

    def test_initial_target_physical_metadata_drift_refuses(self):
        for mutation in('chmod 755 "$MODEL_ROOT/.ssh"','touch -m -d @1 "$MODEL_ROOT/.ssh"'):
            with self.subTest(mutation=mutation):self.refuses(self.fixture(early=True),mutation,operation='root_ssh_guard')

    def test_parent_alias_replacement_mode_or_extra_link_refuses(self):
        cases=('mv "$MODEL_ROOT" "$D/old-root";mkdir -m700 "$MODEL_ROOT"',
               'mv "$MODEL_ROOT" "$D/old-root";ln -s "$D/old-root" "$MODEL_ROOT"',
               'chmod 755 "$MODEL_ROOT"','mkdir -m700 "$MODEL_ROOT/MODEL-unreviewed-directory"')
        for mutation in cases:
            with self.subTest(mutation=mutation):self.refuses(self.fixture(early=True),mutation)

    def test_descriptor_context_nonce_hash_and_token_refusals(self):
        cases=('rm "$D/root-ssh-preboot.tsv"','printf X >> "$D/root-ssh-preboot.tsv"',
               'chmod 644 "$D/root-ssh-preboot.tsv"','ln "$D/root-ssh-preboot.tsv" "$D/descriptor-alias"',
               'printf X >> "$D/preboot-context.json"','nonce=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
               ': > "$MODEL_CMDLINE"',
               'line=$(cat "$MODEL_CMDLINE");printf "%s %s\\n" "$line" "$line" > "$MODEL_CMDLINE"')
        for mutation in cases:
            with self.subTest(mutation=mutation):self.refuses(self.fixture(),mutation,capture_first=False,operation='root_ssh_capture')

    def test_selected_malformed_extra_bytes_blank_line_and_nul_refusals(self):
        for before,after in((b'P root ',b'P ROOT '),(b' d 700 0',b' d 755 0'),
                            (b'P root ',b'P ro\0ot '),(b'PREBOOT_V1',b'PREBOOT_V1\0')):
            with self.subTest(mutation=before):
                f=self.fixture();raw=f.descriptor.read_bytes();self.assertIn(before,raw)
                f.descriptor.write_bytes(raw.replace(before,after,1));f.bind()
                self.refuses(f,'',capture_first=False,operation='root_ssh_capture')
        for suffix in(b'EXTRA',b'\n'):
            with self.subTest(suffix=suffix):
                f=self.fixture();f.descriptor.write_bytes(f.descriptor.read_bytes()+suffix);f.bind()
                self.refuses(f,'',capture_first=False,operation='root_ssh_capture')

    def test_context_or_reference_mutation_refuses_before_directory_removal(self):
        for mutation in('printf X >> "$D/preboot-context.json"','printf X > "$D/cache/root-ssh-parent.reference"',
                         'chmod 644 "$D/cache/root-ssh-parent.reference"',
                         'rm "$D/cache/root-ssh-parent.reference";ln -s "$MODEL_ROOT/MODEL-baseline.profile" "$D/cache/root-ssh-parent.reference"'):
            with self.subTest(mutation=mutation):
                f=self.fixture(early=True);self.refuses(f,mutation);self.assertTrue(f.ssh.is_dir())

    def test_occupied_reference_nodes_refuse_without_clobber(self):
        for kind in('file','symlink','dangling','hardlink','fifo'):
            with self.subTest(kind=kind):
                f=self.fixture();outside=f.top/'MODEL-outside';outside.write_bytes(b'HOST sentinel')
                if kind=='file':f.reference.write_bytes(b'HOST occupied reference')
                elif kind=='symlink':f.reference.symlink_to(outside)
                elif kind=='dangling':f.reference.symlink_to(f.top/'absent')
                elif kind=='hardlink':os.link(outside,f.reference)
                else:os.mkfifo(f.reference)
                initial=f.reference.lstat();self.refuses(f,'',capture_first=False,operation='root_ssh_capture')
                self.assertEqual((f.reference.lstat().st_ino,f.reference.lstat().st_mode),(initial.st_ino,initial.st_mode))
                self.assertEqual(outside.read_bytes(),b'HOST sentinel')

    def test_reference_touch_or_rmdir_errors_propagate(self):
        for mutation in('touch() { return 23; }','rmdir() { return 24; }'):
            with self.subTest(mutation=mutation):self.refuses(self.fixture(early=True),mutation)

    def test_target_recreated_during_parent_touch_refuses_and_retains_reference(self):
        f=self.fixture(early=True)
        # Recreate before the real touch so the expected mtime still matches;
        # only the final absence/link-count guard can catch this late arrival.
        self.refuses(f,'''touch() {
 mkdir -m700 -- "$MODEL_ROOT/.ssh"
 /usr/bin/touch "$@"
}
''')
        self.assertTrue(f.ssh.is_dir())
        self.assertTrue(f.reference.is_file())
        self.assertEqual(f.root.stat().st_nlink,f.original.st_nlink+1)
        self.assertEqual(f.root.stat().st_mtime_ns,f.original.st_mtime_ns)

    def test_zero_and_nonzero_nanoseconds_and_current_atime_preserved(self):
        for mtime in(MTIME,MTIME//10**9*10**9):
            with self.subTest(mtime=mtime):
                f=self.fixture();f.stamp(mtime);f.early_empty();current=1794829001123456789
                result=f.run('root_ssh_capture\nroot_ssh_guard\ntouch -a -d @1794829001.123456789 "$MODEL_ROOT"\nroot_ssh_restore\n')
                self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(f.root.stat().st_atime_ns,current);f.assert_baseline(self)

    def test_parent_xattrs_preserved_and_target_xattr_drift_refused(self):
        f=self.fixture()
        try:
            os.setxattr(f.root,'user.HOST_root_ssh',b'baseline parent');f.stamp();f.early_empty()
            os.setxattr(f.ssh,'user.HOST_root_ssh',b'initial target')
        except OSError as error:
            if error.errno in(errno.ENOTSUP,errno.EOPNOTSUPP):self.skipTest('HOST filesystem has no user xattrs')
            raise
        result=f.run('root_ssh_capture\nroot_ssh_guard\nroot_ssh_restore\n');self.assertEqual(result.returncode,0,result.stderr.decode());f.assert_baseline(self)
        self.assertEqual(os.getxattr(f.root,'user.HOST_root_ssh'),b'baseline parent')
        f=self.fixture(early=True);os.setxattr(f.ssh,'user.HOST_root_ssh',b'initial target')
        self.assertTrue(Path('/usr/bin/setfattr').is_file())
        self.refuses(f,'setfattr -n user.HOST_root_ssh -v CHANGED "$MODEL_ROOT/.ssh"',operation='root_ssh_guard')
        self.assertTrue(f.ssh.is_dir())

    def test_user_snapshot_prunes_only_certified_absent_target_and_racing_descendants(self):
        f=self.fixture(early=True)
        executable=f.top/'bin/sha256sum';executable.parent.mkdir(mode=0o700)
        executable.write_text('''#!/usr/bin/bash
for operand in "$@";do
 if [[ $operand == "$MODEL_ROOT/.ssh/"* ]];then printf BAD_PRIVATE_BODY_READ >&2;exit 97;fi
done
exec /usr/bin/sha256sum "$@"
''');executable.chmod(0o700)
        # The real guard succeeds on empty .ssh; a concurrent writer adds a
        # MODEL file before find. The independent prune must still prevent reads.
        body='''root_ssh_capture
eval "$(declare -f root_ssh_guard | sed '1s/root_ssh_guard/root_ssh_original_guard/')"
root_ssh_guard() {
 if [[ ! -e $MODEL_ROOT/.ssh/MODEL-racing-secret ]];then
  root_ssh_original_guard
  printf 'MODEL_PRIVATE_SENTINEL_BODY_MUST_NOT_BE_READ_BY_HELPER' > "$MODEL_ROOT/.ssh/MODEL-racing-secret"
 fi
 return 0
}
user_snapshot "$D/MODEL-snapshot"
'''
        result=f.run(body,snapshot=True)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        for suffix in ('meta','xattr','hash'):
            output=(f.data/('MODEL-snapshot.'+suffix)).read_bytes()
            self.assertNotIn(b'MODEL-racing-secret',output)
            self.assertNotIn(str(f.ssh).encode(),output)
        for suffix in ('meta','hash'):
            output=(f.data/('MODEL-snapshot.'+suffix)).read_bytes()
            self.assertIn(str(f.baseline).encode(),output)
            self.assertIn(str(f.builder/'MODEL-builder-file').encode(),output)
        self.assertEqual((f.ssh/'MODEL-racing-secret').read_bytes(),SENTINEL.split(b'\0')[0])

    def test_frozen_metadata_comparison_keeps_late_root_link_change_as_hold(self):
        f=self.fixture();(f.root/'.config').rmdir();f.stamp()
        self.assertEqual(f.root.stat().st_nlink,2)
        before_links=f.root.stat().st_nlink;f.early_empty();after_links=f.root.stat().st_nlink
        self.assertEqual(after_links,3)
        frozen=(HERE/'frozen/guest-runtime.sh').read_text()
        compare=frozen[frozen.index('restoration_compare() {'):frozen.index('\n# Only this live procfs root',frozen.index('restoration_compare() {'))]
        equality=frozen[frozen.index('metadata_equality_view() {'):]
        case=(HERE/'guest/case.sh').read_text();start=case.index('same_bytes() {')
        same=case[start:case.index('\nclock_valid()',start)]
        receipts=f.data/'receipts/restoration';receipts.mkdir(mode=0o700,parents=True)
        def metadata(root_links,proc_links):
            rows=[('/root/','41c0',str(os.getuid()),str(os.getgid()),str(root_links),"'/root/'"),
                  ('/proc/','41ed',str(os.getuid()),str(os.getgid()),str(proc_links),"'/proc/'")]
            return b''.join(value.encode()+b'\0'for row in rows for value in row)
        for name,raw in (('before',metadata(before_links,100)),('after',metadata(after_links,200))):
            (f.run_dir/(name+'.meta')).write_bytes(raw);(receipts/(name+'.meta')).write_bytes(raw)
        # Only procfs_guard is modeled. The actual frozen comparator and its
        # real size/SHA helper operate on these owned synthetic metadata rows.
        body=same+'\n'+compare+'\n'+equality+'\nprocfs_guard() { return 0; }\n'
        body+='if restoration_compare meta;then printf BAD_SUCCESS;else printf EXPECTED_FROZEN_HOLD;fi\n'
        result=f.run(body)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn(b'EXPECTED_FROZEN_HOLD',result.stdout);self.assertNotIn(b'BAD_SUCCESS',result.stdout)
        left=(f.run_dir/'before.meta-equality').read_bytes();right=(f.run_dir/'after.meta-equality').read_bytes()
        self.assertNotEqual(left,right)
        self.assertIn(b'VOLATILE_LIVE_PROCFS_NLINK',left);self.assertIn(b'VOLATILE_LIVE_PROCFS_NLINK',right)
        self.assertTrue((receipts/'comparison.env').is_file())
        self.assertTrue(f.ssh.is_dir());self.assertEqual(f.root.stat().st_nlink,3)

    def test_guest_integration_orders_capture_guards_and_post_trust_restoration(self):
        root_source=(HERE/'guest/root.sh').read_text()
        self.assertEqual(root_source.count('. "$D/root-ssh.sh"'),1)
        self.assertEqual(root_source.count('\nroot_ssh_capture\n'),1)
        self.assertEqual(root_source.count('\nroot_ssh_restore\n'),1)
        capture=root_source.index('\nroot_ssh_capture\n')
        restore=root_source.index('\nroot_ssh_restore\n')
        self.assertLess(capture,root_source.index('\nuser_snapshot "$S/user-before"'))
        self.assertGreater(restore,root_source.index('gpgconf --homedir "$D/trust" --kill all'))
        self.assertGreater(restore,root_source.index('if [[ $dependency_mode == DB53 ]];then official_finish;fi'))
        self.assertLess(restore,root_source.index('\nclear_root_phase\n',restore))
        self.assertLess(restore,root_source.index('sync -f "$D"',restore))
        start=root_source.index('user_snapshot() (\n');end=root_source.index('\nassert_users() {',start)
        snapshot=root_source[start:end].splitlines()
        finds=[i for i,line in enumerate(snapshot)if line.startswith(' find ')]
        self.assertEqual(len(finds),3)
        for index in finds:
            self.assertEqual(snapshot[index-1],' root_ssh_guard')
            self.assertIn('-path "$root_ssh_target" -prune -o ',snapshot[index])
        self.assertNotIn('rm -rf',SOURCE)
        self.assertNotIn('-exec',SOURCE)
        self.assertNotIn('touch -a',SOURCE)

    def test_snapshot_tool_error_is_not_an_empty_or_equal_snapshot(self):
        for command in('getfattr','sha256sum'):
            with self.subTest(command=command):self.refuses(self.fixture(early=True),command+'() { return 23; }',operation='root_ssh_guard')


if __name__=='__main__':unittest.main(verbosity=2)
