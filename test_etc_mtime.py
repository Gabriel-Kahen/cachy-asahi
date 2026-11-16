#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Real owned HOST filesystem controls for the finite preboot absence recovery.

Only extracted Bash helpers execute. No guest entry point, ALPM, trust tool,
image, credential or VM is opened. /etc and root ownership assertions are
projected into scratch with an exact source-text inverse.
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
SOURCE=(HERE/'guest/root.sh').read_text()
START='# The normal ldconfig hook can create/remove ld.so.cache and change /etc mtime.\n'
END='cache_snapshot() (\n'
HELPERS=SOURCE[SOURCE.index(START):SOURCE.index(END)]
PREVIOUS_HELPERS='# The normal ldconfig hook can create/remove ld.so.cache and change /etc mtime.\n# Pin the original directory with an open FD; restore certified preboot mtime only, never atime,\n# contents or other metadata. The ordinary reference is private disposable DATA.\ncache_etc_timestamp_capture() {\n local reference=$D/cache/etc-mtime.reference descriptor=$D/preboot-etc.tsv context=$D/preboot-context.json\n local marker observed_nonce context_sha inode links seconds nanos extra line token selected_hash= count=0\n local -a boot_arguments\n [[ -f $context && ! -L $context && $(stat -c \'%u:%g:%h:%a\' -- "$context") == 0:0:1:644 && $(stat -c \'%s\' -- "$context") -le 4096 ]]\n [[ -f $descriptor && ! -L $descriptor && $(stat -c \'%u:%g:%h:%a\' -- "$descriptor") == 0:0:1:600 && $(stat -c \'%s\' -- "$descriptor") -le 256 ]]\n etc_descriptor_identity=$(stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$descriptor")\n read -r -a boot_arguments < /proc/cmdline\n for token in "${boot_arguments[@]}";do\n  if [[ $token == arm16k_perl5423_vm_preboot_etc_sha256=* ]];then selected_hash=${token#*=};count=$((count+1));fi\n done\n [[ $count == 1 && $selected_hash =~ ^[0-9a-f]{64}$ && $(file_sha "$descriptor") == "$selected_hash" ]]\n IFS=\' \' read -r marker observed_nonce context_sha inode links seconds nanos extra < "$descriptor"\n [[ $marker == PERL5423_PREBOOT_ETC_V1 && $observed_nonce == "$nonce" && $context_sha =~ ^[0-9a-f]{64}$ && -z $extra ]]\n [[ $inode =~ ^[1-9][0-9]{0,9}$ && $links =~ ^[1-9][0-9]{0,4}$ && $seconds =~ ^(0|[1-9][0-9]{0,9})$ && $nanos =~ ^(0|[1-9][0-9]{0,8})$ ]]\n (( inode <= 4294967295 && links >= 2 && links <= 65535 && seconds <= 8589934591 && nanos <= 999999999 ))\n printf -v line \'PERL5423_PREBOOT_ETC_V1 %s %s %s %s %s %s\' "$nonce" "$context_sha" "$inode" "$links" "$seconds" "$nanos"\n [[ $(stat -c \'%s\' -- "$descriptor") == $((${#line}+1)) && $(head -c 257 -- "$descriptor") == "$line" && $(file_sha "$context") == "$context_sha" ]]\n [[ $(stat -c \'%i:%h\' -- /etc) == "$inode:$links" ]]\n [[ $(stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$descriptor") == "$etc_descriptor_identity" ]]\n [[ -d /etc && ! -L /etc && $(readlink -f -- /etc) == /etc && $(stat -c \'%u:%g:%a\' -- /etc) == 0:0:755 ]]\n [[ -d $D/cache && ! -L $D/cache && $(readlink -f -- "$D/cache") == "$D/cache" && $(stat -c \'%u:%g:%a\' -- "$D/cache") == 0:0:700 ]]\n [[ ! -e $reference && ! -L $reference ]]\n exec {etc_directory_fd}< /etc\n [[ $(stat -Lc \'%i:%h\' -- "/proc/self/fd/$etc_directory_fd") == "$inode:$links" && $(stat -Lc \'%u:%g:%a:%F\' -- "/proc/self/fd/$etc_directory_fd") == 0:0:755:directory ]]\n etc_directory_identity=$(stat -Lc \'%d:%i:%f:%u:%g:%h\' -- "/proc/self/fd/$etc_directory_fd")\n [[ $(stat -c \'%d:%i:%f:%u:%g:%h\' -- /etc) == "$etc_directory_identity" ]]\n ( set -o noclobber;: > "$reference" )\n [[ -f $reference && ! -L $reference && $(stat -c \'%u:%g:%h:%a:%s\' -- "$reference") == 0:0:1:600:0 ]]\n touch -m --date="@$seconds.$(printf \'%09d\' "$nanos")" -- "$reference"\n [[ $(date -u -r "$reference" +%s.%N) == "$seconds.$(printf \'%09d\' "$nanos")" ]]\n etc_directory_mtime=$(stat -c \'%y\' -- "$reference")\n etc_reference_identity=$(stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$reference")\n [[ $(stat -c \'%y\' -- "$reference") == "$etc_directory_mtime" && $(stat -c \'%d:%i:%f:%u:%g:%h\' -- /etc) == "$etc_directory_identity" ]]\n}\ncache_etc_timestamp_restore() {\n local reference=$D/cache/etc-mtime.reference descriptor=$D/preboot-etc.tsv\n [[ -f $descriptor && ! -L $descriptor && $(stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$descriptor") == "$etc_descriptor_identity" ]]\n [[ -d $D/cache && ! -L $D/cache && $(readlink -f -- "$D/cache") == "$D/cache" && $(stat -c \'%u:%g:%a\' -- "$D/cache") == 0:0:700 ]]\n [[ -f $reference && ! -L $reference && $(stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$reference") == "$etc_reference_identity" ]]\n [[ -d /etc && ! -L /etc && $(readlink -f -- /etc) == /etc && $(stat -c \'%d:%i:%f:%u:%g:%h\' -- /etc) == "$etc_directory_identity" ]]\n [[ $(stat -Lc \'%d:%i:%f:%u:%g:%h\' -- "/proc/self/fd/$etc_directory_fd") == "$etc_directory_identity" ]]\n touch -m --reference="$reference" -- "/proc/self/fd/$etc_directory_fd"\n [[ $(stat -c \'%d:%i:%f:%u:%g:%h\' -- /etc) == "$etc_directory_identity" && $(stat -c \'%y\' -- /etc) == "$etc_directory_mtime" ]]\n [[ $(stat -c \'%d:%i:%f:%u:%g:%h:%s:%y:%z\' -- "$reference") == "$etc_reference_identity" ]]\n rm -- "$reference"\n [[ ! -e $reference && ! -L $reference ]]\n exec {etc_directory_fd}<&-\n}\n'
SOURCE58_ROOT_SHA256='14eecc96b2f0eeced70d342508f4e388e35960eade5db0f797e39e11efdc0a6f'
NONCE='a'*32
PARENTS=('etc','etc/audit','etc/udev')
POLICY=(('etc/.pwd.lock','f','600',0),('etc/.updated','f','644',4096),
        ('etc/audisp','d','755',0),('etc/audit/plugins.d','d','750',0),
        ('etc/audit/rules.d','d','755',0),('etc/ld.so.cache','f','644',1048576),
        ('etc/os-release','l','777',4096),('etc/udev/hwdb.bin','f','444',16777216),
        ('etc/vconsole.conf','f','644',4096))
ATIMES=(1785933514000000000,1785933495000000000,1785933457000000000)
MTIMES=(1794708503123456789,1785933495987654321,1785933457123000000)


def limits():
    for name,cap in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,8),
                     (resource.RLIMIT_AS,192*1024**2),(resource.RLIMIT_FSIZE,1048576),
                     (resource.RLIMIT_NOFILE,96)):
        resource.setrlimit(name,(cap,cap))


def fence(event,args):
    if event=='subprocess.Popen':
        if args[0]!='/usr/bin/bash' or args[1][:3]!=['/usr/bin/bash','--noprofile','--norc']:
            raise AssertionError('only finite HOST Bash fixture may execute')
    elif event.startswith(('socket.','ctypes.','os.exec','os.fork','os.posix_spawn','fcntl.'))or event=='os.system':
        raise AssertionError('HOST filesystem fixture fence: '+event)
sys.addaudithook(fence)


class Fixture:
    def __init__(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='perl-preboot-absence-HOST-')
        self.top=Path(self.tmp.name)
        self.etc=self.top/'etc'
        self.data=self.top/'case'
        self.cache=self.data/'cache'
        self.run_dir=self.top/'run'
        self.cache.mkdir(mode=0o700,parents=True)
        self.run_dir.mkdir(mode=0o700)
        for name in PARENTS:(self.top/name).mkdir(mode=0o755,parents=True,exist_ok=True)
        self.sentinels={}
        for name in ('etc/base.conf','etc/audit/base.conf','etc/udev/base.rules'):
            path=self.top/name;path.write_bytes(('HOST baseline '+name+'\n').encode());path.chmod(0o644)
            self.sentinels[name]=path.read_bytes()
        self.context=self.data/'preboot-context.json'
        self.context.write_bytes(b'{"MODEL":"source/case/nonce/raw/prepared/certificate/namespace joins tested separately"}\n')
        self.context.chmod(0o644)
        self.descriptor=self.data/'preboot-etc.tsv'
        self.cmdline=self.top/'cmdline'
        self.original={}
        self.stamp()

    def close(self):self.tmp.cleanup()

    def stamp(self,mtimes=MTIMES):
        for name,atime,mtime in zip(PARENTS,ATIMES,mtimes):
            path=self.top/name;os.utime(path,ns=(atime,mtime));self.original[name]=path.stat()
        lines=[f'PERL5423_PREBOOT_ETC_V2 {NONCE} {hashlib.sha256(self.context.read_bytes()).hexdigest()}']
        for name in PARENTS:
            row=self.original[name]
            lines.append(f'P {name} {row.st_ino} {row.st_nlink} {row.st_mtime_ns//10**9} {row.st_mtime_ns%10**9}')
        lines.extend(f'A {name} {kind} {mode} {cap}'for name,kind,mode,cap in POLICY)
        self.descriptor.write_text('\n'.join(lines)+'\n');self.descriptor.chmod(0o600)
        self.bind_descriptor()

    def bind_descriptor(self):
        self.cmdline.write_text('arm16k_perl5423_vm_preboot_etc_sha256='+hashlib.sha256(self.descriptor.read_bytes()).hexdigest()+'\n')

    def boot(self,omit=(),hwdb_bytes=65792):
        for index,(name,kind,mode,_)in enumerate(POLICY):
            if name in omit:continue
            path=self.top/name
            if kind=='d':path.mkdir(mode=int(mode,8));path.chmod(int(mode,8))
            elif kind=='l':path.symlink_to('../usr/lib/HOST-MODEL-release')
            else:
                body=b''if name.endswith('.pwd.lock')else (bytes(range(256))*((hwdb_bytes+255)//256))[:hwdb_bytes]if name.endswith('hwdb.bin')else ('HOST boot '+name+'\n').encode()+b'\0BINARY'
                path.write_bytes(body);path.chmod(int(mode,8))
                os.utime(path,ns=(1794827028000000000+index,1794827029000000000+index))
        return self

    def run(self,body,*,before=''):
        uid,gid=os.getuid(),os.getgid()
        text=HELPERS
        replacements=[('/proc/cmdline','"$MODEL_CMDLINE"'),('/etc','"$MODEL_ETC"'),('0:0',f'{uid}:{gid}')]
        for old,new in replacements:
            if old not in text or new in text:raise AssertionError('fixed HOST projection seam missing/colliding: '+old)
            text=re.sub(r'(?<![0-9])0:0(?![0-9])',lambda _:new,text)if old=='0:0'else text.replace(old,new)
        inverse=text
        for old,new in reversed(replacements):inverse=inverse.replace(new,old)
        if inverse!=HELPERS:raise AssertionError('whole source projection inverse')
        script='set -Eeuo pipefail\numask 077\nD=$1\nO=$2\nS=$O/root\nmkdir -m700 "$S"\nnonce='+NONCE+'\n'
        script+='file_sha() { local value;value=$(sha256sum -- "$1");printf %s "${value%% *}"; }\n'
        script+='pacman() { [[ $# == 1 && $1 == -Qlq ]] || exit 97;return 0; }\n'
        script+=text+'\n'+before+'\n'+body
        result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script,'HOST-preboot-controls',str(self.data),str(self.run_dir)],
                              cwd=self.top,env=dict(PATH='/usr/bin:/bin',HOME=str(self.top),LC_ALL='C',TZ='UTC',MODEL_ETC=str(self.etc),MODEL_CMDLINE=str(self.cmdline)),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,preexec_fn=limits)
        if max(len(result.stdout),len(result.stderr))>1048576:raise AssertionError('bounded helper output')
        return result

    def assert_baseline(self,test):
        for name,row in self.original.items():
            actual=(self.top/name).stat()
            test.assertEqual((actual.st_ino,actual.st_mode,actual.st_uid,actual.st_gid,actual.st_nlink,actual.st_mtime_ns),
                             (row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,row.st_mtime_ns),name)
        for name,_,_,_ in POLICY:
            path=self.top/name;test.assertFalse(path.exists()or path.is_symlink(),name)
        for name,body in self.sentinels.items():test.assertEqual((self.top/name).read_bytes(),body)
        test.assertEqual(list(self.cache.iterdir()),[])


class Controls(unittest.TestCase):
    def fixture(self,*,boot=True):
        value=Fixture();self.addCleanup(value.close)
        if boot:value.boot()
        return value

    def assert_refuses(self,f,mutation,*,capture_first=True):
        body=('cache_etc_timestamp_capture\nprintf CAPTURED\\n\n'if capture_first else'')+mutation+'\n'
        body+='cache_etc_timestamp_restore\nprintf BAD_SUCCESS\n'if capture_first else'cache_etc_timestamp_capture\nprintf BAD_SUCCESS\n'
        result=f.run(body)
        self.assertNotEqual(result.returncode,0,result.stderr.decode())
        self.assertNotIn(b'BAD_SUCCESS',result.stdout)
        if capture_first:self.assertIn(b'CAPTURED',result.stdout,result.stderr.decode())
        return result

    def test_full_nine_path_boot_transaction_and_exact_preboot_parent_recovery(self):
        f=self.fixture(boot=False);f.boot(hwdb_bytes=13735371)
        self.assertEqual(f.etc.stat().st_nlink,f.original['etc'].st_nlink+1)
        self.assertEqual((f.etc/'audit').stat().st_nlink,f.original['etc/audit'].st_nlink+2)
        result=f.run("""cache_etc_timestamp_capture
cp -a -- "$MODEL_ETC/ld.so.cache" "$D/cache.saved"
printf 'HOST normal hook replacement' > "$MODEL_ETC/new-cache"
mv -- "$MODEL_ETC/new-cache" "$MODEL_ETC/ld.so.cache"
cp -a -- "$D/cache.saved" "$MODEL_ETC/ld.so.cache"
cache_etc_timestamp_restore
""")
        self.assertEqual(result.returncode,0,result.stderr.decode())
        f.assert_baseline(self)

    def test_absent_at_initial_observation_remains_absent(self):
        f=self.fixture(boot=False)
        result=f.run('cache_etc_timestamp_capture\ncache_etc_timestamp_restore\n')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        f.assert_baseline(self)

    def test_path_appearing_after_initial_observation_refuses_before_other_deletions(self):
        f=Fixture();self.addCleanup(f.close);f.boot(omit=('etc/vconsole.conf',))
        self.assert_refuses(f,'printf NEW > "$MODEL_ETC/vconsole.conf";chmod 644 "$MODEL_ETC/vconsole.conf"')
        self.assertTrue((f.etc/'.updated').exists())
        self.assertTrue((f.etc/'audisp').exists())

    def test_changed_regular_file_bytes_refuse_before_any_deletion(self):
        for name,kind,mode,_ in POLICY:
            if kind!='f':continue
            with self.subTest(name=name):
                f=self.fixture();path='"$MODEL_ETC/'+name[4:]+'"'
                self.assert_refuses(f,'chmod u+w '+path+';printf CHANGED >> '+path+';chmod '+mode+' '+path)
                self.assertTrue((f.etc/'audisp').exists())

    def test_regular_file_mode_mtime_or_hardlink_change_refuses(self):
        for mutation in ('chmod 600 "$MODEL_ETC/.updated"','touch -m -d @1 "$MODEL_ETC/.updated"',
                         'ln "$MODEL_ETC/.updated" "$D/extra-hardlink"'):
            with self.subTest(mutation=mutation):self.assert_refuses(self.fixture(),mutation)

    def test_identical_noncache_file_replacement_refuses(self):
        self.assert_refuses(self.fixture(),'cp -a "$MODEL_ETC/.updated" "$D/substitute";mv "$D/substitute" "$MODEL_ETC/.updated"')

    def test_file_or_directory_aliases_refuse_at_capture(self):
        for name in ('.updated','audisp','udev/hwdb.bin'):
            with self.subTest(name=name):
                f=self.fixture();target=f.etc/name;target.rename(f.top/'original-target');target.symlink_to(f.top/'original-target')
                self.assert_refuses(f,'',capture_first=False)

    def test_symlink_target_and_identical_symlink_inode_replacement_refuse(self):
        for target in ('CHANGED-HOST-target','../usr/lib/HOST-MODEL-release'):
            with self.subTest(target=target):
                self.assert_refuses(self.fixture(),'rm "$MODEL_ETC/os-release";ln -s '+target+' "$MODEL_ETC/os-release"')

    def test_nonempty_directories_refuse_at_capture_and_restore_without_recursion(self):
        for stage in ('capture','restore'):
            with self.subTest(stage=stage):
                f=self.fixture()
                if stage=='capture':(f.etc/'audisp/child').write_bytes(b'HOST UNOWNED CONTENT')
                self.assert_refuses(f,'printf "HOST UNOWNED CONTENT" > "$MODEL_ETC/audisp/child"'if stage=='restore'else'',capture_first=stage=='restore')
                self.assertEqual((f.etc/'audisp/child').read_bytes(),b'HOST UNOWNED CONTENT')
                self.assertTrue((f.etc/'.updated').exists())

    def test_identical_empty_directory_replacement_refuses(self):
        self.assert_refuses(self.fixture(),'mv "$MODEL_ETC/audisp" "$D/original-directory";mkdir -m755 "$MODEL_ETC/audisp";touch -m -r "$D/original-directory" "$MODEL_ETC/audisp"')

    def test_initial_nonempty_lock_wrong_mode_hardlink_and_size_cap_refusals(self):
        cases=('printf X > "$MODEL_ETC/.pwd.lock"',
               'chmod 600 "$MODEL_ETC/.updated"',
               'ln "$MODEL_ETC/.updated" "$D/initial-hardlink"',
               'head -c 4097 /dev/zero > "$MODEL_ETC/.updated"')
        for mutation in cases:
            with self.subTest(mutation=mutation):self.assert_refuses(self.fixture(),mutation,capture_first=False)
        f=self.fixture(boot=False);f.boot(hwdb_bytes=16777217)
        self.assert_refuses(f,'',capture_first=False)

    def test_literal_selected_file_or_directory_ownership_refuses(self):
        for name in ('.updated','audisp/'):
            with self.subTest(name=name):
                self.assert_refuses(self.fixture(),'pacman() { [[ $# == 1 && $1 == -Qlq ]] || exit 97;printf "%s\\n" "$MODEL_ETC/'+name+'"; }',capture_first=False)

    def test_literal_ownership_query_error_refuses(self):
        self.assert_refuses(self.fixture(),'pacman() { return 23; }',capture_first=False)

    def test_parent_inode_alias_mode_or_unaccounted_child_directory_refuses(self):
        for mutation in ('mv "$MODEL_ETC/audit" "$D/old-audit";mkdir -m755 "$MODEL_ETC/audit"',
                         'mv "$MODEL_ETC/udev" "$D/old-udev";ln -s "$D/old-udev" "$MODEL_ETC/udev"',
                         'chmod 700 "$MODEL_ETC"','mkdir "$MODEL_ETC/unreviewed-directory"'):
            with self.subTest(mutation=mutation):self.assert_refuses(self.fixture(),mutation)

    def test_descriptor_context_nonce_token_and_identity_tampering_refuse(self):
        cases=('rm "$D/preboot-etc.tsv"','printf X >> "$D/preboot-etc.tsv"','chmod 644 "$D/preboot-etc.tsv"',
               'ln "$D/preboot-etc.tsv" "$D/descriptor-alias"','printf X >> "$D/preboot-context.json"',
               'nonce=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',': > "$MODEL_CMDLINE"',
               'line=$(cat "$MODEL_CMDLINE");printf "%s %s\\n" "$line" "$line" > "$MODEL_CMDLINE"')
        for mutation in cases:
            with self.subTest(mutation=mutation):self.assert_refuses(self.fixture(),mutation,capture_first=False)

    def test_selected_malformed_or_reordered_descriptor_refuses(self):
        for mutation in ('sed -i "s/P etc /P etc-other /" "$D/preboot-etc.tsv"',
                         'sed -i "s/A etc\\/.pwd.lock f 600 0/A etc\\/.pwd.lock f 600 1/" "$D/preboot-etc.tsv"',
                         'printf EXTRA >> "$D/preboot-etc.tsv"',
                         'printf \"\\n\" >> "$D/preboot-etc.tsv"'):
            with self.subTest(mutation=mutation):
                f=self.fixture();before=mutation+'\nprintf "arm16k_perl5423_vm_preboot_etc_sha256=%s\\n" "$(file_sha "$D/preboot-etc.tsv")" > "$MODEL_CMDLINE"\n'
                result=f.run('cache_etc_timestamp_capture\nprintf BAD_SUCCESS\n',before=before)
                self.assertNotEqual(result.returncode,0,result.stderr.decode());self.assertNotIn(b'BAD_SUCCESS',result.stdout)

        for before,after in ((b'PERL5423_PREBOOT_ETC_V2',b'PERL5423_PREBOOT_ETC_V2\0'),
                             (b'P etc ',b'P et\0c '),
                             (b'A etc/.pwd.lock ',b'A etc/.pwd.\0lock ')):
            with self.subTest(NUL=before):
                f=self.fixture();raw=f.descriptor.read_bytes();self.assertIn(before,raw)
                f.descriptor.write_bytes(raw.replace(before,after,1));f.bind_descriptor()
                self.assert_refuses(f,'',capture_first=False)
                self.assertTrue((f.etc/'.updated').exists())

    def test_reference_mutation_or_touch_error_never_reports_success(self):
        for mutation in ('printf X > "$D/cache/preboot-parent-0.reference"',
                         'rm "$D/cache/preboot-parent-1.reference";ln -s "$MODEL_ETC/base.conf" "$D/cache/preboot-parent-1.reference"',
                         'chmod 644 "$D/cache/preboot-parent-2.reference"',
                         'printf X >> "$D/preboot-context.json"',
                         'cp -a "$D/preboot-context.json" "$D/context-copy";mv "$D/context-copy" "$D/preboot-context.json"',
                         'touch() { return 23; }'):
            with self.subTest(mutation=mutation):
                f=self.fixture();self.assert_refuses(f,mutation)
                if not mutation.startswith('touch()'):self.assertTrue((f.etc/'.updated').exists())

    def test_occupied_reference_nodes_refuse_without_clobber(self):
        for kind in ('ordinary','symlink','dangling','hardlink','fifo'):
            with self.subTest(kind=kind):
                f=self.fixture();outside=f.top/'HOST-unowned';outside.write_bytes(b'HOST sentinel')
                reference=f.cache/'preboot-parent-0.reference'
                if kind=='ordinary':reference.write_bytes(b'HOST occupied reference')
                elif kind=='symlink':reference.symlink_to(outside)
                elif kind=='dangling':reference.symlink_to(f.top/'absent')
                elif kind=='hardlink':os.link(outside,reference)
                else:os.mkfifo(reference)
                before=reference.lstat()
                self.assert_refuses(f,'',capture_first=False)
                self.assertEqual((reference.lstat().st_ino,reference.lstat().st_mode),(before.st_ino,before.st_mode))
                self.assertEqual(outside.read_bytes(),b'HOST sentinel')
                self.assertTrue((f.etc/'.updated').exists())

    def test_snapshot_command_error_refuses_before_deletion(self):
        for command in ('getfattr','sha256sum'):
            with self.subTest(command=command):
                f=self.fixture();self.assert_refuses(f,command+'() { return 23; }')
                self.assertTrue((f.etc/'.updated').exists())

    def test_timestamp_restoration_preserves_current_atime_without_wholeboot_requirement(self):
        f=self.fixture()
        current=(1794829001123456789,1794829002987654321,1794829003555000000)
        body='cache_etc_timestamp_capture\n'
        for name,ns in zip(PARENTS,current):
            suffix=name[3:];body+=f'touch -a -d @{ns//10**9}.{ns%10**9:09d} -- "$MODEL_ETC{suffix}"\n'
        body+='cache_etc_timestamp_restore\n'
        result=f.run(body);self.assertEqual(result.returncode,0,result.stderr.decode())
        for name,ns in zip(PARENTS,current):self.assertEqual((f.top/name).stat().st_atime_ns,ns,name)
        f.assert_baseline(self)

    def test_zero_nanoseconds_and_initial_xattrs_remain_exact_until_removal(self):
        f=self.fixture(boot=False)
        try:
            os.setxattr(f.etc/'base.conf','user.HOST_namespace_control',b'protected baseline')
            os.setxattr(f.etc/'audit','user.HOST_namespace_control',b'protected parent')
            f.stamp(tuple(x//10**9*10**9 for x in MTIMES));f.boot()
            os.setxattr(f.etc/'.updated','user.HOST_namespace_control',b'initial generated state')
        except OSError as error:
            if error.errno in(errno.ENOTSUP,errno.EOPNOTSUPP):self.skipTest('HOST filesystem has no user xattrs')
            raise
        result=f.run('cache_etc_timestamp_capture\ncache_etc_timestamp_restore\n')
        self.assertEqual(result.returncode,0,result.stderr.decode());f.assert_baseline(self)
        self.assertEqual(os.getxattr(f.etc/'base.conf','user.HOST_namespace_control'),b'protected baseline')
        self.assertEqual(os.getxattr(f.etc/'audit','user.HOST_namespace_control'),b'protected parent')

    def test_xattr_change_after_capture_refuses(self):
        f=self.fixture()
        self.assertTrue(Path('/usr/bin/setfattr').is_file())
        try:os.setxattr(f.etc/'.updated','user.HOST_namespace_control',b'initial')
        except OSError as error:
            if error.errno in(errno.ENOTSUP,errno.EOPNOTSUPP):self.skipTest('HOST filesystem has no user xattrs')
            raise
        self.assert_refuses(f,'setfattr -n user.HOST_namespace_control -v CHANGED "$MODEL_ETC/.updated"')

    def test_full_source58_root_inverse_and_existing_transaction_order(self):
        self.assertEqual(SOURCE.count(HELPERS),1)
        restored=SOURCE.replace(HELPERS,PREVIOUS_HELPERS,1)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),SOURCE58_ROOT_SHA256)
        capture=SOURCE.index('\ncache_etc_timestamp_capture\n');restore=SOURCE.index('\ncache_etc_timestamp_restore\n')
        self.assertLess(capture,SOURCE.index('checkpoint_phase dependency_install'))
        self.assertLess(SOURCE.index('same_bytes "$S/before.cache" "$S/after.cache"'),restore)
        self.assertLess(restore,SOURCE.index('payload_snapshot after'))
        self.assertNotIn('rm -rf',HELPERS)
        self.assertNotIn('touch -a',HELPERS)
        self.assertNotIn("allowed_dirs.add('etc')",(HERE/'image.py').read_text())


if __name__=='__main__':unittest.main(verbosity=2)
