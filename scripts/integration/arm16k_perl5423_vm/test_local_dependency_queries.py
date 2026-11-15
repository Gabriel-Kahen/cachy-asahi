# SPDX-License-Identifier: MIT
"""Execute the two actual query guards with fixture tools, never guest entry.

--actual-pacman adds read-only host pacman -T controls on a private synthetic ALPM
DB. It never uses the host DB, installs packages, refreshes repos or uses network.
Source47 case4's 293-byte retained dependency-requires log contained only missing
core/extra/alarm/aur database warnings (SHA256
7d9e2003ec58d5eeecc87a26d86e0c11011e27b0502940c3b25c61d4349572ac).
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
PACMAN=None


def query_blocks():
    lines=(HERE/'guest/root.sh').read_text().splitlines()
    indexes=[i for i,line in enumerate(lines) if line.lstrip().startswith('bounded ') and ' pacman ' in line and ' -T ' in line]
    if len(indexes)!=2:raise ValueError('two actual dependency guards required')
    return ['\n'.join(lines[i:i+2])+'\n' for i in indexes]


def modeled(index,stdout='',stderr='',exit_code=0):
    with tempfile.TemporaryDirectory(prefix='perl-query-FENCED-') as name:
        root=Path(name);bindir=root/'bin';bindir.mkdir();state=root/'state';state.mkdir();data=root/'packet';data.mkdir()
        tool=bindir/'pacman'
        tool.write_text('#!/usr/bin/bash\nprintf "%s\\0" "$@" > "$FENCED_ARGS"\nprintf "%s" "$FENCED_STDOUT"\nprintf "%s" "$FENCED_STDERR" >&2\nexit "$FENCED_EXIT"\n');tool.chmod(0o755)
        script='set -Eeuo pipefail\nsource "$1"\ndependencies=(FENCED_PROVIDER FENCED_SECOND)\n'+query_blocks()[index]+'printf REACHED > "$FENCED_MARKER"\n'
        env=dict(PATH=str(bindir)+':/usr/bin:/bin',HOME=str(root),LC_ALL='C',D=str(data),S=str(state),run_seconds='5',log_bytes='1024',
                 FENCED_ARGS=str(root/'args'),FENCED_STDOUT=stdout,FENCED_STDERR=stderr,FENCED_EXIT=str(exit_code),FENCED_MARKER=str(root/'marker'))
        run=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script,'fenced-query',str(HERE/'guest/case.sh')],env=env,capture_output=True,timeout=10)
        return dict(exit=run.returncode,passed=(root/'marker').exists(),argv=(root/'args').read_bytes().split(b'\0')[:-1],
                    log=next(state.glob('*.log')).read_bytes(),packet=str(data))


class PortableControls(unittest.TestCase):
    def test_both_actual_query_guards_use_their_transaction_config(self):
        for index,name in enumerate(('dependency-pacman.conf','pacman.conf')):
            result=modeled(index)
            self.assertEqual(result['exit'],0);self.assertTrue(result['passed']);self.assertEqual(result['log'],b'')
            self.assertEqual(result['argv'],[b'--config',(result['packet']+'/'+name).encode(),b'-T',b'FENCED_PROVIDER',b'FENCED_SECOND'])

    def test_stderr_warning_remains_durable_and_fatal_even_on_exit_zero(self):
        for index in range(2):
            result=modeled(index,stderr='FENCED warning\n')
            self.assertNotEqual(result['exit'],0);self.assertFalse(result['passed']);self.assertEqual(result['log'],b'FENCED warning\n')

    def test_missing_dependency_stdout_and_nonzero_exit_remain_fatal(self):
        for index in range(2):
            result=modeled(index,stdout='FENCED_MISSING_DEPENDENCY\n',exit_code=127)
            self.assertNotEqual(result['exit'],0);self.assertFalse(result['passed']);self.assertEqual(result['log'],b'FENCED_MISSING_DEPENDENCY\n')

    def test_nonzero_silent_and_nonempty_success_stdout_cannot_advance(self):
        for index in range(2):
            for values in (dict(exit_code=127),dict(stdout='FENCED_UNEXPECTED\n')):
                result=modeled(index,**values)
                self.assertNotEqual(result['exit'],0);self.assertFalse(result['passed'])

    def test_no_sync_or_network_fallback_is_added_to_queries(self):
        for block in query_blocks():
            self.assertNotRegex(block,r'(?:2>|--refresh|--sync|\s-S|\|\s*true|\|\|\s*:)')
            self.assertIn('[[ ! -s $S/',block)


def snapshot(root):
    result={}
    for p in (root,*sorted(root.rglob('*'))):
        s=p.lstat();result[p.relative_to(root).as_posix()]=(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
    return result


class ActualPrivateALPMControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='perl-local-ALPM-DATA-');self.root=Path(self.temp.name);self.db=self.root/'db'
        local=self.db/'local';package=local/'fenced-provider-1-1';package.mkdir(parents=True);(self.db/'sync').mkdir()
        (local/'ALPM_DB_VERSION').write_text('9\n')
        (package/'desc').write_text('%NAME%\nfenced-provider\n\n%VERSION%\n1-1\n\n%DESC%\nFENCED private dependency DATA\n\n%PROVIDES%\nlibgcc=16.1.1\nlibstdc++=16.1.1\nsh\nglibc=2.43\ngdbm=1.26-2\ndb5.3=5.3.28-7\nlibxcrypt=4.5.2-1\nlibcrypt.so=2-64\nbzip2=1.0.8-6\nzlib=1.3.2-3\n\n')
        (package/'files').write_bytes(b'')
        # Match the generated local-only signature policy; private paths replace
        # the guest's trust/cache/log locations. -T does not invoke signature work.
        header='[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nDBPath = '+str(self.db)+'\nLogFile = '+str(self.root/'unused.log')+'\nGPGDir = '+str(self.root/'unused-trust')+'\nCacheDir = '+str(self.root/'unused-cache')+'\n'
        self.clean=self.root/'local-only.conf';self.clean.write_text(header)
        self.repos=self.root/'with-repos.conf';self.repos.write_text(header+''.join('['+n+']\nServer = file:///FENCED-UNUSED-NEVER-FETCHED\n'for n in ('core','extra','alarm','aur')))
        for p in self.db.rglob('*'):p.chmod(0o500 if p.is_dir() else 0o400)
        self.db.chmod(0o500)
        for name in ('unused-trust','unused-cache'):(self.root/name).mkdir(mode=0o500)
        self.before=snapshot(self.root)

    def tearDown(self):
        self.assertEqual(snapshot(self.root),self.before)
        self.assertFalse((self.root/'unused.log').exists())
        for name in ('unused-trust','unused-cache'):self.assertEqual(list((self.root/name).iterdir()),[])
        self.db.chmod(0o700)
        for p in self.db.rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
        self.temp.cleanup()

    def query(self,config,*dependencies):
        return subprocess.run([PACMAN,'--config',str(config),'-T',*dependencies],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              env=dict(PATH='/usr/bin:/bin',HOME=str(self.root),LC_ALL='C',LANG='C'),timeout=10)

    def test_satisfied_local_provides_reproduce_missing_sync_warning_difference(self):
        baseline=self.query(self.repos,'libgcc','libstdc++','sh');fixed=self.query(self.clean,'libgcc','libstdc++','sh')
        self.assertEqual((baseline.returncode,baseline.stdout),(0,b''))
        self.assertEqual(baseline.stderr,b''.join(("warning: database file for '"+n+"' does not exist (use '-Sy' to download)\n").encode()for n in ('core','extra','alarm','aur')))
        self.assertEqual(len(baseline.stderr),293)
        self.assertEqual(hashlib.sha256(baseline.stderr).hexdigest(),'7d9e2003ec58d5eeecc87a26d86e0c11011e27b0502940c3b25c61d4349572ac')
        self.assertEqual((fixed.returncode,fixed.stdout,fixed.stderr),(0,b'',b''))

    def test_perl_versioned_dependencies_and_wrong_version_provides(self):
        result=self.query(self.clean,'glibc','gdbm>=1.17','db5.3','libxcrypt','libcrypt.so=2-64','bzip2','zlib')
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))
        for dependency in ('gdbm>=2.0','libcrypt.so=3-64'):
            result=self.query(self.clean,dependency)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(127,(dependency+'\n').encode(),b''))

    def test_genuinely_missing_dependency_still_refuses_without_any_refresh(self):
        result=self.query(self.clean,'genuinely-missing-fenced-dependency')
        self.assertEqual(result.returncode,127);self.assertEqual(result.stdout,b'genuinely-missing-fenced-dependency\n');self.assertEqual(result.stderr,b'')


def load_tests(loader,unused,pattern):
    suite=loader.loadTestsFromTestCase(PortableControls)
    if PACMAN:suite.addTests(loader.loadTestsFromTestCase(ActualPrivateALPMControls))
    return suite


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--actual-pacman',type=Path)
    args,remaining=parser.parse_known_args();PACMAN=str(args.actual_pacman)if args.actual_pacman else None
    if PACMAN and (not args.actual_pacman.is_absolute() or not args.actual_pacman.is_file()):parser.error('explicit absolute host pacman required')
    suite=load_tests(unittest.defaultTestLoader,None,None)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful()else 1)
