#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real GPG/pacman-key in owned disposable roots; never the host keyring/config."""
import importlib.util
import glob
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('enrollment', HERE / 'enroll.py')
enrollment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrollment)
URL = 'https://repo.example.invalid/generations/' + 'a' * 64 + '/release/repo'
ENV = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}


def command(argv, **kwargs):
    return subprocess.run(list(map(str,argv)), env=ENV, capture_output=True, timeout=60, **kwargs)


def gpg(home, *args):
    result = command(['/usr/bin/gpg','--no-options','--homedir',home,'--batch','--pinentry-mode','loopback','--passphrase','',*args])
    if result.returncode:raise RuntimeError(result.stderr.decode())
    return result.stdout


def fingerprint(home):
    return next(line.split(':')[9] for line in gpg(home,'--with-colons','--fingerprint','--list-keys').decode().splitlines() if line.startswith('fpr:'))


def effective_configuration(target):
    """Query an exact owned config mirror with pacman6-compatible options.

    --rootdir does not relocate absolute Includes. Remap every validated Include
    into a private mirror instead; never let the parser resolve a host Include.
    No package/keyring command or privilege escalation is part of this query.
    """
    selected = enrollment.state(target, 'enroll')
    with tempfile.TemporaryDirectory(prefix='caa-query-') as directory:
        mirror = Path(directory)
        mapping = {path: mirror / path.relative_to(selected['root']) for path, value in selected['observed'].items() if value is not None}
        for path, copied in mapping.items():
            lines = []
            for raw in selected['observed'][path][0].decode('utf-8').splitlines(keepends=True):
                key, separator, value = raw.split('#', 1)[0].strip().partition('=')
                if key.strip() == 'Include':
                    enrollment.need(separator, 'fixture Include assignment missing')
                    matches = sorted(Path(item) for item in glob.glob(str(selected['root'] / value.strip().lstrip('/'))))
                    enrollment.need(matches and all(child in mapping for child in matches), 'fixture Include graph changed')
                    lines.extend('Include = ' + str(mapping[child]) + '\n' for child in matches)
                else:
                    lines.append(raw)
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_text(''.join(lines), encoding='utf-8')
        enrollment.stable(selected)
        result = command(['/usr/bin/pacman-conf', '--config', mapping[selected['main']],
                          '--repo', 'cachy-asahi', 'SigLevel', 'Server'])
        enrollment.stable(selected)
        enrollment.need(enrollment.state(target, 'enroll')['observed'] == selected['observed'], 'fixture Include graph changed during query')
        return result


class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('gpg','gpgconf','pacman-key','pacman-conf','unshare'):
            if not shutil.which(tool):raise unittest.SkipTest('fixture dependency absent: '+tool)
        if command(['unshare','--user','--map-root-user','--','true']).returncode:
            raise unittest.SkipTest('user namespaces unavailable; no host-root fallback')
        cls.space=tempfile.TemporaryDirectory(prefix='caa-enrollment-tests-')
        cls.root=Path(cls.space.name)
        cls.project=cls.root/'project';cls.project.mkdir(mode=0o700)
        cls.seed=cls.root/'base-ring';cls.seed.mkdir(mode=0o700)
        (cls.seed/'pubring.gpg').touch(mode=0o600);(cls.seed/'secring.gpg').touch(mode=0o600)
        for home,label in ((cls.project,'PROJECT'),(cls.seed,'BASE')):
            gpg(home,'--quick-generate-key','DISPOSABLE '+label+' TEST <'+label.lower()+'@example.invalid>','ed25519','sign','1d')
        cls.fpr=fingerprint(cls.project);cls.base_fpr=fingerprint(cls.seed)
        cls.public=gpg(cls.project,'--export',cls.fpr)
        cls.base_export=gpg(cls.seed,'--export',cls.base_fpr)

    @classmethod
    def tearDownClass(cls):
        for home in (cls.project,cls.seed):
            command(['gpgconf','--homedir',home,'--kill','all'])
        cls.space.cleanup()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='case-',dir=self.root)
        self.addCleanup(self.temporary.cleanup)
        self.case=Path(self.temporary.name);self.target=self.case/'root'
        (self.target/'etc/pacman.d').mkdir(parents=True)
        (self.target/'var/lib/pacman').mkdir(parents=True)
        self.ring=self.target/'etc/pacman.d/gnupg'
        shutil.copytree(self.seed,self.ring,ignore=shutil.ignore_patterns('S.*'))
        self.addCleanup(lambda:command(['unshare','--user','--map-root-user','--','gpgconf','--homedir',self.ring,'--kill','all']))
        self.main=self.target/'etc/pacman.conf'
        self.original=b'[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\n[core]\nServer = https://base.example.invalid/$repo/os/$arch'
        self.main.write_bytes(self.original)
        self.key=self.target/'etc/pacman.d/operator-public.gpg';self.key.write_bytes(self.public);self.key.chmod(0o600)

    def cli(self, action='enroll', apply=False, fingerprint=None, url=URL):
        argv=['unshare','--user','--map-root-user','--',sys.executable,'-I','-B',HERE/'enroll.py','--root',self.target]
        if apply:argv+=['--apply']
        argv += [action]
        if action=='enroll':argv+=['--snapshot-url',url,'--public-key',self.key,'--fingerprint',fingerprint or self.fpr]
        result=command(argv)
        self.assertTrue(result.stdout,result.stderr.decode())
        return result,json.loads(result.stdout)

    def enable(self):
        result,body=self.cli(apply=True)
        self.assertEqual(result.returncode,0,body)
        self.assertEqual(body['status'],'enabled')
        return body

    def injected(self, code):
        program='''import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('enroll',sys.argv[1]); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root,key,fpr,url=Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],sys.argv[5]
''' + code + '''
try:
 print(json.dumps(m.execute(root,'enroll',url,key,fpr,True)))
except BaseException as error:
 print(json.dumps(getattr(error,'enrollment_result',{'error':str(error)})));sys.exit(1)
'''
        result=command(['unshare','--user','--map-root-user','--',sys.executable,'-I','-B','-c',program,HERE/'enroll.py',self.target,self.key,self.fpr,URL])
        self.assertTrue(result.stdout,result.stderr.decode())
        return result,json.loads(result.stdout)

    def test_preview_leaves_configuration_and_base_trust_unchanged(self):
        before=gpg(self.ring,'--export',self.base_fpr)
        report=enrollment.execute(self.target,'enroll',URL,self.key,self.fpr)
        self.assertEqual(report['status'],'preview');self.assertFalse(report['keyring_may_have_changed'])
        self.assertEqual(self.main.read_bytes(),self.original)
        self.assertFalse((self.target/enrollment.INCLUDE.lstrip('/')).exists())
        self.assertEqual(gpg(self.ring,'--export',self.base_fpr),before)

    def test_real_enroll_strict_effective_siglevel_idempotent_disable(self):
        body=self.enable();self.assertTrue(body['keyring_may_have_changed'])
        before=self.main.read_bytes()
        result,body=self.cli(apply=True)
        self.assertEqual(result.returncode,0,body);self.assertFalse(body['config_changed']);self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(self.main.read_bytes(),before)
        query=effective_configuration(self.target)
        self.assertEqual(query.returncode,0,query.stderr.decode())
        effective=query.stdout.decode()
        for token in ('PackageRequired','DatabaseRequired','PackageTrustedOnly','DatabaseTrustedOnly',URL):self.assertIn(token,effective)
        self.assertNotIn('Optional',effective)
        self.assertEqual(gpg(self.ring,'--export',self.base_fpr),self.base_export)
        for _ in range(2):
            result,body=self.cli('disable',True);self.assertEqual(result.returncode,0,body)
        self.assertEqual(self.main.read_bytes(),self.original)
        self.assertTrue(gpg(self.ring,'--export',self.fpr))
        self.assertEqual(gpg(self.ring,'--export',self.base_fpr),self.base_export)

    def test_portable_query_uses_owned_nested_include_graph_and_base_policy(self):
        self.enable()
        extra=self.target/'etc/pacman.d/base-options.conf'
        nested=self.target/'etc/pacman.d/base-policy.conf'
        nested.write_bytes(b'SigLevel = Required DatabaseOptional\n')
        extra.write_bytes(b'Include = /etc/pacman.d/base-policy.conf\n')
        self.main.write_bytes(self.main.read_bytes().replace(b'SigLevel = Required DatabaseOptional', b'Include = /etc/pacman.d/base-options.conf'))
        before={path:path.read_bytes() for path in (self.main,extra,nested,self.target/enrollment.INCLUDE.lstrip('/'))}
        original_command=command
        inspected=[]
        def checked(argv, **kwargs):
            self.assertEqual(argv[0],'/usr/bin/pacman-conf')
            self.assertNotIn('--sysroot',argv);self.assertNotIn('--rootdir',argv)
            config=Path(argv[argv.index('--config')+1]);mirror=config.parents[1]
            self.assertFalse(config.is_relative_to(self.target))
            for copied in mirror.rglob('*'):
                if not copied.is_file():continue
                for line in copied.read_text().splitlines():
                    key,separator,value=line.split('#',1)[0].strip().partition('=')
                    if key.strip()=='Include':
                        self.assertTrue(separator)
                        selected=Path(value.strip())
                        self.assertTrue(selected.is_relative_to(mirror));self.assertTrue(selected.is_file())
            inspected.append(True)
            return original_command(argv, **kwargs)
        with patch.dict(effective_configuration.__globals__,{'command':checked}):
            query=effective_configuration(self.target)
        self.assertEqual(inspected,[True])
        self.assertEqual(query.returncode,0,query.stderr.decode())
        for token in ('PackageRequired','DatabaseRequired','PackageTrustedOnly','DatabaseTrustedOnly',URL):self.assertIn(token,query.stdout.decode())
        self.assertNotIn('Optional',query.stdout.decode())
        self.assertEqual({path:path.read_bytes() for path in before},before)
        # The real parser must see fixture changes through the mirror, rather
        # than returning hardcoded policy or reading the host's include.
        include=self.target/enrollment.INCLUDE.lstrip('/')
        changed=URL.replace('a'*64,'b'*64)
        include.write_bytes(include.read_bytes().replace(URL.encode(),changed.encode()))
        query=effective_configuration(self.target)
        self.assertEqual(query.returncode,0,query.stderr.decode());self.assertIn(changed,query.stdout.decode());self.assertNotIn(URL,query.stdout.decode())

    def test_portable_query_refuses_missing_include_before_parser(self):
        self.enable()
        self.main.write_bytes(self.main.read_bytes().replace(b'SigLevel = Required DatabaseOptional', b'Include = /etc/pacman.d/missing-fixture.conf'))
        with self.assertRaises(enrollment.Error):effective_configuration(self.target)

    def test_operator_snapshot_selection_changes_only_owned_include(self):
        self.enable();main=self.main.read_bytes()
        other=URL.replace('a'*64,'b'*64)
        result,body=self.cli(apply=True,url=other)
        self.assertEqual(result.returncode,0,body);self.assertEqual(self.main.read_bytes(),main)
        self.assertIn(other,(self.target/enrollment.INCLUDE.lstrip('/')).read_text())

    def test_user_main_edits_preserved_and_edited_managed_include_refused(self):
        self.enable();edit=b'\n# user edit\n[custom]\nServer = https://custom.example.invalid/repo\n'
        self.main.write_bytes(self.main.read_bytes()+edit)
        include=self.target/enrollment.INCLUDE.lstrip('/')
        original=include.read_bytes();include.write_bytes(original.replace(b'DatabaseRequired',b'DatabaseOptional'))
        result,body=self.cli('disable',True);self.assertNotEqual(result.returncode,0)
        self.assertIn(b'DatabaseOptional',include.read_bytes());self.assertTrue(self.main.read_bytes().endswith(edit))
        include.write_bytes(original)
        result,body=self.cli('disable',True);self.assertEqual(result.returncode,0,body)
        self.assertEqual(self.main.read_bytes(),self.original+edit)

    def test_wrong_primary_and_secret_material_refused_before_trust(self):
        result,body=self.cli(apply=True,fingerprint=self.base_fpr)
        self.assertNotEqual(result.returncode,0);self.assertFalse(body['keyring_may_have_changed'])
        self.key.write_bytes(gpg(self.project,'--export-secret-keys',self.fpr))
        result,body=self.cli(apply=True)
        self.assertNotEqual(result.returncode,0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertEqual(self.main.read_bytes(),self.original)

    def test_foreign_lock_and_unowned_duplicate_selection_preserved(self):
        lock=self.target/'var/lib/pacman/db.lck';lock.write_text('FOREIGN\n')
        result,body=self.cli(apply=True);self.assertNotEqual(result.returncode,0)
        self.assertEqual(lock.read_text(),'FOREIGN\n');lock.unlink()
        self.main.write_bytes(self.original+b'\n[cachy-asahi]\nSigLevel=Never\nServer=https://other.invalid\n')
        result,body=self.cli(apply=True);self.assertNotEqual(result.returncode,0)
        self.assertFalse(body.get('keyring_may_have_changed',False))

    def test_unsafe_permissions_symlink_and_glob_selection_refused(self):
        for change in ('key-mode','key-link','glob'):
            with self.subTest(change=change):
                if change=='key-mode':self.key.chmod(0o666)
                elif change=='key-link':
                    self.key.unlink();self.key.symlink_to(self.case/'actual.gpg');(self.case/'actual.gpg').write_bytes(self.public)
                else:self.main.write_bytes(self.original+b'\nInclude = /etc/pacman.d/*.conf\n')
                result,body=self.cli(apply=True);self.assertNotEqual(result.returncode,0)
                self.key.unlink();self.key.write_bytes(self.public);self.key.chmod(0o600)

    def test_changed_input_stops_before_key_mutation(self):
        result,body=self.injected('''original=m.inspect_key
def changed(*args):
 original(*args)
 path=root/'etc/pacman.conf';path.write_bytes(path.read_bytes()+b'\\n# concurrent edit\\n')
m.inspect_key=changed
''')
        self.assertNotEqual(result.returncode,0);self.assertFalse(body['keyring_may_have_changed'])
        self.assertTrue(self.main.read_bytes().endswith(b'# concurrent edit\n'))

    def test_real_import_then_lsign_failure_reports_retained_key_no_selection(self):
        result,body=self.injected('''original=m.run
def failure(argv,home):
 if '--lsign-key' in argv:raise m.Error('synthetic lsign failure after actual import')
 return original(argv,home)
m.run=failure
''')
        self.assertNotEqual(result.returncode,0);self.assertTrue(body['keyring_may_have_changed'])
        self.assertEqual(self.main.read_bytes(),self.original)
        self.assertFalse((self.target/enrollment.INCLUDE.lstrip('/')).exists())
        self.assertTrue(gpg(self.ring,'--export',self.fpr))
        self.assertEqual(gpg(self.ring,'--export',self.base_fpr),self.base_export)

    def test_failed_main_commit_leaves_recoverable_orphan_include(self):
        result,body=self.injected('''original=m.replace
def failure(path,*args):
 if path.name=='pacman.conf':raise OSError('synthetic main commit failure')
 return original(path,*args)
m.replace=failure
''')
        self.assertNotEqual(result.returncode,0);self.assertTrue(body['config_changed'])
        self.assertEqual(self.main.read_bytes(),self.original)
        self.assertTrue((self.target/enrollment.INCLUDE.lstrip('/')).exists())
        self.enable()
        result,body=self.cli('disable',True);self.assertEqual(result.returncode,0,body)
        self.assertEqual(self.main.read_bytes(),self.original)

    def test_bad_url_and_incomplete_configuration_refused(self):
        for url in ('http://repo.invalid/generations/'+'a'*64+'/release/repo',URL+'?token=x',URL.replace('a'*64,'latest'),URL.replace('https://','https://user@')):
            with self.subTest(url=url),self.assertRaises(enrollment.Error):enrollment.snapshot_url(url)
        self.main.write_bytes(b'[core]\nServer=https://base.invalid\n')
        result,body=self.cli(apply=True);self.assertNotEqual(result.returncode,0)


if __name__=='__main__':
    unittest.main(verbosity=2)
