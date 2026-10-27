#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Host controls stage exact package bytes and use only private process fixtures."""
import argparse
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(add_help=False);p.add_argument('--package-root',type=Path)
OPTIONS,REST=p.parse_known_args()
DEFAULT=next((q/'packages/tools/cachy-asahi-session-diagnostics' for q in HERE.parents
              if (q/'packages/tools/cachy-asahi-session-diagnostics/PKGBUILD').is_file()),None)
PACKAGE=OPTIONS.package_root or DEFAULT


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


F=load('diagnostic_fixture_test',HERE/'cli_fixture.py')
I=load('diagnostic_installed_test',HERE/'installed.py')
V=load('diagnostic_fixture_contract_test',HERE/'fixture_contract.py')


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if PACKAGE is None:raise ValueError('--package-root required')
        cls.temp=tempfile.TemporaryDirectory(prefix='session-diagnostics-private-host-controls-')
        cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name);cls.stage=cls.root/'stage'
        subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',
            'set -eu; source "$1/PKGBUILD"; srcdir=$1; pkgdir=$2; package',
            'stage-session-diagnostics',str(PACKAGE.absolute()),str(cls.stage)],
            capture_output=True,check=True,timeout=10)
        cls.cli=cls.stage/'usr/bin/cachy-asahi-session-diagnostics'
        cls.module,cls.runtime=F.packaged(cls.cli)

    def work(self,name):
        path=self.root/name;path.mkdir(mode=0o700);return path

    def test_guard_refuses_host_before_live_collection(self):
        work=self.work('host-refusal')
        with patch.dict(os.environ,{'CACHY_ASAHI_SESSION_DIAGNOSTICS_FIXTURE':'0'}):
            with patch.object(F,'packaged',side_effect=AssertionError('must not load before guard')):
                with self.assertRaisesRegex(ValueError,'owned native ARM'):
                    F.run(self.cli,work)
        self.assertEqual(list(work.iterdir()),[])

    def test_root_actor_guard_refuses_without_mutation(self):
        result=subprocess.run([sys.executable,'-I','-B',str(HERE/'installed.py')],capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'dedicated disposable native ARM PID1 required',result.stderr)

    def test_owned_empty_private_work_required(self):
        work=self.work('nonempty');(work/'sentinel').write_bytes(b'unchanged')
        with self.assertRaisesRegex(ValueError,'owned empty 0700'):F.run(self.cli,work)
        self.assertEqual((work/'sentinel').read_bytes(),b'unchanged')
        public=self.work('public');public.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'owned empty 0700'):F.run(self.cli,public)

    def test_packaged_bytes_and_path_binding(self):
        self.assertEqual(self.runtime.read_bytes(),(PACKAGE/'session_probe.py').read_bytes())
        alias=self.root/'alias';alias.symlink_to(self.cli)
        with self.assertRaisesRegex(ValueError,'ordinary absolute'):F.packaged(alias)
        with self.assertRaisesRegex(ValueError,'ordinary absolute'):F.packaged(Path('relative'))
        self.assertFalse(list(self.stage.rglob('__pycache__')))

    def test_missing_optional_tools_use_real_private_exec_absence_only(self):
        work=self.work('missing-tools');result=F.missing_tool_control(self.module,work)
        self.assertEqual(result['status'],'PASS_REAL_EXEC_ABSENCE')
        self.assertEqual(result['scope'],'INJECTED_ENDPOINT_CONTEXT_AND_PRIVATE_EXECUTABLE_MAPPING')
        self.assertEqual(len(result['calls']),12)
        self.assertEqual(result['service_queries'],'NONE')
        for row in result['calls']:
            self.assertTrue(Path(row['executed_argv'][0]).is_relative_to(work))
            self.assertFalse(Path(row['executed_argv'][0]).exists())

    def test_headless_assertions_preserve_unknowns_without_any_host_reads_or_queries(self):
        def refuse(*_):raise AssertionError('no tool must execute')
        report=self.module.collect(dict(execution_context='virtual'),run=refuse,read=lambda _:None,environ={},context={})
        value=F.assert_headless(report)
        self.assertEqual(value['unavailable_endpoint_checks'],12)
        self.assertEqual(value['speaker_protection'],'NOT TESTED')
        changed=copy.deepcopy(report);changed['physical_checks']['lock_unlock']='PASS'
        with self.assertRaisesRegex(ValueError,'physical checks'):F.assert_headless(changed)
        changed=copy.deepcopy(report);changed['checks'][0]['state']='checked'
        with self.assertRaisesRegex(ValueError,'headless endpoints'):F.assert_headless(changed)

    def test_exact_runtime_owned_children_retire_without_remainder(self):
        value=F.process_controls(self.module)
        self.assertEqual(value['status'],'PASS_OWNED_INSTALLED_RUNTIME_CHILDREN')
        self.assertTrue(value['all_owned_children_reaped'])
        self.assertTrue(value['events'][1]['descendant_reaped'])
        self.assertEqual(value['events'][2]['launch'],'SKIPPED')

    def test_exceptional_cleanup_echild_never_signals_unowned_pid(self):
        with patch.object(F.os,'waitid',side_effect=ChildProcessError(errno.ECHILD,'owned child reservation lost')) as observe:
            with patch.object(F.os,'kill') as kill,patch.object(F.os,'waitpid') as reap:
                with self.assertRaisesRegex(ValueError,'cleanup-unverified'):
                    F.retire_owned_children([12345])
        observe.assert_called_once_with(os.P_PID,12345,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        kill.assert_not_called();reap.assert_not_called()

    def test_private_tamper_refused_before_probe_and_hostile_python_ignored(self):
        work=self.work('tamper');other=work/'unrelated';other.mkdir()
        original=F.pin(self.runtime.read_bytes())
        events=[]
        def command(program,args,label,expected):
            result=subprocess.run([str(program),*args],cwd=other,
                env=dict(PATH='/nonexistent',PYTHONPATH='/PRIVATE',PYTHONHOME='/PRIVATE',LC_ALL='C'),
                capture_output=True,timeout=5)
            self.assertEqual(result.returncode,expected,result.stderr)
            events.append(label)
            return dict(returncode=result.returncode,stdout_bytes=len(result.stdout),
                stdout_text=result.stdout.decode(),stderr_text=result.stderr.decode())
        result=F.tamper_control(self.cli,self.runtime,work,command)
        self.assertEqual(result['status'],'PASS_PRIVATE_TAMPER_REFUSAL')
        self.assertEqual(events,['tamper-changed','tamper-missing','tamper-oversized','tamper-symlink','tamper-restored'])
        self.assertEqual(F.pin(self.runtime.read_bytes()),original)

    def test_signature_expiry_revocation_and_bad_statuses_refused(self):
        class C:
            need=staticmethod(F.need)
        key='A'*40
        good='[GNUPG:] GOODSIG AAAAAAAA TEST\n[GNUPG:] VALIDSIG '+key+' 1 2 3 4 5 6 7\n'
        I.verify_signature_status(C,good,key)
        for status in ('EXPKEYSIG','KEYEXPIRED','REVKEYSIG','KEYREVOKED','BADSIG','ERRSIG','EXPSIG','SIGEXPIRED','NODATA','FAILURE','ERROR','NO_PUBKEY'):
            with self.subTest(status=status),self.assertRaisesRegex(ValueError,'signature refused'):
                I.verify_signature_status(C,good+'[GNUPG:] '+status+' fixture\n',key)
        with self.assertRaises(ValueError):I.verify_signature_status(C,good,'B'*40)
        with self.assertRaises(ValueError):I.verify_signature_status(C,'[GNUPG:] VALIDSIG '+key,key)

    def test_actual_time_test_signer_transport_only_no_alpm_or_native_result(self):
        source=self.root/'synthetic-signature-transport.pkg.tar.zst'
        source.write_bytes(b'SYNTHETIC SIGNATURE TRANSPORT ONLY; NOT AN ALPM PACKAGE; NATIVE NOT_RUN\n')
        private=self.root/'private-signature-transport'
        class C:
            need=staticmethod(F.need)
            digest=staticmethod(lambda path:F.pin(Path(path).read_bytes())['sha256'])
        class Commands:
            @staticmethod
            def command(argv,timeout=35):
                value=subprocess.run(argv,env=F.ENV,capture_output=True,timeout=timeout)
                F.need(len(value.stdout)+len(value.stderr)<=128*1024 and value.returncode==0,
                       'private TEST signature command failed')
                return value.stdout.decode()
        def fixture_path(value):
            return private if str(value)=='/tmp/session-diagnostics-package-signing' else Path(value)
        before=int(time.time())
        try:
            with patch.object(I,'Path',fixture_path):result=I.sign_package(Commands,C,source)
            self.assertTrue(result['signature_verified_at_actual_time'])
            self.assertTrue(result['actual_time_signature_verified'])
            self.assertFalse(result['fake_signature_time_used'])
            self.assertEqual(result['alpm_local_signature_policy'],'Required')
            self.assertEqual(result['production_trust'],'UNTOUCHED')
            self.assertLessEqual(before,result['created_epoch'])
            self.assertLessEqual(result['created_epoch'],result['verified_epoch'])
            self.assertEqual(C.digest(source),result['archive_sha256'])
            self.assertEqual(C.digest(Path(result['archive'])),result['archive_sha256'])
            self.assertEqual(C.digest(Path(result['archive']+'.sig')),result['signature_sha256'])
            self.assertIn(b'BEGIN PGP PUBLIC KEY BLOCK',(private/'TEST-public.asc').read_bytes())
            status=(private/'verification.txt').read_text()
            I.verify_signature_status(C,status,result['fingerprint'])
            certificate=Commands.command(['/usr/bin/gpg','--no-options','--homedir',result['keyring'],
                '--batch','--with-colons','--show-keys',str(private/'TEST-public.asc')])
            self.assertEqual([row.split(':')[9] for row in certificate.splitlines() if row.startswith('fpr:')],
                             [result['fingerprint']])
            self.assertTrue((private/'keyring/private-keys-v1.d').is_dir())
        finally:
            keyring=private/'keyring'
            if keyring.exists():
                subprocess.run(['/usr/bin/gpgconf','--homedir',str(keyring),'--kill','all'],
                    env=F.ENV,capture_output=True,check=True,timeout=15)
                shutil.rmtree(keyring)
        self.assertFalse((private/'keyring').exists())

    def test_validator_refuses_skipped_fixture_and_lifecycle(self):
        for value in ({},{'status':'PASS_SESSION_DIAGNOSTICS_HEADLESS_CONTROLS'}):
            with self.assertRaises(ValueError):V.validate_fixture(value,os.uname().machine,os.sysconf('SC_PAGE_SIZE'))
        for value in ({},{'status':'PASS_SESSION_DIAGNOSTICS_INSTALLED_LIFECYCLE'}):
            with self.assertRaises(ValueError):V.validate_lifecycle(value)


if __name__=='__main__':unittest.main(argv=[sys.argv[0],*REST],verbosity=2)
