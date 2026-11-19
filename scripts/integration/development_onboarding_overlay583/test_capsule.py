"""Prove the exact local exercise and fenced guest selection without a VM."""
import ast
from base64 import b64decode
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('capsule',HERE/'capsule.py')
C=importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
G=C.module(HERE/'guest.py','onboarding_guest_test')


class PortableSourceChecks(unittest.TestCase):
    def test_deterministic_bundle_and_real_documented_host_cli(self):
        def read_source(name):
            return (C.ROOT/name).read_bytes()

        with tempfile.TemporaryDirectory(dir='/var/tmp',prefix='onboarding-host-smoke-') as path:
            root=Path(path)
            bundle=root/'source.bundle'
            first=C.bundle_fixture(bundle,read_source)
            second=C.bundle_fixture(root/'again.bundle',read_source)
            self.assertEqual(first,second)
            self.assertEqual(first['fixture_commit'],'c077e76ebfcabcc091b1d1590b173e7eb6d4f91f')
            bundle.chmod(0o444)
            home=root/'home'
            home.mkdir(mode=0o700)
            origin=home/'origin'
            C.invoke(root,'-c','protocol.allow=never','-c','protocol.file.allow=always',
                     'clone','--no-local','--branch','onboarding',str(bundle),str(origin))
            self.assertEqual(C.invoke(origin,'rev-parse','HEAD').decode().strip(),first['fixture_commit'])
            script=origin/'examples/development/onboarding.py'
            driver=root/'driver/examples/development/onboarding.py'
            driver.parent.mkdir(parents=True)
            driver.write_bytes(b64decode(first['program']))
            driver.chmod(0o444)
            self.assertEqual(driver.read_bytes(),script.read_bytes())
            work=home/'exercise'
            env=dict(PATH='/usr/bin:/bin',HOME=str(home),TMPDIR=str(home),LC_ALL='C.UTF-8',TZ='UTC',
                     GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_ALLOW_PROTOCOL='file')
            def run(*args):
                result=subprocess.run([sys.executable,'-I','-B',str(driver),*map(str,args)],env=env,
                    stdin=subprocess.DEVNULL,capture_output=True,timeout=20,check=True)
                return result.stdout
            self.assertIn(G.GREETING.encode(),run('prepare',work,'--source',origin,'--revision',first['fixture_commit']))
            edit=work/'checkout'/G.EXAMPLE
            edit.write_bytes(edit.read_bytes().replace(G.GREETING.encode(),G.EDIT.encode()))
            self.assertIn(G.EDIT.encode(),run('rebuild',work,'--expect',G.EDIT))
            edited=next((work/'evidence').glob('rebuild-*'))
            for directory in (work/'evidence/baseline',edited):
                self.assertTrue(os.access(directory/'hello',os.X_OK))
            retained=json.loads(run('verify',edited))
            self.assertEqual(retained['source_revision'],first['fixture_commit'])
            self.assertEqual(retained['scope'],'retained-build-evidence')
            if os.uname().machine!='aarch64':
                with self.assertRaisesRegex(ValueError,'retained AArch64 ELF'):
                    G.verify_evidence({'build_evidence':G.retain_evidence(work)},first)

    def test_guest_guard_refuses_before_subprocess_or_output(self):
        trial=SimpleNamespace(TARGET=Path('/actor-fenced'),pin=C.ref)
        selection=dict(fixture_commit='b'*40,upstream_commit=C.EXAMPLE_SOURCE,tool_versions={})
        with patch.object(G.os,'geteuid',return_value=1000), patch.object(G.subprocess,'Popen',side_effect=AssertionError('actor forbidden')):
            result=G.exercise(trial,dict(nonce='a'*32),b'unchanged',{},1,selection)
        self.assertEqual(result['status'],'HOLD')
        self.assertEqual(result['commands'],[])
        self.assertTrue(result['workspace_removed'])

    def test_inventory_stderr_cannot_pollute_or_overfill_the_lock(self):
        owner=C.module(C.ROOT/C.OWNER,'onboarding_inventory_owner_test')
        owner.prepare()
        warning=b"warning: Public keyring not found; have you run 'pacman-key --init'?\n"
        rows=b'z 2\na 1\n'
        args=[sys.executable,'-I','-B','-c',
              f'import os; os.write(2, {warning!r}); os.write(1, {rows!r})']
        with tempfile.TemporaryDirectory(prefix='onboarding-inventory-') as d:
            receipt,stderr=G.inventory_capture(owner,args,os.environ,6,Path(d))
            self.assertEqual(receipt['output'],rows)
            self.assertEqual(stderr,warning)
            self.assertTrue(receipt['passed'] and receipt['reaped'] and receipt['output_complete'])
            self.assertEqual(receipt['group_census'],'EMPTY_TWICE')
            args[-1]='import os; os.write(1, b"a"*140000); os.write(2, b"b"*140000)'
            with self.assertRaisesRegex(ValueError,'bounded inventory command streams'):
                G.inventory_capture(owner,args,os.environ,6,Path(d))


class HeldSourceChecks(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('CACHY_ONBOARDING_HELD') and os.environ.get('CACHY_ONBOARDING_RUNTIME_WRAPPER'),
                         'Select the exact retained controller and Runtime44 inputs')
    def test_worker_preserves_exact_base_install_and_guest_guards(self):
        sel=dict(bundle='INPUT_DATA_ONLY')
        original=C.invoke(C.ROOT,'show',C.BASE_SOURCE+':'+C.TRIAL)
        candidate=C.project_worker(original,sel,(HERE/'guest.py').read_text())
        def functions(raw):
            return {part.name:ast.dump(part) for part in ast.parse(raw).body if isinstance(part,ast.FunctionDef)}
        before,after=map(functions,(original,candidate))
        self.assertEqual({k for k in before if before[k]!=after[k]},{'evidence_names','execute_guest','read_result'})
        self.assertEqual(after['target_api_mounts'],before['target_api_mounts'])
        held=Path(os.environ['CACHY_ONBOARDING_HELD'])
        runtime_wrapper=Path(os.environ['CACHY_ONBOARDING_RUNTIME_WRAPPER'])
        root=C.body(held/'root-entry.sh',C.ROOT_ENTRY)
        shell=C.project_shell(root,'1'*64)
        self.assertIn(b'--pull=never --init=false --read-only --network=none --cap-drop=ALL',shell)
        self.assertIn(b'assert_owned',shell)
        self.assertIn(b'close_owned',shell)
        self.assertNotIn(b'--first-login',shell)
        with tempfile.TemporaryDirectory(prefix='onboarding-entry-fenced-') as scope:
            path=Path(scope)/'enter.py'
            C.runtime_entry(path,C.ref(shell)['sha256'],runtime_wrapper)
            raw=path.read_bytes()
            self.assertIn(C.SCOPE.encode(),raw)
            self.assertIn(b'RuntimeSession',raw)
            self.assertNotIn(b'--signature-review-sha256',raw)
            compile(raw,str(path),'exec')

    @unittest.skipUnless(os.environ.get('CACHY_ONBOARDING_HELD'),'Select the exact retained init program')
    def test_export_retains_only_the_explicit_onboarding_receipt(self):
        held=Path(os.environ['CACHY_ONBOARDING_HELD'])
        pin=json.loads(C.body(held/'HANDOFF.DATA.json',C.BASE_SHA))['source'][C.GUEST_INIT]
        original=C.body(held/'source'/C.GUEST_INIT,pin['sha256'])
        projected=C.project_guest_init(original)
        self.assertEqual(projected.replace(b'|installed-onboarding.json',b'',1),original)

        def export(init, src, dest):
            function=init.decode().split('export_evidence() {',1)[1].split('\n[[ $$',1)[0]
            code='set -eu; umask 077\nexport_evidence() {'+function+'\nexport_evidence "$1" "$2"\n'
            return subprocess.run(['/usr/bin/bash','-c',code,'test',src,dest],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                                  stdin=subprocess.DEVNULL,capture_output=True,timeout=10)

        with tempfile.TemporaryDirectory(prefix='onboarding-export-') as d:
            root=Path(d)
            source=root/'evidence'
            source.mkdir()
            report=source/'installed-onboarding.json'
            report.write_bytes(b'unit fixture\n')
            (source/'result.json').write_text('{}\n')
            self.assertEqual(export(original,source,root/'old').returncode,1)
            self.assertEqual(export(projected,source,root/'new').returncode,0)
            self.assertEqual((root/'new'/report.name).read_bytes(),report.read_bytes())
            self.assertEqual((root/'new'/report.name).stat().st_mode&0o777,0o600)
            (source/'unexpected').touch()
            self.assertEqual(export(projected,source,root/'unknown').returncode,1)
            (source/'unexpected').unlink()
            with report.open('wb') as file:
                file.truncate(8*1024**2+1)
            self.assertEqual(export(projected,source,root/'over-cap').returncode,1)
            report.unlink()
            report.symlink_to('result.json')
            self.assertEqual(export(projected,source,root/'symlink').returncode,1)


if __name__=='__main__':
    unittest.main()
