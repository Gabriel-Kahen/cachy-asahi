"""Prove the exact local exercise and fenced guest selection without a VM."""
import ast
from base64 import b64decode
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('capsule',HERE/'capsule.py')
C=importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
G=C.module(HERE/'guest.py','onboarding_guest_test')


class Onboarding(unittest.TestCase):
    def test_deterministic_bundle_and_real_documented_host_cli(self):
        with tempfile.TemporaryDirectory(prefix='onboarding-host-smoke-') as path:
            root=Path(path)
            first=C.fixture(root/'source.bundle')
            second=C.fixture(root/'again.bundle')
            self.assertEqual(first,second)
            origin=root/'source'
            C.invoke(root,'clone','--no-local','--branch','onboarding',str(root/'source.bundle'),str(origin))
            self.assertEqual(C.invoke(origin,'rev-parse','HEAD').decode().strip(),first['fixture_commit'])
            script=origin/'examples/development/onboarding.py'
            driver=root/'driver/examples/development/onboarding.py'
            driver.parent.mkdir(parents=True)
            driver.write_bytes(b64decode(first['program']))
            self.assertEqual(driver.read_bytes(),script.read_bytes())
            work=root/'work'
            env=dict(PATH='/usr/bin:/bin',HOME=str(root),LC_ALL='C.UTF-8',TZ='UTC',GIT_ALLOW_PROTOCOL='file')
            def run(*args):
                result=subprocess.run(['/usr/bin/python3.14','-I','-B',str(driver),*map(str,args)],env=env,
                    stdin=subprocess.DEVNULL,capture_output=True,timeout=20,check=True)
                return result.stdout
            self.assertIn(G.GREETING.encode(),run('prepare',work,'--source',origin,'--revision',first['fixture_commit']))
            edit=work/'checkout'/G.EXAMPLE
            edit.write_bytes(edit.read_bytes().replace(G.GREETING.encode(),G.EDIT.encode()))
            self.assertIn(G.EDIT.encode(),run('rebuild',work,'--expect',G.EDIT))
            edited=next((work/'evidence').glob('rebuild-*'))
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

    def test_worker_preserves_exact_base_install_and_guest_guards(self):
        sel=dict(bundle='INPUT_DATA_ONLY')
        original=C.invoke(C.ROOT,'show',C.BASE_SOURCE+':'+C.TRIAL)
        candidate=C.project_worker(original,sel,(HERE/'guest.py').read_text())
        def functions(raw):
            return {part.name:ast.dump(part) for part in ast.parse(raw).body if isinstance(part,ast.FunctionDef)}
        before,after=map(functions,(original,candidate))
        self.assertEqual({k for k in before if before[k]!=after[k]},{'evidence_names','execute_guest','read_result'})
        self.assertEqual(after['target_api_mounts'],before['target_api_mounts'])
        root=C.body(C.HELD/'root-entry.sh',C.ROOT_ENTRY)
        shell=C.project_shell(root,'1'*64)
        self.assertIn(b'--pull=never --init=false --read-only --network=none --cap-drop=ALL',shell)
        self.assertIn(b'assert_owned',shell)
        self.assertIn(b'close_owned',shell)
        self.assertNotIn(b'--first-login',shell)
        with tempfile.TemporaryDirectory(prefix='onboarding-entry-fenced-') as scope:
            path=Path(scope)/'enter.py'
            C.runtime_entry(path,C.ref(shell)['sha256'])
            raw=path.read_bytes()
            self.assertIn(C.SCOPE.encode(),raw)
            self.assertIn(b'RuntimeSession',raw)
            self.assertNotIn(b'--signature-review-sha256',raw)
            compile(raw,str(path),'exec')


if __name__=='__main__':
    unittest.main()
