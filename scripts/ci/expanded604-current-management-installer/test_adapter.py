# SPDX-License-Identifier: MIT
"""Inert generated604 protocol checks; no build, signing, namespace or VM actors."""
import ast
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
import adapter as A

SOURCE=Path(os.environ['EXPANDED604_SOURCE'])
LEGACY=Path(os.environ['EXPANDED604_LEGACY_ROOT'])


class Adapter(unittest.TestCase):
    def raw(self,name):return (LEGACY/'scripts/ci/full-composition-installer-vm'/name).read_bytes()
    def transformed(self,name):return A.transform(self.raw(name),name,source=SOURCE)
    def module(self,name):
        raw,_=self.transformed(name)
        space=dict(__name__='_inert_604_'+name.replace('.','_'),__file__=str(LEGACY/name))
        exec(compile(raw,'<inert604-'+name+'>','exec'),space);return SimpleNamespace(**space)

    def test_exact_six_runners_compile_and_declared_semantic_counts(self):
        counts={}
        for name in A.NAMES:
            raw,receipt=self.transformed(name);compile(raw,name,'exec');counts[name]=receipt['semantic_edits']
        self.assertEqual(counts,dict(zip(A.NAMES,(12,16,1,1,9,2))))

    def test_exact_legacy_bytes_and_second_adaptation_refuse(self):
        raw=self.raw('numeric_vm.py')
        for changed in (raw.replace(b'started+600',b'started+601'),self.transformed('numeric_vm.py')[0]):
            with self.subTest(changed=len(changed)),self.assertRaisesRegex(ValueError,'source bytes differ'):
                A.transform(changed,'numeric_vm.py',source=SOURCE)

    def test_accepted_adapter_helpers_and_import_registration_are_held(self):
        original=sys.modules.get('contract');A.accepted(SOURCE)
        self.assertIs(sys.modules.get('contract'),original)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);base=root/'scripts/ci/expanded600-installer-vm';base.mkdir(parents=True)
            for name in A.HELPERS:(base/name).write_bytes((SOURCE/'scripts/ci/expanded600-installer-vm'/name).read_bytes())
            (base/'adapter-rules.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'helper differs'):A.accepted(root)

    def test_original_metadata_and_all_deadlines_unchanged(self):
        names={'NUMERIC_VM','GROUP_METADATA','SONAME_OUTPUTS','NUMERIC_MAP','SELECTION','CHILD_NOFILE','PARENT_NOFILE'}
        def constants(raw):
            return {target.id:ast.dump(node.value,include_attributes=False) for node in ast.parse(raw).body if isinstance(node,ast.Assign)
                    for target in node.targets if isinstance(target,ast.Name) and target.id in names}
        for name in A.NAMES:self.assertEqual(constants(self.raw(name)),constants(self.transformed(name)[0]))
        for name in ('installer.py','numeric_vm.py','prepare.py','run.py'):
            before=A.accepted(SOURCE).transform(self.raw(name),name)[0];after=self.transformed(name)[0]
            def deadlines(raw):
                return [(scope,ast.dump(node,include_attributes=False)) for node,path,scope,parent in A.nodes(ast.parse(raw))
                        if isinstance(node,ast.keyword) and node.arg in {'deadline','deadline_seconds','seconds','timeout'}]
            self.assertEqual(deadlines(before),deadlines(after))
        numeric=self.transformed('numeric_vm.py')[0]
        self.assertTrue(numeric.endswith((SOURCE/'scripts/ci/expanded600-installer-vm/observer600.py').read_bytes()))
        self.assertIn(b'deadline=started+600',numeric)
        self.assertIn(b'0o4110',self.transformed('profile.py')[0])

    def test_only_explicit_package_bounds_are604(self):
        counts={}
        for name in ('installer.py','numeric_vm.py'):
            tree=ast.parse(self.transformed(name)[0]);bounds=[node for node in ast.walk(tree)
                if isinstance(node,ast.keyword) and node.arg=='max_packages']
            counts[name]=sum(n.value.value==604 for n in bounds)
            self.assertEqual(sorted(n.value.value for n in bounds),[604]*4+[1024]*2 if name=='installer.py' else [604,604,1024])
        self.assertEqual(counts,{'installer.py':4,'numeric_vm.py':2})
        profile=self.transformed('profile.py')[0]
        self.assertIn(b"expected.get('cachy-asahi-setup') == \"0.1.0-5\"",profile)
        self.assertNotIn(b'0.1.0-3',profile)

    def test_owner_creation_and_retirement_share604_scope(self):
        module=self.module('run.py');argv=module.container_args(dict(nonce='a'*32),'vm','sha256:'+'b'*64,[],Path('/tmp/out'),'owned')
        self.assertIn('cachy-asahi.current604-installer='+'a'*32,argv)
        self.assertIn('--cap-drop=ALL',argv);self.assertIn('--read-only',argv);self.assertIn('--user=23001:23001',argv)
        self.assertNotIn('--privileged',argv)
        raw=self.transformed('run.py')[0];self.assertNotIn(b'expanded600-installer',raw)

    def events(self):
        module=self.module('run.py');common=SimpleNamespace(KERNEL='7.2.10-1-aarch64-ARCH')
        result=dict(event='result',status='PASS_CURRENT604_INSTALLER',phase='complete',package_count=604,
            expected_lock_sha256=A.TARGET,hooks='DISABLED',scriptlets='DISABLED',hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED')
        result.update({name:True for name in module.PASS_FLAGS})
        return module,common,[dict(event='boot',scope='generic-arm-full-installer-software',page_size=4096,kernel=common.KERNEL,uid=0),
            result,dict(event='exit',status='PASS_CURRENT604_INSTALLER',cleanup='PASS')]

    def test_all_original_completion_flags_and_exact604_identity_required(self):
        module,common,events=self.events();module.validate_completion(events,'a'*32,common)
        mutations=[(field,False) for field in module.PASS_FLAGS]+[
            ('package_count',600),('expected_lock_sha256',A.OLD),('status','PASS_EXPANDED600_INSTALLER')]
        for field,value in mutations:
            bad=copy.deepcopy(events);bad[1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):module.validate_completion(bad,'a'*32,common)

    def test_ordinary_retirement_precedes_complete_independent_readback(self):
        guest=self.transformed('guest.py')[0].decode()
        self.assertLess(guest.index('receipt=worker.supervise('),guest.index('result=numeric.verify_export('))
        self.assertLess(guest.index("receipt['group_retired']"),guest.index('result=numeric.verify_export('))
        numeric=self.transformed('numeric_vm.py')[0]
        for required in (b"observation.get('complete') is True",b'worker.compare_payload(',b'driver.database(',b"set(row['files'])==expected"):
            self.assertIn(required,numeric)


if __name__=='__main__':unittest.main()
