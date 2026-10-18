# SPDX-License-Identifier: MIT
"""Finite source/API controls; no native, ALPM, signing, namespace or network actors."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock,patch
import adapter as A

DEFAULT_ROOT=next((p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file()),Path.cwd())
ROOT=Path(os.environ.get('EXPANDED604_SOURCE',DEFAULT_ROOT))
PAIR=ROOT/'artifacts/development/setup5-accepted-pair-inputs-20261016/payload'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


class Adapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='root604-adapter-controls-');cls.base=Path(cls.temporary.name)
        cls.old=A.accepted(ROOT);cls.held=cls.old.C.read(cls.old.C.HERE/'held-pins.json');cls.sources={};cls.codes={};cls.oldcodes={}
        # Read-only Git object extraction supplies ONLY the three finite frozen closures.
        for case,row in cls.held.items():
            source=cls.base/('source-'+case);source.mkdir();cls.sources[case]=source
            for name,pin in row['pins'].items():
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(subprocess.check_output(['git','-C',str(ROOT),'show',row['source']+':'+name],timeout=15))
        with patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden')):
            for case in cls.held:
                oldcode=cls.base/('600-'+case);cls.old.prepare(cls.sources[case],oldcode,case,git=False);cls.oldcodes[case]=oldcode
                code=cls.base/('604-'+case);A.prepare(cls.sources[case],code,case,git=False,implementation=ROOT);cls.codes[case]=code
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def test_normal_diagnostic_is_additive_source_bound_and_fault_cases_unchanged(self):
        import driver_progress as D
        code=self.codes['normal'];row=A.C.read(code/'adapter.json')['normal_driver_diagnostic']
        self.assertEqual(row['basis'],'a29d1987d909660feff4630b4a0e66d3073302ac')
        self.assertEqual(row['budgets'],'UNCHANGED')
        for name in (D.DRIVER,D.HOOK):
            baseline,_=A.literals((self.oldcodes['normal']/name).read_bytes(),name)
            output,proof=D.transformed(baseline,name)
            self.assertEqual(output,(code/name).read_bytes());self.assertEqual(proof,row['files'][name])
            with self.assertRaisesRegex(ValueError,'exact original'):D.transformed(baseline+b'\n',name)
        config=A.C.read(code/'upgrade-config.json')
        self.assertEqual(config['code_pins'][D.SELF],A.C.sha(code/D.SELF))
        for case in ('precommit-exit86','postcommit-exit87'):
            self.assertNotIn('normal_driver_diagnostic',A.C.read(self.codes[case]/'adapter.json'))
            self.assertFalse((self.codes[case]/D.SELF).exists())

    def test_exact604_only_setup3_changes_to_genuine5(self):
        before,after=A.C.locks();self.assertEqual((len(before),len(after)),(604,604))
        self.assertEqual(after,before|{'cachy-asahi-setup':'0.1.0-5'})
        self.assertEqual(before['cachy-asahi-setup'],'0.1.0-3');self.assertEqual(before['cachy-asahi-welcome'],'0.1.0-4')
        self.assertEqual(len(set(before)-{'cachy-asahi-setup'}),603)
        self.assertTrue(A.MANAGEMENT<=before.keys());self.assertEqual(A.C.AFTER,'3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5')

    def test_all_private_pin_closures_and_fault_aliases_are_exact(self):
        for case,code in self.codes.items():
            config=A.C.read(code/'upgrade-config.json');receipt=A.C.read(code/'adapter.json')
            for name,digest in config['code_pins'].items():self.assertEqual(A.C.sha(code/name),digest,name)
            self.assertEqual(receipt['protected_package_count'],603);self.assertEqual(receipt['bootstrap_additions'],31)
            self.assertEqual(config['scale']['before_lock_sha256'],A.C.BEFORE);self.assertEqual(config['scale']['after_lock_sha256'],A.C.AFTER)
            self.assertEqual((code/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_bytes(),(A.C.HERE/'before604.lock').read_bytes())
            self.assertEqual((code/'scripts/ci/full-development-composition/expected-setup4-v2.lock').read_bytes(),(A.C.HERE/'after604.lock').read_bytes())
            if case!='normal':
                fault='full-root-failed-update' if case.startswith('pre') else 'full-root-postcommit-failure'
                self.assertEqual((code/'scripts/ci/full-root-upgrade-caller/upgrade_hook.py').read_bytes(),(code/'scripts/ci'/fault/'caller.py').read_bytes())

    def test_original_runtime_and_inspector_bytes_and_budgets_are_preserved(self):
        unchanged=('scripts/client/client.py','scripts/release/release.py','scripts/update/bound_update.py',
            'scripts/update/archive_stream.py','scripts/update/aux_checkpoint.py',
            'scripts/update/aux_initialize.py','scripts/update/aux_copy.py','scripts/update/supervision.py',
            'scripts/ci/full-root-upgrade-caller/persistent_scope.py','scripts/ci/full-root-upgrade-caller/run.py',
            'scripts/port/kernel-native-job/runtime.py',A.PREFIX+'setup5.py',A.PREFIX+'accepted_pair.py')
        for case,code in self.codes.items():
            old=self.oldcodes[case]
            for name in unchanged:self.assertEqual((code/name).read_bytes(),(old/name).read_bytes(),name)
            a=A.C.read(old/'upgrade-config.json');b=A.C.read(code/'upgrade-config.json')
            for key in a:
                if key not in ('purpose','scale','release','code_pins'):self.assertEqual(a[key],b[key],key)
            for key in a['scale']:
                if key not in ('before_lock_sha256','after_lock_sha256'):self.assertEqual(a['scale'][key],b['scale'][key],key)
            self.assertEqual(a['release']|{k:b['release'][k] for k in ('release_id','namespace')},b['release'])
            # Compare each actual deadline/timeout/seconds keyword, not every600 literal.
            for name in self.held[case]['pins']:
                if not name.endswith('.py'):continue
                def budgets(root):
                    return [(s,ast.dump(n,include_attributes=False)) for n,p,s,parent in A.nodes(ast.parse((root/name).read_bytes()))
                        if isinstance(n,ast.keyword) and n.arg in ('deadline','timeout','seconds','worker_seconds','verify_seconds')]
                self.assertEqual(budgets(old),budgets(code),name)

    def test_complete_protected_policy_uses_the_selected604_inventory(self):
        before,after=A.C.locks();protected=sorted(set(before)-{'cachy-asahi-setup'})
        for case,code in self.codes.items():
            module=load('_selected604_policy_'+case,code/'scripts/update/generic_policy.py')
            original=load('_prior600_policy_'+case,self.oldcodes[case]/'scripts/update/generic_policy.py')
            kernel=next(n for n in protected if n.startswith('linux-'))
            policy=dict(schema_version=1,purpose='cachy-asahi-generic-development-update-policy',
                release_id='selected604-test',protected_packages=protected,
                protected_versions={n:before[n] for n in protected},platform_roles={'kernel':[kernel]},
                protected_units={k:sorted(v) for k,v in module.asahi.REQUIRED_UNITS.items()},
                before_lock_sha256=A.C.BEFORE,after_lock_sha256=A.C.AFTER)
            with self.assertRaisesRegex(ValueError,'invalid identifier list'):original.protected_names(policy)
            self.assertEqual(len(module.protected_names(policy)),603)
            settings=dict(purpose='disposable-generic-bound-update',model='generic-development-only',release_id=policy['release_id'])
            snapshot=dict(release={'release_id':policy['release_id']},spec={'policy':{'protected_packages':protected}})
            files={kernel:['/usr/lib/modules/6.1/kernel/inert.ko']}
            self.assertEqual(module.authorize(policy,settings,snapshot,before,after,files,files)['decision'],
                'generic-development-transaction-allowed')
            for names in (protected+[protected[0]],list(before)+['extra-invalid-bound']):
                with self.assertRaises(ValueError):module.protected_names(policy|{'protected_packages':names})
            bad=dict(before);bad[kernel]='changed'
            with self.assertRaises(ValueError):module.authorize(policy,settings,snapshot,bad,after,files,files)

    def test_bootstrap21_projects31_additions_preserves_closed_payload_API(self):
        code=self.codes['normal'];module=load('_604_bootstrap',code/'scripts/ci/full-root-upgrade-caller/container.py')
        self.assertEqual((len(module.PROJECTS),len(module.EXTRAS)),(21,10));self.assertEqual(module.PROJECTS,self.old.SCRIPTS|A.MANAGEMENT|{
            'cachy-asahi-'+n for n in ('hyprland-settings','fish-config','zsh-config','setup','ksmctl','update','fdk-aac','zsh-autosuggestions','topmem','fish-bang-bang')})
        before=A.C.locks()[0];base=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
        base={r['name']:r['version'] for r in base['packages']}
        packages=[dict(name=n,version=before[n],filename=n+'.pkg.tar.xz',sha256='a'*64,size=1,signature_sha256='b'*64,signature_size=1) for n in sorted(module.PROJECTS|module.EXTRAS)]
        projects=[dict(name=p['name'],version=p['version'],archive=p['filename'],sha256=p['sha256'],
            payload=[dict(path='/usr/share/'+p['name'],type='file')]) for p in packages if p['name'] in module.PROJECTS]
        plan=dict(packages=packages,projects=projects)
        with patch.object(module,'pin') as verify:
            self.assertEqual(set(module.inputs(plan,base,before,self.base)),module.PROJECTS|module.EXTRAS)
            self.assertEqual(verify.call_count,62)
        bad=copy.deepcopy(plan);bad['packages']=bad['packages'][:-1]
        with self.assertRaisesRegex(ValueError,'21 projects'):module.inputs(bad,base,before,self.base)
        bad=copy.deepcopy(plan);bad['projects'][0]['payload'][0]['path']='/etc/forbidden'
        with patch.object(module,'pin'),self.assertRaisesRegex(ValueError,'payload namespace'):module.inputs(bad,base,before,self.base)

    def test_real_setup5_inspector_and604_lock_API_stay_composed(self):
        code=self.codes['normal'];ctor=load('_604_constructor',code/'scripts/ci/full-root-upgrade/construct_repository.py')
        api=ctor.apis(code);self.assertEqual(ctor.locks(code,api.setup)[2:],A.C.locks())
        with self.assertRaises(AssertionError):api.setup.expected_lock((self.old.C.HERE/'before600.lock').read_bytes(),(self.old.C.HERE/'after600.lock').read_bytes())
        args=NS(source_root=code,setup4_pair=PAIR,package=PAIR/'packages/cachy-asahi-setup-a/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz',
            provenance=PAIR/'runtime/cachy-asahi-setup-a/provenance.json')
        with patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden')):held=ctor.inspect_package(args,api)
        self.assertEqual(len(held.payload),6);self.assertEqual(ctor.sha(held.package),self.old.PACKAGE)

    def test_changed_original_source_refuses_before_output(self):
        source=self.sources['normal'];path=source/'scripts/client/client.py';raw=path.read_bytes();path.write_bytes(raw+b'\n')
        try:
            target=self.base/'never-created'
            with self.assertRaisesRegex(ValueError,'identity differs'):A.prepare(source,target,'normal',git=False,implementation=ROOT)
            self.assertFalse(target.exists())
        finally:path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'closed'):A.prepare(source,self.base/'bad-case','other',git=False,implementation=ROOT)
        with self.assertRaisesRegex(ValueError,'fresh'):A.prepare(source,self.codes['normal'],'normal',git=False,implementation=ROOT)

    def test_second_adaptation_and_semantic_shape_drift_refuse(self):
        name='scripts/update/scale_update.py';raw=(self.codes['normal']/name).read_bytes()
        with self.assertRaisesRegex(ValueError,'role counts'):A.literals(raw,name)
        name='scripts/ci/full-root-upgrade/root_upgrade.py';raw=(self.oldcodes['normal']/name).read_bytes()
        with self.assertRaisesRegex(ValueError,'role counts'):A.literals(raw.replace(b'max_packages=600',b'max_packages=601'),name)

    def test_fault_boundaries_and_postcommit604_proof_operand_are_inherited(self):
        pre=load('_604_pre_fault',self.codes['precommit-exit86']/'scripts/ci/full-root-failed-update/run.py');arm=Mock()
        class Refuse:
            def precommit(self):raise ValueError('original refusal')
        with self.assertRaisesRegex(ValueError,'original refusal'):pre.fault_class(Refuse,arm)().precommit()
        arm.assert_not_called()
        postpath=self.codes['postcommit-exit87']/'scripts/ci/full-root-postcommit-failure/run.py';post=load('_604_post_fault',postpath)
        class Original:
            def observed_after(self,after):self.checked=after
        worker=post.fault_class(Original,arm)();worker.commit_calls=1;worker.commit_return=1
        with self.assertRaisesRegex(ValueError,'successful original'):worker.observed_after(A.C.locks()[1])
        arm.assert_not_called();worker.commit_return=0
        with self.assertRaisesRegex(ValueError,'checkpoint remains prohibited'):worker.observed_after(A.C.locks()[1])
        arm.assert_called_once_with(worker,A.C.locks()[1])
        keywords=[n.arg for n in ast.walk(ast.parse(postpath.read_bytes())) if isinstance(n,ast.keyword)]
        self.assertEqual(keywords.count('after604_database_verified'),2);self.assertNotIn('after600_database_verified',keywords)
        self.assertEqual(post.CHILD_NOFILE,8192)


if __name__=='__main__':unittest.main(verbosity=2)
