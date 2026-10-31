#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused exact74 construction/refusal controls; no native evidence."""
import ast,copy,importlib.util,json,os,shutil,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
CURRENT=Path(os.environ.get('DOCTOR2_CURRENT74_CURRENT_SOURCE',str(F.HERE.parents[2])))
NATIVE=Path(os.environ.get('DOCTOR2_NATIVE_SOURCE',str(CURRENT/'.ci-inputs/doctor2-native-source')))
HISTORICAL=Path(os.environ.get('DOCTOR2_HISTORICAL_FACTORY',str(F.HERE.parent/'doctor2-native-source')))
COMPARISON=Path(os.environ.get('DOCTOR2_COMPARISON_FACTORY',str(F.HERE.parent/'doctor2-comparison-native-source')))
CURRENT70=Path(os.environ.get('DOCTOR2_CURRENT70_FACTORY',str(F.HERE.parent/'doctor2-current70-native-source')))
EXPECTED=os.environ.get('DOCTOR2_CURRENT74_EXPECTED_SOURCE')
RECIPE='packages/tools/cachy-asahi-doctor2';SLICE='scripts/ci/welcome-native/'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class Constructor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value=F.profile();cls.old=json.loads((CURRENT70/'source.json').read_bytes())
        cls.inputs={str(root):F.files(root) for root in (NATIVE,HISTORICAL,COMPARISON,CURRENT70)}
        cls.package=F.files(CURRENT/RECIPE)
        for obj,name in ((subprocess,'Popen'),(subprocess,'run'),(socket,'socket'),(os,'execv')):
            guard=patch.object(obj,name,side_effect=AssertionError('source constructor forbids actors'));guard.start();cls.addClassCleanup(guard.stop)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def emit(self,name='output',**kwargs):
        output=self.root/name;receipt=F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,CURRENT70,output,**kwargs);return output,receipt
    def refuses(self,current=CURRENT,native=NATIVE,historical=HISTORICAL,comparison=COMPARISON,current70=CURRENT70,**kwargs):
        output=self.root/'refused'
        with self.assertRaises((ValueError,OSError,KeyError)):F.prepare(current,native,historical,comparison,current70,output,**kwargs)
        self.assertFalse(output.exists())
    def test_complete_default_selected_maps_and_optional_independent74(self):
        for selected in (False,True):
            output,receipt=self.emit(str(selected),selected=selected);raw=F.files(output)
            self.assertEqual({n:F.pin(b) for n,b in raw.items()},self.value['views']['selected' if selected else 'default']['files'])
            self.assertEqual(len(raw),74);self.assertEqual(receipt['installed_compare'],'NOT_RUN');self.assertEqual(receipt['acceptance'],'NOT_GRANTED')
            if selected and EXPECTED:self.assertEqual(raw,F.files(Path(EXPECTED)))
    def test_whole70_inverse_and_default_only_five_policy_stamps(self):
        selected,_=self.emit('selected',selected=True);default,_=self.emit('default');a=F.files(selected);b=F.files(default)
        self.assertEqual({n for n in a if a[n]!=b[n]},F.POLICY_STAMPS)
        for chosen,raw in ((False,b),(True,a)):
            prior=self.old['views']['selected' if chosen else 'default'];old=F.files(NATIVE)
            old.update({RECIPE+'/'+n:body for n,body in self.package.items()});old.update({n:text.encode() for n,text in prior['generated'].items()})
            self.assertEqual({n:F.pin(body) for n,body in old.items()},prior['files'])
            inverse={n:body for n,body in raw.items() if n in old}
            for name,body in old.items():
                if inverse[name]!=body:inverse[name]=body
            self.assertEqual({n:F.pin(body) for n,body in inverse.items()},prior['files'])
    def test_actuals_null_and_default_policy_unbound(self):
        for selected in (False,True):
            output,_=self.emit(str(selected),selected=selected);policy=json.loads((output/(SLICE+'doctor2-policy.json')).read_bytes())
            self.assertTrue(all(policy[n] is None for n in ('actual_source','actual_ref','actual_run')))
            contract=load('current74_'+str(selected),output/(SLICE+'contract.py'))
            if selected:self.assertEqual(contract.activation(output)['version'],'0.2.0-2')
            else:
                self.assertEqual(policy['status'],'UNBOUND');self.assertTrue(all(policy[n] is None for n in ('recipe','version','input_sha256')))
                with self.assertRaises(ValueError):contract.activation(output)
    def test_old_missing_extra_changed_and_directory_package_refuse(self):
        self.refuses(current=NATIVE)
        for kind in ('missing','extra','changed','directory'):
            current=self.root/kind;shutil.copytree(CURRENT/RECIPE,current/RECIPE)
            if kind=='missing':(current/RECIPE/'test_comparison.py').unlink()
            elif kind=='extra':(current/RECIPE/'extra').write_text('extra')
            elif kind=='directory':(current/RECIPE/'extra').mkdir()
            else:(current/RECIPE/'cachy-asahi-doctor').write_text('changed')
            self.refuses(current=current)
    def test_each_older_factory_drift_refuses(self):
        for key,source in (('historical',HISTORICAL),('comparison',COMPARISON),('current70',CURRENT70)):
            root=self.root/key;shutil.copytree(source,root);(root/'prepare.py').write_text('changed')
            self.refuses(**{key:root})
    def test_changed_or_extra_native705_refuses(self):
        for kind in ('changed','extra'):
            root=self.root/kind;shutil.copytree(NATIVE,root,ignore=shutil.ignore_patterns('.git'))
            (root/('scripts/ci/welcome-native/run.py' if kind=='changed' else 'extra')).write_text('changed')
            self.refuses(native=root)
    def test_profile_drift_and_actual_claim_refuse(self):
        here=self.root/'profile';here.mkdir();(here/'source.json').write_bytes((F.HERE/'source.json').read_bytes()+b' ')
        with patch.object(F,'HERE',here):self.refuses()
        for name in ('actual_source','actual_ref','actual_run'):
            value=copy.deepcopy(self.value);value[name]='CLAIMED'
            # Whole profile pin is the outer guard; explicitly re-pin only this inert fixture.
            (here/'source.json').write_text(json.dumps(value))
            with patch.object(F,'HERE',here),patch.object(F,'PROFILE',F.pin((here/'source.json').read_bytes())):
                self.refuses()
    def test_bad_generated_missing_extra_or_changed_body_refuses(self):
        for kind in ('missing','extra','changed'):
            value=copy.deepcopy(self.value);generated=value['views']['default']['generated']
            if kind=='missing':generated.pop(SLICE+'installed_comparison.py')
            elif kind=='extra':generated[SLICE+'extra.py']='extra'
            else:generated[SLICE+'installed_comparison.py']+='\n'
            with patch.object(F,'profile',return_value=value):self.refuses()
    def test_output_existing_contained_and_symlink_parent_refuse(self):
        output=self.root/'existing';output.mkdir();(output/'sentinel').write_text('KEEP')
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,CURRENT70,output)
        self.assertEqual((output/'sentinel').read_text(),'KEEP')
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,CURRENT70,alias/'new')
        with self.assertRaises(ValueError):F.fresh(CURRENT/'new',[CURRENT])
        self.assertFalse((CURRENT/'new').exists())
    def test_symlink_hardlink_and_fifo_package_refuse(self):
        for kind in ('symlink','hardlink','fifo'):
            current=self.root/kind;shutil.copytree(CURRENT/RECIPE,current/RECIPE);path=current/RECIPE/'test_comparison.py';path.unlink()
            if kind=='symlink':path.symlink_to(CURRENT/RECIPE/'test_comparison.py')
            elif kind=='fifo':os.mkfifo(path)
            else:
                target=self.root/'original';target.write_bytes((CURRENT/RECIPE/'test_comparison.py').read_bytes());os.link(target,path)
            self.refuses(current=current)
    def test_observed_late_factory_and_package_drift_refuses(self):
        for kind in ('factory','package'):
            current=self.root/(kind+'-current');shutil.copytree(CURRENT/RECIPE,current/RECIPE)
            factory=self.root/(kind+'-factory');shutil.copytree(CURRENT70,factory);original=F.fresh;calls=[]
            def late(output,roots):
                original(output,roots);calls.append(1)
                if len(calls)==2:
                    target=factory/'prepare.py' if kind=='factory' else current/RECIPE/'test_comparison.py'
                    target.write_text("raise AssertionError('late changed code must not execute')\n")
            with patch.object(F,'fresh',side_effect=late):self.refuses(current=current,current70=factory)
    def test_manifest71_current9_helpers6_and_both_precredential_help_entries(self):
        output,_=self.emit(selected=True);raw=F.files(output);manifest=json.loads(raw[SLICE+'ci/source-manifest.json']);pins=json.loads(raw[SLICE+'source-pins.json'])
        self.assertEqual(len(manifest['files']),71);self.assertEqual(len(pins),50)
        self.assertEqual({n:F.pin(b) for n,b in raw.items() if n.startswith(RECIPE+'/')},self.value['current_inputs'])
        self.assertEqual({n:F.pin(b) for n,b in raw.items() if n.startswith('scripts/ci/setup6-retained-helpers/')},self.value['approved_helpers'])
        workflow=raw['.github/workflows/native-arm-build.yml'];self.assertEqual(workflow,raw['.github/workflows/native-arm-welcome-doctor-products.yml'])
        for marker in (b'producer.py" --help',b'installed_comparison.py" --help'):self.assertLess(workflow.index(marker),workflow.index(b'using existing secrets only'))
    def test_hold_all_older_constructors_native_source_and_package(self):
        self.emit()
        for root,raw in self.inputs.items():self.assertEqual(F.files(Path(root)),raw)
        self.assertEqual(F.files(CURRENT/RECIPE),self.package)
    def test_unbound_proof_cannot_publish_source_proof(self):
        output,_=self.emit();caller=load('current74_default_caller',output/(SLICE+'ci/caller.py'));proof=self.root/'proof';github=self.root/'github-output'
        with patch.object(sys,'argv',['caller.py','proof','--workspace',str(output),'--manifest',str(output/(SLICE+'ci/source-manifest.json')),'--proof',str(proof)]),patch.dict(os.environ,GITHUB_OUTPUT=str(github)):
            with self.assertRaises(ValueError):caller.main()
        self.assertFalse(proof.exists());self.assertFalse(github.exists())


class IsolatedEntries(unittest.TestCase):
    def test_both_real_isolated_help_entries_from_foreign_poisoned_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,CURRENT70,source,selected=True)
            foreign=root/'foreign';foreign.mkdir()
            for name in ('contract.py','installed_comparison.py'):(foreign/name).write_text("raise AssertionError('foreign module imported')\n")
            env=dict(os.environ,PYTHONPATH=str(foreign),PYTHONDONTWRITEBYTECODE='1')
            for name in ('producer.py','installed_comparison.py'):
                result=subprocess.run([sys.executable,'-I','-B',str(source/(SLICE+name)),'--help'],cwd=foreign,env=env,capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr);self.assertIn('usage:',result.stdout)
            self.assertFalse((source/'doctor2-retained-inputs.json').exists())


if __name__=='__main__':unittest.main(verbosity=2)
