#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact historical/new source views and refusal controls; no native actors."""
import ast,copy,importlib.util,json,os,re,shutil,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
CURRENT=Path(os.environ.get('DOCTOR2_COMPARISON_CURRENT_SOURCE',str(F.HERE.parents[2])))
NATIVE=Path(os.environ.get('DOCTOR2_NATIVE_SOURCE',str(CURRENT/'.ci-inputs/doctor2-native-source')))
HISTORICAL=Path(os.environ.get('DOCTOR2_HISTORICAL_FACTORY',str(F.HERE.parent/'doctor2-native-source')))
RECIPE='packages/tools/cachy-asahi-doctor2'
SLICE='scripts/ci/welcome-native/'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class Factory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile=F.profile();cls.lock=json.loads((HISTORICAL/'source.json').read_bytes())
        network=patch.object(socket,'socket',side_effect=AssertionError('source network actor forbidden'));network.start();cls.addClassCleanup(network.stop)
        for name in ('Popen','run'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('source actor forbidden'));guard.start();cls.addClassCleanup(guard.stop)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def prepare(self,name='out',**kwargs):
        out=self.root/name;result=F.prepare(CURRENT,NATIVE,HISTORICAL,out,**kwargs);return out,result
    def refuses(self,*,current=CURRENT,native=NATIVE,factory=HISTORICAL,**kwargs):
        out=self.root/'refused'
        with self.assertRaises((ValueError,OSError)):F.prepare(current,native,factory,out,**kwargs)
        self.assertFalse(out.exists())
    def test_new_default_selected_full63_and_nine_current_inputs(self):
        for selected in (False,True):
            out,result=self.prepare(str(selected),selected=selected);view=self.profile['views']['selected' if selected else 'default']
            self.assertEqual({n:F.pin(b) for n,b in F.files(out).items()},view['files'])
            self.assertEqual(len(F.files(out)),63);self.assertEqual(result['version'],'0.2.0-2')
            policy=json.loads((out/(SLICE+'doctor2-policy.json')).read_bytes())
            self.assertTrue(all(policy[n] is None for n in ('actual_source','actual_ref','actual_run')))
            contract=load('new_contract_'+str(selected),out/(SLICE+'contract.py'))
            self.assertEqual(len(contract.recipe(out,contract.DOCTOR)['input_sha256']),9)
            if selected:self.assertEqual(contract.activation(out)['version'],'0.2.0-2')
            else:
                self.assertTrue(all(policy[n] is None for n in ('recipe','version','input_sha256')))
                with self.assertRaises(ValueError):contract.activation(out)
    def test_explicit_historical_both_views_retain_exact_old62(self):
        for selected in (False,True):
            out=self.root/str(selected);result=F.prepare(None,NATIVE,HISTORICAL,out,historical=True,selected=selected)
            self.assertEqual({n:F.pin(b) for n,b in F.files(out).items()},self.lock['selected_files'] if selected else self.lock['default_files'])
            self.assertEqual(result['files'],62);self.assertTrue(result['view'].startswith('historical-'))
    def test_historical_rejects_ambiguous_mutable_current_operand(self):self.refuses(historical=True)
    def test_old_recipe_missing_extra_and_changed_current_inputs_refuse(self):
        self.refuses(current=NATIVE)
        for kind in ('missing','extra','changed','empty-dir'):
            current=self.root/kind;shutil.copytree(CURRENT/RECIPE,current/RECIPE)
            if kind=='missing':(current/RECIPE/'test_comparison.py').unlink()
            elif kind=='extra':(current/RECIPE/'unexpected').write_text('extra')
            elif kind=='empty-dir':(current/RECIPE/'unexpected-directory').mkdir()
            else:(current/RECIPE/'cachy-asahi-doctor').write_text('changed')
            self.refuses(current=current)
    def test_changed_or_extra_full705_predecessor_refuses_before_output(self):
        for kind in ('changed','extra'):
            native=self.root/kind;shutil.copytree(NATIVE,native,ignore=shutil.ignore_patterns('.git'))
            (native/('scripts/ci/welcome-native/run.py' if kind=='changed' else 'extra')).write_text('drift')
            self.refuses(native=native)
    def test_changed_historical_factory_or_profile_refuses(self):
        factory=self.root/'factory';shutil.copytree(HISTORICAL,factory);(factory/'prepare.py').write_text('changed')
        self.refuses(factory=factory)
        profile=self.root/'profile';profile.mkdir();(profile/'source.json').write_bytes((F.HERE/'source.json').read_bytes()+b' ')
        with patch.object(F,'HERE',profile):self.refuses()
    def test_output_existing_contained_or_parent_alias_refuses(self):
        out=self.root/'existing';out.mkdir();(out/'sentinel').write_text('KEEP')
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,out)
        self.assertEqual((out/'sentinel').read_text(),'KEEP')
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,alias/'new')
        with self.assertRaises(ValueError):F.fresh(NATIVE/'new',[NATIVE])
        self.assertFalse((NATIVE/'new').exists())
        with self.assertRaises(ValueError):F.fresh(self.root/'existing/../escaped',[NATIVE])
        self.assertFalse((self.root/'escaped').exists())
    def test_symlink_fifo_and_hardlink_source_refuse_without_waiting(self):
        for kind in ('alias','fifo','hardlink'):
            current=self.root/kind;shutil.copytree(CURRENT/RECIPE,current/RECIPE)
            source=current/RECIPE/'test_comparison.py';source.unlink()
            if kind=='alias':source.symlink_to(CURRENT/RECIPE/'test_comparison.py')
            elif kind=='fifo':os.mkfifo(source)
            else:
                target=self.root/'ordinary';target.write_bytes((CURRENT/RECIPE/'test_comparison.py').read_bytes());os.link(target,source)
            self.refuses(current=current)
    def test_unbound_source_proof_fails_before_proof_or_output_file(self):
        out,_=self.prepare();caller=load('new_default_caller',out/(SLICE+'ci/caller.py'))
        proof=self.root/'proof.json';github_output=self.root/'github-output'
        with patch.object(sys,'argv',['caller.py','proof','--workspace',str(out),'--manifest',str(out/(SLICE+'ci/source-manifest.json')),'--proof',str(proof)]),patch.dict(os.environ,GITHUB_OUTPUT=str(github_output)):
            with self.assertRaises(ValueError):caller.main()
        self.assertFalse(proof.exists());self.assertFalse(github_output.exists())
    def test_selected_rejects_old_version_and_claimed_actual_run(self):
        out,_=self.prepare(selected=True);contract=load('new_selected_contract',out/(SLICE+'contract.py'));path=out/(SLICE+'doctor2-policy.json');original=json.loads(path.read_bytes())
        for key,value in (('version','0.2.0-1'),('actual_run',39321557701)):
            policy=copy.deepcopy(original);policy[key]=value;path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):contract.activation(out)
    def test_manifest_binds_comparison_and_sourcepins43(self):
        out,_=self.prepare(selected=True);manifest=json.loads((out/(SLICE+'ci/source-manifest.json')).read_bytes());pins=json.loads((out/(SLICE+'source-pins.json')).read_bytes())
        self.assertEqual(len(manifest['files']),60);self.assertEqual(len(pins),43)
        name=RECIPE+'/test_comparison.py';self.assertEqual(manifest['files'][name],F.pin((out/name).read_bytes()))
        caller=load('new_selected_caller',out/(SLICE+'ci/caller.py'))
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(caller.prove(out,manifest,env)['source_files'],60) # Modeled environment, not native execution.
        (out/name).write_text('changed')
        with self.assertRaises(ValueError):caller.prove(out,manifest,env)
    def test_actors_security_budgets_and_workflow_structure_unchanged(self):
        before=F.files(NATIVE)
        for selected in (False,True):
            out,_=self.prepare(str(selected),selected=selected);after=F.files(out)
            for name,pin in self.profile['unchanged_actors'].items():self.assertEqual(F.pin(after[name]),pin)
            for name in (SLICE+'run.py',SLICE+'lifecycle.py'):self.assertEqual(before[name],after[name])
            workflow=after['.github/workflows/native-arm-build.yml']
            self.assertEqual(workflow,after['.github/workflows/native-arm-welcome-doctor-products.yml'])
            for name in (SLICE+'ci/caller.py',SLICE+'ci/source-manifest.json'):
                workflow=workflow.replace(F.pin(after[name])['sha256'].encode(),F.pin(before[name])['sha256'].encode())
            self.assertEqual(workflow,before['.github/workflows/native-arm-build.yml'])
            old=ast.parse(before[SLICE+'ci/caller.py']);new=ast.parse(after[SLICE+'ci/caller.py'])
            for name in ('prove','main','regular'):
                self.assertEqual(ast.dump(next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name)),ast.dump(next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name==name)))
    def test_all_original_native_and_caller_controls_remain(self):
        out,_=self.prepare();before=F.files(NATIVE)
        for name in (SLICE+'test_native.py',SLICE+'ci/test_caller.py'):
            tests=lambda raw:{n.name for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')}
            self.assertTrue(tests(before[name])<=tests((out/name).read_bytes()))
    def test_inputs_historical_factory_and_profile_remain_unchanged(self):
        before={str(p):F.pin(F.ordinary(p)) for p in (*HISTORICAL.iterdir(),*(CURRENT/RECIPE).iterdir()) if p.is_file()};native=F.files(NATIVE)
        self.prepare()
        self.assertEqual(native,F.files(NATIVE));self.assertTrue(all(F.pin(F.ordinary(Path(n)))==p for n,p in before.items()))


if __name__=='__main__':unittest.main(verbosity=2)
