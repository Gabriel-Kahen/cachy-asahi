#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact historical/new source views and refusal controls; no native actors."""
import ast,copy,importlib.util,json,os,re,shutil,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
CURRENT=Path(os.environ.get('DOCTOR2_CURRENT70_CURRENT_SOURCE',str(F.HERE.parents[2])))
NATIVE=Path(os.environ.get('DOCTOR2_NATIVE_SOURCE',str(CURRENT/'.ci-inputs/doctor2-native-source')))
HISTORICAL=Path(os.environ.get('DOCTOR2_HISTORICAL_FACTORY',str(F.HERE.parent/'doctor2-native-source')))
COMPARISON=Path(os.environ.get('DOCTOR2_COMPARISON_FACTORY',str(F.HERE.parent/'doctor2-comparison-native-source')))
PUBLISHED=Path(os.environ.get('DOCTOR2_CURRENT70_PUBLISHED_SOURCE',str(CURRENT/'.ci-inputs/doctor2-current70-source')))
RECIPE='packages/tools/cachy-asahi-doctor2'
SLICE='scripts/ci/welcome-native/'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class Factory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile=F.profile();cls.lock=json.loads((HISTORICAL/'source.json').read_bytes())
        cls.prior=json.loads((COMPARISON/'source.json').read_bytes());cls.published=F.files(PUBLISHED)
        if {n:F.pin(b) for n,b in cls.published.items()}!=cls.profile['views']['selected']['files']:raise ValueError('whole published70 source differs')
        network=patch.object(socket,'socket',side_effect=AssertionError('source network actor forbidden'));network.start();cls.addClassCleanup(network.stop)
        for name in ('Popen','run'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('source actor forbidden'));guard.start();cls.addClassCleanup(guard.stop)
        guard=patch.object(os,'execv',side_effect=AssertionError('source exec actor forbidden'));guard.start();cls.addClassCleanup(guard.stop)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def prepare(self,name='out',**kwargs):
        out=self.root/name;result=F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,out,**kwargs);return out,result
    def refuses(self,*,current=CURRENT,native=NATIVE,factory=HISTORICAL,**kwargs):
        out=self.root/'refused'
        with self.assertRaises((ValueError,OSError)):F.prepare(current,native,factory,COMPARISON,out,**kwargs)
        self.assertFalse(out.exists())
    def test_new_default_selected_full70_and_nine_current_inputs(self):
        for selected in (False,True):
            out,result=self.prepare(str(selected),selected=selected);view=self.profile['views']['selected' if selected else 'default']
            self.assertEqual({n:F.pin(b) for n,b in F.files(out).items()},view['files'])
            self.assertEqual(len(F.files(out)),70);self.assertEqual(result['version'],'0.2.0-2')
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
            out=self.root/str(selected);result=F.prepare(None,NATIVE,HISTORICAL,COMPARISON,out,historical=True,selected=selected)
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
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,out)
        self.assertEqual((out/'sentinel').read_text(),'KEEP')
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,alias/'new')
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
        for key,value in (('version','0.2.0-1'),('actual_run',40447616068),('actual_source','88997143a593f2de82fb41ae0224a943a1f99930'),('actual_ref','codex/doctor2-retained574-isolated-entry-v2')):
            policy=copy.deepcopy(original);policy[key]=value;path.write_text(json.dumps(policy))
            with self.assertRaises(ValueError):contract.activation(out)
    def test_manifest_binds_comparison_and_sourcepins50(self):
        out,_=self.prepare(selected=True);manifest=json.loads((out/(SLICE+'ci/source-manifest.json')).read_bytes());pins=json.loads((out/(SLICE+'source-pins.json')).read_bytes())
        self.assertEqual(len(manifest['files']),67);self.assertEqual(len(pins),50)
        name=RECIPE+'/test_comparison.py';self.assertEqual(manifest['files'][name],F.pin((out/name).read_bytes()))
        caller=load('new_selected_caller',out/(SLICE+'ci/caller.py'))
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(caller.prove(out,manifest,env)['source_files'],67) # Modeled environment, not native execution.
        (out/name).write_text('changed')
        with self.assertRaises(ValueError):caller.prove(out,manifest,env)
    def test_actors_security_budgets_and_workflow_structure_unchanged(self):
        before=F.files(NATIVE)
        for selected in (False,True):
            out,_=self.prepare(str(selected),selected=selected);after=F.files(out)
            for name,pin in self.profile['unchanged_705'].items():self.assertEqual(F.pin(after[name]),pin)
            for name in (SLICE+'run.py',SLICE+'lifecycle.py'):self.assertEqual(before[name],after[name])
            workflow=after['.github/workflows/native-arm-build.yml']
            self.assertEqual(workflow,after['.github/workflows/native-arm-welcome-doctor-products.yml'])
            text=workflow.decode()
            for marker in ('timeout-minutes: 90','2300s','2100s','120s','retention-days: 3','persist-credentials: false'):
                self.assertIn(marker,text)
            self.assertLess(text.index('producer.py" --help'),text.index('using existing secrets only'))
            self.assertIn('ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',text)
            old=ast.parse(before[SLICE+'ci/caller.py']);new=ast.parse(after[SLICE+'ci/caller.py'])
            for name in ('prove','main','regular'):
                self.assertEqual(ast.dump(next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name)),ast.dump(next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name==name)))
    def test_all_original_native_and_caller_controls_remain(self):
        out,_=self.prepare();before=F.files(NATIVE)
        for name in (SLICE+'test_native.py',SLICE+'ci/test_caller.py'):
            tests=lambda raw:{n.name for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')}
            self.assertTrue(tests(before[name])<=tests((out/name).read_bytes()))
    def test_inputs_historical_factory_and_profile_remain_unchanged(self):
        before={str(p):F.pin(F.ordinary(p)) for p in (*HISTORICAL.iterdir(),*(CURRENT/RECIPE).iterdir(),*COMPARISON.iterdir()) if p.is_file()};native=F.files(NATIVE)
        self.prepare()
        self.assertEqual(native,F.files(NATIVE));self.assertTrue(all(F.pin(F.ordinary(Path(n)))==p for n,p in before.items()))



    def test_selected70_matches_published_whole_route_and_both_inverses(self):
        base=F.files(NATIVE)
        for selected in (False,True):
            out,_=self.prepare(str(selected),selected=selected);raw=F.files(out)
            if selected:self.assertEqual(raw,self.published)
            package={n:b for n,b in raw.items() if n.startswith(RECIPE+'/')};prior=F.comparison(base,package,self.prior,selected)
            for old,want in ((base,self.lock['selected_files']),(prior,self.prior['views']['selected' if selected else 'default']['files'])):
                inverse={n:b for n,b in raw.items() if n in old}
                for n,b in old.items():
                    if inverse.get(n)!=b:inverse[n]=b
                self.assertEqual({n:F.pin(b) for n,b in inverse.items()},want)
            self.assertEqual(len(set(raw)-set(prior)),7);self.assertEqual(len(set(raw)-set(base)),8)
    def test_all_transport_leaves_bound_and_changed_entry_refuses_before_emission(self):
        out,_=self.prepare(selected=True);contract=load('transport_contract',out/(SLICE+'contract.py'))
        for name in [SLICE+'producer.py',*self.profile['approved_helpers']]:
            path=out/name;before=path.read_bytes();path.write_bytes(before+b'\n')
            with self.subTest(name=name),self.assertRaises(ValueError):contract.verify_source(out)
            path.write_bytes(before)
            altered=copy.deepcopy(self.profile);altered['views']['default']['generated'][name]+='\n'
            with patch.object(F,'profile',return_value=altered):self.refuses()
    def test_missing_extra_transport_and_older63_route_refuse(self):
        for kind in ('missing','extra','old63'):
            value=copy.deepcopy(self.profile);generated=value['views']['default']['generated']
            if kind=='missing':generated.pop(SLICE+'producer.py')
            elif kind=='extra':generated[SLICE+'extra.py']='extra'
            else:value['views']['default']['generated']=self.prior['views']['default']['generated']
            with self.subTest(kind=kind),patch.object(F,'profile',return_value=value):self.refuses()
    def test_changed_comparison_factory_refuses_before_output(self):
        factory=self.root/'comparison';shutil.copytree(COMPARISON,factory);(factory/'prepare.py').write_text('changed')
        out=self.root/'out'
        with self.assertRaises(ValueError):F.prepare(CURRENT,NATIVE,HISTORICAL,factory,out)
        self.assertFalse(out.exists())
    def test_observed_late_recipe_drift_refuses_before_output(self):
        current=self.root/'current';shutil.copytree(CURRENT/RECIPE,current/RECIPE);fresh=F.fresh
        def drift(output,roots):fresh(output,roots);(current/RECIPE/'test_comparison.py').write_text('late drift')
        with patch.object(F,'fresh',side_effect=drift):self.refuses(current=current)
    def test_fixed_desktop574_entry_and_preserved_original_contract_bodies(self):
        out,_=self.prepare(selected=True);raw=F.files(out);before=F.files(NATIVE)
        funcs=lambda b:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
        old=funcs(before[SLICE+'contract.py']);new=funcs(raw[SLICE+'contract.py'])
        for name,body in old.items():
            if name not in ('recipe','check_log','activation'):self.assertEqual(body,new[name])
        for name in ('scripts/ci/maintained_desktop574.py','scripts/ci/maintained-desktop574-inputs.json'):self.assertEqual(raw[name],before[name])
        self.assertEqual({n:F.pin(b) for n,b in raw.items() if n.startswith('scripts/ci/setup6-retained-helpers/')},self.profile['approved_helpers'])
        text=raw[SLICE+'producer.py'].decode();self.assertIn("'desktop574'",text);self.assertIn('time.monotonic()+2300',text)
        self.assertLess(text.index('C.verify_source(root)'),text.index('helper=load_helper(root)'))

    def test_internally_resealed_default_entry_still_refuses_selected_authority(self):
        value=copy.deepcopy(self.profile);name=SLICE+'producer.py'
        text=value['views']['default']['generated'][name]+'\n'
        value['views']['default']['generated'][name]=text
        value['views']['default']['files'][name]=F.pin(text.encode())
        out=self.root/'out'
        with patch.object(F,'profile',return_value=value),self.assertRaisesRegex(ValueError,'default may change only'):
            F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,out)
        self.assertFalse(out.exists())

    def test_historical_late_factory_or_native_drift_refuses_before_output(self):
        for kind in ('factory','native'):
            source=self.root/(kind+'-native');shutil.copytree(NATIVE,source,ignore=shutil.ignore_patterns('.git'))
            factory=self.root/(kind+'-factory');shutil.copytree(HISTORICAL,factory);out=self.root/(kind+'-out');fresh=F.fresh
            def drift(output,roots):
                fresh(output,roots)
                path=factory/'prepare.py' if kind=='factory' else source/(SLICE+'run.py')
                path.write_text("raise AssertionError('late changed code must not execute')\n")
            with self.subTest(kind=kind),patch.object(F,'fresh',side_effect=drift),self.assertRaises(ValueError):
                F.prepare(None,source,factory,COMPARISON,out,historical=True)
            self.assertFalse(out.exists())

class IsolatedEntry(unittest.TestCase):
    def test_real_isolated_help_foreign_cwd_and_missing_bootstrap_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'source';F.prepare(CURRENT,NATIVE,HISTORICAL,COMPARISON,out,selected=True)
            foreign=root/'foreign';foreign.mkdir();(foreign/'contract.py').write_text("raise AssertionError('foreign contract imported')\n")
            env=dict(os.environ,PYTHONPATH=str(foreign),PYTHONDONTWRITEBYTECODE='1')
            command=[sys.executable,'-I','-B',str(out/(SLICE+'producer.py')),'--help']
            result=subprocess.run(command,cwd=foreign,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertIn('--carrier',result.stdout);self.assertIn('--source',result.stdout)
            self.assertFalse((out/'doctor2-retained-inputs.json').exists())
            path=out/(SLICE+'producer.py');path.write_text(path.read_text().replace('sys.path.insert(0,str(Path(__file__).resolve().parent))','pass # deliberately broken bootstrap'))
            result=subprocess.run(command,cwd=foreign,env=env,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertIn("No module named 'contract'",result.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
