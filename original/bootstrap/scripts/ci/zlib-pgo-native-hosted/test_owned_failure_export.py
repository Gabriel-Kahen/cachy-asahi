# SPDX-License-Identifier: MIT
"""Source-only partial export and candidate-state controls; no native actors."""
import importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;PACKET=HERE.parents[2].parent

def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
O=module('_failure_owner','owner.py');R=module('_failure_retention','retention.py');D=module('_failure_driver','execute_builder.py')

def save(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True)+'\n')
def lifecycle(row,code=0):row.update(exit=code,natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,ownership_lost=False,forced_cleanup=False,retirement='REAPED')

class FailureExportControls(unittest.TestCase):
    def setUp(self):
        tmp=PACKET/'evidence/tmp';tmp.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='MODEL_ONLY-failure-export-',dir=tmp);self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.work=self.base/'work';self.work.mkdir()
        self.own=dict(source_sha='a'*40,run_id='123',attempt=1);self.manifest='b'*64
        for name in('Popen','run','check_output'):self.enterContext(patch.object(subprocess,name,side_effect=AssertionError('real process forbidden')))
        for name in('killpg','kill','waitpid','waitid'):self.enterContext(patch.object(os,name,side_effect=AssertionError('numeric actor operation forbidden')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))

    def pair_report(self):
        save(self.work/'pairs-owner.json',dict(status='FAIL',identity=self.own,manifest_sha256=self.manifest,candidate_states=[dict(attempt=1,state='FAILED_OR_INTERRUPTED',stage='BUILDER_EXECUTION',error_type='ValueError'),dict(attempt=2,state='NOT_REACHED',stage=None)]))

    def fixture(self):
        root=self.base/'source';root.mkdir();(root/'source.py').write_bytes(b'MODEL_ONLY source')
        (root/'map.json').write_bytes(b'{"actual":null}')
        (root/'workflow.yml').write_bytes(b'MODEL_ONLY workflow')
        recipe=root/'pgo-source'/R.RECIPE;recipe.mkdir(parents=True);(recipe/'source.py').write_bytes(b'MODEL_ONLY recipe')
        proof=self.base/'proof.json';proof.write_bytes(b'{"status":"MODEL_ONLY"}')
        self.pair_report();save(self.work/'build-intent-1.json',dict(identity=self.own))
        save(self.work/'producer-binding-1.json',dict(status='MODEL_ONLY'))
        attempt=self.work/'attempt-1';output=attempt/'native-build';inner=output/'artifacts/pgo-v1-evidence'
        save(attempt/'source-plan.json',dict(status='MODEL_ONLY'))
        save(output/'provenance.json',dict(status='failed',mode='native',error='MODEL_ONLY failed consumer'))
        (output/'build.log').write_bytes(b'MODEL_ONLY firstcandidate diagnostics\n')
        (output/'inputs').mkdir();(output/'inputs/source.py').write_bytes(b'MODEL_ONLY recipe')
        save(inner/'result.json',dict(status='FAIL',source_sha256=R.SOURCE_SHA,error_type='ValueError',error='MODEL_ONLY tool identity refusal'))
        save(inner/'receipt.json',dict(status='FAIL'))
        save(inner/'commands/commands.json',[])
        save(inner/'tool-identity-observations.json',dict(role='MODEL_ONLY_DIAGNOSTIC_DATA'))
        save(inner/'tool-identity-error.json',dict(role='MODEL_ONLY_DIAGNOSTIC_DATA',error='MODEL_ONLY'))
        args=SimpleNamespace(work=self.work,public=self.base/'public',proof=proof,manifest_sha256=self.manifest)
        owner=SimpleNamespace(ROOT=root,MAP='map.json',ALIASES=('workflow.yml',),binding=lambda *a,**k:({'files':{'source.py':{}}},self.own),fresh=O.fresh,save=O.save)
        return args,owner,inner

    def test_missing_second_binding_does_not_stop_first_failure_and_source_export(self):
        args,owner,inner=self.fixture()
        def qualifier(*a,**k):
            self.assertTrue((args.public/'attempt-1/native-build/artifacts/pgo-v1-evidence/result.json').is_file())
            raise FileNotFoundError('producer-binding-2.json')
        with patch.object(R,'qualify',side_effect=qualifier)as full:self.assertEqual(R.retain(args,owner),1)
        full.assert_called_once();receipt=R.j(args.public/'receipt.json')
        for name in('source/source.py','attempt-1/native-build/build.log','attempt-1/native-build/inputs/source.py','attempt-1/native-build/artifacts/pgo-v1-evidence/result.json','attempt-1/native-build/artifacts/pgo-v1-evidence/tool-identity-observations.json','attempt-1/native-build/artifacts/pgo-v1-evidence/tool-identity-error.json'):self.assertIn(name,receipt['files'])
        self.assertEqual([r['state']for r in receipt['candidate_diagnostics']['candidates']],['FAILED','NOT_REACHED'])
        self.assertEqual(receipt['candidate_diagnostics'],R.candidate_diagnostics(self.work,self.own,self.manifest))
        self.assertEqual(receipt['status'],'PARTIAL_OR_FAILED_PGO_HOSTED_DATA');self.assertEqual(receipt['cleanup_credit'],'NONE');self.assertFalse(receipt['acceptance']);self.assertNotIn('actual',receipt)
        self.assertFalse((self.work/'producer-binding-2.json').exists());self.assertFalse((self.work/'attempt-2').exists())

    def test_unpermitted_or_alias_leaf_cannot_hide_permitted_failure_data_or_promote(self):
        args,owner,inner=self.fixture();(inner/'NOT_PERMITTED').write_bytes(b'unknown DATA')
        (inner/'commands/0000-tool-target.log').symlink_to(self.base/'absent')
        with patch.object(R,'qualify',side_effect=AssertionError('partial export cannot qualify'))as full:self.assertEqual(R.retain(args,owner),1)
        full.assert_not_called();receipt=R.j(args.public/'receipt.json')
        self.assertTrue(receipt['export_errors']);self.assertIn('attempt-1/native-build/artifacts/pgo-v1-evidence/result.json',receipt['files'])
        self.assertTrue((args.public/'source/source.py').is_file());self.assertFalse((args.public/'attempt-1/native-build/artifacts/pgo-v1-evidence/NOT_PERMITTED').exists())
        self.assertEqual(receipt['status'],'PARTIAL_OR_FAILED_PGO_HOSTED_DATA');self.assertFalse(receipt['acceptance']);self.assertNotIn('actual',receipt)

    def test_binding2_absence_alone_never_claims_second_not_reached(self):
        rows=R.candidate_diagnostics(self.work,self.own,self.manifest)['candidates']
        self.assertEqual(rows[1]['state'],'NO_RETAINED_EVIDENCE')
        self.pair_report();rows=R.candidate_diagnostics(self.work,self.own,self.manifest)['candidates'];self.assertEqual(rows[1]['state'],'NOT_REACHED')
        save(self.work/'build-intent-2.json',dict(identity=self.own))
        rows=R.candidate_diagnostics(self.work,self.own,self.manifest)['candidates'];self.assertNotEqual(rows[1]['state'],'NOT_REACHED');self.assertTrue(rows[1]['errors'])
        (self.work/'build-intent-2.json').unlink();(self.work/'attempt-2').symlink_to(self.base/'absent')
        self.assertNotEqual(R.candidate_diagnostics(self.work,self.own,self.manifest)['candidates'][1]['state'],'NOT_REACHED')

    def test_malformed_inner_result_stays_data_and_does_not_gain_failed_pipeline_claim(self):
        args,owner,inner=self.fixture();(inner/'result.json').write_bytes(b'not JSON')
        with patch.object(R,'qualify',side_effect=FileNotFoundError('producer-binding-2.json')):self.assertEqual(R.retain(args,owner),1)
        row=R.j(args.public/'receipt.json')['candidate_diagnostics']['candidates'][0]
        self.assertEqual(row['state'],'FAILED');self.assertTrue(row['errors']);self.assertEqual(row['failure']['basis'],'NATIVE_BUILDER_PROVENANCE')
        self.assertEqual((args.public/'attempt-1/native-build/artifacts/pgo-v1-evidence/result.json').read_bytes(),b'not JSON')

    def test_owner_records_first_actual_exception_and_second_not_reached(self):
        args=SimpleNamespace(work=self.work,manifest_sha256=self.manifest,source_sha='a'*40)
        (self.work/'bootstrap').mkdir();(self.work/'bootstrap/packages.lock').write_bytes(b'MODEL_ONLY lock')
        class Actor:
            def __init__(self,*a):pass
            def run(self,*a,**k):raise ValueError('MODEL_ONLY first builder failure')
        with patch.object(O,'admitted',return_value=({},self.own)),patch.object(O,'Actors',Actor),patch.object(O,'producer_binding',return_value=dict(image='sha256:'+'c'*64)),self.assertRaises(ValueError):O.pairs(args)
        report=O.load(self.work/'pairs-owner.json');self.assertEqual([r['state']for r in report['candidate_states']],['FAILED_OR_INTERRUPTED','NOT_REACHED'])
        self.assertEqual(report['candidate_states'][0]['stage'],'BUILDER_EXECUTION');self.assertTrue((self.work/'build-intent-1.json').is_file());self.assertFalse((self.work/'build-intent-2.json').exists())

    def test_driver_retains_direct_nonzero_execution_outcome_and_cache_invariant(self):
        prep=self.work/'attempt-1';lock=self.base/'lock';lock.write_bytes((HERE/'expected-packages.lock').read_bytes())
        image='sha256:'+'c'*64;binding=self.base/'producer.json';save(binding,dict(schema=1,status='PASS_FRESH_OWNED_RUNTIME_IMAGE_AND_FULL341_LOCK',identity=self.own,image=image,package_count=341,packages=O.pin(lock.read_bytes())))
        args=SimpleNamespace(feature_root=self.base/'feature',preparation=prep,observation=self.work/'observation.json',lock=lock,producer_binding=binding,image=image,source_sha='a'*40)
        holder={};calls=[]
        def owned(argv,**kw):
            calls.append(argv)
            if 'inspect'in argv:
                lifecycle(kw['lifecycle']);return subprocess.CompletedProcess(argv,0,stdout=json.dumps([dict(State=dict(Running=True))]))
            kw['on_tick']();lifecycle(kw['lifecycle'],1);return subprocess.CompletedProcess(argv,1)
        def prepare(*a,**kw):
            (prep/'seed-cache').mkdir(parents=True);(prep/'seed-cache/object').write_bytes(b'MODEL_ONLY')
            return dict(command=['python','-B','build_v2.py','recipe','--image',image])
        def builder_main():return subprocess.run(['docker','run','--rm','--name','cachy-asahi-'+'a'*16,image],timeout=1).returncode
        def parser(path):return dict(status='MODEL_ONLY')
        def spec(name,path):
            values=dict(main=builder_main,package=parser)if name=='selected_actual_build_v2'else dict(prepare=prepare)
            def load(value):
                value.__dict__.update(values)
                if name=='selected_actual_build_v2':holder['builder']=value
            return SimpleNamespace(loader=SimpleNamespace(exec_module=load))
        prior=subprocess.run
        with patch.object(D,'_OWNED',SimpleNamespace(run=owned)),patch.object(D.importlib.util,'spec_from_file_location',side_effect=spec),patch.object(D.importlib.util,'module_from_spec',side_effect=lambda s:SimpleNamespace()),patch.object(D,'check_inspection'),self.assertRaises(ValueError):D.run_builder(args)
        row=O.load(args.observation);self.assertEqual(row['consumer_child']['exit'],1);self.assertEqual(row['driver_execution']['status'],'FAILED_OR_INTERRUPTED');self.assertIsNone(row['driver_execution']['builder_returned_exit'])
        self.assertTrue(row['driver_execution']['source_cache_unchanged']);self.assertEqual(row['status'],'PARTIAL_MOUNTS_OBSERVED_CHILD_NOT_ADMITTED')
        self.assertEqual(O.load(prep/'source-cache-before.json'),O.load(prep/'source-cache-after.json'));self.assertIs(subprocess.run,prior);self.assertIs(holder['builder'].package,parser)
        self.assertEqual(len(calls),2)

if __name__=='__main__':unittest.main()
