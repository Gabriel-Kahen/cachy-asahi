# SPDX-License-Identifier: MIT
"""Passive and explicitly inert callback MODEL controls; no native Qt credit."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location('test_family_'+name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
C,S,N=load('common'),load('source'),load('pipeline')


class Controls(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='qt-family-MODEL-');self.addCleanup(t.cleanup)
        self.root=Path(t.name);self.lock=C.load_lock()

    def test_real_graph_requires_svg_before_declarative(self):
        plan=N.family_plan(self.lock,complete=False)
        self.assertEqual(plan['order'],list(C.ORDER))
        self.assertLess(plan['order'].index('svg'),plan['order'].index('declarative'))
        self.assertIn('qt6-svg=6.12.0',self.lock['components']['declarative']['metadata']['depends'])
        self.assertEqual([r['expected_inventory_count'] for r in plan['stages']],[356,357,358,359,360])
        self.assertIsNone(plan['final_package_count']);self.assertFalse(plan['family_is_one_job'])

    def test_stage_budget_covers_all_bounded_phases(self):
        self.assertLess(2*N.BUILD_SECONDS+N.COMPARE_SECONDS+N.QUALIFY_SECONDS+N.LIFECYCLE_SECONDS+N.CLEANUP_SECONDS,N.STAGE_SECONDS)
        self.assertIsNone(N.POLICY['baseline_authentication_timeout'])
        self.assertEqual(N.POLICY['builder_cpus'],1);self.assertEqual(N.POLICY['qualifier_memory_bytes'],2*1024**3)

    def test_all_frozen_check_marker_projections_have_whole_inverse(self):
        before=b'\n}\n\npackage() {'
        for key,row in self.lock['components'].items():
            raw=(HERE/'fixtures'/('PKGBUILD-'+key+'.DATA')).read_bytes()
            self.assertEqual(C.pin(raw),{k:row['recipe_inputs']['PKGBUILD'][k] for k in ('bytes','sha256')})
            projected=C.project_pkgbuild(raw,key)
            marker=row['marker'].encode();self.assertEqual(projected.count(marker),1)
            after=b"\n  printf '%s\\n' '"+marker+b"'\n}\n\npackage() {"
            self.assertEqual(projected.replace(after,before).replace(
                b'cmake -DCMAKE_AUTOGEN_PARALLEL:STRING=1 -C',b'cmake -C'),raw)
            with self.assertRaises(ValueError):C.project_pkgbuild(projected,key)

    def test_projected_builders_keep_normal_limits_and_unique_clean_ids(self):
        root=HERE.parents[2];raw=(root/'scripts/build/build_v2.py').read_bytes()
        for key,row in self.lock['components'].items():
            body=S.project_builder(raw,key,row['filename']);compile(body,'MODEL-builder','exec')
            for text in (row['filename'],"'--memory-swap', '4g'","'--cpus', '1'",'require_actual_family',key,'family-build-proof.json'):
                self.assertIn(text.encode(),body)
            self.assertNotIn(b'from qt612_actor_gate',body)
            self.assertIn(b'dst=/family,readonly',body)

    def test_entries_keep_actual_helpers_smokes_and_offline_normal_checks(self):
        root=HERE.parents[2];raw=(root/'scripts/build/container-entry-v2.sh').read_bytes()
        for key,row in self.lock['components'].items():
            body=S.project_entry(raw,key,row).decode()
            self.assertIn('pacman -T "${requirements[@]}"',body)
            self.assertIn('makepkg --cleanbuild --force --log --noconfirm',body)
            self.assertIn('python /family/proof.py capture --component '+key,body)
            self.assertIn('family-stage.json',body);self.assertNotIn('--nodeps',body)
            if key=='shadertools':self.assertIn('family-shader-smoke.json',body)
            if key=='declarative':self.assertIn('--contract /inputs/BUILD-CONTRACT.json',body)

    def minimal_source(self):
        root=self.root/'source';w=C.M.Writer(root)
        try:
            row=w.put('MODEL.txt',raw=b'MODEL source bytes')
            mapping=dict(kind='QT612_COMPLETE_FAMILY_SOURCE_DATA_V1',files={'MODEL.txt':row},
                input_plan_complete=False,actual=dict.fromkeys(C.M.ACTUAL),Root_acceptance=None)
            raw=C.encoded(mapping);w.put('source-map.json',raw=raw)
        finally:w.close()
        return root,C.pin(raw)['sha256']

    def test_source_map_current_bytes_and_namespace(self):
        root,sha=self.minimal_source();self.assertFalse(C.read_source(root,sha)['input_plan_complete'])
        (root/'EXTRA').write_bytes(b'EXTRA')
        with self.assertRaises(ValueError):C.read_source(root,sha)

    def test_source_map_rejects_drift_alias_and_mode(self):
        root,sha=self.minimal_source();p=root/'MODEL.txt';raw=p.read_bytes()
        p.write_bytes(b'CHANGED')
        with self.assertRaises(ValueError):C.read_source(root,sha)
        p.write_bytes(raw);p.chmod(0o600)
        with self.assertRaises(ValueError):C.read_source(root,sha)
        p.unlink();p.symlink_to(root/'source-map.json')
        with self.assertRaises(ValueError):C.read_source(root,sha)

    def inventory(self,count=356):
        p=self.root/'inventory.lock';p.write_text(''.join('base%03d 1.0-1\n'%i for i in range(count)));return p

    def test_inventory_requires_exact_count_and_no_official_qt_fallback(self):
        p=self.inventory();self.assertEqual(N.inventory_pin(p,356),C.pin(p.read_bytes()))
        with self.assertRaises(ValueError):N.inventory_pin(p,357)
        p.write_text(p.read_text().replace('base355 1.0-1','qt6-base 6.11.2-1'))
        with self.assertRaises(ValueError):N.inventory_pin(p,356)

    def test_matching_inventory_count_cannot_mask_dependency_drift(self):
        path=self.inventory()
        expected=path.read_bytes()
        path.write_bytes(expected.replace(b'base155 1.0-1',b'base155 1.0-2'))
        with self.assertRaisesRegex(ValueError,'EXACT_STAGE_INVENTORY_CLOSURE'):
            N.inventory_pin(path,356,expected_raw=expected)

    def test_lifecycle_commands_are_bounded_for_every_real_recipe(self):
        lifecycle=load('lifecycle')
        for index,key in enumerate(C.ORDER):
            with self.subTest(component=key):
                base=self.inventory(356+index).read_bytes()
                plan=lifecycle.command_plan(self.lock['components'][key],base,C.pin(b'MODEL receipt'),C.pin(b'MODEL archive'))
                self.assertEqual(plan['steps'][-1]['exact_stdout'],base.decode())
                self.assertLess(sum(step['seconds'] for step in plan['steps']),N.LIFECYCLE_SECONDS)
                for step in plan['steps']:
                    self.assertNotIn('--nodeps',step['argv'])
                    self.assertNotIn('-Sy',step['argv'])

    def test_stage_commands_are_offline_and_serial(self):
        root=self.root/'source';(root/'materials/svg').mkdir(parents=True)
        (root/'materials/svg/plan.json').write_text('{}\n')
        base=self.inventory();(root/'expected356.lock').write_bytes(base.read_bytes())
        mapping={'input_plan_complete':True,'files':{
            'expected356.lock':C.pin(base.read_bytes()),
            'materials/svg/plan.json':C.pin((root/'materials/svg/plan.json').read_bytes()),
            'runtime/svg/scripts/build/container-entry-v2.sh':dict(bytes=1,sha256='1'*64,mode=420)}}
        p=self.inventory(358);p.write_bytes(N.expected_inventory(root,mapping,'svg'))
        with patch.object(N.C,'read_source',return_value=mapping):
            plan=N.stage_commands(source=root,source_map_sha256='0'*64,component='svg',output=self.root/'out',
                image='sha256:'+'2'*64,inventory=p,cache=self.root/'cache',nonce='3'*32)
        self.assertEqual(len(plan['builds']),2)
        for row in plan['builds']:
            self.assertEqual(row['argv'][row['argv'].index('--network')+1],'none')
            self.assertIn('--source-cache',row['argv']);self.assertIn('--reviewed-inputs',row['argv'])
        self.assertFalse(plan['actor_enabled'])

    def model_plan(self):
        inventory=self.inventory()
        return dict(component='gui_server',nonce='1'*32,image='sha256:'+'2'*64,inventory_pin=C.pin(inventory.read_bytes()),
            inventory_path=str(inventory),entry_pin=dict(bytes=1,sha256='4'*64),source_date_epoch=1,
            builds=[dict(attempt=str(i),argv=['MODEL_BUILD',str(i)],env={}) for i in (1,2)],compare=['MODEL_COMPARE'])

    def stage_workspace(self):
        plan = self.model_plan()
        plan['cache'] = str(self.root/'cache')
        return plan, dict(source=self.root/'source', source_map_sha256='0'*64,
                          output=self.root/'out', work=self.root/'work',
                          failure_output=self.root/'failure')

    def test_invalid_workspace_stops_before_any_stage_callback(self):
        plan, paths = self.stage_workspace()
        paths['work'].mkdir()
        paths['failure_output'].mkdir()
        occupied = self.root/'occupied'
        occupied.mkdir()
        (occupied/'build-2').mkdir()
        file_parent = self.root/'file'
        file_parent.touch()
        with patch.object(N, 'require_actual_family') as binding:
            for changes, message in (
                (dict(work=paths['work']), 'FRESH_FAMILY_QUALIFIER_WORK'),
                (dict(failure_output=paths['failure_output']), 'FRESH_FAMILY_FAILURE_OUTPUT'),
                (dict(failure_output=self.root/'missing-parent'/'failure'), 'FRESH_FAMILY_FAILURE_OUTPUT'),
                (dict(work=self.root/'missing-parent'/'scratch'), 'FRESH_FAMILY_QUALIFIER_WORK'),
                (dict(output=file_parent/'attempt'), 'FAMILY_STAGE_OUTPUT_DIRECTORY'),
                (dict(output=occupied), 'FRESH_FAMILY_STAGE_OUTPUTS'),
                (dict(output=paths['source']/'attempt'), 'DISJOINT_FAMILY_STAGE_WRITE_PATHS'),
                (dict(output=Path(plan['cache'])/'attempt'), 'DISJOINT_FAMILY_STAGE_WRITE_PATHS'),
                (dict(work=paths['output']/'qualifier-input'), 'DISJOINT_FAMILY_STAGE_WRITE_PATHS'),
            ):
                with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, message):
                    N.run_stage(plan, object(), **(paths | dict(work=self.root/'new-work',
                                failure_output=self.root/'new-failure') | changes))
            binding.assert_not_called()

    def test_workspace_allows_shared_parent_and_scratch_under_fresh_output(self):
        plan, paths = self.stage_workspace()
        paths['work'] = paths['output']/'scratch'
        with patch.object(N, 'require_actual_family', side_effect=ValueError('MODEL reached binding')) as binding:
            with self.assertRaisesRegex(ValueError, 'MODEL reached binding'):
                N.run_stage(plan, object(), **paths)
            binding.assert_called_once()

    def executor(self,*,fail=False,reaped=True):
        events=[]
        class ModelExecutor:
            API='ROOT_QT612_COMPLETE_FAMILY_OWNED_EXECUTOR_V1'
            def require_domain(self,policy):events.append('domain')
            def require_signed_inventory(self,**kwargs):events.append('readback_authenticated_inputs')
            def require_no_containers(self):events.append('empty')
            def require_absent_twice(self,name):events.append('absent:'+name)
            def run(self,argv,timeout,**kwargs):
                events.append(argv[0])
                if fail:raise ValueError('MODEL primary failure')
                return dict(exit=0,natural=True,reaped=reaped,output_complete=True)
            def qualify(self,**kwargs):
                events.append('qualify')
                request=C.M.decode(Path(kwargs['argv'][-3]).read_bytes())
                frozen=N.C.load_lock()['components'][request['component']]
                expected=request['expected']
                result=dict(status='PASS_QT612_FAMILY_COMPONENT_PAIR_CURRENT_BYTES_ONLY',
                    component=request['component'],source_map_sha256=request['source_map_sha256'],
                    native_acceptance=None,scope='MODEL_NOT_NATIVE',filename=frozen['filename'],recipe_commit=frozen['commit'],
                    **{k:expected[k] for k in ('image','inventory_pin','nonce','entry_pin','source_date_epoch')},
                    provenance_pins={'build-1':C.pin(b'MODEL one'),'build-2':C.pin(b'MODEL two')},
                    observations=[{'archive':C.pin(b'MODEL archive')} for _ in range(2)])
                Path(kwargs['output_json']).write_bytes(C.encoded(result))
                return dict(exit=0,natural=True,reaped=True,output_complete=True,result=result,result_pin=C.pin(C.encoded(result)))
            def lifecycle(self,**kwargs):
                events.append('lifecycle');plan=kwargs['plan']
                result=dict(plan_pin=C.pin(C.encoded(plan)),signature_policy='Required TrustedOnly',
                    archive_pin=plan['archive_pin'],signature_pin=C.pin(b'MODEL signature'),
                    configuration_unchanged=True,host_state_unchanged=True,
                    commands=[dict(role=step['role'],argv=step['argv'],exit=0,natural=True,reaped=True,
                        output_complete=True,stdout=step['exact_stdout'] or '') for step in plan['steps']],
                    scope='MODEL_NOT_AN_ACTUAL_TRANSACTION')
                Path(kwargs['output_json']).write_bytes(C.encoded(result))
                return result
        return ModelExecutor(),events

    def drive(self,executor,**options):
        out=self.root/'out';out.mkdir();(out/'build-1').mkdir();(out/'build-1/build.log').write_bytes(b'MODEL log\n')
        (out/'build-2').mkdir()
        (out/'build-1/provenance.json').write_bytes(b'MODEL one')
        (out/'build-2/provenance.json').write_bytes(b'MODEL two')
        name=self.lock['components']['gui_server']['filename']
        for attempt in ('build-1','build-2'):
            artifacts=out/attempt/'artifacts';artifacts.mkdir()
            (artifacts/name).write_bytes(b'MODEL archive')
        return N._drive_stage(self.model_plan(),executor,source=self.root/'source',source_map_sha256='0'*64,
            output=out,work=self.root/'work',failure_output=self.root/'failure',**options)

    def test_model_stage_orders_absence_before_second_attempt(self):
        executor,events=self.executor();result=self.drive(executor)
        self.assertIsNone(result['Root_acceptance']);self.assertIsNone(result['native_acceptance'])
        builds=[i for i,x in enumerate(events) if x=='MODEL_BUILD']
        self.assertTrue(any(x.startswith('absent:') for x in events[builds[0]+1:builds[1]]))
        self.assertLess(events.index('MODEL_COMPARE'),events.index('qualify'));self.assertLess(events.index('qualify'),events.index('lifecycle'))

    def test_explicit_pair_only_requires_qualifier_and_skips_installation(self):
        executor,events=self.executor();executor.lifecycle=None
        result=self.drive(executor,pair_only=True)
        self.assertEqual(result['status'],N.PAIR_ONLY_STATUS)
        self.assertEqual(result['lifecycle_status'],'NOT_RUN')
        self.assertIsNone(result['lifecycle']);self.assertIsNone(result['native_acceptance'])
        self.assertIn('qualify',events);self.assertNotIn('lifecycle',events)

    def test_failure_export_precedes_caller_cleanup_and_preserves_primary(self):
        executor,events=self.executor(fail=True)
        with self.assertRaises(N.P.ProducerHold) as caught:self.drive(executor)
        hold=caught.exception;self.assertEqual(hold.phase,'BUILD_1');self.assertEqual(hold.primary['exception'],'ValueError')
        self.assertTrue(hold.retention['complete']);self.assertEqual((self.root/'failure/build-1/build.log').read_bytes(),b'MODEL log\n')
        self.assertNotIn('MODEL_COMPARE',events)

    def test_unreaped_attempt_cannot_advance(self):
        executor,events=self.executor(reaped=False)
        with self.assertRaises(N.P.ProducerHold):self.drive(executor)
        self.assertEqual(events.count('MODEL_BUILD'),1);self.assertNotIn('qualify',events)

    def test_unreaped_or_stale_qualifier_cannot_advance(self):
        for change in ('reaped','image'):
            with self.subTest(change=change):
                executor,events=self.executor();actual=executor.qualify
                def stale(**kwargs):
                    worker=actual(**kwargs)
                    if change=='reaped':
                        worker['reaped']=False
                    else:
                        worker['result']['image']='sha256:'+'8'*64
                        worker['result_pin']=C.pin(C.encoded(worker['result']))
                        Path(kwargs['output_json']).write_bytes(C.encoded(worker['result']))
                    return worker
                executor.qualify=stale
                case=self.root/change;case.mkdir()
                original=self.root;self.root=case
                try:
                    with self.assertRaises(N.P.ProducerHold) as error:self.drive(executor)
                finally:
                    self.root=original
                self.assertEqual(error.exception.phase,'QUALIFY')
                self.assertNotIn('lifecycle',events)

    def test_incorrect_rollback_inventory_holds(self):
        executor,events=self.executor();model=executor.lifecycle
        def broken(**kwargs):
            result=model(**kwargs)
            next(r for r in result['commands'] if r['role']=='rolled-back')['stdout']='MODEL changed\n'
            return result
        executor.lifecycle=broken
        with self.assertRaises(N.P.ProducerHold) as error:self.drive(executor)
        self.assertEqual(error.exception.phase,'LIFECYCLE')

    def test_retention_failure_keeps_original_failure(self):
        executor,_=self.executor(fail=True)
        with patch.object(N,'retain_failure',side_effect=OSError('MODEL retention failure')):
            with self.assertRaises(N.P.ProducerHold) as caught:self.drive(executor)
        self.assertEqual(caught.exception.primary['exception'],'ValueError');self.assertFalse(caught.exception.retention['complete'])

    def test_unissued_binding_template_never_claims_authority(self):
        template=N.binding_template();self.assertFalse(template['accepted']);self.assertIsNone(template['issued_by'])
        for name in ('source','ref','run','job','attempt','image','source_map_sha256'):self.assertIsNone(template[name])
        with self.assertRaises((ValueError,TypeError)):
            N.require_actual_family('gui_server',source=str(self.root),source_map_sha256='0'*64)


if __name__=='__main__':unittest.main()
