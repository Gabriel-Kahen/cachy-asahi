# SPDX-License-Identifier: MIT
"""Small inert MODEL bytes exercise construction/readback, never native acceptance."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('binding_tests',HERE/'transport_binding.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
M = B.M


class BindingControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-binding-MODEL-')
        self.addCleanup(temporary.cleanup); self.root = Path(temporary.name)
        self.T = B.transport(); self.b = self.T.basis()
        self.b['recipe_inputs'] = {'PKGBUILD':M.pin(b'MODEL inert recipe')['sha256']}
        self.addCleanup(patch.stopall); patch.object(self.T,'basis',return_value=self.b).start()
        self.first,self.second = self.root/'build-1',self.root/'build-2'
        self.package = 'artifacts/'+self.b['filename']
        self.log = 'artifacts/'+self.b['filename'].removesuffix('.pkg.tar.xz')+'-check.log'
        for attempt,root in (('build-1',self.first),('build-2',self.second)):
            self.write(root,self.package,b'MODEL inert archive: not an installable package')
            self.write(root,'inputs/PKGBUILD',b'MODEL inert recipe')
            stage = dict(status='PASS_QT612_DESTDIR_CONTRACT_ONLY',architecture='aarch64',
                evidence_scope='STAGED_AARCH64_ELF_ONLY',files={},symlinks={},directories={},elf={},
                payload_bytes=1,native_execution='NOT_ESTABLISHED',installation='NOT_RUN',hardware='NOT_RUN')
            self.write(root,'artifacts/qt612-stage-contract.json',M.encoded(stage))
            archive_sha = M.pin((root/self.package).read_bytes())['sha256']
            self.write(root,'validation.json',M.encoded(dict(errors=[],artifacts=[dict(sha256=archive_sha,errors=[])])))
            external = ['build.log','expected-packages.lock','artifacts/packages.lock','artifacts/generated.SRCINFO',
                'artifacts/environment.txt','artifacts/config.sha256','artifacts/makepkg.conf','artifacts/pacman.conf',self.log]
            for name in external: self.write(root,name,('MODEL inert '+name+'\n').encode())
            names = external+['validation.json','artifacts/qt612-stage-contract.json',self.package]
            p = dict(fixture_scope='MODEL_ONLY_NOT_NATIVE_ACCEPTANCE',status='built-package-static-pass',mode='native',
                network='none',exit_code=0,builder_host_arch='aarch64',recipe_inputs=copy.deepcopy(self.b['recipe_inputs']),
                artifacts={self.b['filename']:archive_sha},files={n:M.pin((root/n).read_bytes())['sha256'] for n in names},
                clean_environment_id='MODEL-'+attempt,image='sha256:'+'1'*64,image_id='sha256:'+'1'*64,
                source_date_epoch=1,expected_packages_sha256='2'*64,entry_script_sha256='3'*64,
                recipe_metadata=self.b['recipe_metadata'],source_material={'scope':'MODEL_ONLY'},extra_field='PRESERVED')
            self.write(root,'provenance.json',M.encoded(p))
        self.comparison = self.root/'comparison.json'
        self.comparison.write_bytes(M.encoded(dict(status='contents-reproduced',errors=[],hardware_status='NOT RUN',
            independence_limit='Distinct recorded container runs; independent machine execution is not attested.',
            packages={self.b['filename']:dict.fromkeys(('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'),True)})))
        self.producer = dict(source_commit='0'*40,**dict.fromkeys(('source_map_sha256','program_sha256','finisher_sha256','contract_sha256'),'4'*64))
        self.run = dict(repository='Gabriel-Kahen/cachy-asahi',head_sha='0'*40,run_id='1',run_attempt='1',job_id='1')

    def write(self,root,name,raw):
        p = root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(raw); p.chmod(0o644)

    def export(self):
        return B._export_qualified(first=self.first,second=self.second,comparison=self.comparison,
            producer=self.producer,run=self.run,store_id='MODEL-only-store',retention=self.root/'retention',
            staging=self.root/'staging',output=self.root/'public',T=self.T)

    def test_model_export_and_independent_retention_readback(self):
        result = self.export()
        self.assertEqual(result['status'],'PASS_TRANSPORT_BYTES_ONLY')
        self.assertIsNone(result['Root_acceptance'])
        self.assertEqual(len(list((self.root/'public').rglob('*')))-len([p for p in (self.root/'public').rglob('*') if p.is_dir()]),16)
        self.assertEqual((self.first/'provenance.json').read_bytes(),(self.root/'public/build-1/provenance.json').read_bytes())
        self.assertGreater(B.verify_retention(self.root/'retention',result['retention_receipt'])['objects'],0)

    def test_missing_excluded_operand_refused(self):
        (self.first/'artifacts/environment.txt').unlink()
        with self.assertRaises(OSError): self.export()

    def test_changed_original_operand_refused(self):
        (self.first/'artifacts/environment.txt').write_bytes(b'CHANGED')
        with self.assertRaisesRegex(ValueError,'CURRENT_WHOLE'): self.export()

    def test_symlink_excluded_operand_refused(self):
        path = self.first/'artifacts/environment.txt'; raw = path.read_bytes(); path.unlink()
        other = self.root/'other'; other.write_bytes(raw); path.symlink_to(other)
        with self.assertRaises(ValueError): self.export()

    def test_external_mutation_refused_on_readback(self):
        result = self.export(); obj = next((self.root/'retention/objects').iterdir()); obj.write_bytes(b'CHANGED')
        with self.assertRaises(ValueError): B.verify_retention(self.root/'retention',result['retention_receipt'])

    def test_extra_store_member_refused(self):
        result = self.export(); (self.root/'retention/extra').write_bytes(b'EXTRA')
        with self.assertRaises(ValueError): B.verify_retention(self.root/'retention',result['retention_receipt'])

    def test_omitted_partition_refused(self):
        result = self.export(); receipt = M.decode((self.root/'retention/receipt.json').read_bytes())
        part = receipt['provenance_operands']; del part['build-1']['build.log']
        with self.assertRaises(ValueError): B.verify_retention(self.root/'retention',result['retention_receipt'],part)

    def test_public_api_requires_real_qualifier(self):
        with self.assertRaises((ValueError,KeyError)):
            B.export_pair(first=self.first,second=self.second,comparison=self.comparison,expected=dict(recipe_inputs=self.b['recipe_inputs']),
                producer=self.producer,run=self.run,store_id='MODEL',retention=self.root/'retention',staging=self.root/'staging',output=self.root/'public')
        self.assertFalse((self.root/'public').exists())

    def test_finisher_projection_preserves_archive_validation(self):
        raw = (HERE/'finish_pair.py').read_bytes(); projected = B.project_finisher(raw)
        self.assertIn(b'ALL173_ACTUAL_ARCHIVE_LICENSE_BYTES',projected)
        self.assertIn(b'CURRENT_ARCHIVE_VALIDATION_BINDING',projected)
        with self.assertRaises(ValueError): B.project_finisher(projected)

    def test_executed_finisher_pin_must_match(self):
        raw = B.project_finisher((HERE/'finish_pair.py').read_bytes())
        self.assertTrue(callable(B.finisher(M.pin(raw)['sha256'])))
        with self.assertRaisesRegex(ValueError,'EXECUTED_FINISHER_EXTERNAL_PIN'): B.finisher('0'*64)

    def test_executing_adapter_must_match_selected_source(self):
        source = self.root/'selected-source'
        for name,raw in (('source-map.json',b'MODEL source map'),('producer/transport_binding.py',b'MODEL other adapter'),
                         ('producer/finish_pair.py',b'MODEL finisher'),('transport-binding.DATA.json',b'MODEL contract')):
            self.write(source,name,raw)
        producer = dict(self.producer,source_map_sha256=M.pin(b'MODEL source map')['sha256'],
            program_sha256=M.pin(b'MODEL other adapter')['sha256'],finisher_sha256=M.pin(b'MODEL finisher')['sha256'],
            contract_sha256=M.pin(b'MODEL contract')['sha256'])
        with patch.object(B.P,'verify_producer_source',return_value=True):
            with self.assertRaises(ValueError): B.selected_producer(source,producer,self.run)

    def test_postcollect_hold_invalidates_own_completion_marker(self):
        collect = self.T.collect
        def mutate_after(*args):
            result = collect(*args)
            (self.first/'provenance.json').write_bytes(b'MODEL replaced after copy')
            return result
        with patch.object(self.T,'collect',side_effect=mutate_after):
            with self.assertRaises(ValueError): self.export()
        self.assertFalse((self.root/'public/transport-manifest.json').exists())

    def test_qualified_snapshot_change_cannot_be_exported(self):
        def qualifier(first,second,comparison,*,expected,io_module):
            io_module.stream(first/'build.log',None,{},collect=True)
            (first/'build.log').write_bytes(b'MODEL replaced after qualification')
            return dict(status='QT612_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',Root_acceptance=None)
        with patch.object(B,'finisher',return_value=qualifier), patch.object(B,'selected_producer',return_value={}):
            with self.assertRaisesRegex(ValueError,'OPERAND_CHANGED_AFTER_READ'):
                B.export_pair(first=self.first,second=self.second,comparison=self.comparison,
                    expected=dict(recipe_inputs=B.transport().basis()['recipe_inputs']),producer=self.producer,run=self.run,
                    store_id='MODEL',retention=self.root/'retention',staging=self.root/'staging',output=self.root/'public')
        self.assertFalse((self.root/'public').exists())

    def test_failure_export_whole_and_allowlisted(self):
        self.write(self.root,'private-unselected',b'DO NOT EXPORT')
        primary = B.P.failure_capsule(ValueError('MODEL primary'))
        receipt = B.retain_public_failure_evidence(output_root=self.root,destination=self.root/'failure',phase='BUILD_1',primary=primary)
        self.assertTrue(receipt['complete']); self.assertTrue(receipt['status'].startswith('HOLD'))
        self.assertEqual((self.root/'failure/build-1/build.log').read_bytes(),(self.first/'build.log').read_bytes())
        self.assertFalse((self.root/'failure/private-unselected').exists())

    def test_failure_limit_refuses_without_completion_marker(self):
        primary = B.P.failure_capsule(ValueError('MODEL primary'))
        with patch.object(B,'whole',side_effect=ValueError('MODEL whole-byte cap')):
            with self.assertRaises(ValueError):
                B.retain_public_failure_evidence(output_root=self.root,destination=self.root/'failure',phase='BUILD_1',primary=primary)
        self.assertFalse((self.root/'failure/failure-receipt.json').exists())


if __name__ == '__main__': unittest.main()
