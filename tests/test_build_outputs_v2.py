#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic retained v2 output controls; no build, acquisition or installation."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/build/build_v2.py').is_file())
SCRIPT = Path(__file__).resolve().parents[1]/'scripts/maintenance/build_outputs_v2.py'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

m = load('test_output_v2_subject', SCRIPT)
legacy = load('test_output_v2_fixtures', ROOT/'scripts/maintenance/test_build_outputs.py')
legacy.m = m


class Fixture(legacy.Fixture):
    def __init__(self, root):
        super().__init__(root)
        self.body = b'SYNTHETIC opaque remote source; never executed or extracted\n'
        self.notice = b'SYNTHETIC notice; no legal approval\n'
        self.url = 'https://example.invalid/source.tar.gz'
        self.remote = 'upstream.tar.gz::'+self.url
        self.cache = root/'original-cache'
        m.BATCH.SM.cache.initialize(self.cache)
        obj = self.cache/'objects'/m.sha(self.body)
        obj.write_bytes(self.body); obj.chmod(0o600)
        for bid,b in self.batches.items():
            output=b['output']; recipe=output/'inputs'
            text=(recipe/'PKGBUILD').read_text().replace("source=('payload')", "source=('"+self.remote+"')")
            text=text.replace(m.digest(recipe/'payload'),m.sha(self.body))
            (recipe/'PKGBUILD').write_text(text)
            (recipe/'.SRCINFO').write_text((recipe/'.SRCINFO').read_text().replace('source = payload','source = '+self.remote).replace(m.digest(recipe/'payload'),m.sha(self.body)))
            report=m.BUILD.recipe(recipe/'PKGBUILD')
            assert not report['errors'], report['errors']
            b['record'].update(recipe_inputs=report['input_sha256'], recipe_metadata=report['metadata'])
            (output/'artifacts/generated.SRCINFO').write_text(''.join(f'{k} = {v}\n' for k,vs in report['metadata'].items() for v in vs))
            filename=next(iter(b['record']['artifacts']))
            self.archive(output/'artifacts'/filename,report['input_sha256']['PKGBUILD'])
            task=b['admission']['tasks']['alpha']
            task.update(recipe_inputs=report['input_sha256'], reviewed_inputs_sha256=m.sha(m.encoded(report['input_sha256'])))
            (output.parent/'reviewed_inputs.reviewed').write_bytes(m.encoded(report['input_sha256']))
            b['record']['entry_script_sha256']=m.digest(ROOT/'scripts/build/container-entry-v2.sh')
            b['admission']['builder_interface']=m.INTERFACE
            b['admission']['implementation']={str(ROOT/'scripts/build/container-entry-v2.sh'):b['record']['entry_script_sha256']}
            b['state']['kind']=m.KIND
            self.material(bid)
        self.source['sources'][0].update(recipe_sha256=report['input_sha256']['PKGBUILD'],sources=[dict(url=self.url,sha256=m.sha(self.body))])

    def material(self,bid,revision='SYNTHETIC-reviewed-revision'):
        b=self.batches[bid]; output=b['output']; task=b['admission']['tasks']['alpha']
        row=dict(material=dict(id='upstream-1',path='sources/source.tar.gz',bytes=len(self.body),sha256=m.sha(self.body)),
            url=self.url,revision=revision,license='MIT; unreviewed',
            license_evidence=[dict(id='notice',path='NOTICE',bytes=len(self.notice),sha256=m.sha(self.notice))])
        catalog=m.encoded(dict(schema_version=1,purpose='source-cache-inputs',sources=[row]))
        plan=dict(schema_version=1,purpose='offline-build-sources',recipe_inputs=task['recipe_inputs'],
            catalog_sha256=m.sha(catalog),sources=[dict(source=self.remote,id='upstream-1',revision=revision)])
        prepared=dict(plan=plan,plan_raw=m.encoded(plan),catalog_raw=catalog,cache_path=self.cache,
            selected=[dict(filename='upstream.tar.gz',source=self.remote,record=row)],notices={m.sha(self.notice):self.notice})
        target=output/'source-material'
        if target.exists():
            for item in target.rglob('*'):
                if item.is_file(): item.chmod(0o600)
            shutil.rmtree(target)
        receipt=dict(schema_version=1,purpose='source-cache-receipt',inputs_sha256=m.sha(catalog),source=row,
            object_path='objects/'+row['material']['sha256'],legal_acceptance=False,source_completeness_accepted=False)
        receipt_path=self.cache/'receipts'/(m.sha(catalog)+'-upstream-1.json')
        receipt_path.write_bytes(m.encoded(receipt));receipt_path.chmod(0o600)
        output.chmod(0o700)
        selection=m.BATCH.SM.stage(prepared,target)
        task.update(offline_sources=dict(source_plan=str(self.root/'gone-plan.json'),source_plan_sha256=m.sha(prepared['plan_raw']),
            source_catalog=str(self.root/'gone-catalog.json'),source_cache=str(self.cache),catalog_sha256=m.sha(catalog)),
            source_material=selection,source_material_files=m.BATCH.material_files(prepared))
        b['record']['source_material']=selection
        b['record']['files'].update({'source-material/'+name:checksum for name,checksum in task['source_material_files'].items()})
        self.refresh_record(bid)

    def candidate(self):
        self.write()
        return m.candidate(self.spec_path,m.digest(self.spec_path))


class OutputV2Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='outputs-v2-'); self.addCleanup(temp.cleanup)
        self.root=Path(temp.name); self.f=Fixture(self.root)

    def reject(self, pattern):
        with self.assertRaisesRegex(ValueError,pattern): self.f.candidate()

    def test_complete_retained_selection_without_original_cache(self):
        shutil.rmtree(self.f.cache)
        with patch.object(m.BATCH.SM.cache,'transport',side_effect=AssertionError('network forbidden')):
            result=self.f.candidate()
        self.assertEqual(result,self.f.candidate())
        package=result['packages'][0]
        self.assertEqual(package['source_material'],self.f.batches['first']['record']['source_material'])
        self.assertTrue(all(b['source_material']==package['source_material'] for b in package['rebuilds']))
        self.assertEqual(result['builder_interface'],'offline-build-v2')
        self.assertEqual(result['source_delivery'],'NOT_CHECKED')
        self.assertEqual(result['licensing_approval'],'NOT_ESTABLISHED')
        self.assertFalse(package['source_material']['legal_acceptance'])
        self.assertFalse(package['source_material']['source_completeness_accepted'])
        for name in (*m.TOOLS,'scripts/maintenance/build_batch_v2.py','scripts/maintenance/build_outputs_v2.py'):
            self.assertIn(name,result['implementation'])

    def test_legacy_kind_refused(self):
        self.f.batches['second']['state']['kind']='PINNED_OCI_BUILD_PY'
        self.reject('offline-build-v2 batch evidence')

    def test_explicit_admission_refused_when_missing(self):
        del self.f.batches['first']['admission']['builder_interface']
        self.reject('explicit offline-build-v2 admission')

    def test_legacy_entry_refused(self):
        b=self.f.batches['second']
        b['admission']['implementation']={str(ROOT/'scripts/build/container-entry.sh'):b['record']['entry_script_sha256']}
        self.reject('container entry identity')

    def test_source_tamper_refused_after_generic_evidence_resealed(self):
        b=self.f.batches['second']; path=b['output']/'source-material/srcdest/upstream.tar.gz'
        path.chmod(0o600);path.write_bytes(b'altered source bytes')
        self.f.refresh_record('second')
        self.reject('source-material tree differs')

    def test_notice_tamper_refused_after_generic_evidence_resealed(self):
        b=self.f.batches['second'];path=next((b['output']/'source-material/notices').iterdir())
        path.chmod(0o600);path.write_bytes(b'altered notice')
        self.f.refresh_record('second');self.reject('source-material tree differs')

    def test_source_selection_provenance_cannot_be_substituted(self):
        b=self.f.batches['second'];b['record']['source_material']=copy.deepcopy(b['record']['source_material'])
        b['record']['source_material']['legal_acceptance']=True
        self.f.refresh_record('second');self.reject('source-material provenance differs')

    def test_complete_source_map_required(self):
        task=self.f.batches['first']['admission']['tasks']['alpha']
        del task['source_material_files']['selection.json']
        self.reject('source-material tree differs')

    def test_distinct_valid_selections_cannot_form_pair(self):
        self.f.material('second',revision='SYNTHETIC-different-reviewed-revision')
        self.reject('independent rebuild input mismatch: source_material')

    def test_whole_evidence_guard_still_rejects_extra_file(self):
        (self.f.batches['second']['output']/'unsealed').write_text('extra')
        self.reject('completed output snapshot changed')

    def test_cli_requires_interface_and_accepts_v2(self):
        self.f.write(); target=self.root/'manifests';target.mkdir()
        args=[sys.executable,'-B',str(SCRIPT),'candidate','--spec',str(self.f.spec_path),
            '--spec-sha256',m.digest(self.f.spec_path),'--output',str(target)]
        missing=subprocess.run(args,capture_output=True,text=True,timeout=15)
        self.assertEqual(missing.returncode,2);self.assertIn('--builder-interface',missing.stderr)
        good=subprocess.run(args+['--builder-interface','offline-build-v2'],capture_output=True,text=True,timeout=30)
        self.assertEqual(good.returncode,0,good.stderr)
        saved=m.decode(m.read(Path(json.loads(good.stdout)['path'])))
        self.assertEqual(saved['builder_interface'],m.INTERFACE)
        inspect=subprocess.run([sys.executable,'-B',str(SCRIPT),'inspect-build','--build',str(self.f.batches['first']['output'])],capture_output=True,text=True,timeout=15)
        self.assertEqual(inspect.returncode,2);self.assertIn('--builder-interface',inspect.stderr)

    def inspect(self):
        return subprocess.run([sys.executable,'-B',str(SCRIPT),'inspect-build','--builder-interface',m.INTERFACE,
            '--build',str(self.f.batches['first']['output'])],capture_output=True,text=True,timeout=15)

    def test_v2_inspect_retained_material_without_cache_is_not_task_admission(self):
        shutil.rmtree(self.f.cache)
        result=self.inspect();self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertFalse(report['candidate']);self.assertFalse(report['authenticated'])
        self.assertEqual(report['source_task_admission'],'NOT_CHECKED')
        self.assertEqual(report['source_material'],self.f.batches['first']['record']['source_material'])

    def test_v2_inspect_refuses_legacy_entry(self):
        self.f.batches['first']['record']['entry_script_sha256']=m.digest(ROOT/'scripts/build/container-entry.sh')
        self.f.refresh_record('first')
        result=self.inspect();self.assertEqual(result.returncode,2)
        self.assertIn('retained v2 container entry identity mismatch',result.stderr)

    def test_v2_inspect_refuses_missing_material(self):
        del self.f.batches['first']['record']['source_material']
        self.f.refresh_record('first')
        result=self.inspect();self.assertEqual(result.returncode,2)
        self.assertIn('unexpected/missing fields',result.stderr)

    def test_v2_inspect_refuses_material_file_omitted_from_provenance(self):
        del self.f.batches['first']['record']['files']['source-material/selection.json']
        self.f.refresh_record('first')
        result=self.inspect();self.assertEqual(result.returncode,2)
        self.assertIn('source-material tree differs',result.stderr)

    def test_implementation_drift_refused(self):
        real=m.implementation; calls=0
        def drift():
            nonlocal calls
            calls+=1;result=real()
            if calls>1:result['scripts/build/source_materials.py']='0'*64
            return result
        with patch.object(m,'implementation',side_effect=drift):self.reject('inspector implementation drift')


if __name__=='__main__': unittest.main()
