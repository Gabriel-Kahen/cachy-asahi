# SPDX-License-Identifier: MIT
"""Inert fixtures only: no candidate process, compiler, container or network."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

MODULE=importlib.util.spec_from_file_location('glibc_smoke_runner',Path(__file__).with_name('runner.py'))
R=importlib.util.module_from_spec(MODULE);MODULE.loader.exec_module(R)


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='.inert-test-',dir=R.HERE)
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.stage=self.root/'candidate';self.stage.mkdir()
        for directory in ('usr/lib/gconv','usr/lib/locale/C.utf8'): (self.stage/directory).mkdir(parents=True,exist_ok=True)
        self.roles={}
        for role,name in (('loader','ld-linux-aarch64.so.1'),('libc','libc.so.6'),('libm','libm.so.6')):
            path=self.stage/'usr/lib'/name;path.write_bytes(('inert '+role).encode());self.roles[role]=path
        self.gconv=self.stage/'usr/lib/gconv/ISO8859-1.so';self.gconv.write_bytes(b'inert module')
        self.locale=self.stage/'usr/lib/locale/C.utf8/LC_CTYPE';self.locale.write_bytes(b'inert locale')
        self.value={'schema_version':1,'stage_root':str(self.stage),'library_directories':['usr/lib'],
                    'gconv_directory':'usr/lib/gconv','locale_directory':'usr/lib/locale'}
        for role,path in self.roles.items():self.value[role]={'path':str(path.relative_to(self.stage)),'sha256':R.sha(path)}
        self.input=self.root/'inputs.json';self.save()
        self.spec=R.inputs(self.input);self.before=R.runtime_inventory(self.spec)
        self.work=self.root/'work';self.work.mkdir()
        self.binaries={}
        for name in ('plugin.so','smoke','exec-child'):
            path=self.work/name;path.write_bytes(('inert '+name).encode());self.binaries[str(path)]=R.identity(path)

    def save(self):self.input.write_text(json.dumps(self.value))

    def records(self):
        result=[{'kind':'test','process':'parent','name':name,'status':'PASS'} for name in sorted(R.CASES)]
        result.append({'kind':'test','process':'child','name':'exec_child','status':'PASS'})
        for process in ('parent','child'):
            paths=list(self.roles.values())+[self.work/('smoke' if process=='parent' else 'exec-child')]
            if process=='parent':paths+=[self.work/'plugin.so',self.gconv,self.locale]
            rows=[dict(path=str(path),**{k:v for k,v in R.identity(path).items() if k not in ('sha256','bytes')}) for path in paths]
            result.append({'kind':'identity','process':process,'executable':str(self.roles['loader']),
                           'objects':copy.deepcopy(rows),'mapped_files':copy.deepcopy(rows),
                           'providers':[{'symbol':symbol,'path':str(self.roles['libm' if symbol=='cos' else 'libc'])} for symbol in sorted(R.PROVIDERS)]})
        result.append({'kind':'result','status':'PASS','cases':8,'page_size':16384,'glibc_version':'inert'})
        return result

    def validate(self,records):return R.validate_runtime(records,self.spec,self.before,self.binaries)

    def test_inputs_and_inventory(self):
        self.assertEqual(set(self.before),set(map(str,self.roles.values()))|{str(self.gconv),str(self.locale)})

    def test_expected_hash_required(self):
        self.value['libc']['sha256']='0'*64;self.save()
        with self.assertRaisesRegex(ValueError,'candidate-input-hash-differs'):R.inputs(self.input)

    def test_stage_relative_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError,'stage-relative-path-required'):R.stage_path(self.stage,'usr/../libc')

    def test_escaping_file_alias_rejected(self):
        outside=self.root/'outside';outside.write_bytes(b'inert')
        alias=self.stage/'alias';alias.symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'candidate-alias-escapes-stage'):R.stage_path(self.stage,'alias')

    def test_escaping_inventory_alias_rejected(self):
        (self.stage/'usr/lib/escape').symlink_to(self.input)
        with self.assertRaisesRegex(ValueError,'runtime-tree-alias-escapes'):R.runtime_inventory(self.spec)

    def test_resolved_path_delimiter_rejected(self):
        outside=self.root/'with:colon';outside.write_bytes(b'inert')
        alias=self.root/'alias';alias.symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'absolute-simple-path-required'):R.safe(alias)

    def test_all_identity_joins_pass(self):
        verified,result=self.validate(self.records())
        self.assertEqual(result['page_size'],16384);self.assertEqual(len(verified),8)

    def test_foreign_mapping_rejected(self):
        records=self.records();records[9]['mapped_files'][0]['path']=str(self.input)
        with self.assertRaisesRegex(ValueError,'foreign-runtime-file'):self.validate(records)

    def test_provider_host_fallback_rejected(self):
        records=self.records();records[9]['providers'][0]['path']=str(self.work/'smoke')
        with self.assertRaisesRegex(ValueError,'symbol-resolved-to-wrong-runtime'):self.validate(records)

    def test_mapping_inode_rejected(self):
        records=self.records();records[9]['mapped_files'][0]['inode']+=1
        with self.assertRaisesRegex(ValueError,'runtime-file-hash-or-map-drift'):self.validate(records)

    def test_runtime_hash_drift_rejected(self):
        records=self.records();self.roles['libc'].write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'runtime-file-hash-or-map-drift'):self.validate(records)

    def test_missing_loader_object_rejected(self):
        records=self.records();records[9]['objects']=records[9]['objects'][1:]
        with self.assertRaisesRegex(ValueError,'candidate-libc-loader-libm-not-all-loaded'):self.validate(records)

    def test_gconv_mapping_required(self):
        records=self.records();records[9]['mapped_files']=[r for r in records[9]['mapped_files'] if r['path']!=str(self.gconv)]
        with self.assertRaisesRegex(ValueError,'candidate-gconv-mapping-required'):self.validate(records)

    def test_locale_mapping_required(self):
        records=self.records();records[9]['mapped_files']=[r for r in records[9]['mapped_files'] if r['path']!=str(self.locale)]
        with self.assertRaisesRegex(ValueError,'candidate-locale-mapping-required'):self.validate(records)

    def test_missing_runtime_case_rejected(self):
        with self.assertRaisesRegex(ValueError,'complete-runtime-cases-required'):self.validate(self.records()[1:])

    def test_child_identity_required(self):
        records=self.records();records[10]['process']='parent'
        with self.assertRaisesRegex(ValueError,'runtime-identity-set'):self.validate(records)

    def test_hardware_result_not_inferred(self):
        records=self.records();records[-1]['page_size']=0
        with self.assertRaisesRegex(ValueError,'runtime-result'):self.validate(records)

    def test_guard_refuses_non_arm_before_process(self):
        with patch.object(R.platform,'system',return_value='Linux'),patch.object(R.platform,'machine',return_value='x86_64'),patch.object(R.subprocess,'Popen',side_effect=AssertionError('forbidden')):
            with self.assertRaisesRegex(ValueError,'native-unprivileged-aarch64-required'):R.native_guard()

    def test_execute_refuses_host_without_compiler_or_candidate(self):
        work=self.root/'execute-refusal'
        with patch('sys.argv',['runner','--inputs',str(self.input),'--workspace',str(work),'--execute']),patch.object(R.platform,'machine',return_value='x86_64'),patch.object(R.subprocess,'Popen',side_effect=AssertionError('forbidden')),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(R.main(),1)
        receipt=json.loads((work/'receipt.json').read_text())
        self.assertEqual(receipt['commands'],[]);self.assertEqual(receipt['error_code'],'native-unprivileged-aarch64-required')

    def test_native_guard_requires_offline_container(self):
        with patch.object(R.platform,'system',return_value='Linux'),patch.object(R.platform,'machine',return_value='aarch64'),patch.object(R.os,'getuid',return_value=1000),patch.object(R.os,'geteuid',return_value=1000),patch.object(Path,'is_file',return_value=True),patch.dict(os.environ,{'CACHY_ASAHI_GLIBC_RUNTIME_SMOKE':'1'}),patch.object(Path,'iterdir',return_value=iter([Path('lo'),Path('eth0')])):
            with self.assertRaisesRegex(ValueError,'offline-container-required'):R.native_guard()

    def test_workspace_overlap_fails_without_process(self):
        work=self.stage/'new-work'
        with patch('sys.argv',['runner','--inputs',str(self.input),'--workspace',str(work)]),patch.object(R.subprocess,'Popen',side_effect=AssertionError('forbidden')),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(R.main(),1)
        self.assertEqual(json.loads((work/'receipt.json').read_text())['error_code'],'stage-and-workspace-must-be-separate')

    def test_final_source_drift_cannot_leave_pass(self):
        original=R.identity;count=0
        def changing(path):
            nonlocal count
            row=original(path);count+=1
            if count>len(R.SOURCES):row['sha256']='0'*64
            return row
        work=self.root/'source-check'
        with patch('sys.argv',['runner','--host-compile-only','--workspace',str(work)]),patch.object(R,'compile_suite',return_value=({}, {}, {})),patch.object(R,'identity',side_effect=changing),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(R.main(),1)
        receipt=json.loads((work/'receipt.json').read_text())
        self.assertEqual(receipt['status'],'FAIL');self.assertEqual(receipt['error_code'],'source-mutated-during-check')


class ProcessBounds(unittest.TestCase):
    def fake_process(self,out=b'finite',err=b''):
        streams=[]
        for data in (out,err):
            read,write=os.pipe();os.write(write,data);os.close(write);streams.append(os.fdopen(read,'rb'))
        return SimpleNamespace(pid=12345,stdout=streams[0],stderr=streams[1],wait=lambda timeout:0)

    def check(self,**kwargs):
        proc=self.fake_process()
        with patch.object(R.subprocess,'Popen',return_value=proc),patch.object(R.os,'waitid',return_value=object()),patch.object(R.os,'killpg',side_effect=lambda pid,sig: (_ for _ in ()).throw(ProcessLookupError()) if sig==0 else None) as kill:
            result=R.run_command(['inert-argv'],R.HERE,R.ENV,**kwargs)
        self.assertEqual([call.args[1] for call in kill.call_args_list],[R.signal.SIGTERM,R.signal.SIGKILL,0])
        return result

    def test_finite_capture_and_group_absence(self):
        row,out,err,error=self.check();self.assertIsNone(error)
        self.assertEqual((out,err),(b'finite',b''));self.assertTrue(row['group_absence_verified']);self.assertEqual(row['exit_code'],0)

    def test_output_bound_and_cleanup(self):
        row,out,err,error=self.check(cap=2)
        self.assertEqual(str(error),'command-output-limit');self.assertLessEqual(len(out)+len(err),2);self.assertTrue(row['group_absence_verified'])

    def test_time_bound_and_cleanup(self):
        row,out,err,error=self.check(seconds=0)
        self.assertEqual(str(error),'command-time-limit');self.assertTrue(row['group_absence_verified'])

    def test_interrupt_and_cleanup(self):
        with patch.object(R.selectors.BaseSelector,'select',side_effect=KeyboardInterrupt):
            # Patch the actual platform selector; no subprocess is created.
            with patch.object(R.selectors.DefaultSelector,'select',side_effect=KeyboardInterrupt):
                row,out,err,error=self.check()
        self.assertIsInstance(error,KeyboardInterrupt);self.assertTrue(row['group_absence_verified'])


if __name__=='__main__':unittest.main()
