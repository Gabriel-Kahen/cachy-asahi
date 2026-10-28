# SPDX-License-Identifier: MIT
"""Bounded inert controls; no native compiler, candidate execution, Docker or VM."""
import ast
import base64
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as c
import run as trial

ROOT=Path(os.environ.get('GLIBC16K_SOURCE_ROOT',Path.cwd()))
PAIR=Path(os.environ.get('GLIBC16K_PAIR_ROOT',Path.cwd()/'artifacts/development/glibc-accepted-pair-inputs-20261016/payload'))


class Inputs(unittest.TestCase):
    def test_actual_accepted_input_index_and_archive_pair_bytes(self):
        index,paths=c.pair(PAIR)
        self.assertEqual(index['native_run'],38915137670);self.assertNotEqual(paths[0],paths[1])
        self.assertEqual(paths[0].stat().st_size,19400096)

    def test_closed_reused_source_and_tools_cache_helper_pins(self):
        c.check_source(ROOT);self.assertEqual(len(c.decode(c.read(c.HERE/'dependencies.json'))['files']),19)
        self.assertEqual(c.dependencies()['scripts/ci/tools-generic16k/build_kernel.py']['sha256'],
            '3c8695685dcae7eded7406ccbf0f8152f6f5820f87ef47f4e791b577c2d3b55a')

    def test_pending_tools_cache_cannot_authorize_native_trial(self):
        value=c.decode(c.read(c.HERE/'input-policy.json'));value['status']='PENDING';value['kernel_cache']=None
        with self.assertRaisesRegex(ValueError,'pending final Tools'):c.bindings(value)
        with patch.object(c,'bindings',side_effect=ValueError('pending final Tools')):
            with self.assertRaisesRegex(ValueError,'pending final Tools'):trial.trial(SimpleNamespace())

    def test_final_tools_handoff_is_bound_without_a_null_gate(self):
        value=c.bindings();self.assertEqual(value['kernel_cache']['retained_asset'],647949735)
        self.assertEqual(len(c.dependencies()),22)

    def test_byte_substitution_and_alias_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'file').write_bytes(b'one');row=dict(bytes=3,sha256=c.sha(b'one'))
            c.checked(root,'file',row);(root/'file').write_bytes(b'two')
            with self.assertRaises(ValueError):c.checked(root,'file',row)
            (root/'alias').symlink_to(root/'file')
            with self.assertRaises(ValueError):c.checked(root,'alias',dict(bytes=3,sha256=c.sha(b'two')))

    def test_private_runtime_exact_subset_and_all_loadable_elf_alignment(self):
        generic=c.load(ROOT,'scripts/virtual/generic16k/fixture.py')
        _,packages=c.pair(PAIR)
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)/'candidate';rows=c.stage(packages[0],stage,generic);count=0;elfs={}
            self.assertEqual(len(rows),343)
            for name,row in rows.items():
                self.assertFalse(name.endswith(('.o','.a')))
                raw=(stage/name).read_bytes();self.assertEqual(c.sha(raw),row['sha256'])
                if raw.startswith(b'\x7fELF'):
                    elfs[c.PREFIX+'/'+name]=dict(c.aligned(raw,generic),scope='candidate');count+=1
            self.assertEqual(count,287)
            for role,(name,digest) in c.ROLES.items():self.assertEqual(rows[name]['sha256'],digest)
            self.assertTrue(any(n.startswith('l/') for n in rows));self.assertTrue(any(n.startswith('usr/lib/locale/') for n in rows))
            files={c.PREFIX+'/'+name for name in rows}
            # These fourteen unchanged modules require the already-captured
            # helper DSOs alongside them, not in the parent usr/lib directory.
            importers=[name for name,row in elfs.items()
                       if any(c.PREFIX+'/usr/lib/'+lib not in files for lib in row['needed'])]
            self.assertEqual(len(importers),14)
            self.assertIn(c.PREFIX+'/usr/lib/gconv/EUC-CN.so',importers)
            c.elf_closure(elfs,files)

    def test_private_gconv_origin_and_parent_libraries(self):
        name=c.PREFIX+'/usr/lib/gconv/EUC-CN.so'
        rows={name:dict(scope='candidate',interpreter=None,needed=['libGB.so','libc.so.6'])}
        files={c.PREFIX+'/usr/lib/gconv/libGB.so',c.PREFIX+'/usr/lib/libc.so.6'}
        c.elf_closure(rows,files)

    def test_missing_gconv_helper_remains_fatal_with_importer_diagnostic(self):
        name=c.PREFIX+'/usr/lib/gconv/EUC-CN.so'
        with self.assertRaisesRegex(ValueError,'EUC-CN.so -> libGB.so'):
            c.elf_closure({name:dict(scope='candidate',interpreter=None,needed=['libGB.so'])},set())

    def test_private_gconv_cannot_fall_back_to_bootstrap_helper(self):
        name=c.PREFIX+'/usr/lib/gconv/EUC-CN.so'
        with self.assertRaises(ValueError):
            c.elf_closure({name:dict(scope='candidate',interpreter=None,needed=['libGB.so'])},
                          {'usr/lib/libGB.so','usr/lib/gconv/libGB.so','lib/libGB.so'})

    def test_private_client_cannot_use_gconv_search_directory(self):
        name='work/clients/smoke'
        with self.assertRaises(ValueError):
            c.elf_closure({name:dict(scope='candidate',interpreter=None,needed=['libGB.so'])},
                          {c.PREFIX+'/usr/lib/gconv/libGB.so'})

    def test_non_gconv_candidate_cannot_use_gconv_search_directory(self):
        name=c.PREFIX+'/usr/lib/libc.so.6'
        with self.assertRaises(ValueError):
            c.elf_closure({name:dict(scope='candidate',interpreter=None,needed=['libGB.so'])},
                          {c.PREFIX+'/usr/lib/gconv/libGB.so'})

    def test_bootstrap_cannot_use_private_helper(self):
        with self.assertRaises(ValueError):
            c.elf_closure({'usr/bin/python3':dict(scope='bootstrap',interpreter=None,needed=['libGB.so'])},
                          {c.PREFIX+'/usr/lib/gconv/libGB.so'})

    def test_missing_interpreter_still_fatal(self):
        with self.assertRaisesRegex(ValueError,'captured interpreter absent: work/clients/smoke'):
            c.elf_closure({'work/clients/smoke':dict(scope='candidate',interpreter='/'+c.PREFIX+'/usr/lib/ld-linux-aarch64.so.1',needed=[])},set())

    def test_capture_and_parent_use_same_closure_guard(self):
        for name in ('capture.py','run.py'):
            tree=ast.parse((c.HERE/name).read_bytes())
            calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                   and isinstance(n.func.value,ast.Name) and n.func.value.id=='c' and n.func.attr=='elf_closure']
            self.assertEqual(len(calls),1,name)
            self.assertEqual([ast.unparse(n) for n in calls[0].args],['elfs','files'])

    def test_4k_or_missing_load_segments_rejected(self):
        for loads in ([],[(0,0,100,4096)],[(4096,0,100,16384)]):
            generic=SimpleNamespace(elf=lambda raw:(None,[],loads))
            with self.subTest(loads=loads),self.assertRaises(ValueError):c.aligned(b'fixture',generic)

    def test_package_substitution_refused_before_archive_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package=root/'bad';package.write_bytes(b'fake')
            generic=SimpleNamespace(Archive=__import__('unittest.mock',fromlist=['Mock']).Mock())
            with self.assertRaises(ValueError):c.stage(package,root/'candidate',generic)
            generic.Archive.assert_not_called()


class ExecutionBoundary(unittest.TestCase):
    def test_native_capture_compiles_once_and_never_invokes_runtime(self):
        tree=ast.parse((c.HERE/'capture.py').read_bytes())
        calls=[n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
               and isinstance(n.func.value,ast.Name) and n.func.value.id=='driver']
        self.assertEqual(calls.count('compile_suite'),1)
        self.assertNotIn('validate_runtime',calls);self.assertNotIn('main',calls)
        self.assertIn('run_command',calls) # Separate, unchanged freestanding page probe compile.
        self.assertIn("argv=['/usr/bin/gcc'",(c.HERE/'capture.py').read_text())

    def test_guest_uses_unchanged_mapping_validator_and_actual_page_check(self):
        text=(c.HERE/'guest.py').read_text();self.assertIn('driver.validate_runtime(',text)
        self.assertIn("result['page_size']==16384",text);self.assertIn('os.setgroups([])',text)
        self.assertIn('driver.runtime_inventory(spec)==before',text)
        self.assertNotIn('compile_suite',text);self.assertNotIn("'--host-compile-only'",text)

    def test_native_capture_is_readonly_offline_and_borrowed_image(self):
        args=SimpleNamespace(private=Path('/tmp/private'),job_token='a'*16,source_root=ROOT,base_dir=Path('/tmp/base'),source_commit='b'*40)
        argv=trial.capture_command(args,'sha256:'+'c'*64,'owned',Path('/tmp/out'),Path('/tmp/stage'))
        for option in ('--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges'):self.assertIn(option,argv)
        self.assertNotIn('--privileged',argv);self.assertNotIn('--rm',argv)
        self.assertTrue(any('dst=/opt/caa/g243a1,readonly' in value for value in argv))

    def test_exact_kernel_page_and_nonce_init(self):
        raw=trial.init('a'*32,'7.1.13-generic16k-smoke')
        self.assertIn(b'PAGESIZE) == 16384',raw);self.assertIn(b'/smoke || fail',raw)
        with self.assertRaises(ValueError):trial.init('bad','release')

    def test_thirteen_compile_commands_are_required(self):
        value=dict(status='COMPILED_ONCE_NOT_EXECUTED',commands=[dict(exit_code=0,group_absence_verified=True) for _ in range(13)],
            compiled_files={n:{} for n in c.CLIENTS},sources={n:{} for n in ('abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py')})
        c.compile_receipt(value)
        value['commands'].pop()
        with self.assertRaises(ValueError):c.compile_receipt(value)


class Receipt(unittest.TestCase):
    def good(self):
        result=dict(kind='result',status='PASS',cases=8,page_size=16384)
        rows=[dict(kind='test',process='parent',name=n,status='PASS') for n in sorted(c.CASES)]
        rows += [dict(kind='test',process='child',name='exec_child',status='PASS'),result]
        roles=['/'+c.PREFIX+'/'+name for name,_ in c.ROLES.values()]
        symbols={'malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos'}
        for process in ('parent','child'):
            paths=roles+(['/work/clients/plugin.so','/'+c.PREFIX+'/usr/lib/gconv/ISO8859-1.so',
                '/'+c.PREFIX+'/usr/lib/locale/C.utf8/LC_CTYPE'] if process=='parent' else [])
            rows.append(dict(kind='identity',process=process,objects=[dict(path=p) for p in paths],mapped_files=[dict(path=p) for p in paths],
                providers=[dict(symbol=n,path='/'+c.PREFIX+'/'+c.ROLES['libm' if n=='cos' else 'libc'][0]) for n in symbols]))
        return dict(status='PASS_PRIVATE_GLIBC_GENERIC16K_RUNTIME',architecture='aarch64',page_size=16384,uid=23001,gid=23001,groups=[],
            runtime=result,runtime_records=rows,cases=sorted(c.CASES),commands=[dict(exit_code=0,group_absence_verified=True) for _ in range(14)],
            owned_processes_absent=True,payload_preserved=True,sources_preserved=True,candidate_preserved=True,
            hardware='NOT_RUN',performance='NOT_MEASURED',installation='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED')

    def test_full8cases14commands_normal_groups(self):c.guest_receipt(self.good())

    def test_4k_and_missing_cases_and_abnormal_exit_refused(self):
        mutations=[('page_size',4096),('uid',0),('groups',[0]),('cases',[]),('owned_processes_absent',False),
            ('payload_preserved',False),('candidate_preserved',False),('sources_preserved',False)]
        for key,value in mutations:
            bad=self.good();bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):c.guest_receipt(bad)
        bad=self.good();bad['commands'][-1]['exit_code']=9
        with self.assertRaises(ValueError):c.guest_receipt(bad)

    def test_missing_child_identity_or_host_provider_cannot_pass(self):
        bad=self.good();bad['runtime_records'].pop()
        with self.assertRaises(ValueError):c.guest_receipt(bad)
        bad=self.good();bad['runtime_records'][-1]['providers'][0]['path']='/usr/lib/libc.so.6'
        with self.assertRaises(ValueError):c.guest_receipt(bad)

    def test_truncated_or_unattributed_guest_protocol_refused(self):
        for raw in (b'',b'GLIBC16K PASS '+b'a'*32+b'\n',b'SMOKE16K: mmap,mprotect,file-offset PASS\nGLIBC16K BOOT other 16384\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):trial.guest_report(raw,0,'a'*32,'release',{})

    def test_unknown_consumer_state_blocks_producer_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);private=root/'private';private.mkdir();args=SimpleNamespace(output=root,private=private,job_token='a'*16)
            self.assertFalse(trial.cleanup_safe(args))
            c.save(root/'runtime.json',dict(job_token='a'*16,consumer_cleanup=dict(capture_absent=False,private_removed=False)))
            self.assertFalse(trial.cleanup_safe(args))

    def test_foreign_capture_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'capture.cid').write_text('b'*64)
            args=SimpleNamespace(private=root,job_token='a'*16)
            record=dict(Id='b'*64,Name='/owned',Image='sha256:'+'c'*64,Config=dict(Labels={'org.cachy-asahi.glibc16k.job':'foreign'}))
            from unittest.mock import Mock
            query=Mock(side_effect=['owned',json.dumps([record])]);reuse=SimpleNamespace(query=query)
            with self.assertRaises(ValueError):trial.retire(args,reuse,'owned','sha256:'+'c'*64,True)
            self.assertEqual(query.call_count,2);self.assertTrue(root.exists())


class Workflow(unittest.TestCase):
    def text(self):return (c.HERE.parents[2]/'.github/workflows/native-arm-glibc-generic16k.yml').read_text()

    def test_bound_pair_and_tools_cache_before_secrets(self):
        text=self.text();self.assertLess(text.index('Prove exact reviewed source pair'),text.index('${{ secrets.'))
        self.assertIn('18569401aa28e2be86f4ada20489913f28739b92',text)
        self.assertIn('actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830',text)
        self.assertIn('cache_archive=cache,cache_hit=',text)
        self.assertLess(text.index('acquire.cache_state('),text.index('result=seed.download('))
        self.assertIn("retained_archive=os.environ['KERNEL_RETAINED_ARCHIVE'] or None",text)
        self.assertIn("result['status']=='RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED'",text)
        self.assertIn("else:assert result['status']=='RETAINED_ASSET_UNAVAILABLE'",text)
        self.assertNotIn('glibc-official-release/run.py',text)
        self.assertIn('run.py" cleanup-safe',text)
        self.assertIn('run.py" finalize',text)

    def test_literal_shell_blocks_parse(self):
        lines=self.text().splitlines();blocks=[];i=0
        while i<len(lines):
            if lines[i]=='        run: |':
                i+=1;block=[]
                while i<len(lines) and (lines[i].startswith('          ') or not lines[i]):block.append(lines[i][10:]);i+=1
                blocks.append('\n'.join(block)+'\n')
            else:i+=1
        self.assertGreaterEqual(len(blocks),8)
        for block in blocks:subprocess.run(['bash','-n'],input=block,text=True,capture_output=True,check=True)


if __name__=='__main__':unittest.main()
