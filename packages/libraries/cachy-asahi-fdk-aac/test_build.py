#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Independent planner and source-inventory checks; no compiler execution."""
import sys
sys.dont_write_bytecode = True

import ast
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import source_check

spec = importlib.util.spec_from_file_location('fdk_build', HERE / 'build-codec.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
LAYOUT = json.loads(source_check.read_regular(HERE / 'build-layout.json', 1024 * 1024))
PACKET = HERE / source_check.PACKET
if not PACKET.is_file():
    PACKET = Path('/tmp/fdk-aac-3.0.0-selected-source.tar')


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'source'
        self.output = Path(self.temp.name) / 'output'

    def plan(self, environment=None):
        return build.plan(self.source, self.output, LAYOUT,
                          {} if environment is None else environment)

    def test_plan_has_395_unique_objects_and_two_links(self):
        commands, links = self.plan()
        self.assertEqual(len(commands), 395)
        self.assertEqual(len(links), 2)
        objects = [command[command.index('-o') + 1] for command in commands]
        self.assertEqual(len(set(objects)), 395)
        for obj in objects:
            self.assertTrue(Path(obj).is_relative_to(self.output / 'objects'))
        self.assertFalse(self.source.exists())
        self.assertFalse(self.output.exists())

    def test_compilation_and_linking_follow_pinned_source_inventory(self):
        commands, links = self.plan()
        offset = 0
        for link, (name, lib) in zip(links, LAYOUT['libraries'].items()):
            count = len(lib['sources'])
            group = commands[offset:offset + count]
            offset += count
            self.assertEqual([command[command.index('-c') + 1] for command in group],
                             [str(self.source / path) for path in lib['sources']])
            for command in group:
                self.assertIn('-fPIC', command)
                self.assertEqual([arg for arg in command if arg.startswith('-I')],
                                 ['-I' + str(self.source / path) for path in lib['include_dirs']])
            self.assertIn('-Wl,-soname,' + lib['soname'], link)
            self.assertIn('-Wl,--version-script=' + str(self.output / (name + '.exports')), link)
            self.assertIn('-shared', link)
            self.assertIn('-Wl,--no-undefined', link)
            self.assertEqual(link[-2:], ['-o', str(self.output / lib['file'])])
            self.assertEqual([arg for arg in link if arg.endswith('.o')],
                             [command[-1] for command in group])
            self.assertIn('-lm', link)

    def test_exact_sonames_and_exports_are_distinct(self):
        self.assertEqual({lib['soname'] for lib in LAYOUT['libraries'].values()},
                         {'libfdk-aac.so.2', 'libfdk-xhe-aac.so.0'})
        for lib in LAYOUT['libraries'].values():
            self.assertTrue(lib['exports'])
            self.assertEqual(len(lib['exports']), len(set(lib['exports'])))
            for symbol in lib['exports']:
                self.assertRegex(symbol, r'^[A-Za-z_][A-Za-z0-9_]*$')

    def test_environment_is_split_into_arguments_without_shell_execution(self):
        environment = {'CC': 'cache cc', 'CXX': 'cache c++',
                       'CFLAGS': '-O3 -DVALUE="two words"',
                       'CXXFLAGS': '-O2 -DCPP="three words"',
                       'CPPFLAGS': '-DQUOTED="$(touch forbidden)"',
                       'LDFLAGS': '-Wl,-z,relro -L"path with spaces"'}
        commands, links = self.plan(environment)
        for command in commands:
            source = command[command.index('-c') + 1]
            if source.endswith('.cpp'):
                self.assertEqual(command[:2], ['cache', 'c++'])
                self.assertIn('-DCPP=three words', command)
                self.assertIn('-fno-exceptions', command)
                self.assertIn('-fno-rtti', command)
            else:
                self.assertEqual(command[:2], ['cache', 'cc'])
                self.assertIn('-DVALUE=two words', command)
                self.assertNotIn('-fno-exceptions', command)
                self.assertNotIn('-fno-rtti', command)
            self.assertIn('-DQUOTED=$(touch forbidden)', command)
        for command in links:
            self.assertEqual(command[:2], ['cache', 'cc'])
            self.assertIn('-Lpath with spaces', command)
        self.assertFalse((self.source.parent / 'forbidden').exists())

    def test_plan_does_not_execute_read_or_write_inputs(self):
        forbidden = AssertionError('planner attempted execution or file mutation')
        with mock.patch.object(build.subprocess, 'run', side_effect=forbidden), \
             mock.patch.object(build.os, 'mkdir', side_effect=forbidden), \
             mock.patch('builtins.open', side_effect=forbidden), \
             mock.patch.object(Path, 'read_bytes', side_effect=forbidden), \
             mock.patch.object(Path, 'write_bytes', side_effect=forbidden), \
             mock.patch.object(Path, 'write_text', side_effect=forbidden):
            self.plan()

    def test_plan_preserves_supplied_layout_and_environment(self):
        layout, environment = copy.deepcopy(LAYOUT), {'CC': 'cc -pipe', 'CFLAGS': '-Os'}
        before = copy.deepcopy((layout, environment))
        build.plan(self.source, self.output, layout, environment)
        self.assertEqual((layout, environment), before)

    def test_output_paths_do_not_depend_on_process_working_directory(self):
        first = self.plan()
        with mock.patch.object(build.os, 'getcwd', return_value='/synthetic-polluted-work'):
            self.assertEqual(self.plan(), first)


class InventoryTests(unittest.TestCase):
    def test_layout_revision_counts_and_selected_implementation_scope(self):
        self.assertEqual(LAYOUT['schema_version'], 1)
        self.assertEqual(LAYOUT['source_commit'], source_check.COMMIT)
        self.assertEqual({name: len(lib['sources']) for name, lib in LAYOUT['libraries'].items()},
                         {'libfdk-aac': 170, 'libfdk-xhe-aac': 225})
        selected = LAYOUT['selected_implementation_files']
        self.assertEqual(len(selected), 898)
        for name, record in selected.items():
            path = PurePosixPath(name)
            self.assertFalse(path.is_absolute())
            self.assertNotIn('..', path.parts)
            self.assertIn(path.suffix, {'.c', '.cpp', '.h'})
            self.assertIn(path.parts[0], {'cpp', 'xhe-aac'})
            self.assertGreater(record['bytes'], 0)
            self.assertRegex(record['sha256'], r'^[0-9a-f]{64}$')
        for lib in LAYOUT['libraries'].values():
            self.assertEqual(len(lib['sources']), len(set(lib['sources'])))
            self.assertTrue(set(lib['sources'] + lib['headers']) <= set(selected))
            for directory in lib['include_dirs']:
                self.assertTrue(any(name.startswith(directory + '/') for name in selected))

    @unittest.skipUnless(PACKET.is_file(), 'private source packet is unavailable')
    def test_selected_raw_source_byte_pins_and_grant_markers(self):
        data = source_check.read_selected_packet(PACKET)
        self.assertEqual(hashlib.sha256(data).hexdigest(), source_check.PACKET_SHA)
        selected = LAYOUT['selected_implementation_files']
        found = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            for member in archive:
                if not member.name.startswith(source_check.PREFIX):
                    continue
                name = member.name[len(source_check.PREFIX):]
                if name not in selected:
                    continue
                self.assertIn(member.type, {tarfile.REGTYPE, tarfile.AREGTYPE})
                self.assertNotIn(name, found)
                with archive.extractfile(member) as stream:
                    raw = stream.read(8 * 1024 * 1024 + 1)
                record = selected[name]
                self.assertEqual(len(raw), record['bytes'], name)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'], name)
                self.assertIn(b'Fraunhofer', raw, name)
                self.assertIn(b'Redistribution and use in source and binary forms', raw, name)
                found[name] = raw
        self.assertEqual(set(found), set(selected))


class ObservationTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('actual_fdk_inner', HERE/'inner_observation.py')
        self.inner = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.inner)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.recorder = self.inner.Recorder(output=self.root, bindings=dict.fromkeys(self.inner.BINDINGS,'a'*64))
        self.recorder.phase('BUILD')
        previous = build.OBSERVER, build.COMMAND_IDENTITIES
        build.OBSERVER, build.COMMAND_IDENTITIES = self.recorder, {}
        self.addCleanup(self.restore, previous)

    def restore(self, previous): build.OBSERVER, build.COMMAND_IDENTITIES = previous

    def command(self, code=0, index=0, kind='COMPILE'):
        argv=[sys.executable,'-c','raise SystemExit('+str(code)+')']
        build.COMMAND_IDENTITIES[id(argv)]=(kind,index)
        return argv

    def row(self):
        value=self.recorder.snapshot();self.inner.validate(value);return value

    def test_harmless_natural_zero_and_nonzero_record_original_boundary(self):
        first=self.command()
        self.assertIsNone(build.run(first))
        row=self.row();self.assertEqual(row['compiler_natural_count'],1)
        self.assertEqual(row['first_compiler_natural']['returncode'],0)
        argv=self.command(7,1)
        with self.assertRaises(subprocess.CalledProcessError) as caught: build.run(argv)
        self.assertEqual(caught.exception.returncode,7)
        row=self.row();self.assertEqual(row['compiler_attempt_count'],2)
        self.assertEqual(row['compiler_natural_count'],2)
        self.assertEqual(row['first_failure']['predicate'],'COMPILER_NONZERO')
        self.assertEqual(row['first_failure']['command']['returncode'],7)

    def test_timeout_spawn_and_signal_do_not_manufacture_natural_return(self):
        for index,error in enumerate((subprocess.TimeoutExpired(['fixture'],180),OSError('fixture spawn'),KeyboardInterrupt('fixture signal'))):
            argv=self.command(index=index)
            with self.subTest(error=type(error).__name__),mock.patch.object(build.subprocess,'run',side_effect=error) as run:
                with self.assertRaises(type(error)) as caught: build.run(argv)
                self.assertIs(caught.exception,error)
                run.assert_called_once_with(argv,check=True,timeout=180)
        row=self.row();self.assertEqual(row['compiler_attempt_count'],3)
        self.assertEqual(row['compiler_natural_count'],0)
        self.assertIsNone(row['first_compiler_natural'])
        self.assertEqual(row['first_failure']['predicate'],'COMPILER_TIMEOUT')
        self.assertTrue(row['cancelled'])

    def test_boolean_or_untyped_return_cannot_attest_natural_result(self):
        for index,result in enumerate((subprocess.CompletedProcess(['fixture'],True),object())):
            argv=self.command(index=index)
            with mock.patch.object(build.subprocess,'run',return_value=result): self.assertIsNone(build.run(argv))
        self.assertEqual(self.row()['compiler_natural_count'],0)

    def test_ordinary_observer_failure_never_replaces_original_calledprocesserror(self):
        argv=self.command(7)
        error=subprocess.CalledProcessError(7,argv)
        original=self.recorder.returned
        def failed_return(*args):
            original(*args);raise RuntimeError('private observation unavailable')
        with mock.patch.object(self.recorder,'returned',side_effect=failed_return), \
                mock.patch.object(build.subprocess,'run',side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError) as caught: build.run(argv)
        self.assertIs(caught.exception,error)
        self.assertEqual(self.row()['first_failure']['predicate'],'COMPILER_NONZERO')
        self.assertEqual(self.row()['first_compiler_natural']['returncode'],7)

    def test_ordinary_observer_failure_never_replaces_natural_zero(self):
        argv=self.command()
        original=self.recorder.returned
        def failed_return(*args): original(*args);raise RuntimeError('ordinary observation unavailable')
        with mock.patch.object(self.recorder,'returned',side_effect=failed_return), \
                mock.patch.object(build.subprocess,'run',return_value=subprocess.CompletedProcess(argv,0)) as run:
            self.assertIsNone(build.run(argv));run.assert_called_once_with(argv,check=True,timeout=180)
        self.assertEqual(self.row()['compiler_natural_count'],1)
        self.assertIsNone(self.row()['first_failure'])

    def test_selected_guard_predicates_preserve_original_messages(self):
        source=self.root/'source';source.mkdir();path=source/'unit.c'
        for case,blob,name,predicate,message in (
            ('path',b'fixture','../escape.c','SELECTED_PATH','path escapes'),
            ('bytes',b'Fraunhofer Redistribution and use in source and binary forms','unit.c','SELECTED_BYTES','implementation changed'),
            ('grant',b'fixture','unit.c','SELECTED_GRANT','grant absent')):
            (self.root/'escape.c').write_bytes(blob);path.write_bytes(blob)
            record={'bytes':len(blob),'sha256':source_check.sha(blob) if case!='bytes' else '0'*64}
            (self.root/case).mkdir(mode=0o700)
            recorder=self.inner.Recorder(output=self.root/case,bindings=dict.fromkeys(self.inner.BINDINGS,'a'*64))
            build.OBSERVER=recorder;recorder.phase('BUILD')
            with self.subTest(case=case),self.assertRaisesRegex(ValueError,message):
                build.verify_selected(source,{'selected_implementation_files':{name:record}})
            row=recorder.snapshot();self.assertEqual(row['first_failure']['predicate'],predicate)
            self.assertEqual(row['compiler_attempt_count'],0)

    def test_selected_failure_survives_ordinary_observer_error(self):
        source=self.root/'source';source.mkdir();(source/'unit.c').write_bytes(b'changed')
        original=self.recorder.fail
        def unavailable(*args):original(*args);raise RuntimeError('observer unavailable')
        with mock.patch.object(self.recorder,'fail',side_effect=unavailable),self.assertRaisesRegex(ValueError,'selected implementation changed: unit.c'):
            build.verify_selected(source,{'selected_implementation_files':{'unit.c':{'bytes':7,'sha256':'0'*64}}})
        self.assertEqual(self.row()['first_failure']['predicate'],'SELECTED_BYTES')

    def test_native_host_refusal_precedes_any_observer_or_output(self):
        with mock.patch.dict(build.os.environ,{'CACHY_ASAHI_CONTAINER':'0'}), \
                mock.patch.object(build,'load_observer') as load,mock.patch.object(Path,'mkdir') as mkdir:
            with self.assertRaisesRegex(SystemExit,'no host build'):build.main()
            load.assert_not_called();mkdir.assert_not_called()

    def test_ordinary_loader_failure_keeps_original_source_failure_and_no_actor(self):
        source=self.root/'source';source.mkdir();(source/'unit.c').write_bytes(b'wrong')
        layout={'selected_implementation_files':{'unit.c':{'bytes':5,'sha256':'0'*64}}}
        with mock.patch.dict(build.os.environ,{'CACHY_ASAHI_CONTAINER':'1'}), \
                mock.patch.object(build.platform,'machine',return_value='aarch64'), \
                mock.patch.object(build,'load_observer',side_effect=OSError('loader unavailable')), \
                mock.patch.object(build,'read_regular',return_value=json.dumps(layout).encode()), \
                mock.patch.object(sys,'argv',['build','--source',str(source),'--output',str(self.root/'build')]), \
                mock.patch.object(build.subprocess,'run') as actor:
            with self.assertRaisesRegex(ValueError,'selected implementation changed: unit.c'):build.main()
            actor.assert_not_called()
        self.assertFalse((self.root/'build').exists())

    def test_parallel_observer_records_four_worker_pool_without_command_changes(self):
        commands=[self.command(index=i) for i in range(12)]
        with mock.patch.object(build.subprocess,'run',side_effect=lambda command,**kwargs:subprocess.CompletedProcess(command,0)) as run:
            with build.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(build.run,commands))
        self.assertEqual(run.call_count,12)
        self.assertEqual(self.row()['compiler_attempt_count'],12)
        self.assertEqual(self.row()['compiler_natural_count'],12)
        for call in run.call_args_list:self.assertEqual(call.kwargs,{'check':True,'timeout':180})

    def test_checksum_bound_stdlib_helper_loads_and_changed_source_is_refused(self):
        inputs=self.root/'inputs';inputs.mkdir();helper=(HERE/'inner_observation.py').read_bytes()
        (inputs/'inner_observation.py').write_bytes(helper)
        (inputs/'.SRCINFO').write_text('source = inner_observation.py\nsha256sums = '+hashlib.sha256(helper).hexdigest()+'\n')
        (self.root/'loaded').mkdir(mode=0o700)
        recorder=build.load_observer(inputs,self.root/'loaded')
        self.assertEqual(recorder.snapshot()['bindings']['observer_sha256'],hashlib.sha256(helper).hexdigest())
        (inputs/'inner_observation.py').write_bytes(helper+b'\n# changed\n')
        with self.assertRaisesRegex(ValueError,'observer source changed'):build.load_observer(inputs,self.root/'refused')
        self.assertFalse((self.root/'refused').exists())

    def test_checksum_bound_helper_cannot_import_ungranted_module(self):
        inputs=self.root/'bad-inputs';inputs.mkdir();helper=b'import socket\n'
        (inputs/'inner_observation.py').write_bytes(helper)
        (inputs/'.SRCINFO').write_text('source = inner_observation.py\nsha256sums = '+hashlib.sha256(helper).hexdigest()+'\n')
        with self.assertRaisesRegex(ValueError,'stdlib import refused'):build.load_observer(inputs,self.root/'forbidden')
        self.assertFalse((self.root/'forbidden').exists())


    def test_original_main_model_keeps_pool_commands_and_identity_order(self):
        source=self.root/'model-source';source.mkdir()
        blob=b'Fraunhofer Redistribution and use in source and binary forms'
        selected={}
        libraries={}
        for i,name in enumerate(('libclassic','libxhe')):
            unit='unit'+str(i)+'.c';(source/unit).write_bytes(blob)
            selected[unit]={'bytes':len(blob),'sha256':source_check.sha(blob)}
            libraries[name]={'sources':[unit],'include_dirs':[],'exports':['export_'+str(i)],
                'soname':name+'.so.1','file':name+'.so.1.0','pkgconfig':name}
        layout={'selected_implementation_files':selected,'libraries':libraries}
        output=self.root/'model-build';actual_read=build.read_regular
        def read(path,limit):
            return json.dumps(layout).encode() if path.name=='build-layout.json' else actual_read(path,limit)
        with mock.patch.dict(build.os.environ,{'CACHY_ASAHI_CONTAINER':'1'}), \
                mock.patch.object(build.platform,'machine',return_value='aarch64'), \
                mock.patch.object(build,'load_observer',return_value=self.recorder), \
                mock.patch.object(build,'read_regular',side_effect=read), \
                mock.patch.object(sys,'argv',['build','--source',str(source),'--output',str(output)]), \
                mock.patch.object(build.subprocess,'run',side_effect=lambda command,**kwargs:subprocess.CompletedProcess(command,0)) as actor, \
                mock.patch('builtins.print'):
            build.main()
        arrays=json.loads((output/'build-commands.json').read_bytes())
        expected=arrays['compile_commands']+arrays['link_commands']
        self.assertEqual([call.args[0] for call in actor.call_args_list],expected)
        self.assertEqual([build.COMMAND_IDENTITIES[id(call.args[0])] for call in actor.call_args_list],
                         [('COMPILE',0),('COMPILE',1),('LINK',0),('LINK',1)])
        row=self.row();self.assertEqual(row['phase'],'BUILD')
        self.assertEqual(row['compiler_attempt_count'],4)
        self.assertEqual(row['compiler_natural_count'],4)
        self.assertIsNone(row['first_failure'])
        for call in actor.call_args_list:self.assertEqual(call.kwargs,{'check':True,'timeout':180})

    def test_untyped_calledprocesserror_never_attests_natural_return(self):
        argv=self.command()
        error=subprocess.CalledProcessError(True,argv)
        with mock.patch.object(build.subprocess,'run',side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError) as caught:build.run(argv)
        self.assertIs(caught.exception,error)
        self.assertEqual(self.row()['compiler_natural_count'],0)
        self.assertEqual(self.row()['first_failure']['predicate'],'COMPILER_CALL')


    def test_control_during_natural_nonzero_observation_keeps_cached_first_cause(self):
        argv=self.command(7)
        business=subprocess.CalledProcessError(7,argv);control=KeyboardInterrupt('private observer signal')
        returned=self.recorder.returned;fsync=self.inner.os.fsync;fired=[]
        def interrupted(fd):
            if not fired:fired.append(True);raise control
            return fsync(fd)
        def returned_with_control(*args):
            with mock.patch.object(self.inner.os,'fsync',side_effect=interrupted):returned(*args)
        with mock.patch.object(self.recorder,'returned',side_effect=returned_with_control), \
                mock.patch.object(build.subprocess,'run',side_effect=business):
            with self.assertRaises(KeyboardInterrupt) as caught:build.run(argv)
        self.assertIs(caught.exception,control)
        row=self.row();self.assertEqual(row['compiler_natural_count'],1)
        self.assertEqual(row['first_compiler_natural']['returncode'],7)
        self.assertEqual(row['first_failure']['predicate'],'COMPILER_NONZERO')
        self.assertTrue(row['cancelled']);self.assertTrue(row['write_failed'])


if __name__ == '__main__':
    unittest.main()
