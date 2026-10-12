#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Independent planner and source-inventory checks; no compiler execution."""
import sys
sys.dont_write_bytecode = True

import copy
import hashlib
import importlib.util
import io
import json
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


if __name__ == '__main__':
    unittest.main()
