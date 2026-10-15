"""Inert schema/command-contract tests: no native host, compiler, or plugin actors."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('offline_container', Path(__file__).with_name('container.py'))
container = importlib.util.module_from_spec(spec)
spec.loader.exec_module(container)
TMP = Path(__file__).resolve().parents[4] / 'tmp'
TMP.mkdir(exist_ok=True)


def passing_processing():
    plugins = []
    cases = []
    for uri, profiles in container.PROFILE_VALUES.items():
        channels = 1 if uri == container.URIS[0] else 2
        controls = []
        for index, symbol in enumerate(next(iter(profiles.values()))):
            controls.append({'symbol': symbol, 'index': index, 'default': 0,
                             'minimum': -100, 'maximum': 20000, 'integer': False,
                             'toggled': False, 'enum_values': []})
        plugins.append({'uri': uri, 'port_count': 400, 'required_features':
                        ['http://lv2plug.in/ns/ext/urid#map'],
                        'audio_inputs': ['in'] if channels == 1 else ['in_l', 'in_r'],
                        'audio_outputs': ['out'] if channels == 1 else ['out_l', 'out_r'],
                        'optional_null_atoms': ['in_ui', 'out_ui'], 'controls': controls})
        for profile in profiles:
            for rate in container.RATES:
                for fixture in container.FIXTURES:
                    cases.append({'uri': uri, 'profile': profile, 'rate_hz': rate,
                                  'fixture': fixture, 'status': 'PASS', 'latency_frames': 256,
                                  'peak': 0 if fixture == 'zero' else .0005,
                                  'rms': 0 if fixture == 'zero' else .0001,
                                  'max_bypass_error': 0, 'max_repeat_error': 0,
                                  'sample_count_per_channel': 24576,
                                  'sample_fnv1a64': ['0123456789abcdef'] * 2})
    return {'schema_version': 1, 'mode': 'processing', 'status': 'PASS',
            'failure_class': None, 'plugins': plugins, 'control_binding_count': 31,
            'case_count': 48, 'instance_count': 96, 'cases': cases,
            'audio_devices': 'NOT USED', 'hardware': 'NOT RUN',
            'optimization_acceptance': 'NOT RUN'}


class ContainerTests(unittest.TestCase):
    def rejects(self, code, operation, *args):
        with self.assertRaises(container.Failure) as caught:
            operation(*args)
        self.assertEqual(caught.exception.code, code)

    def test_json_rejects_duplicate_nonfinite_and_extra_data(self):
        for raw in (b'{"x":0,"x":1}', b'{"x":NaN}', b'{"x":Infinity}', b'{} garbage'):
            self.rejects('host_schema', container.json_document, raw)

    def test_flags_refuse_unreviewed_search_and_execution_flags(self):
        self.assertEqual(container.pkg_flags(b'-I/usr/include/lilv-0 -llilv-0'),
                         ['-I/usr/include/lilv-0', '-llilv-0'])
        for flags in (b'-I/private -llilv-0', b'-llilv-0 -Wl,-rpath,/tmp',
                      b'-llilv-0 @/secret', b'-llilv-0 -fplugin=/tmp/x', b'-lm'):
            self.rejects('pkg_config', container.pkg_flags, flags)

    def test_readelf_projection_contains_no_raw_text_or_search_paths(self):
        raw = b'''ELF Header:
 Class: ELF64
 Machine: AArch64
 0 (NEEDED) Shared library: [libc.so.6]
 0 (RUNPATH) Library runpath: [/private/path]
Version needs section '.gnu.version_r' contains 1 entry:
 0x0: Name: GLIBC_2.17 Flags: none Version: 2
'''
        result = container.parse_readelf(raw)
        self.assertEqual(result['needed'], ['libc.so.6'])
        self.assertEqual(result['path_tags'], ['RUNPATH'])
        self.assertEqual(result['version_requirements'], ['GLIBC_2.17'])
        self.assertNotIn('/private', json.dumps(result))
        self.rejects('elf', container.parse_readelf, raw.replace(b'AArch64', b'X86-64'))
        self.rejects('elf_metadata', container.parse_readelf,
                     raw.replace(b'libc.so.6', b'/private/lib.so'))

    def test_structural_checker_rejection_and_rpath_are_failures(self):
        clean = b'Class: ELF64\nMachine: AArch64\n'
        checker = Mock(return_value={'machine': 183, 'load_segments': 2, 'errors': []})
        with patch.object(container, 'bounded_bytes', return_value=b'fake-elf'), \
                patch.object(container, 'command', return_value=clean):
            self.assertEqual(container.elf_observation('/mock', 'host', checker)['structural_16k'], 'PASS')
            checker.return_value['errors'] = ['private structural error']
            self.rejects('elf_structure', container.elf_observation, '/mock', 'host', checker)
            checker.return_value['errors'] = []
            with patch.object(container, 'command', return_value=clean + b'(RPATH) [/private]\n'):
                self.rejects('elf_search_path', container.elf_observation, '/mock', 'host', checker)

    def test_inventory_is_exact_and_sorted(self):
        lines = [f'package-{n} 1-1' for n in range(574)]
        expected = ('\n'.join(sorted(lines)) + '\n').encode()
        with patch.object(container, 'command', return_value=('\n'.join(lines) + '\n').encode()), \
                patch.object(container, 'bounded_bytes', return_value=expected):
            self.assertEqual(len(container.inventory('before')), 64)
            with patch.object(container, 'bounded_bytes', return_value=expected + b'extra 1\n'):
                self.rejects('inventory', container.inventory, 'before')
        for bad in (b'x 1\n', (b'x 1\n' * 574)):
            with patch.object(container, 'command', return_value=bad):
                self.rejects('inventory', container.inventory, 'before')

    def test_mount_validation_uses_deepest_mount(self):
        mounts = ('1 0 0:1 / / ro - overlay overlay ro\n'
                  '2 1 0:2 / /source ro - ext4 disk ro\n'
                  '3 1 0:3 / /var/lib/pacman rw - ext4 disk rw\n')
        self.assertTrue(container.mount_readonly('/', mounts))
        self.assertTrue(container.mount_readonly('/source/host.c', mounts))
        self.assertFalse(container.mount_readonly('/var/lib/pacman', mounts))

    def test_loader_strict_contract(self):
        value = {'schema_version': 1, 'mode': 'loader', 'status': 'PASS', 'selected_uris': container.URIS,
                 'descriptor_count': 198, 'loaded_basenames': ['libc.so.6'], 'loaded_paths': ['/usr/lib/libc.so.6'], 'failure_class': None,
                 'audio_devices': 'NOT USED', 'hardware': 'NOT RUN',
                 'optimization_acceptance': 'NOT RUN'}
        with patch.object(container, 'loaded_libraries', return_value=[{'identity': 'candidate/lsp-plugins-lv2.so',
                                                                       'sha256': 'a' * 64}]):
            result = container.project_loader(json.dumps(value).encode())
            self.assertEqual(result['descriptor_count'], 198)
            self.assertNotIn('loaded_basenames', result)
            value['private_path'] = '/secret'
            self.rejects('host_schema', container.project_loader, json.dumps(value).encode())
            del value['private_path']
            value['selected_uris'] = container.URIS[:-1]
            self.rejects('loader_schema', container.project_loader, json.dumps(value).encode())

    def test_complete_processing_grid_and_control_metadata(self):
        value = passing_processing()
        result = container.project_processing(json.dumps(value).encode())
        self.assertEqual(result, value)
        self.assertEqual(len(result['cases']), 48)
        for mutate in (
                lambda x: x['cases'].append(copy.deepcopy(x['cases'][0])),
                lambda x: x['cases'].__setitem__(1, copy.deepcopy(x['cases'][0])),
                lambda x: x['cases'][0].__setitem__('rate_hz', 192000),
                lambda x: x['cases'][0].__setitem__('private_path', '/secret'),
                lambda x: x['cases'][0].__setitem__('peak', float('nan')),
                lambda x: x['cases'][0].__setitem__('sample_count_per_channel', 1),
                lambda x: x['cases'][0].__setitem__('sample_fnv1a64', ['/secret'] * 2),
                lambda x: x['cases'][1].__setitem__('max_bypass_error', .001),
                lambda x: x['cases'][2].__setitem__('rms', 0),
                lambda x: x['cases'][2].__setitem__('latency_frames', 8193),
                lambda x: x['plugins'][0]['controls'][0].__setitem__('symbol', 'invented'),
                lambda x: x['plugins'][0]['controls'][0].__setitem__('maximum', .5),
                lambda x: x['plugins'][0]['required_features'].append('http://unknown/feature'),
                lambda x: x.__setitem__('instance_count', 95)):
            bad = copy.deepcopy(value)
            mutate(bad)
            with self.assertRaises(container.Failure):
                container.project_processing(json.dumps(bad).encode())

    def test_loaded_identities_hash_observed_paths_and_refuse_other_roots(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            candidate = Path(tmp) / 'lsp-plugins-lv2.so'
            candidate.write_bytes(b'inert')
            with patch.object(container, 'LIBRARY', candidate), patch.object(container, 'digest', return_value='a' * 64):
                result = container.loaded_libraries(['lsp-plugins-lv2.so', 'linux-vdso.so.1'],
                                                     [str(candidate), None])
                self.assertEqual(result[0], {'identity': 'candidate/lsp-plugins-lv2.so', 'sha256': 'a' * 64})
                self.assertEqual(result[1]['sha256'], None)
                for names, paths in ((['bad name'], ['/private/lib.so']),
                                     (['lib.so', 'lib.so'], ['/usr/lib/lib.so'] * 2),
                                     (['lib.so'], []), (['lib.so'], ['/etc/passwd'])):
                    with self.assertRaises(container.Failure):
                        container.loaded_libraries(names, paths)

    def test_host_failures_retain_only_closed_feature_port_or_loader_codes(self):
        for mode, code in (('processing', 'required-feature-unsupported'),
                           ('processing', 'port-shape-invalid'), ('loader', 'dlopen-failed')):
            value = {'schema_version': 1, 'mode': mode, 'status': 'FAIL', 'failure_class': code,
                     'audio_devices': 'NOT USED', 'hardware': 'NOT RUN', 'optimization_acceptance': 'NOT RUN'}
            operation = container.project_loader if mode == 'loader' else container.project_processing
            self.rejects('host_' + code, operation, json.dumps(value).encode())
            value['failure_class'] = '/private/plugin-error'
            self.rejects('host_schema', operation, json.dumps(value).encode())

    def test_no_ambient_variables_in_child_environment(self):
        env = container.runtime_environment()
        self.assertEqual(set(env), {'PATH', 'LANG', 'LC_ALL', 'HOME', 'XDG_RUNTIME_DIR', 'LV2_PATH'})
        self.assertEqual(env['LV2_PATH'], '/tmp/offline/lv2')

    def test_command_arguments_deadline_and_owned_group_cleanup(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            process = Mock(pid=12345, returncode=0)
            process.poll.return_value = 0
            with patch.object(container, 'OUT', Path(tmp)), \
                    patch.object(container.subprocess, 'Popen', return_value=process) as popen, \
                    patch.object(container.os, 'killpg') as killpg:
                self.assertEqual(container.command(['/mock-host', '--loader', '/candidate/x'], 'probe', 30), b'')
                call = popen.call_args
                self.assertEqual(call.args[0], ['/mock-host', '--loader', '/candidate/x'])
                self.assertTrue(call.kwargs['start_new_session'])
                self.assertEqual(call.kwargs['cwd'], '/tmp/offline')
                killpg.assert_called_once_with(12345, container.signal.SIGKILL)
                process.wait.assert_called_once_with(timeout=5)

    def test_timeout_kills_owned_group(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            process = Mock(pid=23456)
            process.poll.return_value = None
            with patch.object(container, 'OUT', Path(tmp)), \
                    patch.object(container.subprocess, 'Popen', return_value=process), \
                    patch.object(container.time, 'monotonic', side_effect=[0, 31]), \
                    patch.object(container.os, 'killpg') as killpg:
                self.rejects('timeout', container.command, ['/mock-host'], 'probe', 30)
                killpg.assert_called_once_with(23456, container.signal.SIGKILL)

    def test_failures_are_sanitized_and_inventory_after_still_runs(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            with patch.object(container, 'OUT', Path(tmp)), \
                    patch.object(container, 'assert_isolation'), \
                    patch.object(container, 'inventory', return_value='a' * 64) as inventory, \
                    patch.object(container, 'digest', side_effect=RuntimeError('/private/secret')):
                self.assertEqual(container.main(), 1)
                value = json.loads((Path(tmp) / 'observations.json').read_text())
                self.assertEqual(value['failure_class'], 'internal_error')
                self.assertTrue(value['inventory']['unchanged'])
                self.assertEqual(inventory.call_count, 2)
                self.assertNotIn('/private', json.dumps(value))

    def test_inventory_after_failure_overrides_success(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            with patch.object(container, 'OUT', Path(tmp)), \
                    patch.object(container, 'assert_isolation'), \
                    patch.object(container, 'inventory', side_effect=['a' * 64, container.Failure('inventory')]), \
                    patch.object(container, 'digest', side_effect=container.Failure('header_hash')):
                self.assertEqual(container.main(), 1)
                value = json.loads((Path(tmp) / 'observations.json').read_text())
                self.assertEqual(value['failure_class'], 'inventory_changed')
                self.assertEqual(value['stage'], 'inventory_after')


if __name__ == '__main__':
    unittest.main()
