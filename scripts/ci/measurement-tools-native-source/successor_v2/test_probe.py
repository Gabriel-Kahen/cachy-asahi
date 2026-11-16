#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced MODEL controls for the installed/moved probe; no native actors."""
import ast
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / 'payload/native'
DENIED = []


def fence(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.fork', 'os.forkpty',
                 'os.posix_spawn', 'os.exec', 'pty.spawn', 'resource.setrlimit') or event.startswith(('socket.', 'ctypes.')):
        DENIED.append(event)
        raise AssertionError('portable probe MODEL forbids actors/authority: ' + event)


sys.addaudithook(fence)


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def functions(path, names, namespace=None):
    """Evaluate only named function definitions, never a production module body."""
    tree = ast.parse(path.read_bytes(), filename=str(path))
    chosen = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in chosen} == set(names), 'all selected pure functions exist')
    module = ast.fix_missing_locations(ast.Module(body=chosen, type_ignores=[]))
    scope = dict(need=need, pin=pin, data_pin=pin, encoded=encoded,
                 Path=Path, re=re, json=json, hashlib=hashlib, base64=base64)
    scope.update(namespace or {})
    exec(compile(module, str(path), 'exec'), scope)
    return SimpleNamespace(**{name: scope[name] for name in names})


class ProbeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixed = Path('/opt/native-measurement-tools-alpm-v1')
        cls.probe = functions(PAYLOAD / 'measurement_installed_probe_v2.py',
                              ('natural', 'sandbox', 'probe_commands'), dict(FIXED=cls.fixed))
        cls.contract = json.loads((HERE.parent / 'payload/native/measurement-contract-v1.json').read_bytes())
        cls.producers = {'native/measurement_installed_probe_v2.py':
                         pin((PAYLOAD / 'measurement_installed_probe_v2.py').read_bytes())['sha256']}
        cls.reader = functions(PAYLOAD / 'measurement_reader_v1.py', ('measurement_probe_v2',),
                               dict(PRODUCERS=cls.producers))

    def model(self, label='system'):
        """Finite invented receipts; these represent no executed native operation."""
        cli = Path('/usr/bin/cachy-asahi-measurement-tools') if label == 'system' else (
            self.fixed / 'user-data/moved-prefix/usr/bin/cachy-asahi-measurement-tools')
        root = self.fixed / ('user-data/system/probe' if label == 'system' else 'user-data/relocated/probe')
        prefix = cli.parent.parent
        docs = prefix / 'share/doc/cachy-asahi-measurement-tools'
        runtime = prefix / 'lib/cachy-asahi/measurement-tools-v1/scripts'
        natural = dict(exit=0, reaped=True, ownership='REAPED', group_census='EMPTY_TWICE',
                       output_complete=True, timeout=False, signals=[], error=None, passed=True, seconds=.1)
        namespace = dict(pid=2, proc_self_pid=2, pid_namespace='pid:[200]', sysfs_entries=[])
        p = dict(schema=2, status='PASS_FINITE_PRIVATE_PID_EMPTY_SYSFS_INSTALLED_PROBE',
                 cli=str(cli), root=str(root), label=label,
                 helper_sha256=self.producers['native/measurement_installed_probe_v2.py'],
                 owner_sha256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f',
                 outer_pid_namespace='pid:[100]', namespace=namespace, commands=[], files={},
                 comparison=dict(status='INCOMPLETE', scope='NOT_EXECUTED_ONLY_ONE_OF_TWELVE_SLOTS'),
                 optimization_acceptance='NOT RUN', workload='ONE_OWNED_PRIVATE_PID_SLOT_ONLY',
                 sensors='EMPTY_SYSFS_NO_PHYSICAL_SENSOR_OBSERVATION', performance='NOT_MEASURED',
                 physical_M2='NOT_RUN', release='NOT_ADMITTED')
        for step, argv, expected in self.probe.probe_commands(cli, root):
            output = encoded(namespace) if step == 'namespace' else b'MODEL private command output\n'
            p['commands'].append(dict(step=step, argv=self.probe.sandbox(root) + argv,
                expected=expected, supervision=dict(natural), output_base64=base64.b64encode(output).decode(),
                output_pin=pin(output)))
        def keep(name, value):
            self.keep(p, name, value)
        base = dict(record_type='measurement-base-state', optimization_acceptance='NOT RUN',
                    execution_context='unknown', architecture='aarch64', machine_model=None,
                    device_tree_compatible=None, page_size_bytes=4096, kernel='MODEL kernel',
                    os_release='MODEL ALARM', m2_air_size=None,
                    packages=dict(returncode=0, stdout='MODEL 1-1\n'),
                    repositories=dict(sync_databases=[]))
        state = {k:base[k] for k in ('architecture', 'machine_model', 'device_tree_compatible',
            'page_size_bytes', 'kernel', 'os_release', 'execution_context', 'm2_air_size')}
        state.update(packages='MODEL 1-1\n', repositories=[])
        config = json.loads((HERE.parents[3] / 'packages/tools/cachy-asahi-measurement-tools/experiment.example.json').read_bytes())
        config['argv'] = ['/usr/bin/python3', str(docs / 'smoke_workload.py')]
        config['inputs'] = list(config['argv'])
        keep('base.json', base); keep('candidate.json', base)
        keep('config.json', config)
        conditions_raw = (HERE.parents[3] / 'packages/tools/cachy-asahi-measurement-tools/conditions.example.json').read_bytes()
        conditions = json.loads(conditions_raw)
        keep('conditions.json', conditions_raw)
        source_paths = {'benchmark.py':runtime / 'benchmarks/benchmark.py',
            'benchmark_platform_metrics.py':runtime / 'benchmarks/benchmark_platform_metrics.py',
            'platform_metrics.py':runtime / 'benchmarks/platform_metrics.py',
            'process_group_memory.py':runtime / 'benchmarks/process_group_memory.py',
            'owned_process.py':runtime / 'virtual/owned_process.py',
            'smoke_workload.py':docs / 'smoke_workload.py'}
        inputs = [dict(path=str(path), resolved_path=str(path),
                       sha256=self.contract['recipe']['source_files'][name]['sha256'])
                  for name, path in source_paths.items()]
        inputs.append(dict(path='/usr/bin/python3', resolved_path='/usr/bin/python3.14', sha256='a'*64))
        plan = dict(schema_version=1, record_type='frozen-experiment-plan', config=config,
                    optimization_acceptance='NOT RUN', states=dict(baseline=state, candidate=state), inputs=inputs,
                    baseline_binding=dict(path=str(root / 'base.json'), resolved_path=str(root / 'base.json'),
                                          sha256=p['files']['base.json']['sha256']),
                    candidate_binding=dict(path=str(root / 'candidate.json'), resolved_path=str(root / 'candidate.json'),
                                           sha256=p['files']['candidate.json']['sha256']))
        keep('plan.json', plan)
        source_pins = {key:self.contract['recipe']['source_files'][leaf]['sha256'] for key, leaf in (
            ('collector_sha256', 'platform_metrics.py'), ('owner_sha256', 'owned_process.py'),
            ('adapter_sha256', 'benchmark_platform_metrics.py'))}
        started = dict(schema_version=1, record_type='benchmark-trial',
            plan_sha256=p['files']['plan.json']['sha256'], slot=0, variant='baseline',
            started_at='2026-11-16T00:00:00+00:00', hostname='MODEL ONLY',
            machine_id=config['machine_id'], base_id=config['base_id'], workload_id=config['workload_id'],
            state=state, conditions=conditions, argv=config['argv'], cwd=str(root),
            environment_sha256='b'*64, comparable_environment_sha256='c'*64,
            declared_environment={'MEASUREMENT_CONTROL':'baseline'},
            execution_label='aarch64/unknown nonacceptance smoke', optimization_acceptance='NOT RUN')
        keep('trial/started.json', started)
        keep('trial/stdout.txt', b'MODEL owned workload output\n')
        keep('trial/stderr.txt', b'')
        keep('trial/telemetry.jsonl', dict(monotonic_ns=30,
            memory=dict(root_rss_kib=None, lifecycle='unknown'), thermal=[], power=[], battery=[],
            missing=['memory', 'thermal', 'power', 'battery']))
        inventory = dict(schema='cachy-asahi-platform-metrics-v1', sysfs_root='/sys', sensors=[], devices=[],
                         classes={name:dict(status='absent', devices=[]) for name in ('power_supply', 'thermal', 'hwmon')})
        summary = dict(schema='cachy-asahi-platform-metrics-v1', sensor_count=0, sensors=[],
            max_gap_seconds=.25, window_monotonic_start_ns=30, window_monotonic_end_ns=60)
        def clocks(n):
            return dict(monotonic_ns=n, boottime_ns=n+1000, realtime_ns=n+2000)
        samples = b''.join(encoded(dict(sequence=i, start=clocks(10+60*i),
            end=clocks(20+60*i), readings=[])) for i in range(2))
        machine = dict(architecture='aarch64')
        binding = dict(machine_before=machine, machine_after=machine, start=clocks(30), end=clocks(60),
                       argv_sha256=hashlib.sha256((json.dumps(config['argv'], sort_keys=True,
                           separators=(',', ':'))+'\n').encode()).hexdigest(), cwd=str(root))
        for part in ('trial/platform-metrics', 'capture'):
            keep(part + '/inventory.json', inventory)
            keep(part + '/samples.jsonl', samples)
            schema = 'benchmark-platform-metrics-v1' if part.startswith('trial') else 'cachy-asahi-platform-metrics-v1'
            capture = dict(schema=schema, completed=True,
                files={leaf:{k:p['files'][part+'/'+leaf][k] for k in ('bytes', 'sha256')}
                       for leaf in ('inventory.json', 'samples.jsonl')})
            if part.startswith('trial'):
                capture_started = dict(schema=schema, completed=False, machine_before=machine,
                    max_gap_seconds=.25, interval_seconds_requested=.1, **source_pins)
                capture.update(capture_started, completed=True, supervision=dict(natural), worker_stopped=True,
                    sampling=dict(bytes=len(samples), error=None, snapshot_seconds=[.001, .001]),
                    machine_after=machine, workload=binding, unresolved_wait_pid=None)
            else:
                capture_started = dict(schema=schema, completed=False,
                    collector={k:self.contract['recipe']['source_files']['platform_metrics.py'][k]
                        for k in ('bytes', 'sha256')}, duration_seconds_requested=.2, interval_seconds_requested=.1,
                    machine_label='finite private empty-sysfs probe',
                    machine_label_source='operator; not hardware authentication', notes=[], references=[],
                    machine=machine, max_gap_seconds=.25, start=clocks(10), limits=dict(MODEL=1))
                capture.update(capture_started, completed=True, sample_count=2)
            keep(part + '/started.json', capture_started)
            keep(part + '/capture.json', capture)
            keep(part + '/summary.json', summary)
        keep('replay.json', dict(summary, inputs=self.doc(p, 'capture/capture.json')['files']))
        trial = dict(started, valid=True, returncode=0, error=None, state_after=state,
            metrics=dict(root_rss_kib=None), sampling_status=dict(worker_stopped=True, workload_reaped=True,
                error=None, dropped_samples=0), platform_metrics=dict(schema='benchmark-platform-metrics-v1',
                source_pins=source_pins, binding=binding, optimization_acceptance='NOT RUN'),
            elapsed_ns=30, monotonic_start_ns=30, monotonic_end_ns=60)
        keep('trial/trial.json', trial)
        self.refresh_raw(p)
        return p, cli, root

    def keep(self, p, name, value):
        raw = value if type(value) is bytes else encoded(value)
        p['files'][name] = dict(pin(raw), base64=base64.b64encode(raw).decode())

    def doc(self, p, name):
        return json.loads(base64.b64decode(p['files'][name]['base64']))

    def refresh_raw(self, p):
        trial = self.doc(p, 'trial/trial.json')
        trial['raw_sha256'] = {name[len('trial/'):]:row['sha256'] for name, row in p['files'].items()
            if name.startswith('trial/') and name not in ('trial/started.json', 'trial/trial.json')}
        self.keep(p, 'trial/trial.json', trial)

    def check(self, p, cli, root):
        return self.reader.measurement_probe_v2(encoded(p), cli, root, self.contract)

    def test_01_no_actor_attempts(self):
        self.assertEqual(DENIED, [])

    def test_02_payloads_parse(self):
        for leaf in ('measurement_tools_v1.py', 'measurement_reader_v1.py',
                     'measurement_installed_probe_v2.py'):
            ast.parse((PAYLOAD / leaf).read_bytes(), filename=leaf)

    def test_03_exact_natural_retirement(self):
        state = dict(exit=0, reaped=True, ownership='REAPED', group_census='EMPTY_TWICE',
                     output_complete=True, timeout=False, signals=[], error=None, passed=True, seconds=.1)
        self.probe.natural(state, 0)
        for key, value in (('exit', False), ('exit', 1), ('reaped', 1), ('reaped', False),
                           ('ownership', 'UNKNOWN'), ('group_census', 'EMPTY_ONCE'),
                           ('group_census', 'RESERVED_LEADER_ONLY'), ('output_complete', False),
                           ('timeout', True), ('signals', ['SIGTERM']), ('error', 'MODEL failure'),
                           ('passed', False), ('seconds', True), ('seconds', -1), ('seconds', 20),
                           ('seconds', float('nan')), ('seconds', float('inf'))):
            changed = dict(state, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.probe.natural(changed, 0)

    def test_04_missing_retirement_facts_refuse(self):
        state = dict(exit=0, reaped=True, ownership='REAPED', group_census='EMPTY_TWICE',
                     output_complete=True, timeout=False, signals=[], error=None, passed=True, seconds=.1)
        for key in state:
            changed = dict(state)
            del changed[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.probe.natural(changed, 0)

    def test_05_private_pid_proc_empty_sysfs_argv(self):
        root = self.fixed / 'user-data/system/probe'
        self.assertEqual(self.probe.sandbox(root), ['/usr/bin/bwrap', '--die-with-parent',
            '--ro-bind', '/', '/', '--bind', str(root), str(root), '--dev', '/dev',
            '--tmpfs', '/sys', '--unshare-net', '--unshare-pid', '--proc', '/proc', '--'])

    def test_06_one_slot_has_no_comparison_or_signing(self):
        for cli, root in ((Path('/usr/bin/cachy-asahi-measurement-tools'), self.fixed / 'user-data/system/probe'),
                          (self.fixed / 'user-data/moved-prefix/usr/bin/cachy-asahi-measurement-tools',
                           self.fixed / 'user-data/relocated/probe')):
            commands = self.probe.probe_commands(cli, root)
            self.assertEqual([name for name, _, _ in commands],
                             ['namespace', 'state', 'prepare-plan', 'trial', 'capture', 'summarize'])
            self.assertTrue(all(code == 0 and type(code) is int for _, _, code in commands))
            self.assertEqual(commands[0][1], ['/usr/bin/python3', '-I', '-B',
                str(self.fixed / 'source/native/measurement_installed_probe_v2.py'), '--namespace-check'])
            trial = commands[3][1]
            self.assertEqual(trial[:3], [str(cli), 'benchmark', 'run'])
            self.assertEqual(trial[trial.index('--slot') + 1], '0')
            self.assertEqual(trial[-1], '--platform-metrics')
            capture = commands[4][1]
            self.assertEqual(capture[capture.index('--duration') + 1], '.2')
            self.assertEqual(capture[capture.index('--interval') + 1], '.1')
            self.assertFalse(any(word in ('compare', 'gpg', 'pacman', 'docker')
                                 for _, argv, _ in commands for word in argv))

    def namespace_model(self, raw=b'42 (MODEL private child) S 1 2 3\n', entries=(), denied=False):
        calls = []
        class SysRoot:
            def __init__(self, path):
                need(path == '/sys', 'only modeled sysfs path')
            def iterdir(self):
                return iter(entries)
        def opened(path, flags):
            calls.append(('open', path, flags))
            return 7
        def read(fd, cap):
            self.assertEqual((fd, cap), (7, 4097))
            if denied:
                raise PermissionError('MODEL proc denied')
            return raw
        fake = SimpleNamespace(getpid=lambda: 42, open=opened, read=read,
            close=lambda fd: calls.append(('close', fd)),
            readlink=lambda path: 'pid:[100]' if path == '/proc/self/ns/pid' else None,
            O_RDONLY=0, O_CLOEXEC=1, O_NOFOLLOW=2)
        probe = functions(PAYLOAD / 'measurement_installed_probe_v2.py', ('namespace_check',),
                          dict(os=fake, Path=SysRoot))
        return probe, calls

    def test_07_proc_virtual_zero_size_does_not_prevent_bounded_self_read(self):
        probe, calls = self.namespace_model()
        self.assertEqual(probe.namespace_check(), dict(pid=42, proc_self_pid=42,
            pid_namespace='pid:[100]', sysfs_entries=[]))
        self.assertEqual(calls, [('open', '/proc/self/stat', 3), ('close', 7)])

    def test_08_proc_identity_overflow_and_nonempty_sysfs_refuse(self):
        for raw, entries in ((b'', ()), (b'x' * 4097, ()),
                             (b'43 (foreign MODEL PID) S\n', ()),
                             (b'42 (MODEL child) S\n', ('MODEL sensor',))):
            probe, calls = self.namespace_model(raw, entries)
            with self.subTest(raw=raw[:30], entries=entries), self.assertRaises(ValueError):
                probe.namespace_check()
            self.assertEqual(calls[-1], ('close', 7))

    def test_09_proc_denial_is_not_an_empty_or_zero_observation(self):
        probe, calls = self.namespace_model(denied=True)
        with self.assertRaises(PermissionError):
            probe.namespace_check()
        self.assertEqual(calls[-1], ('close', 7))

    def test_10_reader_matches_both_complete_modeled_prefixes_without_acceptance(self):
        for label in ('system', 'moved'):
            p, cli, root = self.model(label)
            result = self.check(p, cli, root)
            self.assertEqual(result, dict(
                status='MATCHED_FINITE_PRIVATE_PID_EMPTY_SYSFS_INSTALLED_PROBE_DATA_ONLY',
                files=21, commands=6, trial_slot=0, comparison='INCOMPLETE_NOT_EXECUTED',
                optimization_acceptance='NOT RUN'))

    def refuses(self, p, cli, root):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.check(p, cli, root)

    def change_doc(self, p, name, mutate, refresh=True):
        value = self.doc(p, name)
        mutate(value)
        self.keep(p, name, value)
        if refresh:
            self.refresh_raw(p)

    def test_11_report_identity_source_and_credit_cannot_be_substituted(self):
        original, cli, root = self.model()
        for key, value in (('cli', '/tmp/foreign'), ('root', '/tmp/foreign'), ('label', 'moved'),
                           ('schema', 1), ('status', 'FAIL'), ('helper_sha256', 'f'*64),
                           ('owner_sha256', 'f'*64), ('optimization_acceptance', 'PASS'),
                           ('performance', 'IMPROVED'), ('physical_M2', 'PASS'), ('release', 'ADMITTED'),
                           ('comparison', dict(status='PASS', scope='MEASURED_GAIN'))):
            p = copy.deepcopy(original)
            p[key] = value
            with self.subTest(key=key):
                self.refuses(p, cli, root)
        self.refuses(original, '/tmp/foreign', root)
        self.refuses(original, cli, '/tmp/foreign')

    def test_12_missing_duplicated_reordered_or_modified_commands_refuse(self):
        original, cli, root = self.model()
        for kind in ('missing', 'duplicate', 'order', 'argv', 'network', 'pid', 'proc', 'sysfs', 'expected'):
            p = copy.deepcopy(original)
            rows = p['commands']
            if kind == 'missing': rows.pop()
            elif kind == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            elif kind == 'order': rows[1], rows[2] = rows[2], rows[1]
            elif kind == 'argv': rows[3]['argv'][-1] = '--unowned-legacy'
            elif kind == 'expected': rows[0]['expected'] = False
            else:
                arg = {'network':'--unshare-net', 'pid':'--unshare-pid', 'proc':'--proc', 'sysfs':'--tmpfs'}[kind]
                rows[0]['argv'].remove(arg)
            with self.subTest(kind=kind): self.refuses(p, cli, root)

    def test_13_every_command_requires_complete_natural_retirement(self):
        original, cli, root = self.model()
        for index in range(6):
            for key, value in (('exit', 1), ('exit', False), ('reaped', False), ('ownership', 'UNKNOWN'),
                               ('group_census', 'UNKNOWN'), ('output_complete', False), ('timeout', True),
                               ('signals', ['SIGKILL']), ('error', 'MODEL failure'), ('passed', False),
                               ('seconds', 20), ('seconds', True)):
                p = copy.deepcopy(original)
                p['commands'][index]['supervision'][key] = value
                with self.subTest(index=index, key=key): self.refuses(p, cli, root)
            p = copy.deepcopy(original)
            del p['commands'][index]['supervision']['error']
            self.refuses(p, cli, root)

    def test_14_namespace_and_raw_stdout_join_refuse_spoofing(self):
        original, cli, root = self.model()
        for key, value in (('pid', True), ('proc_self_pid', 3), ('pid_namespace', 'pid:[100]'),
                           ('pid_namespace', 'unobserved'), ('sysfs_entries', ['MODEL real sensor'])):
            p = copy.deepcopy(original)
            p['namespace'][key] = value
            with self.subTest(key=key): self.refuses(p, cli, root)
        for key, value in (('output_base64', base64.b64encode(b'forged').decode()),
                           ('output_pin', pin(b'forged'))):
            p = copy.deepcopy(original)
            p['commands'][0][key] = value
            self.refuses(p, cli, root)

    def test_15_file_namespace_base64_whole_pins_and_bounds_are_closed(self):
        original, cli, root = self.model()
        for kind in ('missing', 'extra', 'base64', 'bytes', 'bool', 'hash', 'bound'):
            p = copy.deepcopy(original)
            if kind == 'missing': del p['files']['capture/started.json']
            elif kind == 'extra': p['files']['extra'] = dict(pin(b''), base64='')
            elif kind == 'base64': p['files']['plan.json']['base64'] = '!invalid!'
            elif kind == 'bytes': p['files']['plan.json']['bytes'] += 1
            elif kind == 'bool': p['files']['trial/stderr.txt']['bytes'] = False
            elif kind == 'hash': p['files']['plan.json']['sha256'] = 'f'*64
            else: self.keep(p, 'trial/stdout.txt', b'x'*(128*1024+1))
            with self.subTest(kind=kind): self.refuses(p, cli, root)

    def test_16_plan_inputs_are_exact_installed_source_bodies(self):
        original, cli, root = self.model('moved')
        for kind in ('sha256', 'resolved_path', 'path', 'missing', 'duplicate'):
            p = copy.deepcopy(original)
            plan = self.doc(p, 'plan.json')
            if kind in ('sha256', 'resolved_path', 'path'): plan['inputs'][0][kind] = 'f'*64
            elif kind == 'missing': plan['inputs'].pop()
            else: plan['inputs'][-1] = copy.deepcopy(plan['inputs'][0])
            self.keep(p, 'plan.json', plan)
            trial = self.doc(p, 'trial/trial.json')
            trial['plan_sha256'] = p['files']['plan.json']['sha256']
            self.keep(p, 'trial/trial.json', trial)
            with self.subTest(kind=kind): self.refuses(p, cli, root)

    def test_17_trial_flags_cannot_replace_raw_ownership_and_state_evidence(self):
        original, cli, root = self.model()
        for key, value in (('valid', 1), ('valid', False), ('slot', True), ('variant', 'candidate'),
                           ('returncode', 1), ('returncode', False), ('error', 'MODEL failure'),
                           ('plan_sha256', 'f'*64), ('state_after', {}), ('conditions', {}),
                           ('optimization_acceptance', 'PASS'), ('metrics', dict(root_rss_kib=0))):
            p = copy.deepcopy(original)
            self.change_doc(p, 'trial/trial.json', lambda trial: trial.update({key:value}))
            with self.subTest(key=key): self.refuses(p, cli, root)
        p = copy.deepcopy(original)
        self.change_doc(p, 'trial/trial.json', lambda trial: trial.pop('error'))
        self.refuses(p, cli, root)

    def test_18_raw_trial_artifact_hashes_are_not_report_flags(self):
        p, cli, root = self.model()
        self.keep(p, 'trial/stdout.txt', b'MODEL different output\n')
        self.refuses(p, cli, root)

    def test_19_missing_unknown_or_boolean_sampling_facts_refuse(self):
        original, cli, root = self.model()
        for key, value in (('worker_stopped', False), ('workload_reaped', False), ('error', 'MODEL gap'),
                           ('dropped_samples', False), ('dropped_samples', 1)):
            p = copy.deepcopy(original)
            self.change_doc(p, 'trial/trial.json', lambda trial: trial['sampling_status'].update({key:value}))
            with self.subTest(key=key): self.refuses(p, cli, root)
        p = copy.deepcopy(original)
        self.change_doc(p, 'trial/trial.json', lambda trial: trial['sampling_status'].pop('error'))
        self.refuses(p, cli, root)

    def test_20_sensor_absence_is_not_sensor_zero_or_missing_inventory(self):
        original, cli, root = self.model()
        for kind in ('sensor', 'device', 'class', 'unknown', 'summary'):
            p = copy.deepcopy(original)
            name = 'capture/summary.json' if kind == 'summary' else 'capture/inventory.json'
            value = self.doc(p, name)
            if kind == 'sensor': value['sensors'] = [dict(value=0)]
            elif kind == 'device': value['devices'] = ['MODEL sensor']
            elif kind == 'class': del value['classes']['hwmon']
            elif kind == 'unknown': value['classes']['thermal']['status'] = 'unknown'
            else: value['sensor_count'] = False
            self.keep(p, name, value)
            if name.endswith('inventory.json'):
                capture = self.doc(p, 'capture/capture.json')
                capture['files']['inventory.json'] = {k:p['files'][name][k] for k in ('bytes', 'sha256')}
                self.keep(p, 'capture/capture.json', capture)
            with self.subTest(kind=kind): self.refuses(p, cli, root)

    def test_21_empty_or_modified_prelaunch_records_refuse_after_repin(self):
        original, cli, root = self.model()
        for name in ('trial/started.json', 'trial/platform-metrics/started.json', 'capture/started.json'):
            for kind in ('empty', 'changed'):
                p = copy.deepcopy(original)
                value = {} if kind == 'empty' else self.doc(p, name)
                if kind == 'changed':
                    value['schema'] = 'MODEL wrong schema' if 'schema' in value else 1
                self.keep(p, name, value)
                self.refresh_raw(p)
                with self.subTest(name=name, kind=kind): self.refuses(p, cli, root)

    def test_22_standalone_replay_must_match_original_raw_summary(self):
        p, cli, root = self.model()
        self.change_doc(p, 'replay.json', lambda doc: doc.update(sensor_count=1))
        self.refuses(p, cli, root)

    def test_23_duplicate_nonfinite_and_oversized_outer_json_refuse(self):
        p, cli, root = self.model()
        for raw in (b'{"schema":2,"schema":2}', b'{"schema":NaN}', b'x'*(1024**2+1), b''):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                self.reader.measurement_probe_v2(raw, cli, root, self.contract)

    def samples(self, p, part, mutate):
        name = part + '/samples.jsonl'
        lines = base64.b64decode(p['files'][name]['base64']).splitlines()
        rows = [json.loads(line) for line in lines]
        mutate(rows)
        raw = b''.join(encoded(row) for row in rows)
        self.keep(p, name, raw)
        capture = self.doc(p, part + '/capture.json')
        capture['files']['samples.jsonl'] = pin(raw)
        if part.startswith('trial'):
            capture['sampling']['bytes'] = len(raw)
            capture['sampling']['snapshot_seconds'] = [.001] * len(rows)
        else:
            capture['sample_count'] = len(rows)
        self.keep(p, part + '/capture.json', capture)
        self.refresh_raw(p)

    def test_24_raw_sample_counts_order_clocks_and_readings_are_independent_facts(self):
        original, cli, root = self.model()
        for part in ('trial/platform-metrics', 'capture'):
            for kind in ('single', 'too-many', 'sequence', 'bool-sequence', 'clock', 'clock-type', 'reading', 'missing-clock'):
                p = copy.deepcopy(original)
                def mutate(rows):
                    if kind == 'single': rows.pop()
                    elif kind == 'too-many': rows[:] = rows * 33
                    elif kind == 'sequence': rows[1]['sequence'] = 0
                    elif kind == 'bool-sequence': rows[0]['sequence'] = False
                    elif kind == 'clock': rows[1]['start']['monotonic_ns'] = 1
                    elif kind == 'clock-type': rows[0]['start']['monotonic_ns'] = True
                    elif kind == 'reading': rows[0]['readings'] = [dict(value=0)]
                    else: del rows[0]['start']['boottime_ns']
                self.samples(p, part, mutate)
                with self.subTest(part=part, kind=kind): self.refuses(p, cli, root)

    def test_25_workload_capture_requires_bounded_natural_reap_and_no_unresolved_pid(self):
        original, cli, root = self.model()
        name = 'trial/platform-metrics/capture.json'
        for key, value in (('reaped', False), ('ownership', 'UNKNOWN'), ('exit', False), ('passed', False),
                           ('seconds', 2.5), ('seconds', True), ('signals', ['SIGTERM'])):
            p = copy.deepcopy(original)
            self.change_doc(p, name, lambda capture: capture['supervision'].update({key:value}))
            with self.subTest(key=key): self.refuses(p, cli, root)
        for key, value in (('unresolved_wait_pid', 42), ('worker_stopped', False), ('completed', False),
                           ('failure', ''), ('schema', 'cachy-asahi-platform-metrics-v1')):
            p = copy.deepcopy(original)
            self.change_doc(p, name, lambda capture: capture.update({key:value}))
            with self.subTest(key=key): self.refuses(p, cli, root)
        p = copy.deepcopy(original)
        self.change_doc(p, name, lambda capture: capture.pop('unresolved_wait_pid'))
        self.refuses(p, cli, root)

    def test_26_workload_bindings_and_clock_brackets_survive_repinning(self):
        original, cli, root = self.model()
        for kind in ('argv', 'cwd', 'clock-zero', 'clock-reversal', 'unbracketed', 'origin', 'elapsed'):
            p = copy.deepcopy(original)
            trial = self.doc(p, 'trial/trial.json')
            capture = self.doc(p, 'trial/platform-metrics/capture.json')
            binding = copy.deepcopy(trial['platform_metrics']['binding'])
            if kind == 'argv': binding['argv_sha256'] = 'f'*64
            elif kind == 'cwd': binding['cwd'] = '/tmp/foreign'
            elif kind == 'clock-zero': binding['start']['monotonic_ns'] = 0
            elif kind == 'clock-reversal': binding['end']['realtime_ns'] = binding['start']['realtime_ns'] - 1
            elif kind == 'unbracketed': binding['start']['monotonic_ns'] = 1
            elif kind == 'origin': binding['start']['boottime_ns'] += 60_000_000
            else: trial['elapsed_ns'] = 1
            trial['platform_metrics']['binding'] = binding
            capture['workload'] = binding
            self.keep(p, 'trial/platform-metrics/capture.json', capture)
            self.keep(p, 'trial/trial.json', trial)
            self.refresh_raw(p)
            with self.subTest(kind=kind): self.refuses(p, cli, root)

    def test_27_capture_accounting_has_no_boolean_or_missing_zero_shortcut(self):
        original, cli, root = self.model()
        name = 'trial/platform-metrics/capture.json'
        for key, value in (('bytes', False), ('bytes', 0), ('snapshot_seconds', []),
                           ('snapshot_seconds', [False, .001]), ('snapshot_seconds', [2.5, .001]),
                           ('error', 'MODEL sampling gap')):
            p = copy.deepcopy(original)
            self.change_doc(p, name, lambda capture: capture['sampling'].update({key:value}))
            with self.subTest(key=key): self.refuses(p, cli, root)

    def test_28_legacy_missing_guardrails_stay_unknown(self):
        original, cli, root = self.model()
        for key, value in (('memory', dict(root_rss_kib=0, lifecycle='live')),
                           ('thermal', [dict(value=0)]), ('missing', []), ('monotonic_ns', 1)):
            p = copy.deepcopy(original)
            self.change_doc(p, 'trial/telemetry.jsonl', lambda doc: doc.update({key:value}))
            with self.subTest(key=key): self.refuses(p, cli, root)

    def test_29_exact_original_conditions_and_nested_nonacceptance_survive(self):
        original, cli, root = self.model()
        p = copy.deepcopy(original)
        self.change_doc(p, 'conditions.json', lambda doc: doc.update(notes='MODEL changed conditions'))
        self.refuses(p, cli, root)
        for name in ('base.json', 'plan.json', 'capture/summary.json'):
            p = copy.deepcopy(original)
            self.change_doc(p, name, lambda doc: doc.update(nested=dict(optimization_acceptance='PASS')))
            with self.subTest(name=name): self.refuses(p, cli, root)

    def test_30_reader_validator_has_no_artifact_code_or_actor_imports(self):
        tree = ast.parse((PAYLOAD / 'measurement_reader_v1.py').read_bytes())
        validator = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == 'measurement_probe_v2')
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(validator)))
        self.assertFalse(any(isinstance(node, ast.Name) and node.id in (
            'exec', 'eval', 'compile', 'importlib', 'subprocess', 'socket', 'ctypes')
            for node in ast.walk(validator)))
        self.assertEqual(DENIED, [])

    def failure_main(self, launch_failure=False):
        """Run the real command-loop and main AST against a finite owned-child MODEL."""
        cli = Path('/usr/bin/cachy-asahi-measurement-tools')
        root = self.fixed / 'user-data/system/probe'
        output = io.BytesIO()
        events = []
        denied = b'bwrap: MODEL namespace creation denied\n'
        class Parser:
            def __init__(self, **kwargs): pass
            def add_argument(self, *args, **kwargs): pass
            def parse_args(self):
                return SimpleNamespace(cli=cli, root=root, label='system', namespace_check=False)
        def popen(argv, **kwargs):
            events.append(('Popen', argv))
            if launch_failure:
                raise FileNotFoundError('MODEL private executable path must not leak')
            return SimpleNamespace(returncode=None, _child_created=False)
        def supervise(child, **kwargs):
            events.append(('supervise', kwargs))
            return dict(exit=1, reaped=True, ownership='REAPED', group_census='EMPTY_TWICE',
                output_complete=True, timeout=False, signals=[], error=None,
                passed=False, seconds=.01, output=denied)
        source = ast.parse((PAYLOAD / 'measurement_installed_probe_v2.py').read_bytes())
        run = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        loop = next(node for node in run.body if isinstance(node, ast.For)
                    and isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name)
                    and node.iter.func.id == 'probe_commands')
        holder = ast.parse("def loop_model(report):\n commands=report['commands']\n pass\n")
        holder.body[0].body[-1] = copy.deepcopy(loop)
        environment = dict(need=need, json=json, base64=base64, pin=pin,
            cli=cli, root=root, natural=self.probe.natural,
            sandbox=self.probe.sandbox,
            probe_commands=lambda cli, root: [self.probe.probe_commands(cli, root)[0]],
            owner=SimpleNamespace(prepare=lambda:events.append(('prepare',)), supervise=supervise),
            subprocess=SimpleNamespace(Popen=popen, DEVNULL='MODEL DEVNULL', PIPE='MODEL PIPE'),
            signal=SimpleNamespace(SIGTERM=15, getsignal=lambda signum:'MODEL previous handler',
                signal=lambda signum, handler:events.append(('signal', signum, handler))))
        exec(compile(ast.fix_missing_locations(holder), '<real probe loop MODEL>', 'exec'), environment)
        def run_model(actual_cli, actual_root, label, report):
            self.assertEqual((actual_cli, actual_root, label), (cli, root, 'system'))
            report.update(schema=2, status='FAIL', phase='initialize', commands=[], files={},
                optimization_acceptance='NOT RUN', performance='NOT_MEASURED',
                physical_M2='NOT_RUN', release='NOT_ADMITTED')
            return environment['loop_model'](report)
        main = functions(PAYLOAD / 'measurement_installed_probe_v2.py', ('main',),
            dict(argparse=SimpleNamespace(ArgumentParser=Parser), run=run_model,
                 sys=SimpleNamespace(stdout=SimpleNamespace(buffer=output)),
                 __doc__='Finite failure MODEL only'))
        code = main.main()
        return code, json.loads(output.getvalue()), output.getvalue(), events, denied

    def test_31_namespace_denial_retains_actual_attempt_argv_and_raw_output_in_failure_json(self):
        code, result, raw, events, denied = self.failure_main()
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['first_failure'], dict(phase='namespace', type='ValueError'))
        self.assertEqual(len(result['commands']), 1)
        row = result['commands'][0]
        self.assertEqual(row['step'], 'namespace')
        self.assertEqual(row['argv'], next(event[1] for event in events if event[0] == 'Popen'))
        self.assertEqual(row['output_pin'], pin(denied))
        self.assertEqual(base64.b64decode(row['output_base64']), denied)
        self.assertEqual(row['supervision']['exit'], 1)
        self.assertEqual(result['files'], {})
        self.assertEqual(result['optimization_acceptance'], 'NOT RUN')
        self.assertEqual(sum(event[0] == 'supervise' for event in events), 1)
        self.assertEqual(events[-1], ('signal', 15, 'MODEL previous handler'))
        self.assertNotIn(b'private executable path', raw)

    def test_32_launch_failure_retains_attempt_without_a_second_wait_or_false_pass(self):
        code, result, raw, events, _ = self.failure_main(launch_failure=True)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['first_failure'], dict(phase='namespace', type='FileNotFoundError'))
        self.assertEqual(result['commands'][0]['supervision'], None)
        self.assertEqual(result['commands'][0]['output_pin'], pin(b''))
        self.assertEqual(result['commands'][0]['output_base64'], '')
        self.assertEqual(sum(event[0] == 'supervise' for event in events), 0)
        self.assertEqual(events[-1], ('signal', 15, 'MODEL previous handler'))
        self.assertNotIn(b'private executable path', raw)
        self.assertEqual(DENIED, [])


if __name__ == '__main__':
    unittest.main()
