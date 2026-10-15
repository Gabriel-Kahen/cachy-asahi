"""Inert graph/report controls only: no compiler, plugin, service or container."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/ci/asahi-lsp-offline/container.py').is_file())
spec = importlib.util.spec_from_file_location('graph_container_test', HERE / 'container.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
COMMON = c.s.held('container', ROOT / 'scripts/ci/asahi-lsp-offline')


def host_row(case, expect='positive'):
    positive = expect == 'positive'; controls = 326 if case['kind'] == 'graph' else 57
    counts = dict.fromkeys(c.COUNTS, 0)
    if positive:
        counts.update(nodes=case['nodes'], lv2=case['lv2_instances'], builtin=case['builtin_instances'],
                      convolvers=case['convolvers'], links=case['links'], controls=controls, readbacks=controls)
    gates = dict.fromkeys(c.GATES, positive); gates['retired'] = True
    candidates = c.candidate_hashes()
    libraries = []
    if positive:
        names = ('bankstown', 'lsp-plugins-lv2') if case['kind'] == 'graph' else ('triforce-lv2',)
        libraries = [candidates[name] for name in names] + [
            {'identity': 'system/' + str(Path(p).relative_to('/usr/lib')), 'sha256': 'a' * 64}
            for p in c.ENGINE_PATHS.values()]
    firs = {x['path']: x for x in c.s.graphs()['firs']}; selections = []
    if positive:
        for node in case['expected']['filter.graph']['nodes']:
            if node.get('label') == 'convolver':
                identity = next(p.lstrip('/') for p in node['config']['filename'] if p.endswith('-48.wav'))
                selections.append({'node': node['name'], 'identity': identity, 'rate': 48000,
                                   'sha256': firs[identity]['sha256']})
    return dict(schema='asahi-audio-offline-graph-host-v1', status='PASS' if positive else 'FAIL',
                failure_class=None if positive else c.NEGATIVES[expect], case=case['id'], expect=expect,
                rate=48000, process_calls=0, counts=counts, gates=gates,
                stage_names=[n['name'] for n in case['expected']['filter.graph']['nodes']] if positive else [],
                fir_selections=selections, libraries=libraries, cleanup=dict.fromkeys(c.CLEANUP, True),
                raw_sha256=case['raw_sha256'] if positive else 'b' * 64)


def passing():
    candidates = {k: v['sha256'] for k, v in c.candidate_hashes().items()}
    elf = {}
    for name in ('host', *c.ENGINE_PATHS, *candidates):
        elf[name] = {'class': 'ELF64', 'machine': 'AArch64', 'needed': ['libc.so.6'],
                     'path_tags': [], 'version_requirements': ['GLIBC_2.17'],
                     'sha256': candidates.get(name, 'a' * 64), 'load_segments': 2,
                     'structural_16k': 'PASS', 'hardware_status': 'NOT RUN'}
    return dict(schema_version=1, status='PASS', failure_class=None, stage='complete',
                inventory=dict(count=574, before_sha256=c.s.LOCK, after_sha256=c.s.LOCK, unchanged=True),
                headers={k: v[1] for k, v in {**COMMON.HEADERS, **c.GRAPH_HEADERS}.items()},
                tools=dict.fromkeys(('gcc', 'pkg-config', 'readelf', 'spa-json-dump'), 'a' * 64),
                engines=dict.fromkeys(c.ENGINE_PATHS, 'a' * 64), candidates=candidates,
                host=dict(sha256='a' * 64, source_sha256=c.s.sha(HERE / 'host.c'),
                          compile_flags=['-std=gnu11', *COMMON.FLAGS[1:], '-lpipewire-0.3', '-llilv-0', '-lserd-0', '-ldl', '-lm']),
                elf=elf, parsing=[dict(id=r['id'], raw_sha256=r['raw_sha256'], status='PASS',
                                      full_equality=True, converter='spa-json-dump') for r in c.s.cases().values()],
                positive_cases=[host_row(r) for r in c.s.cases().values()],
                negative_controls=[host_row(c.s.cases()['j413-speakers'], name) for name in c.s.CONTROLS],
                host_children=12, converter_children=4, safety=copy.deepcopy(c.SAFETY))


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.held = patch.object(c, 'common', return_value=COMMON); self.held.start(); self.addCleanup(self.held.stop)
        self.source = patch.object(c.s, 'sha', return_value='a' * 64); self.source.start(); self.addCleanup(self.source.stop)

    def rejects(self, value):
        with self.assertRaises(COMMON.Failure): c.validate_public(value)

    def test_complete_four_plus_eight_closed_projection(self):
        value = passing(); self.assertIs(c.validate_public(value), value)
        self.assertEqual(sum(x['counts']['nodes'] for x in value['positive_cases']), 36)
        self.assertEqual(sum(x['counts']['lv2'] for x in value['positive_cases']), 12)
        self.assertEqual(sum(x['counts']['convolvers'] for x in value['positive_cases']), 8)

    def test_converter_projection_compares_every_field_and_type(self):
        for case in c.s.cases().values():
            self.assertEqual(c.parse_graph(json.dumps(case['expected']).encode(), case)['status'], 'PASS')
            bad = copy.deepcopy(case['expected']); bad['filter.graph']['nodes'][0]['control']['extra'] = 1
            with self.assertRaises(COMMON.Failure): c.parse_graph(json.dumps(bad).encode(), case)
        case = c.s.cases()['j413-speakers']; bad = copy.deepcopy(case['expected'])
        bad['filter.graph']['nodes'][0]['control']['bypass'] = False
        with self.assertRaises(COMMON.Failure): c.parse_graph(json.dumps(bad).encode(), case)

    def test_standard_decoder_rejects_duplicates_nonfinite_and_trailing(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e1000}', b'{} {}',
                    ('{"a":' + '9' * 1000 + '}').encode()):
            with self.assertRaises(COMMON.Failure): c.strict_json(raw)

    def test_cannot_skip_duplicate_cases_or_children(self):
        for mutate in (lambda v: v.update(host_children=11), lambda v: v.update(converter_children=3),
                       lambda v: v['positive_cases'].__setitem__(1, copy.deepcopy(v['positive_cases'][0])),
                       lambda v: v['negative_controls'].pop(),
                       lambda v: v['parsing'][0].update(full_equality=False)):
            value = passing(); mutate(value); self.rejects(value)

    def test_no_processing_or_weak_cleanup_credit(self):
        for mutate in (lambda r: r.update(process_calls=1), lambda r: r['cleanup'].update(children_unloaded=False),
                       lambda r: r['gates'].update(retired=False), lambda r: r.update(rate=44100),
                       lambda r: r.update(process_calls=False), lambda r: r.update(private_log='/private')):
            value = passing(); mutate(value['positive_cases'][0]); self.rejects(value)

    def test_corrupt_counts_stage_controls_and_readbacks_refuse(self):
        for mutate in (lambda r: r['counts'].update(lv2=4), lambda r: r['counts'].update(readbacks=325),
                       lambda r: r['counts'].update(controls=999), lambda r: r['gates'].update(controls=False),
                       lambda r: r['stage_names'].pop(), lambda r: r['stage_names'].__setitem__(0, r['stage_names'][1])):
            value = passing(); mutate(value['positive_cases'][0]); self.rejects(value)

    def test_every_negative_requires_its_observed_failure_class(self):
        for index in range(8):
            for mutate in (lambda r: r.update(status='PASS'), lambda r: r.update(failure_class='load'),
                           lambda r: r.update(case='j415-speakers'), lambda r: r['cleanup'].update(graph_unloaded=False)):
                value = passing(); mutate(value['negative_controls'][index]); self.rejects(value)

    def test_selected_fir_identity_rate_hash_and_cardinality(self):
        for mutate in (lambda r: r['fir_selections'].pop(),
                       lambda r: r['fir_selections'][0].update(rate=44100),
                       lambda r: r['fir_selections'][0].update(sha256='0' * 64),
                       lambda r: r['fir_selections'][0].update(identity='/private/fir.wav'),
                       lambda r: r['fir_selections'].__setitem__(1, copy.deepcopy(r['fir_selections'][0]))):
            value = passing(); mutate(value['positive_cases'][0]); self.rejects(value)

    def test_dsp_hash_ui_paths_and_extra_library_identity_refuse(self):
        for mutate in (lambda r: r['libraries'][0].update(sha256='0' * 64),
                       lambda r: r['libraries'].append({'identity': 'candidate/lsp-plugins.lv2/lsp-plugins-lv2ui.so', 'sha256': 'a' * 64}),
                       lambda r: r['libraries'].append({'identity': 'system/../private/file.so', 'sha256': 'a' * 64}),
                       lambda r: r['libraries'].pop()):
            value = passing(); mutate(value['positive_cases'][0]); self.rejects(value)

    def test_inventory_elf_headers_and_tools_are_bound(self):
        for mutate in (lambda v: v['inventory'].update(after_sha256='0' * 64),
                       lambda v: v['inventory'].update(count=573), lambda v: v['headers'].pop('spa_json_core'),
                       lambda v: v['tools'].update(gcc='/private/tool'),
                       lambda v: v['elf']['host'].update(path_tags=['RUNPATH']),
                       lambda v: v['elf']['bankstown'].update(sha256='0' * 64),
                       lambda v: v['safety'].update(hardware='PASS')):
            value = passing(); mutate(value); self.rejects(value)

    def test_source_flags_and_engine_observation_crossjoin(self):
        for mutate in (lambda v: v['host'].update(source_sha256='b' * 64),
                       lambda v: v['host']['compile_flags'].append('-I/private'),
                       lambda v: v['host']['compile_flags'].__setitem__(0, '-std=c11'),
                       lambda v: v['host']['compile_flags'].remove('-lserd-0'),
                       lambda v: v['positive_cases'][0]['libraries'][-1].update(sha256='b' * 64)):
            value = passing(); mutate(value); self.rejects(value)
        value = passing(); value['engines']['lv2'] = value['elf']['lv2']['sha256'] = 'b' * 64
        self.rejects(value)

    def test_deadlines_debit_compile_converter_and_host_groups(self):
        clock = [0.0]; total = c.Budget(420, clock=lambda: clock[0])
        clock[0] = 60; group = c.Budget(360, clock=lambda: clock[0])
        clock[0] = 390
        with patch.object(COMMON, 'command', return_value=b'inert') as child:
            c.command(['inert'], 'inert', 30, total, group=group)
            self.assertEqual(child.call_args.args[2], 10)
        clock[0] = 400
        with self.assertRaises(COMMON.Failure): total.take(30, 20)
        clock[0] = 0; compile_group = c.Budget(60, clock=lambda: clock[0]); clock[0] = 59
        self.assertEqual(compile_group.take(60), 1)

    def test_private_fixtures_make_only_the_named_change(self):
        case = c.s.cases()['j413-speakers']
        with tempfile.TemporaryDirectory(dir=HERE) as tmp:
            root = Path(tmp); data = root / 'data'; work = root / 'work'; work.mkdir()
            original = root / 'original.json'; original.write_text(json.dumps(case['expected']))
            before = original.read_bytes()
            for path in case['expected']['filter.graph']['nodes'][3]['config']['filename']:
                file = data / Path(path).relative_to('/usr/share/asahi-audio')
                file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(file.name.encode())
            def digest(path):
                p = Path(path)
                if p.is_relative_to('/usr/share/asahi-audio'):
                    p = data / p.relative_to('/usr/share/asahi-audio')
                return hashlib.sha256(p.read_bytes()).hexdigest()
            with patch.object(c, 'WORK', work), patch.object(c, 'DATA', data), patch.object(COMMON, 'digest', side_effect=digest):
                for name in c.s.CONTROLS:
                    path = c.fixture(name, original, case)
                    self.assertEqual(original.read_bytes(), before)
                    if name in ('malformed', 'duplicate', 'trailing'):
                        with self.assertRaises(COMMON.Failure): c.strict_json(path.read_bytes())
                    else:
                        changed = json.loads(path.read_text())
                        if name in ('allFIRabsent', '48konlyabsent'):
                            expected = copy.deepcopy(case['expected'])
                            arr = expected['filter.graph']['nodes'][3]['config']['filename']
                            expected['filter.graph']['nodes'][3]['config']['filename'] = [
                                str(work / name / 'data' / Path(p).name) for p in arr]
                            self.assertEqual(changed, expected)
                            files = list((work / name / 'data').iterdir())
                            self.assertEqual(len(files), 0 if name == 'allFIRabsent' else 3)
                            self.assertFalse(any(p.name.endswith('-48.wav') for p in files))
                        else:
                            expected = copy.deepcopy(case['expected'])
                            if name == 'missingURI': expected['filter.graph']['nodes'][0]['plugin'] = 'urn:missing:offline-graph'
                            elif name == 'invalidport': expected['filter.graph']['links'][0]['input'] = 'ell:nonexistent_port'
                            else:
                                controls = expected['filter.graph']['nodes'][0]['control']
                                controls['nonexistent_control'] = controls.pop('bypass')
                            self.assertEqual(changed, expected)

    def test_inventory_after_attempted_after_preflight_failure(self):
        with tempfile.TemporaryDirectory(dir=HERE) as tmp, patch.object(c, 'OUT', Path(tmp)), \
             patch.object(COMMON, 'assert_isolation'), patch.object(COMMON, 'mount_readonly', return_value=True), \
             patch.object(COMMON, 'inventory', return_value=c.s.LOCK) as inventory, \
             patch.object(c, 'check_inputs', side_effect=COMMON.Failure('candidate_hash')):
            self.assertEqual(c.main(), 1)
            value = json.loads((Path(tmp) / 'observations.json').read_text())
            self.assertEqual(value['failure_class'], 'candidate_hash'); self.assertTrue(value['inventory']['unchanged'])
            self.assertEqual(inventory.call_count, 2); self.assertEqual(value['host_children'], 0)


if __name__ == '__main__': unittest.main()
