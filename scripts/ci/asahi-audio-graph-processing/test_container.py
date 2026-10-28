"""Inert graph/report controls only: no compiler, plugin, service or container."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
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
            {'identity': c.library_identity(p), 'sha256': c.OFFICIAL_ENGINES.get(key, 'a' * 64)}
            for key,p in c.ENGINE_PATHS.items()]
    firs = {x['path']: x for x in c.s.graphs()['firs']}; selections = []
    if positive:
        for node in case['expected']['filter.graph']['nodes']:
            if node.get('label') == 'convolver':
                identity = next(p.lstrip('/') for p in node['config']['filename'] if p.endswith('-48.wav'))
                selections.append({'node': node['name'], 'identity': identity, 'rate': 48000,
                                   'sha256': firs[identity]['sha256']})
    return dict(schema='asahi-audio-graph-processing-host-v1', status='PASS' if positive else 'FAIL',
                failure_class=None if positive else c.NEGATIVES[expect], case=case['id'], expect=expect,
                rate=48000, process_calls=128 if positive else 0, counts=counts, gates=gates,
                stage_names=[n['name'] for n in case['expected']['filter.graph']['nodes']] if positive else [],
                fir_selections=selections, libraries=libraries, cleanup=dict.fromkeys(c.CLEANUP, True),
                raw_sha256=case['raw_sha256'] if positive else 'b' * 64,
                processing=metrics(case) if positive else None)


def metrics(case, signal='noise'):
    return dict(fixture=signal, block_frames=1024, blocks=128, inputs=case['inputs'], outputs=case['outputs'],
                samples_per_channel=131072, process_calls=128, bytes=case['outputs']*131072*4,
                input_immutable=True, guards=True, finite=True, duplicates=True,
                peak=[0.0 if signal=='silence' else 0.01]*case['outputs'],
                energy=[0.0 if signal=='silence' else 1.0]*case['outputs'])

def positives():
    rows=[]
    for case in c.s.cases().values():
        for signal in ('silence','noise'):
            for repeat in range(2):
                row=host_row(case); row.update(processing=metrics(case,signal),repeat=repeat,sample_sha256='a'*64)
                rows.append(row)
    return rows

def passing():
    candidates = {k: v['sha256'] for k, v in c.candidate_hashes().items()}
    elf = {}
    for name in ('host', *c.ENGINE_PATHS, *candidates):
        elf[name] = {'class': 'ELF64', 'machine': 'AArch64', 'needed': ['libc.so.6'],
                     'path_tags': [], 'version_requirements': ['GLIBC_2.17'],
                     'sha256': candidates.get(name, c.OFFICIAL_ENGINES.get(name, 'a' * 64)), 'load_segments': 2,
                     'structural_16k': 'PASS', 'hardware_status': 'NOT RUN'}
    return dict(schema_version=1, status='PASS', failure_class=None, stage='complete',
                inventory=dict(count=574, before_sha256=c.s.LOCK, after_sha256=c.s.LOCK, unchanged=True),
                headers={k: v[1] for k, v in {**COMMON.HEADERS, **c.GRAPH_HEADERS}.items()},
                tools=dict.fromkeys(('gcc', 'pkg-config', 'readelf', 'spa-json-dump'), 'a' * 64),
                engines={**dict.fromkeys(c.ENGINE_PATHS, 'a' * 64), **c.OFFICIAL_ENGINES}, candidates=candidates,
                host=dict(sha256='a' * 64, source_sha256=c.s.sha(HERE / 'host.c'), processing_header_sha256=c.s.sha(HERE/'processing.h'),
                          compile_flags=['-std=gnu11', *COMMON.FLAGS[1:], '-lpipewire-0.3', '-llilv-0', '-lserd-0', '-ldl', '-lm']),
                elf=elf, parsing=[dict(id=r['id'], raw_sha256=r['raw_sha256'], status='PASS',
                                      full_equality=True, converter='spa-json-dump') for r in c.s.cases().values()],
                positive_cases=positives(),
                negative_controls=[host_row(c.s.cases()['j413-speakers'], name) for name in c.s.CONTROLS],
                host_children=24, converter_children=4, first_host_failure=None, safety=copy.deepcopy(c.SAFETY),
                adapter=dict(identity=c.ADAPTER_IDENTITY,sha256='a'*64,sources=c.ADAPTER_SOURCES,
                             compile_flags=c.adapter_flags(['-lpipewire-0.3','-llilv-0','-lserd-0'])),
                processing=dict(streams=16,exact_repeats=8,microphone_correspondences=4,process_calls=2048))


class ProjectionControls(unittest.TestCase):
    def setUp(self):
        self.patcher=patch.object(c,'common',return_value=COMMON);self.patcher.start()
    def tearDown(self):self.patcher.stop()
    def test_complete_public(self):c.validate_public(passing())
    def test_missing_or_forged_gates_refuse(self):
        for gate in c.GATES:
            value=passing();value['positive_cases'][0]['gates'][gate]=False
            with self.assertRaises(COMMON.Failure):c.validate_public(value)
    def test_no_vacuous_grid(self):
        for field in ('positive_cases','negative_controls','parsing'):
            value=passing();value[field].pop()
            with self.assertRaises(COMMON.Failure):c.validate_public(value)
    def test_bad_repeat_hash(self):
        value=passing();value['positive_cases'][1]['sample_sha256']='b'*64
        with self.assertRaises(COMMON.Failure):c.validate_public(value)
    def test_official_adapter_not_allowed(self):
        value=passing();value['positive_cases'][0]['libraries'].append(dict(identity=c.library_identity(c.OFFICIAL_ADAPTER),sha256='a'*64))
        with self.assertRaises(COMMON.Failure):c.validate_public(value)
    def test_official_engine_alteration_refused_even_when_observations_agree(self):
        for key in c.OFFICIAL_ENGINES:
            value=passing();value['engines'][key]='b'*64;value['elf'][key]['sha256']='b'*64
            identity=c.library_identity(c.ENGINE_PATHS[key])
            for row in value['positive_cases']:
                for library in row['libraries']:
                    if library['identity']==identity:library['sha256']='b'*64
            with self.assertRaises(COMMON.Failure):c.validate_public(value)
    def test_unknown_public_field(self):
        value=passing();value['processing']['extra']=True
        with self.assertRaises(COMMON.Failure):c.validate_public(value)

if __name__=='__main__':unittest.main()
