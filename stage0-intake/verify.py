#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline byte/pin checks of this finite DATA intake; no fetch, extraction or execution."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST_SHA256 = 'a856f127eece4f160cfb82f310ecda99ffb1f0d6f7385ea2fbd0009f69148eb2'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def main():
    manifest = HERE / 'evidence-pins.json'
    assert sha(manifest) == MANIFEST_SHA256, 'evidence manifest changed'
    for name, expected in json.loads(manifest.read_bytes()).items():
        path = HERE / name
        assert HERE in path.resolve().parents and sha(path) == expected, name
    intake = json.loads((HERE / 'acquisition.json').read_bytes())
    facts = json.loads((HERE / 'data-admission.json').read_bytes())
    inputs = json.loads((HERE.parent / 'inputs.json').read_bytes())
    assert sha(HERE.parent / 'inputs.json') == facts['candidate_inputs_sha256']
    assert sha(HERE / 'acquisition.json') == facts['acquisition_sha256']
    expected = {k:v for k,v in inputs['archives'].items() if v['role']=='stage0'}
    assert set(intake['artifacts']) == set(facts['archives']) == set(expected)
    assert len(intake['requests']) <= 8
    assert sum(r['body_bytes'] for r in intake['requests']) == intake['response_body_bytes'] <= 300*1024**2
    for name, pin in expected.items():
        retained = intake['artifacts'][name]
        path = Path(retained['path'])
        assert path.stat().st_size == retained['bytes'] == facts['archives'][name]['bytes']
        assert sha(path) == retained['sha256'] == pin['sha256']
        report = facts['archives'][name]
        assert report['install_manifest']['status'] == 'ALL_INSTALL_MANIFEST_PATHS_AND_COMPONENT_PAYLOAD_JOINED'
        elfs = json.loads((HERE / 'records' / (name+'.elf.json')).read_bytes())
        assert len(elfs) == report['ELF_regular_files']
        assert all(e['machine']==183 and e['load_segments_16k_congruence_and_alignment'] for e in elfs.values())
        assert all('rpath' in e and 'runpath' in e for e in elfs.values())
    assert facts['compatibility']=='UNQUALIFIED' and facts['publisher_execution']==facts['installer_execution']==0
    assert facts['holds_preserved'] == inputs['holds']
    assert not facts['existing_candidate_selector_and_admission_example_changed']
    print('PASS: exact retained archive bytes and pinned DATA records; runtime/bootstrap/16K/legal qualification remains held')


if __name__ == '__main__':
    main()
