#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit real-parent DATA controls; no copy, payload import, actor or Reader."""
import argparse
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import resource
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def main():
    resource.setrlimit(resource.RLIMIT_AS, (512*1024**2, 512*1024**2))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-source', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('successor_parent_DATA_controls', HERE/'prepare.py')
    p = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = p
    spec.loader.exec_module(p)
    before = p.parent(args.previous_source)
    after = p.render(before)
    assert p.restore(after) == before
    assert p.fs.descriptors({n: v for n,v in after.items() if n.startswith('original/')}) == p.fs.descriptors({n: v for n,v in before.items() if n.startswith('original/')})
    old_capsule = p.unpack(before['lifecycle-capsule.tar'][0], json.loads(before['contract.json'][0])['capsule'])
    new_capsule = p.unpack(after['lifecycle-capsule.tar'][0], json.loads(after['contract.json'][0])['capsule'])
    assert {n for n in old_capsule if old_capsule[n] != new_capsule[n]} == {'producer.py','source-map.json'}
    assert new_capsule['producer.py'][0] == after['lifecycle-code/producer.py'][0]
    assert p.edit.inverse(new_capsule['producer.py'][0]) == old_capsule['producer.py'][0]
    old_code = json.loads(before['lifecycle-code-map.json'][0])['files']
    new_code = json.loads(after['lifecycle-code-map.json'][0])['files']
    assert len(old_code) == len(new_code) == 12
    assert {n for n in old_code if old_code[n] != new_code[n]} == {'producer.py'}
    original_inverse = json.loads(after['inverse.json'][0])
    original = {n: v for n,v in after.items() if n not in original_inverse['additions']}
    assert len(original) == 200 and p.fs.descriptors(original) == original_inverse['held']
    assert p.fs.tree(original) == original_inverse['before_tree']
    assert after['input-review.json'] == before['input-review.json']
    assert p.fs.pin(after['input-review.json'][0])['sha256'] == p.INPUT_REVIEW
    unchanged = ['policy.json','root-admission.TEMPLATE.json','lifecycle-code/actor.py','lifecycle-code/domain.json','lifecycle-code/common.py','lifecycle-code/probe.pl','hosted/entry.py','held-source.json']
    for name in unchanged:
        assert after[name] == before[name], name
    for name in ('previous-v1/lifecycle-code-producer.py','previous-v1/capsule-source-map.json','lifecycle-capsule.tar'):
        bad = dict(after)
        body, mode = bad[name]
        bad[name] = (body+b'changed', mode)
        try:
            p.restore(bad)
        except (ValueError, json.JSONDecodeError):
            pass
        else:
            raise AssertionError('tampered inverse accepted: '+name)
    facts = p.facts(after)
    facts.update(actual_parent_data_checks='PASS', full232_inverse=True, unchanged_core_files=11,
        unchanged_capsule_members=18, unchanged_original_files=200, actor_bytes_unchanged=True,
        original200_inverse=True, negative_inverse_cases=3, export='NOT_WRITTEN', actors='NOT_RUN',
        runtime='NOT_RUN', Reader='NOT_RUN', publication='NOT_RUN')
    print(json.dumps(facts, sort_keys=True))


if __name__ == '__main__':
    with contextlib.ExitStack() as stack:
        for name in ('subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open'):
            stack.enter_context(patch(name, side_effect=AssertionError('operational boundary fenced'), create=name=='os.pidfd_open'))
        main()
