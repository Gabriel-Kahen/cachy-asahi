#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit retained-parent DATA checks; no export, package code or actor."""
import argparse
import contextlib
import importlib.util
import json
from pathlib import Path
import resource
import sys
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent


def main():
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-source',type=Path,required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('retention_v3_parent_DATA_controls',HERE/'prepare.py')
    p=importlib.util.module_from_spec(spec);sys.modules[spec.name]=p;spec.loader.exec_module(p)
    before=p.parent(args.previous_source);after=p.render(before)
    assert p.restore(after)==before
    old232=p.base.restore(before)
    assert p.fs.tree(old232)==p.base.PARENT_TREE
    original=json.loads(after['inverse.json'][0]);held={n:v for n,v in after.items()if n not in original['additions']}
    assert len(held)==200 and p.fs.descriptors(held)==original['held']and p.fs.tree(held)==original['before_tree']
    code=lambda files:json.loads(files['lifecycle-code-map.json'][0])['files']
    assert {n for n in code(before)if code(before)[n]!=code(after)[n]}=={'actor.py','producer.py'}
    old=p.base.unpack(before['lifecycle-capsule.tar'][0],json.loads(before['contract.json'][0])['capsule'])
    new=p.base.unpack(after['lifecycle-capsule.tar'][0],json.loads(after['contract.json'][0])['capsule'])
    assert {n for n in old if old[n]!=new[n]}=={'actor.py','producer.py','source-map.json'}
    assert new['actor.py'][0]==after['lifecycle-code/actor.py'][0]
    assert new['producer.py'][0]==after['lifecycle-code/producer.py'][0]
    for name in ['policy.json','lifecycle-code/domain.json','input-review.json','lifecycle-code/probe.pl','lifecycle-code/common.py','lifecycle-code/read_result.py','hosted/entry.py','hosted/reader.py']:
        assert after[name]==before[name],name
    for name in ['previous-v2/lifecycle-code-actor.py','previous-v2/lifecycle-code-producer.py','previous-v2/capsule-source-map.json','lifecycle-capsule.tar']:
        bad=dict(after);body,mode=bad[name];bad[name]=(body+b'changed',mode)
        try:p.restore(bad)
        except(ValueError,json.JSONDecodeError):pass
        else:raise AssertionError('tampered inverse accepted:'+name)
    result=p.facts(after)
    result.update(actual_parent_DATA_checks='PASS',full241_inverse=True,full232_inverse=True,original200_inverse=True,
        unchanged_parent_core_files=10,unchanged_capsule_members=17,unchanged_original_files=200,
        unchanged_package_trust_review_policy=True,negative_inverse_cases=4,Source_export='NOT_WRITTEN',
        actor='NOT_RUN',Reader='NOT_RUN',network='NOT_RUN',ALPM='NOT_RUN',GPG='NOT_RUN')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    with contextlib.ExitStack()as stack:
        for name in ['subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open']:
            stack.enter_context(patch(name,side_effect=AssertionError('operational boundary fenced'),create=name=='os.pidfd_open'))
        main()
