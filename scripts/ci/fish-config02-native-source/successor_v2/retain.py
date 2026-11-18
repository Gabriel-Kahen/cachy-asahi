#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Select bounded public receipts only; never walks mounted daemon/cache storage."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import time

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('fish02_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)


def selected(root):
    rows={}
    for path in root.iterdir():
        if path.name in ('volume','storage.img'):continue
        if path.name=='evidence':
            D.need(path.is_dir() and not path.is_symlink(),'ordinary finite evidence directory')
            for leaf in path.rglob('*'):
                D.need(not leaf.is_symlink(),'no evidence symlink')
                if leaf.is_file():rows[str(leaf.relative_to(root))]=D.read(leaf,16*1024**2,empty=True)
        else:
            D.need(re.fullmatch(r'(?:owner-report|actual-domains|host-tools|host-policy)\.json|(?:owner|daemon)\.log|command-[0-9]{3}\.(?:json|bin)',path.name),
                   'unexpected root receipt filename')
            rows[path.name]=D.read(path,16*1024**2,empty=True)
        D.need(len(rows)<4096 and sum(map(len,rows.values()))<=15*1024**2,'complete bounded public receipt cap')
    D.need('owner-report.json' in rows,'actual owner report required')
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('output',type=Path);p.add_argument('--root',type=Path,required=True);p.add_argument('--source-map-sha256',required=True);a=p.parse_args()
    D.source(a.root,a.source_map_sha256);rows=selected(a.output)
    report=D.decode(rows['owner-report.json']);group=report['controller']['cgroup']
    D.need(group=='/system.slice/cachy-fish02-controller-'+os.environ['GITHUB_RUN_ID']+'-1.scope','exact original controller domain')
    path=Path('/sys/fs/cgroup'+group)
    for _ in range(2):
        D.need(not path.exists() or 'populated 0' in (path/'cgroup.events').read_text(),'original controller domain empty twice');time.sleep(.05)
    rows['controller-retirement.json']=(json.dumps(dict(cgroup=group,empty_twice=True,run=os.environ['GITHUB_RUN_ID'],attempt=1))+'\n').encode()
    encoder=a.root/'held-source32'/D.BASE_PREFIX/'runtime/scripts/ci/log_evidence.py'
    spec=importlib.util.spec_from_file_location('held_fish02_log_encoder',encoder);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='fish02-owned-public-',dir=os.environ['RUNNER_TEMP']) as name:
        output=Path(name)
        for rel,raw in rows.items():
            target=output/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        raw=module.bundle(output)
        print('CACHY_ASAHI_EVIDENCE_BEGIN '+output.name+' sha256='+D.pin(raw)['sha256']+' bytes='+str(len(raw)))
        print(base64.encodebytes(raw).decode(),end='');print('CACHY_ASAHI_EVIDENCE_END '+output.name)


if __name__=='__main__':main()
