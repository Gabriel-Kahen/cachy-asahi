#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the pinned metadata closure; no package/native processes or network."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
from contract import digest, verify_source
import contract as T

HERE = Path(__file__).resolve().parent


def check(source):
    verify_source(source)
    proposal = json.loads((HERE / 'package-inputs.json').read_text())
    lock = source / proposal['base_lock']['path']
    T.need(digest(lock) == proposal['base_lock']['sha256'], 'base lock pin differs')
    base = json.loads(lock.read_text());selected = {r['name']: r for r in base['packages']}
    spec = importlib.util.spec_from_file_location('files_preview', source / 'scripts/port/preview.py')
    preview = importlib.util.module_from_spec(spec);spec.loader.exec_module(preview)
    records = {r['name']: {'NAME':[r['name']], 'VERSION':[r['version']], 'ARCH':[r['arch']],
        'DEPENDS':r['depends'], 'PROVIDES':r['provides'], 'CONFLICTS':r['conflicts'], 'REPLACES':r['replaces']}
        for r in selected.values()}
    with tempfile.TemporaryDirectory(dir=HERE) as directory:
        work=Path(directory);(work/'root').mkdir();preview.write_local(work/'db/local',records)
        edges, conflicts=preview.alpm_audit(work,records)
    T.need(all(e['provider'] for e in edges) and not conflicts, 'dependency/version/conflict failure')
    byname={n:[] for n in selected}
    for edge in edges:byname[edge['package']].append(edge)
    queue=['gtk3','glib2','gcc','make','pkgconf','python','pacman','systemd'];closure=set()
    while queue:
        name=queue.pop()
        if name not in closure:closure.add(name);queue.extend(e['provider'] for e in byname[name])
    T.need(proposal['closure_packages'] == [selected[n] for n in sorted(closure)] and
           proposal['dependency_edges'] == [e for e in edges if e['package'] in closure], 'pinned closure graph differs')
    return dict(status='PASS_PRIVATE_METADATA_CLOSURE', packages=len(closure),
                edges=len(proposal['dependency_edges']), additional_packages=0, native_runtime='NOT_RUN')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args=parser.parse_args();print(json.dumps(check(args.source.resolve()),indent=2))
