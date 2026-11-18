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
import stat
import tempfile
import time

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llhttp-reference_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
INCOMPLETE_REASONS=frozenset(('output-absent','output-unavailable','output-handoff-incomplete',
                              'terminal-report-absent','terminal-report-unavailable'))


def terminal_report(output):
    try:
        info=output.lstat()
    except FileNotFoundError:
        return None,'output-absent'
    except OSError:
        return None,'output-unavailable'
    # Root prepares 0711 for traversal. Only its final 0700 runner-owned
    # handoff permits the complete public namespace census below.
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700):
        return None,'output-handoff-incomplete'
    try:
        return D.read(output/'owner-report.json',16*1024**2),None
    except FileNotFoundError:
        return None,'terminal-report-absent'
    except (OSError,ValueError):
        return None,'terminal-report-unavailable'


def incomplete(run,attempt,source,reason):
    D.need(reason in INCOMPLETE_REASONS and re.fullmatch('[0-9a-f]{40}',source),'allowlisted incomplete controller context')
    return dict(kind='LLHTTP_REFERENCE_CONTROLLER_RETENTION_HOLD_V1',status='HOLD_OWNER_RETENTION',
                reason=reason,source=source,run=run,attempt=1,cgroup=D.controller_scope(run,attempt),
                memory=D.controller_memory(run,attempt),cleanup='UNVERIFIED',retirement='UNVERIFIED')


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
    D.source(a.root,a.source_map_sha256)
    run,attempt,source=(os.environ[k] for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_SHA'))
    group=D.controller_scope(run,attempt)
    D.need(os.environ.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
           and re.fullmatch('[0-9a-f]{40}',source), 'exact hosted retention context')
    expected=Path(os.environ['RUNNER_TEMP'])/'llhttp-reference-owned-v2'
    D.need(a.output == expected and a.output.is_absolute() and a.output == a.output.resolve(), 'exact ordinary owned retention output')
    raw,reason=terminal_report(a.output)
    if raw is None:
        print(json.dumps(incomplete(run,attempt,source,reason),sort_keys=True),flush=True)
        return 2
    report=D.decode(raw)
    D.need(report['controller']['cgroup'] == group and report['source'] == source and report['run'] == run
           and report['attempt'] == 1 and report['source_map_sha256'] == a.source_map_sha256, 'exact original controller report join')
    rows=selected(a.output)
    D.need(rows['owner-report.json'] == raw,'stable exact terminal controller report')
    path=D.CGROUP_ROOT/group[1:]
    for _ in range(2):
        D.need(not path.exists() or 'populated 0' in (path/'cgroup.events').read_text(),'original controller domain empty twice');time.sleep(.05)
    rows['controller-retirement.json']=(json.dumps(dict(cgroup=group,empty_twice=True,run=os.environ['GITHUB_RUN_ID'],attempt=1))+'\n').encode()
    encoder=a.root/'held-source'/D.BASE_PREFIX/'runtime/scripts/ci/log_evidence.py'
    spec=importlib.util.spec_from_file_location('held_llhttp-reference_log_encoder',encoder);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='llhttp-reference-owned-public-',dir=os.environ['RUNNER_TEMP']) as name:
        output=Path(name)
        for rel,raw in rows.items():
            target=output/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        raw=module.bundle(output)
        print('CACHY_ASAHI_EVIDENCE_BEGIN '+output.name+' sha256='+D.pin(raw)['sha256']+' bytes='+str(len(raw)))
        print(base64.encodebytes(raw).decode(),end='');print('CACHY_ASAHI_EVIDENCE_END '+output.name)
    return 0


if __name__=='__main__':raise SystemExit(main())
