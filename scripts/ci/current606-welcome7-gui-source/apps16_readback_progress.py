#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a source-only successor of the exact Apps16 service1800 GUI source."""

import argparse
import base64
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
PARENT = {'bytes': 100693, 'sha256': 'd62aefc197c625b66dea7d33872875baa5d30494bf1a24799e74c61a62718778'}
CONTEXT = 'readback-progress-parent.json'
PAYLOAD = 'factory/installed606_progress.py'
FACTORY = 'factory/factory.py'
OLD_CALL = '    changes=transform(out,mode)\n'
NEW_CALL = OLD_CALL + "    changes['installed606_progress']=load('_installed606_progress',HERE/'installed606_progress.py').apply(out,pin)\n"
START = '\n# Exact service1800 installed606 diagnostics successor.\n'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def need(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1, 'ordinary source leaf')
    raw = path.read_bytes()
    need(len(raw) <= 16 * 1024**2, 'bounded source leaf')
    return raw


GUARD = '''
def _readback_parent(root):
 root=Path(root).absolute()
 context=obj(root/'readback-progress-parent.json')
 need(set(context)=={'manifest','payload','actual'} and context['actual'] is None and context['payload']==_READBACK_PAYLOAD,'exact 606 progress context')
 prior_manifest=base64.b64decode(context['manifest'],validate=True)
 need(pin(prior_manifest)==_READBACK_PARENT,'exact service1800 manifest')
 before={**json.loads(prior_manifest)['files'],'source-manifest.json':pin(prior_manifest)}
 manifest=obj(root/'source-manifest.json')
 need(manifest['status']=='SOURCE_ONLY_GUI_APPS16_INSTALLED606_PROGRESS' and all(manifest[k] is None for k in ('actual_source','actual_ref','actual_run')),'unissued diagnostics source only')
 need(set(manifest['files'])==set(before)-{'source-manifest.json'}|{'factory/installed606_progress.py','readback-progress-parent.json'},'closed exact successor file set')
 closed(root,{**manifest['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 need(pin(read(root/'factory/installed606_progress.py'))==_READBACK_PAYLOAD,'whole installed606 diagnostic module')
 before_admission,marker,_=read(root/'admission.py').partition(_READBACK_START.encode())
 need(marker and pin(before_admission)==before['admission.py'],'whole original service1800 admission')
 current_factory=read(root/'factory/factory.py')
 need(current_factory.count(_READBACK_NEW_CALL.encode())==1,'one exact diagnostic emission seam')
 before_factory=current_factory.replace(_READBACK_NEW_CALL.encode(),_READBACK_OLD_CALL.encode(),1)
 originals={'source-manifest.json':prior_manifest,'admission.py':before_admission,'factory/factory.py':before_factory}
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=originals[name] if name in originals else read(path,cap)
  need(name in before and pin(raw)==before[name] and len(raw)<=cap,'whole service1800 source operand '+name);return raw
 def prior_closed(where,wanted):
  prefix='' if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in before.items() if n.startswith(prefix)}==wanted,'closed original service1800 namespace')
  for n in wanted:prior_read(where/n)
  return wanted
 for name in before:prior_read(root/name)
 parent=types.ModuleType('_installed606_progress_original_service1800');parent.__file__=str(root/'admission.py')
 exec(compile(before_admission,parent.__file__,'exec'),vars(parent))
 parent.read=prior_read;parent.obj=lambda p:json.loads(prior_read(p));parent.closed=prior_closed
 return parent

def _readback_fact(fact):
 need(fact['files']==574 and fact['fullscan_seconds']==600,'whole original service1800 proof and readback deadline')
 return dict(fact,files=576,installed606_progress='BOUNDED_MONOTONIC_DIAGNOSTICS_ONLY')

def source_context(root):
 return _readback_fact(_readback_parent(root).source_context(root))

def prove(root):
 fact=_readback_fact(_readback_parent(root).prove(root))
 return dict(fact,status='PASS_WHOLE574_AND_INSTALLED606_DIAGNOSTICS_SOURCE_ONLY')
'''


def emit(predecessor, output):
    predecessor = predecessor.absolute()
    output = output.absolute()
    need(predecessor.resolve() == predecessor and output.resolve() == output and not output.exists()
         and not output.is_relative_to(predecessor) and not predecessor.is_relative_to(output), 'fresh disjoint ordinary output')
    manifest_raw = read(predecessor / 'source-manifest.json')
    need(pin(manifest_raw) == PARENT, 'exact Apps16 service1800 source manifest')
    manifest = json.loads(manifest_raw)
    before = {**manifest['files'], 'source-manifest.json': PARENT}
    actual = {p.relative_to(predecessor).as_posix() for p in predecessor.rglob('*') if p.is_file() or p.is_symlink()}
    need(set(before) == actual and not any(p.is_symlink() for p in predecessor.rglob('*')), 'whole closed ordinary service1800 source')
    files = {name: read(predecessor / name) for name in before}
    need({name: pin(raw) for name, raw in files.items()} == before, 'every exact source operand')
    payload = read(HERE / 'installed606_progress.py')
    files[PAYLOAD] = payload
    files[CONTEXT] = encoded(dict(manifest=base64.b64encode(manifest_raw).decode(), payload=pin(payload), actual=None))
    factory = files[FACTORY].decode()
    need(factory.count(OLD_CALL) == 1, 'exact original prepare_code stage')
    files[FACTORY] = factory.replace(OLD_CALL, NEW_CALL, 1).encode()
    files['admission.py'] += (START + f'_READBACK_START={START!r}\n_READBACK_PARENT={PARENT!r}\n'
                              f'_READBACK_PAYLOAD={pin(payload)!r}\n_READBACK_NEW_CALL={NEW_CALL!r}\n'
                              f'_READBACK_OLD_CALL={OLD_CALL!r}\n' + GUARD).encode()
    files.pop('source-manifest.json')
    manifest['status'] = 'SOURCE_ONLY_GUI_APPS16_INSTALLED606_PROGRESS'
    manifest['files'] = {name: pin(raw) for name, raw in files.items()}
    files['source-manifest.json'] = encoded(manifest)
    output.mkdir(mode=0o700)
    for name, raw in sorted(files.items()):
        if name.endswith('.py'):
            compile(raw, name, 'exec')
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod((predecessor / name).stat().st_mode & 0o777 if name in before else 0o644)
    return dict(status='EMITTED_APPS16_INSTALLED606_OBSERVER_SOURCE_ONLY', files=len(files), authority=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predecessor-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(emit(args.predecessor_root, args.output), sort_keys=True))
