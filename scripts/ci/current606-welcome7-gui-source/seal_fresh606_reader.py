#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebind the fixed Apps16 service1800 once-original reader to fresh 606 source."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fresh606 import decode, encoded, need, pin, read
from seal_fresh606 import replace


BASIS = {'bytes': 287013, 'sha256': '9af7c1e0a19fd2de439f12945a6bffc94c18300f3a1a9d67aeed794d41a86fc8'}
QUALIFICATION = {'bytes': 499, 'sha256': '76f458fea04b60811bab3eeedf2947ae02d10ae5212df609f26abdb5470d60e2'}
QUALIFICATION_OUTPUT = {'bytes': 85228, 'sha256': '58bc7f68745bd8f33c0500a34b3887a0ea654dc94001e20fda9c69d3c59b72bd'}
PIN = {
    'builder': 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac',
    'controller': '74ac9e38332ccb207cae4dc00bd821846cc8e7f83dbbda12478990fe62395ad1',
    'guest': '9674da5a122395df4c496e7af4ed68dfb091d0793e184eff7d317bbb4df1dcf9',
}
FILES = ('Root-publication.json','Root-source-authorization.json','Root-git-source-authorization.json')


NEW_READER = '''# SPDX-License-Identifier: MIT
"""Exact fresh TEST receipt and prior reader qualification custody, passive only."""
from datetime import datetime
from pathlib import Path

def basis(H, here):
 r=H.read(here/'fresh606-reader-basis.json',1024**2)
 old=Path(r['original_reader'])
 H.closed(old,r['original_reader_files'])
 for role,pin in r['historical_records'].items():
  H.need(H.pin(H.ordinary(Path(role),1024**2))==pin,'exact prior qualified reader custody')
 return dict(status='PRIOR_EXACT757_QUALIFICATION_HELD_HISTORICALLY',source=r['old_source'],new_authority=None)

def utc(text):
 if type(text) is not str or not text.endswith('Z'):
  raise ValueError('original UTC workflow timestamp required')
 return datetime.fromisoformat(text[:-1]+'+00:00').timestamp()

def verify(H, root, public, originals, binding, case, own):
 f=H.load('_fresh606_passive_receipt',root/'factory/fresh606.py')
 record=H.read(public/'generated/candidates/test-signature-renewal.json',65536)
 path=root/'fresh-test/selection.json';data=H.read(path,65536)
 H.need(own['fresh_test_selection']==H.pin(H.ordinary(path,65536)), 'exact original case ingress signer selection')
 run=H.read(originals/'run.json');H.run_identity(run,binding,case)
 f.recorded(data,record,run_start=utc(run['run_started_at']),run_end=utc(run['updated_at']))
 return dict(status='PASS_PASSIVE_CURRENT606_TEST_INGRESS_RECEIPT_AND_ACTUAL_INTERVAL',scope=record['scope'],
             signer=record['certificate']['fingerprint'],case=case,run=run['id'],actual_authority=False)
'''


def files_at(root):
    entries = list(root.rglob('*'))
    need(not any(p.is_symlink() for p in entries), 'ordinary reader/source data only')
    return {p.relative_to(root).as_posix(): pin(read(p, 32*1024**2)) for p in entries if p.is_file()}


def build(args):
    post = decode(read(args.basis, want=BASIS))
    status = decode(read(args.qualification, want=QUALIFICATION))
    qualification = decode(read(args.qualification_output, want=QUALIFICATION_OUTPUT))
    need(post['status'] == 'PASS_SOURCE574_GIT_READER757_ONCE_PUBLIC_TRANSPORT_FAILURE_CUSTODY_ONLY'
         and post['Root_acceptance'] == 'NOT_ISSUED' and post['run'] == 40202454241 and len(post['reader_files']) == 757
         and qualification['status'] == 'PASS_FULL_ORIGINAL348_CONTEXT_AND_CURRENT606_SOURCE_ONLY' and qualification['actual'] is None
         and status['exit'] == 0 and status['cap'] == 300 and status['timeout'] is status['retry'] is False,
         'exact prior reader PASS and original 4 KiB failure custody')
    need(post['public']['base/installed-packages.lock']['sha256'] == PIN['builder']
         and post['public']['generated/qemu-context/expected590.lock']['sha256'] == PIN['controller'],
         'exact original574 builder and590 controller inventory evidence')
    rows = files_at(args.original_reader)
    need(rows == post['reader_files'], 'all exact original757 reader bytes')
    source_rows = files_at(args.source)
    manifest = decode(read(args.source/'source-manifest.json'))
    need(manifest['status'] == 'SOURCE_ONLY_CURRENT606_EXACT_FRESH_TEST_INGRESS'
         and manifest['actual_source'] is manifest['actual_ref'] is manifest['actual_run'] is None
         and manifest['files'] == {n:w for n,w in source_rows.items() if n != 'source-manifest.json'}
         and source_rows['factory/expected606.lock']['sha256'] == PIN['guest'], 'whole fresh source, exact guest lock and NULL actual authority')
    need(args.output == args.output.resolve() and args.output.parent.is_dir() and not args.output.exists()
         and not args.output.is_relative_to(args.source) and not args.output.is_relative_to(args.original_reader)
         and not args.output.is_relative_to(args.assets), 'fresh reader output disjoint from previous custody')
    raw = {n: read(args.original_reader/n, 32*1024**2, w) for n,w in rows.items()}
    old_known = decode(raw['known-source.json'])
    profile = decode(raw['reader-profile.json'])
    flow = dict(old_known, source=None, ref=None, source_path=str(args.source))
    for name in FILES:
        raw.pop(name)
    if args.publication:
        for name in FILES:
            raw[name] = read(args.publication/name, 4*1024**2)
        pub, authorization, git = (decode(raw[n]) for n in FILES)
        src, ref = pub['source'], pub['ref']
        need(pub == dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=src,ref=ref,files=len(source_rows),git_joins=len(source_rows),actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
             and authorization.get('files',authorization) == git['files'] == source_rows and git['source'] == src
             and git['status'] == 'PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN', 'genuine whole current Source publication and Git closure')
        flow.update(source=src, ref='refs/heads/'+ref)
    profile.update(source_path=str(args.source), source_files=source_rows, original_assets=str(args.assets), original_asset_files=files_at(args.assets))
    need(all(value is None for value in flow['runs'].values()) and flow['workflow_id'] is None, 'new reader may bind only an unopened run')
    raw['reader-profile.json'] = encoded(profile)
    raw['known-source.json'] = raw['binding-template.json'] = encoded(flow)
    raw['fresh606_reader.py'] = NEW_READER.encode()
    raw['fresh606-reader-basis.json'] = encoded(dict(original_reader=str(args.original_reader), original_reader_files=rows,old_source=old_known['source'],
        historical_records={str(args.basis):BASIS, str(args.qualification):QUALIFICATION, str(args.qualification_output):QUALIFICATION_OUTPUT}))
    raw['source.py'] = replace(raw['source.py'], b" return H.load('_service_whole756_context',HERE/'service_context.py').parent_preflight(H,HERE)\n",
                               b" return H.load('_held_service1800_reader_basis',HERE/'fresh606_reader.py').basis(H,HERE)\n")
    raw['verify.py'] = replace(raw['verify.py'], b' inv=H.read(public/\'actual-invocation.json\');',
                              b" ingress=H.load('_current606_new_ingress_reader',H.HERE/'fresh606_reader.py').verify(H,root,public,originals,binding,case,own)\n inv=H.read(public/'actual-invocation.json');")
    raw['verify.py'] = replace(raw['verify.py'], b'value=dict(service_validation_DATA=service_data,', b'value=dict(fresh_test_ingress_DATA=ingress,service_validation_DATA=service_data,')
    for name, body in raw.items():
        if name.endswith('.py'):
            compile(body,name,'exec')
    args.output.mkdir(mode=0o700)
    for name, body in sorted(raw.items()):
        path = args.output/name
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:
            stream.write(body)
        parent_leaf = args.original_reader/name
        path.chmod(parent_leaf.stat().st_mode & 0o777 if parent_leaf.is_file() else 0o644)
    return dict(status='EMITTED_FRESH606_READER_NO_ACTUAL_CASE',reader_files=len(raw),source_files=len(source_rows), actual=None,
                publication=flow['source'], source_map_pin=pin(encoded(source_rows)), reader_map_pin=pin(encoded({n:pin(b) for n,b in raw.items()})))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('original-reader','basis','qualification','qualification-output','source','assets','output'):
        parser.add_argument('--'+field,required=True,type=lambda p:Path(p).absolute())
    parser.add_argument('--publication',type=lambda p:Path(p).absolute())
    print(json.dumps(build(parser.parse_args()),sort_keys=True))
