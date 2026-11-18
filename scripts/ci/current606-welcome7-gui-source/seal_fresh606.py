#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only rebind of the exact progress576 case to the actual 606 TEST public packet."""

import argparse
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fresh606 import DOCUMENTS, PUBLIC_MEMBERS, SCOPE, close, current, decode, encoded, need, pin, read


HERE = Path(__file__).resolve().parent
MANIFEST = {'bytes': 100980, 'sha256': '546c0b3a374393290a217eed78040f4feaa46476a60ab51220d1b9e39c330535'}
INDEPENDENT = {'bytes': 13946, 'sha256': '5371ef0794cda49d6ef8edbbb53185ea4d31af34d3c7834097e6b429ee994863'}
TERMINAL = {'bytes': 2408, 'sha256': '1fa4c31d663b993338cd56f1e52f623be0937c5402a183f8b646532aaec92d24'}
PARSER = {'bytes': 5557, 'sha256': '67117180079bc527f7b58d023cb4eb530a3960745f48520352da92274ac30a6f'}
SELECTED_FINGERPRINT = '7F17A10021208924CCB32A70DEB2CB5E7C601EE9'
WORKFLOWS = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-current606-welcome8-gui.yml')
ORIGINAL_TEST_STEP = b'      -\n        "name": "Checkout exact original GUI TEST signature overlay"\n'
NEXT_STEP = b'      -\n        "name": "Checkout complete original574 retained input source"\n'
EXACT_LOCKS = {
    'factory/expected606.lock': '9674da5a122395df4c496e7af4ed68dfb091d0793e184eff7d317bbb4df1dcf9',
    'factory/installed606_progress.py': None,
}
CONTEXT = 'fresh-test/progress576-inverse.json'
SELECT = 'fresh-test/selection.json'
CHANGED = {'admission.py', 'factory/factory.py', 'factory/service_capacity.py', 'native.py', *WORKFLOWS}


def replace(raw, before, after):
    need(raw.count(before) == 1, 'exact single original 606 seam: ' + before[:60].decode())
    return raw.replace(before, after, 1)


def index(packet, independent_path, terminal_path):
    independent = decode(read(independent_path, want=INDEPENDENT))
    terminal = decode(read(terminal_path, want=TERMINAL))
    need(independent['issuer'] == terminal['issuer'] == 'Root' and independent['status'] == 'PASS_INDEPENDENT_CURRENT606_PUBLIC_TEST_SIGNER_ONLY'
         and terminal['status'] == 'CLOSED_CURRENT606_FRESH_TEST_SIGNER_ONLY_PASS' and independent['signer']['fingerprint'] == SELECTED_FINGERPRINT
         and independent['Root_qualification'] is independent['public_source'] is independent['active_run'] is None,
         'exact independent current public-only signer and owned terminal facts')
    files = independent['file_pins']['public']
    raw = close(packet, files, original=True)
    catalog = decode(raw['catalog.json'])
    facts = decode(raw['Root-public-verification.json'])
    need(facts['key'] == independent['signer'] == terminal['signer']
         and facts['status'] == 'PASS_ROOT_LOCAL_TEST_SUCCESSOR_PUBLIC_RSA_MATH'
         and facts['Root_issued'] is False and facts['Root_acceptance'] is None
         and facts['private_generated_home_retired'] is facts['public_verify_home_retired'] is facts['public_verify_agent_retired'] is True
         and terminal['original_custody_pass'] is True and independent['file_pins']['proof'] == pin(raw['Root-public-verification.json']),
         'actual original full signer proof and owned retirement')
    need(set(catalog['inputs']) == set(DOCUMENTS) and set(independent['detached']) == set(DOCUMENTS) | {'catalog'}, 'whole actual current detached selection')
    detached = {label: {key: row[key] for key in ('input_pin', 'signature_pin', 'gpgv_exit', 'status')}
                for label, row in independent['detached'].items()}
    signer_detached = {label: {key: row[key] for key in ('input_pin','signature_pin','gpg_exit','status')}
                       for label, row in facts['signatures'].items()}
    value = dict(scope=SCOPE, actual=None, production_trust=False, signer=independent['signer'],
                 window=independent['time_window'], signing=facts['signing'], independent_detached=detached, signer_detached=signer_detached,
                 public_files=files, documents=catalog['inputs'], independent_receipt_pin=INDEPENDENT, terminal_pin=TERMINAL)
    current(value, full_launch=True)
    projected = {name: raw[name] for name in PUBLIC_MEMBERS}
    need(not any(b'/home/' in member or b'/tmp/' in member for member in [*projected.values(), encoded(value)]), 'source projection carries no host paths')
    return value, projected


GUARD = '''
def _ingress_original(root):
 root=Path(root).absolute()
 context=obj(root/'fresh-test/progress576-inverse.json')
 need(pin(enc(context))==_TEST_INGRESS_INVERSE,'whole progress576 ingress inverse')
 old_manifest=base64.b64decode(context['manifest'],validate=True)
 need(pin(old_manifest)==_TEST_INGRESS_PARENT,'whole immutable progress576 manifest')
 original_files={**json.loads(old_manifest)['files'],'source-manifest.json':pin(old_manifest)}
 future=obj(root/'source-manifest.json')
 need(future['actual_source'] is future['actual_ref'] is future['actual_run'] is None and future['status']=='SOURCE_ONLY_CURRENT606_EXACT_FRESH_TEST_INGRESS','unissued new GUI Source scope')
 need(set(future['files'])==set(original_files)-{'source-manifest.json'}|set(_TEST_INGRESS_ADDED),'exact fresh ingress source delta')
 closed(root,{**future['files'],'source-manifest.json':pin(read(root/'source-manifest.json'))})
 need(all(future['files'][name]==want for name,want in _TEST_INGRESS_NEW.items()),'all exact bound fresh ingress functions and public proof bytes')
 before={n:base64.b64decode(raw,validate=True) for n,raw in context['before'].items()}
 before['source-manifest.json']=old_manifest
 def prior_read(path,cap=16*1024**2):
  name=Path(path).relative_to(root).as_posix();raw=before[name] if name in before else read(path,cap)
  need(name in original_files and len(raw)<=cap and pin(raw)==original_files[name],'whole original progress576 byte '+name);return raw
 def prior_closed(where,wanted):
  prefix='' if where==root else where.relative_to(root).as_posix()+'/'
  need({n.removeprefix(prefix):w for n,w in original_files.items() if n.startswith(prefix)}==wanted,'only original progress source namespace')
  for n in wanted:prior_read(where/n)
  return wanted
 for name in original_files:prior_read(root/name)
 prior=types.ModuleType('_exact_current606_progress576');prior.__file__=str(root/'admission.py')
 exec(compile(before['admission.py'],prior.__file__,'exec'),vars(prior))
 prior.read=prior_read;prior.obj=lambda p:json.loads(prior_read(p));prior.closed=prior_closed
 return prior

def source_context(root):
 return dict(_ingress_original(root).source_context(root),files=_TEST_INGRESS_COUNT,fresh_ingress='PUBLIC_ONLY_CURRENT_TEST_INPUTS')

def prove(root):
 parent=_ingress_original(root).prove(root)
 need(parent['files']==576 and parent['fullscan_seconds']==600,'whole original progress and unchanged600 deadline')
 return dict(parent,files=_TEST_INGRESS_COUNT,fresh_ingress='PUBLIC_ONLY_CURRENT_TEST_INPUTS',status='PASS_COMPLETE_PROGRESS576_AND_FRESH_TEST_INGRESS_SOURCE_ONLY')
'''


def pieces(predecessor, packet, parser, independent, terminal):
    manifest_raw = read(predecessor/'source-manifest.json', want=MANIFEST)
    manifest = decode(manifest_raw)
    before_map = {**manifest['files'], 'source-manifest.json': MANIFEST}
    all_paths = list(predecessor.rglob('*'))
    need(all(not path.is_symlink() for path in all_paths)
         and {path.relative_to(predecessor).as_posix() for path in all_paths if path.is_file()} == set(before_map), 'whole ordinary progress576 source')
    files = {name: read(predecessor/name, cap=16*1024**2, want=w) for name,w in before_map.items()}
    for name, digest in EXACT_LOCKS.items():
        need(name in files and (digest is None or pin(files[name])['sha256'] == digest), 'held exact606 inventory and progress implementation')
    data, packet_files = index(packet, independent, terminal)
    old = {name: base64.b64encode(files[name]).decode() for name in CHANGED}
    files[CONTEXT] = encoded(dict(manifest=base64.b64encode(manifest_raw).decode(), before=old))
    files[SELECT] = encoded(data)
    files['factory/fresh606.py'] = read(HERE/'fresh606.py')
    files['factory/public_certificate.py'] = read(parser, want=PARSER)
    for name, raw in packet_files.items():
        files['fresh-test/public/'+name] = raw

    old_step = files[WORKFLOWS[0]].split(ORIGINAL_TEST_STEP,1)[1].split(NEXT_STEP,1)[0]
    for name in WORKFLOWS:
        raw = replace(files[name], ORIGINAL_TEST_STEP+old_step, b'')
        raw = replace(raw, b'$GITHUB_WORKSPACE/test-renewal', b'$GITHUB_WORKSPACE/gui606-source/fresh-test/public')
        raw = replace(raw, b'python3 -I -B \\"$SLICE/test_lane.py\\"', b'python3 -I -B \\"$CURRENT\\" presecret')
        files[name] = raw
    need(files[WORKFLOWS[0]] == files[WORKFLOWS[1]], 'both unchanged workflow aliases share the exact versioned public TEST binding')
    raw = files['native.py']
    raw = replace(raw, b'def proof(case,state,env):\n', b"def fresh():return load('_current606_ingress',ROOT/'factory/fresh606.py')\ndef fresh_data():return A.obj(ROOT/'fresh-test/selection.json')\n\ndef proof(case,state,env):\n fresh().current(fresh_data(),full_launch=True)\n")
    raw = replace(raw, b"original348=old,actual_GUI=", b"original348=old,fresh_test_selection=A.pin(A.read(ROOT/'fresh-test/selection.json')),actual_GUI=")
    raw = replace(raw, b'  import input606\n', b"  f=fresh();f.current(fresh_data(),full_launch=False);f.recorded(fresh_data(),A.obj(assets/f.INDEX))\n  import input606\n")
    raw = replace(raw, b"('preflight','proof','assets','run','cleanup','retain','transport')", b"('preflight','presecret','proof','assets','run','cleanup','retain','transport')")
    raw = replace(raw, b' a=p.parse_args();A.prove(ROOT)\n', b' a=p.parse_args()\n')
    raw = replace(raw, b' state=a.state.absolute();selected(a.case)\n', b" if a.phase=='presecret':\n  A.prove(ROOT);return fresh().presecret(ROOT/'original',Path(os.environ['WELCOME5_GUI_ASSETS']).absolute())\n state=a.state.absolute();selected(a.case)\n")
    raw = replace(raw, b"original().assets.prepare(ROOT/'original',a.public.absolute(),a.project.absolute(),a.output.absolute(),a.renewal.absolute())",
                  b"fresh().prepare_assets(ROOT/'original',a.public.absolute(),a.project.absolute(),a.output.absolute(),a.renewal.absolute(),original().assets)")
    files['native.py'] = raw
    files['factory/factory.py'] = replace(files['factory/factory.py'], b';held.prepare(root,assets,out,selected)\n',
                                         b";load('_current606_fresh_ingress',HERE/'fresh606.py').prepare_code(held,root,assets,out,selected)\n")
    before = b";raw=read(Path(namespace['__file__']));need(raw.endswith(FACTORY_FOOTER.encode())"
    original_call = b';held.prepare(root,assets,out,selected)\n'
    selected_call = b";load('_current606_fresh_ingress',HERE/'fresh606.py').prepare_code(held,root,assets,out,selected)\n"
    progress_call = b"    changes['installed606_progress']=load('_installed606_progress',HERE/'installed606_progress.py').apply(out,pin)\n"
    join = (";raw=read(Path(namespace['__file__']));progress=" + repr(progress_call) + ";ingress=" + repr(selected_call)
            + ";need(raw.count(progress)==raw.count(ingress)==1,'exact selected observer and TEST ingress factory seams');raw=raw.replace(progress,b'',1).replace(ingress,"
            + repr(original_call) + ",1);need(raw.endswith(FACTORY_FOOTER.encode())").encode()
    files['factory/service_capacity.py'] = replace(files['factory/service_capacity.py'], before, join)
    additions = sorted(set(files)-set(before_map))
    new = {n: pin(files[n]) for n in sorted(set(additions)|CHANGED-{'admission.py'})}
    files['admission.py'] += (f'\n_TEST_INGRESS_INVERSE={pin(files[CONTEXT])!r}\n_TEST_INGRESS_PARENT={MANIFEST!r}\n'
                              f'_TEST_INGRESS_ADDED={additions!r}\n_TEST_INGRESS_NEW={new!r}\n'
                              f'_TEST_INGRESS_COUNT={len(files)!r}\n' + GUARD).encode()
    files.pop('source-manifest.json')
    manifest['status'] = 'SOURCE_ONLY_CURRENT606_EXACT_FRESH_TEST_INGRESS'
    manifest['files'] = {name: pin(raw) for name,raw in files.items()}
    files['source-manifest.json'] = encoded(manifest)
    return files


def emit(predecessor, packet, parser, independent, terminal, output):
    need(output == output.resolve() and output.parent.is_dir() and not output.exists()
         and not output.is_relative_to(predecessor) and not output.is_relative_to(packet), 'fresh isolated source output')
    files = pieces(predecessor, packet, parser, independent, terminal)
    for name, raw in files.items():
        if name.endswith('.py'):
            compile(raw, name, 'exec')
    output.mkdir(mode=0o700)
    for name, raw in sorted(files.items()):
        dest = output/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(raw)
        old = predecessor/name
        dest.chmod(old.stat().st_mode & 0o777 if old.exists() else 0o644)
    return dict(status='EMITTED_FRESH606_TEST_SOURCE_ONLY', files=len(files), manifest=pin(files['source-manifest.json']), actual=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('predecessor', 'packet', 'certificate-parser', 'independent', 'terminal', 'output'):
        parser.add_argument('--'+field, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(emit(*(p.absolute() for p in vars(args).values())), sort_keys=True))
