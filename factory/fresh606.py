# SPDX-License-Identifier: MIT
"""Public-only TEST ingress for the four frozen current606 GUI operands."""

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
LANE = 'scripts/ci/welcome5-native-gui'
OLD_SOURCES = {'native73': '1057f6b5494adc71c469e8867d14fb0db01ce02f',
               'held77': '77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90'}
ROLES = ('dns2', 'doctor', 'orphans', 'welcome5')
DOCUMENTS = (*ROLES, 'held77-index', 'native73-index')
INDEX = 'fresh-test-ingress.json'
SCOPE = 'CURRENT606_GUI_TEST_PUBLIC_INGRESS_ONLY'
PUBLIC_MEMBERS = {'LICENSE', 'catalog.json', 'catalog.json.sig', 'index.json', 'public-key.asc',
                  *(f'signatures/{n}.sig' for n in DOCUMENTS)}
ORIGINAL_PUBLIC_MEMBERS = PUBLIC_MEMBERS | {'Root-public-verification.json', 'provenance.json'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path, cap=1024**2, want=None):
    need(path == path.absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary canonical input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'bounded ordinary public leaf')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before, f) == getattr(after, f) == getattr(path.lstat(), f) for f in fields), 'stable exact public leaf')
    need(want is None or pin(raw) == want, 'whole public leaf differs: ' + path.name)
    return raw


def decode(raw):
    def pairs(values):
        result = dict(values)
        need(len(values) == len(result), 'duplicate public metadata key')
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def close(packet, files, *, original=False):
    expected = ORIGINAL_PUBLIC_MEMBERS if original else PUBLIC_MEMBERS
    need(set(files) == expected and packet.is_dir(), 'closed selected public TEST packet')
    physical = {p.relative_to(packet).as_posix() for p in packet.rglob('*') if not p.is_dir()}
    dirs = {p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_dir()}
    need(physical == expected and dirs == {'signatures'} and not any(p.is_symlink() for p in packet.rglob('*')), 'only public certificate/signatures/metadata')
    return {n: read(packet / n, 128 * 1024, w) for n, w in files.items()}



SERIAL_PAIR = ('minimal-generic16k', 'overlay-generic16k')
SERIAL_STATUS = 'APPROVED_CURRENT606_PUBLIC_TEST_SERIAL_ARM16K_WINDOW'
SERIAL_SCOPE = 'CURRENT606_GUI_TEST_PUBLIC_INGRESS_SERIAL_ARM16K_ONLY'

def case_window(data, case):
    window = data['window']
    if case not in SERIAL_PAIR:
        return window, window['start']
    review = data['serial_pair_review']
    approved = review['approved_utc']
    need(pin(encoded(review)) == data['serial_pair_review_pin']
         and review['scope'] == SERIAL_SCOPE and review['status'] == SERIAL_STATUS
         and review['issuer'] == 'Root' and review['case_order'] == list(SERIAL_PAIR)
         and review['production_trust'] is False and review['native_acceptance'] is False
         and review['signer_terminal'] == data['terminal_pin']
         and review['independent_signer'] == data['independent_receipt_pin']
         and review['packet_index'] == data['public_files']['index.json']
         and review['certificate'] == data['signer']
         and review['original_window'] == window
         and type(approved) is int and window['start'] <= approved,
         'exact Root scoped public TEST serial ARM16K review')
    higher = review['serial_window']
    need(higher == dict(start=window['start'], end=window['start']+86400,
                       seconds=86400, min_remaining_seconds=28620, observed=approved)
         and approved <= higher['end'] - 28620
         and higher['end'] < data['signer']['expires'],
         'reviewed 24-hour public TEST window with full unchanged launch reserve')
    return higher, approved


def current(data, *, full_launch, case=None):
    window, allowed = case_window(data, case)
    key, start, end, now = data['signer'], window['start'], window['end'], time.time()
    need(key['key_created'] == key['certificate_selfsig_created'] == key['validity_anchor'] == start
         and key['expires'] - start == 14 * 86400 and start <= allowed <= now < end < key['expires']
         and end - start == window['seconds'] == (86400 if case in SERIAL_PAIR else 43200)
         and window['min_remaining_seconds'] == 28620,
         'actual current TEST certificate and exact case-approved window')
    need(not full_launch or end - now >= 28620, 'TEST window has less than 477 minutes remaining for new entry')
    return now


def signature_status(text, key, signing):
    need(type(text) is str and len(text) <= 8192 and '\0' not in text, 'finite public-only machine signature status')
    lines = text.splitlines()
    need(all(line.startswith('[GNUPG:] ') for line in lines), 'only framed GPG status')
    rows = [line.split()[1:] for line in lines]
    need(all(row and row[0] in {'NEWSIG', 'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG', 'TRUST_UNDEFINED'} for row in rows), 'invalid or unknown GPG status')
    valid = [row for row in rows if row[0] == 'VALIDSIG']
    good = [row for row in rows if row[0] == 'GOODSIG']
    fp = key['fingerprint']
    need(len(valid) == len(good) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == fp
         and valid[0][4:10] == ['0', '4', '0', '1', '8', '00'] and good[0][1] == fp[-16:]
         and ' '.join(good[0][2:]) == key['uid'], 'one exact nonexpiring RSA/SHA256 detached TEST signature')
    creation = int(valid[0][3])
    need(signing['started'] <= creation <= signing['finished'] and valid[0][2] == time.strftime('%Y-%m-%d', time.gmtime(creation)), 'same fresh signer UTC interval')


def data_only(data, packet, bodies):
    need(data['scope'] == SCOPE and data['actual'] is None and data['production_trust'] is False, 'only selected 606 TEST ingress data')
    need(set(data['public_files']) == ORIGINAL_PUBLIC_MEMBERS, 'whole independently verified original public13 digest map')
    raw = close(packet, {name: data['public_files'][name] for name in PUBLIC_MEMBERS})
    cert = load('_reviewed_public_certificate_parser', HERE / 'public_certificate.py')
    key = data['signer']
    need(cert.parse_public_certificate(raw['public-key.asc']) == key, 'exact genuine TEST public certificate identity')
    index = decode(raw['index.json'])
    need(index['files'] == {name: row for name, row in data['public_files'].items() if name not in {'LICENSE', 'index.json'}}, 'all exact indexed public files')
    catalog = decode(raw['catalog.json'])
    need(catalog['inputs'] == data['documents'] and catalog['signer'] == key['fingerprint'] and catalog['expires'] == key['expires'], 'exact six unchanged bodies signed under current TEST certificate')
    need(set(bodies) == set(DOCUMENTS) and set(data['signer_detached']) == set(data['independent_detached']) == set(DOCUMENTS) | {'catalog'}, 'whole six original bodies and catalog')
    expected = {'catalog': raw['catalog.json']}
    for label, path in bodies.items():
        expected[label] = read(path, want=data['documents'][label]['pin'])
    for label, body in expected.items():
        name = 'catalog.json.sig' if label == 'catalog' else f'signatures/{label}.sig'
        first = data['signer_detached'][label]
        second = data['independent_detached'][label]
        need(first['gpg_exit'] == second['gpgv_exit'] == 0 and first['input_pin'] == second['input_pin'] == pin(body)
             and first['signature_pin'] == second['signature_pin'] == pin(raw[name]), 'exact signer and independent verifier body/signature joins')
        signature_status(first['status'], key, data['signing'])
        signature_status(second['status'], key, data['signing'])
    return raw, expected, data['signing'], cert.unarmor(raw['public-key.asc'])


def operand_paths(public, project, data):
    bases = {'native73': project, 'held77': public}
    return {label: bases[row['carrier']] / row['path'] for label, row in data['documents'].items()}


def asset_bodies(assets, data):
    paths = {}
    for label, row in data['documents'].items():
        relative = Path(row['path']).relative_to('payload')
        if row['carrier'] == 'held77':
            path = assets / 'held' / relative.name if label in ROLES else assets / 'fresh-held77-index.json'
        else:
            path = assets / 'welcome5' / relative
        paths[label] = path
    return paths


def verify_live(data, packet, bodies, *, case=None):
    started = current(data, full_launch=True, case=case)
    raw, contents, signing, binary = data_only(data, packet, bodies)
    deadline = time.monotonic() + 60
    report = {}
    with tempfile.TemporaryDirectory(prefix='current606-public-only-') as td:
        home = Path(td)
        ring = home / 'keyring.gpg'
        ring.write_bytes(binary)
        env = dict(PATH='/usr/bin:/bin', HOME=td, LC_ALL='C', TZ='UTC')
        for label, content in contents.items():
            name = 'catalog.json.sig' if label == 'catalog' else f'signatures/{label}.sig'
            body, sig = home / (label + '.body'), home / (label + '.sig')
            body.write_bytes(content)
            sig.write_bytes(raw[name])
            result = subprocess.run(['/usr/bin/gpgv', '--homedir', td, '--keyring', str(ring), '--status-fd', '1', '--', str(sig), str(body)],
                                    env=env, stdin=subprocess.DEVNULL, capture_output=True, check=True,
                                    timeout=min(10, max(.01, deadline - time.monotonic())))
            need(len(result.stderr) <= 8192 and time.monotonic() < deadline, 'bounded public-only verification')
            text = result.stdout.decode('utf-8', 'strict')
            signature_status(text, data['signer'], signing)
            report[label] = dict(input_pin=pin(content), signature_pin=pin(raw[name]), gpgv_exit=0, status=text)
    # Bind the copy to the same stable files that were mathematically checked.
    late_raw, late_contents, _, _ = data_only(data, packet, bodies)
    need(late_raw == raw and late_contents == contents, 'late whole original/fresh packet identity')
    case_data = dict(serial_case=case, verification_started=started) if case in SERIAL_PAIR else {}
    return dict(scope=SCOPE, certificate=data['signer'], window=case_window(data,case)[0],
                verified=current(data, full_launch=False, case=case), **case_data,
                packet_index=data['public_files']['index.json'], detached=report, public_verifier_home_retired=not home.exists(), actual=None)


def recorded(data, receipt, *, run_start=None, run_end=None, case=None):
    stated = receipt.get('serial_case')
    need((case is None and (stated is None or (stated in SERIAL_PAIR and run_start is run_end is None)))
         or (stated == (case if case in SERIAL_PAIR else None)), 'same exact public TEST case')
    window, allowed = case_window(data, stated)
    need(receipt['scope'] == SCOPE and receipt['certificate'] == data['signer'] and receipt['window'] == window
         and receipt['packet_index'] == data['public_files']['index.json'] and receipt['public_verifier_home_retired'] is True
         and receipt['actual'] is None and set(receipt['detached']) == set(DOCUMENTS) | {'catalog'}, 'scoped live public verification receipt')
    verified = receipt['verified']
    need(type(verified) in (int, float) and math.isfinite(verified) and allowed <= verified < window['end'], 'finite verified TEST window')
    if stated is not None:
        started = receipt['verification_started']
        need(type(started) in (int, float) and math.isfinite(started)
             and allowed <= started <= verified and window['end'] - started >= window['min_remaining_seconds'],
             'actual public verification began with the full unchanged reserve')
    if run_start is not None or run_end is not None:
        need(type(run_start) in (int, float) and type(run_end) in (int, float)
             and allowed <= run_start <= verified <= run_end < window['end']
             and (stated is None or run_start <= started)
             and window['end'] - run_start >= window['min_remaining_seconds'], 'actual case interval inside the qualified TEST launch window')
    for role, row in receipt['detached'].items():
        expected = data['independent_detached'][role]
        need(type(row['gpgv_exit']) is int and row['gpgv_exit'] == 0 and row['input_pin'] == expected['input_pin']
             and row['signature_pin'] == expected['signature_pin'], 'observed seven signature role pins')
        signature_status(row['status'], data['signer'], data['signing'])
    return receipt


def prepare_assets(source, public, project, output, packet, original_assets, *, case=None):
    data = decode(read(source.parent / 'fresh-test/selection.json'))
    need(packet == source.parent / 'fresh-test/public' and not output.exists(), 'Source-owned TEST packet and fresh output')
    original_assets.revision(public, OLD_SOURCES['held77'])
    original_assets.revision(project, OLD_SOURCES['native73'])
    bodies = operand_paths(public, project, data)
    receipt = verify_live(data, packet, bodies, case=case)
    policy = original_assets.C.selection(source)
    value = original_assets.assemble_data(source, public / 'payload', project / 'payload', output, policy)
    shutil.copytree(packet, output / 'fresh-test-public')
    (output / 'fresh-held77-index.json').write_bytes(read(bodies['held77-index'], want=data['documents']['held77-index']['pin']))
    (output / INDEX).write_bytes(encoded(receipt))
    data_only(data, output/'fresh-test-public', asset_bodies(output, data))
    return dict(value, status='PREPARED_EXACT606_CURRENT_PUBLIC_TEST_INPUTS_ONLY', fresh_test=receipt)


def projected(assets, products, data, lock):
    raw, _, _, _ = data_only(data, assets/'fresh-test-public', asset_bodies(assets, data))
    receipt = recorded(data, decode(read(assets/INDEX)))
    control = decode(read(products/'control.json'))
    need(set(control) == {'signer'} and re.fullmatch('[A-F0-9]{40}', control['signer']), 'closed historical disposable trust projection')
    for role in ROLES:
        name = Path(data['documents'][role]['path']).name
        read(products/name, want=data['documents'][role]['pin'])
    for role in ROLES:
        leaf = Path(data['documents'][role]['path']).name
        (products/(leaf+'.sig')).write_bytes(raw[f'signatures/{role}.sig'])
    key = data['signer']['fingerprint']
    for name in ('TEST-public.asc', 'welcome5-TEST.asc'):
        (products/name).write_bytes(raw['public-key.asc'])
    (products/'control.json').write_bytes(encoded(dict(signer=key)))
    (products/'trust.json').write_bytes(encoded([dict(key='welcome5-TEST.asc', signer=key)]))
    (products/'test-signature-renewal.json').write_bytes(encoded(receipt))
    return lock


def prepare_code(held, original, assets, output, selected):
    data = decode(read(original.parent/'fresh-test/selection.json'))
    data_only(data, assets/'fresh-test-public', asset_bodies(assets, data))
    recorded(data, decode(read(assets/INDEX)))
    previous = held.A
    scoped = load('_current606_private_candidate_stage', held.HERE/'candidates.py')
    scoped.stage = lambda source, inputs, products: projected(inputs, products, data, scoped.stage_data(source, inputs, products, scoped.selection(source)))
    held.A = scoped
    try:
        return held.prepare(original, assets, output, selected)
    finally:
        held.A = previous


def presecret(original, assets):
    # The original test suite owns its own mocked no-actor prepare calls.
    import unittest
    from unittest.mock import patch
    sys.path.insert(0, str(original / LANE))
    import prepare as held
    prepare = held.prepare
    original_prepare = load('_current606_original_private_prepare', held.HERE/'prepare.py')
    with patch.object(held, 'prepare', side_effect=lambda s, a, out, selected: prepare_code(original_prepare, s, a, out, selected)):
        tests = load('_current606_held_presecret_unittest', original/LANE/'test_lane.py')
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(tests))
        need(result.wasSuccessful() and result.testsRun > 0 and held.prepare is not prepare, 'complete original presecret suite with fresh source-owned projection')
