#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit project TEST native-provider admission; official v18 stays unchanged."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREDECESSOR = '8128cd73c85d533092d081f0b9131b2ca9893ecd'
BASE = HERE.parent / 'successor_v18/payload/hosted/build_dependencies.py'
BASE_PIN = dict(bytes=20374, sha256='ba8aaf5b89c5fa318ce1595bbb486edec270b8e0f4ea71975c42a0f70046e882')
PACKETS_PIN = dict(bytes=9009, sha256='6926902e69e639b999aa67d7ff01b617ec7c57e9074ba8d52330f21cf24edfa9')
SPECS_PIN = dict(bytes=2977, sha256='8efd0c4b1652a6b26528c1d14c6591963284d2e7c2bad4586ee49080ef7ea2d8')
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'image', 'Root_acceptance', 'native_acceptance'))
QUALIFICATION = dict(cap0_phases=['data', 'probe'], cli_probes=9,
                     resources_changed=False, makepkg_dependency_checks=True)
HELPERS = {
    'archive.py': dict(bytes=6619, sha256='8784e0bd57d8e59fce745022eaa8283ad99c76b15aa8d589ec1d0681cfe4b774'),
    'native.py': dict(bytes=13523, sha256='a14397834ad37129943a288373558a51383fe097ddd555ca032153fdde4903f0'),
    'image.py': dict(bytes=12066, sha256='64c60a0ba986e883451bdffb0a30af8eec40d49ee98b8fcd46e1ccbace3baca7'),
}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def module(path, expected=None):
    path = Path(path)
    if expected is None and path.parent == HERE:
        need(path.name in HELPERS, 'explicit whole-pinned project helper only')
        expected = HELPERS[path.name]
    need(path == path.resolve() and path.is_file() and path.stat().st_nlink == 1
         and path.stat().st_size <= 128 * 1024, 'ordinary bounded trusted admission helper')
    raw = path.read_bytes()
    need(expected is None or pin(raw) == expected, 'exact immutable predecessor/helper bytes')
    value = types.ModuleType('project_test_' + path.stem)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def base():
    return module(BASE, BASE_PIN)


D = base()
S = module(ROOT / 'scripts/ci/management-tools-generic16k/signature_observer.py', PACKETS_PIN)
raw_specs = D.read(HERE / 'recipes.DATA.json', D.MIB)
need(pin(raw_specs) == SPECS_PIN, 'immutable original project recipe selection')
SPECS = D.decode(raw_specs)
encode, decode = D.encode, D.decode


def reference(row, cap=D.INPUT_CAP):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'explicit whole relative reference')
    D.relative(row['path'])
    need(not set(Path(row['path']).parts) & {'.gnupg', '.ssh', '.aws', '.config'}, 'no private keyhome/credential domain')
    D.descriptor({k: row[k] for k in ('bytes', 'sha256')}, cap)
    return row


def read_ref(root, row, cap=D.INPUT_CAP, tick=lambda: None):
    reference(row, cap)
    path = Path(root) / row['path']
    need(not path.lstat().st_mode & 0o022, 'retained provider input must not be writable by others')
    raw = D.read(path, min(cap, row['bytes']), tick)
    need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'whole retained project input differs')
    return raw


def validate_policy(p):
    need(type(p) is dict and set(p) == {'schema', 'kind', 'predecessor', 'parent350', 'trust', 'packages', 'qualification', 'actual'}
         and type(p['schema']) is int and p['schema'] == 1
         and p['kind'] == 'PROJECT_TEST_NATIVE_BUILD_DEPENDENCIES_V1'
         and p['predecessor'] == PREDECESSOR and p['parent350'] == D.PARENT350
         and encode(p['actual']) == encode(ACTUAL) and encode(p['qualification']) == encode(QUALIFICATION),
         'separate unissued project TEST policy; no official/v18 policy substitution')
    t = p['trust']
    need(type(t) is dict and set(t) == {'scope', 'public_key', 'primary_fingerprint', 'signing_fingerprint', 'ALARM_authentication'}
         and t['scope'] == 'PROJECT_TEST_ONLY' and t['ALARM_authentication'] is False,
         'explicit separate project TEST trust')
    reference(t['public_key'], S.MAX_PUBLIC)
    for key in ('primary_fingerprint', 'signing_fingerprint'):
        need(type(t[key]) is str and re.fullmatch('[0-9A-F]{40}', t[key]) and t[key] != D.SIGNER,
             'full explicit project fingerprint; never ALARM signer')
    rows = p['packages']
    need(type(rows) is list and len(rows) == 2 and all(type(r) is dict for r in rows)
         and {r.get('name') for r in rows} == set(SPECS), 'exact two project provider packages')
    names, providers, total = set(), set(), 0
    for row in rows:
        need(type(row) is dict and set(row) == {'name', 'version', 'filename', 'archive', 'signature', 'metadata', 'providers', 'license_provenance', 'url', 'native'}
             and row['name'] not in names, 'unique complete project package tuple')
        names.add(row['name']); spec = SPECS[row['name']]
        need(row['version'] == spec['version']
             and row['filename'] == row['name'] + '-' + spec['version'].split(':')[-1] + '-aarch64.pkg.tar.xz'
             and type(row['url']) is str and row['url'].startswith('https://') and len(row['url']) <= 2048,
             'fixed project version/XZ native output and recorded provenance')
        for key, cap in (('archive', D.INPUT_CAP), ('signature', 65536)):
            D.descriptor(row[key], cap); total += row[key]['bytes']
        m = row['metadata']
        need(type(m) is dict and set(m) == {'pkgname', 'pkgver', 'arch', 'license', 'depend', 'provides', 'conflict', 'replaces'}
             and m['pkgname'] == [row['name']] and m['pkgver'] == [row['version']] and m['arch'] == ['aarch64']
             and m['license'] == spec['licenses'] and m['depend'] == spec['dependencies']
             and m['conflict'] == spec['conflicts'] and m['replaces'] == [], 'exact original project metadata; no baseline replacement')
        need(all(type(values) is list and len(values) <= 64 and len(values) == len(set(values))
                 and all(type(v) is str and 0 < len(v) <= 255 and '\n' not in v and '\x00' not in v for v in values)
                 for values in m.values()), 'finite typed project metadata')
        short = 'llhttp' if 'llhttp' in row['name'] else 'git2'
        need(len(m['provides']) == 2 and spec['required_provides'][0] in m['provides']
             and any(re.fullmatch('lib' + short + r'\.so(?:=[A-Za-z0-9.+:-]+)?', v) for v in m['provides']),
             'actual complete version and SONAME provides; no planned metadata substitute')
        q = row['license_provenance']; prefix = 'dependency-provenance/' + row['name'] + '/'
        need(type(q) is dict and set(q) == {'url', 'revision', 'licenses', 'pkgbuild', 'buildinfo', 'license_files', 'recipe_files', 'sources'}
             and q['revision'] == spec['recipe_revision'] and q['licenses'] == m['license']
             and q['url'] == 'https://github.com/Gabriel-Kahen/cachy-asahi/blob/' + q['revision'] + '/' + spec['recipe_path'] + '/PKGBUILD',
             'immutable original project recipe/source/license provenance')
        reference(q['pkgbuild'], D.MIB); D.descriptor(q['buildinfo'], D.MIB)
        need(q['pkgbuild'] == dict(path=prefix + 'PKGBUILD', **spec['known_recipe_files']['PKGBUILD']), 'fixed original project recipe bytes')
        need(type(q['recipe_files']) is dict and 2 <= len(q['recipe_files']) <= 128
             and type(q['license_files']) is dict and set(q['license_files']) == {prefix + 'licenses/' + n for n in spec['license_files']},
             'complete recipe snapshot and required upstream license files')
        for name, wanted in q['recipe_files'].items():
            D.relative(name); D.descriptor(wanted, 4 * D.MIB)
            need(name.startswith(prefix) and '/licenses/' not in name and '/sources/' not in name, 'package-scoped recipe inputs')
            leaf = name[len(prefix):]
            if leaf in spec['known_recipe_files']:
                need(wanted == spec['known_recipe_files'][leaf], 'unchanged known original recipe input')
        need(all(q['recipe_files'].get(prefix + name) == spec['known_recipe_files'][name] for name in ('PKGBUILD', 'smoke.c')), 'original recipe and smoke inputs retained')
        for name, wanted in q['license_files'].items(): D.descriptor(wanted, D.MIB)
        source_name = prefix + 'sources/' + spec['source']['filename']
        wanted_source = {k: spec['source'][k] for k in ('url', 'revision', 'bytes', 'sha256')}
        need(q['sources'] == {source_name: wanted_source}, 'exact primary upstream source archive/revision/checksum')
        need(type(row['providers']) is dict and 1 <= len(row['providers']) <= 32, 'full finite provider inventory')
        for name, item in row['providers'].items():
            D.relative(name)
            need(name.startswith('usr/lib/') and name not in providers and type(item) is dict
                 and type(item.get('mode')) is int and 0 <= item['mode'] <= 0o777, 'unique exact provider path/mode')
            providers.add(name)
            if item.get('kind') == 'file':
                need(set(item) == {'kind', 'mode', 'bytes', 'sha256'}, 'regular provider descriptor')
                D.descriptor({k: item[k] for k in ('bytes', 'sha256')}, 16 * D.MIB)
            else:
                need(set(item) == {'kind', 'mode', 'target'} and item['kind'] == 'symlink' and item['mode'] == 0o777
                     and D.literal(item['target']) and '/' not in item['target'], 'internal declared provider alias')
    need(total <= D.INPUT_CAP, 'finite complete project package/signature inputs')
    return p


def root_decision(raw, expected_sha256, p, policy_pin, now):
    need(D.sha(expected_sha256) and pin(raw)['sha256'] == expected_sha256, 'independently selected external Root decision SHA required')
    decision = decode(raw)
    need(raw == encode(decision) and set(decision) == {'schema', 'kind', 'issuer', 'approved', 'scope', 'policy_pin', 'accepted_tuples', 'reviews', 'issued_at', 'expires_at', 'Root_acceptance', 'release_acceptance'}
         and type(decision['schema']) is int and decision['schema'] == 1
         and decision['kind'] == 'ROOT_ACCEPTED_NATIVE_PROJECT_TEST_PROVIDER_TUPLES_V1'
         and decision['issuer'] == 'Root' and decision['approved'] is True and decision['scope'] == 'PROJECT_TEST_ONLY'
         and decision['policy_pin'] == policy_pin
         and decision['accepted_tuples'] == {row['name']: pin(encode(row)) for row in p['packages']}
         and decision['reviews'] == dict(native_execution=True, clean_pair=True, normal_dependency_checks=True,
                                         complete_inventories=True, exact_source_license_bytes=True)
         and all(type(v) is bool for v in decision['reviews'].values())
         and decision['Root_acceptance'] is None and decision['release_acceptance'] is False,
         'explicit exact Root-reviewed native TEST tuples; no global/release acceptance')
    need(type(now) is int and type(decision['issued_at']) is type(decision['expires_at']) is int
         and 0 <= decision['issued_at'] <= now < decision['expires_at'] <= decision['issued_at'] + 86400,
         'fresh finite external Root review')
    return decision


def public_key(raw, trust):
    packets = S.packets(raw)
    need(all(tag in {2, 6, 13, 14, 17} for tag, _ in packets), 'only public transferable key packets; no secret/encrypted input')
    primary = [body for tag, body in packets if tag == 6]
    need(len(primary) == 1, 'one explicit public primary')
    fingerprints = []
    for tag, body in packets:
        if tag in (6, 14):
            need(len(body) >= 6 and body[0] == 4 and len(body) <= 65535, 'bounded v4 project public key')
            fingerprints.append(hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest().upper())
    need(fingerprints[0] == trust['primary_fingerprint'] and trust['signing_fingerprint'] in fingerprints, 'actual public TEST key fingerprints')


def audit_source(root, row, tick=lambda: None):
    q = row['license_provenance']; spec = SPECS[row['name']]
    for name, wanted in q['recipe_files'].items(): read_ref(root, dict(path=name, **wanted), 4 * D.MIB, tick)
    D.audit_provenance(root, row, tick)
    source_name, selected = next(iter(q['sources'].items()))
    source = read_ref(root, dict(path=source_name, **{k: selected[k] for k in ('bytes', 'sha256')}), D.INPUT_CAP, tick)
    wanted = {spec['source']['archive_prefix'] + '/' + Path(n).name: v for n, v in q['license_files'].items()}
    observed, total, count = {}, 0, 0
    import io
    with tarfile.open(fileobj=io.BytesIO(source), mode='r|gz') as archive:
        for member in archive:
            tick(); count += 1; total += member.size
            need(count <= 32768 and 0 <= member.size <= 32 * D.MIB and total <= 128 * D.MIB, 'finite upstream source audit')
            if member.name in wanted:
                need(member.isfile() and member.size <= D.MIB, 'regular actual upstream license')
                body = archive.extractfile(member).read()
                need(pin(body) == wanted[member.name] and member.name not in observed, 'whole actual upstream source license correspondence')
                observed[member.name] = pin(body)
            archive.members.clear()
    need(observed == wanted, 'every required upstream source license retained')
    return dict(recipe_files=q['recipe_files'], sources=q['sources'], licenses=q['license_files'])


def admit(source_root, policy_raw, policy_sha256, decision_raw, decision_sha256, *, now=None, tick=lambda: None):
    need(D.sha(policy_sha256) and pin(policy_raw)['sha256'] == policy_sha256, 'external exact project policy SHA')
    p = validate_policy(decode(policy_raw)); need(policy_raw == encode(p), 'canonical project policy')
    now = int(time.time()) if now is None else now
    decision = root_decision(decision_raw, decision_sha256, p, pin(policy_raw), now)
    expected = D.expected_inventory(source_root, p)
    baseline = D.inventory(D.read(Path(source_root) / 'expected349.lock', D.MIB))
    for row in p['packages']:
        need(not set(row['metadata']['conflict']) & set(baseline), 'project conflict may not replace any baseline package')
    key = read_ref(source_root, p['trust']['public_key'], S.MAX_PUBLIC, tick); public_key(key, p['trust'])
    receipts = {}; N = module(HERE / 'native.py')
    for row in p['packages']:
        package = Path(source_root) / 'build-dependencies' / row['filename']
        need(pin(D.read(package, row['archive']['bytes'], tick)) == row['archive'], 'exact native project package operand')
        signature = D.read(package.with_name(package.name + '.sig'), row['signature']['bytes'], tick)
        need(pin(signature) == row['signature'] and len(S.packets(signature)) == 1 and S.packets(signature)[0][0] == 2,
             'actual detached project signature operand required')
        receipts[row['name']] = dict(source=audit_source(source_root, row, tick), native=N.validate(Path(source_root), row, tick))
    return dict(policy=p, policy_pin=pin(policy_raw), Root_decision=decision, Root_decision_pin=pin(decision_raw),
                source_root=Path(source_root), expected_inventory=expected, receipts=receipts,
                signature_mathematics_verified=False, status='ROOT_SELECTED_PROJECT_TEST_INPUT_DATA_ONLY',
                Root_acceptance=None, native_acceptance=False, release_acceptance=False)


def signature_status(raw, p, now):
    need(type(raw) is bytes and len(raw) <= 65536, 'bounded project signature status')
    text = raw.decode(); rows = [line.split() for line in text.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    bad = ('BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED', 'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'ERROR', 'NODATA')
    need(len(rows) == 1 and len(rows[0]) == 12 and not any(token in text for token in bad), 'one valid unexpired nonrevoked TEST signature')
    r = rows[0]
    need(r[2] == p['trust']['signing_fingerprint'] and r[-1] == p['trust']['primary_fingerprint']
         and r[4].isdigit() and r[5].isdigit() and int(r[4]) <= now
         and (int(r[5]) == 0 or now < int(r[5])) and r[9] in ('8', '9', '10', '11'), 'exact Root-selected TEST signer and signature lifetime/hash')


def prepare_context(state, context, output, call, *, now=None, tick=lambda: None):
    """Use caller-owned supervised public gpgv; no default subprocess/installation."""
    p, root = state['policy'], state['source_root']; validate_policy(p)
    need(state['policy_pin'] == pin(encode(p)) and state['Root_decision_pin'], 'explicit admitted immutable selection state')
    now = int(time.time()) if now is None else now
    root_decision(encode(state['Root_decision']), state['Root_decision_pin']['sha256'], p, state['policy_pin'], now)
    need(state['expected_inventory'] == D.expected_inventory(root, p), 'same complete baseline plus project additions inventory')
    context, output = Path(context), Path(output)
    for directory in (context, output):
        need(directory == directory.resolve() and directory.is_dir() and not directory.is_relative_to(root)
             and directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700,
             'separate existing private caller-owned DATA output')
    target = context / 'project-test-dependencies'; home = output / 'project-test-verification'
    need(not target.exists() and not home.exists(), 'fresh dedicated TEST context; no existing keyhome adopted')
    target.mkdir(mode=0o700); home.mkdir(mode=0o700)
    key = read_ref(root, p['trust']['public_key'], S.MAX_PUBLIC, tick); public_key(key, p['trust'])
    keyring = target / 'public-test.gpg'; keyring.write_bytes(key); keyring.chmod(0o444)
    A = module(HERE / 'archive.py'); audits, signatures = {}, {}
    for row in p['packages']:
        audit_source(root, row, tick)
        package = root / 'build-dependencies' / row['filename']; signature = package.with_name(package.name + '.sig')
        need(pin(D.read(package, row['archive']['bytes'], tick)) == row['archive']
             and pin(D.read(signature, row['signature']['bytes'], tick)) == row['signature'], 'stable exact package and detached signature before verification')
        result = call(['/usr/bin/gpgv', '--homedir', str(home), '--keyring', str(keyring), '--status-fd', '1', str(signature), str(package)], timeout=30)
        need(type(result.returncode) is int and result.returncode == 0, 'successful supervised public TEST gpgv required')
        signature_status(result.stdout, p, now)
        audits[row['name']] = A.audit(package, row, D, tick)
        signatures[row['name']] = dict(archive=row['archive'], signature=row['signature'],
            public_key={k: p['trust']['public_key'][k] for k in ('bytes', 'sha256')},
            primary_fingerprint=p['trust']['primary_fingerprint'], signing_fingerprint=p['trust']['signing_fingerprint'],
            gpgv_status=pin(result.stdout))
        for path, wanted in ((package, row['archive']), (signature, row['signature'])):
            raw = D.read(path, wanted['bytes'], tick); need(pin(raw) == wanted, 'stable verified context input')
            destination = target / path.name
            with destination.open('xb') as stream: stream.write(raw)
            destination.chmod(0o444)
    need(not any(home.iterdir()), 'public gpgv leaves no agent/keyhome state')
    (target / 'expected-qualified.lock').write_bytes(state['expected_inventory']); (target / 'expected-qualified.lock').chmod(0o444)
    return dict(schema=1, kind='VERIFIED_PROJECT_TEST_PROVIDER_CONTEXT_DATA_V1', trust_scope='PROJECT_TEST_ONLY',
                ALARM_authentication=False, policy=state['policy_pin'], Root_decision=state['Root_decision_pin'],
                packages=audits, verified_signatures=signatures, inventory=pin(state['expected_inventory']), network=False,
                native_acceptance=False, Root_acceptance=None, release_acceptance=False)


def image_dockerfile(state, original, verified_context, *, now=None):
    """Produce DATA text only after the same fresh external Root selection."""
    p = validate_policy(state['policy'])
    root_decision(encode(state['Root_decision']), state['Root_decision_pin']['sha256'],
                  p, pin(encode(p)), int(time.time()) if now is None else now)
    v = verified_context
    need(v.get('kind') == 'VERIFIED_PROJECT_TEST_PROVIDER_CONTEXT_DATA_V1'
         and v.get('trust_scope') == 'PROJECT_TEST_ONLY' and v.get('ALARM_authentication') is False
         and v.get('policy') == state['policy_pin'] and v.get('Root_decision') == state['Root_decision_pin']
         and v.get('inventory') == pin(state['expected_inventory']) and v.get('native_acceptance') is False
         and v.get('Root_acceptance') is None and v.get('release_acceptance') is False,
         'verified complete TEST context required before image text')
    need(set(v.get('packages', {})) == set(SPECS) and set(v.get('verified_signatures', {})) == set(SPECS),
         'both fully audited and verified TEST providers required')
    for row in p['packages']:
        result = v['packages'][row['name']]; signature = v['verified_signatures'][row['name']]
        need(result.get('complete_provider_inventory') is True and result.get('providers') == row['providers']
             and all(signature.get(k) == row[k] for k in ('archive', 'signature'))
             and signature.get('public_key') == {k: p['trust']['public_key'][k] for k in ('bytes', 'sha256')}
             and all(signature.get(k) == p['trust'][k] for k in ('primary_fingerprint', 'signing_fingerprint')),
             'same complete package bytes and separate TEST signer')
    return module(HERE / 'image.py').extend_dockerfile(original, p, D)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    for name in ('policy', 'decision'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    state = admit(args.source_root, D.read(args.policy, D.MIB), args.policy_sha256,
                  D.read(args.decision, D.MIB), args.decision_sha256)
    print(encode({k: state[k] for k in ('status', 'policy_pin', 'Root_decision_pin', 'signature_mathematics_verified',
                                       'Root_acceptance', 'native_acceptance', 'release_acceptance')}).decode(), end='')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('HOLD_PROJECT_TEST_PROVIDER: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(2)
