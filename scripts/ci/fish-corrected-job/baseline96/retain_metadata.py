#!/usr/bin/env python3
"""Retain bounded JSON build evidence in logs; exclude payloads and key homes."""
import argparse
import base64
import gzip
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import stat
import ast

BASE = Path(__file__).resolve().parent
# Bind the bootstrap contract from source bytes before any project import.
import types
_contract_path = BASE / 'contract.py'
_contract_info = _contract_path.lstat()
if not stat.S_ISREG(_contract_info.st_mode) or _contract_info.st_nlink != 1 or _contract_info.st_size > 65536:
    raise ValueError('successor-bootstrap-contract-type')
_contract_fd = os.open(_contract_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    _contract_raw = os.read(_contract_fd, 65537)
finally:
    os.close(_contract_fd)
if hashlib.sha256(_contract_raw).hexdigest() != 'c84168539130394f9fe51bf440d036f44813ff2b923c1e9d77748f97f755c922':
    raise ValueError('successor-bootstrap-contract-pin')
c = types.ModuleType('contract')
c.__file__ = str(_contract_path)
exec(compile(_contract_raw, str(_contract_path), 'exec'), c.__dict__)


PHASES = {'preflight', 'base-probe', 'host-probe', 'acquisition', 'gpg-import', 'gpg-verify',
          'bootstrap', 'original-build', 'original-compare', 'complete'}
OUTCOMES = {'not-run', 'started', 'pass', 'command-failed', 'delegate-refused', 'runner-failed', 'cancelled'}
OUTPUT_REFUSALS = {'successor-bootstrap-binding', 'successor-build-artifact-record', 'successor-build-inventory',
    'successor-build-provenance', 'successor-build-validation', 'successor-builder-inventory',
    'successor-container-independence', 'successor-container-journal', 'successor-container-journal-binding',
    'successor-distinct-environments', 'successor-native-result', 'successor-native-result-binding',
    'successor-pair-comparison', 'successor-pair-equality', 'successor-pair-inputs', 'successor-signature-result',
    'successor-signature-set', 'successor-worker-count', 'successor-worker-daemon', 'successor-worker-receipt'}
GENERIC_REFUSALS = {'os-error', 'unicode-error', 'key-error', 'type-error', 'value-error',
                    'subprocess-error', 'unknown-error', 'cancelled'}


def projection_context(reviews, inputs):
    """Only captured reviewed metadata supplies emitted package basenames."""
    artifact_names, hashes = {}, {}
    for path, pins in reviews.items():
        text = c.pinned(BASE / 'native' / path / '.SRCINFO', pins['.SRCINFO']).decode('utf-8')
        fields = {}
        for line in text.splitlines():
            parts = line.strip().split(' = ', 1)
            if len(parts) == 2: fields.setdefault(parts[0], []).append(parts[1])
        name = Path(path).name
        c.need(fields.get('pkgname') == [name] and len(fields.get('pkgver', [])) == 1
            and len(fields.get('pkgrel', [])) == 1 and fields.get('arch') == ['any']
            and fields.get('epoch', ['0']) == ['0'], 'successor-projection-reviewed-metadata')
        version, release = fields['pkgver'][0], fields['pkgrel'][0]
        c.need(all(re.fullmatch('[A-Za-z0-9._+-]{1,64}', v) for v in (name, version, release)),
               'successor-projection-reviewed-token')
        artifact_names[name] = {f'{name}-{version}-{release}-any.pkg.tar.{extension}'
                                for extension in ('zst', 'xz', 'gz', 'bz2')}
        hashes[name] = pins
    raw = c.pinned(BASE / 'providers/evidence.py', '26f272f1199232429d50cb916faa3a08110818d13f28aa9d9d7ff6a2d7858cf9')
    declarations = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == 'BASE_PROBE_POLICY_CODES' for t in node.targets)]
    c.need(len(declarations) == 1, 'successor-projection-source-enum')
    reasons = ast.literal_eval(declarations[0].value)
    c.need(type(reasons) is set and all(type(v) is str for v in reasons), 'successor-projection-source-enum')
    return {'artifacts': artifact_names, 'recipes': hashes, 'epoch': inputs['source_date_epoch'],
        'entry_sha256': hashlib.sha256(c.read(BASE / 'native/scripts/build/container-entry.sh')).hexdigest(),
        'reasons': reasons | OUTPUT_REFUSALS | GENERIC_REFUSALS}


def finite(value, choices):
    c.need(type(value) is str and value in choices, 'projection-fields')
    return value


def number(value, minimum, maximum, nullable=False):
    if value is None and nullable: return None
    c.need(type(value) is int and minimum <= value <= maximum, 'projection-fields')
    return value


def pin(value, image=False):
    if value is None: return None
    c.need(type(value) is str and re.fullmatch(('sha256:' if image else '')+'[0-9a-f]{64}', value), 'projection-fields')
    return value


def artifacts(value, allowed):
    if value is None: return None
    c.need(type(value) is dict and len(value) <= 1 and set(value) <= allowed, 'projection-fields')
    c.need(all(type(digest) is str for digest in value.values()), 'projection-fields')
    return {name: pin(digest) for name, digest in value.items()}


def project(kind, value, context, recipe=None):
    c.need(type(value) is dict, 'projection-fields')
    if 'schema_version' in value:
        c.need(type(value['schema_version']) is int and value['schema_version'] == 1, 'projection-fields')
    if kind == 'worker':
        status = finite(value.get('status'), {'PASS', 'FAIL'})
        diagnostic = value.get('diagnostic')
        c.need(type(diagnostic) is dict and set(diagnostic) in (
            {'phase','outcome'}, {'phase','outcome','call','refusal_code'}), 'projection-fields')
        phase, outcome = finite(diagnostic['phase'], PHASES), finite(diagnostic['outcome'], OUTCOMES)
        safe_diagnostic = {'phase': phase, 'outcome': outcome}
        if 'call' in diagnostic:
            safe_diagnostic.update(call=finite(diagnostic['call'], {'docker-info','docker-version','docker-context',
                'image-inspect','inventory-probe','unclassified'}), refusal_code=finite(diagnostic['refusal_code'], context['reasons']|{'none'}))
        first = value.get('first_failure')
        if first is not None: first = finite(first, context['reasons'])
        c.need(type(value.get('cancelled')) is bool, 'projection-fields')
        counts = {key:number(value.get(key),0,maximum) for key,maximum in
            (('build_invocations',8),('builds_completed',8),('comparisons_completed',4),('signatures_verified',249))}
        c.need(counts['builds_completed'] <= counts['build_invocations'], 'projection-fields')
        code = number(value.get('native_code'),-128,255,nullable=True)
        if status == 'PASS':
            c.need(code == 0 and counts == {'build_invocations':8,'builds_completed':8,
                'comparisons_completed':4,'signatures_verified':249} and not value['cancelled']
                and first is None and phase == 'complete' and outcome == 'pass', 'projection-fields')
        return {'declared_status':status,'cancelled':value['cancelled'],'first_failure':first,
                'native_code':code,'counts':counts,'diagnostic':safe_diagnostic}
    if kind == 'result':
        finite(value.get('mode'), {'build'})
        status = finite(value.get('status'), {'failed','signed-input-audit-pass','building','native-builds-and-byte-comparison-pass'})
        native = finite(value.get('native_build'), {'NOT RUN','PASS'})
        finite(value.get('hardware_validation'), {'NOT RUN'})
        pins = {}
        for key, expected in (('reviewed_inputs_sha256',c.INPUTS),('reviewed_recipes_sha256',c.RECIPES),('bootstrap_script_sha256',c.NATIVE)):
            pins[key] = pin(value.get(key))
            c.need(pins[key] == expected, 'projection-binding')
        signed = number(value.get('verified_signed_packages'),0,248,nullable=True)
        if status == 'native-builds-and-byte-comparison-pass':
            c.need(native == 'PASS' and signed == 248, 'projection-fields')
        return {'declared_status':status,'native_build':native,'hardware_validation':'NOT RUN',
                'verified_signed_packages':signed,'pins':pins}
    if kind == 'provenance':
        status = finite(value.get('status'), {'preflight-failed','building','built-package-static-pass','failed'})
        mode = finite(value.get('mode'), {'native'})
        image, image_id = pin(value.get('image'),image=True), pin(value.get('image_id'),image=True)
        code = number(value.get('exit_code'),-128,255,nullable=True)
        guards = {}
        for key, expected in (('expected_packages_sha256',c.INVENTORY),('entry_script_sha256',context['entry_sha256'])):
            actual = pin(value.get(key)); guards[key+'_matches'] = None if actual is None else actual == expected
        recipe_inputs = value.get('recipe_inputs')
        c.need(recipe_inputs is None or (type(recipe_inputs) is dict and set(recipe_inputs) <= set(context['recipes'][recipe])
            and all(type(v) is str and pin(v) is not None for v in recipe_inputs.values())), 'projection-fields')
        guards['recipe_inputs_match'] = None if recipe_inputs is None else recipe_inputs == context['recipes'][recipe]
        epoch = number(value.get('source_date_epoch'),0,2**63-1,nullable=True)
        guards['source_date_epoch_matches'] = None if epoch is None else epoch == context['epoch']
        environment = value.get('clean_environment_id')
        c.need(environment is None or (type(environment) is str and re.fullmatch('cachy-asahi-[0-9a-f]{16}',environment)), 'projection-fields')
        artifact_map = artifacts(value.get('artifacts'),context['artifacts'][recipe])
        if status == 'built-package-static-pass':
            c.need(code == 0 and image is not None and image_id == image and artifact_map
                and environment is not None and all(v is True for v in guards.values()), 'projection-fields')
        return {'declared_status':status,'mode':mode,'image':image,'image_id':image_id,'exit_code':code,
            'artifacts':artifact_map,'guards':guards,
            'environment_sha256':None if environment is None else hashlib.sha256(environment.encode()).hexdigest()}
    c.need(kind == 'compare', 'projection-fields')
    status = finite(value.get('status'), {'fail','contents-reproduced'})
    errors = value.get('errors')
    c.need(type(errors) is list and len(errors) <= 64 and all(type(v) is str for v in errors), 'projection-fields')
    packages = value.get('packages'); safe = None
    if packages is not None:
        c.need(type(packages) is dict and len(packages) <= 1 and set(packages) <= context['artifacts'][recipe], 'projection-fields')
        safe = {}
        for name, row in packages.items():
            keys = {'installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'}
            c.need(type(row) is dict and set(row) == keys and all(type(v) is bool for v in row.values()), 'projection-fields')
            safe[name] = dict(row)
    if status == 'contents-reproduced':
        c.need(not errors and safe and all(row['installed_contents_equal'] and row['pkginfo_equal']
            and row['bytes_equal'] for row in safe.values()), 'projection-fields')
    return {'declared_status':status,'error_count':len(errors),'packages':safe}


def observation(raw, kind, context, recipe=None):
    try: value = c.decode(raw)
    except (ValueError, UnicodeError):
        return {'availability':'REFUSED','reason':'invalid-json','value':None}
    try: value = project(kind, value, context, recipe)
    except (ValueError, KeyError, TypeError):
        return {'availability':'REFUSED','reason':'invalid-fields','value':None}
    return {'availability':'OBSERVED','reason':'none','value':value}


def collect(job, inputs):
    native = job / 'private/producer'
    paths = ['public/status.json', 'private/result.json', 'private/native-worker.json']
    paths += ['private/producer/' + n for n in ('result.json', 'acquisition.json', 'cache-checksums.json', 'bootstrap.json')]
    recipes = c.decode(c.pinned(BASE / 'native/scripts/ci/recipes.lock.json', c.RECIPES))
    context = projection_context(recipes, inputs)
    projections = {'private/native-worker.json':('worker',None),'private/producer/result.json':('result',None)}
    for path in recipes:
        name = Path(path).name
        paths += [f'private/producer/{name}-{n}/provenance.json' for n in (1, 2)]
        paths += [f'private/producer/{name}-compare.json']
        projections.update({f'private/producer/{name}-{n}/provenance.json':('provenance',name) for n in (1,2)})
        projections[f'private/producer/{name}-compare.json'] = ('compare',name)
    records, size = {}, 0
    for name in paths:
        path = job / name
        if not path.exists() and not path.is_symlink():
            if name in projections: records[name] = {'observation':{'availability':'UNAVAILABLE','reason':'missing','value':None}}
            continue
        try: raw = c.read(path, 4 * 1024**2)
        except (OSError, ValueError):
            if name not in projections: raise
            records[name] = {'observation':{'availability':'UNAVAILABLE','reason':'unreadable','value':None}}
            continue
        if name not in projections: c.decode(raw)
        size += len(raw)
        c.need(size <= 8 * 1024**2, 'successor-metadata-size')
        # Preserve raw-file identity, not arbitrary private fields or error text.
        records[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        if name in projections:
            kind, recipe = projections[name]
            records[name]['observation'] = observation(raw,kind,context,recipe)
    public = job / 'public/status.json'
    if public.exists():
        value = c.decode(c.read(public, 65536))
        keys = {'schema_version', 'baseline_id', 'lineage', 'packet_sha256', 'source_commit', 'inputs_sha256',
                'inventory_sha256', 'native_sha256', 'recipes_sha256', 'status', 'native_build', 'phase',
                'first_cause', 'cancelled', 'hardware', 'installation', 'public_admission',
                'source_redistribution', 'legacy_docker_cache_absence', 'owned_image_absence'}
        c.need(set(value) == keys and type(value['schema_version']) is int and value['schema_version'] == 1
               and value['baseline_id'] == c.ID and value['lineage'] == 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL'
               and value['inputs_sha256'] == c.INPUTS and value['inventory_sha256'] == c.INVENTORY
               and value['native_sha256'] == c.NATIVE and value['recipes_sha256'] == c.RECIPES
               and value['hardware'] == value['installation'] == 'NOT RUN' and value['public_admission'] is False
               and value['source_redistribution'] == 'UNRESOLVED' and value['legacy_docker_cache_absence'] == 'NOT CLAIMED', 'successor-metadata-status-binding')
        c.need(value['status'] in ('PASS', 'FAIL') and value['native_build'] == ('PASS' if value['status'] == 'PASS' else 'NOT ACCEPTED')
               and value['phase'] in ('preflight', 'cache', 'native', 'cleanup', 'complete')
               and all(type(value[k]) is bool for k in ('cancelled', 'owned_image_absence'))
               and type(value['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', value['source_commit'])
               and type(value['packet_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['packet_sha256']), 'successor-metadata-status-type')
        failures = {'successor-preflight-failed', 'successor-cache-failed', 'successor-native-failed', 'successor-cleanup-failed',
                    'successor-cancelled', 'successor-runner-close-failed', 'successor-finalization-failed', 'successor-publication-failed'}
        c.need((value['status'] == 'PASS' and value['first_cause'] is None and not value['cancelled']
                and value['owned_image_absence'] and value['phase'] == 'complete')
               or (value['status'] == 'FAIL' and type(value['first_cause']) is str and value['first_cause'] in failures), 'successor-metadata-admission')
        records['public/status.json']['json'] = value
    signature_path = native / 'signatures.json'
    if signature_path.exists():
        raw = c.read(signature_path, 4 * 1024**2); signatures = c.decode(raw)
        allowed = {p['filename'] for p in [inputs['rootfs'], *inputs['packages']]}
        c.need(set(signatures) <= allowed, 'successor-metadata-signatures')
        safe = {}
        for name, row in signatures.items():
            c.need(type(row) is dict and type(row.get('exit_code')) is int and -128 <= row['exit_code'] <= 255
                   and type(row.get('status')) is str and len(row['status']) <= 65536, 'successor-metadata-signature-type')
            valid = [line.split() for line in row['status'].splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            for words in valid:
                c.need(len(words) == 12 and words[2] == words[-1] == inputs['signer_fingerprint']
                       and all(re.fullmatch('[A-Za-z0-9:._-]{1,128}', word) for word in words[2:]), 'successor-metadata-signature-status')
            c.need(len(valid) <= 1, 'successor-metadata-signature-count')
            safe[name] = {'exit_code': row['exit_code'], 'validsig': [' '.join(words) for words in valid]}
        records['private/producer/signatures-sanitized.json'] = {'raw_sha256': hashlib.sha256(raw).hexdigest(), 'json': safe}
    raw = json.dumps({'schema_version': 1, 'baseline_id': c.ID,
                      'payloads_and_key_homes': 'EXCLUDED', 'records': records}, sort_keys=True, allow_nan=False).encode()
    c.need(len(raw) <= 8 * 1024**2, 'successor-metadata-size')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs, _ = c.verify(BASE, args.packet_sha256)
    raw = collect(args.output.absolute(), inputs)
    encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    print('MAINTAINED_NATIVE_METADATA_GZIP_BASE64_SHA256=' + hashlib.sha256(raw).hexdigest())
    for offset in range(0, len(encoded), 4096): print('MAINTAINED_NATIVE_METADATA=' + encoded[offset:offset+4096])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
