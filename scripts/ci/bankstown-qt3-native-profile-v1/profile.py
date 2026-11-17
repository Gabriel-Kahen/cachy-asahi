#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Passive image-to-profile seam for the frozen Bankstown Qt3 consumer."""
import importlib.util
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('bankstown_profile_v1_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P, I, R = load('passive'), load('inventory'), load('receipt')
PROTECTED = HERE / 'expected349.lock'
FINAL = dict(Root_final_acceptance=None, independent_component_acceptance=False,
             hardware_acceptance=False, release_acceptance=False, legal='HELD', key_freshness='HELD')


def live_executor(executor, image):
    P.need(callable(getattr(executor, 'live', None)), 'SAME_LIVE_OWNED_EXECUTOR_REQUIRED')
    executor.live()
    facts, expected = executor.facts, image['executor']
    P.need(type(facts) is dict and facts.get('api') == 'CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'
           and all(facts.get(k) == expected[k] for k in ('code_pin', 'engine_id', 'docker_endpoint'))
           and facts.get('binding') == image['binding'] and facts.get('nonce') == image['nonce']
           and facts.get('stage') == 'qt3'
           and facts.get('owner_domain', {}).get('pid') == expected['owner_pid']
           and facts.get('daemon_domain', {}).get('pid') == expected['daemon_pid']
           and getattr(executor, 'deadline', None) == image['lifetime']['work_deadline_monotonic']
           and all(facts.get(k) is True for k in ('daemon_pidfd_held', 'whole_owner_deadline_enforced',
                                                 'daemon_deadline_enforced', 'exclusive_daemon')),
           'ACTUAL_SAME_EXECUTOR_LIFETIME_JOIN')


def prepare(*, image_receipt_path, image_receipt_sha256, admission_path,
            admission_sha256, catalog_path, source_root, executor):
    """All selector SHA256 values must arrive through external trusted custody."""
    raw = P.read(image_receipt_path)
    P.need(P.pin(raw)['sha256'] == P.sha(image_receipt_sha256), 'EXTERNAL_IMAGE_RECEIPT_PIN_DIFFERS')
    image = R.validate(P.decoded(raw), P, now=time.monotonic())
    live_executor(executor, image)
    source_root = P.ordinary(source_root)
    P.need(source_root == Path(image['source']['root']), 'RECEIPT_SOURCE_ROOT_DIFFERS')
    consumer = P.consumers(source_root)
    admission = P.read(admission_path)
    trial = consumer.A.validate_trial(admission, admission_sha256, now=time.time())
    pin = lambda row: {k: row[k] for k in ('bytes', 'sha256')}
    P.need(trial['source'] == {k: image['source'][k] for k in ('commit', 'ref')}
           and trial['image'] == {'id': image['image']['id'], 'inventory': pin(image['image']['inventory'])}
           and trial['catalog'] == pin(image['catalog'])
           and trial['owned_executor'] == {k: image['executor'][k] for k in ('code_pin', 'docker_endpoint', 'engine_id')},
           'IMAGE_TRIAL_SOURCE_CATALOG_EXECUTOR_JOIN')
    P.need(Path(catalog_path) == Path(image['catalog']['path']), 'EXTERNAL_CATALOG_PATH_DIFFERS')
    catalog = P.read_ref(image['catalog'], 64 * 1024**2)
    inventory = P.read_ref(image['image']['inventory'])
    protected = P.read(PROTECTED)
    joins = I.check(inventory, protected, catalog)
    P.need(image['image']['protected349'] == P.pin(protected), 'RECEIPT_PROTECTED349_DIFFERS')
    # The consumer itself reads these through its uniquely admitted source map.
    for expected, body in ((trial['catalog'], catalog), (trial['image']['inventory'], inventory)):
        paths = [path for path, row in trial['materials'].items() if row == expected]
        P.need(len(paths) == 1 and P.read(source_root / paths[0], cap=64 * 1024**2) == body,
               'EXACT_ADMITTED_SOURCE_MATERIAL_REQUIRED')
    root = P.ordinary(image['filesystem']['root'])
    P.need(root.is_dir() and root != Path('/'), 'EXPLICIT_PASSIVE_MATERIALIZED_ROOT_REQUIRED')
    deadline = min(image['lifetime']['work_deadline_monotonic'], time.monotonic() + 300,
                   time.monotonic() + trial['expires_at'] - time.time())
    P.need(deadline > time.monotonic(), 'EXPIRED_PASSIVE_SELECTION')
    archive_identity = P.verify_blob(image['filesystem']['archive'], deadline=deadline)
    return dict(image=image, image_raw=raw, admission=admission, trial=trial, consumer=consumer,
                catalog_path=Path(catalog_path), root=root, joins=joins,
                deadline=deadline, archive_identity=archive_identity, executor=executor)


def finish(state, profile_path, expected_profile_raw):
    image = state['image']
    live_executor(state['executor'], image)
    P.need(time.monotonic() < state['deadline'], 'PASSIVE_EXPORT_DEADLINE')
    R.validate(image, P, now=time.monotonic())
    P.need(P.identity(P.ordinary(image['filesystem']['archive']['path']).lstat()) == state['archive_identity'],
           'IMAGE_EXPORT_ARCHIVE_CHANGED')
    profile_pin = P.pin(expected_profile_raw)
    P.need(P.read(profile_path, expected=profile_pin) == expected_profile_raw, 'PROFILE_OUTPUT_CHANGED')
    return dict(schema=1, kind='BANKSTOWN_QT3_PROFILE_DATA_V1', status='PASS_PASSIVE_PROFILE_DATA_ONLY',
                image_receipt=P.pin(state['image_raw']), admission=P.pin(state['admission']),
                source=image['source'], binding=image['binding'], nonce=image['nonce'],
                delegation_pin=image['delegation_pin'], image=image['image'],
                catalog=image['catalog'], filesystem=image['filesystem'], executor=image['executor'],
                lifetime=image['lifetime'], inventory_joins=state['joins'],
                frozen_consumers={path: {'bytes': size, 'sha256': digest} for path, (size, digest) in P.PINS.items()},
                profile=dict(path=str(P.ordinary(profile_path)), **profile_pin), **FINAL)


def export(*, profile_path, output_receipt_path, **inputs):
    P.need(Path(profile_path) != Path(output_receipt_path), 'DISTINCT_FRESH_OUTPUTS_REQUIRED')
    P.need(not P.ordinary(profile_path).exists() and not P.ordinary(output_receipt_path).exists(),
           'FRESH_PROFILE_AND_RECEIPT_REQUIRED')
    state = prepare(**inputs)
    projected = state['consumer'].export_profile(admission_raw=state['admission'], admission_sha256=inputs['admission_sha256'],
        catalog_path=state['catalog_path'], root=state['root'], output=Path(profile_path))
    result = finish(state, profile_path, state['consumer'].A.encoded(projected))
    P.write(output_receipt_path, P.encoded(result))
    return result


def verify(*, profile_path, profile_sha256, output_receipt_path, output_receipt_sha256, **inputs):
    """Rederive a passive projection. Runtime consumer verification still requires /."""
    state = prepare(**inputs)
    raw = P.read(profile_path)
    P.need(P.pin(raw)['sha256'] == P.sha(profile_sha256), 'EXTERNAL_PROFILE_PIN_DIFFERS')
    expected = state['consumer']._prepare(state['admission'], inputs['admission_sha256'],
                                          state['catalog_path'], state['root'])
    P.need(raw == state['consumer'].A.encoded(expected), 'RELOCATED_CONSUMER_PROJECTION_DIFFERS')
    result = finish(state, profile_path, raw)
    actual = P.read(output_receipt_path)
    P.need(P.pin(actual)['sha256'] == P.sha(output_receipt_sha256)
           and actual == P.encoded(result), 'EXTERNAL_PROFILE_RECEIPT_DIFFERS')
    return result


if __name__ == '__main__':
    print('Import the passive API with the same externally owned live executor', file=sys.stderr)
    sys.exit(2)
