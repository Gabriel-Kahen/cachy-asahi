# SPDX-License-Identifier: MIT
"""Finite bootstrap fetch dispatch; binding performs no reads, actors or fetches."""
import hashlib
import json
import math
import os
import time
from pathlib import Path

ORIGINAL = '00aab63e0b388efa1f9c7145ba49ffc8333987322de1482e9b6cc6d2676c9166'
EXTRAS = '3c43d8e9216cc26ea9734080ca4c1291c69bc51962ab2f7b004a54cfd9b1574d'


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError):
        raise ValueError('BOOTSTRAP_INPUT_SCHEMA_REFUSED') from None


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _signature(row):
    return dict(filename=row['filename'] + '.sig', url=row['url'] + '.sig',
                sha256=row['signature_sha256'], size=row['signature_size'])


def _cache_path(value):
    try:
        text = os.fspath(value); path = Path(text)
        _need(type(text) is str and path.is_absolute() and '..' not in path.parts and str(path) == text,
              'BOOTSTRAP_CACHE_REFUSED')
        return text
    except (TypeError, ValueError):
        raise ValueError('BOOTSTRAP_CACHE_REFUSED') from None


def bind_fetch(original_inputs, extras, cache, package_fetch, parent_fetch, acquisition_error, diagnostics, deadline):
    """Use original base5 fetch; retry only the exact rootfs transport failure once.

    Both callbacks accept (row, selected_cache), matching native.fetch. The owner
    authenticates the module via closed source proof and saves its original fetch
    before assignment. Only the trusted exact AcquisitionError transport category
    for the pinned rootfs gets a second original-fetch attempt. HTTP, pin, cache,
    package and signature failures propagate immediately. No URL/pin is changed.
    """
    original_raw, extras_raw = _canonical(original_inputs), _canonical(extras)
    _need(hashlib.sha256(original_raw).hexdigest() == ORIGINAL and
          hashlib.sha256(extras_raw).hexdigest() == EXTRAS, 'BOOTSTRAP_INPUT_PINS_REFUSED')
    _need(callable(package_fetch) and callable(parent_fetch) and package_fetch is not parent_fetch,
          'BOOTSTRAP_CALLBACK_REFUSED')
    _need(isinstance(acquisition_error, type) and issubclass(acquisition_error, ValueError),
          'BOOTSTRAP_ACQUISITION_ERROR_REFUSED')
    _need(type(deadline) in (int, float) and math.isfinite(deadline), 'BOOTSTRAP_DEADLINE_REFUSED')
    _need(type(diagnostics) is dict and not diagnostics, 'BOOTSTRAP_DIAGNOSTICS_REFUSED')
    bound_cache = _cache_path(cache)
    original, additions = json.loads(original_raw), json.loads(extras_raw)
    base_rows = original['keyring_files'] + [original['rootfs'], _signature(original['rootfs'])]
    rootfs_name = original['rootfs']['filename']
    package_rows = []
    for row in original['packages'] + additions:
        package_rows.extend((row, _signature(row)))
    _need(len(base_rows) == 5 and len(package_rows) == 512, 'BOOTSTRAP_INPUT_SET_REFUSED')
    base = {row['filename']: _canonical(row) for row in base_rows}
    packages = {row['filename']: _canonical(row) for row in package_rows}
    _need(len(base) == 5 and len(packages) == 512 and not set(base) & set(packages), 'BOOTSTRAP_INPUT_SET_REFUSED')

    diagnostics.update(schema=1, filename=rootfs_name, url=original['rootfs']['url'],
                       expected_bytes=original['rootfs']['size'], expected_sha256=original['rootfs']['sha256'],
                       original_cause='UNKNOWN_DNS_TLS_TIMEOUT_OR_OTHER_TRANSPORT',
                       received_bytes=None, received_bytes_proof='NOT_EXPOSED_BY_ORIGINAL_FETCH',
                       maximum_acquisition_attempts=2, attempts=[], cache_validations=[])
    rootfs_completed = False

    def rootfs_fetch():
        nonlocal rootfs_completed
        _need(time.monotonic() < deadline, 'BOOTSTRAP_DEADLINE_REFUSED')
        if rootfs_completed:
            _need(not diagnostics['cache_validations'], 'BOOTSTRAP_ROOTFS_CACHE_VALIDATION_CONSUMED')
            _need((Path(bound_cache) / rootfs_name).exists(), 'BOOTSTRAP_ROOTFS_CACHE_LOST_REFUSED')
            started = time.monotonic_ns()
            record = {'status': 'IN_PROGRESS'}
            diagnostics['cache_validations'].append(record)
            try:
                result = parent_fetch(json.loads(base[rootfs_name]), Path(bound_cache))
                record['status'] = 'PASS'
                return result
            except BaseException:
                record['status'] = 'FAIL'
                raise
            finally:
                record['elapsed_ns'] = max(0, time.monotonic_ns() - started)
        _need(not diagnostics['attempts'], 'BOOTSTRAP_ROOTFS_ATTEMPTS_CONSUMED')
        for index in range(2):
            _need(time.monotonic() < deadline, 'BOOTSTRAP_DEADLINE_REFUSED')
            started = time.monotonic_ns()
            record = dict(attempt=index + 1, status='IN_PROGRESS', error=None, http_status=None,
                          received_bytes=None, received_bytes_proof='NOT_EXPOSED_BY_ORIGINAL_FETCH')
            diagnostics['attempts'].append(record)
            try:
                result = parent_fetch(json.loads(base[rootfs_name]), Path(bound_cache))
                record['status'] = 'PASS'; rootfs_completed = True
                return result
            except BaseException as error:
                record['status'] = 'FAIL'
                exact = type(error) is acquisition_error and error.filename == rootfs_name
                record['error'] = error.category if exact and error.category in ('HTTPS transport failure', 'HTTP failure') else 'OTHER_FAILURE'
                record['http_status'] = error.http_status if exact and type(error.http_status) is int and 100 <= error.http_status <= 599 else None
                if not (index == 0 and exact and error.category == 'HTTPS transport failure' and error.http_status is None):
                    raise
            finally:
                record['elapsed_ns'] = max(0, time.monotonic_ns() - started)

    def fetch(row, selected_cache):
        _need(_cache_path(selected_cache) == bound_cache, 'BOOTSTRAP_CACHE_REFUSED')
        _need(type(row) is dict and type(row.get('filename')) is str, 'BOOTSTRAP_INPUT_ROW_REFUSED')
        name = row['filename']; raw = _canonical(row)
        if name in base:
            _need(raw == base[name], 'BOOTSTRAP_INPUT_ROW_REFUSED')
            if name == rootfs_name:
                return rootfs_fetch()
            return parent_fetch(json.loads(base[name]), Path(bound_cache))
        _need(name in packages and raw == packages[name], 'BOOTSTRAP_INPUT_ROW_REFUSED')
        return package_fetch(json.loads(packages[name]), Path(bound_cache))

    return fetch
