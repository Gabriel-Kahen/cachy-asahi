# SPDX-License-Identifier: MIT
"""Finite bootstrap fetch dispatch; binding performs no reads, actors or fetches."""
import hashlib
import json
import os
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


def bind_fetch(original_inputs, extras, cache, package_fetch, parent_fetch):
    """Use the saved original fetch for base5; cache-only for package/signature512.

    Both callbacks accept (row, selected_cache), matching native.fetch. The owner
    authenticates the module via closed source proof and saves its original fetch
    before assignment. Callback results/errors propagate unchanged, without retry.
    """
    original_raw, extras_raw = _canonical(original_inputs), _canonical(extras)
    _need(hashlib.sha256(original_raw).hexdigest() == ORIGINAL and
          hashlib.sha256(extras_raw).hexdigest() == EXTRAS, 'BOOTSTRAP_INPUT_PINS_REFUSED')
    _need(callable(package_fetch) and callable(parent_fetch) and package_fetch is not parent_fetch,
          'BOOTSTRAP_CALLBACK_REFUSED')
    bound_cache = _cache_path(cache)
    original, additions = json.loads(original_raw), json.loads(extras_raw)
    base_rows = original['keyring_files'] + [original['rootfs'], _signature(original['rootfs'])]
    package_rows = []
    for row in original['packages'] + additions:
        package_rows.extend((row, _signature(row)))
    _need(len(base_rows) == 5 and len(package_rows) == 512, 'BOOTSTRAP_INPUT_SET_REFUSED')
    base = {row['filename']: _canonical(row) for row in base_rows}
    packages = {row['filename']: _canonical(row) for row in package_rows}
    _need(len(base) == 5 and len(packages) == 512 and not set(base) & set(packages), 'BOOTSTRAP_INPUT_SET_REFUSED')

    def fetch(row, selected_cache):
        _need(_cache_path(selected_cache) == bound_cache, 'BOOTSTRAP_CACHE_REFUSED')
        _need(type(row) is dict and type(row.get('filename')) is str, 'BOOTSTRAP_INPUT_ROW_REFUSED')
        name = row['filename']; raw = _canonical(row)
        if name in base:
            _need(raw == base[name], 'BOOTSTRAP_INPUT_ROW_REFUSED')
            return parent_fetch(json.loads(base[name]), Path(bound_cache))
        _need(name in packages and raw == packages[name], 'BOOTSTRAP_INPUT_ROW_REFUSED')
        return package_fetch(json.loads(packages[name]), Path(bound_cache))

    return fetch
