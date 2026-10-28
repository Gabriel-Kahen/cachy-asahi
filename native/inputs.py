# SPDX-License-Identifier: MIT
"""Original341 only: five exact base rows plus496 cache-only package/signatures."""
import hashlib
import json
from pathlib import Path

ORIGINAL = '00aab63e0b388efa1f9c7145ba49ffc8333987322de1482e9b6cc6d2676c9166'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def signature(row):
    return dict(filename=row['filename'] + '.sig', url=row['url'] + '.sig',
                sha256=row['signature_sha256'], size=row['signature_size'])


def bind_fetch(original, cache, package_fetch, parent_fetch):
    if hashlib.sha256(canonical(original)).hexdigest() != ORIGINAL:
        raise ValueError('exact original341 inputs required')
    if not callable(package_fetch) or not callable(parent_fetch) or package_fetch is parent_fetch:
        raise ValueError('distinct finite fetch callbacks required')
    cache = Path(cache)
    if not cache.is_absolute() or '..' in cache.parts:
        raise ValueError('absolute fixed cache required')
    base_rows = original['keyring_files'] + [original['rootfs'], signature(original['rootfs'])]
    package_rows = [item for row in original['packages'] for item in (row, signature(row))]
    base = {row['filename']: canonical(row) for row in base_rows}
    packages = {row['filename']: canonical(row) for row in package_rows}
    if len(base) != 5 or len(packages) != 496 or set(base) & set(packages):
        raise ValueError('finite original5+496 namespace required; no extras512')
    def fetch(row, selected_cache):
        if Path(selected_cache) != cache or type(row) is not dict or type(row.get('filename')) is not str:
            raise ValueError('cache or original input row refused')
        name, body = row['filename'], canonical(row)
        if name in base and body == base[name]:
            return parent_fetch(json.loads(base[name]), cache)
        if name in packages and body == packages[name]:
            return package_fetch(json.loads(packages[name]), cache)
        raise ValueError('unknown/changed original input refused')
    return fetch
