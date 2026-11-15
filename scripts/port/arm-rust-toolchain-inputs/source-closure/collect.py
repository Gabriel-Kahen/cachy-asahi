#!/usr/bin/env python3
"""Bounded opaque source retention: no archive opening, recipe evaluation or build."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent


def require(ok, message):
    if not ok:
        raise ValueError(message)


def tmp_path(path):
    result = path.resolve()
    require(Path('/tmp') in result.parents and not path.is_symlink(), 'cache/output must be below /tmp')
    return result


def checksums(path):
    digests = {'sha256': hashlib.sha256(), 'blake2b': hashlib.blake2b()}
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def verify_file(path, record):
    require(path.is_file() and not path.is_symlink(), f'nonregular source input: {path.name}')
    actual = checksums(path)
    require(all(actual[k] == v for k, v in record['checksums'].items()), f'checksum mismatch: {path.name}')
    if 'bytes' in record:
        require(path.stat().st_size == record['bytes'], f'size mismatch: {path.name}')
    return {'bytes': path.stat().st_size, 'checksums': actual}


def recipe_correspondence():
    data = json.loads((HERE / 'correspondence.json').read_text())
    rows = []
    for recipe in data['recipes']:
        actual = hashlib.sha256((HERE / recipe['retained_file']).read_bytes()).hexdigest()
        rows.append({'package': recipe['package'], 'actual_recipe_sha256': actual,
                     'BUILDINFO_recipe_sha256': recipe['retained_pkgbuild_sha256'],
                     'exact_byte_match': actual == recipe['retained_pkgbuild_sha256']})
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Budget:
    def __init__(self, cache, limits, archives):
        self.cache, self.limits, self.archives = cache, limits, archives
        self.journal = cache.parent / 'http-ledger.json'
        self.requests = json.loads(self.journal.read_text()) if self.journal.exists() else []
        require(len(self.requests) <= limits['total_HTTP_requests'], 'request budget already exceeded')
        self.opener = urllib.request.build_opener(NoRedirect)

    def free(self, amount=0):
        stat = os.statvfs('/tmp')
        require(stat.f_bavail * stat.f_frsize >= self.limits['min_tmp_free_bytes'] + amount + 8 * 1024**2,
                'refusing to reduce/tmp free space below3GiB')

    def archive_bytes(self):
        total = 0
        for path in self.cache.iterdir():
            require(path.is_file() and not path.is_symlink(), 'nonregular source-cache node')
            require(path.name in self.archives or path.name == 'rustc-1.99.0-src.tar.xz.asc',
                    'unreviewed file in dedicated source cache')
            if path.name in self.archives:
                total += path.stat().st_size
        return total

    def open(self, url, deadline):
        while True:
            require(len(self.requests) < self.limits['total_HTTP_requests'], 'four-request budget exhausted')
            require(time.monotonic() < deadline, 'transfer deadline exceeded')
            parts = urllib.parse.urlsplit(url)
            require(parts.scheme == 'https' and parts.username is None and parts.hostname in
                    {'static.rust-lang.org', 'github.com', 'release-assets.githubusercontent.com',
                     'objects.githubusercontent.com', 'releases.llvm.org'}, 'unreviewed source host/transport')
            self.requests.append({'ordinal': len(self.requests) + 1,
                                  'UTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                  'url': urllib.parse.urlunsplit(parts._replace(query='', fragment='')),
                                  'query_redacted': bool(parts.query), 'url_sha256': hashlib.sha256(url.encode()).hexdigest()})
            self.journal.write_text(json.dumps(self.requests, sort_keys=True, indent=2) + '\n')
            try:
                response = self.opener.open(url, timeout=self.limits['socket_timeout_seconds'])
                self.requests[-1]['HTTP'] = response.status
                self.journal.write_text(json.dumps(self.requests, sort_keys=True, indent=2) + '\n')
                return response
            except urllib.error.HTTPError as error:
                self.requests[-1]['HTTP'] = error.code
                self.journal.write_text(json.dumps(self.requests, sort_keys=True, indent=2) + '\n')
                location = error.headers.get('Location')
                error.close()
                if error.code not in (301, 302, 303, 307, 308):
                    raise
                require(location is not None, 'redirect missing location')
                url = urllib.parse.urljoin(url, location)

    def fetch(self, name, record, archive=True):
        target = self.cache / name
        if target.exists() or target.is_symlink():
            return verify_file(target, record)
        maximum = min(record['max_bytes'], self.limits['new_archive_bytes'] - self.archive_bytes()) if archive else record['max_bytes']
        require(maximum > 0, 'archive byte budget exhausted')
        self.free(maximum)
        deadline = time.monotonic() + self.limits['transfer_deadline_seconds']
        with self.open(record['url'], deadline) as response:
            if response.headers.get('Content-Length'):
                require(int(response.headers['Content-Length']) <= maximum, 'advertised source size exceeds budget')
            with tempfile.TemporaryDirectory(prefix='opaque-source-', dir=self.cache.parent) as temp:
                partial = Path(temp) / name
                count = 0
                with partial.open('xb') as out:
                    while chunk := response.read(min(1048576, maximum + 1 - count)):
                        require(time.monotonic() < deadline, 'source transfer deadline exceeded')
                        count += len(chunk)
                        require(count <= maximum, 'source byte bound exceeded')
                        self.free(len(chunk))
                        out.write(chunk)
                verified = verify_file(partial, record)
                partial.chmod(0o600)
                require(not target.exists(), 'source cache changed during acquisition')
                partial.rename(target)
        return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['collect', 'verify'])
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cache, output = tmp_path(args.cache), tmp_path(args.output)
    require(cache != output and cache not in output.parents and output not in cache.parents, 'cache/output overlap')
    require(not output.exists() and output.parent.is_dir(), 'output must be new with existing parent')
    data = (HERE / 'source-inputs.json').read_bytes()
    manifest = json.loads(data)
    for name, record in manifest['materials'].items():
        verify_file(HERE / name, {'bytes': record['bytes'], 'checksums': {'sha256': record['sha256']}})
    budget = Budget(cache, manifest['budgets'], manifest['archives'])
    budget.free()
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.chmod(0o700)
    require(budget.archive_bytes() <= manifest['budgets']['new_archive_bytes'], 'existing archive cache exceeds1GiB')
    output.mkdir(mode=0o700)
    results = {}
    for name, record in manifest['archives'].items():
        try:
            actual = budget.fetch(name, record) if args.operation == 'collect' else verify_file(cache / name, record)
            results[name] = dict(actual, status='EXACT_DECLARED_CHECKSUM_BYTES_RETAINED', archive_opening='NOT_RUN')
        except (OSError, ValueError) as error:
            results[name] = {'status': 'UNACQUIRED_OR_REFUSED', 'reason': str(error)}
        report = {'schema': 1, 'purpose': manifest['purpose'], 'manifest_sha256': hashlib.sha256(data).hexdigest(),
                  'inputs': results, 'HTTP_requests': budget.requests, 'archive_bytes': budget.archive_bytes(),
                  'materials': manifest['materials'], 'binary_source_correspondence': 'HELD_FOUR_RECIPE_HASH_MISMATCHES',
                  'recipe_comparisons': recipe_correspondence(),
                  'archive_opening_extraction_recipe_execution_build': 'NOT_RUN',
                  'submodule_crate_and_complete_source_closure': 'NOT_ESTABLISHED',
                  'source_signature_mathematics': 'NOT_PERFORMED_NO_RELEASE_KEY_BYTES', 'source_legal_acceptance': 'HELD'}
        (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        print(json.dumps({'input': name, **results[name]}, sort_keys=True), flush=True)
    # A detached signature is data, not authenticated authority. Retain it only
    # if the fixed budget permits; no keyserver or implicit verifier is invoked.
    signature = manifest.get('optional_signature')
    if signature:
        try:
            record = dict(signature, checksums=signature.get('checksums', {}))
            if args.operation == 'collect' and ((cache / signature['filename']).exists() or
                                                len(budget.requests) < manifest['budgets']['total_HTTP_requests']):
                report['detached_signature'] = budget.fetch(signature['filename'], record, archive=False)
            else:
                report['detached_signature'] = verify_file(cache / signature['filename'], record)
        except (OSError, ValueError) as error:
            report['detached_signature'] = {'status': 'NOT_RETAINED', 'reason': str(error)}
    report['HTTP_requests'] = budget.requests
    report['retained_source_bytes'] = sum(p.stat().st_size for p in cache.iterdir())
    report['archive_retention_complete'] = all(r['status'] == 'EXACT_DECLARED_CHECKSUM_BYTES_RETAINED' for r in results.values())
    (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return 0 if all(r['status'] == 'EXACT_DECLARED_CHECKSUM_BYTES_RETAINED' for r in results.values()) else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        raise SystemExit(f'REFUSED: {error}')
