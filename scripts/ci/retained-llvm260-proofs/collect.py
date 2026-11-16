#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trusted-main LLVM260 public proof DATA collector; never executes Source code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time

MIB = 1024 ** 2
LEAF_LIMIT = 8 * MIB
ZIP_LIMIT = 32 * MIB
STATUS = 'PASS_INDEPENDENT_LLVM23_BUILDINFO_ARCHITECTURE_SUCCESSOR_DATA_ONLY'
SCOPE = 'LLVM260_RETAINED_PUBLIC_TEST_PROOFS_DATA_ONLY'
REPOSITORY = 'https://github.com/Gabriel-Kahen/cachy-asahi.git'
CASE = dict(source='031bf1634429446cd0068f4842d56af276cf40f4',
            ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r3',
            run='43760769287', job='132954847327', artifact='14186236728', attempt=1,
            map_sha256='75426d36fae416d1bc3606b8d1a7165408964996bb6467e3223842612221e187',
            package='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst',
            package_bytes=192385078,
            package_sha256='689621ffa5261bdc7d382448529f6fa5d6e30f473d7470101cd0ab7d94140042')
NAMES = dict(llvm_signature=CASE['package']+'.sig', public_test_key='llvm260-TEST-public.asc',
             verification_proof='llvm260-TEST-verification.json',
             reader_binding='llvm260-reader7-binding.json', reader_result='llvm260-reader7-result.json',
             source_audit='llvm260-source-audit.json', root_decision='llvm260-Root-decision.json')
END = None


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= LEAF_LIMIT, 'bounded nonempty JSON body')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    need(type(value) is dict, 'JSON object required')
    return value


def inputs(ref, commit, manifest_sha):
    need(type(ref) is str and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9][A-Za-z0-9._/-]{0,160}', ref)
         and not any(x in ref for x in ('..', '//', '@{'))
         and all(part and not part.startswith('.') and not part.endswith(('.', '.lock')) for part in ref.split('/')),
         'exact safe codex Source branch ref')
    need(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit), 'exact 40-hex Source commit')
    need(digest(manifest_sha), 'external whole manifest SHA256')


def validate(manifest_raw, manifest_sha, raws):
    need(pin(manifest_raw)['sha256'] == manifest_sha, 'external manifest hash mismatch')
    manifest = decode(manifest_raw)
    need(set(manifest) == {'schema', 'scope', 'case', 'reader_expected_status', 'files'}
         and type(manifest['schema']) is int and manifest['schema'] == 1
         and manifest['scope'] == SCOPE and manifest['case'] == CASE
         and manifest['reader_expected_status'] == STATUS, 'fixed LLVM260 manifest contract')
    files = manifest['files']
    need(type(files) is dict and set(files) == set(NAMES) and set(raws) == set(NAMES),
         'exact seven public roles')
    for role, name in NAMES.items():
        row = files[role]
        need(type(row) is dict and set(row) == {'name', 'bytes', 'sha256'} and row['name'] == name
             and type(row['bytes']) is int and 0 < row['bytes'] <= LEAF_LIMIT
             and digest(row['sha256']), 'fixed public name and bounded actual whole pin')
        raw = raws[role]
        need(type(raw) is bytes and 0 < len(raw) <= LEAF_LIMIT
             and pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'whole public leaf mismatch')
        need(not re.search(br'-----BEGIN (?:PGP PRIVATE KEY BLOCK|[A-Z0-9 ]*PRIVATE KEY)-----', raw),
             'private key marker forbidden')
    # Worst-case stored ZIP plus deflate expansion, ZIP64 and conservative per-entry
    # extras/data descriptors. upload-artifact uses compression-level: 0.
    bound = 1024 + sum(len(raws[r]) + (len(raws[r]) // 16383 + 1) * 5
                       + 1024 + 2 * len(n.encode('ascii')) for r, n in NAMES.items())
    need(bound <= ZIP_LIMIT, 'conservative whole uploaded ZIP exceeds 32 MiB')
    key_raw = raws['public_test_key'].strip()
    need(key_raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n')
         and key_raw.endswith(b'-----END PGP PUBLIC KEY BLOCK-----')
         and key_raw.count(b'-----BEGIN') == 1 and key_raw.count(b'-----END') == 1,
         'single public armored TEST certificate required')
    binding, result, proof, decision = (decode(raws[r]) for r in
                                       ('reader_binding', 'reader_result', 'verification_proof', 'root_decision'))
    decode(raws['source_audit'])  # Rust source/legal review: no invented LLVM tuple fields.
    actual = binding['actual']
    need(type(actual) is dict and all(actual[k] == CASE[k] for k in
                                    ('source', 'ref', 'run', 'job', 'artifact', 'attempt'))
         and type(actual['attempt']) is int and binding['source_map_sha256'] == CASE['map_sha256']
         and binding['package_sha256'] == CASE['package_sha256'], 'fixed actual Reader7 tuple/map/package')
    need(result['actual'] == actual and result['status'] == STATUS
         and result['binding_sha256'] == pin(raws['reader_binding'])['sha256'], 'successful whole-bound Reader7')
    archive = dict(bytes=CASE['package_bytes'], sha256=CASE['package_sha256'])
    signature = pin(raws['llvm_signature'])
    key = proof['public_test_key']
    need(type(key) is dict and set(key) == {'bytes', 'sha256', 'fingerprint', 'trust_scope'}
         and type(key['fingerprint']) is str and re.fullmatch(r'(?:[0-9A-F]{40}|[0-9A-F]{64})', key['fingerprint'])
         and {k: key[k] for k in ('bytes', 'sha256')} == pin(raws['public_test_key'])
         and key['trust_scope'] == 'TEST_ONLY', 'same whole public TEST key and actual fingerprint')
    need(proof['schema'] == 1 and proof['Root_issuer'] == 'Root'
         and proof['status'] == 'ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and proof['verified'] is True
         and proof['archive'] == archive and proof['signature'] == signature
         and proof['trust_scope'] == 'TEST_ONLY', 'Root-verified unchanged archive/signature/key proof')
    source = dict(sha=CASE['source'], ref=CASE['ref'], run=CASE['run'], job=CASE['job'])
    original = dict(source=CASE['source'], run=CASE['run'], job=CASE['job'], artifact_id=CASE['artifact'])
    need(decision['schema'] == 1 and decision['issuer'] == 'Root' and decision['accepted'] is True
         and decision['holds_preserved'] is True and decision['status'] == 'ACCEPTED_PRIVATE_LLVM23_PACKAGE_TEST_ONLY'
         and decision['source'] == source and decision['original'] == original
         and decision['artifact']['id'] == CASE['artifact']
         and decision['archive'] == dict(archive, package='cachy-asahi-llvm23-source-reference',
                                         version='23.1.1-1', arch='aarch64')
         and decision['signature'] == signature and decision['public_test_key'] == key
         and decision['verification_proof_sha256'] == pin(raws['verification_proof'])['sha256'],
         'final Root TEST decision joins verified proof and fixed Original')
    return bound


def git(repo, *args, max_bytes=65536):
    remaining = 60 if END is None else END - time.monotonic()
    need(remaining > 0, 'collector wall budget expired')
    # No Source worktree, hooks, credentials, submodules, external protocols or
    # global configuration. The only fetch target is the fixed public repository.
    env = dict(PATH=os.environ['PATH'], HOME=str(repo), LANG='C', LC_ALL='C',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
               GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1')
    command = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
               '-c', 'protocol.https.allow=always', '-C', str(repo), *args]
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=remaining, check=False)
    need(result.returncode == 0, 'Git data operation failed')
    need(len(result.stdout) <= max_bytes, 'Git data output limit')
    return result.stdout


def read_source(repo, commit):
    tree = git(repo, 'ls-tree', '-rz', '--full-tree', commit)
    rows = {}
    for row in tree.split(b'\0')[:-1]:
        metadata, name_raw = row.split(b'\t', 1)
        name = name_raw.decode('ascii')
        mode, kind, oid = metadata.decode('ascii').split(' ')
        need(name not in rows and name in {'manifest.json', *NAMES.values()}
             and mode == '100644' and kind == 'blob' and re.fullmatch('[0-9a-f]{40}', oid),
             'closed eight ordinary 0644 Source blobs; no extra namespace')
        rows[name] = oid
    need(set(rows) == {'manifest.json', *NAMES.values()}, 'complete eight-file Source required')
    result = {}
    for name, oid in rows.items():
        size = git(repo, 'cat-file', '-s', oid, max_bytes=32).strip()
        need(re.fullmatch(b'[0-9]+', size) and 0 < int(size) <= LEAF_LIMIT, 'Git leaf size cap')
        raw = git(repo, 'cat-file', 'blob', oid, max_bytes=LEAF_LIMIT)
        need(len(raw) == int(size), 'whole Git leaf length')
        result[name] = raw
    return result.pop('manifest.json'), {r: result[n] for r, n in NAMES.items()}


def private_parent(path):
    need(path.is_absolute() and path == path.resolve() and path.is_dir(), 'canonical RunnerTemp directory')
    for item in (path, *path.parents):
        need(not item.is_symlink(), 'no symlink RunnerTemp ancestors')
    info = path.stat()
    need(info.st_uid == os.geteuid() and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022,
         'owned non-writable RunnerTemp required')


def stage(parent, raws):
    private_parent(parent)
    output = Path(tempfile.mkdtemp(prefix='llvm260-public-proofs-', dir=parent))
    for role, name in NAMES.items():
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raws[role])
    return output


def main():
    global END
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-ref', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    inputs(args.source_ref, args.source_commit, args.manifest_sha256)
    need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized trusted collector')
    resource.setrlimit(resource.RLIMIT_AS, (256 * MIB, 256 * MIB))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (40 * MIB, 40 * MIB))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    END = time.monotonic() + 60
    parent = Path(os.environ['RUNNER_TEMP'])
    private_parent(parent)
    with tempfile.TemporaryDirectory(prefix='llvm260-source-git-', dir=parent) as directory:
        repo = Path(directory)
        git(repo, 'init', '--bare', '--quiet')
        git(repo, 'fetch', '--quiet', '--no-tags', '--no-recurse-submodules', '--depth=1',
            '--filter=blob:limit=8388609', REPOSITORY, args.source_ref)
        head = git(repo, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}').decode('ascii').strip()
        need(head == args.source_commit, 'Source ref/commit mismatch')
        manifest, raws = read_source(repo, head)
        bound = validate(manifest, args.manifest_sha256, raws)
        output = stage(parent, raws)
    print(json.dumps(dict(scope=SCOPE, files=7, zip_upper_bound=bound, trust_scope='TEST_ONLY')))
    # GitHub output path is runner-owned and the fresh output path has no data-derived parts.
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
        stream.write('proof_directory=' + str(output) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, RecursionError,
            subprocess.SubprocessError, MemoryError) as error:
        print('REFUSED: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
