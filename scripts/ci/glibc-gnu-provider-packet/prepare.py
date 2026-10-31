#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passively join one collected native provider pair to explicit Root decisions.

No package, exported Python, compiler, shell, Git, container or VM is executed.
No output directory exists until every admission and byte join has passed.
"""
import argparse
import collections
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import struct
import tarfile
import tempfile
import time
import zipfile

RUN = 38960150458
SOURCE = '0056a7c1b83ff325f1368d3659cfeb8e5a5c8358'
PACKAGE = 'cachy-asahi-glibc-gnu-provider-2.43.caa1-1-aarch64.pkg.tar.xz'
HELD = 'glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz'
HELD_SHA = '8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b'
LOCK = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
NORMAL = 'a766bc7cd31cce18fe7e564432de4e4b63db49763608ae70ef8fab61cd29116c'
SMOKE = 'e10336aef200731c7dd4b06546b718e095c1ecf7718e4a25fa57d6bbed6270a6'
GNU = {'glibc-2.43.tar.gz':dict(bytes=40287809,sha256='e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004'),
       'glibc-2.43.tar.gz.sig':dict(bytes=1018,sha256='bfd0c5a9924e4f084281cd2f3ba96e5c6e87a6d363113e7a0f98c5151463c9e3'),
       'gnu-keyring.gpg':dict(bytes=3698125,sha256='0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca')}
# Literal byte identities read from SOURCE; validation never executes Git.
FROZEN_RECIPE = {'build-harness/expected.SRCINFO': {'bytes': 1302,
                                    'sha256': '7d6cef16f2a0e5833569dcf2d9c07849278171577744166bb63c377c7d9533e5'},
 'source/0001-mount-macro-guards.patch': {'bytes': 905,
                                          'sha256': '09117692cd3a1d5838ea700df68b512f9f625a6d2af497a1afcf92046deca8f5'},
 'source/0002-held-builder-test-expectations.patch': {'bytes': 1169,
                                                      'sha256': 'f730c778ba51f9e525c9f6a7949a76af00364d49f41eedb5d73b8e86a3d4c132'},
 'source/COPYING.LESSERv2': {'bytes': 26419,
                             'sha256': '20e50fe7aae3e56378ebf0417d9de904f55a0e61e4df315333e632a4d3555d95'},
 'source/COPYINGv2': {'bytes': 17984,
                      'sha256': 'edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6'},
 'source/LICENSES': {'bytes': 19665, 'sha256': 'b22a69aa3f80a5201818c66cb0df0f25f9fa13cf5861b0093a058dbd12d50dce'},
 'source/PKGBUILD': {'bytes': 3733, 'sha256': 'a2d08f4786879a86af14cccf1cffe21811aa8dfa4428559848fa4cede839ab64'},
 'source/README.md': {'bytes': 3346, 'sha256': '78e75a94748863b80b00ae24ea8b3b3d384e8c2c096a8fe1b98d4b12550c2449'},
 'source/source-lock.json': {'bytes': 6600,
                             'sha256': 'f01bfcaefdbd32b440cdde5b4efda7c5c6902f34998ad34d9298663bc3155941'},
 'source/stage.py': {'bytes': 8147, 'sha256': '43b1b441dcc384379ab80c4864bbf7ffd898d56e4ba629c0faa966c25a979e6c'}}
BINARIES = {'smoke-normal', 'exec-child', 'plugin.so'}
ABI_LIBRARIES = {'ld-linux-aarch64.so.1','libc.so.6','libm.so.6','libresolv.so.2','libdl.so.2',
                 'libpthread.so.0','librt.so.1','libutil.so.1','libanl.so.1','libBrokenLocale.so.1','libthread_db.so.1'}
CASES = {'allocation', 'dlopen_dlsym', 'pthread_tls_join', 'utf8_iconv_locale',
         'numeric_math', 'fd_stat_clock_random', 'numeric_address_lookup', 'fork_exec_wait'}
MiB = 1024**2


def need(ok, why):
    if not ok:
        raise ValueError(why)


def path(name):
    need(type(name) is str and 0 < len(name) <= 1024 and not name.startswith('/') and
         all(p not in ('', '.', '..') for p in name.split('/')) and '\\' not in name and
         not any(ord(c) < 32 for c in name), 'closed relative path required')
    return name


def digest(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ref(name, raw):
    return dict(path=path(name), **digest(raw))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def obj(raw, cap=2*MiB):
    need(len(raw) <= cap, 'bounded JSON required')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=pairs)
    need(type(result) is dict, 'JSON object required')
    return result


def ordinary(file, cap=256*MiB):
    file = Path(file).absolute()
    need(not any(p.is_symlink() for p in (file, *file.parents)), 'ordinary unaliased input required')
    info = file.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= cap,
         'bounded ordinary input required')
    raw = file.read_bytes()
    need(len(raw) == info.st_size and len(raw) <= cap, 'input changed during read')
    return raw


def exact(row, raw):
    need(type(row) is dict and type(row.get('bytes')) is int and row['bytes'] >= 0 and
         re.fullmatch('[0-9a-f]{64}', str(row.get('sha256', ''))) and
         {k: row[k] for k in ('bytes', 'sha256')} == digest(raw), 'actual byte/hash join failed')


def export(raw):
    files = {}; total = 0; seen = set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        need(len(archive.infolist()) <= 512, 'bounded export member count')
        for row in archive.infolist():
            name = path(row.filename.rstrip('/'))
            need(name not in seen and not row.flag_bits & 1 and
                 stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
                 'ordinary distinct export member required')
            seen.add(name)
            if row.is_dir():
                continue
            total += row.file_size
            need(row.file_size <= 256*MiB and total <= 768*MiB, 'bounded export bytes')
            files[name] = archive.read(row)
            need(len(files[name]) == row.file_size, 'export ZIP length differs')
    need('retention.json' in files, 'original exporter retention manifest required')
    report = obj(files['retention.json'])
    need(report['status'] == 'PASS_UNSELECTED_GNU_PROVIDER_NATIVE_PAIR_EVIDENCE' and
         report['errors'] == [] and type(report['files']) is dict and
         set(report['files']) == set(files)-{'retention.json'}, 'closed successful native export required')
    for name, row in report['files'].items():
        exact(row, files[path(name)])
        need(type(row['source_bytes']) is int and type(row['truncated']) is bool and
             row['source_bytes'] >= row['bytes'] and row['truncated'] == (row['source_bytes'] > row['bytes']),
             'honest retained/truncated byte counts required')
        need(not row['truncated'] or name.endswith(('build.log', 'smoke.log', 'upstream-check.log', 'upstream-abi.log')),
             'proof/source/compiler outputs must be complete')
    need(report['total_bytes'] == sum(len(v) for k, v in files.items() if k != 'retention.json'),
         'export aggregate differs')
    return files


def fields(raw):
    need(len(raw) <= 65536, 'bounded literal metadata')
    rows = {}
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.fullmatch(r'([A-Za-z0-9_]+) = (.{1,4096})', line)
        need(m is not None, 'literal metadata required')
        rows.setdefault(m[1], []).append(m[2])
        need(len(rows) <= 64 and len(rows[m[1]]) <= 1024, 'metadata field bound')
    return rows


def interpreter(raw):
    need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01' and
         struct.unpack_from('<H', raw, 18)[0] == 183, 'normal AArch64 ELF required')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    need(size == 56 and 0 < count <= 1024 and offset + count*size <= len(raw), 'ELF table bound')
    found = []; loads = 0
    for i in range(count):
        row = struct.unpack_from('<IIQQQQQQ', raw, offset+i*size)
        if row[0] == 1:
            loads += 1
            need(row[7] >= 16384 and row[7] & (row[7]-1) == 0 and row[2] % row[7] == row[3] % row[7] and
                 row[6] >= row[5] and row[2]+row[5] <= len(raw), '16K aligned bounded ELF required')
        if row[0] == 3:
            need(0 < row[5] <= 256 and row[2]+row[5] <= len(raw), 'PT_INTERP bound')
            value = raw[row[2]:row[2]+row[5]]
            need(value.endswith(b'\0') and b'\0' not in value[:-1], 'one terminated interpreter')
            found.append(value[:-1].decode('ascii'))
    need(loads and len(found) <= 1, 'loadable ELF and unique interpreter')
    return found[0] if found else None


def package(raw, recipe, retained):
    """Hash every payload node without extraction; join actual embedded metadata."""
    nodes = {}; metadata = {}; total = 0; deadline = time.monotonic()+90
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r|xz') as archive:
        for member in archive:
            name = path(member.name.rstrip('/'))
            need(time.monotonic() < deadline and len(nodes) < 60000 and name not in nodes and
                 not member.mode & 0o7000 and not member.sparse and
                 (member.isfile() or member.isdir() or member.issym() or member.islnk()), 'bounded ordinary package node')
            total += member.size
            need(member.size <= 256*MiB and total <= 512*MiB, 'bounded package payload')
            meta = name in ('.PKGINFO', '.BUILDINFO', '.MTREE')
            need(meta or name in ('usr', 'etc') or name.startswith(('usr/', 'etc/')), 'conventional package path')
            row = dict(mode=member.mode, type=member.type.decode('ascii'))
            if member.isfile():
                stream = archive.extractfile(member); hasher = hashlib.sha256(); remaining = member.size
                chunks = [] if meta else None
                need(not meta or member.size <= 2*MiB, 'bounded package metadata')
                while remaining:
                    chunk = stream.read(min(MiB, remaining)); need(chunk, 'short package member')
                    remaining -= len(chunk); hasher.update(chunk)
                    if meta: chunks.append(chunk)
                row.update(bytes=member.size, sha256=hasher.hexdigest())
                if meta: metadata[name] = b''.join(chunks)
            elif member.issym() or member.islnk():
                target = member.linkname
                need(target and not target.startswith('/') and '\x00' not in target, 'relative package link')
                joined = posixpath.normpath(target if member.islnk() else posixpath.join(posixpath.dirname(name), target))
                path(joined); need(joined.startswith('usr/'), 'package link escapes provider')
                row['target'] = target
            nodes[name] = row
    need(set(metadata) == {'.PKGINFO', '.BUILDINFO', '.MTREE'} and
         all(metadata[n] == retained[n] for n in metadata), 'embedded/retained package metadata join')
    info, build = fields(metadata['.PKGINFO']), fields(metadata['.BUILDINFO'])
    need(info.get('pkgname') == build.get('pkgname') == ['cachy-asahi-glibc-gnu-provider'] and
         info.get('pkgver') == build.get('pkgver') == ['2.43.caa1-1'] and
         info.get('arch') == build.get('pkgarch') == ['aarch64'] and build.get('format') == ['2'] and
         build.get('pkgbuild_sha256sum') == [recipe] and info.get('provides') == ['glibc=2.43'] and
         info.get('conflict') == ['glibc'] and info.get('backup') == ['etc/gai.conf'] and
         sorted(info.get('depend', [])) == sorted(['linux-api-headers>=4.10', 'filesystem', 'tzdata']) and
         'replaces' not in info, 'actual provider identity/BUILDINFO recipe join')
    required = {'etc/gai.conf', 'usr/lib/libc.so.6', 'usr/lib/libm.so.6', 'usr/lib/ld-linux-aarch64.so.1',
                'usr/lib/gconv/ISO8859-1.so', 'usr/lib/locale/C.utf8/LC_CTYPE'}
    required |= {'usr/share/licenses/cachy-asahi-glibc-gnu-provider/'+n for n in ('COPYINGv2','COPYING.LESSERv2','LICENSES')}
    need(required <= set(nodes) and '.INSTALL' not in nodes and
         not any(n.startswith(('opt/', 'usr/share/libalpm/hooks/')) for n in nodes), 'provider payload/license gate')
    return dict(nodes=len(nodes), bytes=total, node_map_sha256=hashlib.sha256(encoded(nodes)).hexdigest(),
                licenses={n: nodes[n] for n in sorted(required) if '/licenses/' in n})


def licenses(raw):
    result = {}; total = 0; count = 0; deadline = time.monotonic()+90
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r|gz') as archive:
        for member in archive:
            count += 1; total += member.size
            need(count <= 60000 and total <= 512*MiB and member.size <= 64*MiB and
                 time.monotonic() < deadline, 'bounded original GNU source archive')
            if member.name in {'glibc-2.43/'+n for n in ('COPYINGv2','COPYING.LESSERv2','LICENSES')}:
                need(member.isfile() and member.size <= MiB, 'ordinary GNU license source')
                result[member.name.split('/')[-1]] = digest(archive.extractfile(member).read())
    need(set(result) == {'COPYINGv2','COPYING.LESSERv2','LICENSES'}, 'complete original GNU licenses')
    return result


def commands(files, directory, rows, count):
    need(type(rows) is list and len(rows) == count, 'complete compiler/runtime command count')
    for i, row in enumerate(rows):
        need(row['exit_code'] == 0 and row['group_absence_verified'] is True, 'command exit/group retirement')
        for suffix in ('stdout', 'stderr'):
            raw = files[directory+('/command-%02d.' % i)+suffix]
            need(row[suffix+'_bytes'] == len(raw) and row[suffix+'_sha256'] == digest(raw)['sha256'],
                 'complete original compiler/runtime output join')


def upstream(value):
    need(value['status'] == 'PASS_UPSTREAM_APPLICABLE_TESTS' and value['check_exit'] == value['abi_exit'] == 0 and
         value['malformed'] == [] and type(value['results']) is list and 1 <= len(value['results']) <= 50000,
         'complete applicable upstream checks required')
    counts = dict(collections.Counter(row['status'] for row in value['results']))
    expected = dict.fromkeys(('PASS','FAIL','XFAIL','XPASS','UNSUPPORTED','ERROR'), 0); expected.update(counts)
    need(value['counts'] == expected and expected['PASS'] > 0 and
         all(expected[k] == 0 for k in ('FAIL','XPASS','ERROR')) and
         len({row['path'] for row in value['results']}) == len(value['results']), 'upstream records/counts/failures differ')
    for row in value['results']:
        path(row['path']); need(re.fullmatch('[0-9a-f]{64}', row['sha256']), 'original test result digest')


def native(files, run):
    read = lambda name: obj(files[name], 32*MiB)
    proof = read('source-proof.json'); result = read('runtime/result.json'); base = read('base/report.json')
    need(proof['status'] == 'SOURCE_PROOF_PASS' and proof['source_sha'] == proof['workflow_sha'] == SOURCE and
         str(proof['run_id']) == str(RUN) and str(proof['run_attempt']) == str(run['run_attempt']), 'actual native source/run proof')
    seed = str(RUN)+':'+str(run['run_attempt'])+':'+SOURCE
    token = hashlib.sha256(('glibc-provider-consumer:'+seed).encode()).hexdigest()[:32]
    need(proof['consumer_token'] == token and proof['job_token'] == hashlib.sha256(('glibc-provider-producer:'+seed).encode()).hexdigest()[:16], 'actual ownership tokens')
    need(result['status'] == 'PASS_UNSELECTED_NATIVE_PAIR' and result['archive_bytes_reproduced'] is True and
         result['normal_client_bytes_reproduced'] is True and result['source_bundle_preserved'] is True and
         result['frozen_sources_preserved'] is True and result['ownership_token'] == token and
         result['base_lock_sha256'] == LOCK and base['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and
         digest(files['base/installed-packages.lock'])['sha256'] == LOCK and
         len(files['base/installed-packages.lock'].splitlines()) == 574, 'complete preserved native pair/base')
    names = {'caa-glibc-provider-'+token+'-'+suffix for suffix in ('probe','a','a-smoke','b','b-smoke')}
    def retired(rows):
        need(len(rows) == 5 and {r['container'] for r in rows} == names and
             all(r['status'] == 'PASS-absence-verified' for r in rows), 'all distinct native consumers must retire')
    retired(result['cleanup'])
    cleanup = read('ordered-cleanup.json')
    need(cleanup['status'] == 'PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and
         cleanup['consumer']['status'] == 'PASS_CONSUMERS_RETIRED' and cleanup['producer']['status'] == 'PASS' and
         cleanup['producer']['probe']['absence_verified'] is True and cleanup['producer']['image']['absence_verified'] is True,
         'ordered native producer cleanup required')
    retired(cleanup['consumer']['containers'])
    bundle = read('source/bundle.json'); harness = read('build-harness/source-manifest.json')
    need(bundle['status'] == 'SOURCE_BUNDLE_READY_UNSELECTED_GNU_PROVIDER' and
         result['source_bundle_manifest_sha256'] == digest(files['source/bundle.json'])['sha256'] and
         result['harness_manifest_sha256'] == digest(files['build-harness/source-manifest.json'])['sha256'], 'source/harness manifest join')
    for directory, manifest in (('source/', bundle), ('build-harness/', harness)):
        need(type(manifest['files']) is dict and 1 <= len(manifest['files']) <= 32, 'bounded source closure')
        for name, row in manifest['files'].items():
            need('/' not in path(name), 'flat original source member'); exact(row, files[directory+name])
    recipe = digest(files['source/PKGBUILD'])['sha256']
    need(set(bundle['files']) == {n.removeprefix('source/') for n in FROZEN_RECIPE if n.startswith('source/')} |
         set(GNU) | {'source-authentication.json'}, 'exact frozen recipe/source bundle closure')
    for name, identity in FROZEN_RECIPE.items():
        exact(identity, files[name])
    # makepkg generated metadata is retained per build, never a source bundle input.
    need('source/.SRCINFO' not in files, 'generated SRCINFO belongs to native evidence')
    for name, row in GNU.items(): exact(row, files['source/'+name])
    original_licenses = licenses(files['source/glibc-2.43.tar.gz'])
    policy = read('build-harness/normal-client-policy.json')
    need(policy['status'] == 'BOUND_EXACT_NORMAL_CHILD_EXEC_SOURCE_PATCH' and
         policy['patched_abi_smoke'] == dict(bytes=12437, sha256=NORMAL) and policy['runtime_manifest_sha256'] == SMOKE,
         'exact reviewed normal source policy')
    exact(policy['patch'], files['build-harness/normal-child-exec.patch'])
    rows = result['builds']; need(len(rows) == 2 and {r['side'] for r in rows} == {'a','b'}, 'two original builds')
    payloads = {}; normal = {}
    for row in rows:
        side = row['side']; prefix = 'runtime/'+side+'/'; evidence = prefix+'evidence/'
        archive = files['packages/'+side+'/'+PACKAGE]
        need(row['status'] == 'PASS_NATIVE_BUILD_TEST_ABI_RUNTIME' and row['container'] == 'caa-glibc-provider-'+token+'-'+side and
             row['sha256'] == digest(archive)['sha256'] and row['makepkg_exit'] == 0, 'distinct actual build/archive join')
        for name in ('check-exit','abi-exit','makepkg-exit'):
            need(files[evidence+name].strip() == b'0', 'actual make/check/ABI exit must be zero')
        for name in ('packages-before.lock','packages-after.lock','packages-runtime.lock'):
            need(files[evidence+name] == files['base/installed-packages.lock'], 'original574 DB inventory preserved')
        upstream(read(evidence+'upstream-tests.json'))
        need(fields(files[evidence+'generated.SRCINFO']) == fields(files['build-harness/expected.SRCINFO']), 'actual SRCINFO expectation')
        stage = read(evidence+'provider-stage.json'); owned = read(evidence+'provider-ownership.json')
        need(stage['status'] == 'PASS_INERT_PROVIDER_STAGING' and stage['dirname_object_bytes'] == 18 and
             owned['status'] == 'PASS_HELD574_PROVIDER_FILE_OWNERSHIP' and owned['checked_packages'] == 574 and
             owned['inventory_sha256'] == LOCK and owned['other_owner_collisions'] == {}, 'payload/ownership checks')
        abi = read(evidence+'static-abi.json')
        need(abi['status'] == 'PASS_STATIC_PUBLIC_ABI' and len(abi['libraries']) == 11 and
             {r['library'] for r in abi['libraries']} == ABI_LIBRARIES and
             all(not r['missing'] and r['baseline_symbols'] > 0 for r in abi['libraries']), 'complete static ABI')
        headers = read(prefix+'header-check/receipt.json')
        need(headers['status'] == 'PASS_CANDIDATE_C_HEADERS_COMPILE_ONLY' and headers['bootstrap_libc_header_fallback'] is False and headers['dependencies'], 'candidate header compilation')
        runtime = read(prefix+'runtime-smoke/receipt.json')
        need(runtime['status'] == 'PASS_OWNED_CANDIDATE_GLIBC_RUNTIME_SMOKE' and runtime['mode'] == 'NATIVE_EXECUTE' and
             runtime['host_architecture'] == 'aarch64' and runtime['input_sha256'] == digest(files[prefix+'runtime-inputs.json'])['sha256'] and
             runtime['runtime']['status'] == 'PASS' and runtime['runtime']['cases'] == 8 and set(runtime['cases']) == CASES and
             row['runtime_receipt_sha256'] == digest(files[prefix+'runtime-smoke/receipt.json'])['sha256'], 'actual staged runtime cases')
        commands(files, prefix+'runtime-smoke', runtime['commands'], 14)
        normal[side] = read(prefix+'normal-clients/receipt.json'); receipt = normal[side]
        need(receipt['status'] == 'PASS_COMPILED_NORMAL_INTERPRETER_CLIENTS_NOT_EXECUTED' and
             receipt['policy_sha256'] == digest(files['build-harness/normal-client-policy.json'])['sha256'] and
             receipt['runtime_manifest_sha256'] == SMOKE and receipt['sources']['abi_smoke.c'] == policy['patched_abi_smoke'] and
             receipt['original_sources'] == {n:{k:r[k] for k in ('bytes','sha256')}
                                             for n,r in runtime['sources'].items()} and set(receipt['sources']) == set(runtime['sources']) and
             all(receipt['sources'][n] == receipt['original_sources'][n] for n in receipt['sources'] if n != 'abi_smoke.c') and
             receipt['bootstrap_headers'] and set(receipt['compiled_files']) == BINARIES and
             row['normal_compile_receipt_sha256'] == digest(files[prefix+'normal-clients/receipt.json'])['sha256'], 'normal compiler/source receipt join')
        commands(files, prefix+'normal-clients/build', receipt['commands'], 13)
        need(set(receipt['toolchain']) == {'gcc','cc1','collect2','as','ld','version'} and
             all(type(receipt['toolchain'][n]['bytes']) is int and receipt['toolchain'][n]['bytes'] > 0 and
                 re.fullmatch('[0-9a-f]{64}', receipt['toolchain'][n]['sha256']) for n in ('gcc','cc1','collect2','as','ld')) and
             type(receipt['source_patch_tool']['bytes']) is int and receipt['source_patch_tool']['bytes'] > 0 and
             re.fullmatch('[0-9a-f]{64}', receipt['source_patch_tool']['sha256']), 'actual recorded normal compiler/patch tools')
        patch = receipt['source_patch_command']
        need(patch['exit_code'] == 0 and patch['group_absence_verified'] is True, 'normal source patch retired')
        for suffix in ('stdout','stderr'):
            need(patch[suffix+'_bytes'] == len(files[prefix+'normal-clients/patch.'+suffix]) and
                 patch[suffix+'_sha256'] == digest(files[prefix+'normal-clients/patch.'+suffix])['sha256'], 'original patch outputs')
        for name in BINARIES:
            raw = files[prefix+'normal-clients/bin/'+name]; compiled = receipt['compiled_files'][name]
            exact(compiled, raw)
            observed = interpreter(raw)
            need(compiled['elf_machine'] == 183 and compiled['artifact'] == 'bin/'+name and
                 compiled['interpreter'] == observed and
                 (observed is None if name == 'plugin.so' else observed in ('/lib/ld-linux-aarch64.so.1','/usr/lib/ld-linux-aarch64.so.1')) and
                 row['normal_clients'][name] == digest(raw)['sha256'], 'normal system-interpreter binary join')
        payloads[side] = package(archive, recipe, {n: files[prefix+'package-metadata/'+n] for n in ('.PKGINFO','.BUILDINFO','.MTREE')})
        for name, identity in original_licenses.items():
            packaged = payloads[side]['licenses']['usr/share/licenses/cachy-asahi-glibc-gnu-provider/'+name]
            need({k:packaged[k] for k in ('bytes','sha256')} == identity,
                 'installed license bytes join original GNU source')
    need(files['packages/a/'+PACKAGE] == files['packages/b/'+PACKAGE] and payloads['a'] == payloads['b'] and
         all(files['runtime/a/normal-clients/bin/'+n] == files['runtime/b/normal-clients/bin/'+n] for n in BINARIES), 'independent package/normal-client byte equality')
    return proof, recipe, payloads


def normal_sources(files, root):
    manifest_raw = ordinary(root/'source-manifest.json', 65536)
    need(digest(manifest_raw)['sha256'] == SMOKE, 'held original runtime source manifest')
    manifest = obj(manifest_raw)
    receipt = obj(files['runtime/a/normal-clients/receipt.json'])
    need(set(receipt['original_sources']) == {'abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py'},
         'exact original runtime sources')
    result = {'normal-source/source-manifest.json':manifest_raw}
    license_raw = ordinary(root/'LICENSE', MiB)
    exact(manifest['files']['LICENSE'], license_raw)
    result['normal-source/LICENSE'] = license_raw
    for name,row in receipt['original_sources'].items():
        raw = ordinary(root/name, MiB); exact(row, raw); exact(manifest['files'][name], raw)
        result['normal-source/original/'+name] = raw
    change = obj(files['build-harness/normal-exec-change.json'])
    raw = result['normal-source/original/abi_smoke.c']
    before, after = change['replacement_before'].encode(), change['replacement_after'].encode()
    need(digest(raw)['sha256'] == change['before_sha256'] and raw.count(before) == 1, 'exact one normal-child source edit')
    patched = raw.replace(before, after)
    need(digest(patched)['sha256'] == change['after_sha256'] == NORMAL, 'exact compiled normal-source bytes')
    result['normal-source/smoke-normal.c'] = patched
    return result


def decisions(files, run, artifact, pair_raw, probes_raw, private_raw, private_runtime):
    pair, probes, private = map(obj, (pair_raw, probes_raw, private_raw))
    expected = dict(run_id=RUN, source_sha=SOURCE, artifact_sha256=digest(artifact)['sha256'],
                    retention_sha256=digest(files['retention.json'])['sha256'])
    for value in (pair, probes):
        need(all(value.get(k) == v for k,v in expected.items()), 'Root decision actual run/source/export join')
    recipe = digest(files['source/PKGBUILD'])['sha256']
    need(pair['status'] == 'ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and pair['hardware'] == 'NOT_RUN' and
         pair['archive_sha256'] == digest(files['packages/a/'+PACKAGE])['sha256'] and
         pair['provider_pkgbuild_sha256'] == recipe, 'explicit Root actual native-pair acceptance required')
    selected = {n: ref('runtime/a/normal-clients/bin/'+n, files['runtime/a/normal-clients/bin/'+n]) for n in sorted(BINARIES)}
    compile_refs = {s: ref('runtime/'+s+'/normal-clients/receipt.json', files['runtime/'+s+'/normal-clients/receipt.json']) for s in ('a','b')}
    need(probes['status'] == 'ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and probes['normal_source_sha256'] == NORMAL and
         probes['files'] == selected and probes['compile_receipts'] == compile_refs, 'explicit Root actual normal-client acceptance required')
    need(private['status'] == 'ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and private['run_id'] == 38941180852 and
         private['source_sha'] == '308c9b0cba5ad6c90530e4b10f0e3fb3e01dcbfb' and
         private['page_size'] == 16384 and private['cases'] == 8 and private['runtime_records'] == 12 and
         private['commands'] == 14 and private['compile_commands'] == 13 and
         private['actual_parent_child_providers'] == private['source_archive_payload_join'] == private['ordered_cleanup'] == 'PASS' and
         private['hardware'] == private['installation'] == 'NOT_RUN' and private['security'] == 'NO_CREDIT' and
         private['performance'] == 'NOT_MEASURED' and private['release'] == 'NOT_ADMITTED',
         'retained Rootaccepted private actual16K prerequisite')
    binding = obj(files['source-proof.json'])['private16k']
    exact(binding['root_verification'], private_raw); exact(binding, private_runtime)
    value = obj(private_runtime)
    need(value['status'] == 'PASS_PRIVATE_GLIBC_GENERIC16K_AND_ORDERED_CLEANUP' and
         value['source_commit'] == private['source_sha'] and value['natural_VM_exit'] is True and value['QEMU_exit'] == 0 and
         value['kernel_work_removed'] is True and value['producer_cleanup']['status'] == 'PASS', 'retained actual16K runtime join')
    return selected, recipe


def prepare(args):
    output = args.output.absolute()
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir() and
         not any(p.is_symlink() for p in output.parents), 'fresh ordinary output parent')
    collected = {n: ordinary(args.collection/n) for n in ('collection.json','run.json','artifacts.json','artifact.zip','logs.zip')}
    collection, run, listing = (obj(collected[n]) for n in ('collection.json','run.json','artifacts.json'))
    need(run['id'] == RUN and run['head_sha'] == SOURCE and run['status'] == 'completed' and run['conclusion'] == 'success' and
         type(run['run_attempt']) is int and run['run_attempt'] > 0, 'actual successful completed native run required')
    for name in ('artifact.zip','logs.zip'): exact(collection[name], collected[name])
    candidates = [r for r in listing['artifacts'] if r.get('workflow_run',{}).get('id') == RUN and
                  r['workflow_run'].get('head_sha') == SOURCE and r.get('digest') == 'sha256:'+digest(collected['artifact.zip'])['sha256']]
    need(len(candidates) == 1 and candidates[0]['expired'] is False and
         candidates[0]['size_in_bytes'] == len(collected['artifact.zip']) and
         candidates[0]['name'] == 'glibc-gnu-provider-'+str(RUN)+'-'+str(run['run_attempt']), 'original API artifact identity/digest join')
    files = export(collected['artifact.zip'])
    receipts = {n: ordinary(getattr(args, n)) for n in ('pair_decision','normal_decision','private16k','private_runtime')}
    probes, recipe = decisions(files, run, collected['artifact.zip'], receipts['pair_decision'], receipts['normal_decision'], receipts['private16k'], receipts['private_runtime'])
    proof, actual_recipe, payloads = native(files, run)
    need(actual_recipe == recipe, 'recipe identity consistency')
    held = ordinary(args.held)
    need(args.held.name == HELD and digest(held)['sha256'] == HELD_SHA, 'exact held rollback archive required')
    # Keep the original ZIP and its collection/API metadata so every original
    # member origin remains independently reproducible inside this packet.
    original = dict(files)
    source_files = normal_sources(files, args.runtime_sources)
    files.update(source_files)
    files.update({'collected/'+n: raw for n,raw in collected.items()})
    names = {'pair_decision':'acceptance/provider-pair.json','normal_decision':'acceptance/normal-probes.json',
             'private16k':'acceptance/private16k.json','private_runtime':'acceptance/private16k-runtime.json'}
    files.update({names[n]:raw for n,raw in receipts.items()}); files['rollback/'+HELD] = held
    origins = {n: dict(kind='original_zip_member', archive='collected/artifact.zip', member=n,
                       source_sha=SOURCE, **digest(raw)) for n,raw in original.items()}
    origins.update({'collected/'+n:dict(kind='original_collection_file', input=str(args.collection/n), **digest(raw)) for n,raw in collected.items()})
    origins.update({names[n]:dict(kind='explicit_Root_input', input=str(getattr(args,n)), **digest(raw)) for n,raw in receipts.items()})
    origins['rollback/'+HELD] = dict(kind='retained_held_rollback', input=str(args.held), **digest(held))
    origins.update({n:dict(kind='exact_single_child_exec_edit' if n == 'normal-source/smoke-normal.c'
                          else 'held_reviewed_runtime_source', runtime_manifest_sha256=SMOKE, **digest(raw))
                    for n,raw in source_files.items()})
    # The owner requires positive-sized ordinary refs. Empty original outputs
    # stay verifiable in collected/artifact.zip and the closed source map.
    files = {n:raw for n,raw in files.items() if raw}
    files['source-map.json'] = encoded(dict(schema_version=1, run_id=RUN, source_sha=SOURCE,
        artifact_sha256=digest(collected['artifact.zip'])['sha256'], files=origins,
        passive_joins=dict(provider_pkgbuild_sha256=recipe, payloads=payloads),
        scope='accepted native pair and compiled normal probes only; installed/hardware/security/performance/release NOT ADMITTED'))
    need(8 <= len(files) <= 256 and sum(map(len,files.values())) <= 512*MiB and
         all(len(v) <= 256*MiB for v in files.values()) and
         all(len(v) > 0 for n,v in files.items() if n in {r['path'] for r in probes.values()}), 'owner packet count/byte bound')
    index = dict(schema_version=1, status='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS',
        files={n:digest(raw) for n,raw in sorted(files.items())},
        private16k=ref(names['private16k'], receipts['private16k']), provider_pair=ref(names['pair_decision'], receipts['pair_decision']),
        probe_receipt=ref(names['normal_decision'], receipts['normal_decision']), held=ref('rollback/'+HELD,held),
        archives={s:ref('packages/'+s+'/'+PACKAGE, files['packages/'+s+'/'+PACKAGE]) for s in ('a','b')},
        probes=probes, provider_pkgbuild_sha256=recipe)
    # Only this point can mutate the filesystem. Refuse replacement and remove
    # our own temporary tree on interruption/failure; inputs remain untouched.
    temporary = Path(tempfile.mkdtemp(prefix='.'+output.name+'-', dir=output.parent))
    try:
        for name,raw in files.items():
            target = temporary/path(name); target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o755 if '/normal-clients/bin/' in name else 0o600)
            exact(index['files'][name], ordinary(target))
        (temporary/'packet.json').write_bytes(encoded(index))
        # Exclusive publication reservation: another preparer cannot have its
        # existing empty directory replaced by the final rename.
        output.mkdir(mode=0o700)
        reservation = output.stat()
        try:
            os.rename(temporary, output)
        except BaseException:
            if output.exists() and output.stat().st_ino == reservation.st_ino and not any(output.iterdir()):
                output.rmdir()
            raise
    except BaseException:
        if temporary.exists(): shutil.rmtree(temporary)
        raise
    return dict(status='PREPARED_ROOT_ACCEPTED_IMMUTABLE_INPUTS_ONLY', output=str(output),
                packet=digest(encoded(index)), files=len(files), total_bytes=sum(map(len,files.values())),
                native_run=RUN, native_source=SOURCE, installed='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('collection','pair-decision','normal-decision','private16k','private-runtime','runtime-sources','held','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(json.dumps(dict(status='REFUSED_BEFORE_PACKET_PUBLICATION', error=str(error)[:256]), sort_keys=True))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
