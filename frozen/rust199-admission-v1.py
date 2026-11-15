# SPDX-License-Identifier: MIT
"""Root-supplied Rust material gate. No acquisition, image mutation or execution."""
import copy
import hashlib
import json
import math
import os
from pathlib import PurePosixPath
import re
import stat

MIB = 1024**2
GIB = 1024**3
TARGET = 'aarch64-unknown-linux-gnu'
CANDIDATE = 'dd6871d566661c4fe9eba055ae19e1e017e0b69d'
INPUTS_SHA = '4011253ed366f871b1f5e2cac1f5af0dc63049c1fa7badd293318adb44741672'
LLVM_SOURCE = '4ceaa1c6958349451197b19acdb084a2a5be216b'
LLVM_PACKAGE = 'cachy-asahi-llvm23-source-reference'
LLVM_ARCHIVE = LLVM_PACKAGE + '-23.1.1-1-aarch64.pkg.tar.zst'
BASELINE_SHA = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
PROPOSAL = dict(cpus=2, memory_bytes=8*GIB, memory_swap_bytes=8*GIB, swap_bytes=0, pids=512,
    prepare_actor_seconds=900, build_actor_seconds=16200, native_seconds=19800, cleanup_seconds=300,
    export_bytes=4*GIB, package_bytes=2*GIB, log_bytes=64*MIB, job_minutes=360,
    minimum_host_memory_bytes=12*GIB, minimum_host_disk_bytes=80*GIB, minimum_host_available_inodes=1000000,
    active_host_memory_reserve_bytes=4*GIB, active_host_disk_reserve_bytes=8*GIB)
CLAIMS = dict(root_authenticated=False, native_acceptance=False, hardware_acceptance=False, release_acceptance=False)
MATERIALS = {
    'rustc-1.99.0-src.tar.xz': dict(bytes=265258564,
        sha256='cc41916a8c84f5d9ec4f55561b44e39f43b647b133f8a6f51be9ea13c83f7036',
        url='https://static.rust-lang.org/dist/rustc-1.99.0-src.tar.xz'),
    'llvm-project-23.1.1.src.tar.xz': dict(bytes=179168672,
        sha256='ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6',
        url='https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.1/llvm-project-23.1.1.src.tar.xz'),
    'cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz': dict(bytes=11116188,
        sha256='5784379d73ac881d15a9e67eed2882cd58c747c276221c23cdf9aff37e015ff6',
        url='https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz'),
    'rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz': dict(bytes=30768752,
        sha256='a36f7ac98af20ef0ba6368aace0345efabbebaef7962eba99f47190fd256162d',
        url='https://static.rust-lang.org/dist/2026-08-20/rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz'),
    'rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz': dict(bytes=66413136,
        sha256='00590657f2356d7163ca5ef295283523974c340fa21bb94b420ce794f29b358c',
        url='https://static.rust-lang.org/dist/2026-08-20/rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz'),
}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def keys(value, required, message):
    need(type(value) is dict and set(value) == set(required), message)


def path(value):
    need(type(value) is str and re.fullmatch('/[A-Za-z0-9._+/-]{1,4095}', value) and
         all(p not in ('', '.', '..') for p in value.split('/')[1:]), 'ordinary nonroot absolute path required')
    return PurePosixPath(value)


def selector(value, *, source=None, approval=False):
    wanted = {'sha', 'ref', 'run', 'job'} | ({'map_sha256', 'approval'} if approval else set())
    keys(value, wanted, 'actual Root Source/ref/run/job selectors required')
    need(sha(value['sha'], 40) and (source is None or value['sha'] == source) and
         type(value['ref']) is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+', value['ref']) and
         all(type(value[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', value[k]) for k in ('run', 'job')),
         'published Source is not a completed/accepted native job')
    if approval:
        need(sha(value['map_sha256']) and sha(value['approval']), 'external Root Source map/approval pins required')


def descriptor(row, cap=4*MIB, *, fixed_path=None, extras=()):
    keys(row, {'path', 'local_path', 'bytes', 'sha256'} | set(extras), 'actual Root external file pin required')
    actor_path = path(row['path'])
    need(str(actor_path).startswith('/inputs/') and (fixed_path is None or str(actor_path) == fixed_path),
         'fixed readonly actor operand path required')
    path(row['local_path'])
    need(type(row['bytes']) is int and 0 < row['bytes'] <= cap and sha(row['sha256']), 'positive bounded external file bytes/SHA required')


def read_file(value, cap, expected=None, keep=False):
    """Stream large packages; retain only bounded JSON/inventory bodies."""
    import pathlib
    p = pathlib.Path(path(value))
    need(not any(q.is_symlink() for q in (p, *p.parents)), 'external file aliases refused')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap and
             (not stat.S_IMODE(before.st_mode) & 0o222 or os.statvfs(p).f_flag & os.ST_RDONLY),
             'ordinary readonly bounded single-link external file required')
        total, digest, chunks = 0, hashlib.sha256(), []
        while block := os.read(fd, min(MIB, cap + 1 - total)):
            total += len(block)
            need(total <= cap, 'external file byte bound')
            digest.update(block)
            if keep:
                chunks.append(block)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(total == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()),
             'external file changed during complete read')
        actual = dict(bytes=total, sha256=digest.hexdigest())
        if expected is not None:
            need(actual == {k: expected[k] for k in ('bytes', 'sha256')}, 'external file bytes/SHA differs')
        return b''.join(chunks) if keep else actual
    finally:
        os.close(fd)


def decode(raw):
    need(type(raw) is bytes and len(raw) <= 4*MIB, 'bounded JSON input required')
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    def real(value):
        result = float(value)
        need(math.isfinite(result), 'finite JSON number required')
        return result
    def invalid(_):
        raise ValueError('nonfinite JSON refused')
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_float=real, parse_constant=invalid)
    except RecursionError as error:
        raise ValueError('JSON depth bound') from error
    pending, count = [(result, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= 32 and count <= 200000, 'JSON structure bound')
        if type(item) is dict:
            pending.extend((x, depth+1) for x in item.values())
        elif type(item) is list:
            pending.extend((x, depth+1) for x in item)
    need(type(result) is dict, 'JSON object required')
    return result


def read_json(value, expected):
    need(sha(expected), 'whole external JSON pin required')
    raw = read_file(value, 4*MIB, keep=True)
    need(hashlib.sha256(raw).hexdigest() == expected, 'external JSON SHA differs')
    return decode(raw)


def _json(row):
    read_file(row['local_path'], 4*MIB, row)
    return read_json(row['local_path'], row['sha256'])


def material_rows(rows, check_files):
    need(type(rows) is list and len(rows) == 5, 'exact five pinned material declarations required')
    seen = set()
    for row in rows:
        keys(row, {'name', 'bytes', 'sha256', 'url', 'local_path', 'transport'}, 'complete pinned material row required')
        name = row['name']
        need(type(name) is str and name in MATERIALS and name not in seen, 'unknown or duplicate material')
        seen.add(name)
        need({k: row[k] for k in ('bytes', 'sha256', 'url')} == MATERIALS[name] and
             type(row['bytes']) is int, 'frozen Rust/LLVM/stage0 material pin or URL differs')
        need(row['transport'] in ('LOCAL_READONLY', 'PINNED_HTTPS_DECLARATION'), 'no implicit acquisition transport')
        if row['transport'] == 'LOCAL_READONLY':
            path(row['local_path'])
        else:
            need(row['local_path'] is None, 'prospective HTTPS declaration is not a local material')
        if check_files:
            need(row['transport'] == 'LOCAL_READONLY', 'HTTPS declaration cannot satisfy implemented readonly local intake')
    need(seen == set(MATERIALS), 'complete five-material namespace required')


def original_join(original, source, artifact):
    keys(original, {'source', 'run', 'job', 'artifact_id'}, 'actual accepted Original selectors required')
    need(sha(original['source'], 40) and all(type(original[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', original[k])
         for k in ('run', 'job', 'artifact_id')) and original['artifact_id'] == artifact['id'] and
         original['source'] == source['sha'] and original['run'] == source['run'] and original['job'] == source['job'],
         'Original artifact must belong to the exact accepted LLVM Source/run/job')


def llvm_declaration(llvm):
    keys(llvm, {'source', 'archive', 'signature', 'public_test_key', 'verification_proof', 'root_decision',
                'artifact', 'original'}, 'accepted LLVM material/Root decision/public TEST proof required')
    selector(llvm['source'], source=LLVM_SOURCE)
    descriptor(llvm['archive'], 8*GIB, fixed_path='/inputs/' + LLVM_ARCHIVE, extras=('package', 'version', 'arch'))
    need((llvm['archive']['package'], llvm['archive']['version'], llvm['archive']['arch']) ==
         (LLVM_PACKAGE, '23.1.1-1', 'aarch64'), 'exact private LLVM23 package required')
    descriptor(llvm['signature'], MIB, fixed_path='/inputs/' + LLVM_ARCHIVE + '.sig')
    descriptor(llvm['public_test_key'], 8*MIB, extras=('fingerprint', 'trust_scope'))
    key = llvm['public_test_key']
    need(type(key['fingerprint']) is str and re.fullmatch('(?:[0-9A-F]{40}|[0-9A-F]{64})', key['fingerprint']) and
         key['trust_scope'] == 'TEST_ONLY', 'public TEST key fingerprint/scope required; no production trust')
    for k in ('verification_proof', 'root_decision'):
        descriptor(llvm[k])
    artifact = llvm['artifact']
    keys(artifact, {'id', 'bytes', 'sha256', 'metadata_sha256'}, 'actual Original artifact pins required')
    need(type(artifact['id']) is str and re.fullmatch('[1-9][0-9]{0,19}', artifact['id']) and
         type(artifact['bytes']) is int and 0 < artifact['bytes'] <= 16*GIB and
         sha(artifact['sha256']) and sha(artifact['metadata_sha256']), 'publication is not an acquired Original artifact')
    original = llvm['original']
    original_join(original, llvm['source'], artifact)


def candidate_qualification(q, proof, a):
    need(q['schema'] == 1 and q['scope'] == 'PRIVATE_SOURCE_REFERENCE_INPUT_QUALIFICATION_ONLY' and
         q['status'] == 'QUALIFIED_FOR_PRIVATE_BUILD_ONLY' and q['holds_preserved'] is True and
         q['inputs_sha256'] == INPUTS_SHA, 'unchanged candidate admission must actually qualify this private source')
    env, stage0, audit = q['environment'], q['stage0'], q['source_audit']
    need(env['native_target'] == TARGET and env['llvm_version'] == '23.1.1' and
         env['llvm_prefix'] == '/opt/cachy-asahi/llvm23-source-reference' and env['root'] == a['image_root'] and
         env['tree_sha256'] == a['image']['rootfs_tree_sha256'], 'original candidate environment/rootfs tree join differs')
    path(env['root'])  # Never rewrite the original separate tree root to '/'.
    need(stage0['native_target'] == TARGET and stage0['version'] == '1.98.0' and
         stage0['compatibility'] == 'QUALIFIED_FOR_THIS_SOURCE' and
         stage0['assembled_tree_sha256'] == a['stage0_tree_sha256'], 'metadata/model stage0 digest is not native source compatibility')
    need(audit['status'] == 'REVIEWED_FOR_THIS_PRIVATE_BUILD' and sha(audit['library_cargo_config_sha256']) and
         all(audit[k] is True for k in ('consumed_git_dependencies_and_paths_reviewed',
             'compiler_rt_libunwind_members_and_notices_reviewed', 'retained_source_authentication_rejoined')),
         'Root source/path/license review and all retained holds required')
    need(q['qualification_evidence']['path'] == '/inputs/qualification.json' and
         q['qualification_evidence']['sha256'] == a['candidate']['qualification']['sha256'], 'original qualification evidence pin differs')
    need(proof['schema'] == 1 and proof['status'] == 'QUALIFIED_FOR_THIS_SOURCE' and
         proof['native_runtime'] is True and proof['metadata_only'] is False and proof['native_target'] == TARGET and
         proof['stage0_version'] == '1.98.0' and proof['assembled_tree_sha256'] == a['stage0_tree_sha256'] and
         proof['rust_source_sha256'] == MATERIALS['rustc-1.99.0-src.tar.xz']['sha256'],
         'actual native stage0 qualification for this source required; Cargo metadata0.99 is not qualification')


def _inventory(row):
    body = read_file(row['local_path'], MIB, row, keep=True)
    result = {}
    for line in body.decode().splitlines():
        fields = line.split(' ')
        need(len(fields) == 2 and re.fullmatch('[A-Za-z0-9@._+-]+', fields[0]) and
             re.fullmatch('[A-Za-z0-9:._+~-]+', fields[1]) and fields[0] not in result, 'literal unique ALPM inventory rows required')
        result[fields[0]] = fields[1]
    need(len(result) == row['count'] and body == ''.join(f'{k} {v}\n' for k, v in sorted(result.items())).encode(),
         'actual complete sorted ALPM inventory count differs')
    return result


def readonly_subpath(proof, a):
    need(proof['schema'] == 1 and proof['status'] == 'ROOT_QUALIFIED_READONLY_VOLUME_SUBPATH' and
         proof['image_id'] == a['image']['id'] and proof['candidate_admission_sha256'] == a['candidate_admission']['sha256'] and
         proof['stage0_tree_sha256'] == a['stage0_tree_sha256'] and
         proof['paths'] == ['/stage0', '/work/build/stage0'] and
         all(proof[k] is True for k in ('readonly', 'namespace_permissions_verified', 'write_attempts_denied', 'alias_write_attempts_denied')),
         'actual readonly stage0 subpath and namespace permissions qualification required')


def external_proofs(a):
    llvm, image = a['llvm'], a['image']
    q = _json(a['candidate_admission'])
    original_proof = _json(a['candidate']['qualification'])
    candidate_qualification(q, original_proof, a)
    signature, decision = _json(llvm['verification_proof']), _json(llvm['root_decision'])
    archive_pin = {k: llvm['archive'][k] for k in ('bytes', 'sha256')}
    signature_pin = {k: llvm['signature'][k] for k in ('bytes', 'sha256')}
    key_pin = {k: llvm['public_test_key'][k] for k in ('bytes', 'sha256', 'fingerprint', 'trust_scope')}
    need(signature['schema'] == 1 and signature['status'] == 'ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and
         signature['verified'] is True and signature['archive'] == archive_pin and signature['signature'] == signature_pin and
         signature['public_test_key'] == key_pin and signature['trust_scope'] == 'TEST_ONLY', 'actual Root public TEST verification proof required')
    need(decision['schema'] == 1 and decision['issuer'] == 'Root' and decision['accepted'] is True and
         decision['status'] == 'ACCEPTED_PRIVATE_LLVM23_PACKAGE_TEST_ONLY' and decision['holds_preserved'] is True and
         decision['source'] == llvm['source'] and decision['artifact'] == llvm['artifact'] and decision['original'] == llvm['original'] and
         decision['archive'] == {k: llvm['archive'][k] for k in ('bytes', 'sha256', 'package', 'version', 'arch')} and
         decision['signature'] == signature_pin and decision['public_test_key'] == key_pin and
         decision['verification_proof_sha256'] == llvm['verification_proof']['sha256'], 'actual scoped Root LLVM acceptance required')
    baseline, qualified = _inventory(image['baseline_inventory']), _inventory(image['qualified_inventory'])
    need(all(qualified.get(k) == v for k, v in baseline.items()) and qualified.get(LLVM_PACKAGE) == '23.1.1-1',
         'normal image must retain baseline349 and include exact private LLVM package')
    subpath = _json(image['readonly_volume_subpath_proof'])
    readonly_subpath(subpath, a)
    proof = _json(image['qualification_proof'])
    need(proof['schema'] == 1 and proof['status'] == 'ROOT_QUALIFIED_NORMAL_ISOLATED_IMMUTABLE_IMAGE' and
         proof['normal_isolated'] is True and proof['native_runtime'] is True and proof['holds_preserved'] is True and
         proof['image_id'] == image['id'] and proof['rootfs_tree_sha256'] == image['rootfs_tree_sha256'] and
         proof['qualified_llvm_tree_sha256'] == image['qualified_llvm_tree_sha256'] and
         proof['candidate_admission_sha256'] == a['candidate_admission']['sha256'] and
         proof['stage0_tree_sha256'] == a['stage0_tree_sha256'] and proof['llvm_package_sha256'] == llvm['archive']['sha256'] and
         proof['baseline_inventory_sha256'] == BASELINE_SHA and proof['qualified_inventory_sha256'] == image['qualified_inventory']['sha256'] and
         proof['qualified_inventory_count'] == len(qualified) and
         proof['readonly_volume_subpath_sha256'] == image['readonly_volume_subpath_proof']['sha256'],
         'actual qualified normal immutable image/rootfs/private LLVM/original candidate bindings required')


def validate(a, check_files=True):
    """Return a defensive copy. Root authentication and fresh host guards are external."""
    need(type(check_files) is bool, 'explicit file-check mode required')
    keys(a, {'schema', 'status', 'holds_preserved', 'source', 'candidate', 'candidate_admission', 'materials',
             'llvm', 'image', 'image_root', 'stage0_tree_sha256', 'resources', 'claims'}, 'complete external Root admission required')
    need(type(a['schema']) is int and a['schema'] == 1 and a['status'] == 'ROOT_ADMITTED_RUST199_NATIVE_PRIVATE_BUILD' and
         a['holds_preserved'] is True and type(a['claims']) is dict and set(a['claims']) == set(CLAIMS) and
         all(value is False for value in a['claims'].values()),
         'external scoped Root admission with all holds and no acceptance claims required')
    selector(a['source'], approval=True)
    keys(a['candidate'], {'commit', 'inputs_sha256', 'qualification'}, 'frozen candidate and original qualification required')
    need(a['candidate']['commit'] == CANDIDATE and a['candidate']['inputs_sha256'] == INPUTS_SHA, 'frozen dd6871d5 source candidate differs')
    descriptor(a['candidate_admission'], fixed_path='/inputs/candidate-admission.json')
    descriptor(a['candidate']['qualification'], fixed_path='/inputs/qualification.json')
    llvm_declaration(a['llvm'])
    image = a['image']
    keys(image, {'id', 'rootfs_tree_sha256', 'qualified_llvm_tree_sha256', 'qualification_proof',
                 'baseline_inventory', 'qualified_inventory', 'readonly_volume_subpath_proof'}, 'actual normal isolated image qualification required')
    need(type(image['id']) is str and re.fullmatch('sha256:[0-9a-f]{64}', image['id']) and
         sha(image['rootfs_tree_sha256']) and sha(image['qualified_llvm_tree_sha256']) and sha(a['stage0_tree_sha256']),
         'actual immutable image/full rootfs/private LLVM/stage0 tree pins required')
    path(a['image_root'])
    for key in ('qualification_proof', 'readonly_volume_subpath_proof'):
        descriptor(image[key])
    for key in ('baseline_inventory', 'qualified_inventory'):
        descriptor(image[key], MIB, extras=('count',))
        need(type(image[key]['count']) is int, 'actual qualified inventory count required')
    need(image['baseline_inventory']['count'] == 349 and image['baseline_inventory']['sha256'] == BASELINE_SHA and
         350 <= image['qualified_inventory']['count'] <= 600, 'baseline349 is not the final private-LLVM image inventory')
    need(a['resources'] == PROPOSAL and all(type(v) is int for v in a['resources'].values()), 'fixed native resource/deadline/reserve policy required')
    material_rows(a['materials'], check_files)
    if check_files:
        # All external gates are required before any material read. This module
        # never downloads a declaration or upgrades an unqualified proof.
        external_proofs(a)
        read_file(a['llvm']['archive']['local_path'], 8*GIB, a['llvm']['archive'])
        read_file(a['llvm']['signature']['local_path'], MIB, a['llvm']['signature'])
        read_file(a['llvm']['public_test_key']['local_path'], 8*MIB, a['llvm']['public_test_key'])
        for row in a['materials']:
            read_file(row['local_path'], row['bytes'], row)
    return copy.deepcopy(a)
