# SPDX-License-Identifier: MIT
"""Exact closed carrier, filtered metadata and complete explicit blob acquisition.

Canonical profile/material/tree/namespace and child supervision code remains exact.
No checkout, lazy acquisition, retry, omitted required DATA or timeout extension.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

PUBLIC = 'https://github.com/Gabriel-Kahen/cachy-asahi.git'
CANONICAL = 'scripts/maintenance/retained_git_transport.py'
CANONICAL_SHA256 = '9b90c423fd67c261d8be1dddd8450df5b927b6dbaba9972c4daff8c0da2836b7'


def _canonical(root):
    path = Path(root) / CANONICAL
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CANONICAL_SHA256:
        raise ValueError('exact canonical retained transport required')
    name = '_native_exact_retained_transport'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class EvidenceCarrierPaths:
    """Explicit path router: only canonical logical data/ maps to carrier.

    os.fspath and every other child resolve to the separate evidence directory.
    This creates no filesystem alias and leaves the carrier logical closure exact.
    """
    def __init__(self, evidence, carrier):
        self.evidence, self.carrier = evidence, carrier

    def __fspath__(self):
        return os.fspath(self.evidence)

    def __str__(self):
        return str(self.evidence)

    def __truediv__(self, name):
        return self.carrier if name == 'data' else self.evidence / name


def tree_objects(table):
    root = {}; identifiers = set()
    for name, row in table.items():
        node = root
        for part in name.split('/')[:-1]:
            node = node.setdefault(part, {})
        node[name.split('/')[-1]] = (row['mode'], row['oid'])
    def digest(node):
        raw = b''
        for name, value in sorted(node.items(), key=lambda item: (item[0] + ('/' if type(item[1]) is dict else '')).encode()):
            mode, oid = ('40000', digest(value)) if type(value) is dict else value
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
        oid = hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        identifiers.add(oid)
        return oid
    return digest(root), identifiers


def deliver(root, carrier, evidence, profile_raw, profile_sha256, *, fixture_local=False,
            url=PUBLIC, policy=None):
    """Two nonretry roles share400s;480s bounds all acquisition and materialization."""
    started = time.monotonic(); root = Path(root).absolute()
    C = _canonical(root)
    policy = dict(C.reference_policy() if policy is None else policy)
    C.policy_check(policy)
    if not fixture_local:
        C.need(url == PUBLIC and policy == C.reference_policy(), 'fixed public transport authority and original clocks required')
    profile_json = json.loads(profile_raw)
    profile = C.profile_check(profile_raw, profile_sha256, profile_json.get('source'))
    C.source_url(url, fixture_local)
    carrier, evidence = C.absolute(carrier), C.absolute(evidence)
    for target in (carrier, evidence):
        C.need(not target.is_relative_to(root) and not root.is_relative_to(target), 'DATA disjoint from executable Source')
    C.need(not carrier.is_relative_to(evidence) and not evidence.is_relative_to(carrier), 'carrier and evidence must be disjoint')
    C.need(not os.path.lexists(carrier) and not os.path.lexists(evidence), 'fresh carrier and evidence required; no overwrite')
    for target in (evidence, carrier):
        parent = C.directory(target.parent)
        try:
            info = os.fstat(parent)
            C.need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned private DATA parent required')
            os.mkdir(target.name, 0o700, dir_fd=parent)
        finally:
            os.close(parent)
    paths = EvidenceCarrierPaths(evidence, carrier)
    class Delivery(C.Delivery):
        phase = 'setup'
        def command(self, argv, **kwargs):
            before = len(self.rows)
            try:
                return super().command(argv, **kwargs)
            finally:
                if len(self.rows) == before + 1:
                    row = self.rows[-1]
                    row['phase'] = self.phase
                    row['role'] = 'NETWORK' if self.phase in ('metadata_fetch', 'required_blobs_fetch') else 'LOCAL_PROOF_OR_MATERIALIZATION'
                    row['evidence_root'] = str(evidence)
                    row['data_root'] = str(carrier)
    delivery = Delivery(paths, started + policy['transport_seconds'], policy)
    acquisition_deadline = started + policy['fetch_seconds']
    report = dict(schema_version=1, status='FAIL_RETAINED_GIT_DATA', source=profile['source'],
        url=url, fixture=fixture_local, profile_sha256=profile_sha256, policy=policy,
        file_count=len(profile['files']), material_bytes=sum(v['bytes'] for v in profile['files'].values()),
        destination=str(evidence), data_path=str(carrier), retry=False, partial_data_retained=True,
        source_code_execution='NOT_RUN', signature_authentication='NOT_RUN', native_build='NOT_RUN',
        trust_admission=False, release_acceptance=False, acquisition_roles=[], commands=[],
        fetch_seconds_shared=True, unselected_blobs='REFUSED', history='REFUSED', lazy_fetch='DISABLED')
    try:
        for name in ('logs', 'empty-home'):
            os.mkdir(name, 0o700, dir_fd=delivery.fd)
        delivery.write('expected-profile.json', profile_raw)
        git = [C.GIT, '--no-replace-objects', '-c', 'credential.helper=', '-c', 'http.extraHeader=',
            '-c', 'http.sslVerify=true', '-c', 'http.followRedirects=false', '-c', 'http.proxy=',
            '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null', '-c', 'core.fsmonitor=false',
            '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', '-c', 'fetch.writeCommitGraph=false',
            '-c', 'protocol.allow=never', '-c', 'protocol.' + ('file' if fixture_local else 'https') + '.allow=always']
        git_dir = carrier / '.git'
        delivery.command([*git, 'init', '--bare', '--object-format=sha1', '--template=', str(git_dir)], seconds=10)
        git += ['--git-dir=' + str(git_dir)]
        local_git = [*git, '-c', 'protocol.file.allow=never', '-c', 'protocol.https.allow=never']
        def acquire(phase, wants, *, metadata=False):
            C.need(phase not in report['acquisition_roles'], 'acquisition role cannot repeat')
            delivery.tick(); remaining = acquisition_deadline - time.monotonic()
            C.need(remaining > .02, 'shared400 acquisition budget exhausted')
            delivery.phase = phase
            report['acquisition_roles'].append(phase)
            command = [*git, '-c', 'http.lowSpeedLimit=65536', '-c', 'http.lowSpeedTime=60',
                '-c', 'fetch.fsckObjects=true', 'fetch', '--progress', '--no-tags', '--no-recurse-submodules',
                '--no-auto-maintenance', '--filter=blob:none']
            command += ['--depth=1'] if metadata else ['--no-write-fetch-head']
            delivery.command([*command, url, *wants], seconds=remaining)
            C.need(time.monotonic() < acquisition_deadline, 'shared400 acquisition budget exhausted')
        acquire('metadata_fetch', [profile['source']], metadata=True)
        delivery.phase = 'metadata_proof'
        fetched = delivery.command([*local_git, 'rev-parse', '--verify', 'FETCH_HEAD']).strip()
        C.need(fetched == profile['source'].encode(), 'exact metadata source required')
        commit = delivery.command([*local_git, 'cat-file', 'commit', profile['source']], stdout_limit=65536)
        C.need(hashlib.sha1(b'commit ' + str(len(commit)).encode() + b'\0' + commit).hexdigest() == profile['source'], 'exact raw commit required')
        first = commit.split(b'\n', 1)[0]
        C.need(first.startswith(b'tree ') and C.SHA1.fullmatch(first[5:].decode('ascii')), 'exact commit tree required')
        tree = first[5:].decode('ascii')
        raw_tree = delivery.command([*local_git, 'ls-tree', '-rz', '--full-tree', profile['source']])
        table = {}
        for raw in raw_tree.split(b'\0'):
            if not raw: continue
            header, name = raw.split(b'\t', 1); mode, kind, oid = header.decode('ascii').split(); name = name.decode('ascii')
            C.relative(name)
            C.need(kind == 'blob' and mode in ('100644', '100755') and C.SHA1.fullmatch(oid)
                and name in profile['files'] and name not in table, 'whole exact Git membership required')
            table[name] = dict(mode=mode, oid=oid)
        reconstructed, tree_ids = tree_objects(table)
        C.need(set(table) == set(profile['files']) and reconstructed == tree and C.tree_oid(table) == tree,
            'complete original profile/tree closure required')
        expected_metadata = {profile['source']: 'commit', **{oid: 'tree' for oid in tree_ids}}
        def inventory():
            raw = delivery.command([*local_git, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)'])
            result = {}
            for line in raw.splitlines():
                # Git's fixed warning shares the bounded diagnostic channel.
                # Every actual object still has to match the complete allowed set.
                if line == b'warning: This repository uses promisor remotes. Some objects may not be loaded.':
                    continue
                parts = line.decode('ascii').split()
                C.need(len(parts) == 2, 'bounded object inventory framing required')
                oid, kind = parts
                C.need(C.SHA1.fullmatch(oid) and kind in ('blob', 'tree', 'commit') and oid not in result, 'unique ordinary object inventory required')
                result[oid] = kind
            return result
        C.need(inventory() == expected_metadata, 'metadata role fetched blobs/history/unselected objects; filter not accepted')
        report['metadata_object_inventory'] = expected_metadata
        required = sorted({row['oid'] for row in table.values()})
        report['required_blob_oids'] = required
        acquire('required_blobs_fetch', required)
        delivery.phase = 'complete_object_proof'
        all_objects = dict(expected_metadata, **{oid: 'blob' for oid in required})
        C.need(inventory() == all_objects, 'required object set incomplete or unselected/history object present')
        report['object_inventory'] = all_objects
        directories = sorted({p.as_posix() for name in table for p in C.relative(name).parents if p != C.PurePosixPath('.')}, key=lambda value:(value.count('/'),value))
        for name in directories:
            delivery.tick(); target = carrier / name; parent = C.directory(target.parent)
            try: os.mkdir(target.name, 0o700, dir_fd=parent)
            finally: os.close(parent)
        delivery.phase = 'all_required_materialization'
        for name, row in sorted(table.items()):
            want = profile['files'][name]
            delivery.command([*local_git, 'cat-file', 'blob', row['oid']], stdout_limit=want['bytes'],
                material=(want, row['oid'], 0o755 if row['mode'] == '100755' else 0o644, name))
        delivery.phase = 'final_namespace_proof'
        delivery.command([*local_git, 'update-ref', '--no-deref', 'HEAD', profile['source']])
        head = delivery.command([*local_git, 'rev-parse', '--verify', 'HEAD']).strip()
        C.need(head == profile['source'].encode(), 'full carrier HEAD differs')
        C.namespace(delivery, profile['files'], table); delivery.tick()
        report.update(status='PASS_EXACT_RETAINED_GIT_DATA_ONLY', tree=tree, blob_joins=len(table), full_namespace=True,
            materialized_files=len(table), acquisition_completed_within_shared400=True)
        return report
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:2048]
        report['failed_phase'] = delivery.phase
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started
        report['commands'] = delivery.rows
        try: delivery.receipt(report)
        finally: os.close(delivery.fd)
