#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Adopt only pinned, existing public DATA; no acquisition, actors or authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

HERE = Path(__file__).resolve().parent
LOCK_PIN = dict(bytes=1822, sha256='de3d4a61f7f0672c8fd5b382f03c72569a5b0b268de8af829fd785c9d5fe46ad')
READER = 'scripts/ci/bankstown-qt3-hosted-reader-v1/source79/reader.py'
AUDIO = 'scripts/ci/bankstown-qt3-native-source/inputs.py'
GROUPS = {'base_materials':498, 'supplemental_materials':16, 'keyring_materials':3, 'candidate_materials':256}
PRIVATE = {'.gnupg', '.ssh', '.aws', '.config'}
ATTRS = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')


def need(value, why):
    if not value:
        raise ValueError(why)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_JSON'))


def ordinary(value):
    need(type(value) is str and 0 < len(value) <= 4096
         and all(32 <= ord(c) != 127 for c in value), 'ORDINARY_DATA_PATH')
    path = Path(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts
         and not PRIVATE.intersection(path.parts)
         and not any(p.is_symlink() for p in (path, *path.parents)), 'PUBLIC_UNALIASED_DATA_PATH')
    return path


def descriptor(row, cap=1024**3):
    need(type(row) is dict and set(row) == {'path','bytes','sha256'}
         and type(row['bytes']) is int and 0 <= row['bytes'] <= cap
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
         'EXPLICIT_WHOLE_REQUIRED_PIN')
    ordinary(row['path'])
    return row


def identity(row):
    return tuple(getattr(row, key) for key in ATTRS)


def shape(row):
    path = ordinary(row['path'])
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and not info.st_mode & 0o022 and info.st_size == row['bytes'], 'ORDINARY_SINGLE_LINK_EXACT_SIZE')
    return info


def stream(row, observed, *, target=None, sink=None, collect=False, cap=1024**3):
    """One bounded stable whole stream, optionally copying to a fresh DATA leaf."""
    descriptor(row, cap)
    path = ordinary(row['path'])
    before = shape(row)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    output = None
    try:
        need(identity(before) == identity(os.fstat(fd)), 'INPUT_OPEN_RACE')
        inode = before.st_dev, before.st_ino
        need(all((v[0],v[1]) != inode or name == str(path) for name,v in observed.items()), 'NO_INPUT_INODE_ALIAS')
        if target is not None:
            target = ordinary(str(target))
            need(sink is not None, 'ANCHORED_OUTPUT_DOMAIN_REQUIRED')
            output = os.fdopen(sink.create(target), 'wb')
        digest, size, parts, tail = hashlib.sha256(), 0, [], b''
        while block := os.read(fd, min(1024**2, row['bytes']+1-size)):
            size += len(block)
            need(size <= row['bytes'], 'INPUT_STREAM_CAP')
            need(not re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----', tail+block), 'PRIVATE_KEY_REFUSED')
            tail = block[-128:]
            digest.update(block)
            if output:
                output.write(block)
            if collect:
                parts.append(block)
        need(dict(bytes=size,sha256=digest.hexdigest()) == {k:row[k] for k in ('bytes','sha256')}
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'STABLE_WHOLE_REQUIRED_PIN')
        observed[str(path)] = identity(before)
    finally:
        try:
            if output:
                try:
                    output.flush()
                    copied_info = os.fstat(output.fileno())
                finally:
                    output.close()
        finally:
            os.close(fd)
    if target is not None:
        sink.finish(target, copied_info)
    return b''.join(parts) if collect else None


def unchanged(observed):
    need(all(identity(ordinary(path).lstat()) == value for path,value in observed.items()), 'INPUT_CHANGED_AFTER_STREAM')


def read(path, expected, observed):
    return stream(dict(path=str(path), **expected), observed, collect=True, cap=64*1024**2)


def module(repo, member, expected, observed):
    path = repo/member
    raw = read(path, expected, observed)
    value = types.ModuleType('source79_adoption_'+path.stem)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


class CopyDomain:
    """Keep all creations anchored to retained, owner0700 directory fds."""
    def __init__(self, root):
        self.root, self.dirs, self.files = root, {}, {}
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent)
            fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            self.dirs[root] = (fd, os.fstat(fd))
        finally:
            os.close(parent)
        try:
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        keys = ('st_dev','st_ino','st_mode','st_uid','st_gid')
        stable = lambda row:tuple(getattr(row,k) for k in keys)
        for path,(fd,before) in self.dirs.items():
            need(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700
                 and stable(before) == stable(os.fstat(fd)) == stable(ordinary(str(path)).lstat()),
                 'STABLE_OWNED0700_OUTPUT_DIRECTORY')
            expected = {p.name for p in (*self.files,*self.dirs) if p.parent == path}
            scan = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                with os.scandir(scan) as entries:
                    found = set()
                    for entry in entries:
                        need(len(found) < 1024, 'OUTPUT_NAMESPACE_CAP')
                        found.add(entry.name)
            finally:
                os.close(scan)
            need(found == expected, 'EXACT_CREATED_OUTPUT_NAMESPACE')
        for path,before in self.files.items():
            need(identity(path.lstat()) == before, 'CREATED_OUTPUT_CHANGED')

    def mkdir(self, path):
        self.check()
        parent = self.dirs[path.parent][0]
        os.mkdir(path.name, 0o700, dir_fd=parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        self.dirs[path] = (fd, os.fstat(fd))
        self.check()

    def create(self, path):
        self.check()
        return os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=self.dirs[path.parent][0])

    def finish(self, path, opened):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and identity(info) == identity(opened),
             'CREATED_OWNER0600_DATA_LEAF')
        self.files[path] = identity(info)
        self.check()

    def close(self):
        for fd,_ in self.dirs.values():
            os.close(fd)


def write(path, value, sink):
    raw = encoded(value)
    with os.fdopen(sink.create(path), 'wb') as target:
        target.write(raw)
        target.flush()
        opened = os.fstat(target.fileno())
    sink.finish(path, opened)
    return dict(path=str(path), **pin(raw))


def select_groups(base, candidates, plan, selected):
    need(type(base) is dict and set(base) == {'base_lock','bootstrap_profile','baseline_inventory',
         'base_materials','supplemental_materials','keyring_materials'}, 'CLOSED_BASE517_MANIFEST')
    additions = set(selected)-set(plan['packages'])
    need(len(additions) == 128, 'EXACT128_ADDITIONS')
    wanted = dict(plan['groups'])
    wanted['candidate_materials'] = {selected[name]['filename']+suffix: selected[name]['signature' if suffix else 'archive']
        for name in additions for suffix in ('','.sig')}
    groups = {key:base[key] for key in GROUPS if key != 'candidate_materials'}
    groups['candidate_materials'] = candidates
    paths = []
    for key, refs in groups.items():
        need(type(refs) is dict and len(refs) == GROUPS[key] and set(refs) == set(wanted[key]), 'EXACT_REQUIRED_ROLE_SET')
        for name, ref in refs.items():
            descriptor(ref)
            need({k:ref[k] for k in ('bytes','sha256')} == wanted[key][name], 'ROLE_REQUIRED_ARCHIVE_PIN')
            paths.append(ref['path'])
    need(len(paths) == len(set(paths)) == 773, 'DISTINCT773_REQUIRED_PATHS')
    return groups


def missing_roles(groups):
    missing, inodes = [], set()
    for group, refs in groups.items():
        for name, row in sorted(refs.items()):
            try:
                info = shape(row)
            except FileNotFoundError:
                missing.append(dict(group=group, name=name, **row))
                continue
            need((info.st_dev,info.st_ino) not in inodes, 'NO_MATERIAL_INODE_ALIAS')
            inodes.add((info.st_dev,info.st_ino))
    return missing


def request_handoff(out, lock, observed, sink):
    """Concrete transport proposal with all Root authority still NULL."""
    templates = {name:decode(read(HERE/name, expected, observed))
                 for name,expected in lock['templates'].items()}
    delegation = templates['Root-delegation.UNISSUED.template.json']
    request = templates['Root-request.UNISSUED.template.json']
    need(delegation['issuer'] is None and delegation['approved'] is None
         and delegation['inputs_pin'] is None and delegation['nonce'] is None
         and delegation['binding']['source'] == lock['publication']['source']
         and delegation['binding']['ref'] == lock['publication']['ref']
         and len(delegation['materials']) == 77
         and request['issuer'] is None and request['approved'] is None,
         'UNISSUED_SOURCE79_REQUEST_TEMPLATES')
    delegation_ref = write(out/'Root-delegation.UNISSUED.DATA.json', delegation, sink)
    request.update(delegation_json=encoded(delegation).decode(),
                   delegation_pin={k:delegation_ref[k] for k in ('bytes','sha256')},
                   staged_root=str(out))
    # No fake hosted envelope: final trust is required before assembler issuance.
    request_ref = write(out/'Root-request.UNISSUED.DATA.json', request, sink)
    return dict(delegation=delegation_ref, request=request_ref,
        outstanding=['Root-selected current official public trust and admission',
            'Reassemble all779 references and bind final owner inputs pin',
            'Root-retained UID0 owner0700 exact read-only mount and retirement custody',
            'Root-selected trusted Main, host/resources/lease, nonce and validity interval',
            'Actual ARM run/job/attempt context and separate trial/profile selections'],
        staged_inputs=None, Root_authority=None, dispatch_ready=False)


def adopt(*, repo, source_root, provider_source_root, base_manifest, candidate_manifest, publication_receipt, output):
    observed = {}
    repo, source, provider_source, out = map(lambda p:ordinary(str(p)), (repo,source_root,provider_source_root,output))
    need(not out.exists() and out.parent.is_dir() and not any(
        out == p or out.is_relative_to(p) or p.is_relative_to(out)
        for p in (source,provider_source,repo/'scripts')), 'FRESH_DISJOINT_ADOPTION_OUTPUT')
    lock = decode(read(HERE/'inputs.lock.json', LOCK_PIN, observed))
    publication = decode(read(publication_receipt, lock['pins']['publication_receipt'], observed))
    need(all(publication.get(k) == v for k,v in lock['publication'].items())
         and publication.get('issuer') == 'Root' and publication.get('public_clone_complete') is True
         and publication.get('public_blob_tree_join') is True
         and publication.get('status') == 'PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY', 'EXACT_ACTUAL_SOURCE79_PUBLICATION')
    R = module(repo, READER, lock['helpers'][READER], observed)
    readiness = R.source_readiness(source)
    need(readiness['status'] == 'PASS_SOURCE79_DATA_ONLY' and readiness['dispatch_ready'] is False, 'PASSIVE_SOURCE79_ONLY')
    A = module(repo, AUDIO, lock['helpers'][AUDIO], observed)
    P = A.held(source, 'base_inputs_current_v3.py')
    base = decode(read(base_manifest, lock['pins']['base_manifest'], observed))
    candidates = decode(read(candidate_manifest, lock['pins']['candidate_manifest'], observed))
    provider_map = dict(path=str(provider_source/'source-map.json'), **lock['pins']['provider_source_map'])
    plan = P.metadata(source_root=provider_source, source_map=provider_map,
                      base_lock=base['base_lock'], bootstrap_profile=base['bootstrap_profile'])
    need(base['baseline_inventory'] == plan['baseline_inventory'], 'EXACT_BASELINE_MANIFEST_REFERENCE')
    groups = select_groups(base, candidates, plan, A.selected_packages(source, P))
    total = sum(row['bytes'] for refs in groups.values() for row in refs.values())
    need(total == lock['required_material_bytes'], 'EXACT773_REQUIRED_BYTES')
    missing = missing_roles(groups)
    report = dict(schema=1, kind='SOURCE79_LOCAL_RECIPIENT_ADOPTION_DATA_ONLY', publication=lock['publication'],
        Root_publication_receipt=dict(path=str(publication_receipt), **lock['pins']['publication_receipt']),
        required_files=773, required_bytes=total, missing_files=len(missing), missing_bytes=sum(r['bytes'] for r in missing),
        missing_roles=missing, Root_authority=None, official_trust=None, Root_material_custody=None,
        Root_delegation=None, dispatch_ready=False, native='NOT_RUN', hardware='NOT_RUN', release=False,
        legal='HELD', source_acceptance='HELD', key_freshness='HELD', original_Qt_minus2='UNCHANGED',
        exact_Qt_PKGBUILD_sha256='0bd04f4db92ed8b0992e851a4ddd68f39ac7b6b079af4e354dba466946ca2272')
    sink = CopyDomain(out)
    try:
        if missing:
            report.update(status='HOLD_MISSING_LOCAL_MATERIALS', material_copied_files=0, material_copied_bytes=0,
                          material_verification='NOT_RUN_MISSING_INPUTS', complete773_join=False)
            unchanged(observed)
            write(out/'adoption.DATA.json', report, sink)
            return report
        # All material roles are pinned before any archive body is opened or copied.
        need(not any(Path(row['path']).is_relative_to(out) for refs in groups.values() for row in refs.values()), 'DISJOINT_MATERIAL_OUTPUT')
        adopted = {}
        for group, refs in groups.items():
            directory = out/group
            sink.mkdir(directory)
            adopted[group] = {}
            for name, row in sorted(refs.items()):
                P.filename(name)
                target = directory/name
                stream(row, observed, target=target, sink=sink)
                adopted[group][name] = dict(row, path=str(target))
        metadata = out/'metadata'
        sink.mkdir(metadata)
        fixed = {}
        for key in ('base_lock','bootstrap_profile'):
            target = metadata/(key+'.json')
            stream(base[key], observed, target=target, sink=sink, cap=1024**2)
            fixed[key] = dict(base[key], path=str(target))
        refs = {name:row for key in ('base_materials','supplemental_materials','keyring_materials') for name,row in adopted[key].items()}
        complete517 = P.build_selected_references(materials=refs, source_root=provider_source,
            source_map=provider_map, **fixed)
        request = dict(P.assembler_fields(complete517),
            baseline_inventory=dict(path=str(source/'inputs/stages/baseline349.expected.lock'), **P.INVENTORY_PIN),
            candidate_materials=adopted['candidate_materials'],
            catalog=dict(path=str(source/'inputs/catalog333.DATA.json'), bytes=27829517,
                         sha256='aa612232f6bf711b9d1137ec8e10c8aaca99d026f26fce2b1954f64c9973b673'), official_trust=None)
        mapping = decode(read(source/'source-map.json', R.SOURCE79['source_map'], observed))
        joined = A.plan_inputs(source_root=source, source_rows=mapping['files'], request=request, verify_archives=True)
        need(joined['verified_archives'] is True and len(joined['base_rows']) == 257
             and len(joined['additions']) == 128 and len(joined['expected']) == 477, 'REAL_COMPLETE773_JOIN')
        unchanged(observed)
        R.source_readiness(source)
        report.update(status='COMPLETE773_LOCAL_ADOPTION_DATA_ONLY', material_copied_files=773, material_copied_bytes=total,
            metadata_copied_files=2, metadata_copied_bytes=sum(row['bytes'] for row in fixed.values()),
            complete773_join=True, local_material_custody='FRESH_OWNER0700_DATA_COPY_WHOLE_VERIFIED',
            owner_inputs=write(out/'owner-inputs.UNISSUED.DATA.json', request, sink),
            owner_inputs_pin=pin(encoded(request)), base517=write(out/'complete517.DATA.json', complete517, sink),
            prospective_inventory_pin=joined['prospective_inventory_pin'],
            Root_request_handoff=request_handoff(out, lock, observed, sink),
            trust_note='official_trust is NULL; this owner request cannot pass hosted admission')
        unchanged(observed)
        write(out/'adoption.DATA.json', report, sink)
        return report
    finally:
        sink.close()


def no_actors(event, args):
    need(not event.startswith(('subprocess.','socket.','ctypes.'))
         and event not in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'), 'ACTOR_FREE_DATA_ADOPTION')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('repo','source-root','provider-source-root','base-manifest','candidate-manifest','publication-receipt','output'):
        parser.add_argument('--'+key, type=Path, required=True)
    args = parser.parse_args()
    sys.addaudithook(no_actors)
    result = adopt(**vars(args))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
