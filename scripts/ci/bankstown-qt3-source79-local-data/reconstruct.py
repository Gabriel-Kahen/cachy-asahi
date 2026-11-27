#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Reconstruct exact unissued Source72/78/79 from retained, pinned local DATA."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
LOCK_PIN = dict(bytes=3401, sha256='f6a25c9081d9356922285ed45400465d69e9d7b0613a29edc0bf5762c9f0c537')
NATIVE = 'scripts/ci/bankstown-qt3-native-source/prepare.py'
HOSTED = 'scripts/ci/bankstown-qt3-hosted-v1/prepare.py'
DISPATCH = 'scripts/ci/bankstown-qt3-hosted-v1/prepare_dispatch.py'
INVENTORY = 'scripts/ci/bankstown-qt3-native-profile-v1/inventory.py'
READER = 'scripts/ci/bankstown-qt3-hosted-reader-v1/source79/reader.py'
CHECKER = 'scripts/checks/package_checks.py'
HELD_CHECKER = ('scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source/'
                'scripts/ci/llhttp-reference-native-source/base/runtime/' + CHECKER)


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve()
         and not any(p.is_symlink() for p in (path, *path.parents)), 'ORDINARY_ABSOLUTE_DATA')
    return path


def read(path, expected, mode=0o644):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == expected['bytes'] <= 64*1024**2
             and stat.S_IMODE(before.st_mode) == mode, 'EXACT_ORDINARY_INPUT_SHAPE')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            body = stream.read(expected['bytes']+1)
        fields = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity = lambda row: tuple(getattr(row, key) for key in fields)
        need(pin(body) == expected and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'STABLE_WHOLE_INPUT_PIN')
        return body
    finally:
        os.close(fd)


def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o644)


def module(repo, member, helpers):
    raw = read(repo/member, helpers[member])
    spec = importlib.util.spec_from_file_location('local_source79_'+Path(member).stem, repo/member)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(repo/member), 'exec'), value.__dict__)
    return value


def decode_catalog(path, compressed_pin, raw_pin, output):
    """Exact compressed pin plus bounded whole raw pin; no archive/payload role."""
    read(path, compressed_pin)
    digest, size = hashlib.sha256(), 0
    with gzip.open(path, 'rb') as source, output.open('xb') as target:
        while block := source.read(min(1024**2, raw_pin['bytes']+1-size)):
            size += len(block)
            need(size <= raw_pin['bytes'], 'CATALOG_DECOMPRESSION_BOUND')
            digest.update(block)
            target.write(block)
    output.chmod(0o644)
    need(dict(bytes=size, sha256=digest.hexdigest()) == raw_pin, 'WHOLE_RETAINED_CATALOG_PIN')
    read(path, compressed_pin)  # Reject compressed input replacement during replay.


def reconstruct(*, repo, output):
    repo, out = ordinary(repo), ordinary(output)
    need(repo.is_dir() and not out.exists() and out != repo
         and not out.is_relative_to(repo/'scripts') and not repo.is_relative_to(out),
         'FRESH_DISJOINT_DATA_OUTPUT')
    lock = json.loads(read(HERE/'inputs.lock.json', LOCK_PIN))
    need(all(value is None for value in lock['actual'].values()), 'UNISSUED_RETAINED_INPUTS')
    # Admit every reviewed helper before any definition is compiled.
    for member, expected in lock['helpers'].items():
        read(repo/member, expected)
    source_map_raw = read(repo/lock['source72_map']['member'],
                          {k:lock['source72_map'][k] for k in ('bytes','sha256')})
    source_map = json.loads(source_map_raw)
    need(len(source_map['files']) == 70 and all(v is None for v in source_map['actual'].values()),
         'EXACT_UNISSUED_SOURCE72_INPUT_MAP')
    out.mkdir(mode=0o700)
    materials = out/'retained-inputs'
    materials.mkdir(mode=0o700)
    cat = lock['catalog']
    catalog_path = materials/'catalog333.DATA.json'
    decode_catalog(HERE/cat['compressed']['member'],
                   {k:cat['compressed'][k] for k in ('bytes','sha256')}, cat['raw'], catalog_path)
    baseline_path = repo/lock['baseline_alias']['member']
    baseline_raw = read(baseline_path, {k:lock['baseline_alias'][k] for k in ('bytes','sha256')})
    J = module(repo, INVENTORY, lock['helpers'])
    catalog_raw = read(catalog_path, cat['raw'])
    expected = J.inventory(baseline_raw, 349)
    for name, version in J.catalog(catalog_raw).items():
        need(name not in expected or expected[name] == version, 'PROTECTED_VERSION_UNCHANGED')
        expected[name] = version
    prospective = ''.join(name+' '+version+'\n' for name,version in sorted(expected.items())).encode()
    need(pin(prospective) == {k:lock['prospective477'][k] for k in ('bytes','sha256')},
         'EXACT_DERIVED_PROSPECTIVE477_PIN')
    joins = J.check(prospective, baseline_raw, catalog_raw)
    del catalog_raw
    prospective_path = materials/'prospective477.expected.DATA.lock'
    write(prospective_path, prospective)
    aliases = {'inputs/catalog333.DATA.json':catalog_path,
               'inputs/prospective477.expected.DATA.lock':prospective_path,
               'inputs/stages/baseline349.expected.lock':baseline_path,
               CHECKER:repo/HELD_CHECKER}
    rows = {}
    for member, row in source_map['files'].items():
        path = aliases.get(member, repo/member)
        read(path, {k:row[k] for k in ('bytes','sha256')}, row['mode'])
        rows[member] = dict(path=str(path), **row)
    P = module(repo, NATIVE, lock['helpers'])
    P.prepare_source(file_rows=rows, file_rows_sha256=pin(encoded(rows))['sha256'], output=out/'source72')
    need((out/'source72/source-map.json').read_bytes() == source_map_raw,
         'EXACT_RECONSTRUCTED_SOURCE72_MAP')
    H = module(repo, HOSTED, lock['helpers'])
    H.prepare_source(source72=out/'source72', output=out/'source78', runtime_root=repo/H.PREFIX)
    D = module(repo, DISPATCH, lock['helpers'])
    result = D.prepare_source(source78=out/'source78', output=out/'source79', workflow_path=repo/D.WORKFLOW)
    need(result['source'] == lock['source79'] and D.inverse_files(D.snapshot(out/'source79'))
         == D.snapshot(out/'source78'), 'EXACT_SOURCE79_AND_FULL_INVERSE')
    R = module(repo, READER, lock['helpers'])
    readiness = R.source_readiness(out/'source79')
    need(readiness['status'] == 'PASS_SOURCE79_DATA_ONLY' and readiness['workflow_gap_closed'] is True
         and readiness['dispatch_ready'] is False, 'PASSIVE_READER_NO_DISPATCH_AUTHORITY')
    report = dict(schema=1, kind='LOCAL_PINNED_SOURCE79_RECONSTRUCTION_DATA_ONLY',
                  source=result['source'], retained_catalog=cat['raw'], prospective_inventory=pin(prospective),
                  inventory_joins=joins, same_complete_Source78_inverse=True, Reader=readiness,
                  public_Source_CID=None, Root_authority=None, actual773_custody='UNBOUND',
                  source_acceptance='HELD', legal='HELD', key_freshness='HELD',
                  exact_Qt_recipe_correspondence='HELD', native='NOT_RUN', hardware='NOT_RUN', release=False)
    write(out/'reconstruction.DATA.json', encoded(report))
    return report


def no_actors(event, args):
    need(not event.startswith(('subprocess.','socket.','ctypes.'))
         and event not in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'),
         'ACTOR_FREE_LOCAL_DATA_REPLAY')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.addaudithook(no_actors)
    report = reconstruct(repo=args.repo, output=args.output)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
