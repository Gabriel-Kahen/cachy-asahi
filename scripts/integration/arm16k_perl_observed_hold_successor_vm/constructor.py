#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Compose an unissued observed-HOLD Perl Source with a whole310 efficient inverse."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import types

HERE = Path(__file__).resolve().parent
CAP = 4 * 1024**2
PREFIX = '_observed_hold/'
ACTUAL = ('Source_CID', 'source_ref', 'Root_authority', 'runtime', 'nonce', 'VM', 'ALPM', 'M2', 'release')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and raw == canonical(value), 'canonical JSON object')
    return value


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute unaliased DATA path')
    return path


def read(path):
    path = ordinary(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        first = os.fstat(stream.fileno())
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size <= CAP,
             'bounded ordinary single-link source leaf')
        raw = stream.read(CAP + 1)
        last = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(first) == identity(last) == identity(path.lstat()) and len(raw) == first.st_size <= CAP,
         'source changed during read')
    mode = stat.S_IMODE(first.st_mode)
    need(mode in (0o644, 0o755), 'Git-representable ordinary source mode')
    return raw, mode


def rows(files):
    return {name: dict(**pin(body), mode=mode) for name, (body, mode) in sorted(files.items())}


def snapshot(root):
    root = ordinary(root)
    need(root.is_dir(), 'explicit source directory')
    files = {}; directories = set(); size = 0
    for current, dirs, leaves in os.walk(root, followlinks=False):
        for name in dirs:
            child = ordinary(Path(current) / name)
            directories.add(child.relative_to(root).as_posix())
        for name in leaves:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            need(len(files) < 512, 'finite source leaf count')
            files[relative] = read(path)
            size += len(files[relative][0])
            need(size <= CAP, 'unchanged four-MiB fixture Source cap')
    expected_dirs = {p.as_posix() for name in files for p in PurePosixPath(name).parents if str(p) != '.'}
    need(directories == expected_dirs, 'exact namespace without empty/extra directories')
    return files


def closed(files, expected):
    need('source.lock.json' in files and files['source.lock.json'][1] == 0o644,
         'ordinary Source lock')
    raw = files['source.lock.json'][0]
    need(pin(raw) == expected, 'whole externally pinned Source lock')
    lock = decode(raw)
    need(type(lock.get('actual')) is dict and all(value is None for value in lock['actual'].values()),
         'unissued Source only; no inherited actual authority')
    need(lock['files'] == rows({name: row for name, row in files.items() if name != 'source.lock.json'}),
         'whole Source membership, bytes and modes')
    return lock


def family(files, expected):
    need(rows(files) == expected['files'] and pin(canonical(expected['files'])) == expected['map'],
         'complete immutable proposal family, bytes and modes')


def own(expected):
    files = snapshot(HERE)
    closed(files, expected)
    return files, decode(files['inputs.json'][0])


def module(raw, filename, name):
    # Only complete previously authenticated immutable proposal bytes execute.
    value = types.ModuleType(name)
    value.__file__ = str(filename)
    exec(compile(raw, str(filename), 'exec'), value.__dict__)
    return value


def project(predecessor, guard, qmp, constructor, qmp_root):
    inputs = decode(constructor['inputs.json'][0])
    old_lock = closed(predecessor, inputs['predecessor']['source_lock'])
    need(len(predecessor) == inputs['predecessor']['files'] == 310 and
         sum(len(body) for body, _ in predecessor.values()) == inputs['predecessor']['closed_leaf_bytes'] == 3239759,
         'complete frozen Source310 tuple')
    need(inputs['fixture_source_cap_bytes'] == CAP and
         all(value is None for value in inputs['actual'].values()), 'unchanged cap and unissued inputs')
    family(guard, inputs['proposals']['guard'])
    family(qmp, inputs['proposals']['qmp'])
    guards = module(guard['proposal.py'][0], Path('/immutable-proposal/guard.py'), 'exact_guard_proposal')
    guard_names = ('guest/root.sh', 'guest/initialized-state.sh')
    original_guard = {name: predecessor[name][0] for name in guard_names}
    generated_guard, mapping = guards.transform(original_guard)
    need(set(generated_guard) == set(guard_names) and
         all(generated_guard[name] == guard[name][0] for name in guard_names), 'whole two-leaf committed guard derivative')
    need(guards.inverse(original_guard, generated_guard, mapping) == original_guard,
         'complete guest predicate/status byte inverse')
    diagnostic = module(qmp['proposal.py'][0], qmp_root / 'proposal.py', 'exact_qmp_proposal')
    generated_qmp = diagnostic.transform(predecessor['controller.py'][0], predecessor['hold_cleanup.py'][0])
    qmp_names = {'controller.py', 'hold_cleanup.py', 'qmp_observations.py'}
    need(set(generated_qmp) == qmp_names and
         generated_qmp['hold_cleanup.py'] == qmp['generated-hold_cleanup.py'][0] and
         generated_qmp['qmp_observations.py'] == qmp['observations.py'][0], 'whole three-leaf committed QMP derivative')
    need(diagnostic.inverse(predecessor['controller.py'][0], predecessor['hold_cleanup.py'][0], generated_qmp) ==
         (predecessor['controller.py'][0], predecessor['hold_cleanup.py'][0]), 'whole QMP byte inverse')
    result = {name: row for name, row in predecessor.items() if name != 'source.lock.json'}
    generated = dict(generated_guard, **generated_qmp)
    changes = {}
    for name, body in generated.items():
        mode = predecessor[name][1] if name in predecessor else 0o644
        result[name] = body, mode
        changes[name] = dict(before=rows({name: predecessor[name]})[name] if name in predecessor else None,
                             after=rows({name: result[name]})[name])
    need(set(changes) == set(guard_names) | qmp_names, 'only five declared operational leaves')
    need(not any(name.startswith(PREFIX) for name in predecessor), 'new versioned successor namespace')
    # Keep the old whole lock and only four overwritten preimages. All other310
    # predecessor bytes/modes are reused in place, including earlier145 inverses.
    result[PREFIX + 'inverse/source.lock.json'] = predecessor['source.lock.json']
    for name in changes:
        if name in predecessor:
            result[PREFIX + 'inverse/leaves/' + name] = predecessor[name]
    for prefix, source in (('proposals/guard/', guard), ('proposals/qmp/', qmp), ('constructor/', constructor)):
        for name, row in source.items():
            need(PREFIX + prefix + name not in result, 'new successor namespace only')
            result[PREFIX + prefix + name] = row
    manifest_name = PREFIX + 'construction.DATA.json'
    added = sorted((set(result) - set(predecessor)) | {manifest_name})
    manifest = dict(kind='UNISSUED_OBSERVED_HOLD_PERL_LIFECYCLE_SUCCESSOR_V1',
                    predecessor=inputs['predecessor'], proposals=inputs['proposals'],
                    constructor=pin(constructor['source.lock.json'][0]), changes=changes,
                    inverse='WHOLE310_REUSE_UNCHANGED_PLUS_FOUR_PREIMAGES_OLD_LOCK_AND_ADDED_MEMBERSHIP',
                    added_membership=added, fixture_source_cap_bytes=CAP, actual=dict.fromkeys(ACTUAL))
    result[manifest_name] = canonical(manifest), 0o644
    lock = dict(old_lock, files=rows(result), actual=dict.fromkeys(old_lock['actual']))
    result['source.lock.json'] = canonical(lock), 0o644
    need(sum(len(body) for body, _ in result.values()) <= CAP, 'successor fits unchanged four-MiB Source cap')
    return result


def inverse(files, expected_predecessor):
    manifest = decode(files[PREFIX + 'construction.DATA.json'][0])
    added = manifest['added_membership']
    need(type(added) is list and added == sorted(set(added)) and all(name in files for name in added),
         'complete unique added-membership inverse')
    predecessor = {name: row for name, row in files.items() if name not in added}
    predecessor['source.lock.json'] = files[PREFIX + 'inverse/source.lock.json']
    for name, change in manifest['changes'].items():
        if change['before'] is not None:
            original = files[PREFIX + 'inverse/leaves/' + name]
            need(rows({name: original})[name] == change['before'], 'exact original changed preimage')
            predecessor[name] = original
        else:
            need(name not in predecessor, 'added operational leaf removed by membership inverse')
    closed(predecessor, expected_predecessor['source_lock'])
    need(len(predecessor) == expected_predecessor['files'] == 310 and
         sum(len(body) for body, _ in predecessor.values()) == expected_predecessor['closed_leaf_bytes'] == 3239759,
         'complete310 byte/mode/old-lock inverse')
    return predecessor


def verify_export(root, expected, constructor_expected):
    constructor, inputs = own(constructor_expected)
    files = snapshot(root)
    closed(files, expected)
    def subtree(prefix):
        return {name[len(prefix):]: row for name, row in files.items() if name.startswith(prefix)}
    predecessor = inverse(files, inputs['predecessor'])
    guard = subtree(PREFIX + 'proposals/guard/')
    qmp = subtree(PREFIX + 'proposals/qmp/')
    need(subtree(PREFIX + 'constructor/') == constructor, 'whole original constructor provenance')
    replay = project(predecessor, guard, qmp, constructor, ordinary(root) / PREFIX / 'proposals/qmp')
    need(files == replay, 'whole deterministic physical successor and complete310 byte/mode inverse')
    compiled = 0
    for name, (body, _) in files.items():
        if name.endswith('.py'):
            compile(body, name, 'exec'); compiled += 1
    return dict(status='PASS_PHYSICAL_SOURCE_AND_WHOLE310_EFFICIENT_INVERSE_ONLY',
                source_lock=expected, files=len(files), closed_leaf_bytes=sum(len(body) for body, _ in files.values()),
                fixture_source_cap_bytes=CAP, compiled_python_files=compiled,
                changed_execution_leaves=sorted(decode(files[PREFIX + 'construction.DATA.json'][0])['changes']),
                retained_preimage_leaves=4, actual=dict.fromkeys(ACTUAL))


def construct(predecessor_root, guard_root, qmp_root, output, constructor_expected):
    constructor, inputs = own(constructor_expected)
    roots = [ordinary(path) for path in (predecessor_root, guard_root, qmp_root)]
    output = ordinary(output)
    need(not output.exists() and output.parent.is_dir() and output.parent.stat().st_uid == os.getuid()
         and not output.parent.stat().st_mode & 0o022, 'fresh output in private owned parent')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
             for root in (*roots, HERE)), 'output disjoint from immutable source inputs')
    snapshots = [snapshot(root) for root in roots]
    result = project(*snapshots, constructor, roots[2])
    need(all(snapshot(root) == previous for root, previous in zip(roots, snapshots)) and
         snapshot(HERE) == constructor, 'all immutable inputs stable through projection')
    output.mkdir(mode=0o700)
    for name, (body, mode) in sorted(result.items()):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(body)
        path.chmod(mode)
    return verify_export(output, pin(result['source.lock.json'][0]), constructor_expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--constructor-lock-sha256', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('construct')
    for name in ('predecessor', 'guard', 'qmp', 'output'):
        create.add_argument('--' + name, type=Path, required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('--source', type=Path, required=True)
    verify.add_argument('--source-lock-sha256', required=True)
    args = parser.parse_args()
    try:
        own_raw = read(HERE / 'source.lock.json')[0]
        expected = dict(bytes=len(own_raw), sha256=args.constructor_lock_sha256)
        if args.command == 'construct':
            value = construct(args.predecessor, args.guard, args.qmp, args.output, expected)
        else:
            raw = read(args.source / 'source.lock.json')[0]
            value = verify_export(args.source, dict(bytes=len(raw), sha256=args.source_lock_sha256), expected)
        print(json.dumps(value, sort_keys=True, indent=2))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f'successor DATA refusal: {error}\n')


if __name__ == '__main__':
    main()
