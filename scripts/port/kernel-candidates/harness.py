#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate pinned data and apply one patch to NEW private source slices only."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[3]
PIN = re.compile(r'[0-9a-f]{64}')
LIMIT = 2 * 1024**3
GUARDS = ('CONFIG_ARM64=y', 'CONFIG_ARCH_APPLE=y', 'CONFIG_ARM64_16K_PAGES=y',
          '# CONFIG_ARM64_4K_PAGES is not set', '# CONFIG_ARM64_64K_PAGES is not set',
          'CONFIG_DRM_ASAHI=y', 'CONFIG_APPLE_DART=y', 'CONFIG_IOMMU_DEFAULT_DMA_STRICT=y',
          'CONFIG_SND_SOC_APPLE_MCA=m', 'CONFIG_SND_SOC_APPLE_MACAUDIO=m',
          'CONFIG_SND_SOC_APPLE_AOP_AUDIO=m', 'CONFIG_RUST=y')


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return stream_digest(stream)


def stream_digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024**2), b''):
        result.update(block)
    return result.hexdigest()


def regular(path, size):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input refused')
    need(stat.S_ISREG(path.stat().st_mode) and path.stat().st_size <= size, 'bounded regular input required')


def read_json(path):
    regular(path, 1024**2)
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def safe_name(name):
    path = PurePosixPath(name)
    need(name and not path.is_absolute() and '..' not in path.parts and str(path) == name,
         'noncanonical source path')
    return name


def private_output(output, root=None):
    root = ROOT if root is None else root
    need(output.is_absolute() and '..' not in output.parts and output == output.resolve() and
         not output.exists(), 'new canonical absolute output required')
    need(not any(p.is_symlink() for p in (output, *output.parents)), 'symlink output refused')
    base = root / 'artifacts/kernel-candidates'
    need(output.is_relative_to(base) and output != base, 'owned ignored output required')


def patch_paths(data, expected):
    need(len(data) <= 1024**2 and b'\x00' not in data, 'bounded text patch required')
    text = data.decode('utf-8')
    paths = re.findall(r'^diff --git a/(\S+) b/(\S+)$', text, re.M)
    need(paths and all(a == b and safe_name(a) for a, b in paths), 'same-file text modifications only')
    need(len(re.findall(r'^diff --git ', text, re.M)) == len(paths), 'malformed diff section')
    need(not re.search(r'^@@', text[:text.index('diff --git ')], re.M), 'hunk outside diff section')
    need(len(paths) == len(set(a for a, _ in paths)) and {a for a, _ in paths} == set(expected),
         'exact patch target set required')
    need(not re.search(r'^(?:new file|deleted file|old mode|new mode|rename |copy |GIT binary|Binary files)', text, re.M),
         'creation/deletion/mode/rename/binary patch refused')
    need(re.findall(r'^--- (.*)$', text, re.M) == ['a/' + a for a, _ in paths] and
         re.findall(r'^\+\+\+ (.*)$', text, re.M) == ['b/' + a for a, _ in paths], 'patch headers differ')
    return [a for a, _ in paths]


def validate(lock_path, lock_sha, archive, config, patch):
    regular(lock_path, 1024**2)
    need(PIN.fullmatch(lock_sha or '') and digest(lock_path) == lock_sha, 'candidate lock pin differs')
    lock = read_json(lock_path)
    need(lock['schema_version'] == 1 and lock['experiment'] == 'KERNEL-C01' and
         lock['selected_for_release'] is False, 'source-only candidate lock required')
    for path, key, cap in ((archive, 'archive', 300 * 1024**2), (config, 'config', 1024**2), (patch, 'patch', 1024**2)):
        regular(path, cap)
        need(PIN.fullmatch(lock[key]['sha256']) and digest(path) == lock[key]['sha256'], key + ' pin differs')
        need(path.stat().st_size == lock[key]['bytes'], key + ' size differs')
    need(set(GUARDS) <= set(config.read_text().splitlines()), 'Apple/16K config guards differ')
    files = lock['files']; licenses = lock['licenses']
    need(1 <= len(files) <= 4 and 1 <= len(licenses) <= 6 and not set(files) & set(licenses), 'finite disjoint slice required')
    for name, row in {**files, **licenses}.items():
        safe_name(name)
        need(PIN.fullmatch(row['before_sha256']), 'source member pin required')
    patch_paths(patch.read_bytes(), files)
    selected, seen, total, count = {}, set(), 0, 0
    prefix = lock['archive']['root']
    safe_name(prefix); need('/' not in prefix, 'single archive root required')
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            count += 1; total += member.size
            need(count <= 110000 and total <= LIMIT and member.size >= 0, 'archive budget exceeded')
            safe_name(member.name)
            need(member.name not in seen, 'duplicate archive member'); seen.add(member.name)
            need(member.name == prefix or member.name.startswith(prefix + '/'), 'archive root differs')
            need(member.isfile() or member.isdir() or member.issym(), 'special/hardlink member refused')
            if member.issym():
                need(not PurePosixPath(member.linkname).is_absolute(), 'absolute archive link refused')
                parts = list(PurePosixPath(member.name).parent.parts)
                for part in PurePosixPath(member.linkname).parts:
                    if part == '..':
                        need(len(parts) > 1, 'escaping archive link'); parts.pop()
                    elif part != '.':
                        parts.append(part)
            rel = member.name[len(prefix) + 1:]
            if rel in files or rel in licenses:
                need(member.isfile() and member.size <= 1024**2, 'regular bounded slice member required')
                data = stream.extractfile(member).read()
                need(hashlib.sha256(data).hexdigest() == {**files, **licenses}[rel]['before_sha256'], 'member pin differs: ' + rel)
                selected[rel] = data
    need(set(selected) == set(files) | set(licenses), 'source slice incomplete')
    # Detect input changes during streaming before any output is made.
    need(digest(archive) == lock['archive']['sha256'] and digest(config) == lock['config']['sha256'] and
         digest(patch) == lock['patch']['sha256'] and digest(lock_path) == lock_sha, 'input changed during validation')
    return lock, selected, {'members': count, 'declared_unpacked_bytes': total,
                            'selected_bytes': sum(map(len, selected.values()))}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def verify_full_tree(archive, source, lock, patched=True):
    """Compare EVERY retained archive member with the private patched tree."""
    regular(archive, 300 * 1024**2)
    need(digest(archive) == lock['archive']['sha256'], 'full verification archive pin differs')
    names, changed, count, total, members = set(), [], 0, 0, 0
    with tarfile.open(archive, 'r|gz') as stream:
        for member in stream:
            members += 1; total += member.size
            need(total <= LIMIT and members <= 110000 and member.size >= 0, 'full verification archive budget exceeded')
            safe_name(member.name)
            need(member.name == lock['archive']['root'] or member.name.startswith(lock['archive']['root'] + '/'),
                 'full verification archive root differs')
            rel = member.name[len(lock['archive']['root']) + 1:]
            if not rel:
                continue
            names.add(rel)
            names.update(str(p) for p in PurePosixPath(rel).parents if str(p) != '.')
            target = source / rel
            if member.isfile():
                regular(target, LIMIT)
                before = stream_digest(stream.extractfile(member))
                expected = lock['files'].get(rel, {}).get('after_sha256', before) if patched else before
                need(digest(target) == expected, 'full-tree member differs: ' + rel)
                count += 1
                if expected != before:
                    changed.append(rel)
            elif member.issym():
                need(target.is_symlink() and os.readlink(target) == member.linkname, 'source link differs')
                need(target.resolve().is_relative_to(source.resolve()), 'resolved source link escapes kernel root')
            else:
                need(target.is_dir() and not target.is_symlink(), 'source directory differs')
    need({str(p.relative_to(source)) for p in source.rglob('*')} == names, 'full-tree member set differs')
    need(set(changed) == (set(lock['files']) if patched else set()), 'full-tree changed-file set differs')
    need(digest(archive) == lock['archive']['sha256'], 'archive changed during full verification')
    return {'regular_files_verified': count, 'changed_files': sorted(changed), 'all_other_members_identical': True}


def extract_bounded(archive, output, lock):
    snapshot = output / 'source-snapshot.tar.gz'
    copied = 0; hashed = hashlib.sha256()
    with archive.open('rb') as src, snapshot.open('xb') as dst:
        for block in iter(lambda: src.read(1024**2), b''):
            copied += len(block)
            need(copied <= lock['archive']['bytes'] <= 300 * 1024**2, 'compressed snapshot budget exceeded')
            hashed.update(block); dst.write(block)
    need(copied == lock['archive']['bytes'] and hashed.hexdigest() == lock['archive']['sha256'], 'source snapshot pin differs')
    total, count, seen = 0, 0, set()
    def preserve_safe_link(member, destination):
        accepted = tarfile.data_filter(member, destination)
        # Python normalizes relative link spelling; preserve the original
        # pinned bytes ONLY after its resolved-target safety check succeeds.
        if member.issym():
            original_target = Path(destination) / PurePosixPath(member.name).parent / member.linkname
            kernel_root = Path(destination) / lock['archive']['root']
            need(original_target.resolve().is_relative_to(kernel_root.resolve()), 'original source link escapes kernel root')
            return accepted.replace(linkname=member.linkname)
        return accepted
    with tarfile.open(snapshot, 'r|gz') as stream:
        for member in stream:
            total += member.size; count += 1
            need(total <= LIMIT and count <= 110000 and member.size >= 0, 'extraction budget exceeded')
            safe_name(member.name)
            need(member.name not in seen and (member.name == lock['archive']['root'] or
                 member.name.startswith(lock['archive']['root'] + '/')), 'extraction member root/duplicates differ')
            seen.add(member.name)
            need(member.isfile() or member.isdir() or member.issym(), 'special extraction member refused')
            stream.extract(member, output / 'source-tree', filter=preserve_safe_link)
    need(digest(snapshot) == lock['archive']['sha256'], 'snapshot changed during extraction')
    return snapshot


def run(args):
    private_output(args.output)
    lock, selected, inventory = validate(args.lock, args.lock_sha256, args.archive, args.config, args.patch)
    config_data, patch_data = args.config.read_bytes(), args.patch.read_bytes()
    need(hashlib.sha256(config_data).hexdigest() == lock['config']['sha256'] and
         hashlib.sha256(patch_data).hexdigest() == lock['patch']['sha256'], 'snapshot pin differs')
    args.output.mkdir(parents=True, mode=0o700)
    report = {'experiment': 'KERNEL-C01', 'status': 'SOURCE_VALIDATED', 'mode': args.mode,
              'candidate_lock_sha256': args.lock_sha256, 'source_commit': lock['archive']['commit'],
              'archive_sha256': lock['archive']['sha256'], 'config_sha256': lock['config']['sha256'],
              'patch_sha256': lock['patch']['sha256'], 'inventory': inventory, 'commands': [],
              'kernel_build': 'NOT RUN', 'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED',
              'selected_for_release': False, 'full_source_tree': False}
    try:
        (args.output / 'config').write_bytes(config_data)
        (args.output / 'candidate.patch').write_bytes(patch_data)
        save(args.output / 'build-plan.json', lock['build_plan'])
        full = getattr(args, 'full_source', False)
        need(not full or args.mode in ('apply', 'baseline'), 'full materialization requires apply/baseline mode')
        if full:
            source = args.output / 'source-tree' / lock['archive']['root']
            source.parent.mkdir(mode=0o700)
            need(shutil.disk_usage(args.output).free >= 4 * 1024**3, '4GiB free source budget required')
            # Immutable-by-hash snapshot and second-pass member caps prevent
            # an input swap from exceeding the validated storage envelope.
            archive = extract_bounded(args.archive, args.output, lock)
        else:
            source = args.output / 'source-slice'; source.mkdir(mode=0o700)
            for name, data in selected.items():
                target = source / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        if args.mode == 'apply':
            # No kernel Makefile, recipe, helper or other upstream code runs.
            env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(args.output)}
            regular(Path('/usr/bin/patch'), 8 * 1024**2)
            report['patch_tool_sha256'] = digest(Path('/usr/bin/patch'))
            base = ['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                    '--reject-file=-', '-p1', '--input', str(args.output / 'candidate.patch')]
            for label, argv in (('dry-run', base + ['--dry-run']), ('apply', base)):
                result = subprocess.run(argv, cwd=source, env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, timeout=30, check=False)
                log = args.output / (label + '.log'); log.write_bytes(result.stdout)
                report['commands'].append({'argv': argv, 'cwd': str(source), 'exit': result.returncode,
                                           'log': log.name, 'log_sha256': digest(log)})
                need(result.returncode == 0 and len(result.stdout) <= 64 * 1024 and
                     not re.search(rb'(?i)fuzz|reject|FAILED|Reversed', result.stdout), 'exact patch command failed')
            report['changed_files'] = {}
            for name, row in lock['files'].items():
                regular(source / name, 1024**2)
                need(digest(source / name) == row['after_sha256'], 'patched member differs: ' + name)
                report['changed_files'][name] = {'before_sha256': row['before_sha256'], 'after_sha256': row['after_sha256']}
            for name, row in lock['licenses'].items():
                need(digest(source / name) == row['before_sha256'], 'license text changed')
            if full:
                report['full_tree_verification'] = verify_full_tree(archive, source, lock)
                report['full_source_tree'] = True
            else:
                need({str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()} == set(selected), 'unexpected output file')
            report.update(status='PATCH_APPLIED_TO_SOURCE_SLICE', fuzz=0, rejects=0)
            if full:
                report['status'] = 'PATCH_APPLIED_TO_FULL_PRIVATE_SOURCE'
        elif full:
            report['full_tree_verification'] = verify_full_tree(archive, source, lock, patched=False)
            report.update(status='BASELINE_FULL_PRIVATE_SOURCE_VERIFIED', full_source_tree=True)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError, KeyboardInterrupt):
        report['status'] = 'FAIL'; raise
    finally:
        save(args.output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'baseline', 'apply'))
    for name in ('lock', 'archive', 'config', 'patch', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--lock-sha256', required=True)
    parser.add_argument('--full-source', action='store_true', help='materialize <=2GiB private tree, verify every member')
    args = parser.parse_args()
    try:
        result = run(args); print(result['status']); return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        print('Kernel candidate refused; inspect pinned inputs and retained failure receipt.'); return 1


if __name__ == '__main__':
    raise SystemExit(main())
