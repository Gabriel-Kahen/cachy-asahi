# SPDX-License-Identifier: MIT
"""Finite DATA view of one actual image, using maintained actor custody."""
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import tarfile
import time

HERE = Path(__file__).resolve().parent


def local(name):
    spec = importlib.util.spec_from_file_location('bankstown_qt3_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


H = local('handoff')


def file_reference(path, *, cap=16 * 1024**3, deadline):
    path = H.ordinary(str(path))
    before = path.lstat()
    H.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
           and 0 < before.st_size <= cap, 'FINITE_IMAGE_DATA_FILE')
    digest, size = hashlib.sha256(), 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        H.need(H.identity(before) == H.identity(os.fstat(fd)), 'IMAGE_DATA_OPEN_CHANGED')
        while part := os.read(fd, 1024**2):
            H.need(time.monotonic() < deadline, 'IMAGE_DATA_DEADLINE')
            size += len(part)
            H.need(size <= before.st_size, 'IMAGE_DATA_GREW')
            digest.update(part)
        H.need(size == before.st_size and H.identity(before) == H.identity(os.fstat(fd))
               == H.identity(path.lstat()), 'IMAGE_DATA_CHANGED')
    finally:
        os.close(fd)
    return dict(path=str(path), bytes=size, sha256=digest.hexdigest())


def name(value):
    while value.startswith('./'):
        value = value[2:]
    value = value.rstrip('/')
    path = PurePosixPath(value)
    H.need(value and not path.is_absolute() and str(path) == value
           and all(p not in ('', '.', '..') for p in path.parts)
           and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'IMAGE_MEMBER_NAME')
    return value


def link_target(member, target, *, hard=False):
    H.need(type(target) is str and target and '\x00' not in target, 'IMAGE_LINK_TARGET')
    value = target if target.startswith('/') or hard else posixpath.dirname(member) + '/' + target
    stack = []
    for part in value.split('/'):
        if part == '..':
            H.need(stack, 'IMAGE_LINK_ESCAPES')
            stack.pop()
        elif part not in ('', '.'):
            stack.append(part)
    H.need(stack, 'IMAGE_LINK_ROOT_REFUSED')
    return '/'.join(stack)


def unpack_view(archive_path, root, *, deadline, byte_cap=16 * 1024**3, member_cap=300000):
    """Never execute, chown or install exported data; links are created last."""
    root = H.ordinary(str(root))
    H.need(not root.exists(), 'FRESH_IMAGE_DATA_ROOT')
    root.mkdir(mode=0o700)
    seen, links, directories, total = set(), [], [], 0
    with tarfile.open(archive_path, 'r|') as archive:
        for member in archive:
            H.need(time.monotonic() < deadline, 'IMAGE_DATA_DEADLINE')
            if member.name in ('.', './') and member.isdir():
                continue
            relative = name(member.name)
            H.need(relative not in seen and len(seen) < member_cap
                   and 0 <= member.size <= 1024**3, 'IMAGE_MEMBER_BOUND_OR_DUPLICATE')
            seen.add(relative)
            total += member.size
            H.need(total <= byte_cap, 'IMAGE_EXPANDED_BYTE_BOUND')
            destination = root / relative
            H.ordinary(str(destination))
            destination.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                destination.mkdir(exist_ok=True)
                directories.append((destination, member.mode))
            elif member.isfile():
                with archive.extractfile(member) as source, destination.open('xb') as output:
                    left = member.size
                    while left:
                        H.need(time.monotonic() < deadline, 'IMAGE_DATA_DEADLINE')
                        part = source.read(min(left, 1024**2))
                        H.need(part, 'TRUNCATED_IMAGE_MEMBER')
                        output.write(part)
                        left -= len(part)
                destination.chmod(member.mode & 0o7777)
            elif member.issym() or member.islnk():
                target = link_target(relative, member.linkname, hard=member.islnk())
                links.append((destination, member, root / target))
            else:
                raise ValueError('IMAGE_EXPORT_SPECIAL_MEMBER_REFUSED')
    pending = [row for row in links if row[1].islnk()]
    for _ in range(64):
        if not pending:
            break
        following = []
        for destination, member, target in pending:
            H.ordinary(str(target))
            if target.exists():
                H.need(target.is_file(), 'IMAGE_HARDLINK_REGULAR_TARGET')
                os.link(target, destination, follow_symlinks=False)
            else:
                following.append((destination, member, target))
        H.need(len(following) < len(pending), 'IMAGE_HARDLINK_CYCLE_OR_MISSING')
        pending = following
    H.need(not pending, 'IMAGE_HARDLINK_DEPTH')
    for destination, member, target in links:
        if member.issym():
            # Preserve literal logical links; profile.resolve never follows them
            # into the host. All data writes finished before any symlink exists.
            destination.symlink_to(member.linkname)
    for directory, mode in reversed(directories):
        directory.chmod(mode & 0o7777)
    return dict(members=len(seen), expanded_bytes=total, data_only=True)


def materialize_image(*, source_root, image_report, delegation, context, policy,
                      catalog_reference, executor, output):
    """Export/probe a real IID inside the same admitted daemon; no new executor."""
    I = local('inputs')
    M = I.held(source_root, 'image_current_v3.py')
    out = H.ordinary(str(output))
    H.need(not out.exists(), 'FRESH_MATERIALIZATION_OUTPUT')
    out.mkdir(mode=0o700)
    executor.live()
    facts = executor.facts
    deadline = executor.deadline
    H.need(image_report['status'] == 'PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY'
           and image_report['binding'] == context['binding']
           and image_report['owner_executor_facts'] == facts
           and image_report['cleanup']['errors'] == [], 'ACTUAL_SAME_IMAGE_STAGE')
    b = M.Build(executor, delegation, context, policy, out)
    b.end = min(b.end, deadline - 90)
    b.cleanup_end = min(b.cleanup_end, deadline)
    labels = {M.LABEL + '.nonce': context['nonce'], M.LABEL + '.source': context['binding']['source'],
              M.LABEL + '.stage': context['stage']}
    archive_path, root = out / 'image.tar', out / 'root'
    primary = None
    try:
        image = image_report['image_id']
        b.image(image, labels)
        actor = b.actor('probe', image, labels, None, [], image_report['packages'], {})
        b.docker('export-image-data', ['container', 'export', '--output', str(archive_path), actor['cid']], 180)
        archive_ref = file_reference(archive_path, deadline=b.end)
        view = unpack_view(archive_path, root, deadline=b.end)
        H.verify_reference(archive_ref, deadline=b.end)
        executor.live()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            cleanup = b.cleanup()
            (out / 'materialization-cleanup.json').write_bytes(H.encoded(cleanup))
            H.need(not cleanup['errors'], 'MATERIALIZATION_CLEANUP_HOLD')
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('Materialization cleanup also held: ' + str(error))
    inventory = image_report['inventory_pin']
    receipt = dict(schema=1, kind=H.KIND, status='PASS_PRIVATE_IMAGE_DATA_ONLY',
        source=dict(root=str(source_root), commit=context['binding']['source'], ref=context['binding']['ref']),
        binding=context['binding'], nonce=context['nonce'], delegation_pin=context['delegation_pin'],
        catalog=catalog_reference,
        image=dict(id=image, inventory=inventory, protected349=H.PROTECTED349),
        filesystem=dict(root=str(root), image_id=image, archive=archive_ref),
        executor=dict(code_pin=facts['code_pin'], engine_id=facts['engine_id'], docker_endpoint=facts['docker_endpoint'],
                      owner_pid=facts['owner_domain']['pid'], daemon_pid=facts['daemon_domain']['pid']),
        lifetime=dict(observed_monotonic=time.monotonic(), work_deadline_monotonic=deadline),
        legal='HELD', key_freshness='HELD', **H.FINAL)
    raw = H.encoded(receipt)
    H.validate_image_receipt(raw, H.pin(raw)['sha256'])
    path = out / 'image-receipt.json'
    path.write_bytes(raw)
    (out / 'view-DATA.json').write_bytes(H.encoded(view))
    return receipt, path
