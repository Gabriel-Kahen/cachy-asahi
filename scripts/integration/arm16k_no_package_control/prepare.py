#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Snapshot public control choices and reader source; never opens a guest image."""
import argparse
import ast
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location('control_prepare_'+name, HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


K = module('contracts')


def reader_shape(raw):
    K.need(type(raw) is bytes and 0 < len(raw) <= 1024**2, 'bounded public reader source')
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, UnicodeError):
        raise ValueError('valid public Python metadata reader source required') from None
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == 'observe']
    K.need(len(functions) == 1 and type(functions[0]) is ast.FunctionDef, 'one public synchronous metadata observe API')
    args = functions[0].args
    K.need(not args.posonlyargs and [arg.arg for arg in args.args] == ['raw_path', 'debugfs_pin', 'deadline'] and
           not args.vararg and not args.kwarg and not args.defaults and
           [arg.arg for arg in args.kwonlyargs] == ['legacy_root', 'guard'] and args.kw_defaults == [None, None],
           'exact metadata reader observe(raw_path,debugfs_pin,deadline,*,legacy_root,guard) API')
    # Parsing is structural only. Root must separately review and admit the code;
    # a matching API and hash do not establish safe or metadata-only behavior.
    return raw


def prepare(inputs_path, source_lock_sha256, reader_path, output, *, now=None, source_loader=None):
    K.need(K.sha(source_lock_sha256), 'external new Source lock SHA256 required')
    source = (source_loader or module('support').source)(source_lock_sha256)
    packet = K.load(inputs_path)
    current = int(time.time()) if now is None else now
    K.inputs(packet, source, current)
    out = K.ordinary(output)
    inputs_path, reader_path = K.ordinary(inputs_path), K.ordinary(reader_path)
    K.need(not out.exists(), 'fresh constructor snapshot output required')
    for operand in (inputs_path, reader_path, HERE):
        K.need(out != operand and out not in operand.parents and operand not in out.parents,
               'constructor output disjoint from public inputs reader and Source')
    K.resources(packet['resources'], source, current, 'prepare', out)
    raw = reader_shape(K.read_bytes(reader_path, 1024**2))
    K.need(K.bytes_pin(raw) == packet['reader'], 'exact Root-selected public reader pin')
    rows = {'control-packet.json': K.canonical(packet), 'raw_metadata.py': raw}
    # No image, prepared baseline, credential, Docker or quota operand is read.
    # The constructor only validates the declared HOME prepare output binding.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open('/', flags)
    root = None
    try:
        for part in out.parts[1:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        K.need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022,
               'ordinary owned nonwritable constructor parent')
        os.mkdir(out.name, 0o700, dir_fd=parent)
        root = os.open(out.name, flags, dir_fd=parent)
        created = os.fstat(root)
        for name, body in rows.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
            try:
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(fd)
                os.fchmod(fd, 0o400)
            finally:
                os.close(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
        held = os.fstat(root)
        K.need(stat.S_ISDIR(held.st_mode) and identity(held) == identity(created),
               'same held constructor directory before membership')
        # Refresh enumeration on this original FD after populating the directory.
        os.lseek(root, 0, os.SEEK_SET)
        K.need(set(os.listdir(root)) == set(rows), 'exact constructor snapshot membership')
        after = os.fstat(root)
        K.need(identity(after) == identity(held) and
               all(getattr(after, n) == getattr(held, n) for n in
                   ('st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
               'same held constructor directory after membership')
        os.fchmod(root, 0o500)
        os.fsync(root)
        final = os.stat(out.name, dir_fd=parent, follow_symlinks=False)
        K.need((final.st_dev, final.st_ino, final.st_uid, final.st_gid, final.st_mode) ==
               (created.st_dev, created.st_ino, created.st_uid, created.st_gid, stat.S_IFDIR | 0o500),
               'stable read-only constructor snapshot directory')
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)
    return dict(kind='NO_PACKAGE_CONTROL_PACKET_SNAPSHOT_V1', operation=K.OP,
        status='PUBLIC_PACKET_AND_READER_SNAPSHOTTED_NOT_EXECUTED', output=str(out),
        packet=K.json_pin(packet), reader=K.bytes_pin(raw), source_lock=source,
        actual_actor=None, actual_VM=None, Root_acceptance=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--source-lock-sha256', required=True)
    parser.add_argument('--reader', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    K.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid() == os.geteuid() != 0,
           'ordinary isolated bytecode-free public constructor required')
    print(K.canonical(prepare(args.inputs, args.source_lock_sha256, args.reader, args.output)).decode(), end='')


if __name__ == '__main__':
    main()
