#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Receive bounded camera metadata. Never query a device or capture an image."""
import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import stat

RECORD_BYTES = 65536
EXPECTED_BYTES = 4096
IDENTITY = {'board', 'soc', 'arch', 'page_size', 'kernel_release', 'kernel_source_revision',
            'kernel_image_sha256', 'probe_source_sha256', 'run_id', 'nonce'}
FIELDS = {'schema_version', 'purpose', 'origin', 'identity', 'state', 'backend', 'devices',
          'hardware_validation', 'capture'}
CAPS = {'VIDEO_CAPTURE', 'VIDEO_CAPTURE_MPLANE', 'STREAMING', 'READWRITE'}
LABEL = re.compile(r'[A-Za-z0-9_.:\-]{1,64}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def result(code=None):
    return {'status': 'FAIL' if code else 'PASS-metadata', 'error': code,
            'hardware_validation': 'NOT RUN', 'firmware_validation': 'NOT RUN',
            'capture': 'NOT RUN', 'runtime_preview': 'NOT RUN', 'device_access': False}


def decode(raw):
    def pairs(items):
        output = {}
        for key, value in items:
            need(key not in output, 'schema')
            output[key] = value
        return output
    def constant(value):
        raise Refused('schema')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def identity(value):
    need(isinstance(value, dict) and set(value) == IDENTITY, 'identity')
    need(value['board'] in ('apple,j413', 'apple,j415') and value['soc'] == 'apple,t8112'
         and value['arch'] == 'aarch64' and type(value['page_size']) is int
         and value['page_size'] == 16384, 'identity')
    need(isinstance(value['kernel_release'], str) and 0 < len(value['kernel_release']) <= 128
         and re.fullmatch(r'[A-Za-z0-9._+\-]+', value['kernel_release']), 'identity')
    need(isinstance(value['kernel_source_revision'], str)
         and re.fullmatch(r'[0-9a-f]{40}', value['kernel_source_revision']), 'identity')
    need(all(isinstance(value[key], str) and HASH.fullmatch(value[key])
             for key in ('kernel_image_sha256', 'probe_source_sha256')), 'identity')
    need(isinstance(value['run_id'], str) and LABEL.fullmatch(value['run_id'])
         and isinstance(value['nonce'], str) and re.fullmatch(r'[0-9a-f]{32}', value['nonce']), 'identity')


def receive(raw, sha256, expected):
    """Validate caller-bound claims; PASS-metadata never means camera support passed."""
    try:
        need(isinstance(raw, bytes) and 0 < len(raw) <= RECORD_BYTES, 'bounds')
        need(isinstance(sha256, str) and HASH.fullmatch(sha256) and digest(raw) == sha256, 'evidence-binding')
        identity(expected)
        value = decode(raw)
        need(isinstance(value, dict) and set(value) == FIELDS and type(value['schema_version']) is int
             and value['schema_version'] == 1 and value['purpose'] == 'camera-metadata-observation', 'schema')
        need(value['origin'] in ('controlled-fixture', 'captured-target-metadata')
             and value['hardware_validation'] == value['capture'] == 'NOT RUN', 'schema')
        identity(value['identity'])
        need(value['identity'] == expected, 'identity')
        need(value['state'] in ('observed', 'no-device', 'unsupported', 'unknown')
             and value['backend'] in ('v4l2', 'libcamera', 'unknown'), 'schema')
        devices = value['devices']
        need(isinstance(devices, list) and len(devices) <= 8, 'bounds')
        ids, usable, unavailable = set(), [], []
        for device in devices:
            need(isinstance(device, dict) and set(device) == {'id', 'driver', 'state', 'capabilities', 'formats'}, 'schema')
            need(all(isinstance(device[key], str) and LABEL.fullmatch(device[key]) for key in ('id', 'driver')), 'schema')
            need(device['id'] not in ids, 'schema')
            ids.add(device['id'])
            need(device['state'] in ('available', 'unsupported', 'unknown'), 'schema')
            capabilities = device['capabilities']
            need(isinstance(capabilities, list) and len(capabilities) <= 4, 'bounds')
            need(all(isinstance(cap, str) and cap in CAPS for cap in capabilities)
                 and len(set(capabilities)) == len(capabilities), 'schema')
            formats = device['formats']
            need(isinstance(formats, list) and len(formats) <= 16, 'bounds')
            modes = set()
            for mode in formats:
                need(isinstance(mode, dict) and set(mode) == {'fourcc', 'width', 'height', 'fps_num', 'fps_den'}, 'schema')
                need(isinstance(mode['fourcc'], str) and re.fullmatch(r'[A-Z0-9]{4}', mode['fourcc']), 'schema')
                for field, maximum in [('width', 8192), ('height', 8192), ('fps_num', 120000), ('fps_den', 10000)]:
                    need(type(mode[field]) is int and 0 < mode[field] <= maximum, 'bounds')
                rate = Fraction(mode['fps_num'], mode['fps_den'])
                need(rate <= 120, 'bounds')
                key = (mode['fourcc'], mode['width'], mode['height'], rate)
                need(key not in modes, 'schema')
                modes.add(key)
            if device['state'] == 'available' and 'STREAMING' in capabilities and formats and (
                    'VIDEO_CAPTURE' in capabilities or 'VIDEO_CAPTURE_MPLANE' in capabilities):
                usable.append({'id': device['id'], 'driver': device['driver'], 'formats': len(formats)})
            else:
                unavailable.append(device['id'])
        need(value['state'] != 'no-device' or not devices, 'schema')
        if value['state'] != 'observed':
            return result(value['state'])
        if not devices:
            return result('no-device')
        if value['backend'] != 'v4l2':
            return result('unknown' if value['backend'] == 'unknown' else 'unsupported')
        if unavailable:
            return result('unknown' if any(d['state'] == 'unknown' for d in devices) else 'unsupported')
        if not usable:
            return result('unsupported')
        return {**result(), 'origin': value['origin'], 'identity': value['identity'],
                'backend': 'v4l2', 'metadata_candidates': usable, 'evidence_sha256': sha256}
    except (Refused, ValueError, UnicodeError, TypeError, KeyError, RecursionError) as error:
        return result(str(error) if isinstance(error, Refused) else 'schema')


def snapshot(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns'))


def read_at(directory, name, limit, sha256):
    need(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_\-][A-Za-z0-9_.\-]{0,63}', name)
         and name not in ('.', '..'), 'unsafe-namespace')
    need(hasattr(os, 'O_PATH'), 'unsupported')
    pointer, fd = None, None
    try:
        # O_PATH binds an inode without invoking a device driver's open operation.
        pointer = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(pointer)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe-namespace')
        need(0 < before.st_size <= limit, 'bounds')
        # This kernel FD link refers to the held inode, even if its name is replaced.
        fd = os.open('/proc/self/fd/' + str(pointer), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        need(snapshot(before) == snapshot(os.fstat(fd))
             == snapshot(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'evidence-drift')
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        need(snapshot(before) == snapshot(after) == snapshot(os.fstat(pointer))
             == snapshot(current), 'evidence-drift')
        need(isinstance(sha256, str) and HASH.fullmatch(sha256) and digest(raw) == sha256, 'evidence-binding')
        return bytes(raw)
    finally:
        try:
            if fd is not None:
                os.close(fd)
        finally:
            if pointer is not None:
                os.close(pointer)



def inspect_namespace(namespace, record_name, record_sha256, expected_name, expected_sha256):
    """The only file access is to two ordinary metadata files under this namespace."""
    directory, opened, links = None, [], []
    try:
        path = Path(namespace)
        need(isinstance(namespace, (str, Path)) and path.is_absolute()
             and str(namespace) == os.path.normpath(str(namespace))
             and len(path.parts) <= 64, 'unsafe-namespace')
        need(not any(path == root or path.is_relative_to(root) for root in map(Path, ('/dev', '/proc', '/sys'))), 'unsafe-namespace')
        for ancestor in [path, *path.parents]:
            need(not ancestor.is_symlink(), 'linked-namespace')
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(directory)
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            opened.append(child)
            links.append((directory, part, snapshot(os.fstat(child))))
            directory = child
        before = os.fstat(directory)
        expected_raw = read_at(directory, expected_name, EXPECTED_BYTES, expected_sha256)
        raw = read_at(directory, record_name, RECORD_BYTES, record_sha256)
        output = receive(raw, record_sha256, decode(expected_raw))
        need(snapshot(before) == snapshot(os.fstat(directory)) == snapshot(path.stat(follow_symlinks=False)), 'evidence-drift')
        need(expected_raw == read_at(directory, expected_name, EXPECTED_BYTES, expected_sha256)
             and raw == read_at(directory, record_name, RECORD_BYTES, record_sha256), 'evidence-drift')
        need(all(pin == snapshot(os.stat(name, dir_fd=parent, follow_symlinks=False))
                 for parent, name, pin in links), 'evidence-drift')
        return output
    except Refused as error:
        return result(str(error))
    except (OSError, ValueError, TypeError, RecursionError):
        return result('unsafe-namespace')
    finally:
        for fd in reversed(opened):
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--record-sha256', required=True)
    parser.add_argument('--expected', required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    output = inspect_namespace(args.namespace, args.record, args.record_sha256, args.expected, args.expected_sha256)
    print(json.dumps(output, sort_keys=True))
    return 0 if output['status'] == 'PASS-metadata' else 1


if __name__ == '__main__':
    raise SystemExit(main())
