#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline static desktop-entry inspection; never launches commands or sessions."""
import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import desktop_applications as desktop

KIND = 'cachy-asahi-desktop-static-inventory-v1'
CAP = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'bounded regular JSON file required')
        raw = bytearray()
        while len(raw) <= cap:
            block = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) <= cap, 'JSON byte cap exceeded')
        return bytes(raw), json.loads(raw, object_pairs_hook=unique,
                                     parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    finally:
        os.close(fd)


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def binding(report, environment, selected, mime):
    normalized = dict(report)
    del normalized['root']  # Logical staged paths, mode bits and symlinks remain bound.
    return dict(schema=1, kind=KIND, environment=desktop.pin(environment),
                selected=selected, mime=mime, audit_sha256=digest(normalized),
                files=report['pins'])


def validate_inventory(value):
    require(type(value) is dict and set(value) == {'schema', 'kind', 'environment', 'selected', 'mime', 'audit_sha256', 'files'},
            'exact inventory schema required')
    require(type(value['schema']) is int and value['schema'] == 1 and value['kind'] == KIND,
            'unsupported inventory version')
    require(type(value['audit_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['audit_sha256']),
            'inventory audit digest required')
    require(type(value['files']) is dict and len(value['files']) <= 100000, 'bounded inventory file map required')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version='cachy-asahi-desktop-tools 0.1.0')
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation in ('capture', 'audit'):
        command = sub.add_parser(operation, help='capture a static inventory' if operation == 'capture' else 'audit an exactly pinned inventory')
        command.add_argument('--root', type=Path, required=True)
        command.add_argument('--environment', type=Path, required=True)
        command.add_argument('--select', action='append', required=True)
        command.add_argument('--mime', action='append', default=[])
        if operation == 'audit':
            command.add_argument('--inventory', type=Path, required=True)
            command.add_argument('--inventory-sha256', required=True)
    args = parser.parse_args(argv)
    audit = None
    try:
        inventory_raw = inventory = None
        if args.operation == 'audit':
            require(re.fullmatch('[0-9a-f]{64}', args.inventory_sha256) is not None, 'explicit lowercase inventory SHA256 required')
            inventory_raw, inventory = read_json(args.inventory, CAP)
            require(hashlib.sha256(inventory_raw).hexdigest() == args.inventory_sha256, 'inventory byte pin mismatch')
            validate_inventory(inventory)
        raw, env = read_json(args.environment, desktop.TEXT_CAP)
        selected, mime = list(dict.fromkeys(args.select)), list(dict.fromkeys(args.mime))
        if inventory is not None:
            require(inventory['environment'] == desktop.pin(raw) and inventory['selected'] == selected and inventory['mime'] == mime,
                    'inventory environment or selection differs')
        audit = desktop.Audit(args.root, env)
        report = audit.run(selected, mime)
        current = binding(report, raw, selected, mime)
        if args.operation == 'capture':
            if report['status'] != 'PASS_STAGED_CHECKS':
                print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
                return 1
            encoded = json.dumps(current, sort_keys=True, indent=2, allow_nan=False)
            require(len(encoded.encode()) + 1 <= CAP, 'captured inventory byte cap exceeded')
            print(encoded)
            return 0
        require(digest(current) == digest(inventory), 'staged inventory differs: file bytes, modes, links, discovery or audit result changed')
        report['inventory_input'] = desktop.pin(inventory_raw)
        report['inventory_binding'] = 'EXACT_STATIC_INVENTORY'
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
        return 0 if report['status'] == 'PASS_STAGED_CHECKS' else 1
    except (ValueError, OSError, configparser.Error, UnicodeError, KeyError, TypeError, struct.error, RecursionError) as error:
        print(json.dumps(dict(schema=1, status='REFUSED', error=str(error)), sort_keys=True))
        return 2
    finally:
        if audit is not None:
            audit.stage.close()


if __name__ == '__main__':
    sys.exit(main())
