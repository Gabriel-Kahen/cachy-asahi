#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned official HTTPS acquisition only; signatures/builds remain unrun."""
import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import threading
import time
from types import ModuleType, SimpleNamespace
import urllib.error
import urllib.parse

BASE = Path(__file__).resolve().parent
HOSTS = {'ca.us.mirror.archlinuxarm.org', 'raw.githubusercontent.com'}
CONFIG_KEYS = {'source', 'packet_sha256', 'contract_sha256', 'native_sha256', 'inputs_sha256',
               'deadline_at', 'jobroot', 'cache', 'source_commit', 'clock_sha256', 'run_id', 'run_attempt'}
REFUSALS = {'prefetch-deadline', 'prefetch-parent', 'prefetch-file', 'prefetch-file-bound',
    'prefetch-file-drift', 'prefetch-json-duplicate', 'prefetch-json-number', 'prefetch-json-object',
    'prefetch-url-duplicate', 'prefetch-url-policy', 'prefetch-tls-environment', 'prefetch-url-refused',
    'prefetch-socket', 'prefetch-http-status', 'prefetch-redirect-refused', 'prefetch-http-encoding',
    'prefetch-http-length', 'prefetch-read-size', 'prefetch-response-bytes', 'prefetch-response-size',
    'prefetch-root', 'prefetch-root-owner', 'prefetch-root-not-fresh', 'prefetch-directory-drift',
    'prefetch-temp-policy', 'prefetch-cache-binding', 'prefetch-existing-cache', 'prefetch-target-binding',
    'prefetch-cache-set', 'prefetch-final-inode', 'prefetch-final-size', 'prefetch-final-pin',
    'prefetch-config-keys', 'prefetch-config-binding', 'prefetch-contract-pin', 'prefetch-input-pin',
    'prefetch-items', 'prefetch-source-drift', 'prefetch-acquisition', 'prefetch-counts',
    'prefetch-disposal', 'prefetch-config-pin', 'prefetch-receipt-bound', 'prefetch-receipt-write',
    'prefetch-receipt-drift', 'prefetch-receipt-exists'}


def refusal(error):
    if isinstance(error, KeyboardInterrupt): return 'cancelled'
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in REFUSALS:
        return error.args[0]
    if getattr(error, 'category', None) == 'HTTP failure':
        return 'http-throttled' if getattr(error, 'http_status', None) == 429 else 'http-failure'
    if getattr(error, 'category', None) == 'HTTPS transport failure': return 'transport-failure'
    return 'acquisition-failed'


def need(value, code):
    if not value: raise ValueError(code)


def live(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline)
         and time.monotonic() < deadline, 'prefetch-deadline')


def read(path, limit=8 * 1024**2):
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'prefetch-parent')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, 'prefetch-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd); data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(chunk); need(len(data) <= limit, 'prefetch-file-bound')
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(item, k)
             for item in (opened, after, named) for k in fields), 'prefetch-file-drift')
        return bytes(data)
    finally: os.close(fd)


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'prefetch-json-duplicate'); result[key] = value
        return result
    def constant(value): raise ValueError('prefetch-json-number')
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    need(type(value) is dict, 'prefetch-json-object')
    return value


def module(name, path, raw):
    value = ModuleType(name); value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


class Transport:
    """Direct TLS, zero redirects/proxies; outer Runner is the hard time cutoff."""
    def __init__(self, items, deadline, connection=None, context=None):
        self.items = {row['url']: row for row in items}; self.deadline = deadline
        need(len(self.items) == len(items), 'prefetch-url-duplicate')
        for url in self.items:
            parsed = urllib.parse.urlsplit(url)
            need(type(url) is str and len(url) <= 4096 and parsed.scheme == 'https'
                and parsed.hostname in HOSTS and parsed.port is None and parsed.username is None
                and parsed.password is None and not parsed.query and not parsed.fragment
                and parsed.path.startswith('/') and all(33 <= ord(c) < 127 for c in url), 'prefetch-url-policy')
        self.connection = connection or http.client.HTTPSConnection
        need(not any(k in os.environ for k in ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'SSLKEYLOGFILE')), 'prefetch-tls-environment')
        self.context = context if context is not None else ssl.create_default_context()

    def left(self):
        live(self.deadline)
        return min(30.0, self.deadline - time.monotonic())

    def urlopen(self, url, timeout=60):
        need(type(url) is str and url in self.items and type(timeout) in (int, float)
             and 0 < timeout <= 60, 'prefetch-url-refused')
        parsed = urllib.parse.urlsplit(url)
        connection = self.connection(parsed.hostname, timeout=min(timeout, self.left()), context=self.context)
        response = None
        try:
            connection.connect(); live(self.deadline)
            sock = connection.sock
            need(sock is not None, 'prefetch-socket')
            sock.settimeout(min(timeout, self.left()))
            connection.request('GET', parsed.path, headers={'Accept-Encoding': 'identity'})
            sock.settimeout(min(timeout, self.left()))
            response = connection.getresponse(); live(self.deadline)
            need(type(response.status) is int, 'prefetch-http-status')
            if response.status != 200:
                code = response.status
                response.close()
                if 300 <= code <= 399: raise ValueError('prefetch-redirect-refused')
                raise urllib.error.HTTPError(url, code, 'HTTP failure', None, None)
            need(response.getheader('Content-Encoding') in (None, 'identity'), 'prefetch-http-encoding')
            length = response.getheader('Content-Length')
            need(length is None or (re.fullmatch('[0-9]{1,10}', length) is not None
                 and int(length) == self.items[url]['size']), 'prefetch-http-length')
            return Response(self, response, connection, sock, url, self.items[url]['size'])
        except BaseException:
            try:
                if response is not None: response.close()
            finally: connection.close()
            raise


class Response:
    def __init__(self, transport, response, connection, sock, url, size):
        self.transport, self.response, self.connection, self.sock = transport, response, connection, sock
        self.url, self.maximum, self.count = url, size, 0
    def __enter__(self): return self
    def __exit__(self, *args):
        try: self.response.close()
        finally: self.connection.close()
    def read(self, size):
        need(type(size) is int and 0 < size <= 1024**2, 'prefetch-read-size')
        self.sock.settimeout(self.transport.left())
        data = self.response.read1(size)
        live(self.transport.deadline)
        need(type(data) is bytes, 'prefetch-response-bytes')
        self.count += len(data)
        need(self.count <= self.maximum, 'prefetch-response-size')
        return data


class Custody:
    """Exclusive cooperative 0700 namespace; original fetch rename remains intact."""
    def __init__(self, root, cache, deadline):
        self.root, self.cache, self.deadline = Path(root), Path(cache), deadline
        need(self.root.is_absolute() and self.root == self.root.resolve() and self.cache == self.root / 'cache', 'prefetch-root')
        self.rootfd = self.cachefd = None
        self.lock, self.local, self.loans, self.started = threading.Lock(), threading.local(), {}, set()
        self.first_failure = None
        try:
            self.rootfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.root_info = os.fstat(self.rootfd)
            need(self.root_info.st_uid == os.getuid() and self.root_info.st_gid == os.getgid()
                and stat.S_IMODE(self.root_info.st_mode) == 0o700, 'prefetch-root-owner')
            need(not os.listdir(self.rootfd), 'prefetch-root-not-fresh')
            os.mkdir('cache', mode=0o700, dir_fd=self.rootfd)
            self.cachefd = os.open('cache', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.rootfd)
            self.cache_info = os.fstat(self.cachefd); self.check()
        except BaseException:
            self.close(); raise
    def check(self, deadline=True):
        if deadline: live(self.deadline)
        for path, fd, known in ((self.root, self.rootfd, self.root_info), (self.cache, self.cachefd, self.cache_info)):
            opened, named = os.fstat(fd), path.lstat()
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode')
            need(all(getattr(known, key) == getattr(opened, key) == getattr(named, key) for key in fields), 'prefetch-directory-drift')
    def close(self):
        first = None
        for name in ('cachefd', 'rootfd'):
            fd = getattr(self, name, None)
            if fd is not None:
                setattr(self, name, None)
                try: os.close(fd)
                except BaseException as error:
                    if first is None: first = error
        if first is not None: raise first
    def save_receipt(self, value):
        self.check(deadline=False)
        raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()
        need(len(raw) <= 65536, 'prefetch-receipt-bound')
        temporary = '.prefetch-receipt-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.rootfd)
        try:
            opened = os.fstat(fd)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view); need(count > 0, 'prefetch-receipt-write'); view = view[count:]
            os.fsync(fd)
            named = os.stat(temporary, dir_fd=self.rootfd, follow_symlinks=False)
            need((named.st_dev,named.st_ino)==(opened.st_dev,opened.st_ino) and named.st_nlink==1,
                 'prefetch-receipt-drift')
            self.check(deadline=False)
            try: os.stat('prefetch-receipt.json',dir_fd=self.rootfd,follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise ValueError('prefetch-receipt-exists')
            os.rename(temporary,'prefetch-receipt.json',src_dir_fd=self.rootfd,dst_dir_fd=self.rootfd)
            os.fsync(self.rootfd);self.check(deadline=False)
        finally:
            try: os.close(fd)
            finally:
                try: os.unlink(temporary,dir_fd=self.rootfd)
                except FileNotFoundError: pass
    def mkstemp(self, prefix, suffix, dir):
        self.check()
        directory = Path(dir)
        if directory == self.cache:
            row = self.local.row
            need(prefix == row['filename'] + '.' and suffix == '.partial', 'prefetch-temp-policy')
            fdroot = self.cachefd
        else:
            need(directory == self.root and prefix == 'acquisition.' and suffix == '.partial', 'prefetch-temp-policy')
            fdroot = self.rootfd
        name = prefix + secrets.token_hex(16) + suffix
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fdroot)
        info = os.fstat(fd)
        if directory == self.cache:
            self.local.inode = (info.st_dev, info.st_ino)
        return fd, str(directory / name)
    def fetch(self, original, row, cache):
        try:
            return self._fetch(original, row, cache)
        except BaseException as error:
            with self.lock:
                if self.first_failure is None: self.first_failure = refusal(error)
            raise
    def _fetch(self, original, row, cache):
        self.check(); name = row['filename']
        need(Path(cache) == self.cache, 'prefetch-cache-binding')
        with self.lock:
            need(name not in self.started and not (self.cache / name).exists()
                 and not (self.cache / name).is_symlink(), 'prefetch-existing-cache')
            self.started.add(name)
        self.local.row, self.local.inode = row, None
        target = original(row, self.cache)
        self.check(); info = target.lstat()
        need(target == self.cache / name and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == row['size'] and (info.st_dev, info.st_ino) == self.local.inode, 'prefetch-target-binding')
        with self.lock: self.loans[name] = self.local.inode
        return target
    def verify(self, items):
        self.check()
        enumeration = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.cachefd)
        try: names = set(os.listdir(enumeration))
        finally: os.close(enumeration)
        need(names == {row['filename'] for row in items}
             and set(self.loans) == {row['filename'] for row in items}, 'prefetch-cache-set')
        for row in items:
            self.check(); path = self.cache / row['filename']; before = path.lstat()
            fd = os.open(row['filename'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.cachefd)
            try:
                opened = os.fstat(fd); digest, count = hashlib.sha256(), 0
                need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_uid == os.getuid()
                    and opened.st_gid == os.getgid() and stat.S_IMODE(opened.st_mode) == 0o600
                    and (opened.st_dev, opened.st_ino) == self.loans[row['filename']], 'prefetch-final-inode')
                while chunk := os.read(fd, 1024**2):
                    live(self.deadline); count += len(chunk)
                    need(count <= row['size'], 'prefetch-final-size'); digest.update(chunk)
                after, named = os.fstat(fd), path.lstat()
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
                need(count == row['size'] and digest.hexdigest() == row['sha256'] and
                     all(getattr(before, k) == getattr(item, k) for item in (opened, after, named) for k in fields), 'prefetch-final-pin')
            finally: os.close(fd)
        self.check()


def run(config):
    need(type(config) is dict and set(config) == CONFIG_KEYS, 'prefetch-config-keys')
    live(config['deadline_at'])
    need(Path(config['source']) == BASE and type(config['source_commit']) is str
        and re.fullmatch('[0-9a-f]{40}', config['source_commit']) and os.environ.get('GITHUB_SHA') == config['source_commit']
        and all(type(config[k]) is str and re.fullmatch('[0-9a-f]{64}', config[k])
                for k in ('packet_sha256', 'contract_sha256', 'native_sha256', 'inputs_sha256', 'clock_sha256'))
        and all(type(config[k]) is str and re.fullmatch('[0-9]{1,20}', config[k])
                and config[k] == os.environ.get('GITHUB_RUN_ID' if k == 'run_id' else 'GITHUB_RUN_ATTEMPT')
                for k in ('run_id', 'run_attempt')), 'prefetch-config-binding')
    raw = read(BASE / 'contract.py')
    need(hashlib.sha256(raw).hexdigest() == config['contract_sha256'], 'prefetch-contract-pin')
    c = module('prefetch_contract', BASE / 'contract.py', raw)
    inputs, packet = c.verify(BASE, config['packet_sha256'], config['deadline_at'])
    need(config['inputs_sha256'] == c.INPUTS and config['native_sha256'] == c.NATIVE, 'prefetch-input-pin')
    items = list(inputs['keyring_files'])
    for row in [inputs['rootfs'], *inputs['packages']]:
        items += [row, {'filename': row['filename']+'.sig', 'url':row['url']+'.sig',
                        'size':row['signature_size'], 'sha256':row['signature_sha256']}]
    need(len(items) == 501 and len({r['filename'] for r in items}) == 501
        and all(type(r['size']) is int and 0 <= r['size'] <= 2*1024**3 for r in items), 'prefetch-items')
    root = Path(config['jobroot']); saved_path = list(sys.path); previous = sys.modules.get('package_checks')
    receipt = {'schema_version':1,'status':'FAIL','signature_authentication':'NOT RUN','native_build':'NOT RUN',
        'source_commit':config['source_commit'],'clock_sha256':config['clock_sha256'],
        'packet_sha256':config['packet_sha256'],'inputs_sha256':c.INPUTS,'native_sha256':c.NATIVE,
        'run_id':config['run_id'],'run_attempt':config['run_attempt'],'cancelled':False,'first_failure':None,
        'deadline_at':config['deadline_at'],
        'counts':{'total':501,'pass':0,'fail':0,'pending':501},'pinned_bytes':sum(r['size'] for r in items),
        'cache_verified':False,'redirect_policy':'REJECT ALL','deadline_scope':'parent hard cutoff plus per-I/O checks'}
    custody = None
    try:
        custody = Custody(root, config['cache'], config['deadline_at'])
        def load(name, relative):
            path = BASE / relative; raw = c.read(path, deadline=config['deadline_at'])
            need(c.sha(raw) == packet['files'][relative]['sha256'], 'prefetch-source-drift')
            return module(name, path, raw)
        sys.modules['package_checks'] = load('package_checks', 'native/scripts/checks/package_checks.py')
        native = load('prefetch_native', 'native/scripts/ci/native_arm.py')
        transport = Transport(items, config['deadline_at'])
        native.urllib = SimpleNamespace(request=SimpleNamespace(urlopen=transport.urlopen), error=urllib.error)
        native.tempfile = SimpleNamespace(mkstemp=custody.mkstemp)
        original = native.fetch
        native.fetch = lambda row, cache:custody.fetch(original, row, cache)
        result = native.acquire(items, custody.cache, root)
        receipt['counts'] = dict(result['counts'])
        need(result['acquisition'] == 'PASS' and receipt['counts'] == {'total':501,'pass':501,'fail':0,'pending':0}, 'prefetch-acquisition')
        custody.verify(items); receipt.update(status='PASS',cache_verified=True)
    except BaseException as error:
        receipt['status'] = 'FAIL'
        receipt['cancelled'] = isinstance(error, KeyboardInterrupt)
        receipt['first_failure'] = (custody.first_failure if custody is not None else None) or refusal(error)
        try:
            observed = decode(read(root / 'acquisition.json', 2*1024**2))
            counts = observed['counts']
            need(set(counts) == {'total','pass','fail','pending'} and all(type(v) is int and 0<=v<=501 for v in counts.values())
                and counts['total']==501 and counts['pass']+counts['fail']+counts['pending']==501, 'prefetch-counts')
            receipt['counts'] = counts
        except BaseException: pass
    finally:
        sys.path[:] = saved_path
        if previous is None: sys.modules.pop('package_checks', None)
        else: sys.modules['package_checks'] = previous
        # The parent observes actual exit/deadline and never admits a stale PASS.
        if time.monotonic() >= config['deadline_at']:
            receipt.update(status='FAIL',first_failure=receipt['first_failure'] or 'prefetch-deadline')
        if custody is not None:
            try: custody.save_receipt(receipt)
            finally:
                try: custody.close()
                except BaseException:
                    receipt.update(status='FAIL', first_failure=receipt['first_failure'] or 'prefetch-disposal')
    return int(receipt['status'] != 'PASS')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True); parser.add_argument('--config-sha256',required=True)
    args=parser.parse_args()
    try:
        raw=read(args.config,65536)
        need(re.fullmatch('[0-9a-f]{64}',args.config_sha256) and hashlib.sha256(raw).hexdigest()==args.config_sha256,'prefetch-config-pin')
        return run(decode(raw))
    except BaseException:
        print('prefetch-refused',file=sys.stderr); return 1


if __name__=='__main__': raise SystemExit(main())
