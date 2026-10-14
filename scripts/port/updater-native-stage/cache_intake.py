"""Original 501 transport only. Root owns registration, cutoff and 249 authentication."""
import ast
import base64
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse

PINS = {
    'native': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    'controller': 'bbe279edb9743f98e8feed8365859abc221b2665924658e600775c902e18299e',
    'packet': '9d5a7dc25fd44e127c457c72addb28272b1eb1f5391c4c5b8d5b0a226a3be048',
    'inputs': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',
}
HOSTS = {'ca.us.mirror.archlinuxarm.org', 'raw.githubusercontent.com'}
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(value, reason):
    if not value:
        raise ValueError(reason)


class Guard:
    """One original E, first observed cause, retained allocations before postcheck."""
    def __init__(self, end, check):
        need(type(end) in (int, float) and math.isfinite(end) and callable(check), 'intake-clock')
        self.end, self.check, self.last, self.first = end, check, None, None
        self.resources = {}
        self.allocations = 0

    def fail(self, error):
        if self.first is None:
            self.first = error
        self.first.retained_intake_resources = self.resources
        return self.first

    def live(self):
        if self.first is not None:
            raise self.first
        try:
            self.check()
            now = time.monotonic()
            need(type(now) in (int, float) and math.isfinite(now)
                 and (self.last is None or now >= self.last) and now < self.end, 'intake-deadline')
            self.last = now
        except BaseException as error:
            raise self.fail(error)

    def invoke(self, function, *args, **kwargs):
        self.live()
        name = getattr(function, '__name__', '')
        slot = None
        if function in (os.open, os.fdopen, tempfile.mkstemp) or name in ('open', 'urlopen', 'getresponse', 'HTTPSConnection'):
            self.allocations += 1
            slot = ('allocation', self.allocations)
            self.resources[slot] = {'operation': name, 'identity': 'UNKNOWN'}
        try:
            value = function(*args, **kwargs)
            # Register before a potentially failing postcondition. These are
            # uncertainty records, never inferred absence or automatic disposal.
            bound = getattr(function, '__self__', None)
            if function is os.open:
                self.resources[('fd', value)] = value
            elif function is tempfile.mkstemp:
                self.resources[('fd', value[0])] = value[0]
            elif function is os.fdopen:
                self.resources.pop(('fd', args[0]), None)
                self.resources[('object', id(value))] = value
            elif name in ('open', 'urlopen', 'getresponse', 'HTTPSConnection'):
                self.resources[('object', id(value))] = value
            elif function is os.close:
                self.resources.pop(('fd', args[0]), None)
            elif name in ('close', '__exit__'):
                self.resources.pop(('object', id(bound)), None)
            if slot is not None:
                self.resources.pop(slot)
            self.live()
            if name != 'getresponse' and hasattr(value, '__enter__') and hasattr(value, '__exit__'):
                return Context(self, value)
            return value
        except BaseException as error:
            raise self.fail(error)


class Context:
    def __init__(self, guard, value):
        self.guard, self.value = guard, value

    def __enter__(self):
        value = self.guard.invoke(self.value.__enter__)
        value = value.value if isinstance(value, Context) else value
        return StreamCalls(self.guard, value) if hasattr(value, 'write') or hasattr(value, 'read') else value

    def __exit__(self, kind, error, trace):
        if error is not None:
            self.guard.fail(error)
        # No late disposal. The first cause and retained object survive cutoff.
        return self.guard.invoke(self.value.__exit__, kind, error, trace)


class StreamCalls:
    """Also gate writes made inside json.dump, not just its outer invocation."""
    def __init__(self, guard, value):
        self.guard, self.value = guard, value

    def __getattr__(self, name):
        value = getattr(self.value, name)
        return (lambda *args, **kwargs: self.guard.invoke(value, *args, **kwargs)) if callable(value) else value


class Calls(ast.NodeTransformer):
    def visit_Call(self, node):
        self.generic_visit(node)
        return ast.copy_location(ast.Call(ast.Attribute(ast.Name('_guard', ast.Load()),
                    'invoke', ast.Load()), [node.func, *node.args], node.keywords), node)


def selected(raw, names, namespace, guard):
    """Authenticate the entire source first; compile definitions only, no imports."""
    tree = guard.invoke(ast.parse, raw)
    nodes = [node for node in tree.body if
             isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
             or isinstance(node, ast.Assign) and any(isinstance(t, ast.Name)
                 and t.id in names for t in node.targets)]
    found = {node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    found.update(t.id for node in nodes if isinstance(node, ast.Assign)
                 for t in node.targets if isinstance(t, ast.Name))
    need(found == set(names), 'intake-definition-membership')
    code = guard.invoke(compile, ast.fix_missing_locations(Calls().visit(
        ast.Module(nodes, []))), '<authenticated-intake-definitions>', 'exec')
    namespace['_guard'] = guard
    guard.invoke(exec, code, namespace)


class Future:
    def __init__(self, guard, function, args):
        self.guard, self.function, self.args = guard, function, args

    def result(self):
        return self.guard.invoke(self.function, *self.args)


class Sequential:
    """Original acquire futures API, no threads or concurrent namespace writers."""
    def __init__(self, guard, max_workers):
        need(max_workers == 4, 'intake-original-executor')
        self.guard = guard

    def __enter__(self):
        self.guard.live()
        return self

    def __exit__(self, *args):
        self.guard.live()

    def submit(self, function, *args):
        self.guard.live()
        return Future(self.guard, function, args)


class Transport:
    """Exact selected HTTPS URLs, no proxies or redirects, each action under E."""
    def __init__(self, guard, items):
        self.guard = guard
        self.urls = {row['url']: row for row in items}
        need(len(self.urls) == len(items), 'intake-url-membership')
        for url in self.urls:
            parsed = guard.invoke(urllib.parse.urlsplit, url)
            need(type(url) is str and len(url) <= 4096 and parsed.scheme == 'https'
                 and parsed.hostname in HOSTS and parsed.port is None
                 and parsed.username is None and parsed.password is None
                 and not parsed.query and not parsed.fragment and parsed.path.startswith('/')
                 and all(33 <= ord(c) < 127 for c in url), 'intake-url-policy')
        need(not any(k in os.environ for k in ('SSL_CERT_FILE', 'SSL_CERT_DIR', 'SSLKEYLOGFILE')),
             'intake-tls-environment')
        self.context = guard.invoke(ssl.create_default_context)

    def left(self):
        self.guard.live()
        left = self.guard.end - time.monotonic()
        need(left > 0, 'intake-deadline')
        return min(30.0, left)

    def urlopen(self, url, timeout=60):
        g = self.guard
        g.live()
        need(url in self.urls and type(timeout) in (int, float) and 0 < timeout <= 60,
             'intake-url-refused')
        parsed = g.invoke(urllib.parse.urlsplit, url)
        connection = g.invoke(http.client.HTTPSConnection, parsed.hostname,
                              timeout=min(timeout, self.left()), context=self.context)
        g.invoke(connection.connect)
        sock = connection.sock
        need(sock is not None, 'intake-socket')
        g.invoke(sock.settimeout, self.left())
        g.invoke(connection.request, 'GET', parsed.path, headers={'Accept-Encoding': 'identity'})
        g.invoke(sock.settimeout, self.left())
        response = g.invoke(connection.getresponse)
        g.resources[('object', id(response))] = response
        need(response.status == 200, 'intake-http-status')
        need(g.invoke(response.getheader, 'Content-Encoding') in (None, 'identity'), 'intake-http-encoding')
        length = g.invoke(response.getheader, 'Content-Length')
        need(length is None or re.fullmatch('[0-9]{1,10}', length) is not None
             and int(length) == self.urls[url]['size'], 'intake-http-length')
        return Response(self, response, connection, sock, url, self.urls[url]['size'])


class Response:
    def __init__(self, transport, response, connection, sock, url, size):
        self.transport, self.response, self.connection, self.sock = transport, response, connection, sock
        self.url, self.size, self.count = url, size, 0

    def __enter__(self):
        self.transport.guard.live()
        return self

    def __exit__(self, *args):
        g = self.transport.guard
        g.invoke(self.response.close)
        g.invoke(self.connection.close)

    def read(self, size):
        g = self.transport.guard
        need(type(size) is int and 0 < size <= 1024**2, 'intake-read-size')
        g.invoke(self.sock.settimeout, self.transport.left())
        block = g.invoke(self.response.read1, size)
        need(type(block) is bytes, 'intake-read-type')
        self.count += len(block)
        need(self.count <= self.size, 'intake-read-bound')
        return block


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'intake-json-duplicate')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: need(False, 'intake-json-constant'))


def bounded(function):
    def run(self, *args, **kwargs):
        try:
            guard = getattr(self, 'guard', None)
            if guard is not None:
                guard.live()
            value = function(self, *args, **kwargs)
            self.guard.live()
            return value
        except BaseException as error:
            guard = getattr(self, 'guard', None)
            if guard is None:
                raise
            raise guard.fail(error)
    return run


class CacheIntake:
    @bounded
    def __init__(self, native_raw, controller_raw, packet_raw, inputs_raw, *, work_end, check):
        self.guard = g = Guard(work_end, check)
        for name, raw in (('native', native_raw), ('controller', controller_raw),
                          ('packet', packet_raw), ('inputs', inputs_raw)):
            g.live()
            need(type(raw) is bytes and len(raw) <= 2*1024**2, 'intake-source-buffer')
            need(g.invoke(hashlib.sha256, raw).hexdigest() == PINS[name], 'intake-source-pin')
            g.live()
        self.packet = g.invoke(decode, packet_raw)
        self.inputs = g.invoke(decode, inputs_raw)
        need(self.packet['metadata_pins']['scripts/ci/inputs.lock.json'] == PINS['inputs'],
             'intake-packet-input')
        need(self.packet['source_files']['scripts/ci/native_arm.py']['sha256'] == PINS['native']
             and self.packet['source_files']['scripts/ci/development/controller.py']['sha256']
             == PINS['controller'], 'intake-packet-source')
        self.items = list(self.inputs['keyring_files'])
        for row in [self.inputs['rootfs'], *self.inputs['packages']]:
            self.items.extend([row, {'filename': row['filename']+'.sig', 'url': row['url']+'.sig',
                                   'size': row['signature_size'], 'sha256': row['signature_sha256']}])
        need(len(self.items) == 501 and len({r['filename'] for r in self.items}) == 501
             and sum(r['size'] for r in self.items) <= 4*1024**3, 'intake-exact501')
        base = dict(os=os, re=re, hashlib=hashlib, json=json, tempfile=tempfile, Path=Path,
                    sys=sys, base64=base64, stat=stat, require=need,
                    within=lambda end: (need(end == g.end, 'intake-original-end'), g.live()))
        self.seed_namespace = dict(base)
        selected(controller_raw, {'OLD_FOUR_PRIVATE_PREFIX', 'OLD_FOUR_PRIVATE_ROWS',
                                  'seed_old_four_private_cache'}, self.seed_namespace, g)
        self.native = dict(base)
        self.native['json'] = SimpleNamespace(dump=self.receipt_dump)
        self.native['urllib'] = SimpleNamespace(error=urllib.error)
        self.native['concurrent'] = SimpleNamespace(futures=SimpleNamespace(
            ThreadPoolExecutor=lambda max_workers: Sequential(g, max_workers),
            as_completed=lambda futures: iter(futures)))
        selected(native_raw, {'AcquisitionError', 'input_name', 'check_pin', 'fetch', 'acquire'}, self.native, g)
        self.native['sha'] = self.file_hash
        self.state = 'NEW'
        g.live()

    def receipt_dump(self, value, stream, **options):
        raw = self.guard.invoke(json.dumps, value, **options)
        need(len(raw) <= 2*1024**2, 'intake-receipt-bound')
        for offset in range(0, len(raw), 65536):
            self.guard.invoke(stream.write, raw[offset:offset+65536])

    def identity(self, node):
        return tuple(getattr(node, field) for field in FIELDS)

    def directory(self, path):
        g = self.guard
        path = Path(path)
        need(path.is_absolute() and '..' not in path.parts, 'intake-absolute-directory')
        uid, gid = g.invoke(os.getuid), g.invoke(os.getgid)
        for parent in path.parents:
            info = g.invoke(parent.lstat)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid)
                 and (not info.st_mode & 0o022
                      or parent == Path('/tmp') and info.st_uid == info.st_gid == 0
                      and stat.S_IMODE(info.st_mode) == 0o1777), 'intake-directory-ancestor')
        info = g.invoke(path.lstat)
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and info.st_uid == uid and info.st_gid == gid, 'intake-private-directory')
        return path, self.identity(info)

    @bounded
    def seed(self, cache):
        need(self.state == 'NEW', 'intake-seed-order')
        cache, known = self.directory(cache)
        need(not self.guard.invoke(os.listdir, cache), 'intake-fresh-cache')
        self.guard.invoke(self.seed_namespace['seed_old_four_private_cache'], cache, self.packet, self.guard.end)
        need(self.identity(self.guard.invoke(cache.lstat))[:6] == known[:6], 'intake-cache-directory-drift')
        self.cache, self.cache_identity, self.state = cache, known[:6], 'SEEDED'

    def file_hash(self, path):
        g = self.guard
        path = Path(path)
        before = g.invoke(path.lstat)
        fd = g.invoke(os.open, path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        opened = g.invoke(os.fstat, fd)
        need(self.identity(before) == self.identity(opened), 'intake-open-drift')
        digest = hashlib.sha256()
        count = 0
        while True:
            block = g.invoke(os.read, fd, 1024**2)
            if not block:
                break
            count += len(block)
            need(count <= 2*1024**3, 'intake-hash-bound')
            g.invoke(digest.update, block)
        value = g.invoke(digest.hexdigest)
        after = g.invoke(os.fstat, fd)
        named = g.invoke(path.lstat)
        need(self.identity(before) == self.identity(after) == self.identity(named), 'intake-hash-drift')
        g.invoke(os.close, fd)
        return value

    @bounded
    def verify(self):
        g, cache = self.guard, self.cache
        need(self.identity(g.invoke(cache.lstat))[:6] == self.cache_identity, 'intake-cache-directory-drift')
        names = g.invoke(os.listdir, cache)
        need(len(names) == 501 and set(names) == {r['filename'] for r in self.items}, 'intake-cache-membership')
        uid, gid = g.invoke(os.getuid), g.invoke(os.getgid)
        observed = []
        for row in self.items:
            path = cache / row['filename']
            before = g.invoke(path.lstat)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_uid == uid
                 and before.st_gid == gid and before.st_size == row['size'], 'intake-cache-file')
            pin = self.file_hash(path)
            after = g.invoke(path.lstat)
            need(pin == row['sha256'] and self.identity(before) == self.identity(after), 'intake-cache-pin-drift')
            observed.append({'filename': row['filename'], 'sha256': pin, 'bytes': row['size'],
                             'identity': self.identity(after)})
        after_names = g.invoke(os.listdir, cache)
        need(len(after_names) == 501 and set(after_names) == set(names), 'intake-cache-enumeration-drift')
        need(self.identity(g.invoke(cache.lstat))[:6] == self.cache_identity, 'intake-cache-directory-drift')
        g.live()
        return observed

    @bounded
    def acquire(self, cache, evidence):
        need(self.state == 'SEEDED' and Path(cache) == self.cache, 'intake-acquire-order')
        evidence, known = self.directory(evidence)
        need(evidence != self.cache and not evidence.is_relative_to(self.cache)
             and not self.cache.is_relative_to(evidence), 'intake-directory-separation')
        need(not self.guard.invoke(os.listdir, evidence), 'intake-fresh-evidence')
        self.state = 'ACQUIRING'
        self.native['urllib'].request = SimpleNamespace(urlopen=Transport(self.guard, self.items).urlopen)
        try:
            result = self.guard.invoke(self.native['acquire'], self.items, self.cache, evidence)
            need(result['acquisition'] == 'PASS' and result['signature_authentication'] == 'NOT RUN'
                 and result['counts'] == {'total': 501, 'pass': 501, 'fail': 0, 'pending': 0}, 'intake-acquisition')
            observed = self.verify()
            need(self.identity(self.guard.invoke(evidence.lstat))[:6] == known[:6], 'intake-evidence-drift')
            need(not self.guard.resources, 'intake-resource-uncertainty')
            self.state = 'QUIESCENT'
            return {'status': 'TRANSPORT_ONLY', 'signature_authentication': 'NOT RUN',
                    'native_build': 'NOT RUN', 'objects': observed, 'work_end': self.guard.end,
                    'counts': dict(result['counts']), 'sole_writer_required': True}
        except BaseException as error:
            self.state = 'FAILED'
            raise self.guard.fail(error)
