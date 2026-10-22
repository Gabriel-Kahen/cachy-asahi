#!/usr/bin/env python3
"""Fetch/reconstruct pinned private runner inputs as data; never execute sources.

No Cargo/compiler/package/installer/container/upload operation. The original
archive contains ungranted artwork and the full vendor has unresolved notices:
all source/cache bytes stay private and may not be published by this program.
"""
import argparse
import copy
from contextlib import contextmanager
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ORIGINAL_URL = 'https://codeload.github.com/CachyOS/cachy-update/tar.gz/e2b1b7144be71cf392809f48d1440f8da1d9c81a'
ORIGINAL_SHA = 'b5e4ca8f2f779d1a877ab7a815cbb40a9a9cecf16ac59852eb7a3072fb3a261d'
ORIGINAL_SIZE = 176500
ARCHIVE_TOTAL = 43696783
VENDOR_SHA = 'e44dd795d5c392e37f44f63e041f25055924b75784b990788b24a80b442d5a9c'
SANITIZED_SHA = '86196b4d7be8336c321e3a033984a17e602a5e70ec5ea11126d1a249ddda8eab'
VENDOR_BYTES = 323117153
TAR_INPUTS = {'sanitized': ('cb1a9d4d27a7105fedeee561704da7dee217bb994fe13e28d4df0991ce890c7f', 1044480),
              'vendor': ('56c18f093e6d0fe5454b6998b9b4f647bdfa9442e3221250a140a479ccd10ab3', 323092480)}
TRANSPORT = 'gzip-stored-v1'
LIMITS = {'wall_seconds': 900, 'cpu_seconds': 600, 'address_space_bytes': 2 * 1024**3,
          'file_bytes': 512 * 1024**2, 'download_bytes': ORIGINAL_SIZE + ARCHIVE_TOTAL,
          'retained_bytes': 1024**3, 'expanded_source_bytes': 384 * 1024**2,
          'source_members': 200000}


class MaterializeError(ValueError):
    def __init__(self, reason, code='input-validation'):
        self.code=code
        super().__init__(reason)


class Cancelled(BaseException):
    pass


def need(value, reason, code='input-validation'):
    if not value:
        raise MaterializeError(reason,code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'input symlink refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, 'bounded regular input required')
        chunks, size = [], 0
        while block := os.read(fd, min(65536, limit + 1 - size)):
            chunks.append(block);size += len(block)
            need(size <= limit, 'input read exceeded bound')
        need(size == info.st_size, 'input changed while reading')
        return b''.join(chunks)
    finally:
        os.close(fd)


def load(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def save(path, value):
    """Atomic durable status independent of private source/log files."""
    fd, name = tempfile.mkstemp(prefix='.status-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2);stream.write('\n')
            stream.flush();os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def verify_pins(expected):
    need(re.fullmatch('[0-9a-f]{64}', expected or ''), 'external runner-input lock hash required')
    raw = read(HERE / 'runner-inputs.lock.json', 1024 * 1024)
    need(sha(raw) == expected, 'runner-input lock differs from external pin')
    pins = load(raw)
    need(pins['schema_version'] == 1 and pins['original_sha256'] == ORIGINAL_SHA
         and pins['sanitized_sha256'] == SANITIZED_SHA and pins['vendor_sha256'] == VENDOR_SHA
         and pins.get('transport') == TRANSPORT and pins.get('vendor_bytes') == VENDOR_BYTES,
         'source identity constraints differ')
    for name, expected_file in pins['files_sha256'].items():
        need(isinstance(name, str) and not name.startswith('/') and '\\' not in name
             and all(part not in ('', '.', '..') for part in name.split('/'))
             and re.fullmatch('[0-9a-f]{64}', expected_file), 'unsafe local source pin')
        need(sha(read(HERE / name, 16 * 1024 * 1024)) == expected_file, 'pinned generator/source file differs')
    required = {'audit-source.py', 'audit-cargo.py', 'PKGBUILD', '.SRCINFO', 'NOTICE', 'ICON-LICENSE',
                'source-audit.json', 'cargo-audit.json', 'additional-cargo-licenses.json', 'portable-gzip.py'}
    need(required <= set(pins['files_sha256']), 'complete source generator pin set required')
    return pins


def module(filename):
    spec = importlib.util.spec_from_file_location('materializer_' + filename.replace('-', '_'), HERE / filename)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


@contextmanager
def portable_encoding(portable):
    """Change only gzip transport in this isolated data worker; restore on failure."""
    original = gzip.GzipFile
    gzip.GzipFile = portable.GzipFile
    try:
        yield
    finally:
        gzip.GzipFile = original


def tar_identity(path, kind):
    expected, size = TAR_INPUTS[kind]
    digest, expanded = hashlib.sha256(), 0
    with gzip.open(path, 'rb') as stream:
        while block := stream.read(65536):
            expanded += len(block)
            need(expanded <= size, 'decoded tar size differs', kind + '-reproduction')
            digest.update(block)
    need(expanded == size and digest.hexdigest() == expected,
         'decoded original tar bytes differ', kind + '-reproduction')
    return expected


class ExactHTTPS(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        before, after = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(url)
        need(after.scheme == 'https' and after.netloc == before.netloc and not after.username
             and not after.password, 'HTTPS redirect host differs')
        return super().redirect_request(request, response, code, message, headers, url)


def fetch(url, destination, expected_sha, expected_size, deadline, opener=None):
    parsed = urllib.parse.urlsplit(url)
    need(parsed.scheme == 'https' and parsed.netloc in ('codeload.github.com', 'static.crates.io')
         and not parsed.username and not parsed.password and not parsed.fragment, 'pinned HTTPS source only')
    need(isinstance(expected_size, int) and 0 < expected_size <= 32 * 1024**2
         and re.fullmatch('[0-9a-f]{64}', expected_sha), 'finite download pin required')
    need(not destination.exists() and not destination.is_symlink(), 'fresh download required')
    partial = destination.with_name(destination.name + '.partial')
    opener = opener or urllib.request.build_opener(ExactHTTPS())
    per_file = min(deadline, time.monotonic() + 60)
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'cachy-asahi-private-materializer/1'})
        with opener.open(request, timeout=min(20, max(.1, per_file - time.monotonic()))) as response, partial.open('xb') as stream:
            need(response.status == 200 and urllib.parse.urlsplit(response.url).netloc == parsed.netloc, 'source response differs')
            size, digest = 0, hashlib.sha256()
            while True:
                need(time.monotonic() < per_file, 'download deadline')
                block = response.read(65536)
                if not block: break
                size += len(block)
                need(size <= expected_size, 'download exceeds exact frozen bytes')
                digest.update(block);stream.write(block)
            need(size == expected_size and digest.hexdigest() == expected_sha, 'download size/checksum differs','download-integrity')
        partial.chmod(0o600);partial.rename(destination)
        return size
    finally:
        partial.unlink(missing_ok=True)


def disk_bound(root):
    total = count = 0
    for path in root.rglob('*'):
        count += 1
        need(count <= LIMITS['source_members'], 'retained member bound')
        need(not path.is_symlink(), 'private data symlink refused')
        info = path.stat()
        need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'private data special file refused')
        if path.is_file(): total += info.st_size
        need(total <= LIMITS['retained_bytes'], 'aggregate private data bound')
    return total


def reconstruct(output, pins_sha, archive_cache=None):
    ordinary_user()
    need(output.is_absolute() and output.is_relative_to('/tmp') and output.resolve(strict=True)==output
         and output.is_dir() and output.stat().st_uid==os.getuid()
         and stat.S_IMODE(output.stat().st_mode)==0o700,'private owned canonical child output required')
    need((output/'materializer-result.json').is_file(),'fresh parent launch receipt required')
    parent_receipt=load(read(output/'materializer-result.json',1024*1024))
    need(parent_receipt.get('schema_version')==1 and parent_receipt.get('scope')=='private source materialization'
         and parent_receipt.get('status')=='RUNNING' and parent_receipt.get('phase')=='launch-data-worker'
         and parent_receipt.get('runner_inputs_sha256')==pins_sha,'fresh parent launch receipt required')
    pins = verify_pins(pins_sha)  # Before dynamic imports or any network input.
    source, cargo, portable = module('audit-source.py'), module('audit-cargo.py'), module('portable-gzip.py')
    receipt = {'schema_version': 1, 'scope': 'private source materialization', 'status': 'RUNNING',
               'phase': 'fetch-original', 'runner_inputs_sha256': pins_sha,
               'source_hashes': {'original': ORIGINAL_SHA, 'sanitized': SANITIZED_SHA, 'vendor': VENDOR_SHA},
               'downloads': {'count': 0, 'bytes': 0}, 'limits': LIMITS,
               'generator': {'python': platform.python_version(), 'zlib_build': zlib.ZLIB_VERSION,
                             'zlib_runtime': zlib.ZLIB_RUNTIME_VERSION, 'transport': TRANSPORT},
               'native_compilation': 'NOT RUN', 'publication': 'NOT ACCEPTED',
               'public_export_policy': 'Only schema-projected status/hash receipts; no original artwork, vendor, source caches, binaries or raw logs.'}
    save(output / 'materializer-result.json', receipt)
    deadline = time.monotonic() + LIMITS['wall_seconds']
    cache = output / 'private-cache';cache.mkdir(mode=0o700)
    for name in ('archives', 'vendor'): (cache / name).mkdir(mode=0o700)
    try:
        original = cache / 'original.tar.gz'
        if archive_cache:
            data = read(archive_cache / 'original.tar.gz', 1024 * 1024)
            need(len(data) == ORIGINAL_SIZE and sha(data) == ORIGINAL_SHA, 'offline original differs')
            original.write_bytes(data)
        else:
            receipt['downloads']['bytes'] += fetch(ORIGINAL_URL, original, ORIGINAL_SHA, ORIGINAL_SIZE, deadline)
            receipt['downloads']['count'] += 1
        files = source.inspect(read(original, 1024 * 1024))
        lock = files['src/tray/Cargo.lock'][0]
        entries = cargo.lock_entries(lock)
        registry = [entry for entry in entries if 'source' in entry]
        frozen = load(read(HERE / 'cargo-audit.json', 8 * 1024 * 1024))
        ledger = {(r['name'], r['version']): r for r in frozen['registry_sources']}
        need(len(entries) == 168 and len(registry) == len(ledger) == 167
             and sum(r['archive_size'] for r in ledger.values()) == ARCHIVE_TOTAL, 'complete fixed archive ledger required')
        need(set(ledger) == {(entry['name'], entry['version']) for entry in registry}, 'registry input set differs')
        manifest = cache / 'Cargo.toml';manifest.write_bytes(files['src/tray/Cargo.toml'][0])
        need(sha(manifest.read_bytes()) == cargo.LOCAL_MANIFEST_SHA256, 'tray manifest differs')
        sanitized = output / 'private-sanitized'
        receipt['phase']='regenerate-sanitized'
        save(output / 'materializer-result.json',receipt)
        with portable_encoding(portable):
            generated = source.prepare(original, HERE, sanitized)
        receipt['regenerated']={'sanitized_sha256':generated['sanitized_sha256'],
                                'sanitized_tar_sha256':tar_identity(sanitized / generated['sanitized_source'], 'sanitized')}
        need(generated['sanitized_sha256'] == SANITIZED_SHA
             and read(sanitized / 'source-audit.json', 1024 * 1024) == read(HERE / 'source-audit.json', 1024 * 1024), 'sanitized archive/evidence differs','sanitized-reproduction')
        rows, expanded = [], 0
        for entry in registry:
            need(time.monotonic() < deadline, 'whole materializer deadline')
            row = ledger[(entry['name'], entry['version'])]
            filename = entry['name'] + '-' + entry['version'] + '.crate'
            receipt.update(phase='fetch-registry', completed_registry=len(rows))
            save(output / 'materializer-result.json', receipt)
            need(row['archive_sha256'] == entry['checksum'], 'registry checksum pin differs')
            destination = cache / 'archives' / filename
            if archive_cache:
                data = read(archive_cache / 'archives' / filename, cargo.MAX_ARCHIVE)
                need(len(data) == row['archive_size'] and sha(data) == entry['checksum'], 'offline archive differs')
                destination.write_bytes(data);destination.chmod(0o600)
            else:
                url = 'https://static.crates.io/crates/' + entry['name'] + '/' + filename
                receipt['downloads']['bytes'] += fetch(url, destination, entry['checksum'], row['archive_size'], deadline)
                receipt['downloads']['count'] += 1
            need(receipt['downloads']['bytes'] <= LIMITS['download_bytes'], 'aggregate download bound')
            current = cargo.audit_entry(entry, cache, offline=True)
            # Match every recomputed hash/source/notice/helper record against the frozen audit.
            candidate_row, frozen_row = copy.deepcopy(current), copy.deepcopy(row)
            for value in (candidate_row, frozen_row):
                value.pop('retained_archive');value.pop('retained_source')
            need(candidate_row == frozen_row, 'reconstructed registry evidence differs')
            expanded += sum(p.stat().st_size for p in Path(current['retained_source']).rglob('*') if p.is_file())
            need(expanded <= LIMITS['expanded_source_bytes'], 'aggregate expanded source bound')
            rows.append(current)
            if len(rows) % 16 == 0: disk_bound(output)
        reconstructed = copy.deepcopy(frozen);reconstructed['registry_sources'] = sorted(rows, key=lambda r:(r['name'],r['version']))
        need(cargo.portable_report(reconstructed) == cargo.portable_report(frozen), 'portable complete audit differs')
        receipt.update(phase='regenerate-vendor', completed_registry=167)
        save(output / 'materializer-result.json', receipt)
        with portable_encoding(portable):
            bundle = cargo.vendor_bundle(frozen, lock, cache)
        receipt['regenerated'].update(vendor_sha256=bundle['sha256'],vendor_bytes=bundle['size'],registry_sources=167,
                                      vendor_tar_sha256=tar_identity(Path(bundle['path']), 'vendor'))
        need(bundle['sha256'] == VENDOR_SHA and bundle['size'] == VENDOR_BYTES,
             'portable vendor bytes differ from reviewed transport pin','vendor-reproduction')
        # Also bind directly to the reviewed PKGBUILD/.SRCINFO, not just duplicated constants.
        metadata = {}
        for line in read(HERE / '.SRCINFO',1024 * 1024).decode().splitlines():
            name,separator,value = line.strip().partition(' = ')
            if separator: metadata.setdefault(name,[]).append(value)
        need(metadata['sha256sums'][:2] == [SANITIZED_SHA,VENDOR_SHA]
             and metadata['source'][:2] == [generated['sanitized_source'],'cachy-update-vendor.tar.gz'], 'reviewed recipe archive pins differ')
        receipt.update(status='PASS', phase='complete', retained_private_bytes=disk_bound(output),
                       publication='NOT ACCEPTED', native_compilation='NOT RUN')
        return {'source': sanitized / generated['sanitized_source'], 'vendor': Path(bundle['path'])}
    except BaseException as error:
        receipt.update(status='CANCELLED' if isinstance(error, Cancelled) else 'FAIL', phase=receipt['phase'], error_type=type(error).__name__,
                       failure_code='cancellation' if isinstance(error,Cancelled) else getattr(error,'code','data-worker-failure'))
        raise
    finally:
        save(output / 'materializer-result.json', receipt)


def ordinary_user():
    need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0, 'ordinary positive matching real/effective UID/GID required')


def child_limits():
    os.umask(0o077)
    for kind, limit in ((resource.RLIMIT_AS, LIMITS['address_space_bytes']), (resource.RLIMIT_CPU, LIMITS['cpu_seconds']),
                        (resource.RLIMIT_FSIZE, LIMITS['file_bytes']), (resource.RLIMIT_NOFILE,128), (resource.RLIMIT_CORE,0)):
        resource.setrlimit(kind,(limit,limit))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(Cancelled()))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(MaterializeError('whole materializer deadline')))
    signal.alarm(LIMITS['wall_seconds'])


def run(output, pins_sha, archive_cache=None):
    ordinary_user()
    verify_pins(pins_sha)
    need(output.is_absolute() and output.is_relative_to('/tmp') and output.parent.resolve(strict=True) == output.parent
         and not output.exists() and not output.is_symlink(), 'fresh canonical private /tmp output required')
    output.mkdir(mode=0o700)
    receipt = {'schema_version':1,'scope':'private source materialization','status':'RUNNING',
               'phase':'launch-data-worker','runner_inputs_sha256':pins_sha,'native_compilation':'NOT RUN',
               'publication':'NOT ACCEPTED','limits':LIMITS}
    save(output/'materializer-result.json',receipt)
    command = [sys.executable,'-I',str(Path(__file__).resolve()),'--child','--output',str(output),'--pins-sha256',pins_sha]
    if archive_cache: command += ['--archive-cache',str(archive_cache)]
    child, failure, cleanup = None,None,[]
    cancel_signals = {signal.SIGTERM, signal.SIGINT}
    if signal.getsignal(signal.SIGALRM) not in (signal.SIG_DFL, signal.SIG_IGN):
        cancel_signals.add(signal.SIGALRM)
    deferred = []
    def defer(signum, frame):
        if not deferred: deferred.append(signum)
    previous = {signum:signal.getsignal(signum) for signum in cancel_signals}
    try:
        # Install non-raising handlers before owning a child. Cancellation is
        # checked at bounded wait points; teardown never changes handlers.
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, cancel_signals)
        try:
            for signum in cancel_signals: signal.signal(signum,defer)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
        with (output/'private-worker.stdout').open('wb') as stdout,(output/'private-worker.stderr').open('wb') as stderr:
            if deferred: raise Cancelled()
            # A pending cancellation may be delivered only after the owned
            # process handle is recorded. The single-threaded child restores
            # its prior signal mask before exec, so cancellation reaches it.
            prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, cancel_signals)
            try:
                child = subprocess.Popen(command,stdout=stdout,stderr=stderr,start_new_session=True,
                    preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask),
                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','HOME':str(output),'PYTHONDONTWRITEBYTECODE':'1'})
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
            deadline = time.monotonic()+LIMITS['wall_seconds']+10
            while True:
                if deferred: raise Cancelled()
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise subprocess.TimeoutExpired(command,LIMITS['wall_seconds']+10)
                try:
                    child.wait(timeout=min(.1,remaining))
                    break
                except subprocess.TimeoutExpired:
                    pass
        if deferred: raise Cancelled()
        receipt = load(read(output/'materializer-result.json',1024*1024))
        need(child.returncode == 0 and receipt['status']=='PASS','bounded data worker failed')
    except BaseException as error:
        failure = error
        try: receipt=load(read(output/'materializer-result.json',1024*1024))
        except BaseException: pass
        receipt.update(status='CANCELLED' if isinstance(error,Cancelled) else 'FAIL',error_type=type(error).__name__)
    finally:
        # The already-installed handlers defer every teardown cancellation.
        try:
            if child is not None:
                try: os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                except BaseException as error: cleanup.append(type(error).__name__)
                try: child.wait(timeout=3)
                except BaseException as error: cleanup.append(type(error).__name__)
            if deferred:
                receipt.update(status='CANCELLED',cancel_signal=deferred[0],error_type='Cancelled')
                if failure is None: failure=Cancelled()
            if cleanup: receipt.update(status='FAIL',cleanup_errors=cleanup)
            if child is not None: receipt['worker_exit_code']=child.returncode
            save(output/'materializer-result.json',receipt)
            # A signal delivered during the durable commit must supersede PASS.
            if deferred:
                receipt.update(status='FAIL' if cleanup else 'CANCELLED',cancel_signal=deferred[0],error_type='Cancelled')
                if failure is None: failure=Cancelled()
                save(output/'materializer-result.json',receipt)
        finally:
            prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK,cancel_signals)
            try:
                pending = signal.sigpending() & cancel_signals
                if pending and not deferred: deferred.append(int(next(iter(pending))))
                if deferred:
                    receipt.update(status='FAIL' if cleanup else 'CANCELLED',cancel_signal=deferred[0],error_type='Cancelled')
                    if failure is None: failure=Cancelled()
                    save(output/'materializer-result.json',receipt)
                for signum,handler in previous.items(): signal.signal(signum,handler)
            finally:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK,prior_mask)
                except BaseException as error:
                    # A signal delivered while restoring the caller must also
                    # supersede success after the child has been killed/reaped.
                    receipt.update(status='FAIL' if cleanup else 'CANCELLED',error_type='Cancelled')
                    failure=error
                    blocked=signal.pthread_sigmask(signal.SIG_BLOCK,cancel_signals)
                    try: save(output/'materializer-result.json',receipt)
                    finally: signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
    if failure is not None: raise failure
    need(not cleanup,'data worker teardown failed')
    return receipt


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--pins-sha256',required=True)
    parser.add_argument('--archive-cache',type=Path,help='optional readonly checksum-bound input cache; default fetches HTTPS')
    parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(Cancelled()))
    signal.signal(signal.SIGINT,lambda *_:(_ for _ in ()).throw(Cancelled()))
    try:
        if args.child:
            ordinary_user();child_limits()
            reconstruct(args.output.absolute(),args.pins_sha256,args.archive_cache)
        else:
            result=run(args.output.absolute(),args.pins_sha256,args.archive_cache)
            print(json.dumps({'status':result['status'],'registry_sources':167,'source_hashes':result.get('source_hashes'),
                              'publication':'NOT ACCEPTED','native_compilation':'NOT RUN'},sort_keys=True))
    except BaseException as error:
        print(json.dumps({'status':'CANCELLED' if isinstance(error,Cancelled) else 'FAIL','error_type':type(error).__name__,
                          'publication':'NOT ACCEPTED','native_compilation':'NOT RUN'}))
        raise SystemExit(1)
