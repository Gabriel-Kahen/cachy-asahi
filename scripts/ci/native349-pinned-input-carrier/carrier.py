#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""One exact public-input carrier; private credential exists only in fetch()."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
EXPECTED = json.loads((HERE/'expected-files.json').read_text())
BINDING = json.loads((HERE/'binding.TEMPLATE.json').read_text())
HOST_REFERENCE = json.loads((HERE/'github-host-reference.json').read_text())
SECRET = 'CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY'
REPOSITORY = 'Gabriel-Kahen/cachy-asahi-ci-inputs'
FORBIDDEN = {'fa96de743c6806092284a2069f2aa4c01234d200', '15d272e7a4647495ecf98c1afc36e62477b0eb74',
             'e1c763a74f7db48aba5e2c57757abc79233c8543', 'fd2755ce0d8972b69f32b2412d80180b36aac377'}
TOTAL = 544634853
LARGEST = 104330276
GIT = ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'maintenance.auto=false',
       '-c', 'gc.auto=0', '-c', 'core.preloadIndex=false', '-c', 'index.threads=1', '-c', 'pack.threads=1',
       '-c', 'core.autocrlf=false', '-c', 'core.attributesFile=/dev/null', '-c', 'submodule.recurse=false',
       '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'credential.helper=']


def need(value, guard):
    if not value:
        raise ValueError(guard)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for name, value in rows:
            need(name not in result, 'duplicate-json')
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite-json'))


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def key_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid)


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary-path')
    return path


def whole(path, maximum=1024**2):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum
             and not before.st_mode & 0o022, 'ordinary-bounded-file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum+1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'stable-file')
        return raw
    finally:
        os.close(fd)


def file_pin(path, maximum=LARGEST):
    path = ordinary(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum
         and not before.st_mode & 0o022, 'ordinary-public-input')
    digest = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        need(identity(before) == identity(os.fstat(stream.fileno())), 'same-open-input')
        while raw := stream.read(1024**2):
            size += len(raw); need(size <= maximum, 'public-input-budget'); digest.update(raw)
        need(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()), 'unchanged-input')
    need(size == before.st_size, 'whole-public-input')
    return dict(bytes=size, sha256=digest.hexdigest())


def binding():
    b = BINDING
    need(set(b) == {'repository', 'branch', 'commit', 'tree', 'manifest', 'ssh_host_keys', 'deploy_key_fingerprint', 'Root_receipt', 'readonly_repository_scope'}, 'binding-schema')
    need(b['repository'] == REPOSITORY and b['branch'] == 'native349-r1'
         and re.fullmatch('[0-9a-f]{40}', b['commit'] or '') and re.fullmatch('[0-9a-f]{40}', b['tree'] or ''), 'Root-carrier-CID-tree-unissued')
    for name in ('manifest', 'Root_receipt'):
        row = b[name]
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and 0 < row['bytes'] <= 1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''), 'Root-carrier-receipt-unissued')
    need(b['ssh_host_keys'] == [HOST_REFERENCE['key']] and b['readonly_repository_scope'] == REPOSITORY
         and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', b['deploy_key_fingerprint'] or ''), 'Root-host-key-deploy-scope-unissued')
    need(EXPECTED['all501_required'] is True and len(EXPECTED['files']) == 182
         and sum(r['bytes'] for r in EXPECTED['files'].values()) == TOTAL
         and max(r['bytes'] for r in EXPECTED['files'].values()) == LARGEST < 100*1024**2, 'exact182-original501')
    return b


def manifest(raw):
    value = decode(raw)
    need(raw == encode(value) and set(value) == {'schema', 'kind', 'input_lock_sha256', 'all501_required', 'files', 'package_provenance', 'native_build', 'installation', 'Root_acceptance'}, 'canonical-manifest-schema')
    need(value['schema'] == 1 and value['kind'] == 'NATIVE349_EXACT_MISSING_PUBLIC_INPUTS_V1'
         and value['input_lock_sha256'] == EXPECTED['input_lock_sha256'] and value['all501_required'] is True
         and value['files'] == EXPECTED['files'] and value['native_build'] == value['installation'] == 'NOT RUN'
         and value['Root_acceptance'] is None, 'exact182-lock-no-rebaseline')
    need(set(value['package_provenance']) == set(EXPECTED['package_provenance']), 'exact91-provenance')
    for name, before in EXPECTED['package_provenance'].items():
        row = value['package_provenance'][name]
        need(set(row) == set(before) | {'signature_verification'} and all(row[k] == v for k, v in before.items()), 'original-provenance')
        proof = row['signature_verification']
        need(set(proof) == {'status', 'primary_fingerprint', 'receipt'} and proof['status'] == 'PASS_EXACT_OFFICIAL_SIGNATURE'
             and proof['primary_fingerprint'] == EXPECTED['signer_fingerprint'], 'official-signature-provenance')
        receipt = proof['receipt']
        need(set(receipt) == {'bytes', 'sha256'} and type(receipt['bytes']) is int and 0 < receipt['bytes'] <= 4*1024**2
             and re.fullmatch('[0-9a-f]{64}', receipt['sha256'] or ''), 'signature-receipt-pin')
    return value


def material(root, expected_manifest=None):
    root = ordinary(root)
    names = set()
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'carrier-symlink')
        if path.is_file(): names.add(str(path.relative_to(root)))
        elif path.is_dir(): need(path == root/'packages', 'carrier-extra-directory')
        else: need(False, 'carrier-special-file')
    need(names == set(EXPECTED['files']) | {'manifest.json'}, 'complete183-public-namespace')
    raw = whole(root/'manifest.json')
    need((expected_manifest is None or pin(raw) == expected_manifest)
         and stat.S_IMODE((root/'manifest.json').stat().st_mode) == 0o644, 'manifest-pin-mode')
    value = manifest(raw)
    for name, row in EXPECTED['files'].items():
        need(stat.S_IMODE((root/name).stat().st_mode) == row['mode']
             and file_pin(root/name) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact-public-input-pin-mode')
    return value


def copy_public(source, destination, uid=None, gid=None):
    """Copy only the already pinned finite public namespace; no key/config path."""
    source, destination = ordinary(source), ordinary(destination)
    need(not destination.exists() and not destination.is_relative_to(source) and not source.is_relative_to(destination), 'fresh-disjoint-material')
    value = material(source, BINDING['manifest'])
    destination.mkdir(mode=0o700)
    for name in ('manifest.json', *EXPECTED['files']):
        target = destination/name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (source/name).open('rb') as src, target.open('xb') as dst:
            os.fchmod(dst.fileno(), 0o644)
            shutil.copyfileobj(src, dst, 1024**2)
        if uid is not None: os.chown(target, uid, gid)
    if uid is not None:
        os.chown(destination/'packages', uid, gid); os.chown(destination, uid, gid)
    material(destination, BINDING['manifest'])
    return dict(kind='EXACT_PUBLIC_182_CARRIER_STAGE', files=182, bytes=TOTAL, manifest=pin(encode(value)), private_key_present=False, accepting=False)


def stage(source, destination, uid, gid):
    binding(); need(SECRET not in os.environ and 'SSH_AUTH_SOCK' not in os.environ, 'no-fetch-credential-in-controller')
    source, destination = ordinary(source), ordinary(destination)
    need(destination.name == 'native349-pinned-inputs' and destination.parent.name == 'work' and destination.parent.parent.name == 'volume', 'owned-quota-only-stage')
    run = os.environ.get('GITHUB_RUN_ID', '')
    need(re.fullmatch('[1-9][0-9]{1,19}', run) and source.name == 'public'
         and source.parent.name == 'native349-carrier-'+run+'-1' and source.parent.parent == destination.parents[3], 'same-run-exact-public-fetch-output')
    return copy_public(source, destination, uid, gid)


def seed(source, cache):
    binding(); need(SECRET not in os.environ and 'SSH_AUTH_SOCK' not in os.environ, 'no-fetch-credential-in-payload')
    source, cache = ordinary(source), ordinary(cache)
    need(source.name == 'native349-pinned-inputs' and cache.name == 'cache'
         and cache.parent.name == 'llhttp-reference-native' and source.parent == cache.parent.parent, 'same-owned-work-cache')
    material(source, BINDING['manifest']); need(cache.is_dir() and not cache.is_symlink(), 'canonical-existing-cache-required')
    for relative, row in EXPECTED['files'].items():
        name = relative.removeprefix('packages/'); target = cache/name
        if target.exists():
            need(file_pin(target) == {k: row[k] for k in ('bytes', 'sha256')}, 'never-overwrite-wrong-cache')
        else:
            with (source/relative).open('rb') as src, target.open('xb') as dst:
                os.fchmod(dst.fileno(), 0o600); shutil.copyfileobj(src, dst, 1024**2)
            need(file_pin(target) == {k: row[k] for k in ('bytes', 'sha256')}, 'whole-seeded-cache-input')
    return dict(kind='ONLY_EXACT_MISSING182_SEEDED_BEFORE_ALL501_ACQUIRE', files=182, bytes=TOTAL,
                all501_required=True, URL_overrides=False, signature_authentication='MANDATORY_EXISTING_CANONICAL_AUDIT_NOT_BYPASSED')


def project_entry(raw):
    before = "seed.seed_current_build_cache(output/'cache',profile['inputs_sha256'])"
    after = before+"\n        PINNED_CARRIER.seed(PINNED_INPUTS,output/'cache')"
    text = raw.decode(); need(text.count(before) == 1 and after not in text, 'one-seed-before-audit-seam')
    new = text.replace(before, after)
    need(new.replace(after, before).encode() == raw, 'whole-unchanged-held-entry-inverse')
    return new.encode()


def metadata_guard(stored, reachable):
    s = {n.split(b' ', 1)[0].decode() for n in stored.splitlines()}
    r = {n.split(b' ', 1)[0].decode() for n in reachable.splitlines()}
    need(all(re.fullmatch('[0-9a-f]{40}', n) for n in s | r) and not (s | r) & FORBIDDEN, 'forbidden-stored-or-reachable-OID')
    need(s == r and BINDING['commit'] in s, 'only-complete-reachable-carrier-objects')
    return dict(stored=len(s), reachable=len(r), forbidden_body_reads=False)


def tree_metadata(raw):
    found = {}
    for item in raw.split(b'\0'):
        if not item: continue
        header, name = item.split(b'\t', 1); mode, kind, oid, size = header.decode().split()
        name = name.decode('ascii'); need(name not in found and mode == '100644' and kind == 'blob', 'carrier-tree-modes-types')
        expected = BINDING['manifest']['bytes'] if name == 'manifest.json' else EXPECTED['files'].get(name, {}).get('bytes')
        need(size.isdecimal() and int(size) == expected and re.fullmatch('[0-9a-f]{40}', oid), 'carrier-precheckout-exact-blob-size')
        found[name] = oid
    need(set(found) == set(EXPECTED['files']) | {'manifest.json'} and not set(found.values()) & FORBIDDEN, 'carrier-tree-only183')
    return found


def tool(name):
    path = Path('/usr/bin')/name; info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and os.access(path, os.X_OK), 'observed-existing-fetch-tool')
    return dict(path=str(path), identity=identity(info), sha256=file_pin(path, 16*1024**2)['sha256'])


def admitted_source(root, env):
    """Independently repeat five-input/source admission before credential access."""
    digest = env.get('SOURCE_MAP_SHA256', '')
    need(re.fullmatch('[0-9a-f]{64}', digest), 'explicit-Root-source-map')
    raw = whole(root/'source-map.json', 2*1024**2)
    need(pin(raw)['sha256'] == digest, 'Root-source-map-pin')
    rows = decode(raw)['files']; name = 'scripts/ci/llhttp-reference-native-source/owner/data.py'
    body = whole(root/name, 2*1024**2)
    need(pin(body) == {k:rows[name][k] for k in ('bytes','sha256')}, 'pinned-source-admission-code')
    spec = importlib.util.spec_from_file_location('carrier_exact_source_admission', root/name)
    data = importlib.util.module_from_spec(spec); spec.loader.exec_module(data)
    data.admission(root, digest, env.get('ROOT_LLHTTP_REFERENCE_ADMISSION_JSON','').encode(),
        env.get('ROOT_LLHTTP_REFERENCE_RUNTIME_JSON','').encode(), env.get('ADMISSION_SHA256',''), env.get('RUNTIME_SHA256',''), env, int(time.time()))


def fetch(root, output, runner=None, environment=None):
    """No call path may read the deploy-key environment before all Root pins exist."""
    b = binding(); root, output = ordinary(root), ordinary(output)
    need(sys.flags.isolated and __debug__ and platform.machine() in ('aarch64', 'arm64') and os.getuid() > 0, 'genuine-ordinary-ARM-fetch')
    env = os.environ if environment is None else environment
    admitted_source(root, env)
    need(not output.exists() and not output.is_relative_to(root) and re.fullmatch('/[A-Za-z0-9_./-]+', str(output)), 'fresh-fetch-output')
    need(shutil.disk_usage(output.parent).free >= 14*1024**3+2*TOTAL+64*1024**2, 'original-controller-disk-reserve-plus-finite-fetch')
    observed = {n: tool(n) for n in ('git', 'ssh', 'ssh-keygen')}
    output.mkdir(mode=0o700); keyhome = output/'credential-home'; keyhome.mkdir(mode=0o700)
    keyhome_identity = key_identity(keyhome.lstat()); private = keyhome/'identity'; known = keyhome/'known_hosts'; store = output/'git'; public = output/'public'
    command_rows = []; deadline = time.monotonic()+180; private_identity = None; secret = None
    if runner is None:
        spec = importlib.util.spec_from_file_location('pinned_carrier_owned', root/'held-source/scripts/ci/llhttp-reference-native-source/base/runtime/owned_process.py')
        owned = importlib.util.module_from_spec(spec); spec.loader.exec_module(owned); owned.prepare()
    clean = dict(PATH='/usr/bin:/bin', HOME=str(keyhome), LC_ALL='C', TZ='UTC', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                 GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false', SSH_ASKPASS='/bin/false')
    def run(argv, seconds=45):
        need(len(command_rows) < 24 and time.monotonic() < deadline, 'finite-fetch-commands-deadline')
        for n, row in observed.items():
            need(tool(n) == row, 'same-qualified-fetch-tools')
        if runner is not None: return runner(argv, clean)
        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3)); resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
            resource.setrlimit(resource.RLIMIT_FSIZE, (2*TOTAL+64*1024**2, 2*TOTAL+64*1024**2)); resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o022)
        # Metadata parsers consume stdout alone. SSH/Git diagnostic text is not
        # public evidence; status/retirement still fail closed without retaining it.
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=store if store.exists() else output,
                                 env=clean, start_new_session=True, preexec_fn=limits)
        row = owned.supervise(child, cap=min(seconds, deadline-time.monotonic()), retirement=1, grace=.1, max_output=1024**2)
        raw = row.pop('output'); command_rows.append(dict(command=(argv[len(GIT):] if argv[:len(GIT)] == GIT else argv[:3]), retirement=row, output=pin(raw)))
        need(row['exit'] == 0 and row['reaped'] and row['ownership'] == 'REAPED' and row['group_census'] == 'EMPTY_TWICE'
             and not row['signals'] and not row['timeout'] and row['error'] is None and row['output_complete'], 'natural-fetch-child-required')
        return raw
    def remove_keyhome():
        if not keyhome.exists(): return
        need(key_identity(keyhome.lstat()) == keyhome_identity and not keyhome.is_symlink(), 'same-credential-home')
        need(set(p.name for p in keyhome.iterdir()) <= {'known_hosts'}, 'only-own-host-pin-in-keyhome')
        if known.exists():
            need(whole(known) == ('github.com '+HOST_REFERENCE['key']+'\n').encode() and stat.S_IMODE(known.stat().st_mode) == 0o600, 'same-own-host-pin')
            known.unlink()
        keyhome.rmdir()
    try:
        secret = env.pop(SECRET, None)
        need(type(secret) is str and 64 <= len(secret) <= 32768 and secret.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
             and secret.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----'), 'Root-deploy-key-required')
        fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        private_identity = key_identity(os.fstat(fd))
        with os.fdopen(fd, 'w') as stream: stream.write(secret); stream.flush(); os.fsync(stream.fileno())
        secret = None
        known.write_text('github.com '+HOST_REFERENCE['key']+'\n'); known.chmod(0o600)
        public_key = run(['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(private)]).decode().strip().split()
        need(len(public_key) >= 2, 'deploy-public-key')
        fingerprint = 'SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(public_key[1], validate=True)).digest()).decode().rstrip('=')
        need(fingerprint == b['deploy_key_fingerprint'], 'exact-Root-deploy-key-fingerprint')
        ssh = ['/usr/bin/ssh', '-F', '/dev/null', '-q', '-i', str(private), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(known), '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms=ssh-ed25519',
               '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
               '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=15', '-o', 'VerifyHostKeyDNS=no']
        clean['GIT_SSH_COMMAND'] = shlex.join(ssh)
        run(GIT+['init', '-q', str(store)])
        run(GIT+['remote', 'add', 'origin', 'git@github.com:'+REPOSITORY+'.git'])
        run(GIT+['fetch', '--quiet', '--no-tags', '--depth=1', 'origin', b['commit']], 150)
        need(key_identity(private.lstat()) == private_identity, 'same-temporary-key-before-delete'); private.unlink(); private_identity = None
        clean.pop('GIT_SSH_COMMAND'); remove_keyhome(); clean['HOME'] = str(output)
        need(SECRET not in env and not private.exists() and not keyhome.exists(), 'key-and-home-absent-before-checkout-controller')
        run(GIT+['update-ref', 'refs/heads/carrier', b['commit']])
        guard = metadata_guard(run(GIT+['cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)']), run(GIT+['rev-list', '--objects', '--all']))
        commit = run(GIT+['cat-file', '-p', b['commit']]); header = commit.split(b'\n\n', 1)[0].splitlines()
        need(header[0] == ('tree '+b['tree']).encode() and not any(n.startswith(b'parent ') for n in header), 'actual-parentless-pinned-tree')
        tree_metadata(run(GIT+['ls-tree', '-r', '-l', '-z', '--full-tree', b['commit']]))
        run(GIT+['checkout', '--quiet', '--detach', b['commit']])
        # No private/unlisted tracked file was eligible for checkout.
        material_root = output/'material'; material_root.mkdir(mode=0o700)
        (store/'manifest.json').rename(material_root/'manifest.json'); (store/'packages').rename(material_root/'packages')
        material(material_root, b['manifest']); material_root.rename(public)
        # Only this invocation's freshly-created Git store; no external mount or path.
        need(store.parent == output and not store.is_symlink(), 'same-owned-fetch-store'); shutil.rmtree(store)
        receipt = dict(status='EXACT_PRIVATE_GIT_PUBLIC_INPUTS_FETCHED', repository=REPOSITORY, commit=b['commit'], tree=b['tree'],
                       files=182, bytes=TOTAL, manifest=b['manifest'], object_metadata_guard=guard, private_key_absent=True, private_key_home_absent=True,
                       agent_used=False, credentials_forwarded=False, accepting=False, commands=command_rows)
        (output/'fetch-receipt.json').write_bytes(encode(receipt)); return receipt
    finally:
        secret = None
        env.pop(SECRET, None)
        if private_identity is not None:
            need(private.exists() and key_identity(private.lstat()) == private_identity, 'same-key-final-cleanup'); private.unlink()
        need(not private.exists(), 'private-key-not-retained'); remove_keyhome()
        need(not keyhome.exists(), 'private-key-home-not-retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = fetch(args.root, args.output)
        print(json.dumps({k: result[k] for k in ('status', 'files', 'bytes', 'private_key_absent', 'accepting')}))
    except BaseException as error:
        print(json.dumps(dict(status='HOLD_PINNED_INPUT_CARRIER', error_class=type(error).__name__, private_key_value_logged=False)))
        raise SystemExit(2)
