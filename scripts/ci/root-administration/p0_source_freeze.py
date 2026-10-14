"""Root-invoked read-only Source freezer, outside the selected269 Source set."""
import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import time

FILE_LIMIT = 8 * 1024**2
TOTAL_LIMIT = 64 * 1024**2
INITIAL = 'scripts/ci/integration.lock.json'
PACKET = 'scripts/ci/development/packet.py'
WORKFLOW = '.github/workflows/native-arm-p0.yml'
LOCK = 'scripts/ci/development/packet.lock.json'
REQUIRED_PUBLIC = {WORKFLOW, 'scripts/ci/development/p0_ci.py', 'scripts/install/p0_entry.py',
    'scripts/ci/development/p0_native_arm.py', 'scripts/port/repository-native-handoff/transport.py',
    'scripts/port/repository-native-handoff/source-map.json', 'scripts/ci/development/common.py',
    'scripts/ci/development/controller.py', PACKET, 'scripts/ci/development/repository_handoff.py'}
SHA = re.compile('[0-9a-f]{64}')
COMMIT = re.compile('[0-9a-f]{40}')
_GIT_QUARANTINE = []
_READ_QUARANTINE = []
_WRITE_QUARANTINE = []


def need(value, code):
    if not value:
        raise ValueError(code)


def live(endpoint, clock):
    need(type(endpoint) in (int, float) and math.isfinite(endpoint) and endpoint > 0,
         'original-endpoint-required')
    need(clock() < endpoint, 'original-endpoint-expired')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def relative(value):
    need(type(value) is str and 0 < len(value) <= 4096 and '\0' not in value and
         not any(c in value for c in '\n\r\t') and
         str(PurePosixPath(value)) == value and not value.startswith('/') and
         not any(p in ('.', '..', '') for p in value.split('/')), 'Source-path-refused')
    return value


def source_map(value):
    need(type(value) is dict and 0 < len(value) <= 270, 'Source-map-refused')
    for name, row in value.items():
        relative(name)
        need(type(row) is dict and set(row) == {'mode', 'sha256'} and type(row['mode']) is int and
             row['mode'] in (0o644, 0o755) and type(row['sha256']) is str and SHA.fullmatch(row['sha256']),
             'Source-row-refused')


def constants(raw, endpoint, clock):
    """Static literal projection; never execute a selected project body."""
    live(endpoint, clock)
    tree = ast.parse(raw)
    values = {}
    def value(node):
        if isinstance(node, ast.Name):return values[node.id]
        if isinstance(node, ast.Set):return {value(n) for n in node.elts}
        if isinstance(node, (ast.Tuple, ast.List)):return [value(n) for n in node.elts]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):return value(node.left) | value(node.right)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('frozenset', 'set'):
            need(len(node.args) == 1 and not node.keywords, 'Source-literal-refused')
            return set(value(node.args[0]))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'split':
            need(not node.args and not node.keywords, 'Source-literal-refused')
            return value(node.func.value).split()
        return ast.literal_eval(node)
    for node in tree.body:
        live(endpoint, clock)
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:values[node.targets[0].id] = value(node.value)
            except (ValueError, KeyError, TypeError):pass
    live(endpoint, clock)
    return values


def freeze_source(*, checkout, source_commit, publication_raw, publication_sha256, endpoint,
                  git, tree, clock=time.monotonic, entry=None):
    """Return Source data only; caller provides Root-selected Git/read backends."""
    captured = clock()
    start = captured if entry is None else entry
    need(type(start) in (int, float) and math.isfinite(start) and 0 < start <= captured,
         'original-entry-required')
    live(endpoint, clock)
    need(type(source_commit) is str and COMMIT.fullmatch(source_commit), 'Root-Source-required')
    root = Path(checkout)
    need(root.is_absolute() and str(root) == str(PurePosixPath(str(root))) and '..' not in root.parts,
         'Root-checkout-required')
    need(type(publication_raw) is bytes and len(publication_raw) <= FILE_LIMIT and
         type(publication_sha256) is str and SHA.fullmatch(publication_sha256) and
         digest(publication_raw) == publication_sha256, 'Root-publication-hash-refused')
    proof = json.loads(publication_raw)
    need(type(proof) is dict and proof.get('Source') == source_commit and proof.get('remote') == source_commit and
         sum(key in proof for key in ('rows','files')) == 1,
         'Root-publication-Source-refused')
    proof_rows = proof['files'] if 'files' in proof else proof['rows']
    need(type(proof_rows) is dict,'Root-publication-table-refused')
    need(git.head(root, endpoint) == source_commit, 'checkout-HEAD-refused')
    seed = {}
    for name in (INITIAL, PACKET):
        seed[name] = tree.read(root / name, FILE_LIMIT, endpoint)
    initial = json.loads(seed[INITIAL][0]); declaration = constants(seed[PACKET][0], endpoint, clock)
    need(declaration.get('INITIAL') == INITIAL and declaration.get('LOCK') == LOCK and
         declaration.get('INSTALLER_COMPOSITION') == 'installer-preflight' and
         declaration.get('PURPOSE') == 'frozen-development-only-native-arm-source-packet', 'Source-selector-refused')
    source_map(initial['source_files']);source_map(initial['generated_fixture_files'])
    need(len(initial['source_files']) == 159 and len(initial['generated_fixture_files']) == 125 and
         initial.get('purpose') == 'frozen-development-only-native-integration', 'original-contract-refused')
    extra, installer = declaration.get('COMPOSED_EXTRA'), declaration.get('INSTALLER_EXTRA')
    need(type(extra) is set and len(extra) == 99 and type(installer) is set and len(installer) == 11,
         'Source-selector-refused')
    paths = set(initial['source_files']) | extra | installer
    need(len(paths) == 269 and LOCK not in paths and WORKFLOW not in paths and
         'scripts/ci/development/p0_ci.py' in paths, 'exact269-selector-refused')
    wanted = paths | {WORKFLOW}
    for name in wanted:relative(name)
    entries = git.entries(root, source_commit, sorted(wanted), endpoint)
    need(type(entries) is dict and set(entries) == wanted, 'Git-exact270-refused')
    bodies, rows, physical = {}, {}, {}
    total = 0
    for name in sorted(wanted):
        live(endpoint, clock)
        entry = entries[name]
        need(type(entry) is dict and set(entry) == {'mode','oid'} and type(entry['mode']) is int and
             entry['mode'] in (0o644, 0o755) and type(entry['oid']) is str and COMMIT.fullmatch(entry['oid']),
             'Git-blob-mode-refused')
        blob = git.blob(root, entry['oid'], FILE_LIMIT, endpoint)
        need(type(blob) is bytes and len(blob) <= FILE_LIMIT and
             hashlib.sha1(b'blob ' + str(len(blob)).encode() + b'\0' + blob).hexdigest() == entry['oid'],
             'Git-blob-identity-refused')
        current, mode = tree.read(root / name, FILE_LIMIT, endpoint)
        need(current == blob and mode == entry['mode'], 'physical-Git-Source-drift')
        total += len(blob);need(total <= TOTAL_LIMIT, 'Source-total-limit')
        bodies[name] = blob
        rows[name] = {'mode': mode, 'sha256': digest(blob)}
        physical[name] = {'bytes': len(blob), **rows[name]}
    need(all(bodies[name] == raw and rows[name]['mode'] == mode for name, (raw, mode) in seed.items()),
         'selector-changed-during-freeze')
    need(all(rows[name] == row for name, row in initial['source_files'].items()), 'original159-drift')
    for logical, expected in declaration['P0_OVERLAY_ROWS'].items():
        variant = 'scripts/ci/development/p0_' + Path(logical).name
        need(rows.get(variant) == expected, 'P0-variant-drift')
    pins = declaration.get('COMPOSED_PINS');maps = declaration.get('COMPOSED_MAPS')
    need(type(pins) is set and len(pins) == 12 and pins <= paths and type(maps) is dict and len(maps) == 3,
         'metadata-contract-refused')
    for name, prefix in maps.items():
        mapping = json.loads(bodies[name]);source_map(mapping)
        expected = {Path(p).name for p in extra if p.startswith(prefix + '/') and p.endswith('.py')}
        need(set(mapping) == expected and all(rows.get(prefix + '/' + p) == row for p, row in mapping.items()),
             'Source-map-leaf-drift')
    recipes = json.loads(bodies['scripts/ci/recipes.lock.json'])
    need(type(recipes) is dict and len(recipes) == 4, 'original-four-recipes-required')
    recipe_paths = set()
    for directory, recipe in recipes.items():
        relative(directory);need(directory.startswith('packages/') and type(recipe) is dict and recipe,
                                 'recipe-map-refused')
        for name, pin in recipe.items():
            relative(name);path = directory + '/' + name;recipe_paths.add(path)
            need(type(pin) is str and SHA.fullmatch(pin) and rows.get(path, {}).get('sha256') == pin,
                 'recipe-input-drift')
    need(len(recipe_paths) == 71 and recipe_paths <= set(initial['source_files']), 'original71-inputs-required')
    stage = json.loads(bodies['scripts/experiments/stage.lock.json'])
    for name, row in stage['source_files'].items():
        relative(name);need(rows.get('scripts/experiments/' + name) == row, 'experiment-map-drift')
    exporter = stage['exporter']
    need(type(exporter) is dict and set(exporter) == {'path','mode','sha256'} and
         rows.get(exporter['path']) == {k:exporter[k] for k in ('mode','sha256')}, 'experiment-exporter-drift')
    tooling = json.loads(bodies['scripts/virtual/tooling.lock.json'])
    audit = json.loads(bodies['scripts/virtual/tooling-audit.json'])
    need(tooling['base_inputs_lock_sha256'] == rows['scripts/ci/inputs.lock.json']['sha256'] and
         audit['tooling_lock_sha256'] == rows['scripts/virtual/tooling.lock.json']['sha256'], 'virtual-metadata-drift')
    policy = json.loads(bodies[declaration['GENERIC_POLICY']])
    need(policy.get('supported_models') == [] and policy.get('platform_scope') == 'generic-builder-only' and
         policy.get('review_status') == 'ACCEPTED', 'generic-policy-refused')
    need(REQUIRED_PUBLIC <= set(proof_rows) <= wanted, 'Root-publication-required-rows')
    for name, row in proof_rows.items():
        need(type(row) is dict and set(row) == {'bytes','mode','sha256'} and row == physical[name],
             'Root-publication-row-drift')
    packet = {'schema_version': 2, 'composition': 'installer-preflight', 'purpose': declaration['PURPOSE'],
        'development_only': True, 'selected_for_release': False, 'hardware_validation': 'NOT RUN',
        'metadata_pins': {p: rows[p]['sha256'] for p in sorted(pins)},
        'initial_source_files': initial['source_files'], 'generated_fixture_files': initial['generated_fixture_files'],
        'source_files': {p: rows[p] for p in sorted(paths)}}
    publication = {'Source': source_commit, 'remote': source_commit, 'branch': 'codex/signer-native-runtime-v1',
        'files': [{'path': p, **physical[p]} for p in sorted(REQUIRED_PUBLIC)]}
    need(all(row['mode'] == 0o644 for row in publication['files']), 'publication644-required')
    # Repeat all physical bytes/modes and HEAD under the same original endpoint.
    for name in sorted(wanted):
        current, mode = tree.read(root / name, FILE_LIMIT, endpoint)
        need(current == bodies[name] and mode == rows[name]['mode'], 'final-physical-Source-drift')
    need(git.head(root, endpoint) == source_commit, 'final-HEAD-drift')
    raw = encoded(packet); pubraw = encoded(publication); rowsraw = encoded(physical)
    need(len(raw) <= FILE_LIMIT and len(pubraw) <= FILE_LIMIT, 'data-output-limit')
    live(endpoint, clock)
    return {'packet_raw': raw, 'packet_sha256': digest(raw), 'publication_raw': pubraw,
            'publication_sha256': digest(pubraw), 'source_rows': physical, 'Source': source_commit,
            'source_rows_raw': rowsraw, 'source_rows_sha256': digest(rowsraw),
            'proof_sha256': publication_sha256, 'entry': start, 'endpoint': endpoint,
            'selected': False, 'grants_issued': False}


class CheckoutBytes:
    """Deferred held/named leaf read; Root supplies the trusted checkout namespace."""
    def __init__(self, clock=time.monotonic):self.clock = clock
    def read(self, path, limit, endpoint):
        need(not _READ_QUARANTINE, 'unresolved-prior-read-custody')
        live(endpoint, self.clock)
        before = os.stat(path, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             'regular-Source-leaf-required')
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        first = None;data = bytearray()
        try:
            need(identity(os.fstat(fd)) == identity(before), 'held-Source-drift')
            while True:
                live(endpoint, self.clock)
                part = os.read(fd, min(65536, limit + 1 - len(data)))
                if not part:break
                data.extend(part);need(len(data) <= limit, 'Source-file-limit')
            need(len(data) == before.st_size and identity(os.fstat(fd)) == identity(before) and
                 identity(os.stat(path, follow_symlinks=False)) == identity(before), 'final-held-Source-drift')
        except BaseException as error:first = error
        finally:
            try:
                need(identity(os.fstat(fd)) == identity(before), 'close-Source-FD-drift')
                os.close(fd)
            except BaseException as error:
                _READ_QUARANTINE.append(fd)
                if first is None:first = error
                BaseException.__setattr__(first,'freeze_cleanup_uncertain',True)
                if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(first,'freeze_cancelled',True)
            try:live(endpoint,self.clock)
            except BaseException as error:
                if first is None:first = error
                if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(first,'freeze_cancelled',True)
        if first is not None:raise first
        return bytes(data), stat.S_IMODE(before.st_mode)


class ReadOnlyGit:
    """Root-only closed Git reads, capped output and original endpoint. No fetch/write."""
    def __init__(self, executable, executable_sha256, clock=time.monotonic):
        self.executable = str(executable);self.expected = executable_sha256;self.clock = clock
    def command(self, root, args, limit, endpoint):
        need(not _GIT_QUARANTINE, 'unresolved-prior-Git-custody')
        need(type(args) is list and all(type(p) is str for p in args) and
             type(limit) is int and 0 < limit <= FILE_LIMIT, 'closed-Git-read-required')
        closed = args == ['rev-parse','--verify','HEAD'] or (
            len(args) == 3 and args[:2] == ['cat-file','blob'] and COMMIT.fullmatch(args[2])) or (
            6 < len(args) <= 6+270 and args[:4] == ['ls-tree','-r','-z','--full-tree'] and
            COMMIT.fullmatch(args[4]) and args[5] == '--' and
            all(relative(p) == p for p in args[6:]))
        need(closed, 'closed-Git-read-required')
        live(endpoint, self.clock)
        raw, mode = CheckoutBytes(self.clock).read(Path(self.executable), FILE_LIMIT, endpoint)
        need(mode == 0o755 and digest(raw) == self.expected, 'Root-Git-body-refused')
        env = {'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1',
               'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0',
               'GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1',
               'GIT_ATTR_NOSYSTEM':'1'}
        try:
            process = subprocess.Popen([self.executable,'--no-optional-locks','--literal-pathspecs',
                '-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',
                '-c','protocol.allow=never','-C',str(root),*args], env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except BaseException as error:
            _GIT_QUARANTINE.append(('partial-Git-birth',))
            BaseException.__setattr__(error,'freeze_cleanup_uncertain',True)
            raise
        selector = None;out = bytearray();first = None;reaped = False
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                live(endpoint, self.clock)
                for key, _ in selector.select(max(0, endpoint-self.clock())):
                    chunk = os.read(key.fileobj.fileno(), min(65536, limit+1-len(out)))
                    if not chunk:selector.unregister(key.fileobj)
                    else:out.extend(chunk);need(len(out) <= limit, 'Git-output-limit')
            live(endpoint, self.clock)
            code = process.wait(timeout=max(0, endpoint-self.clock()));reaped = True
            need(code == 0, 'Git-read-failed')
        except BaseException as error:
            first = error
            # Closed builtin reads have no selected helper chain; dispose only this own child.
            if not reaped:
                try:
                    live(endpoint,self.clock);process.kill()
                    process.wait(timeout=max(0,endpoint-self.clock()));reaped = True
                except BaseException as cleanup_error:
                    _GIT_QUARANTINE.append(process)
                    BaseException.__setattr__(first,'freeze_cleanup_uncertain',True)
                    if isinstance(cleanup_error,KeyboardInterrupt):
                        BaseException.__setattr__(first,'freeze_cancelled',True)
        finally:
            for close in ([selector.close] if selector is not None else []) + [process.stdout.close]:
                try:close()
                except BaseException as error:
                    if first is None:first = error
                    BaseException.__setattr__(first,'freeze_cleanup_uncertain',True)
                    if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(first,'freeze_cancelled',True)
        if first is not None:raise first
        live(endpoint, self.clock);return bytes(out)
    def head(self, root, endpoint):
        raw = self.command(root, ['rev-parse','--verify','HEAD'], 128, endpoint)
        return raw.decode('ascii').strip()
    def entries(self, root, commit, paths, endpoint):
        raw = self.command(root, ['ls-tree','-r','-z','--full-tree',commit,'--',*paths], 2*1024**2, endpoint)
        rows = {}
        for entry in raw.split(b'\0'):
            if not entry:continue
            header, name = entry.split(b'\t',1);mode, kind, oid = header.split(b' ')
            name = name.decode('utf-8');relative(name)
            need(kind == b'blob' and name not in rows, 'Git-tree-refused')
            rows[name] = {'mode': int(mode,8) & 0o7777, 'oid': oid.decode('ascii')}
        return rows
    def blob(self, root, oid, limit, endpoint):
        return self.command(root, ['cat-file','blob',oid], limit, endpoint)


def write_new(path, raw, endpoint, clock=time.monotonic):
    """Fresh private output only; register the returned FD before another effect."""
    need(not _WRITE_QUARANTINE and type(raw) is bytes and len(raw) <= FILE_LIMIT,
         'fresh-data-write-required')
    live(endpoint,clock)
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    expected = None;first = None
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid(),
             'owned-data-file-required')
        expected = (info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode),info.st_uid,info.st_gid,info.st_nlink)
        def guard():
            held = os.fstat(fd);named = os.stat(path,follow_symlinks=False)
            anchor = (held.st_dev,held.st_ino,stat.S_IFMT(held.st_mode),held.st_uid,held.st_gid,held.st_nlink)
            need(anchor == expected and identity(held) == identity(named),'owned-data-file-drift')
            return held
        guard();live(endpoint,clock);os.fchmod(fd,0o600)
        done = 0
        while done < len(raw):
            guard();live(endpoint,clock)
            count = os.write(fd,raw[done:done+65536]);need(count > 0,'data-write-incomplete');done += count
        info = guard()
        need(info.st_size == len(raw) and stat.S_IMODE(info.st_mode) == 0o600,'data-write-incomplete')
        live(endpoint,clock)
    except BaseException as error:first = error
    finally:
        try:
            need(expected is not None,'pending-data-FD-unbound')
            guard();os.close(fd)
        except BaseException as error:
            _WRITE_QUARANTINE.append((str(path),fd,expected))
            if first is None:first = error
            BaseException.__setattr__(first,'freeze_cleanup_uncertain',True)
            if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(first,'freeze_cancelled',True)
        try:live(endpoint,clock)
        except BaseException as error:
            if first is None:first = error
            if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(first,'freeze_cancelled',True)
    if first is not None:raise first
    observed,mode = CheckoutBytes(clock).read(path,FILE_LIMIT,endpoint)
    need(observed == raw and mode == 0o600,'data-write-readback-drift')
    live(endpoint,clock)


def main():
    captured = time.monotonic()
    parser = argparse.ArgumentParser()
    for name in ('checkout','source-commit','publication-proof','publication-sha256','git','git-sha256','output'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--deadline', type=float, required=True)
    parser.add_argument('--entry', type=float)
    args = parser.parse_args();live(args.deadline,time.monotonic)
    need(captured < args.deadline, 'original-entry-expired')
    proof, _ = CheckoutBytes().read(Path(args.publication_proof), FILE_LIMIT, args.deadline)
    result = freeze_source(checkout=args.checkout,source_commit=args.source_commit,publication_raw=proof,
        publication_sha256=args.publication_sha256,endpoint=args.deadline,
        git=ReadOnlyGit(args.git,args.git_sha256),tree=CheckoutBytes(),entry=args.entry if args.entry is not None else captured)
    output = Path(args.output)
    need(output.is_absolute() and not output.exists() and '..' not in output.parts, 'fresh-data-output-required')
    live(args.deadline,time.monotonic);output.mkdir(mode=0o700)
    for name, raw in [('packet.json',result['packet_raw']),('publication.json',result['publication_raw']),
                      ('source-rows.json',result['source_rows_raw'])]:
        live(args.deadline,time.monotonic)
        write_new(output/name,raw,args.deadline)
    live(args.deadline,time.monotonic)
    print(json.dumps({'Source':result['Source'],'packet_sha256':result['packet_sha256'],
        'publication_sha256':result['publication_sha256'],'source_count':269,'rows_count':270,
        'selected':False,'grants_issued':False},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
