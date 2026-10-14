"""Proposal-only exact membership custody. There is deliberately no OS adapter."""
import hashlib
import re
from dataclasses import dataclass

CHUNK = 65536
SOURCE_BYTES = 4 * 1024 * 1024
COMPRESSED_BYTES = 64 * 1024 * 1024
EVIDENCE_BYTES = 128 * 1024 * 1024
READ_BYTES = 1024 * 1024 * 1024
FILES = 128
READ_CALLS = 65536
PATH_BYTES = 256
DEPTH = 8


SOURCE19 = {'packages/shells/cachy-asahi-fish-bang-bang/.SRCINFO': {'bytes': 1120, 'mode': 420, 'sha256': '2d51a0849e341581ae89d548a81a7074b8d5acc79c143155b3991b96232c6c01'}, 'packages/shells/cachy-asahi-fish-bang-bang/LICENSE.project': {'bytes': 1081, 'mode': 420, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'}, 'packages/shells/cachy-asahi-fish-bang-bang/LICENSE.upstream': {'bytes': 1108, 'mode': 420, 'sha256': '14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0'}, 'packages/shells/cachy-asahi-fish-bang-bang/NOTICE': {'bytes': 811, 'mode': 420, 'sha256': '0704c1ff8bcd8c94ad40888b35c5e25468ea9152b5781e7722ff0d04fb8aa879'}, 'packages/shells/cachy-asahi-fish-bang-bang/PKGBUILD': {'bytes': 2123, 'mode': 420, 'sha256': '05a1b2cb4710cc14f62678df37d1236fee909874b5b709d82d54fe4b8dc0f93d'}, 'packages/shells/cachy-asahi-fish-bang-bang/README.md': {'bytes': 2182, 'mode': 420, 'sha256': '46ed4a6e1dfed5f9aea5a1bb2ceff1c49d1972a8cf7f2c656a7cdfd87436b37c'}, 'packages/shells/cachy-asahi-fish-bang-bang/__history_previous_command.fish': {'bytes': 170, 'mode': 420, 'sha256': 'd34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50'}, 'packages/shells/cachy-asahi-fish-bang-bang/__history_previous_command_arguments.fish': {'bytes': 198, 'mode': 420, 'sha256': '4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64'}, 'packages/shells/cachy-asahi-fish-bang-bang/integration-proposal.json': {'bytes': 984, 'mode': 420, 'sha256': '951ef1f566e2b1e524bba9dd2a8f4945cc6087f0727d2623566dfce6422c5de6'}, 'packages/shells/cachy-asahi-fish-bang-bang/opt-in.fish': {'bytes': 2599, 'mode': 420, 'sha256': 'd4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7'}, 'packages/shells/cachy-asahi-fish-bang-bang/source-provenance.json': {'bytes': 1688, 'mode': 420, 'sha256': 'bc5200e4264569fe170944ce837d4f7578ba03ed605ec671cd6dda7ef6a0714c'}, 'packages/shells/cachy-asahi-fish-bang-bang/usage.md': {'bytes': 2810, 'mode': 420, 'sha256': '37a52ff036984a5beb4f42b8837a78f3de3391081240b470177ecc0b03aa6890'}, 'packages/tools/cachy-asahi-topmem/.SRCINFO': {'bytes': 779, 'mode': 420, 'sha256': 'fa8b8e01ce36cfe9c5b3cd0f94ae5303c6d8e6444d91831eacf9a762f7490459'}, 'packages/tools/cachy-asahi-topmem/LICENSE': {'bytes': 1081, 'mode': 420, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'}, 'packages/tools/cachy-asahi-topmem/NOTICE': {'bytes': 395, 'mode': 420, 'sha256': '07227afce6f380bcf3deaf9b273fb286f6bcee69b5f1dddec9ebcd1dc2ecd098'}, 'packages/tools/cachy-asahi-topmem/PKGBUILD': {'bytes': 1195, 'mode': 420, 'sha256': 'fc17b0af876ae0dfb97b00e2293bb01fb8c054702d19252804e8ab11196315d2'}, 'packages/tools/cachy-asahi-topmem/README.md': {'bytes': 2543, 'mode': 420, 'sha256': '90082e9119cdea843b0e060f4061a300015dffd6a25c55d12a72b0a75348cf2b'}, 'packages/tools/cachy-asahi-topmem/cachy-asahi-topmem': {'bytes': 4203, 'mode': 493, 'sha256': '96c1b49a92cb6e97d1fe5c51c23f452d79341f2d71cd624cd3197d33b29633b1'}, 'packages/tools/cachy-asahi-topmem/test_topmem.py': {'bytes': 7277, 'mode': 420, 'sha256': '207d3c924e37b3e27be2e0024dfe786716cd4464d3042125af543dfbdec6b847'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/.SRCINFO': {'bytes': 1086, 'mode': 420, 'sha256': '792f2eecf1e573ea5db849e363ac5e539278767e087b7f640eb58cefbabb798c'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/LICENSE.project': {'bytes': 1081, 'mode': 420, 'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/LICENSE.upstream': {'bytes': 1096, 'mode': 420, 'sha256': '4598a6be0b8d7f2b708da5259d2a30d4e15e59b3c66781bab9e27744a9f859d8'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/NOTICE': {'bytes': 633, 'mode': 420, 'sha256': '9171e9a773c8b7c60ae8e489608f7ef4a4dba3a762156aa57e4673960ab2c921'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/PKGBUILD': {'bytes': 2209, 'mode': 420, 'sha256': '12d3fb64c53b23d1e07131a82a6319dee9cb2ac0ebb233e569167947c5ac44e7'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/README.md': {'bytes': 3269, 'mode': 420, 'sha256': '775d480926b42496f937aaa019978ae26db6d21cbfa331ef33999f1874c1e4fd'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/check-module.py': {'bytes': 13447, 'mode': 420, 'sha256': 'fa81e94383b3d7caa1522ea6be165579ba7a4d0775f6cc7f1e14c343fb6946bc'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/integration-proposal.json': {'bytes': 1130, 'mode': 420, 'sha256': '40949e6667a2859c7fbc8ce82b78183db3bf353669e2ea1291ff47c2551d6c3d'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/opt-in.zsh': {'bytes': 253, 'mode': 420, 'sha256': '692bca1e9ba1a2e9bd32de08cb6ffa5d15b19f85b48e1c08d85a48e41fe6f768'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/source-provenance.json': {'bytes': 1482, 'mode': 420, 'sha256': '0e46b589fefba600766591e8cc02897111c5f45e17415f4a2aac004d46418f36'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/usage.md': {'bytes': 2776, 'mode': 420, 'sha256': '3b43dee6a8f3c20796bb6e0965fd60b3b2e7b7e8c2d508efc011ba36aada6760'}, 'packages/shells/cachy-asahi-zsh-autosuggestions/zsh-autosuggestions.zsh': {'bytes': 27017, 'mode': 420, 'sha256': 'eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a'}}


class Refused(ValueError):
    pass


def path(value):
    if type(value) is not str or len(value.encode()) > PATH_BYTES:
        raise Refused('path bound')
    parts = value.split('/')
    if len(parts) > DEPTH or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', p)
                                or p in ('.', '..') for p in parts):
        raise Refused('path shape')
    return value


def rows(value, *, count=None, total=EVIDENCE_BYTES, each=COMPRESSED_BYTES):
    if type(value) is not dict or not value or len(value) > FILES or (count is not None and len(value) != count):
        raise Refused('membership count')
    result = {}
    used = 0
    for name, row in value.items():
        path(name)
        if type(row) is not dict or set(row) != {'bytes', 'mode', 'sha256'}:
            raise Refused('row shape')
        size, mode, sha = row['bytes'], row['mode'], row['sha256']
        if type(size) is not int or not 0 <= size <= each or type(mode) is not int or mode not in (0o600, 0o644, 0o755):
            raise Refused('row bounds')
        if type(sha) is not str or not re.fullmatch('[0-9a-f]{64}', sha):
            raise Refused('row digest')
        used += size
        if used > total:
            raise Refused('aggregate byte bound')
        result[name] = dict(row)
    # A regular file cannot also serve as another member's directory.
    if any('/'.join(n.split('/')[:i]) in result for n in result for i in range(1, len(n.split('/')))):
        raise Refused('file directory collision')
    return result


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    nlink: int
    kind: str


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    kind: str


class Artifact:
    """Owner-issued handle; rewind never restores the aggregate read budget."""
    def __init__(self, owner, name, handle, identity, ancestors, expected, *, output=False):
        self._owner, self._name, self._handle = owner, name, handle
        self._identity, self._ancestors = identity, ancestors
        self._sha256, self._size = expected['sha256'], expected['bytes']
        self._output = output

    @property
    def sha256(self):
        return self._sha256

    @property
    def size(self):
        return self._size

    @property
    def mode(self):
        return self._identity.mode

    @property
    def path(self):
        return self._name

    @property
    def fd(self):
        self.verify()
        def work():
            fd = self._owner.ops.borrow_fd(self._handle)
            self.verify()
            return fd
        return self._owner._work(work)

    def verify(self):
        def work():
            o = self._owner
            if self not in o._artifacts or self._handle not in o._owned:
                raise Refused('retired or foreign artifact')
            if self._output and o.ops.output_owned(self._name) is not True:
                raise Refused('positive output custody revoked')
            if (o.ops.stat_handle(self._handle) != self._identity or
                    o.ops.stat_named(self._name) != self._identity or
                    o.ops.ancestors(self._name) != self._ancestors):
                raise Refused('held named ancestry changed')
            if self._output and o.ops.output_owned(self._name) is not True:
                raise Refused('positive output custody revoked')
            return True
        return self._owner._work(work)

    def read(self, n):
        def work():
            self.verify()
            o = self._owner
            if type(n) is not int or not 0 < n <= CHUNK:
                raise Refused('read bound')
            if o._read_requested + n > READ_BYTES or o._read_calls >= READ_CALLS:
                raise Refused('read work bound')
            o._read_calls += 1
            o._read_requested += n  # Charge before the callback, including failed reads.
            data = o.ops.read(self._handle, n)
            if type(data) is not bytes or len(data) > n:
                raise Refused('read callback contract')
            self.verify()
            return data
        return self._owner._work(work)

    def rewind(self):
        def work():
            self.verify()
            self._owner.ops.rewind(self._handle)
            self.verify()
        return self._owner._work(work)


class Owner:
    """Injected Ops and original Authority only. No renewed clocks or grant inference.

    Ops open/create must call adopt(handle) BEFORE any fallible post-acquisition
    operation, including exceptions after acquisition. All path operations must
    use held no-follow root/ancestor descriptors, reject symlinks/hardlinks and
    bind caller UID/GID. list_names(root, limit) must stop at limit+1 nodes and
    include files/directories; it must never silently truncate. close is a
    nonblocking handle close; is_closed must positively establish retirement.
    This contract requires an independently reviewed live adapter before use.
    """
    def __init__(self, authority, ops, *, enabled=False):
        self.authority, self.ops = authority, ops
        self.enabled = enabled is True and getattr(authority, 'execution_granted', False) is True
        if self.enabled:
            authority.claim_custody(self)
        self._owned, self._artifacts = [], []
        self._retired, self._close_attempts = set(), {}
        self._read_requested = 0
        self._read_calls = 0
        self.first_failure = None
        self.cleanup_failures = []
        self.failed = False
        self.closed = False
        self._cleanup_stopped = False

    def _fail(self, error, cleanup=False):
        self.failed = True
        # Root's recorder owns immutable first failure and cancellation policy.
        if cleanup:
            if len(self.cleanup_failures) < FILES * 7:
                self.cleanup_failures.append(type(error).__name__)
        elif self.first_failure is None:
            self.first_failure = type(error).__name__
        try:
            self.authority.record_failure(error, cleanup=cleanup)
        except BaseException:
            # Recorder failure cannot skip owned cleanup or replace the cause.
            self.failed = True

    def _check(self):
        if not self.enabled or self.failed or self.closed:
            raise Refused('custody disabled failed or closed')
        self.authority.check()

    def _work(self, fn):
        try:
            self._check()
            result = fn()
            self._check()
            return result
        except BaseException as error:
            self._fail(error)
            raise

    def _adopt(self, handle):
        if handle in self._owned or handle in self._retired:
            raise Refused('duplicate live handle')
        self._owned.append(handle)
        self._close_attempts[handle] = 0
        if len(self._owned) > FILES:
            raise Refused('owned handle bound')

    def acquire(self, name, expected, *, uid=None, gid=None):
        """Hash through held identity once, then hand the same handle to checker."""
        return self._acquire(name, expected, uid=uid, gid=gid)

    def acquire_output(self, name, *, mode=0o644, max_bytes=COMPRESSED_BYTES):
        """Hash a fresh positively owned output, never a path-digest pre-read.

        Ops.output_owned must bind the held output root to Root's finished owned
        container/provenance lease. No basename, random name or boolean guess
        constitutes that proof; this is another live adapter admission input.
        """
        return self._acquire(name, None, output=True, mode=mode, max_bytes=max_bytes)

    def _acquire(self, name, expected, *, uid=None, gid=None, output=False,
                 mode=None, max_bytes=COMPRESSED_BYTES):
        def work():
            path(name)
            if output:
                if type(mode) is not int or mode not in (0o600, 0o644, 0o755) or type(max_bytes) is not int or not 0 <= max_bytes <= COMPRESSED_BYTES:
                    raise Refused('output bound shape')
                if self.ops.output_owned(name) is not True:
                    raise Refused('positive output custody missing')
            else:
                row = rows({name: expected})[name]
            owner_uid = self.ops.uid if uid is None else uid
            owner_gid = self.ops.gid if gid is None else gid
            if type(owner_uid) is not int or type(owner_gid) is not int or min(owner_uid, owner_gid) < 0:
                raise Refused('owner binding')
            handle = self.ops.open_named(name, self._adopt)
            if handle not in self._owned:
                raise Refused('unadopted acquisition')
            identity = self.ops.stat_handle(handle)
            if output:
                if type(identity) is not Identity or type(identity.size) is not int or not 0 <= identity.size <= max_bytes:
                    raise Refused('output file bound')
                row = {'bytes': identity.size, 'mode': mode, 'sha256': None}
            if (type(identity) is not Identity or identity.kind != 'regular' or
                    identity.nlink != 1 or identity.uid != owner_uid or identity.gid != owner_gid or
                    identity.mode != row['mode'] or
                    identity.size != row['bytes']):
                raise Refused('file identity shape')
            if any(type(getattr(identity, field)) is not int or getattr(identity, field) < 0
                   for field in ('device', 'inode', 'uid', 'gid', 'mode', 'size', 'mtime_ns', 'ctime_ns', 'nlink')):
                raise Refused('file identity numeric shape')
            ancestors = self.ops.ancestors(name)
            if type(ancestors) is not tuple or not ancestors or len(ancestors) > DEPTH:
                raise Refused('ancestor identity shape')
            if any(type(a) is not DirectoryIdentity or a.kind != 'directory' or
                   a.mode not in (0o700, 0o755) or a.uid != owner_uid or a.gid != owner_gid
                   for a in ancestors):
                raise Refused('ancestor ownership shape')
            if any(type(getattr(a, field)) is not int or getattr(a, field) < 0
                   for a in ancestors for field in ('device', 'inode', 'uid', 'gid', 'mode')):
                raise Refused('ancestor identity numeric shape')
            item = Artifact(self, name, handle, identity, ancestors, row, output=output)
            self._artifacts.append(item)
            digest, size = hashlib.sha256(), 0
            while True:
                data = item.read(min(CHUNK, row['bytes'] - size + 1))
                if not data:
                    break
                size += len(data)
                if size > row['bytes']:
                    raise Refused('file size overrun')
                digest.update(data)
            checksum = digest.hexdigest()
            if size != row['bytes'] or (not output and checksum != row['sha256']):
                raise Refused('file authentication')
            if output:
                item._sha256 = checksum
                if self.ops.output_owned(name) is not True:
                    raise Refused('positive output custody changed')
            item.rewind()
            return item
        return self._work(work)

    def verify_all(self):
        return self._work(lambda: all(a.verify() for a in self._artifacts))

    prepare_mount = verify_all

    def snapshot_exact19(self, source_rows, destination):
        """Copy only the sealed19 rows, preserve modes, then retain both identities."""
        def work():
            expected = rows(source_rows, count=19, total=SOURCE_BYTES, each=SOURCE_BYTES)
            if expected != SOURCE19:
                raise Refused('sealed Source19 mismatch')
            target_root = path(destination)
            if self.ops.list_names(target_root, FILES) != ():
                raise Refused('snapshot destination not empty')
            for name, row in expected.items():
                original = self.acquire(name, row)
                target = path(target_root + '/' + name)
                handle = self.ops.create_named(target, row['mode'], self._adopt)
                if handle not in self._owned:
                    raise Refused('unadopted output')
                while True:
                    data = original.read(CHUNK)
                    if not data:
                        break
                    self.ops.write(handle, data)  # Adapter must either fully write or refuse.
                    self._check()
                self.ops.finish_write(handle)
                self.acquire(target, row)
            self.verify_all()
            self._membership(target_root, set(expected))
            return {n: dict(r) for n, r in expected.items()}
        return self._work(work)

    def _membership(self, root, names):
        required = set(names)
        for name in names:
            required.update('/'.join(name.split('/')[:i]) for i in range(1, len(name.split('/'))))
        found = self.ops.list_names(root, FILES)
        if type(found) is not tuple or len(found) > FILES or len(set(found)) != len(found):
            raise Refused('enumeration bound or duplicate')
        if any(path(n) != n for n in found) or set(found) != required:
            raise Refused('exact membership mismatch')

    def seal_evidence(self, root, expected_rows):
        def work():
            expected = rows(expected_rows)
            target_root = path(root)
            self._membership(target_root, set(expected))
            artifacts = {name: self.acquire(path(target_root + '/' + name), row) for name, row in expected.items()}
            self.verify_all()
            self._membership(target_root, set(expected))
            return artifacts
        return self._work(work)

    def _cleanup_allowed(self):
        if self._cleanup_stopped:
            return False
        try:
            self.authority.check(cleanup=True)
            return True
        except BaseException as error:
            self._fail(error, cleanup=True)
            self._cleanup_stopped = True
            return False

    def close(self):
        """Finite retries; uncertain descriptors stay owned and prohibit success."""
        if not self._cleanup_allowed():
            return False
        for handle in tuple(self._owned):
            while self._close_attempts[handle] < 3:
                if not self._cleanup_allowed():
                    return False
                self._close_attempts[handle] += 1
                try:
                    state = self.ops.verify_close_identity(handle)
                    if not self._cleanup_allowed():
                        return False
                    if state == 'RETIRED':
                        self._owned.remove(handle)
                        self._retired.add(handle)
                        break
                    if state != 'OWNED':
                        raise Refused('close identity unproved')
                except BaseException as error:
                    self._fail(error, cleanup=True)
                    continue
                if not self._cleanup_allowed():
                    return False
                try:
                    self.ops.close(handle)
                except BaseException as error:
                    self._fail(error, cleanup=True)
                if not self._cleanup_allowed():
                    return False
                try:
                    retired = self.ops.is_closed(handle) is True
                    if not self._cleanup_allowed():
                        return False
                except BaseException as error:
                    self._fail(error, cleanup=True)
                    retired = False
                if retired:
                    self._owned.remove(handle)
                    self._retired.add(handle)
                    break
            else:
                self._fail(Refused('owned handle retirement unproved'), cleanup=True)
        if getattr(self.authority, 'primary', None) is not None:
            self.failed = True
        self.closed = not self._owned
        return self.closed and not self.failed
