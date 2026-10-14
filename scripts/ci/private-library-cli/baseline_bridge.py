# SPDX-License-Identifier: MIT
"""Borrow the original producer's baseline only at its selected live callback.

Registration is an ordinary trusted-bootstrap API, not a Python sandbox or frame
proof. JSON cannot issue a Lease. Original producer audit/build control flow is
trusted; retained signature decisions are rechecked, not freshly authenticated.
No actor runs on import. The borrowed image and cache are never removed here.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

import boundary
import owned_build
import parent_bridge

INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
RECIPES = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
INTEGRATION = '5d0f6b1d335c1949965699d4db6658af313af8977079e9a6464f0e5db4071ed3'
LOCK = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
PRODUCERS = {'native_arm': 'scripts/ci/native_arm.py', 'integration': 'scripts/ci/integration.py'}
SELECTION_KEYS = ('schema_version', 'purpose', 'identity', 'nonce', 'clock',
    'original_entry_monotonic', 'sources', 'inputs', 'producer_sources',
    'tool_pins', 'environment', 'output_path', 'credentials', 'cache_path')
PRODUCER_PINS = {'native_arm':'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    'integration':'5ceaa566f1084b25e8ebbbe8585b577de64595f70035e89943e87fbb83c6becf'}
PRECONSUMER_STAGES = ('fixtures','signer','lifecycle','repository','onboarding','desktop','source-suites')
STABLE_DIR = (0, 1, 2, 4, 5)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Held:
    """Retain small files and directories; stream cache payloads without copying."""
    def __init__(self, cutoff):
        self.cutoff, self.files, self.directories, self.closed = cutoff, [], [], False
        self.close_errors = []
        self.read_bytes = 0

    def check(self):
        need(not self.closed and time.monotonic() < self.cutoff, 'BORROW_ORIGINAL_CUTOFF')

    def directory(self, path):
        self.check(); path = parent_bridge.checked_path(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        row = [fd, path, parent_bridge.identity(os.fstat(fd))]
        self.directories.append(row)
        need(stat.S_ISDIR(row[2][2]) and not row[2][2] & 0o022, 'BORROW_DIRECTORY_MODE')
        self.guard(); return path

    def read(self, path, limit=8*1024**2, expected=None):
        self.check(); path = parent_bridge.checked_path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        row = [fd, path, None, None]; self.files.append(row)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, 'BORROW_FILE_TYPE_CAP')
        raw = parent_bridge.read_fd(fd, limit)
        self.read_bytes += len(raw)
        need(self.read_bytes <= 512*1024**2, 'BORROW_RETAINED_PROOF_TOTAL_CAP')
        row[2], row[3] = parent_bridge.identity(info), sha(raw)
        need(row[2] == parent_bridge.identity(path.lstat()), 'BORROW_FILE_IDENTITY')
        if expected is not None:
            need(row[3] == expected, 'BORROW_FILE_PIN')
        self.guard(); return raw

    def ref(self, path):
        path = parent_bridge.checked_path(path)
        rows = [r for r in self.files if r[1] == path and r[2] is not None]
        need(bool(rows), 'BORROW_FILE_NOT_HELD')
        row = rows[-1]
        result = dict(path=str(path), sha256=row[3], bytes=row[2][6], identity=list(row[2]))
        boundary.file_ref(result); return result

    def json(self, path, expected=None):
        # Original package-audit.json is about6.35MiB; it is not the1MiB
        # child protocol. Retain the ordinary8MiB proof-file cap and strict JSON.
        def pairs(rows):
            result = {}
            for key,value in rows:
                need(key not in result, 'BORROW_DUPLICATE_JSON_KEY'); result[key] = value
            return result
        def constant(_): raise ValueError('BORROW_NONFINITE_JSON')
        return json.loads(self.read(path, expected=expected),object_pairs_hook=pairs,parse_constant=constant)

    def payload(self, path, expected):
        """Hash one pinned <=2GiB cache object, checking the original clock per chunk."""
        self.check(); path = parent_bridge.checked_path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        first = None
        try:
            info = os.fstat(fd); before = parent_bridge.identity(info)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 type(expected['size']) is int and 0 <= info.st_size == expected['size'] <= 2*1024**3,
                 'BORROW_CACHE_TYPE_SIZE')
            digest, count = hashlib.sha256(), 0
            while True:
                self.check(); block = os.read(fd, 1024**2)
                if not block: break
                count += len(block); need(count <= expected['size'], 'BORROW_CACHE_SIZE')
                digest.update(block)
            need(count == expected['size'] and digest.hexdigest() == expected['sha256'] and
                 before == parent_bridge.identity(os.fstat(fd)) == parent_bridge.identity(path.lstat()),
                 'BORROW_CACHE_PIN')
            return before
        except BaseException as error:
            first = error; raise
        finally:
            try: os.close(fd)
            except BaseException as error:
                if first is None: raise
                first.add_note('BORROW_CACHE_CLOSE_UNCERTAIN:' + type(error).__name__)

    def guard(self, *, rehash=False):
        self.check()
        for fd, path, identity in self.directories:
            current, named = parent_bridge.identity(os.fstat(fd)), parent_bridge.identity(path.lstat())
            need(all(current[n] == named[n] == identity[n] for n in STABLE_DIR), 'BORROW_DIRECTORY_DRIFT')
        for fd, path, identity, digest in self.files:
            if identity is None: continue
            need(parent_bridge.identity(os.fstat(fd)) == identity == parent_bridge.identity(path.lstat()), 'BORROW_FILE_DRIFT')
            if rehash:
                need(sha(parent_bridge.read_fd(fd, 64*1024**2)) == digest, 'BORROW_FILE_BYTE_DRIFT')
        self.check()

    def close(self, primary=None):
        first = primary
        for row in (*self.files, *self.directories):
            try: os.close(row[0])
            except BaseException as error:
                self.close_errors.append(error)
                parent_bridge.HELD.append(dict(kind='BORROW_DESCRIPTOR_CLOSE_UNCERTAIN',fd=row[0]))
                if first is None: first = error
                else: first.add_note('BORROW_DESCRIPTOR_CLOSE_UNCERTAIN:' + type(error).__name__)
        self.closed = True
        if primary is None and first is not None: raise first


def _producer_root(modules, rows):
    need(type(modules) is dict and set(modules) == set(PRODUCERS) and
         all(type(m) is types.ModuleType for m in modules.values()), 'BORROW_PRODUCER_MODULES')
    boundary.exact(rows, PRODUCERS)
    root = None
    for name, relative in PRODUCERS.items():
        row = rows[name]; boundary.exact(row, ('path', 'sha256', 'bytes', 'mode'))
        boundary.pin(row['sha256']); need(row['sha256'] == PRODUCER_PINS[name] and row['mode'] in (0o444,0o555,0o644,0o755), 'BORROW_SELECTED_PRODUCER_PIN')
        path = parent_bridge.checked_path(row['path'])
        current_root = path.parents[2]
        need(path == current_root/relative and Path(modules[name].__file__).absolute() == path,
             'BORROW_PRODUCER_ORIGIN')
        need(root is None or root == current_root, 'BORROW_PRODUCER_ROOT')
        raw = owned_build.read_regular(path)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and
             stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'BORROW_PRODUCER_PIN')
        root = current_root
    need(Path(modules['native_arm'].ROOT).absolute() == root, 'BORROW_NATIVE_ROOT')
    return root


class Registration:
    """One registration and one synchronous selected consumer scope."""
    def __init__(self, adapter, pin, controller_type, modules):
        boundary.file_ref(pin)
        need(type(adapter) is types.ModuleType and sys.modules.get(adapter.__name__) is adapter,
             'BORROW_ADAPTER_MODULE')
        self.pin = deepcopy(pin)
        self.held = Held(float('inf'))
        need(not pin['identity'][2] & 0o222, 'BORROW_READONLY_REGISTRATION')
        try:
            self._register(adapter, pin, controller_type, modules)
        except BaseException as error:
            self.held.close(error); raise

    def _register(self, adapter, pin, controller_type, modules):
        self.selection = self.held.json(pin['path'], pin['sha256'])
        need(self.held.ref(pin['path']) == pin, 'BORROW_REGISTRATION_IDENTITY')
        selected = self.selection; boundary.exact(selected, SELECTION_KEYS)
        need(selected['schema_version'] == 1 and selected['purpose'] == 'project-libraries-cli-root-selection',
             'BORROW_ROOT_SELECTION')
        self.root = _producer_root(modules, selected['producer_sources'])
        for row in selected['producer_sources'].values(): self.held.read(row['path'], expected=row['sha256'])
        source = selected['sources']; relative = 'scripts/ci/private-library-cli/consumer_adapter.py'
        need(Path(adapter.__file__).absolute() == Path(source['root'])/relative and
             sha(owned_build.read_regular(adapter.__file__)) == source['files'][relative]['sha256'],
             'BORROW_SELECTED_ADAPTER')
        need(controller_type is modules['integration'].Controller, 'BORROW_SELECTED_CONTROLLER')
        self.controller_type, self.modules = controller_type, modules
        self.active = self.controller = self.lease = None
        self.used = self.retained = False

    @contextmanager
    def consumer_scope(self, controller):
        need(not self.used and self.active is None and type(controller) is self.controller_type,
             'BORROW_SCOPE_REPLAY_OR_CONTROLLER')
        self.held.guard(rehash=True)
        self.used, self.controller, self.active = True, controller, object()
        first = None
        try:
            yield self
        except BaseException as error:
            first = error; raise
        finally:
            self.active = None
            close_first = first
            pending = self.lease is not None and self.lease.child_submission_attempted and not self.lease.child_retired
            if pending:
                self.retained = True
                parent_bridge.HELD.append(dict(kind='BORROWED_LIFETIME_RECOVERY',registration=self,lease=self.lease))
                error = ValueError('BORROWED_LIFETIME_RETAINED_CHILD_NOT_RETIRED')
                if first is not None:first.add_note(str(error))
                if first is None:raise error
            else:
                try:
                    if self.lease is not None: self.lease.release(first)
                except BaseException as error:
                    close_first = error
                try: self.held.close(close_first)
                except BaseException as error:
                    if close_first is None: close_first = error
                    else: close_first.add_note('REGISTRATION_CLOSE_UNCERTAIN:' + type(error).__name__)
                if self.lease is not None and self.held.close_errors:
                    self.lease.postverified = False
                    if self.lease.state is not None:
                        for error in self.held.close_errors: self.lease.state.fail(error,cleanup=True)
                if first is None and close_first is not None: raise close_first

    def borrow(self, controller, record, cache, *, original_clock, original_entry):
        need(self.active is not None and self.controller is controller and self.lease is None,
             'BORROW_ONLY_LIVE_SELECTED_CONSUMER')
        selected = self.selection
        need(record['identity'] == selected['identity'] and record['nonce'] == selected['nonce'] and
             record['sources'] == selected['sources'] and record['inputs'] == selected['inputs'] and
             record['runtime']['socket'] == selected['tool_pins']['socket'] and
             record['clock'] == original_clock and original_entry == record['entry_monotonic'] == selected['original_entry_monotonic'],
             'BORROW_SELECTION_JOIN')
        need(parent_bridge.checked_path(cache) == parent_bridge.checked_path(selected['cache_path']), 'BORROW_CACHE_ARGUMENT')
        clock_raw = self.held.read(selected['clock']['path'], expected=selected['clock']['sha256'])
        need(self.held.ref(selected['clock']['path']) == selected['clock'] and boundary.decode(clock_raw) == original_clock,
             'BORROW_CLOCK_FILE_JOIN')
        boundary.validate_clock(original_clock, record['identity'], parent_bridge.clock_domain())
        cutoff = min(original_clock['deadline_monotonic']-120, original_entry+10080)
        need(original_clock['issued_monotonic'] <= original_entry <= time.monotonic() < cutoff == record['cutoff_monotonic'],
             'BORROW_ORIGINAL_CLOCK')
        self.held.cutoff = cutoff
        need(controller.cancelled is False and self.modules['integration'].CANCEL_REQUESTED is False and
             controller.commit == record['identity']['source_commit'], 'BORROW_LIVE_CONTROLLER')
        self.lease = Lease(self, controller, record, cache)
        return self.lease


def register_consumer(adapter_module, source_registration_pin, controller_type, native_modules):
    """Called only by the selected ordinary trusted bootstrap/adapter."""
    return Registration(adapter_module, source_registration_pin, controller_type, native_modules)


class Lease:
    def __init__(self, registration, controller, record, cache):
        need(type(registration) is Registration and registration.active is not None and
             registration.controller is controller and registration.lease is None, 'LEASE_NOT_ISSUED')
        self.registration, self.controller, self.record = registration, controller, record
        self.held = Held(record['cutoff_monotonic'])
        self.cache = self.native_out = None
        self.pidfd = None; self.released = self.postverified = self.preflight_done = self.terminal_done = False
        self.preflight_snapshot = self.observation = self.state = self.terminal_result = None
        self.child_submission_attempted = self.child_retired = False
        self.cache_rows, self.cache_identities = {}, {}
        try:
            self.cache = self.held.directory(cache)
            self.native_out = self.held.directory(controller.native_out)
            self.pidfd = os.pidfd_open(os.getpid(), 0)
            birth = parent_bridge.Host(None).birth(os.getpid())
            need(birth['pid'] == os.getpid() and birth['ppid'] > 0 and birth['start_ticks'] > 0, 'BORROW_PARENT_BIRTH')
            self.parent_birth = birth
            self.proof = self._baseline()
            path = Path(record['output']['path'])/'baseline-borrow.json'
            owned_build.save(path, self.proof)
            self.held.read(path)
            self._wire = dict(schema_version=1, kind='borrowed-baseline', image_id=controller.image,
                socket_identity=deepcopy(record['runtime']['socket']['identity']),
                packages_lock=self.held.ref(self.native_out/'packages.lock'), evidence=self.held.ref(path),
                run_id=record['identity']['run_id'], run_attempt=record['identity']['run_attempt'], nonce=record['nonce'],
                parent=dict(pid=birth['pid'], session_id=birth['sid'], start_time_ticks=birth['start_ticks'], pidfd_held=True),
                gates=dict(packages=341, acquired_objects=501, signature_decisions=249, builds=8, comparisons=4,
                    native_linux_arm64=True, integration='PASS'), cleanup_owner='parent',
                cache={'archlinuxarm_keyring':self.held.ref(self.cache/'archlinuxarm.gpg')})
            boundary.validate_lease(self._wire, record['identity'], record['runtime'], record['nonce'])
        except BaseException as error:
            self.release(error); raise

    @property
    def wire(self): return deepcopy(self._wire)

    def __reduce_ex__(self, protocol): raise TypeError('LIVE_LEASE_NOT_SERIALIZABLE')

    def _baseline(self):
        import operations
        report = self.controller.report
        need(type(report) is dict and report.get('controller_execution') != 'FAIL' and
             type(report.get('stages')) is dict and set(report['stages']) == set(PRECONSUMER_STAGES) and
             all(type(report['stages'][name]) is dict and report['stages'][name].get('status') == 'PASS' for name in PRECONSUMER_STAGES),
             'BORROW_PRECONSUMER_STAGES')
        root = self.registration.root; out = self.native_out; native = self.registration.modules['native_arm']
        inputs = self.held.json(root/'scripts/ci/inputs.lock.json', INPUTS)
        reviews = self.held.json(root/'scripts/ci/recipes.lock.json', RECIPES)
        self.held.read(root/'scripts/ci/integration.lock.json', expected=INTEGRATION)
        need(self.controller.lock == boundary.decode(owned_build.read_regular(root/'scripts/ci/integration.lock.json')),
             'BORROW_CONTROLLER_LOCK')
        self.held.read(out/'inputs.lock.json', expected=INPUTS)
        lock = self.held.read(out/'packages.lock', expected=LOCK).decode()
        wanted = {p['name'][0]:p['version'][0] for p in inputs['rootfs_packages']}
        wanted.update({p['name']:p['version'] for p in inputs['packages']})
        need(len(wanted) == 341 and lock == ''.join(k+' '+v+'\n' for k,v in sorted(wanted.items())), 'BORROW_ACTUAL_341_LOCK')
        result = self.held.json(out/'result.json'); bootstrap = self.held.json(out/'bootstrap.json')
        need(result.get('native_build') == 'PASS' and result.get('reviewed_inputs_sha256') == INPUTS and
             result.get('reviewed_recipes_sha256') == RECIPES and result.get('verified_signed_packages') == 248 and
             result.get('bootstrap_script_sha256') == self.registration.selection['producer_sources']['native_arm']['sha256'] and
             bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == self.controller.image and
             bootstrap.get('packages_lock_sha256') == LOCK and bootstrap.get('inputs_sha256') == INPUTS and
             self.held.read(out/'image-id').decode().strip() == self.controller.image, 'BORROW_PRODUCER_RECEIPTS')
        boundary.image(self.controller.image)
        runner = self.held.json(out/'runner.json')
        need(runner.get('kernel',{}).get('system') == 'Linux' and runner.get('kernel',{}).get('machine') in ('aarch64','arm64') and
             runner.get('docker_server_arch') in ('aarch64','arm64') and runner.get('commit') == self.controller.commit and
             runner.get('bootstrap_script_sha256') == result['bootstrap_script_sha256'], 'BORROW_ORIGINAL_NATIVE_OBSERVATION')
        items = inputs['keyring_files']+[inputs['rootfs'], native.signature_item(inputs['rootfs'])]
        for p in inputs['packages']: items += [p, native.signature_item(p)]
        need(len(items) == 501 and len({i['filename'] for i in items}) == 501 and
             sum(i['size'] for i in items) <= 2*1024**3, 'BORROW_FIXED_CACHE_CLOSURE')
        for item in items:
            name = native.input_name(item['filename']); boundary.pin(item['sha256'])
            self.cache_rows[name] = deepcopy(item)
            self.cache_identities[name] = self.held.payload(self.cache/name, item)
        self.held.read(self.cache/'archlinuxarm.gpg', expected=inputs['keyring_files'][0]['sha256'])
        checksums = self.held.json(out/'cache-checksums.json')
        need(checksums == {i['filename']:i['sha256'] for i in items}, 'BORROW_CACHE_RECEIPT_JOIN')
        acquisition = self.held.json(out/'acquisition.json')
        need(acquisition.get('acquisition') == 'PASS' and acquisition.get('counts') == dict(total=501, **{'pass':501}, fail=0, pending=0)
             and set(acquisition.get('inputs',{})) == set(checksums), 'BORROW_ACQUISITION')
        for item in items:
            need(acquisition['inputs'][item['filename']] == dict(status='PASS', expected_sha256=item['sha256'], expected_bytes=item['size']),
                 'BORROW_ACQUISITION_ITEM')
        signatures = self.held.json(out/'signatures.json')
        signed = [inputs['rootfs']]+inputs['packages']
        need(len(signed) == 249 and set(signatures) == {i['filename'] for i in signed}, 'BORROW_SIGNATURE_SET')
        for item in signed:
            row = signatures[item['filename']]
            need(type(row.get('exit_code')) is int and row['exit_code'] == 0 and type(row.get('status')) is str and
                 len(row['status'].encode()) <= 65536, 'BORROW_SIGNATURE_DECISION')
            native.valid_signature(row['status'], inputs['signer_fingerprint'])
        need(self.held.json(out/'rootfs-inventory.json') == inputs['rootfs_packages'], 'BORROW_ROOTFS_INVENTORY')
        audits = self.held.json(out/'package-audit.json')
        need(set(audits) == {p['filename'] for p in inputs['packages']}, 'BORROW_PACKAGE_AUDIT_SET')
        for p in inputs['packages']:
            found = audits[p['filename']]['metadata']
            for target, source in (('pkgname','name'),('pkgver','version'),('arch','arch'),('license','license'),
                    ('depend','depends'),('provides','provides'),('conflict','conflicts'),('replaces','replaces')):
                expected = p[source] if type(p[source]) is list else [p[source]]
                need(sorted(found.get(target,[])) == sorted(expected), 'BORROW_PACKAGE_AUDIT_METADATA')
        self.held.json(out/'rootfs-hooks.json')
        oracles = operations.SelectedOracles(self.record, producer_root=self.registration.root)
        names = tuple(native.RECIPES)
        need(len(reviews) == len(names) == 4 and {Path(p).name for p in reviews} == set(names), 'BORROW_FOUR_RECIPE_SET')
        pairs, environments = {}, set()
        for relative, hashes in reviews.items():
            boundary.relative(relative); recipe = oracles.recipe(root/relative/'PKGBUILD')
            need(not recipe['errors'] and recipe['input_sha256'] == hashes, 'BORROW_REVIEWED_RECIPE')
            key = Path(relative).name
            for number in (1,2):
                attempt = self.held.directory(out/(key+'-'+str(number)))
                provenance = self.held.json(attempt/'provenance.json')
                need(provenance.get('recipe_inputs') == hashes and provenance.get('recipe_metadata') == recipe['metadata'] and
                     provenance.get('status') == 'built-package-static-pass' and provenance.get('mode') == 'native' and
                     provenance.get('image') == provenance.get('image_id') == self.controller.image and
                     provenance.get('source_date_epoch') == inputs['source_date_epoch'] and
                     provenance.get('expected_packages_sha256') == LOCK, 'BORROW_ORIGINAL_BUILD')
                environment = provenance.get('clean_environment_id')
                need(type(environment) is str and environment.startswith('cachy-asahi-') and environment not in environments,
                     'BORROW_DISTINCT_ORIGINAL_ENVIRONMENTS')
                environments.add(environment)
                files = provenance.get('files',{})
                need(type(files) is dict and 9 <= len(files) <= 80 and type(provenance.get('artifacts')) is dict and
                     len(provenance['artifacts']) == 1, 'BORROW_BUILD_EVIDENCE_SET')
                for name, digest in files.items():
                    boundary.relative(name); self.held.read(attempt/name, 64*1024**2, digest)
                for name,digest in hashes.items():
                    boundary.relative(name); self.held.read(attempt/'inputs'/name, expected=digest)
                for name,digest in provenance['artifacts'].items():
                    need(Path(name).name == name and name.endswith(('.pkg.tar.xz','.pkg.tar.gz')), 'BORROW_ORIGINAL_ARCHIVE_FORMAT')
                    self.held.read(attempt/'artifacts'/name, 64*1024**2, digest)
                need(self.held.read(attempt/'expected-packages.lock') == self.held.read(attempt/'artifacts/packages.lock') == lock.encode(),
                     'BORROW_BUILD_ACTUAL_LOCK')
                oracles.bind_generated(recipe['metadata'], oracles.metadata(self.held.read(attempt/'artifacts/generated.SRCINFO').decode()))
                oracles.modules['compare'].verify(attempt)
            pair = oracles.modules['compare'].compare(out/(key+'-1'), out/(key+'-2'))
            need(pair.get('status') == 'contents-reproduced' and pair.get('errors') == [] and len(pair.get('packages',{})) == 1 and
                 all(all(row.get(k) is True for k in boundary.GATES) for row in pair['packages'].values()), 'BORROW_ORIGINAL_FULL_COMPARISON')
            need(self.held.json(out/(key+'-compare.json')) == pair, 'BORROW_ORIGINAL_COMPARE_RECEIPT')
            pairs[key] = pair
        self.held.guard(rehash=True)
        return dict(schema_version=1, purpose='live-original-producer-borrow', image_id=self.controller.image,
            trusted_callpoint='integration.Controller.run/consumer-before-finally', inputs_sha256=INPUTS,
            recipes_sha256=RECIPES, integration_sha256=INTEGRATION, lock_sha256=LOCK,
            preconsumer_stages={name:report['stages'][name]['status'] for name in PRECONSUMER_STAGES},
            cache={name:dict(sha256=row['sha256'], bytes=row['size'], identity=self.cache_identities[name])
                for name,row in self.cache_rows.items()}, comparisons=pairs,
            held_files=[self.held.ref(r[1]) for r in self.held.files if r[2] is not None],
            limits=['Original producer execution is trusted at the selected callback.',
                'Original retained signature decisions are rechecked; no fresh GPG authentication.',
                'Original comparisons attest distinct recorded names, not newly proven CID custody.',
                'Integration PASS means seven preconsumer stages only; original finish/cleanup/job finalization is pending.',
                'No public redistribution or hardware acceptance.'])

    def _guard(self, record, custody, *, rehash=False, cleanup=False):
        need(not self.released and self.registration.active is not None and self.registration.lease is self and
             self.controller is self.registration.controller and record['baseline'] == self._wire and
             record['identity'] == self.registration.selection['identity'] and record['nonce'] == self._wire['nonce'], 'LEASE_LIVE_JOIN')
        custody.guard(cleanup=cleanup)
        self.registration.held.guard(rehash=True); self.held.guard(rehash=rehash)
        need(self.controller.image == self._wire['image_id'] and self.controller.commit == record['identity']['source_commit'], 'LEASE_CONTROLLER_DRIFT')
        if not cleanup:
            need(self.controller.cancelled is False and self.registration.modules['integration'].CANCEL_REQUESTED is False, 'LEASE_PRODUCER_CANCELLED')
        need(self.pidfd is not None and parent_bridge.Host(None).birth(os.getpid()) == self.parent_birth, 'LEASE_PARENT_BIRTH_DRIFT')
        os.fstat(self.pidfd)
        for name,row in self.cache_rows.items():
            need(parent_bridge.identity((self.cache/name).lstat()) == self.cache_identities[name], 'LEASE_CACHE_IDENTITY_DRIFT')
            if rehash: need(self.held.payload(self.cache/name,row) == self.cache_identities[name], 'LEASE_CACHE_BYTE_DRIFT')

    def _command(self, record, custody, command_id, *, cleanup=False):
        import evidence
        runner = parent_bridge.OwnedRunner(record, custody.state, custody)
        self._guard(record, custody, cleanup=cleanup)
        result = runner.run(command_id, {}, timeout=60, cleanup=cleanup)
        evidence.success_process(result)
        need(type(result['log']) is bytes and len(result['log']) == result['bytes'] <= boundary.LOG_LIMIT and
             sha(result['log']) == result['sha256'], 'BASELINE_COMMAND_LOG')
        self._guard(record, custody, cleanup=cleanup)
        return result

    def _observe(self, record, custody, *, cleanup=False):
        info = boundary.decode(self._command(record,custody,'baseline-info',cleanup=cleanup)['log'])
        image = boundary.decode(self._command(record,custody,'baseline-inspect',cleanup=cleanup)['log'])
        return self._observation(info,image)

    def _observation(self, info, image):
        need(info.get('Architecture') in ('aarch64','arm64') and info.get('OSType') == 'linux' and
             type(info.get('ID')) is str and 0 < len(info['ID']) <= 256 and
             type(info.get('ServerVersion')) is str and 0 < len(info['ServerVersion']) <= 256,
             'BASELINE_DAEMON_OBSERVATION')
        need(image.get('Id') == self._wire['image_id'] and image.get('Architecture') == 'arm64' and image.get('Os') == 'linux',
             'BASELINE_IMAGE_OBSERVATION')
        return dict(daemon={k:info[k] for k in ('ID','Architecture','OSType','ServerVersion')}, image_id=image['Id'])

    def preflight(self, record, custody):
        need(not self.preflight_done and not self.terminal_done and custody.state.snapshot()['commands'] == 1, 'LEASE_PREFLIGHT_REPLAY')
        self.preflight_done = True
        self.state = custody.state
        self._guard(record,custody,rehash=True)
        self.observation = self._observe(record,custody)
        self.preflight_snapshot = custody.state.snapshot()
        need(self.preflight_snapshot['commands'] == 3 and self.preflight_snapshot['fetches'] == 0, 'LEASE_PREFLIGHT_BUDGET')
        owned_build.save(Path(record['output']['path'])/'baseline-preflight.json', self.observation)
        return deepcopy(self.preflight_snapshot)

    def terminal(self, record, child, process, custody):
        import operations
        need(self.preflight_done and not self.terminal_done and parent_bridge.process_retired(process), 'LEASE_TERMINAL_REPLAY_OR_RETIREMENT')
        self.terminal_done = True
        state = custody.state; checked = values = ledger = None
        process_row = dict(pid=process['birth']['pid'], session_id=process['birth']['sid'], start_time_ticks=process['birth']['start_ticks'],
            pidfd_held=process['pidfd_owned'], reaped=process['reaped'], exit_code=process['exit_code'], natural=process['natural_exit'])
        # Preserve the validated inner terminal even when the wrapper already
        # holds an earlier command-exit failure. It is private evidence only.
        try:
            if child is not None:
                owned_build.save(Path(record['output']['path'])/'baseline-child-terminal.json', child)
        except BaseException as error:
            state.fail(error, cleanup=state.first_cause is not None)
        try:
            self._guard(record,custody,rehash=True,cleanup=True)
            need(child is not None and state.budget_known and state.child_budget_merged, 'LEASE_CHILD_BUDGET_UNKNOWN')
            if self.controller.cancelled or self.registration.modules['integration'].CANCEL_REQUESTED:
                state.fail(KeyboardInterrupt('LEASE_PRODUCER_CANCELLED'), cancel=True)
            # Each read-only postcheck is attempted independently with known
            # remaining budget. A failed absence check cannot skip baseline
            # reobservation, and none of these commands removes borrowed state.
            failures = []
            for command_id in ('parent-container-absence','parent-image-absence'):
                try:
                    need(not self._command(record,custody,command_id,cleanup=True)['log'].strip(), 'PARENT_OWNED_RESOURCE_REMAINS')
                except BaseException as error:
                    state.fail(error,cleanup=True,cancel=isinstance(error,KeyboardInterrupt)); failures.append(error)
            observations = {}
            for command_id in ('baseline-info','baseline-inspect'):
                try:
                    observations[command_id] = boundary.decode(self._command(record,custody,command_id,cleanup=True)['log'])
                except BaseException as error:
                    state.fail(error,cleanup=True,cancel=isinstance(error,KeyboardInterrupt)); failures.append(error)
            if len(observations) == 2:
                checked = self._observation(observations['baseline-info'],observations['baseline-inspect'])
                need(checked == self.observation, 'BASELINE_POST_OBSERVATION_DRIFT')
            need(not failures, 'LEASE_POSTCHECK_FAILURE')
            self._guard(record,custody,rehash=True,cleanup=True)
            raw = owned_build.read_regular(Path(record['output']['path'])/'resource-ledger.jsonl', boundary.RECORD_LIMIT)
            ledger = boundary.validate_journal(raw, nonce=record['nonce'], baseline_id=self._wire['image_id'])
            need(ledger == child['resources'], 'PARENT_JOURNAL_CHILD_JOIN')
            values = operations.verify_business(record,custody,child,producer_root=self.registration.root)
            need(process['exit_code'] == 0 and process['natural_exit'] is True and process['uncertainty'] == [] and
                 process['first_failure'] is None and child['status'] == 'CHILD_COMPLETE', 'LEASE_CHILD_NOT_COMPLETE')
            need(state.first_cause is None and not state.cleanup_errors and not state.cancelled, 'LEASE_STICKY_FAILURE')
            owned_build.save(Path(record['output']['path'])/'baseline-postflight.json',dict(
                schema_version=1,purpose='parent-after-child-baseline-check',status='PASS',
                observation=checked,process=process_row,budget=state.snapshot(),
                journal_sha256=sha(raw),owned_absence_checks={
                    'parent-container-absence':True,'parent-image-absence':True}))
            self.postverified = True
        except BaseException as error:
            state.fail(error, cancel=isinstance(error,KeyboardInterrupt))
        if not self.postverified:
            self.terminal_result = state.terminal(child=process_row,status='INCOMPLETE')
            return self.terminal_result
        class Replay:
            def snapshot(inner): return deepcopy(ledger)
        self.terminal_result = state.terminal(ledger=Replay(),child=process_row,status='PRIVATE_CHECKED',
            private_checks={k:True for k in boundary.PRIVATE_CHECKS}, **values)
        return self.terminal_result

    def release(self, primary=None):
        need(not self.child_submission_attempted or self.child_retired, 'LEASE_RELEASE_BEFORE_CHILD_RETIREMENT')
        if self.released: return
        self.released = True
        first = primary
        try: self.held.close(first)
        except BaseException as error: first = error
        if self.state is not None:
            for error in self.held.close_errors: self.state.fail(error,cleanup=True)
        if self.pidfd is not None:
            fd,self.pidfd = self.pidfd,None
            try: os.close(fd)
            except BaseException as error:
                parent_bridge.HELD.append(dict(kind='LEASE_PIDFD_CLOSE_UNCERTAIN',fd=fd))
                if self.state is not None: self.state.fail(error,cleanup=True)
                if first is None: first = error
                else: first.add_note('LEASE_PIDFD_CLOSE_UNCERTAIN:' + type(error).__name__)
        if first is not None: self.postverified = False
        if primary is None and first is not None: raise first
