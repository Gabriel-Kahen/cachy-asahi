"""Private proposal: exact-ID Docker ownership; no actor runs on import.

The coordinator supplies the authenticated CLI runner and durable journal writer.
These are trusted implementation capabilities, never fields in a Source grant.
The runner must retire its command before returning/raising and use the supplied
absolute endpoint. Docker mutations can still have ambiguous daemon outcomes:
missing objects after such a mutation are uncertainty, not successful cleanup.
"""
import copy
import json
import math
import re
import time

DOCKER = '/usr/bin/docker'
ROLES = ('provision', 'topmem-1', 'topmem-2', 'fish-1', 'fish-2')
IMAGE_ROLES = ('rootfs', 'compiler')
PREFIX = 'org.cachy-asahi.pair.'
MAX_JSON = 2 * 1024 * 1024
MAX_RECORD = 256 * 1024
CPU = 2_000_000_000
MEMORY = 4 * 1024 ** 3
PIDS = 256


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def image_id(value):
    return type(value) is str and re.fullmatch('sha256:[0-9a-f]{64}', value) is not None


def endpoint(value):
    return type(value) in (float, int) and math.isfinite(value) and value > 0


def absolute(value):
    return (type(value) is str and value.startswith('/') and value != '/' and
            len(value) <= 4096 and all(part not in ('', '.', '..')
                                     for part in value[1:].split('/')) and
            all(char not in value for char in ('\x00', '\n', '\r', ',')))


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_JSON, 'docker-response-bound')
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'docker-duplicate-json-key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=object_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused('docker-nonfinite-json')))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Refused('docker-json') from error


class Owner:
    """At most five fresh containers and two fresh images, under one endpoint.

    call(argv: tuple[str,...], end: float) -> bytes, nonzero must raise.
    journal(serialized_bytes) must atomically/durably retain bytes in Root-owned
    FD custody or raise. No Docker operation occurs until its intent is durable.
    Root owns path/FD custody and authenticates fixed input/source buffers; this
    broker binds those paths to the exact inspectable Docker resource contract.
    """
    def __init__(self, call, journal, *, work_end, cleanup_end, daemon_id,
                 source_sha, context_sha, nonce, uid, gid, now=time.monotonic):
        need(callable(call) and callable(journal) and callable(now), 'trusted-capabilities')
        need(endpoint(work_end) and endpoint(cleanup_end) and work_end < cleanup_end,
             'original-endpoints')
        need(type(daemon_id) is str and re.fullmatch('[A-Za-z0-9:_-]{1,128}', daemon_id),
             'daemon-identity')
        need(digest(source_sha) and digest(context_sha) and type(nonce) is str and
             re.fullmatch('[0-9a-f]{32}', nonce), 'source-context-nonce')
        need(type(uid) is int and type(gid) is int and 0 < uid < 2**31 and 0 < gid < 2**31,
             'nonroot-package-identity')
        self.call, self.journal, self.now = call, journal, now
        self.work_end, self.cleanup_end = work_end, cleanup_end
        self.daemon_id, self.source_sha, self.context_sha = daemon_id, source_sha, context_sha
        self.nonce, self.uid, self.gid = nonce, uid, gid
        self.containers, self.images = [], []
        self.first_cause = None
        self.cleanup_errors = []
        self.cleaned = False
        self._persist()

    def _cause(self, error):
        if self.first_cause is None:
            self.first_cause = error

    def _check(self, end):
        need(self.now() < end, 'original-endpoint-expired')

    def _persist(self):
        value = {'schema': 1, 'purpose': 'native-two-recipe-build-pair-owner',
                 'daemon_id': self.daemon_id, 'nonce': self.nonce,
                 'source_sha256': self.source_sha, 'context_sha256': self.context_sha,
                 'work_end': self.work_end, 'cleanup_end': self.cleanup_end,
                 'containers': self.containers, 'images': self.images,
                 'cleanup_errors': self.cleanup_errors}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        need(len(raw) <= MAX_RECORD, 'journal-bound')
        self.journal(raw)

    def _operation(self, args, cleanup=False):
        end = self.cleanup_end if cleanup else self.work_end
        self._check(end)
        need(cleanup or self.first_cause is None, 'first-cause-work-stopped')
        raw = self.call((DOCKER, *args), end)
        self._check(end)
        need(type(raw) is bytes and len(raw) <= MAX_JSON, 'docker-response-bound')
        return raw

    def _daemon(self, cleanup=False):
        value = decode(self._operation(('info', '--format', '{{json .ID}}'), cleanup))
        need(value == self.daemon_id, 'daemon-identity-drift')

    def _labels(self, role):
        return {PREFIX + 'nonce': self.nonce, PREFIX + 'source': self.source_sha,
                PREFIX + 'context': self.context_sha, PREFIX + 'daemon': self.daemon_id,
                PREFIX + 'role': role}

    def _label_args(self, role):
        return tuple(arg for key, value in sorted(self._labels(role).items())
                     for arg in ('--label', key + '=' + value))

    def _changes(self, role):
        return tuple(arg for key, value in sorted(self._labels(role).items())
                     for arg in ('--change', 'LABEL ' + key + '=' + value))

    def _find_container(self, row, cleanup=False):
        # List is only a discovery operation. Inspect is mandatory before mutation.
        self._daemon(cleanup)
        raw = self._operation(('container', 'ls', '--all', '--no-trunc', '--format', '{{json .}}',
                               '--filter', 'name=^/' + row['name'] + '$'), cleanup)
        lines = raw.splitlines()
        need(len(lines) <= 1, 'reserved-name-ambiguous')
        named = None
        if lines:
            item = decode(lines[0])
            need(type(item) is dict and item.get('Names') == row['name'] and digest(item.get('ID')),
                 'reserved-name-list')
            need(row['id'] is None or row['id'] == item['ID'], 'reserved-name-id-drift')
            named = item['ID']
        if row['id'] is not None:
            raw = self._operation(('container', 'ls', '--all', '--no-trunc', '--format', '{{json .}}',
                                   '--filter', 'id=' + row['id']), cleanup)
            ids = [decode(line) for line in raw.splitlines()]
            need(len(ids) <= 1 and all(type(item) is dict and item.get('ID') == row['id'] and
                 item.get('Names') == row['name'] for item in ids), 'retained-container-name-id-drift')
            need((bool(ids) and named == row['id']) or (not ids and named is None),
                 'retained-container-list-disagreement')
        return named

    def _image(self, identifier, row, cleanup=False):
        need(image_id(identifier), 'image-full-id')
        self._daemon(cleanup)
        values = decode(self._operation(('image', 'inspect', identifier), cleanup))
        need(type(values) is list and len(values) == 1, 'image-inspect-cardinality')
        item = values[0]
        need(type(item) is dict and item.get('Id') == identifier and item.get('Os') == 'linux' and
             item.get('Architecture') == 'arm64' and type(item.get('Config')) is dict,
             'image-native-identity')
        config = item['Config']
        need(config.get('Labels') == self._labels(row['role']), 'image-ownership-labels')
        need(not config.get('Volumes') and not config.get('Healthcheck') and
             not config.get('OnBuild') and not config.get('Entrypoint') and not config.get('Cmd') and
             not config.get('Env'),
             'image-hidden-execution')
        need(config.get('User') == ('0:0' if row['role'] == 'rootfs' else f'{self.uid}:{self.gid}') and
             config.get('WorkingDir') == ('/' if row['role'] == 'rootfs' else '/tmp'),
             'image-user')
        return item

    def _find_images(self, row, cleanup=False):
        self._daemon(cleanup)
        filters = tuple(arg for key, value in sorted(self._labels(row['role']).items())
                        for arg in ('--filter', 'label=' + key + '=' + value))
        raw = self._operation(('image', 'ls', '--all', '--no-trunc', '--quiet', *filters), cleanup)
        ids = set(raw.decode('ascii').splitlines())
        need(len(ids) <= 1 and all(image_id(value) for value in ids), 'owned-image-list')
        if row['id'] is not None:
            need(not ids or ids == {row['id']}, 'owned-image-id-drift')
            raw = self._operation(('image', 'ls', '--all', '--no-trunc', '--quiet'), cleanup)
            all_ids = set(raw.decode('ascii').splitlines())
            need(len(all_ids) <= 4096 and all(image_id(value) for value in all_ids), 'finite-all-image-list')
            need((row['id'] in all_ids and ids == {row['id']}) or
                 (row['id'] not in all_ids and not ids), 'retained-image-index-drift')
        return next(iter(ids)) if ids else None

    def _container(self, identifier, row, cleanup=False):
        need(digest(identifier), 'container-full-id')
        self._daemon(cleanup)
        values = decode(self._operation(('container', 'inspect', identifier), cleanup))
        need(type(values) is list and len(values) == 1, 'container-inspect-cardinality')
        item = values[0]
        need(type(item) is dict and item.get('Id') == identifier and
             item.get('Name') == '/' + row['name'] and item.get('Image') == row['image'],
             'container-full-identity')
        config, host = item.get('Config'), item.get('HostConfig')
        need(type(config) is dict and type(host) is dict, 'container-config')
        need(config.get('Labels') == self._labels(row['role']) and
             config.get('User') == row['user'] and config.get('Entrypoint') == ['/bin/bash'] and
             config.get('Cmd') == row['command'] and config.get('Env') == row['environment'],
             'container-label-command-user')
        need(host.get('NetworkMode') == 'none' and host.get('Privileged') is False and
             host.get('ReadonlyRootfs') == (row['role'] != 'provision') and
             host.get('NanoCpus') == CPU and host.get('Memory') == MEMORY and
             host.get('MemorySwap') == MEMORY and host.get('PidsLimit') == PIDS and
             host.get('AutoRemove') is False and host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0} and
             host.get('SecurityOpt') == ['no-new-privileges'] and host.get('CapDrop') == ['ALL'] and
             host.get('CapAdd') == ([] if row['role'] != 'provision' else ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID']) and
             not host.get('Devices') and not host.get('DeviceRequests') and not host.get('VolumesFrom') and
             not host.get('PidMode') and host.get('IpcMode') == 'private' and
             host.get('CgroupnsMode') == 'private' and host.get('Runtime') == 'runc' and
             host.get('Tmpfs') == ({} if row['role'] == 'provision' else
                                  {'/tmp': 'rw,nosuid,nodev,exec,size=4g'}),
             'container-resource-isolation')
        mounts = item.get('Mounts')
        need(type(mounts) is list and len(row['mounts']) <= len(mounts) <= len(row['mounts']) + 1 and
             all(type(mount) is dict and (mount.get('Type') == 'bind' or
                 (row['role'] != 'provision' and mount.get('Type') == 'tmpfs' and
                  mount.get('Destination') == '/tmp' and mount.get('RW') is True)) for mount in mounts),
             'container-mount-cardinality')
        actual = sorted((mount.get('Source'), mount.get('Destination'), mount.get('RW'))
                        for mount in mounts if type(mount) is dict and mount.get('Type') == 'bind')
        expected = sorted((mount['source'], mount['target'], not mount['readonly']) for mount in row['mounts'])
        need(actual == expected, 'container-owned-mounts')
        need(type(item.get('State')) is dict, 'container-state')
        return item

    def _ticket(self, ticket):
        need(type(ticket) is int and 0 <= ticket < len(self.containers), 'container-ticket')
        return self.containers[ticket]

    def reserve(self, role, image, *, mounts, command, environment):
        """Authenticated Root supplies commands and held paths, never grant input."""
        try:
            self._check(self.work_end)
            need(not self.cleaned and role in ROLES and len(self.containers) < 5 and
                 role not in {row['role'] for row in self.containers}, 'fixed-role-reservation')
            images = [row for row in self.images if row['id'] == image and row['ready']]
            need(len(images) == 1, 'image-not-owned-ready')
            expected_role = 'rootfs' if role == 'provision' else 'compiler'
            need(images[0]['role'] == expected_role, 'image-role')
            need(type(command) in (list, tuple) and 1 <= len(command) <= 16 and
                 all(type(value) is str and 0 < len(value) <= 65536 and '\x00' not in value for value in command),
                 'authenticated-command-bound')
            need(type(environment) in (list, tuple) and
                 list(environment) == ([] if role == 'provision' else
                    ['CACHY_ASAHI_CONTAINER=1', 'SOURCE_DATE_EPOCH=1791748800']) and len(environment) <= 16 and
                 all(type(value) is str and re.fullmatch('[A-Z][A-Z0-9_]*=[^\x00\n\r]{0,4096}', value)
                     for value in environment) and
                 len({value.split('=', 1)[0] for value in environment}) == len(environment),
                 'authenticated-environment-bound')
            need(type(mounts) in (list, tuple) and len(mounts) == 4 and
                 all(type(mount) is dict and set(mount) == {'source', 'target', 'readonly'} and
                     absolute(mount['source']) and absolute(mount['target']) and
                     type(mount['readonly']) is bool for mount in mounts), 'held-path-mounts')
            targets = [mount['target'] for mount in mounts]
            need(len(set(targets)) == len(targets) and
                 all(target in ('/deps', '/context', '/keys', '/provision.sh', '/inputs', '/out',
                               '/builder-entry.sh', '/expected-packages.lock') for target in targets), 'fixed-mount-targets')
            need((role == 'provision' and set(targets) == {'/deps', '/context', '/keys', '/provision.sh'} and
                  all(mount['readonly'] for mount in mounts) and list(command) == ['/provision.sh']) or
                 (role != 'provision' and set(targets) == {'/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'} and
                  all(mount['readonly'] == (mount['target'] != '/out') for mount in mounts) and
                  list(command) == ['/builder-entry.sh']),
                 'role-mount-contract')
            self._image(image, images[0])
            row = {'role': role, 'name': 'cachy-asahi-pair-' + self.nonce + '-' + role,
                   'image': image, 'id': None, 'mounts': copy.deepcopy(list(mounts)),
                   'command': list(command), 'environment': list(environment),
                   'user': '0:0' if role == 'provision' else f'{self.uid}:{self.gid}',
                   'attempted': False, 'confirmed': False, 'waited': False, 'removed': False}
            self.containers.append(row)
            self._persist()
            return len(self.containers) - 1
        except BaseException as error:
            self._cause(error)
            raise

    def import_rootfs(self, rootfs):
        try:
            need(not self.cleaned and not self.images and absolute(rootfs), 'single-held-rootfs')
            row = {'role': 'rootfs', 'id': None, 'attempted': False, 'confirmed': False,
                   'ready': False, 'removed': False}
            self.images.append(row)
            self._persist()
            need(self._find_images(row) is None, 'image-label-collision')
            row['attempted'] = True
            self._persist()
            raw = self._operation(('image', 'import', '--platform', 'linux/arm64',
                                   *self._changes('rootfs'), '--change', 'USER 0:0', '--change', 'WORKDIR /', rootfs))
            identifier = raw.decode('ascii').strip()
            need(image_id(identifier), 'import-outcome-ambiguous')
            row['id'], row['confirmed'] = identifier, True
            self._persist()
            self._image(identifier, row)
            row['ready'] = True
            self._persist()
            return identifier
        except BaseException as error:
            self._cause(error)
            raise

    def create(self, ticket):
        try:
            row = self._ticket(ticket)
            need(not self.cleaned and not row['attempted'], 'single-create')
            need(self._find_container(row) is None, 'reserved-name-collision')
            row['attempted'] = True
            self._persist()
            options = ('create', '--name', row['name'], '--pull=never', '--platform', 'linux/arm64',
                       '--network=none', '--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256',
                       '--cap-drop=ALL', '--security-opt=no-new-privileges', '--restart=no',
                       '--ipc=private', '--cgroupns=private', '--runtime=runc',
                       '--user', row['user'], '--entrypoint', '/bin/bash')
            if row['role'] != 'provision':
                options += ('--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g')
            else:
                options += tuple(arg for cap in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID')
                                 for arg in ('--cap-add', cap))
            options += self._label_args(row['role'])
            options += tuple(arg for value in row['environment'] for arg in ('--env', value))
            options += tuple(arg for mount in row['mounts'] for arg in (
                '--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target'] +
                (',readonly' if mount['readonly'] else '')))
            raw = self._operation((*options, row['image'], *row['command']))
            identifier = raw.decode('ascii').strip()
            need(digest(identifier), 'create-outcome-ambiguous')
            row['id'], row['confirmed'] = identifier, True
            self._persist()
            self._container(identifier, row)
            return identifier
        except BaseException as error:
            self._cause(error)
            raise

    def start(self, ticket):
        try:
            row = self._ticket(ticket)
            need(not self.cleaned and row['confirmed'] and not row.get('start_attempted'), 'single-owned-start')
            item = self._container(row['id'], row)
            need(item['State'].get('Status') == 'created', 'start-created-only')
            row['start_attempted'] = True
            self._persist()
            # Detached start keeps the command owner distinct from daemon lifetime.
            self._operation(('container', 'start', row['id']))
        except BaseException as error:
            self._cause(error)
            raise

    def wait(self, ticket):
        try:
            row = self._ticket(ticket)
            need(not self.cleaned and row.get('start_attempted') and not row['waited'], 'single-owned-wait')
            self._container(row['id'], row)
            raw = self._operation(('container', 'wait', row['id']))
            need(re.fullmatch(rb'[0-9]{1,3}\n?', raw) is not None, 'container-wait-code')
            code = int(raw)
            item = self._container(row['id'], row)
            need(0 <= code <= 255 and item['State'].get('Status') == 'exited' and
                 type(item['State'].get('ExitCode')) is int and item['State']['ExitCode'] == code and
                 item['State'].get('OOMKilled') is False and not item['State'].get('Error'), 'container-exit-state')
            row['waited'], row['exit_code'] = True, code
            self._persist()
            need(code == 0, 'container-command-failed')
            return code
        except BaseException as error:
            self._cause(error)
            raise

    def logs(self, ticket):
        try:
            row = self._ticket(ticket)
            need(not self.cleaned and row['waited'], 'logs-after-owned-wait')
            self._container(row['id'], row)
            return self._operation(('container', 'logs', row['id']))
        except BaseException as error:
            self._cause(error)
            raise

    def commit(self, ticket):
        try:
            row = self._ticket(ticket)
            need(not self.cleaned and row['role'] == 'provision' and row['waited'] and
                 row.get('exit_code') == 0 and len(self.images) == 1, 'single-successful-provision-commit')
            item = self._container(row['id'], row)
            need(item['State'].get('Status') == 'exited', 'commit-stopped-only')
            image = {'role': 'compiler', 'id': None, 'attempted': False, 'confirmed': False,
                     'ready': False, 'removed': False}
            self.images.append(image)
            self._persist()
            need(self._find_images(image) is None, 'image-label-collision')
            image['attempted'] = True
            self._persist()
            raw = self._operation(('container', 'commit', '--pause=false', *self._changes('compiler'),
                                   '--change', f'USER {self.uid}:{self.gid}', '--change', 'WORKDIR /tmp',
                                   '--change', 'ENTRYPOINT []', '--change', 'CMD []', row['id']))
            identifier = raw.decode('ascii').strip()
            need(image_id(identifier), 'commit-outcome-ambiguous')
            image['id'], image['confirmed'] = identifier, True
            self._persist()
            self._image(identifier, image)
            image['ready'] = True
            self._persist()
            return identifier
        except BaseException as error:
            self._cause(error)
            raise

    def _retire_container(self, row):
        if row['removed'] or not row['attempted']:
            return
        identifier = self._find_container(row, True)
        need(identifier is not None or row['confirmed'], 'unknown-create-no-positive-reconciliation')
        if identifier is not None:
            self._container(identifier, row, True)
            # Never remove a bare name; successful inspect is the destructive predicate.
            self._daemon(True)
            self._operation(('container', 'rm', '--force', identifier), True)
        need(self._find_container(row, True) is None, 'container-removal-absence')
        row['removed'] = True
        self._persist()

    def _retire_image(self, row):
        if row['removed'] or not row['attempted']:
            return
        identifier = self._find_images(row, True)
        need(identifier is not None or row['confirmed'], 'unknown-image-no-positive-reconciliation')
        if identifier is not None:
            self._image(identifier, row, True)
            self._daemon(True)
            # No force, no prune, no deletion of foreign image users or descendants.
            self._operation(('image', 'rm', identifier), True)
        need(self._find_images(row, True) is None, 'image-removal-absence')
        row['removed'] = True
        self._persist()

    def cleanup(self):
        """Finite all-resource attempt, preserving cause; never resets endpoints.

        Caller must defer cancellation around this finite cleanup and publish only
        after successful return. No hard latency guarantee for daemon/syscalls is
        inferred from successful fixture controls. Expiry makes cleanup uncertain.
        """
        if self.cleaned:
            return {'status': 'PASS' if not self.cleanup_errors else 'FAIL',
                    'errors': list(self.cleanup_errors), 'cause': self.first_cause}
        for kind, rows, operation in (('container', self.containers, self._retire_container),
                                       ('image', self.images, self._retire_image)):
            for row in reversed(rows):
                try:
                    operation(row)
                except BaseException as error:
                    self._cause(error)
                    self.cleanup_errors.append({'kind': kind, 'role': row['role'],
                                                'error_type': type(error).__name__, 'uncertain': True})
        self.cleaned = True
        try:
            self._persist()
        except BaseException as error:
            self._cause(error)
            self.cleanup_errors.append({'kind': 'journal', 'role': 'terminal',
                                        'error_type': type(error).__name__, 'uncertain': True})
        return {'status': 'PASS' if not self.cleanup_errors else 'FAIL',
                'errors': list(self.cleanup_errors), 'cause': self.first_cause}
