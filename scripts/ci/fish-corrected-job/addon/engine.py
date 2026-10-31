# SPDX-License-Identifier: MIT
"""Finite Fish V2 engine; shares the corrected caller producer/runtime."""
"""Proposed reusable finite addon API. Source-only; inherits worker clock/image/recovery."""
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from contextlib import contextmanager

def bind(profile, base):
    BASE = Path(base)
    PROFILE = profile
    if PROFILE == 'fish-history-v1':
        NAME = 'cachy-asahi-fish-bang-bang'
        LOCK = 'ae2fec448fb5511e8dba7bcd5b04bf5695c067e7a1e7d117b44cfcf24040be10'
        OWNED = {'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command.fish': ('__history_previous_command.fish', 420), 'usr/share/cachy-asahi/fish-bang-bang/__history_previous_command_arguments.fish': ('__history_previous_command_arguments.fish', 420), 'usr/share/cachy-asahi/fish-bang-bang/opt-in.fish': ('opt-in.fish', 420), 'usr/share/cachy-asahi/fish-bang-bang/README.md': ('usage.md', 420), 'usr/share/licenses/cachy-asahi-fish-bang-bang/NOTICE': ('NOTICE', 420), 'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.upstream': ('LICENSE.upstream', 420), 'usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.project': ('LICENSE.project', 420)}
        DEPENDS = ['fish>=4.0']
        OPTDEPENDS = ['cachy-asahi-fish-config: separately enabled original shell helpers']
        RECIPE_FILES = ('.SRCINFO', 'PKGBUILD', '__history_previous_command.fish', '__history_previous_command_arguments.fish', 'opt-in.fish', 'usage.md', 'NOTICE', 'LICENSE.upstream', 'LICENSE.project')
        SCOPE = 'fish-history-addon'
        SIGNING = 'fish-history-signing'
        REPO = 'fish-history'
        SIGNER_ENV = 'FISH_SIGNER_FP'
        ENTRY_TARGET = '/fish-history-lifecycle.sh'
        PROBE_TARGET = '/fish-history-probe.py'
        STATUS = 'PROVISIONAL_FISH_HISTORY_NATIVE_ADDON'
        PACKAGE_PATTERN = re.escape(NAME) + '-0\\.1\\.0-[12]-any\\.pkg\\.tar\\.(xz|gz|zst)'
        EXTRA_SOURCE = {'original-config.fish'}
        EXTRA_SOURCE_ORDER = ('original-config.fish',)
    elif PROFILE == 'topmem-v1':
        NAME = 'cachy-asahi-topmem'
        LOCK = '5afc6f120ee8a741cbe890c2f010a6a7d0c9b4fa3ea6d10b13500f42ef4c3eba'
        OWNED = {'usr/bin/cachy-asahi-topmem': ('cachy-asahi-topmem', 493), 'usr/share/doc/cachy-asahi-topmem/README.md': ('README.md', 420), 'usr/share/licenses/cachy-asahi-topmem/NOTICE': ('NOTICE', 420), 'usr/share/licenses/cachy-asahi-topmem/LICENSE': ('LICENSE', 420)}
        DEPENDS = ['python>=3.11']
        OPTDEPENDS = []
        RECIPE_FILES = ('.SRCINFO', 'LICENSE', 'NOTICE', 'PKGBUILD', 'README.md', 'cachy-asahi-topmem', 'test_topmem.py')
        SCOPE = 'topmem-addon'
        SIGNING = 'topmem-signing'
        REPO = 'topmem'
        SIGNER_ENV = 'TOPMEM_SIGNER_FP'
        ENTRY_TARGET = '/topmem-lifecycle.sh'
        PROBE_TARGET = '/topmem-smoke.py'
        STATUS = 'PROVISIONAL_TOPMEM_NATIVE_ADDON'
        PACKAGE_PATTERN = re.escape(NAME) + '-0\\.1\\.0-[12]-any\\.pkg\\.tar\\.(xz|gz|zst)'
        EXTRA_SOURCE = set()
        EXTRA_SOURCE_ORDER = ()
    else:
        raise ValueError('addon-profile-unselected')

    def natural(value):
        need(type(value) is dict and set(value) == {'started', 'natural_poll_code', 'runner_return_code', 'reaping', 'reaped_code', 'before_cleanup'}, 'addon-natural-process')
        need(value['started'] is True and value['reaping'] == 'COMPLETED' and all((type(value[k]) is int and value[k] == 0 for k in ('natural_poll_code', 'runner_return_code', 'reaped_code'))), 'addon-natural-process')
        before = value['before_cleanup']
        need(type(before) is dict and set(before) == {'state', 'returncode'} and (before['state'] == 'exited') and (type(before['returncode']) is int) and (before['returncode'] == 0), 'addon-natural-process')

    def need(value, code):
        if not value:
            raise ValueError(code)

    def live(end):
        need(type(end) in (int, float) and math.isfinite(end) and (time.monotonic() < end), 'addon-deadline')

    def pin(value):
        need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'addon-pin')
        return value

    def canonical(path, root):
        need(type(path) is str and ',' not in path and ('\n' not in path), 'addon-path')
        p = Path(path)
        need(p.is_absolute() and '..' not in p.parts and (p == p.resolve()) and p.is_relative_to(root) and (p != root), 'addon-owned-path')
        need(all((stat.S_ISDIR(q.lstat().st_mode) for q in p.parents)), 'addon-parent')
        return p

    def directory(path, public=False):
        s = path.lstat()
        need(type(public) is bool and stat.S_ISDIR(s.st_mode) and (s.st_uid == os.getuid()) and (stat.S_IMODE(s.st_mode) == (493 if public else 448)), 'addon-owned-directory')
        return s

    def read(path, end, limit=64 * 1024 * 1024):
        live(end)
        need(all((stat.S_ISDIR(p.lstat().st_mode) for p in path.parents)), 'addon-file-parent')
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (before.st_uid == os.getuid()) and (0 < before.st_size <= limit), 'addon-owned-file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            data = bytearray()
            while (raw := os.read(fd, min(65536, limit + 1 - len(data)))):
                live(end)
                data.extend(raw)
                need(len(data) <= limit, 'addon-file-bound')
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(len(data) == before.st_size and all((getattr(before, k) == getattr(s, k) for s in (opened, os.fstat(fd), path.lstat()) for k in fields)), 'addon-file-drift')
            return bytes(data)
        finally:
            os.close(fd)

    def save(path, value):
        data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        need(len(data) <= 1024 * 1024, 'addon-journal-bound')
        temp = path.with_name('.' + path.name)
        with temp.open('xb') as stream:
            temp.chmod(384)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def inspect(report, version, pins):
        info = report['metadata']['.PKGINFO']
        members = report['members']
        need(not report['errors'] and (not report['elf']) and (info['pkgname'] == [NAME]) and (info['pkgver'] == [version]) and (info['arch'] == ['any']) and (info['depend'] == DEPENDS) and (info['license'] == ['MIT']), 'addon-package')
        dirs = {str(p) for n in OWNED for p in Path(n).parents if str(p) != '.'}
        need({n for n, r in members.items() if not n.startswith('.') and r['type'] != '5'} == set(OWNED) and {n for n in members if n.startswith('.')} <= {'.PKGINFO', '.BUILDINFO', '.MTREE'} and all((n in dirs and r['mode'] == 493 and (r['uid'] == r['gid'] == 0) for n, r in members.items() if r['type'] == '5')), 'addon-payload-hooks')
        for n, (source, mode) in OWNED.items():
            row = members[n]
            need(row['type'] == '0' and row['mode'] == mode and (row['uid'] == row['gid'] == 0) and (row['sha256'] == pins[source]), 'addon-payload')
        if PROFILE == 'fish-history-v1':
            need(info.get('optdepend', []) == OPTDEPENDS, 'addon-optional-dependency')

    def commands(config, image, epoch):
        root = Path(config['jobroot'])
        out = root / SCOPE
        native = Path(config['snapshot'])
        rows = []
        need(type(epoch) is int and epoch == 1791748800 and (type(image) is str) and re.fullmatch('sha256:[0-9a-f]{64}', image), 'addon-image-epoch')
        for variant in ('current', 'upgrade-fixture'):
            pair = [out / (variant + '-' + str(n)) for n in (1, 2)]
            for n, target in enumerate(pair, 1):
                rows.append((variant, 'build-' + str(n), [sys.executable, str(native / 'scripts/build/build.py'), str(BASE / 'recipes' / variant), '--image', image, '--mode', 'native', '--source-date-epoch', str(epoch), '--expected-packages', str(root / 'producer/packages.lock'), '--reviewed-inputs', str(out / (variant + '-review.json')), '--timeout', '300', '--output', str(target)]))
            rows.append((variant, 'compare', [sys.executable, str(native / 'scripts/build/compare.py'), str(pair[0]), str(pair[1]), '--require-bytes']))
        return rows

    class Commands:
        """Exact addon union delegates to actual captured ProducerCommands._run.

    Original run/GuardedCommands and their counters are never extended or called.
    The existing _run loads actual build.main/compare.main via graph's buffers.
    """

        def __init__(self, producer, config, broker, runner, expected):
            need(expected == commands(config, broker.image, 1791748800), 'addon-command-registration')
            self.delegate = producer.ProducerCommands(config, broker, runner)
            self.producer = producer
            self.expected = expected
            self.finished = []
            self.started = []
            self.end = config['work_deadline']
            self.path = Path(config['jobroot']) / (SCOPE + '/commands.json')
            need(not self.path.exists(), 'addon-command-journal-fresh')
            self.persist()

        def persist(self):
            save(self.path, dict(scope=SCOPE + '-only', started=self.started, finished=self.finished, builds=sum((k != 'compare' for _, k in self.finished)), comparisons=sum((k == 'compare' for _, k in self.finished))))

        def run(self, argv, timeout):
            live(self.end)
            i = len(self.finished)
            need(type(argv) is list and all((type(v) is str for v in argv)) and (len(self.started) == i) and (i < len(self.expected)) and (argv == self.expected[i][2]), 'addon-command-union')
            need(type(timeout) in (int, float) and math.isfinite(timeout) and (0 < timeout <= min(360, self.end - time.monotonic())), 'addon-timeout')
            variant, kind, _ = self.expected[i]
            self.started.append([variant, kind])
            self.persist()
            log = io.StringIO()
            result = self.delegate._run(argv, log, self.producer.subprocess.STDOUT, timeout, False, False)
            live(self.end)
            (self.path.parent / (variant + '-' + kind + '.log')).write_text(log.getvalue())
            need(type(result.returncode) is int and result.returncode == 0, 'addon-command-failed')
            if kind == 'compare':
                comparison = json.loads(log.getvalue())
                need(comparison['status'] == 'contents-reproduced' and comparison['errors'] == [] and (len(comparison['packages']) == 1) and all((type(v) is bool and v for row in comparison['packages'].values() for v in row.values())), 'addon-comparison')
            self.finished.append([variant, kind])
            self.persist()
            return 0

    def key_contract(c, path, expected_sha, root, end):
        """External Root pin selects owner/key/tool policy; no arbitrary fingerprint grant."""
        path = canonical(str(path), root)
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and (s.st_nlink == 1) and (stat.S_IMODE(s.st_mode) == 384), 'addon-private-key-owner')
        contract = c.decode(c.pinned(path, pin(expected_sha), deadline=end))
        need(set(contract) == {'schema_version', 'owner', 'fingerprint', 'certificate', 'certificate_sha256', 'keyhome', 'gpg_sha256', 'repo_add_sha256'} and type(contract['schema_version']) is int and (contract['schema_version'] == 1) and (type(contract['owner']) is str) and re.fullmatch('[A-Za-z0-9_.-]{1,64}', contract['owner']) and (type(contract['fingerprint']) is str) and re.fullmatch('[A-F0-9]{40}', contract['fingerprint']), 'addon-key-owner')
        cert = canonical(contract['certificate'], root)
        home = canonical(contract['keyhome'], root)
        need(cert == root / (SIGNING + '/public/public-key.asc') and home == root / (SIGNING + '/keyhome'), 'addon-key-path')
        directory(home)
        raw = read(cert, end, 65536)
        need(hashlib.sha256(raw).hexdigest() == pin(contract['certificate_sha256']) and raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and (b'PRIVATE KEY' not in raw), 'addon-public-certificate')
        pin(contract['gpg_sha256'])
        pin(contract['repo_add_sha256'])
        return contract

    def tool(path, expected, c, end):
        """Fresh root-owned fixed-tool bytes, plus retained/named Source read checks."""
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and (s.st_gid == 0) and (stat.S_IMODE(s.st_mode) == 493) and (s.st_nlink == 1), 'addon-tool-metadata')
        need(c.sha(c.read(path, 64 * 1024 * 1024, deadline=end)) == pin(expected), 'addon-tool-pin')
        after = path.lstat()
        need(all((getattr(s, k) == getattr(after, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))), 'addon-tool-drift')

    class Repository:

        def __init__(self, c, load, runner, contract, out, end):
            self.c = c
            self.native = load('native_arm', Path(runner.addon_snapshot) / 'scripts/ci/native_arm.py')
            self.runner = runner
            self.contract = contract
            self.out = out
            self.end = end
            self.journal = []
            need(runner.env.get('GNUPGHOME') == contract['keyhome'], 'addon-keyhome-env')

        def run(self, argv):
            live(self.end)
            expected = self.contract['gpg_sha256'] if argv[0] == '/usr/bin/gpg' else self.contract['repo_add_sha256']
            need(argv[0] in ('/usr/bin/gpg', '/usr/bin/repo-add'), 'addon-repository-program')
            tool(Path(argv[0]), expected, self.c, self.end)
            self.journal.append(dict(argv=argv, status='started'))
            save(self.out / 'signatures.json', self.journal)
            result = self.runner.run(argv, timeout=min(120, self.end - time.monotonic()), separate_stderr=True)
            live(self.end)
            need(type(result.returncode) is int and result.returncode == 0, 'addon-signing-command')
            self.journal[-1]['status'] = 'pass'
            save(self.out / 'signatures.json', self.journal)
            return result.stdout

        def publish(self, artifacts):
            repo = self.out / 'repo'
            need(not repo.exists() and (not repo.is_symlink()), 'addon-repository-fresh')
            repo.mkdir(mode=493)
            repo.chmod(493)
            k = self.contract
            fp = k['fingerprint']
            gpg = ['/usr/bin/gpg', '--no-autostart', '--batch', '--no-options', '--homedir', k['keyhome'], '--no-auto-key-retrieve']
            info = self.run(gpg + ['--with-colons', '--show-keys', k['certificate']]).decode().splitlines()
            primary = []
            awaiting = False
            for line in info:
                fields = line.split(':')
                if fields[0] == 'pub':
                    need(fields[1] not in ('r', 'e'), 'addon-key-revoked')
                    awaiting = True
                elif fields[0] == 'fpr' and awaiting:
                    primary.append(fields[9])
                    awaiting = False
            need(primary == [fp], 'addon-key-fingerprint')
            exported = self.run(gpg + ['--armor', '--export', fp])
            need(hashlib.sha256(exported).hexdigest() == k['certificate_sha256'], 'addon-export-certificate')
            (repo / 'public-key.asc').write_bytes(exported)
            (repo / 'public-key.asc').chmod(420)
            for variant, label in (('current', 'v1'), ('upgrade-fixture', 'v2')):
                directory = repo / label
                directory.mkdir(mode=493)
                directory.chmod(493)
                row = artifacts[variant]
                need(type(row) is dict and set(row) == {'path', 'sha256'}, 'addon-repo-artifact')
                source = Path(row['path'])
                target = directory / source.name
                need(source.parent == self.out / (variant + '-1') / 'artifacts', 'addon-repo-artifact-path')
                raw = read(source, self.end)
                need(hashlib.sha256(raw).hexdigest() == pin(row['sha256']), 'addon-repo-artifact-drift')
                target.write_bytes(raw)
                target.chmod(420)

                def sign(p):
                    self.run(gpg + ['--local-user', fp, '--digest-algo', 'SHA256', '--output', str(p) + '.sig', '--detach-sign', str(p)])
                sign(target)
                self.run(['/usr/bin/repo-add', '--include-sigs', '--sign', '--key', fp, str(directory / (REPO + '.db.tar.gz')), str(target)])
                for name in (REPO + '.db.tar.gz', REPO + '.files.tar.gz'):
                    p = directory / name
                    if not Path(str(p) + '.sig').exists():
                        sign(p)
                for p in (target, directory / (REPO + '.db.tar.gz'), directory / (REPO + '.files.tar.gz')):
                    status = self.run(gpg + ['--status-fd', '1', '--verify', str(p) + '.sig', str(p)]).decode()
                    self.native.valid_signature(status, fp)
                    p.chmod(420)
                    Path(str(p) + '.sig').chmod(420)
                for name in (REPO + '.db', REPO + '.files'):
                    for suffix in ('', '.sig'):
                        alias = directory / (name + suffix)
                        target = directory / (name + '.tar.gz' + suffix)
                        if alias.is_symlink():
                            need(os.readlink(alias) == target.name, 'addon-repo-alias')
                            alias.unlink()
                        need(not alias.exists(), 'addon-repo-alias')
                        alias.write_bytes(read(target, self.end))
                        alias.chmod(420)
            return repo

    @contextmanager
    def repository_custody(repo, root, package_names, certificate_sha, end):
        """Hold exact job-local directories/files through lifecycle; no caller mount path."""
        p = canonical(str(repo), root)
        need(p == root / (SCOPE + '/repo'), 'addon-repository-job-path')
        dirs = [root, root / SCOPE, p, p / 'v1', p / 'v2']
        held = []
        expected = {'public-key.asc'}
        for label, name in zip(('v1', 'v2'), package_names):
            need(type(name) is str and re.fullmatch(PACKAGE_PATTERN, name), 'addon-package-basename')
            expected |= {label + '/' + n for n in (name, name + '.sig', REPO + '.db.tar.gz', REPO + '.db.tar.gz.sig', REPO + '.files.tar.gz', REPO + '.files.tar.gz.sig', REPO + '.db', REPO + '.db.sig', REPO + '.files', REPO + '.files.sig')}

        def state(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        try:
            for d in dirs:
                s = directory(d, public=d in (p, p / 'v1', p / 'v2'))
                fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                held.append((d, fd, state(s)))
            actual = {str(f.relative_to(p)) for f in p.rglob('*') if not f.is_dir()}
            need(actual == expected and {str(f.relative_to(p)) for f in p.rglob('*') if f.is_dir()} == {'v1', 'v2'}, 'addon-repository-members')
            for name in sorted(expected):
                f = p / name
                before = state(f.lstat())
                raw = read(f, end)
                need(stat.S_IMODE(f.lstat().st_mode) == 420, 'addon-repository-mode')
                if name == 'public-key.asc':
                    need(hashlib.sha256(raw).hexdigest() == pin(certificate_sha), 'addon-repository-certificate')
                fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                held.append((f, fd, before))
                need(state(os.fstat(fd)) == before == state(f.lstat()), 'addon-repository-open-drift')

            def check():
                live(end)
                need(all((state(os.fstat(fd)) == before == state(f.lstat()) for f, fd, before in held)), 'addon-repository-drift')
            check()
            yield check
            check()
        finally:
            for _, fd, _ in held:
                os.close(fd)

    def lifecycle_argv(config, image, fingerprint):
        root = Path(config['jobroot'])
        repo = canonical(str(root / (SCOPE + '/repo')), root)
        directory(root)
        directory(root / SCOPE)
        directory(repo, public=True)
        need(type(fingerprint) is str and re.fullmatch('[A-F0-9]{40}', fingerprint) and (type(config['nonce']) is str) and re.fullmatch('[0-9a-f]{32}', config['nonce']), 'addon-lifecycle-selection')
        argv = [config['docker_binary'], '--host', config['endpoint'], 'run', '--rm', '--name', NAME + '-' + config['nonce'], '--label', 'org.cachy-asahi.' + SCOPE + '.nonce=' + config['nonce'], '--pull=never', '--platform=linux/arm64', '--network=none', '--user=0:0', '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=CHOWN', '--security-opt=no-new-privileges', '--ipc=private', '--pids-limit=256', '--memory=1g', '--memory-swap=1g', '--cpus=2', '--env', 'CACHY_ASAHI_CONTAINER=1', '--env', SIGNER_ENV + '=' + fingerprint, '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=256m', '--mount', 'type=bind,src=' + str(repo) + ',dst=/repo,readonly', '--mount', 'type=bind,src=' + str(BASE / 'lifecycle-entry.sh') + (',dst=' + ENTRY_TARGET + ',readonly'), '--mount', 'type=bind,src=' + str(BASE / 'smoke.py') + (',dst=' + PROBE_TARGET + ',readonly'), '--entrypoint=/bin/bash', image, ENTRY_TARGET]
        if PROFILE == 'fish-history-v1':
            argv[-2:-2] = ['--mount', 'type=bind,src=' + str(BASE / 'original-config.fish') + ',dst=/fish-original-config.fish,readonly']
            argv.extend(['--deadline', str(config['work_deadline']), '--nonce', config['nonce']])
        return argv

    def execute(worker, receipt, config, addon_manifest_sha, key_owner_path, key_owner_sha):
        """Concrete entry: actual worker graph/owner/Runner and captured build APIs.

    Root MUST authenticate worker/addon entry and select external manifest/key pins;
    inert source tests cannot supply this live authority.
    """
        end = config['work_deadline']
        live(end)
        need(worker.validate_receipt(receipt, config) is receipt, 'addon-baseline')
        need(config.get('addon_profile') == PROFILE, 'addon-profile-binding')
        need(repository_slot[1] is True, 'addon-v2-publisher-required')
        repository_admit = getattr(worker, 'addon_repository_admit', None)
        need(callable(repository_admit), 'addon-v2-admission-required')
        lifecycle = None
        if PROFILE == 'fish-history-v1':
            lifecycle = getattr(worker, 'addon_lifecycle', None)
            need(callable(lifecycle), 'addon-caller-lifecycle-api-required')
        root = Path(config['jobroot'])
        directory(root)
        need(root.is_absolute() and root == root.resolve() and (receipt['cleanup'] == 'PARENT RECOVERY REQUIRED'), 'addon-live-job')
        out = root / SCOPE
        need(not out.exists() and (not out.is_symlink()), 'addon-fresh')
        out.mkdir(mode=448)
        with worker.graph(config) as (c, producer, load):
            manifest = c.decode(c.pinned(BASE / 'source-manifest.json', pin(addon_manifest_sha), deadline=end))
            need(set(manifest) == {'schema_version', 'files', 'recipes_sha256', 'parent_packet_sha256'} and type(manifest['schema_version']) is int and (manifest['schema_version'] == 1) and (manifest['parent_packet_sha256'] == config['packet_sha256']), 'addon-source-manifest')
            need(c.sha(c.pinned(Path(config['source']) / 'packet.json', manifest['parent_packet_sha256'], deadline=end)) == manifest['parent_packet_sha256'], 'addon-parent-selection')
            files = {'addon.py', 'engine.py', 'lifecycle-entry.sh', 'smoke.py', 'recipes.lock.json'} | EXTRA_SOURCE | {'recipes/' + v + '/' + n for v in ('current', 'upgrade-fixture') for n in RECIPE_FILES}
            need(type(manifest['files']) is dict and set(manifest['files']) == files and (manifest['recipes_sha256'] == LOCK), 'addon-source-union')
            for name, row in manifest['files'].items():
                need(type(row) is dict and set(row) == {'bytes', 'mode', 'sha256'} and (type(row['bytes']) is type(row['mode']) is int), 'addon-source-row')
                p = BASE / name
                raw = c.pinned(p, pin(row['sha256']), deadline=end)
                s = p.lstat()
                need(len(raw) == row['bytes'] and stat.S_IMODE(s.st_mode) == row['mode'], 'addon-source-fields')
            pins = c.decode(c.pinned(BASE / 'recipes.lock.json', LOCK, deadline=end))
            need(set(pins) == {'current', 'upgrade-fixture'} and all((len(v) == len(RECIPE_FILES) for v in pins.values())), 'addon-recipe-union')
            for variant, rows in pins.items():
                need({p.name for p in (BASE / 'recipes' / variant).iterdir()} == set(rows), 'addon-recipe-members')
                for name, digest in rows.items():
                    need(manifest['files']['recipes/' + variant + '/' + name]['sha256'] == digest, 'addon-recipe-pin')
                (out / (variant + '-review.json')).write_text(json.dumps(rows, sort_keys=True) + '\n')
            key = key_contract(c, key_owner_path, key_owner_sha, root, end)
            broker = worker.owner(config, producer, end)
            broker.journal_path = out / 'build-containers.json'
            need(broker.initialize(receipt['daemon']) == receipt['daemon'] and broker.image == receipt['image_id'], 'addon-owned-image')
            inputs = c.decode(c.read(root / 'producer/inputs.lock.json', 2 * 1024 * 1024, deadline=end))
            expected = commands(config, broker.image, inputs['source_date_epoch'])
            env = {**worker.environment(config), 'GNUPGHOME': key['keyhome']}
            runner = producer.jr.Runner(min(7200, end - time.monotonic()), env, out / 'tool-logs')
            runner.deadline = min(runner.deadline, end)
            runner.addon_snapshot = config['snapshot']
            dispatch = Commands(producer, config, broker, runner, expected)
            checks = load('package_checks', Path(config['snapshot']) / 'scripts/checks/package_checks.py')
            artifacts = {}
            with broker.runtime.cancellation_handlers():
                for variant, kind, argv in expected:
                    dispatch.run(argv, min(360 if kind != 'compare' else 120, end - time.monotonic()))
                    if kind != 'compare':
                        target = Path(argv[-1])
                        paths = list((target / 'artifacts').glob('*.pkg.tar.*'))
                        paths = [p for p in paths if not p.name.endswith('.sig')]
                        need(len(paths) == 1, 'addon-artifact-set')
                        report = checks.package(paths[0])
                        inspect(report, '0.1.0-' + ('1' if variant == 'current' else '2'), pins[variant])
                        provenance = c.decode(c.read(target / 'provenance.json', 1024 * 1024, deadline=end))
                        need(report['sha256'] == provenance['artifacts'][paths[0].name], 'addon-artifact-provenance')
                        if kind == 'build-1':
                            artifacts[variant] = dict(path=str(paths[0]), sha256=report['sha256'])
                repo = repository_factory()(c, load, runner, key, out, end).publish(artifacts)
                for name in ('lifecycle-entry.sh', 'smoke.py') + EXTRA_SOURCE_ORDER:
                    c.pinned(BASE / name, manifest['files'][name]['sha256'], deadline=end)
                with repository_custody(repo, root, [Path(artifacts[v]['path']).name for v in ('current', 'upgrade-fixture')], key['certificate_sha256'], end) as check:
                    produced = repository_admit(c, config, key, end)
                    need(type(produced) is int and produced == 2, 'addon-v2-database-admission')
                    argv = lifecycle_argv(config, broker.image, key['fingerprint'])
                    check()
                    broker._info(broker.runner)
                    row = dict(scope=SCOPE + '-lifecycle', image=broker.image, daemon=receipt['daemon'], nonce=config['nonce'], name=argv[argv.index('--name') + 1], argv=argv, attempted=True, result='UNKNOWN', cleanup='PARENT RECOVERY REQUIRED')
                    save(out / 'lifecycle-container.json', row)
                    if PROFILE == 'fish-history-v1':
                        result, observation = lifecycle(config, argv, out, end)
                        row['natural'] = observation
                        save(out / 'lifecycle-container.json', row)
                        need(type(result.args) in (list, tuple) and list(result.args) == argv, 'addon-lifecycle-argv')
                        natural(observation)
                        need(type(result.stdout) is bytes and len(result.stdout) <= 1024 * 1024, 'addon-lifecycle-output')
                        evidence = c.decode(result.stdout)
                        save(out / 'lifecycle-evidence.json', evidence)
                        validate_lifecycle(evidence)
                        need(evidence['nonce'] == config['nonce'] and evidence['deadline'] == end and (evidence['fingerprint'] == key['fingerprint']), 'addon-lifecycle-body-binding')
                        row['evidence_sha256'] = c.sha(c.read(out / 'lifecycle-evidence.json', 1024 * 1024, deadline=end))
                    else:
                        result = runner.run(argv, timeout=min(600, end - time.monotonic()), separate_stderr=True)
                    live(end)
                    check()
                    broker._info(broker.runner)
                    for name in ('lifecycle-entry.sh', 'smoke.py') + EXTRA_SOURCE_ORDER:
                        c.pinned(BASE / name, manifest['files'][name]['sha256'], deadline=end)
                    need(type(result.returncode) is int and result.returncode == 0, 'addon-lifecycle-failed')
                    produced = repository_admit(c, config, key, end)
                    need(type(produced) is int and produced == 2, 'addon-v2-database-admission')
                    row['result'] = 'provisional-zero'
                    save(out / 'lifecycle-container.json', row)
            live(end)
            return dict(status=STATUS, builds=4, comparisons=2, parent_cleanup_required=True, parent_worker_receipt_unchanged=True, hardware='NOT RUN', release_selected=False)

    def validate_lifecycle(value):
        """Closed admission schema. Pure; safe for the selected engine to embed."""

        def require(test):
            if not test:
                raise ValueError('fish-lifecycle-evidence')

        def pin(text):
            require(type(text) is str and len(text) == 64 and all((c in '0123456789abcdef' for c in text)))
        require(type(value) is dict and set(value) == {'schema_version', 'scope', 'status', 'nonce', 'deadline', 'fingerprint', 'phases', 'inventory_before_sha256', 'inventory_after_sha256', 'inventory_restored', 'ownership', 'first_failure', 'cancelled', 'cleanup', 'hardware', 'progress'})
        require(type(value['schema_version']) is int and value['schema_version'] == 1 and (value['scope'] == 'fish-history-lifecycle') and (value['status'] == 'PASS'))
        require(type(value['nonce']) is str and len(value['nonce']) == 32 and all((c in '0123456789abcdef' for c in value['nonce'])))
        require(type(value['deadline']) in (int, float) and value['deadline'] > 0 and (value['deadline'] < float('inf')))
        require(type(value['fingerprint']) is str and len(value['fingerprint']) == 40 and all((c in '0123456789ABCDEF' for c in value['fingerprint'])))
        require(value['first_failure'] is None and value['cancelled'] is False and (value['cleanup'] is True) and (value['inventory_restored'] is True) and (value['hardware'] == 'NOT_RUN'))
        pin(value['inventory_before_sha256'])
        pin(value['inventory_after_sha256'])
        require(value['inventory_before_sha256'] == value['inventory_after_sha256'])
        phases = ('prepare', 'installed-v1', 'upgraded-v2', 'removed', 'reinstalled-v2', 'removed-final', 'baseline')
        require(type(value['phases']) is list and len(value['phases']) == 7)
        baseline = None
        for phase, row in zip(phases, value['phases']):
            require(type(row) is dict and set(row) == {'schema_version', 'phase', 'status', 'first_failure', 'protected_before', 'protected_after', 'cases', 'payload', 'HOME_overridden', 'expanded_commands_executed', 'cancelled'})
            require(type(row['schema_version']) is int and row['schema_version'] == 1 and (row['phase'] == phase) and (row['status'] == 'PASS') and (row['first_failure'] is None) and (row['HOME_overridden'] is False) and (row['expanded_commands_executed'] is False) and (row['cancelled'] is False))
            names = {'config/fish/config.fish', 'config/fish/functions/__history_previous_command.fish', 'config/fish/functions/fish_user_key_bindings.fish', 'data/fish/protected_history', 'user-opt-in.fish'}
            for field in ('protected_before', 'protected_after'):
                records = row[field]
                require(type(records) is dict and set(records) == names)
                for record in records.values():
                    require(type(record) is dict and set(record) == {'sha256', 'bytes', 'mode', 'mtime_ns', 'nlink', 'uid', 'gid'})
                    pin(record['sha256'])
                    require(type(record['bytes']) is int and 0 < record['bytes'] <= 262144 and (type(record['mode']) is int) and (record['mode'] == 384) and (type(record['mtime_ns']) is int) and (record['mtime_ns'] >= 0) and (type(record['nlink']) is int) and (record['nlink'] == 1) and (type(record['uid']) is int) and (record['uid'] == 1000) and (type(record['gid']) is int) and (record['gid'] == 1000))
                if baseline is None:
                    baseline = records
                require(records == baseline)
            cli = {'guarded-user-line', 'original-helpers', 'user-module', 'user-key-module', 'guarded-repeat', 'noninteractive', 'generic-user-binding', 'existing-function', 'existing-bang', 'existing-dollar', 'prefix-bang', 'prefix-dollar'}
            installed = phase in ('installed-v1', 'upgraded-v2', 'reinstalled-v2')
            expected = cli | ({'bang', 'argument', 'argument-prefix', 'literal-dollar', 'quoted-literal', 'protected-history', 'empty-bang', 'empty-argument', 'vi-insert', 'hybrid-insert', 'cancel-line'} if installed else {'removed-bang', 'removed-argument'}) if phase not in ('prepare', 'baseline') else set()
            require(type(row['cases']) is list and len(row['cases']) == len(expected))
            require(all((type(r) is dict and type(r.get('name')) is str for r in row['cases'])))
            require({r['name'] for r in row['cases']} == expected)
            for record in row['cases']:
                require(type(record) is dict and set(record) == {'name', 'kind', 'status', 'output_sha256', 'natural_return_zero', 'cleanup', 'expanded_enter'})
                require(record['kind'] == ('cli' if record['name'] in cli else 'pty') and record['status'] == 'PASS' and (record['natural_return_zero'] is True) and (record['cleanup'] is True) and (record['expanded_enter'] is False))
                pin(record['output_sha256'])
            owned = {'usr/share/cachy-asahi/fish-bang-bang/' + n for n in ('__history_previous_command.fish', '__history_previous_command_arguments.fish', 'opt-in.fish', 'README.md')} | {'usr/share/licenses/cachy-asahi-fish-bang-bang/' + n for n in ('NOTICE', 'LICENSE.upstream', 'LICENSE.project')}
            if phase in ('prepare', 'baseline'):
                require(row['payload'] is None)
            else:
                require(type(row['payload']) is dict and set(row['payload']) == owned and all((type(v) is str for v in row['payload'].values())) and (set(row['payload'].values()) == {'PINNED' if installed else 'ABSENT'}))
        require(type(value['ownership']) is list and len(value['ownership']) == 5)
        for phase, version, row in zip(phases[1:6], ('0.1.0-1', '0.1.0-2', None, '0.1.0-2', None), value['ownership']):
            require(type(row) is dict and set(row) == {'phase', 'version', 'paths', 'owners', 'integrity_zero'})
            require(row['phase'] == phase and row['version'] == version and (type(row['paths']) is list) and (row['paths'] == sorted(owned)) and (type(row['owners']) is dict) and (set(row['owners']) == owned) and all((type(v) is str for v in row['owners'].values())) and (set(row['owners'].values()) == {'cachy-asahi-fish-bang-bang' if version else 'ABSENT'}) and (row['integrity_zero'] is True))
        expected = ['inventory-before', 'probe-prepare', 'certificate', 'import-test-certificate', 'local-sign-test-certificate']
        for phase in phases[1:6]:
            if phase in ('installed-v1', 'upgraded-v2', 'reinstalled-v2'):
                expected += [phase + '.install', phase + '.version', phase + '.integrity', phase + '.paths'] + [phase + '.owner'] * 7
            else:
                expected += [phase + '.remove']
            expected += ['probe-' + phase]
        expected += ['probe-baseline', 'inventory-after']
        require(type(value['progress']) is list and len(value['progress']) == len(expected))
        for operation, row in zip(expected, value['progress']):
            require(type(row) is dict and set(row) == {'operation', 'status', 'output_sha256', 'natural_return_zero'})
            require(row['operation'] == operation and row['status'] == 'PASS' and (row['natural_return_zero'] is True))
            pin(row['output_sha256'])
        return value

    def signing_journal(rows, root, key):
        need(type(rows) is list and len(rows) == 14 and all((type(r) is dict and set(r) == {'argv', 'status'} and (r['status'] == 'pass') and (type(r['argv']) is list) and (1 <= len(r['argv']) <= 64) and all((type(a) is str and len(a) <= 4096 for a in r['argv'])) for r in rows)), 'addon-v2-signature-journal')
        prefix = ['/usr/bin/gpg', '--no-autostart', '--batch', '--no-options', '--homedir', key['keyhome'], '--no-auto-key-retrieve']
        fp = key['fingerprint']
        index = 0
        names = []

        def expect(argv):
            nonlocal index
            need(index < len(rows) and rows[index]['argv'] == argv, 'addon-v2-signature-argv')
            index += 1

        def sign(path):
            return prefix + ['--local-user', fp, '--digest-algo', 'SHA256', '--output', str(path) + '.sig', '--detach-sign', str(path)]
        expect(prefix + ['--with-colons', '--show-keys', key['certificate']])
        expect(prefix + ['--armor', '--export', fp])
        for label, version in (('v1', '1'), ('v2', '2')):
            target = Path(rows[index]['argv'][-1])
            directory = Path(root) / SCOPE / 'repo' / label
            need(target.parent == directory and re.fullmatch(re.escape(NAME) + '-0\\.1\\.0-' + version + '-any\\.pkg\\.tar\\.(xz|gz|zst)', target.name), 'addon-v2-signature-target')
            names.append(target.name)
            paths = [target, directory / (REPO + '.db.tar.gz'), directory / (REPO + '.files.tar.gz')]
            for path in paths:
                expect(sign(path))
            for path in paths:
                expect(prefix + ['--status-fd', '1', '--verify', str(path) + '.sig', str(path)])
        need(index == len(rows), 'addon-v2-signature-argv')
        return names
    repository_slot = [Repository, False]

    def repository_factory():
        return repository_slot[0]

    @contextmanager
    def repository_runtime(replacement):
        need(type(replacement) is type and issubclass(replacement, Repository) and (replacement is not Repository) and (repository_slot[1] is False), 'addon-v2-publisher-selection')
        previous = tuple(repository_slot)
        repository_slot[:] = [replacement, True]
        try:
            yield
        finally:
            repository_slot[:] = previous
    return {'execute': execute, 'commands': commands, 'inspect': inspect, 'lifecycle_argv': lifecycle_argv, 'scope': SCOPE, 'recipe_files': RECIPE_FILES, 'key_contract': key_contract, 'repository_custody': repository_custody, 'Commands': Commands, 'natural': natural, 'validate_lifecycle': validate_lifecycle, 'signing_journal': signing_journal, 'need': need, 'live': live, 'pin': pin, 'read': read, 'save': save, 'directory': directory, 'tool': tool, 'repository_factory': repository_factory, 'repository_runtime': repository_runtime}
