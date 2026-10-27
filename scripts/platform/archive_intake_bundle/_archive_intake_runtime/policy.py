#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only finite policy increment. CLI never opens selected archives."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

BASE = Path(__file__).absolute().parent
PINS_SHA = 'b740615be3de67a04df08eaf1c2ce47d898def8246cd588b8c1b4bda25cfcbf2'
GIB = 1024**3
LIMITS = dict(packages=261, jobs=1, compressed_archive_bytes=300_000_000,
              compressed_work_bytes=3*GIB, decoded_archive_bytes=GIB,
              decoded_total_bytes=8*GIB, file_bytes=512*1024**2,
              members_per_archive=100000, members_total=500000,
              spool_bytes=8*GIB, spool_io_bytes=32*GIB,
              semantic_metadata_bytes=32*1024**2, report_bytes=256*1024**2,
              journal_bytes=32*1024**2, cpu_seconds=1200, wall_seconds=1200,
              external_wall_seconds=1210, cleanup_seconds=10,
              external_address_space_bytes=2*GIB,
              per_archive_wall_seconds=300, decoder_memory_bytes=64*1024**2,
              read_write_quantum_bytes=65536, cancellation_check_quantum_bytes=65536)
OUTPUT_CAP = LIMITS['spool_bytes'] + LIMITS['members_total']*4096
STORAGE_RESERVE = LIMITS['spool_bytes'] + OUTPUT_CAP + LIMITS['report_bytes'] + GIB


def need(value, code):
    if not value:
        raise ValueError(code)


def state(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'policy-duplicate-json-key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'policy-nonfinite-json'))


@contextmanager
def snapshot():
    """Hold only fixed, pinned ordinary source leaves; close every acquired FD."""
    held, raws = [], {}
    failure = None
    try:
        need(BASE == BASE.resolve(), 'policy-source-directory')
        manifest = BASE/'runtime-pins.json'
        before = manifest.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_uid == os.getuid() and before.st_size <= 16384,
             'policy-manifest-file')
        fd = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        held.append((manifest, fd, state(before)))
        need(state(os.fstat(fd)) == state(before), 'policy-manifest-identity')
        raw = os.read(fd, 16385)
        need(hashlib.sha256(raw).hexdigest() == PINS_SHA, 'policy-runtime-pin')
        rows = decode(raw)['files']
        need(len(rows) == 44 and sum(r['size'] for r in rows) <= 2*1024**2,
             'policy-source-union')
        names = {r['path'] for r in rows}
        need(len(names) == len(rows) and all(not Path(n).is_absolute()
             and all(p not in ('', '.', '..') for p in n.split('/')) for n in names),
             'policy-source-names')
        directories = {''}
        for name in names:
            p = Path(name).parent
            while str(p) != '.':
                directories.add(str(p)); p = p.parent
        fds = {}
        for name in sorted(directories, key=lambda n: (n.count('/'), n)):
            p = BASE/'runtime'/name
            before = p.lstat()
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
                 and stat.S_IMODE(before.st_mode) == 0o700, 'policy-directory-owner-mode')
            fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held.append((p, fd, state(before)))
            need(state(os.fstat(fd)) == state(before), 'policy-directory-identity')
            fds[name] = fd
        for row in rows:
            p = BASE/'runtime'/row['path']
            parent = str(Path(row['path']).parent)
            parent = '' if parent == '.' else parent
            leaf = p.name
            before = os.stat(leaf, dir_fd=fds[parent], follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.getuid() and before.st_size == row['size']
                 and stat.S_IMODE(before.st_mode) == row['mode'], 'policy-source-file')
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=fds[parent])
            held.append((p, fd, state(before)))
            need(state(os.fstat(fd)) == state(before), 'policy-source-identity')
            data = bytearray()
            while len(data) <= row['size']:
                part = os.read(fd, min(65536, row['size'] + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            raw = bytes(data)
            need(len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                 'policy-source-pin')
            raws[row['path']] = raw
        def check():
            need(all(state(os.fstat(fd)) == before == state(p.lstat())
                     for p, fd, before in held), 'policy-source-drift')
        check()
        yield raws, check
        check()
    except BaseException as error:
        failure = error
    finally:
        for _, fd, _ in reversed(held):
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None:
                    failure = error
                elif isinstance(failure, Exception) and not isinstance(error, Exception):
                    error.__cause__ = failure; failure = error
                else:
                    failure.add_note('policy owned close: '+type(error).__name__)
        if failure is not None:
            raise failure


def loaded(name, raw):
    module = types.ModuleType('_full261_'+name.replace('/', '_'))
    module.__file__ = str(BASE/'runtime'/name)
    module.__source_bytes__ = raw
    module.__source_sha256__ = hashlib.sha256(raw).hexdigest()
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def sources(raws):
    """Fresh private module namespace; historical core bytes are never edited."""
    core = loaded('intake/source/core.py', raws['intake/source/core.py'])
    need(core.__source_sha256__ == '3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7'
         and core.COMPRESSED == 2*GIB, 'policy-historical-core')
    core.COMPRESSED = LIMITS['compressed_work_bytes']
    base = core.Budget
    class Budget(base):
        def __init__(self, deadline, cancel=lambda: False):
            self.cancel, self.cpu_start = cancel, time.process_time()
            self.journal_bytes = self.jobs = 0
            super().__init__(deadline)
        @contextmanager
        def job(self):
            self.check()
            need(self.jobs < LIMITS['jobs'], 'policy-job-limit')
            self.jobs += 1
            try:
                yield
                self.check()
            finally:
                self.jobs -= 1
        def check(self):
            if self.cancel():
                raise KeyboardInterrupt('policy-cancelled')
            need(time.process_time() - self.cpu_start < LIMITS['cpu_seconds'], 'policy-cpu-limit')
            super().check()
        def journal(self, count):
            self.check()
            need(type(count) is int and 0 <= count <= 65536, 'policy-journal-quantum')
            self.journal_bytes += count
            need(self.journal_bytes <= LIMITS['journal_bytes'], 'policy-journal-limit')
    core.Budget = Budget
    return {name: loaded('intake/'+name+'.py', raws['intake/'+name+'.py'])
            for name in ('intake', 'spool', 'bridge')} | {
                'core': core, 'assembler': loaded('intake/source/assembler.py', raws['intake/source/assembler.py']),
                'consumer': loaded('consumer/consumer.py', raws['consumer/consumer.py'])}


def sizing(index):
    rows = index['packages']
    need(len(rows) == LIMITS['packages'], 'policy-package-count')
    sizes = [r['archive']['size'] for r in rows]
    need(all(type(n) is int and 0 < n <= LIMITS['compressed_archive_bytes'] for n in sizes),
         'policy-archive-size')
    work = 3*sum(sizes)
    need(work <= LIMITS['compressed_work_bytes'], 'policy-compressed-work')
    return dict(archive_bytes=sum(sizes), compressed_reserved_work_bytes=work,
                compressed_headroom_bytes=LIMITS['compressed_work_bytes']-work,
                spool_and_output_same_filesystem_required=True,
                output_cap_bytes=OUTPUT_CAP, storage_reserve_bytes=STORAGE_RESERVE,
                decoded_spool_member_time_sufficiency_proven=False,
                joules=None, energy_measured=False)


def projection_check(old, new):
    two = {'networkmanager', 'perl'}
    prior = [r for r in old['packages'] if r['identity']['name'] not in two]
    current = [r for r in new['packages'] if r['identity']['name'] not in two]
    need(len(prior) == len(current) == 259 and prior == current,
         'policy-other259-reference-drift')
    return len(current)


def space_check(core, parent, budget):
    """Read-only preflight, shared filesystem reservation ceiling; no directory creation."""
    with core.opened(Path(parent), budget, directory=True) as (fd, _):
        fs = os.fstatvfs(fd)
        need(fs.f_frsize > 0 and fs.f_bavail >= 0, 'policy-space-values')
        available = fs.f_frsize * fs.f_bavail
        need(available >= STORAGE_RESERVE, 'policy-insufficient-space')
        budget.check()
        return dict(available_bytes=available, required_bytes=STORAGE_RESERVE,
                    concurrent_disk_consumption_not_reserved=True)


def prepare():
    with snapshot() as (raws, check):
        modules = sources(raws)
        consumer = modules['consumer']
        with consumer.snapshot() as (proof, proof_check):
            plan = consumer.decode(proof['inputs/assembly-plan.json'])
            index = consumer.decode(proof['inputs/package-reference-index.json'])
            joined = consumer.associations(proof, plan, index)
            preserved = projection_check(decode(raws['intake/source/inputs/package-reference-index.json']), index)
            metrics = sizing(index)
            proof_check(); check()
        readiness = consumer.readiness()
        check()
        return dict(status='POLICY_SOURCE_PREPARED_ACTUAL_ADMISSION_NOTRUN',
                    source_policy='HISTORICAL_CORE_PLUS_EXPLICIT_3GIB_WORK_PROFILE',
                    limits=LIMITS, sizing=metrics, retained_two=joined, readiness=readiness,
                    unchanged_other_archive_references=preserved,
                    Root_Source_selection_and_process_supervision_required=True,
                    hard_process_limits_or_cancellation_latency_tested=False,
                    cooperative_CPU_wall_and_chunk_checks_only=True,
                    actual_archive_intake=False, assembly_authorized=False,
                    all261_crypto_and_26_signer_owner_joins_accepted=False,
                    source_build_license_hook_install_hardware_accepted=False)


if __name__ == '__main__':
    need(len(sys.argv) == 1, 'policy-cli-no-actor-arguments')
    print(json.dumps(prepare(), sort_keys=True, indent=2))
