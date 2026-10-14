# SPDX-License-Identifier: MIT
"""Seed four pinned inputs under the existing FDK job endpoint only."""
import hashlib
import math
import os
from pathlib import Path
import stat
import time
import types

import packet
import job_runtime as runtime

INTAKE = 'scripts/port/fdk-native-job/cache_intake.py'
INTAKE_SHA = '07ada8534f4fd21def79ab98c62334e4e0e6a7f5b15a9da8c7eacf44376c334d'
BUFFERS = {
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    'scripts/port/fdk-native-job/donor/current-controller.py': 'bbe279edb9743f98e8feed8365859abc221b2665924658e600775c902e18299e',
    'scripts/port/fdk-native-job/donor/current-packet.json': '9d5a7dc25fd44e127c457c72addb28272b1eb1f5391c4c5b8d5b0a226a3be048',
    'scripts/ci/inputs.lock.json': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',
}
SEEDS = (
    ('jbigkit-2.1-8-aarch64.pkg.tar.xz', 48816,
     'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db'),
    ('jbigkit-2.1-8-aarch64.pkg.tar.xz.sig', 566,
     'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f'),
    ('libtiff-4.7.2-1-aarch64.pkg.tar.xz', 354480,
     '02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd'),
    ('libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig', 566,
     '8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa'),
)
PRIVATE_PREFIX = 'CACHY_OLD_FOUR_'
PATH_TYPE = type(Path('/'))


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def seed(snapshot, private, runner, start, files_map):
    """Retain a Source-owned intake before construction; never claim disposal.

    No acquisition, signature check or native command occurs here. The original
    producer still consumes alarm-cache and authenticates the entire501 set.
    """
    first = intake = None
    deadline = last = None
    errors = []
    cancelled = False
    observation = {'status': 'FAIL', 'objects': 0, 'bytes': 0,
                   'signature_authentication': 'NOT RUN', 'native_build': 'NOT RUN',
                   'resource_uncertain': True, 'cancelled': False,
                   'secondary_errors': 0}

    def check():
        nonlocal last
        need(type(runner) is runtime.Runner and runner.deadline is deadline
             and type(deadline) in (int, float) and math.isfinite(deadline)
             and type(start) in (int, float) and math.isfinite(start)
             and start <= deadline <= start + 9000, 'fdk-cache-original-setup-end')
        now = time.monotonic()
        need(type(now) in (int, float) and math.isfinite(now)
             and (last is None or now >= last) and now < deadline
             and now < start + 9000, 'fdk-cache-deadline')
        last = now

    def remember(error):
        nonlocal first, cancelled
        if first is None: first = error
        errors.append(error)
        cancelled = cancelled or isinstance(error, (runtime.Cancelled, KeyboardInterrupt))
        observation.update(cancelled=cancelled, secondary_errors=len(errors) - 1)

    def source_check():
        check()
        need(type(files_map) is dict and packet.preview(snapshot)['files'] == files_map,
             'fdk-cache-source-closure')
        check()

    def capture(name, pin):
        check()
        raw, mode = packet.capture(snapshot / name, 2 * 1024**2)
        check()
        need(type(raw) is bytes and type(mode) is int and mode == 0o644
             and hashlib.sha256(raw).hexdigest() == pin, 'fdk-cache-source-pin')
        check()
        return raw

    try:
        need(type(runner) is runtime.Runner, 'fdk-cache-runner')
        need(getattr(runner, 'current_cache_intake', None) is None
             and getattr(runner, 'current_cache_observation', None) is None, 'fdk-cache-replay')
        deadline = runner.deadline
        runner.current_cache_observation = observation
        runner.current_cache_errors = errors
        check()
        need(type(snapshot) is type(private) is PATH_TYPE and snapshot.is_absolute()
             and private.is_absolute() and '..' not in snapshot.parts and '..' not in private.parts
             and snapshot == private / 'source', 'fdk-cache-fixed-private-root')
        source_check()
        raw = capture(INTAKE, INTAKE_SHA)
        buffers = tuple(capture(name, pin) for name, pin in BUFFERS.items())
        check()
        module = types.ModuleType('fdk_current_cache_intake')
        module.__file__ = str(snapshot / INTAKE)
        code = compile(raw, INTAKE, 'exec')
        check()
        exec(code, module.__dict__)
        check()
        cls = module.CacheIntake
        need(type(cls) is type and cls.__module__ == module.__name__, 'fdk-cache-class')
        intake = cls.__new__(cls)
        runner.current_cache_intake = intake
        check()
        intake.__init__(*buffers, work_end=deadline, check=check)
        check()
        cache = private / 'cache'
        cache.mkdir(mode=0o700)
        check()
        intake.seed(cache)
        check()
        guard = intake.guard
        need(intake.state == 'SEEDED' and type(guard.resources) is dict and not guard.resources,
             'fdk-cache-seeded-resources')
        names = guard.invoke(os.listdir, cache)
        need(type(names) is list and len(names) == 4 and set(names) == {r[0] for r in SEEDS},
             'fdk-cache-seed-membership')
        uid, gid = guard.invoke(os.getuid), guard.invoke(os.getgid)
        for name, size, pin in SEEDS:
            path = cache / name
            before = guard.invoke(path.lstat)
            need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_nlink == 1 and before.st_uid == uid and before.st_gid == gid
                 and before.st_size == size, 'fdk-cache-seed-owner')
            actual = intake.file_hash(path)
            after = guard.invoke(path.lstat)
            need(actual == pin and intake.identity(before) == intake.identity(after),
                 'fdk-cache-seed-pin')
        after_names = guard.invoke(os.listdir, cache)
        need(type(after_names) is list and len(after_names) == 4 and set(after_names) == set(names)
             and intake.identity(guard.invoke(cache.lstat))[:6] == intake.cache_identity
             and type(guard.resources) is dict and not guard.resources,
             'fdk-cache-seed-final-observation')
        source_check()
    except BaseException as error:
        remember(error)
    finally:
        try:
            for name in tuple(os.environ):
                if name.startswith(PRIVATE_PREFIX):
                    try:
                        del os.environ[name]
                    except BaseException as error:
                        remember(error)
        except BaseException as error:
            remember(error)
        try:
            check()
        except BaseException as error:
            remember(error)
    if first is not None:
        try:
            first.retained_cache_intake = intake
            first.retained_cache_errors = tuple(errors)
        except BaseException: pass
        raise first
    observation.update(status='SEEDED_TRANSPORT_ONLY', objects=4, bytes=404428,
                       resource_uncertain=False)
    return dict(observation)
