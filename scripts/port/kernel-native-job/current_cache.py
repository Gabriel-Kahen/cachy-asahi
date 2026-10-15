# SPDX-License-Identifier: MIT
"""Seed six pinned inputs under the existing kernel setup endpoint only."""
import hashlib
import math
import os
from pathlib import Path
import stat
import time
import types

import packet
import runtime

INTAKE = 'scripts/port/kernel-native-job/cache_intake.py'
INTAKE_SHA = '74a44a0c090ae0e334e545c5cbb4809271054eac6194f297c91abc13d6d0272e'
BUFFERS = {
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    'scripts/port/kernel-native-job/donor/current-controller.py': '6d11dedad65470650e9ada0cff47f9f5a3337ddcdc390fce76742b61598f3d61',
    'scripts/port/kernel-native-job/donor/current-packet.json': '2233f89144232c33bea9a756a7efb9aa6f5f720ba74d2bfcb5ef1e61a2ffefc5',
    'scripts/ci/inputs.lock.json': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',
}
SEEDS = (('jbigkit-2.1-8-aarch64.pkg.tar.xz', 48816, 'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db'), ('jbigkit-2.1-8-aarch64.pkg.tar.xz.sig', 566, 'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f'), ('libtiff-4.7.2-1-aarch64.pkg.tar.xz', 354480, '02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd'), ('libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig', 566, '8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa'), ('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz', 40428, '4866e25c5a7c33c3ded9f221058b5f4136cdbd991f3dc77a2f7a740368c95a61'), ('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig', 566, 'dc7ad4f478d7b196b5189e670e2d80f3e68ad28aa869b0bee697d2c5309064fa'))
RETAINED_BUBBLEWRAP_PRIVATE_PREFIX = 'CACHY_RETAINED_BUBBLEWRAP_V1_'
PRIVATE_PREFIX = 'CACHY_OLD_FOUR_'
PATH_TYPE = type(Path('/'))


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def capture_retained_private_environment():
    return {name: os.environ.pop(name) for name in tuple(os.environ)
            if name.startswith(RETAINED_BUBBLEWRAP_PRIVATE_PREFIX)}


def ordinary_error(error):
    return any(base is Exception for base in type.__dict__['__mro__'].__get__(type(error)))


def seed(snapshot, private, runner, start, files_map):
    """Retain a Source-owned intake before construction; never claim disposal.

    No acquisition, signature check or native command occurs here. The original
    producer still consumes alarm-cache and authenticates the entire501 set.
    """
    first = intake = None
    deadline = last = None
    errors = []
    cancelled = False
    captured = None
    seed_receipt = {}
    cleanup_control = None
    observation = {'status': 'FAIL', 'objects': 0, 'bytes': 0,
                   'signature_authentication': 'NOT RUN', 'native_build': 'NOT RUN',
                   'resource_uncertain': True, 'cancelled': False,
                   'secondary_errors': 0}

    def check():
        nonlocal last
        need(type(runner) is runtime.Runner and runner.deadline is deadline
             and type(deadline) in (int, float) and math.isfinite(deadline)
             and type(start) in (int, float) and math.isfinite(start)
             and start <= deadline <= start + 20760, 'kernel-cache-original-setup-end')
        now = time.monotonic()
        need(type(now) in (int, float) and math.isfinite(now)
             and (last is None or now >= last) and now < deadline
             and now < start + 20760, 'kernel-cache-deadline')
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
             'kernel-cache-source-closure')
        check()

    def capture(name, pin):
        check()
        raw, mode = packet.capture(snapshot / name, 2 * 1024**2)
        check()
        need(type(raw) is bytes and type(mode) is int and mode == 0o644
             and hashlib.sha256(raw).hexdigest() == pin, 'kernel-cache-source-pin')
        check()
        return raw

    try:
        captured = capture_retained_private_environment()
        need(type(runner) is runtime.Runner, 'kernel-cache-runner')
        need(getattr(runner, 'current_cache_intake', None) is None
             and getattr(runner, 'current_cache_observation', None) is None, 'kernel-cache-replay')
        deadline = runner.deadline
        runner.current_cache_observation = observation
        runner.current_cache_errors = errors
        check()
        need(type(snapshot) is type(private) is PATH_TYPE and snapshot.is_absolute()
             and private.is_absolute() and '..' not in snapshot.parts and '..' not in private.parts
             and snapshot == private / 'source', 'kernel-cache-fixed-private-root')
        source_check()
        raw = capture(INTAKE, INTAKE_SHA)
        buffers = tuple(capture(name, pin) for name, pin in BUFFERS.items())
        check()
        module = types.ModuleType('kernel_current_cache_intake')
        module.__file__ = str(snapshot / INTAKE)
        code = compile(raw, INTAKE, 'exec')
        check()
        exec(code, module.__dict__)
        check()
        cls = module.CacheIntake
        need(type(cls) is type and cls.__module__ == module.__name__, 'kernel-cache-class')
        intake = cls.__new__(cls)
        runner.current_cache_intake = intake
        check()
        intake.__init__(*buffers, work_end=deadline, check=check)
        check()
        cache = private / 'alarm-cache'
        cache.mkdir(mode=0o700)
        check()
        intake.seed(cache, captured=captured, receipt=seed_receipt)
        check()
        guard = intake.guard
        need(intake.state == 'SEEDED' and type(guard.resources) is dict and
             type(seed_receipt.get('directory')) is int and
             guard.resources == {('fd', seed_receipt['directory']): seed_receipt['directory']},
             'kernel-cache-seeded-resources')
        names = guard.invoke(os.listdir, cache)
        need(type(names) is list and len(names) == 6 and set(names) == {r[0] for r in SEEDS},
             'kernel-cache-seed-membership')
        uid, gid = guard.invoke(os.getuid), guard.invoke(os.getgid)
        for name, size, pin in SEEDS:
            path = cache / name
            before = guard.invoke(path.lstat)
            need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_nlink == 1 and before.st_uid == uid and before.st_gid == gid
                 and before.st_size == size, 'kernel-cache-seed-owner')
            actual = intake.file_hash(path)
            after = guard.invoke(path.lstat)
            need(actual == pin and intake.identity(before) == intake.identity(after),
                 'kernel-cache-seed-pin')
        after_names = guard.invoke(os.listdir, cache)
        need(type(after_names) is list and len(after_names) == 6 and set(after_names) == set(names)
             and intake.identity(guard.invoke(cache.lstat))[:6] == intake.cache_identity
             and type(guard.resources) is dict and
             guard.resources == {('fd', seed_receipt['directory']): seed_receipt['directory']},
             'kernel-cache-seed-final-observation')
        source_check()
    except BaseException as error:
        remember(error)
    finally:
        try:
            for name in tuple(os.environ):
                if name.startswith((PRIVATE_PREFIX, RETAINED_BUBBLEWRAP_PRIVATE_PREFIX)):
                    try:
                        del os.environ[name]
                    except BaseException as error:
                        remember(error)
        except BaseException as error:
            remember(error)
        try:
            if type(captured) is dict: captured.clear()
        except BaseException as error:
            remember(error)
        try:
            check()
        except BaseException as error:
            remember(error)
    if first is None:
        try:
            intake.finish_seed(seed_receipt)
            need(not intake.guard.resources, 'kernel-cache-finish-resources')
        except BaseException as error:
            remember(error)
    if first is not None:
        if intake is not None:
            try: intake.rollback_seed(seed_receipt, first)
            except BaseException as error:
                remember(error)
                if not ordinary_error(error) and ordinary_error(first): cleanup_control = error
            if seed_receipt.get('state') == 'ROLLED_BACK' and seed_receipt.get('uncertain') is False:
                observation['resource_uncertain'] = bool(intake.guard.resources)
        first.retained_seed_receipt = seed_receipt
        try:
            first.retained_cache_intake = intake
            first.retained_cache_errors = tuple(errors)
        except BaseException: pass
        if cleanup_control is not None: raise cleanup_control from first
        raise first
    observation.update(status='SEEDED_TRANSPORT_ONLY', objects=6, bytes=445422,
                       resource_uncertain=False)
    return dict(observation)
