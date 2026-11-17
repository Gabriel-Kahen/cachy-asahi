# SPDX-License-Identifier: MIT
"""Pinned host reference and public fixture; no guest or image observation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FAMILY = ROOT / 'scripts/integration/arm16k_perl_auxcache_semantics'
HOST = FAMILY / 'auxcache.py'
HOST_PIN = dict(bytes=6791, sha256='39d91683505507f67250d1c8b5508f4d923fd1d71a13c4f7aaac404373adb52b')
BASELINE_PIN = dict(bytes=12313, sha256='bf57218ea22ca530decf18bf8ec548c22ec96afb0afc423088a97fbb148149ed')
AFTER_PIN = dict(bytes=12313, sha256='fac650a7800c4e307a3f4c3791d8897ffd8a37e2dd193e7c1890a666638aa984')
CANONICAL_PIN = dict(bytes=11373, sha256='101a81b8720aeb3f5994f133226c19f06a3b9073d51cee7d419c2ceb96184f1d')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def checked(path, expected):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o644 or info.st_size != expected['bytes']:
        raise ValueError('ordinary whole-pinned DATA operand required')
    raw = path.read_bytes()
    if pin(raw) != expected:
        raise ValueError('whole DATA pin differs')
    return raw


def reference():
    raw = checked(HOST, HOST_PIN)
    spec = importlib.util.spec_from_file_location('auxiliary_ci_host_reference', HOST)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(HOST), 'exec'), value.__dict__)
    return value


def baseline():
    raw = checked(FAMILY / 'baseline-aux.ACTUAL.bin', BASELINE_PIN)
    metadata = json.loads((HERE / 'provenance.DATA.json').read_bytes())
    if metadata['fixture'] != dict(path='scripts/integration/arm16k_perl_auxcache_semantics/baseline-aux.ACTUAL.bin', **BASELINE_PIN):
        raise ValueError('public fixture provenance differs')
    return raw


def actual_after():
    return checked(HERE / 'actual-after-aux.bin', AFTER_PIN)
