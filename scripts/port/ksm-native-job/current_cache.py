# SPDX-License-Identifier: MIT
"""One current501 prefill under the coordinator's existing KSM producer end."""
import ast
import base64
import hashlib
import http
import http.client
import json
import math
import os
from pathlib import Path
import pathlib
import re
import ssl
import stat
import sys
import tempfile
import time
import types
import urllib
import urllib.error
import urllib.parse

INTAKE = 'scripts/port/ksm-native-job/cache_intake.py'
INTAKE_SHA = '07ada8534f4fd21def79ab98c62334e4e0e6a7f5b15a9da8c7eacf44376c334d'
BUFFERS = ('scripts/ci/native_arm.py',
           'scripts/port/ksm-native-job/donor/current-controller.py',
           'scripts/port/ksm-native-job/donor/current-packet.json',
           'scripts/ci/inputs.lock.json')
IMPORTS = {'ast': ast, 'base64': base64, 'hashlib': hashlib, 'http': http,
    'http.client': http.client, 'json': json, 'math': math, 'os': os,
    'pathlib': pathlib, 're': re, 'ssl': ssl, 'stat': stat, 'sys': sys,
    'tempfile': tempfile, 'time': time, 'types': types, 'urllib': urllib,
    'urllib.error': urllib.error, 'urllib.parse': urllib.parse}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def prefill(snapshot, source, private, runner, state, producer_end):
    """Return TRANSPORT_ONLY; retain intake before construction, never dispose it.

    Root checks the original Source tree before/after this call. Signature audit
    remains the unchanged producer's task. No interval or external cache root is
    accepted here; caller owns eventual resource retirement.
    """
    first = receipt = intake = original_deadline = None
    last = None

    def check():
        nonlocal last
        state.check()
        need(type(original_deadline) in (int, float) and math.isfinite(original_deadline)
             and runner.deadline == original_deadline
             and type(producer_end) in (int, float) and math.isfinite(producer_end)
             and producer_end <= original_deadline - 1650, 'current-cache-original-end')
        now = time.monotonic()
        need(type(now) in (int, float) and math.isfinite(now)
             and (last is None or now >= last) and now < producer_end,
             'current-cache-deadline')
        last = now

    def resources():
        check()
        observed = runner.check_resources()
        check()
        need(type(observed) is dict and observed.get('known') is True
             and observed.get('status') == 'PASS-observed-resources',
             'current-cache-resource-observation')

    try:
        original_deadline = runner.deadline
        check()
        source, private = Path(source), Path(private)
        need(source.is_absolute() and private.is_absolute()
             and '..' not in source.parts and '..' not in private.parts
             and private == Path(runner.private_root), 'current-cache-fixed-private-root')
        need(getattr(runner, 'current_cache_intake', None) is None
             and getattr(state, 'current_cache_intake', None) is None, 'current-cache-replay')
        resources()
        raw = snapshot.files[INTAKE]
        need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == INTAKE_SHA,
             'current-cache-intake-source-pin')
        buffers = tuple(snapshot.files[name] for name in BUFFERS)
        need(all(type(value) is bytes and len(value) <= 2*1024**2 for value in buffers),
             'current-cache-captured-buffers')
        check()
        module = snapshot.module(INTAKE, 'ksm_current_cache_intake', imports=IMPORTS)
        check()
        cls = module.CacheIntake
        check()
        intake = cls.__new__(cls)
        runner.current_cache_intake = state.current_cache_intake = intake
        check()
        intake.__init__(*buffers, work_end=producer_end, check=check)
        check()
        cache, evidence = private / 'cache', private / 'cache-evidence'
        for path in (cache, evidence):
            check()
            path.mkdir(mode=0o700)
            check()
        intake.seed(cache)
        check()
        receipt = intake.acquire(cache, evidence)
        check()
        objects = intake.verify()
        check()
        need(type(receipt) is dict and receipt.get('status') == 'TRANSPORT_ONLY'
             and receipt.get('signature_authentication') == receipt.get('native_build') == 'NOT RUN'
             and receipt.get('work_end') == producer_end and receipt.get('sole_writer_required') is True
             and receipt.get('counts') == {'total': 501, 'pass': 501, 'fail': 0, 'pending': 0}
             and all(type(v) is int for v in receipt['counts'].values())
             and type(objects) is list and len(objects) == 501 and receipt.get('objects') == objects
             and intake.state == 'QUIESCENT' and type(intake.guard.resources) is dict
             and not intake.guard.resources,
             'current-cache-complete-quiescent-transport')
    except BaseException as error:
        first = error
    finally:
        try:
            names = tuple(os.environ)
            for name in names:
                if name.startswith('CACHY_OLD_FOUR_'):
                    try:
                        del os.environ[name]
                    except BaseException as error:
                        if first is None:
                            first = error
        except BaseException as error:
            if first is None:
                first = error
        try:
            resources()
        except BaseException as error:
            if first is None:
                first = error
    if first is not None:
        try:
            first.retained_cache_intake = intake
        except BaseException:
            pass
        raise first
    return receipt
