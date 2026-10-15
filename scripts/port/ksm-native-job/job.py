#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source acceptance and explicit refusal for the missing owned-producer interface.

This entry point deliberately launches no native command. A frozen source packet
is necessary, but cannot supply resource ownership that the producer lacks.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import time

PREFIX = 'scripts/port/ksm-native-job/'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
RECIPES_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
MAP_SHA = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
PINS = {
    'scripts/ci/native_arm.py': '077d3f8db24000dbbd7af23ba1a07757f4aeb21ff036498085618847ab5b5ce9',
    'scripts/ci/inputs.lock.json': INPUTS_SHA,
    'scripts/ci/recipes.lock.json': RECIPES_SHA,
    'scripts/client/stage.py': '13c2108aa03d76305a16bf1c9d08aa610e51f54f7726e4732c13d0824e5733f5',
    'scripts/ci/source_suites.py': '4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100',
    'scripts/build/build.py': 'e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45',
    'scripts/build/compare.py': '4198864c264642b196a090a67b36185e5c194e38edc4cb928d08eb65b9f710cd',
    'scripts/build/container-entry.sh': '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24',
    'scripts/port/refreshed-desktop/proposed-builder-inventory.lock': PACKAGES_SHA,
    'scripts/port/ksm-lifecycle/contract.py': 'bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b',
    'scripts/port/ksm-lifecycle/stage.py': '7387ab33c353d30b04208718147f92aa2a1e26a2d2b717e81a3bb082ef376010',
    'scripts/port/ksm-lifecycle/worker.py': '8670e05d0cd51a3d3d685702768634bde50427e2a0c8173f1852f94a7ff554d1',
    'scripts/port/ksm-lifecycle/test_contract.py': '13c7273a83cf3b67330f76380c05c14aa8af6ff4d7173c43d607d5c8b25e4258',
    'scripts/port/ksm-lifecycle/test_stage.py': 'e34c99bb71f57748c5f171f08085ca4d0ab3846e26cbc48ca07e246730218332',
    'scripts/port/ksm-lifecycle/test_worker.py': '5e9bac1045407585f26c8819c9e4d283cae3044e1cefbebabc1f4c086e517aa8',
    'scripts/port/ksm-lifecycle/source-checkpoint.json': '2d3b4fd99d708473d69c325778d0db345fab19a4d0b7e04bf346405f99f3219c',
    'scripts/port/ksm-native-job/current_cache.py': 'ab0229e957807c9dec63325d81aed80d77ff74708a2af31a4e720a8ee247ca4e',
    'scripts/port/ksm-native-job/cache_intake.py': 'c474a32b7be41d73504906932cab8022318cdd81e49ca6da45ed942c5bf3d5dc',
    'scripts/port/ksm-native-job/donor/current-controller.py': '6d11dedad65470650e9ada0cff47f9f5a3337ddcdc390fce76742b61598f3d61',
    'scripts/port/ksm-native-job/donor/current-packet.json': '2233f89144232c33bea9a756a7efb9aa6f5f720ba74d2bfcb5ef1e61a2ffefc5',
}
CHECKPOINT_SOURCES = ('scripts/client/stage.py', 'scripts/ci/source_suites.py', 'scripts/port/ksm-lifecycle/contract.py', 'scripts/port/ksm-lifecycle/stage.py', 'scripts/port/ksm-lifecycle/worker.py')
HISTORICAL_147 = {'checkpoint_sha256': 'f3966ce9d97b6a3661a57474740052eaa837929c7b7553ac2d82702562f03fc8', 'test_receipt_sha256': 'c0d5255a81443a4af927fff30c6ca04326abbe753b48a0ea46a1153b295f33aa', 'count': 147, 'inputs_sha256': '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650', 'packages_sha256': '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f', 'client_stage_sha256': 'dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154', 'worker_sha256': '76a3e94f317bea79d1e2444630d719b8acaed6c6cb6427c0bb19beedbc4d6b83'}
KSM_INPUTS = {'.SRCINFO', 'LICENSE', 'NOTICE', 'PKGBUILD', 'README.md', 'adaptation.patch',
              'cachy-asahi-ksmctl', 'check-source.py', 'management-policy.md', 'native-stage.md',
              'policy.py', 'source-provenance.json', 'test_ksmctl.py', 'test_policy.py', 'upstream-ksmctl'}
# Maximum, not estimates. No phase may restart or borrow cleanup/public reserves.
BUDGETS = {'source_seconds': 180, 'producer_seconds': 6600,
           'build_seconds_each': 360, 'build_count': 2, 'compare_seconds': 120,
           'lifecycle_seconds': 600, 'cleanup_seconds': 180, 'public_seconds': 30,
           'aggregate_seconds': 8460, 'image_count': 1, 'container_count': 14,
           'source_bytes_each': 2 * 1024**2, 'source_bytes_total': 32 * 1024**2,
           'private_bytes_total': 16 * 1024**3, 'disk_reserve_bytes': 8 * 1024**3,
           'public_bytes_total': 32 * 1024**2 + 65536, 'public_file_count': 3}
BLOCKERS = (
    'original-bootstrap-has-no-owned-image-reservation-or-label',
    'original-inventory-probe-has-no-owned-container-name-or-label',
    'original-builds-have-no-cancellation-recovery-journal',
    'original-cli-has-no-per-operation-cli-socket-daemon-binding',
    'original-cli-has-no-enforced-aggregate-output-or-disk-budget',
    'ksm-builder-has-no-reservation-journal-or-ownership-label',
)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_policy(files):
    """Check captured bytes, never reopen a helper or use cached bytecode."""
    for name, pin in PINS.items():
        need(name in files and sha(files[name]) == pin, 'held-source-pin-drift')
    approved = {name: sha(files['packages/tools/cachy-asahi-ksmctl/' + name]) for name in KSM_INPUTS}
    need(sha((json.dumps(approved, sort_keys=True, indent=2) + '\n').encode()) == MAP_SHA,
         'gpl15-source-drift')
    recipes = json.loads(files['scripts/ci/recipes.lock.json'])
    need(type(recipes) is dict and len(recipes) == 4, 'four-original-recipes-required')
    for directory, rows in recipes.items():
        for name, pin in rows.items():
            need(sha(files[directory + '/' + name]) == pin, 'original-recipe-drift')
    checkpoint = json.loads(files['scripts/port/ksm-lifecycle/source-checkpoint.json'])
    # The unchanged 147-test receipt is historical; this checkpoint grants no native PASS.
    historical = HISTORICAL_147
    need(sha(files['scripts/port/ksm-lifecycle/source-test-results.json']) ==
         historical['test_receipt_sha256'], 'historical147-source-test-receipt-drift')
    receipt = json.loads(files['scripts/port/ksm-lifecycle/source-test-results.json'])
    need(type(receipt.get('tests_run')) is int and receipt['tests_run'] == 147 and
         receipt.get('failures') == receipt.get('errors') == receipt.get('skips') == 0,
         'historical147-source-tests-required')
    expected = {'schema_version': 1, 'status': 'CURRENT_BASELINE_PIN_REBIND_ONLY',
        'actual_native_lifecycle_execution': 'NOT RUN', 'inputs_sha256': INPUTS_SHA,
        'packages_sha256': PACKAGES_SHA,
        'source_sha256': {name: PINS[name] for name in CHECKPOINT_SOURCES},
        'historical_147': historical}
    need(type(checkpoint) is dict and checkpoint == expected and
         type(checkpoint.get('schema_version')) is int and
         type(checkpoint.get('historical_147', {}).get('count')) is int,
         'current-baseline-checkpoint-required')
    for name, pin in checkpoint['source_sha256'].items():
        need(sha(files[name]) == pin, 'current-checkpoint-helper-drift')


def assess(snapshot, environ=None, *, clock=time.monotonic, cancelled=lambda: False,
           identity=None, started_at=None):
    """Return a bounded refusal. No shell, producer, Docker or KSM execution."""
    env = os.environ if environ is None else environ
    start = clock() if started_at is None else started_at
    report = {'schema_version': 1, 'scope': 'DEVELOPMENT TEST ONLY', 'status': 'FAIL',
              'source_acceptance': 'NOT RUN', 'producer': 'NOT RUN', 'ksm_builds': 'NOT RUN',
              'comparison': 'NOT RUN', 'lifecycle': 'NOT RUN', 'cleanup': 'NOT RUN',
              'public_export': 'NOT RUN', 'hardware': 'NOT RUN', 'management': 'NOT RUN',
              'performance': 'NOT RUN', 'published': False, 'owned_resources': [],
              'budgets': dict(BUDGETS), 'blockers': []}
    try:
        need(not cancelled(), 'job-cancelled')
        need(env.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi', 'repository-required')
        need(re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', '')) and
             env.get('GITHUB_WORKFLOW_SHA') == env['GITHUB_SHA'] and
             re.fullmatch(r'[0-9]{1,20}', env.get('GITHUB_RUN_ID', '')), 'same-job-required')
        need(snapshot.provenance['kind'] == 'reviewed-committed-source-packet-capture' and
             snapshot.provenance['commit'] == env['GITHUB_SHA'] and
             snapshot.provenance['packet_sha256'] == env.get('PACKET_SHA256') and
             snapshot.provenance['workflow'] == '.github/workflows/native-arm-ksm.yml',
             'accepted-snapshot-binding-required')
        uid, euid, gid, egid, system, machine = identity or (
            os.getuid(), os.geteuid(), os.getgid(), os.getegid(), platform.system(), platform.machine())
        need(uid == euid and gid == egid and 0 < uid <= 65535 and 0 < gid <= 65535 and
             system == 'Linux' and machine in {'aarch64', 'arm64'}, 'native-positive-identity-required')
        source_policy(snapshot.files)
        need(clock() - start <= BUDGETS['source_seconds'], 'source-deadline')
        need(not cancelled(), 'job-cancelled')
        report.update(status='BLOCKED', source_acceptance='PASS', blockers=list(BLOCKERS))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        report['source_acceptance'] = 'FAIL'
        report['blockers'] = ['preflight-refused']
    if cancelled():
        report.update(status='FAIL', source_acceptance='FAIL', blockers=['job-cancelled'])
    return report
