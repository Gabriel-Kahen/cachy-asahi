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
INPUTS_SHA = '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
RECIPES_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
PACKAGES_SHA = '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
MAP_SHA = 'f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44'
PINS = {
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
    'scripts/ci/inputs.lock.json': INPUTS_SHA,
    'scripts/ci/recipes.lock.json': RECIPES_SHA,
    'scripts/client/stage.py': 'dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154',
    'scripts/ci/source_suites.py': '4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100',
    'scripts/build/build.py': 'e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45',
    'scripts/build/compare.py': 'd75d9177cb741d7ae8e13466aa4b9e96587470b88749735ef2923f9a4446748d',
    'scripts/build/container-entry.sh': '89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24',
    'scripts/port/refreshed-desktop/proposed-builder-inventory.lock': PACKAGES_SHA,
    'scripts/port/ksm-lifecycle/contract.py': 'bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b',
    'scripts/port/ksm-lifecycle/stage.py': 'be4a61ac4ed8efbf243e2be1a5211c4ad0553f7be13a26b64e3e655de73cbaee',
    'scripts/port/ksm-lifecycle/worker.py': '76a3e94f317bea79d1e2444630d719b8acaed6c6cb6427c0bb19beedbc4d6b83',
    'scripts/port/ksm-lifecycle/test_contract.py': '13c7273a83cf3b67330f76380c05c14aa8af6ff4d7173c43d607d5c8b25e4258',
    'scripts/port/ksm-lifecycle/test_stage.py': 'e34c99bb71f57748c5f171f08085ca4d0ab3846e26cbc48ca07e246730218332',
    'scripts/port/ksm-lifecycle/test_worker.py': '5e9bac1045407585f26c8819c9e4d283cae3044e1cefbebabc1f4c086e517aa8',
    'scripts/port/ksm-lifecycle/source-checkpoint.json': 'f3966ce9d97b6a3661a57474740052eaa837929c7b7553ac2d82702562f03fc8',
}
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
    # The checkpoint records source tests; it never supplies native acceptance.
    need(sha(files['scripts/port/ksm-lifecycle/source-test-results.json']) ==
         'c0d5255a81443a4af927fff30c6ca04326abbe753b48a0ea46a1153b295f33aa',
         'accepted147-source-test-receipt-drift')
    need(checkpoint.get('actual_native_lifecycle_execution') == 'NOT RUN',
         'source-checkpoint-scope')
    need(checkpoint['test_results']['count'] == 147 and
         checkpoint['test_results']['skipped_count'] == 0 and
         checkpoint['test_results']['failure_count'] == checkpoint['test_results']['error_count'] == 0,
         'accepted147-source-tests-required')


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
