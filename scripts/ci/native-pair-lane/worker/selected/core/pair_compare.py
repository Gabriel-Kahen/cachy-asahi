# SPDX-License-Identifier: MIT
"""Pure proposed pair gate. Root supplies captured summaries and live authority.

No filesystem, archive, decompression, process, clock or ownership actor exists
here. Data equality cannot attest that Root's claimed capture was performed.
"""
import hashlib
import json
import re

LABELS = ('topmem-current-1', 'topmem-current-2', 'fish-current-1', 'fish-current-2')
PAIRS = {'topmem': LABELS[:2], 'fish': LABELS[2:]}
EQUALITIES = ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')
EPOCH = 1791748800
INVENTORY = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
TOOLCHAIN = {'bash': '5.3.20-1', 'binutils': '2.46+r70+g155188ea10a7-1',
    'fish': '4.9.3-1', 'gcc': '16.1.1+r12+g301eb08fa2c5-1',
    'gcc-libs': '16.1.1+r12+g301eb08fa2c5-1', 'glibc': '2.43+r22+g8362e8ce10b2-2',
    'gnupg': '2.4.9-3', 'libarchive': '3.8.9-1', 'make': '4.4.1-3',
    'pacman': '7.1.0.r9.g54d9411-2', 'python': '3.14.8-1', 'tar': '1.35-5',
    'xz': '5.8.4-1', 'zstd': '1.5.7-3'}
SELECTED_INPUTS = {'fish': {'.SRCINFO': '2d51a0849e341581ae89d548a81a7074b8d5acc79c143155b3991b96232c6c01', 'LICENSE.project': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'LICENSE.upstream': '14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0', 'NOTICE': '0704c1ff8bcd8c94ad40888b35c5e25468ea9152b5781e7722ff0d04fb8aa879', 'PKGBUILD': '05a1b2cb4710cc14f62678df37d1236fee909874b5b709d82d54fe4b8dc0f93d', 'README.md': '46ed4a6e1dfed5f9aea5a1bb2ceff1c49d1972a8cf7f2c656a7cdfd87436b37c', '__history_previous_command.fish': 'd34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50', '__history_previous_command_arguments.fish': '4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64', 'integration-proposal.json': '951ef1f566e2b1e524bba9dd2a8f4945cc6087f0727d2623566dfce6422c5de6', 'opt-in.fish': 'd4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7', 'source-provenance.json': 'bc5200e4264569fe170944ce837d4f7578ba03ed605ec671cd6dda7ef6a0714c', 'usage.md': '37a52ff036984a5beb4f42b8837a78f3de3391081240b470177ecc0b03aa6890'}, 'topmem': {'.SRCINFO': 'fa8b8e01ce36cfe9c5b3cd0f94ae5303c6d8e6444d91831eacf9a762f7490459', 'LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'NOTICE': '07227afce6f380bcf3deaf9b273fb286f6bcee69b5f1dddec9ebcd1dc2ecd098', 'PKGBUILD': 'fc17b0af876ae0dfb97b00e2293bb01fb8c054702d19252804e8ab11196315d2', 'README.md': '90082e9119cdea843b0e060f4061a300015dffd6a25c55d12a72b0a75348cf2b', 'cachy-asahi-topmem': '96c1b49a92cb6e97d1fe5c51c23f452d79341f2d71cd624cd3197d33b29633b1', 'test_topmem.py': '207d3c924e37b3e27be2e0024dfe786716cd4464d3042125af543dfbdec6b847'}}
SELECTED_METADATA = {'fish': {'arch': ['any'], 'depends': ['fish>=4.0'], 'epoch': ['0'], 'license': ['MIT'], 'optdepends': ['cachy-asahi-fish-config: separately enabled original shell helpers'], 'pkgname': ['cachy-asahi-fish-bang-bang'], 'pkgrel': ['1'], 'pkgver': ['0.1.0'], 'sha256sums': ['d34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50', '4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64', 'd4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7', '37a52ff036984a5beb4f42b8837a78f3de3391081240b470177ecc0b03aa6890', '0704c1ff8bcd8c94ad40888b35c5e25468ea9152b5781e7722ff0d04fb8aa879', '14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0', '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'], 'source': ['__history_previous_command.fish', '__history_previous_command_arguments.fish', 'opt-in.fish', 'usage.md', 'NOTICE', 'LICENSE.upstream', 'LICENSE.project']}, 'topmem': {'arch': ['any'], 'depends': ['python>=3.11'], 'epoch': ['0'], 'license': ['MIT'], 'optdepends': [], 'pkgname': ['cachy-asahi-topmem'], 'pkgrel': ['1'], 'pkgver': ['0.1.0'], 'sha256sums': ['96c1b49a92cb6e97d1fe5c51c23f452d79341f2d71cd624cd3197d33b29633b1', '207d3c924e37b3e27be2e0024dfe786716cd4464d3042125af543dfbdec6b847', '90082e9119cdea843b0e060f4061a300015dffd6a25c55d12a72b0a75348cf2b', '07227afce6f380bcf3deaf9b273fb286f6bcee69b5f1dddec9ebcd1dc2ecd098', '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'], 'source': ['cachy-asahi-topmem', 'test_topmem.py', 'README.md', 'NOTICE', 'LICENSE']}}
COMMON = {'nonce', 'source_commit', 'context_sha256', 'daemon', 'image_id',
    'entry_script_sha256', 'toolchain', 'inventory_sha256', 'inventory_count',
    'epoch', 'source19_sha256', 'checker_source_sha256', 'decoded_metadata_source_sha256'}
SUMMARY = {'artifact', 'compressed_sha256', 'payload_sha256', 'pkginfo_sha256',
    'buildinfo_sha256', 'checker_source_sha256', 'decoded_metadata_source_sha256'}
BUILD = COMMON | {'label', 'container_id', 'mode', 'exit_code', 'recipe_inputs',
    'recipe_metadata', 'summary'}
META = {'arch', 'depends', 'epoch', 'license', 'optdepends', 'pkgname', 'pkgrel',
    'pkgver', 'sha256sums', 'source'}


class PairRefusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise PairRefusal(code)


def closed(value, keys, code):
    need(type(value) is dict and set(value) == set(keys), code)


def digest(value):
    """Canonical source/data binding; caller validates the closed shape first."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def sha(value, code):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) and
         value != '0' * 64, code)


def bounded(value, authority):
    """Reject alternate Python types and unbounded/nonfinite data before equality."""
    stack = [(value, 0)]; nodes = size = 0
    while stack:
        authority.check()
        item, depth = stack.pop(); nodes += 1
        need(nodes <= 2048 and depth <= 8, 'data-bound')
        if type(item) is dict:
            need(len(item) <= 64 and all(type(k) is str for k in item), 'object-bound')
            stack.extend((k, depth + 1) for k in item)
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            need(len(item) <= 64, 'list-bound')
            stack.extend((v, depth + 1) for v in item)
        elif type(item) is str:
            need(len(item) <= 1024 and all(ord(c) >= 32 and ord(c) < 127 for c in item), 'text-bound')
            size += len(item)
        elif type(item) is int:
            need(-1 <= item <= 2**63 - 1, 'integer-bound')
        else:
            need(type(item) is bool, 'data-type')
        need(size <= 65536, 'data-byte-bound')


def validate_expected(expected, authority):
    bounded(expected, authority)
    closed(expected, COMMON | {'schema_version', 'packages', 'reservations'}, 'expected-shape')
    need(type(expected['schema_version']) is int and expected['schema_version'] == 1, 'expected-version')
    need(type(expected['nonce']) is str and re.fullmatch('[0-9a-f]{32}', expected['nonce']), 'nonce')
    need(type(expected['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', expected['source_commit'])
         and expected['source_commit'] != '0' * 40, 'source-commit')
    need(type(expected['image_id']) is str and re.fullmatch('sha256:[0-9a-f]{64}', expected['image_id'])
         and expected['image_id'] != 'sha256:' + '0' * 64, 'image')
    for key in COMMON:
        if key.endswith('_sha256'):
            sha(expected[key], key)
    closed(expected['daemon'], {'id', 'architecture'}, 'daemon')
    need(type(expected['daemon']['id']) is str and re.fullmatch('[A-Za-z0-9:_-]{8,128}', expected['daemon']['id'])
        and expected['daemon']['architecture'] in ('aarch64', 'arm64'), 'native-daemon')
    need(type(expected['inventory_count']) is int and expected['inventory_count'] == 341
        and expected['inventory_sha256'] == INVENTORY, 'inventory')
    need(type(expected['epoch']) is int and expected['epoch'] == EPOCH, 'epoch')
    closed(expected['toolchain'], TOOLCHAIN, 'toolchain-shape')
    need(expected['toolchain'] == TOOLCHAIN, 'toolchain')
    closed(expected['reservations'], LABELS, 'reservations')
    ids = list(expected['reservations'].values())
    for value in ids:
        sha(value, 'container-id')
    need(len(set(ids)) == 4, 'four-distinct-containers')
    closed(expected['packages'], PAIRS, 'packages')
    sources = {}
    for package in PAIRS:
        row = expected['packages'][package]
        closed(row, {'artifact', 'recipe_inputs', 'recipe_metadata'}, 'package-shape')
        need(row['artifact'] == 'cachy-asahi-' + ('topmem' if package == 'topmem' else 'fish-bang-bang') + '-0.1.0-1-any.pkg.tar.zst', 'artifact')
        inputs = row['recipe_inputs']
        need(type(inputs) is dict and len(inputs) == (7 if package == 'topmem' else 12)
             and {'PKGBUILD', '.SRCINFO'} <= set(inputs), 'source19-inputs')
        for name, value in inputs.items():
            need(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+', name)
                 and name not in ('.', '..'), 'source-name')
            sha(value, 'source-sha256')
        need(inputs == SELECTED_INPUTS[package], 'sealed-source19-inputs')
        sources[package] = inputs
        closed(row['recipe_metadata'], META, 'recipe-metadata')
        need(all(type(v) is list and all(type(s) is str for s in v) for v in row['recipe_metadata'].values()), 'metadata-types')
        need(row['recipe_metadata'] == SELECTED_METADATA[package], 'sealed-recipe-metadata')
        need(row['recipe_metadata']['pkgname'] == ['cachy-asahi-' + ('topmem' if package == 'topmem' else 'fish-bang-bang')], 'pkgname')
    need(digest(sources) == expected['source19_sha256'], 'source19-binding')
    return expected


def _check(expected, builds, comparisons, authority):
    validate_expected(expected, authority)
    bounded(builds, authority); bounded(comparisons, authority)
    closed(builds, LABELS, 'four-builds')
    closed(comparisons, PAIRS, 'two-comparisons')
    for package, labels in PAIRS.items():
        authority.check()
        spec = expected['packages'][package]; summaries = []
        for label in labels:
            row = builds[label]; closed(row, BUILD, 'build-shape')
            need(row['label'] == label and row['container_id'] == expected['reservations'][label], 'owned-container-binding')
            need(row['mode'] == 'native' and type(row['exit_code']) is int and row['exit_code'] == 0, 'build-result')
            need(all(type(row[k]) is type(expected[k]) and row[k] == expected[k] for k in COMMON), 'build-common-binding')
            need(row['recipe_inputs'] == spec['recipe_inputs'] and row['recipe_metadata'] == spec['recipe_metadata'], 'recipe-binding')
            summary = row['summary']; closed(summary, SUMMARY, 'summary-shape')
            need(summary['artifact'] == spec['artifact'], 'summary-artifact')
            for key in SUMMARY - {'artifact'}:
                sha(summary[key], 'summary-digest')
            need(all(summary[k] == expected[k] for k in ('checker_source_sha256', 'decoded_metadata_source_sha256')), 'summary-source-binding')
            summaries.append(summary)
        comparison = comparisons[package]
        closed(comparison, {'schema_version', 'labels', 'artifact', 'equalities'}, 'comparison-shape')
        need(type(comparison['schema_version']) is int and comparison['schema_version'] == 1
            and comparison['labels'] == list(labels) and comparison['artifact'] == spec['artifact'], 'comparison-binding')
        claims = comparison['equalities']; closed(claims, EQUALITIES, 'equality-shape')
        observed = dict(zip(EQUALITIES, (summaries[0][key] == summaries[1][key] for key in
            ('compressed_sha256', 'payload_sha256', 'pkginfo_sha256', 'buildinfo_sha256'))))
        need(all(claims[k] is True and observed[k] is True for k in EQUALITIES), 'all-four-equalities')
    authority.check()
    return {'schema_version': 1, 'status': 'strict-pair-summary-equality',
        'binding_sha256': digest(expected), 'build_labels': list(LABELS),
        'packages': {k: dict(comparisons[k]['equalities']) for k in PAIRS},
        'hardware_status': 'NOT RUN', 'ownership_attested_by_pure_checker': False}


def check_pair_set(expected, builds, comparisons, authority):
    """Recheck closed captured data using caller's original J/E/cancellation policy.

    check() must refuse expired/cancelled/sticky-failed caller authority. Root's
    record_failure(error) latches the original exception; no local clock/reset.
    Errors from recording cannot replace the original validation/control error.
    """
    try:
        return _check(expected, builds, comparisons, authority)
    except BaseException as error:
        try:
            authority.record_failure(error)
        except BaseException:
            pass
        raise
