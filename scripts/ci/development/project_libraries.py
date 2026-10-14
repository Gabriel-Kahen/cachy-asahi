#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private same-job project library builds; only fixed-schema metadata is public.

All actors reuse common.command and the existing build/compare/container entry.
Registration in the exact Root packet/Session graph is required before dispatch.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request

from common import check_deadline, command, copy_regular, digest, read_json, read_regular, require, save
from base_stages import checker, defer_cleanup, start

CONTRACT = 'manifests/reviewed/project-private-libraries.json'
STAGE = 'project-libraries'
PIN = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
PACKAGES = ('jbigkit', 'libtiff')
PRIVATE_COMPOSITION = 'project-libraries-maintained-v1'
PRIMARY = '68B3537F39A313B3E574D06777193F152BDBE6A6'
MATERIALIZER_PATH = 'scripts/ci/development/prepare_project_library_sources.py'
PLAN_PATH = 'scripts/ci/development/project_library_sources/materialization-plan.json'
PLAN_SHA256 = '0bc87cda6c02df5c643da1a3790ea9eab343f5f6f1c0647889e646ea98069799'
PHASES = ('preflight', 'runtime-inputs', 'materialize', 'jbigkit-build-1', 'jbigkit-build-2', 'jbigkit-compare',
          'owned-builder-layer', 'libtiff-build-1', 'libtiff-build-2', 'libtiff-compare',
          'provider-SONAME-association', 'private-postbuild-association', 'cleanup')


MATERIALIZE_CHECKPOINTS = frozenset(('before-filtered-gzip-block', 'after-filtered-gzip-block', 'after-byte-input', 'after-directory-observation', 'after-filtered-gzip-close', 'after-filtered-tar-member', 'after-fresh-destination', 'after-gzip-read', 'after-input-final-fstat', 'after-input-fstat', 'after-input-open', 'after-input-pread', 'after-member-read', 'after-output-mode', 'after-output-open', 'after-output-write', 'after-package-directory', 'after-project-patch-transform', 'after-tar-close', 'after-tar-member', 'before-directory-observation', 'before-filter-member-proof', 'before-filtered-gzip-open', 'before-filtered-tar-member', 'before-fresh-destination', 'before-gzip-open', 'before-gzip-read', 'before-input-final-fstat', 'before-input-open', 'before-input-pread', 'before-input-read', 'before-member-read', 'before-notice-member', 'before-notice-span', 'before-output-byte-proof', 'before-output-mode', 'before-output-open', 'before-output-write', 'before-package-directory', 'before-project-patch-transform', 'before-shared-patch-hunk', 'before-shared-patch-section', 'before-synthetic-fixture', 'before-tar-open', 'preparation-completion', 'preparation-entry'))
MATERIALIZE_REASONS = {'archive member cap': 'ARCHIVE_SHAPE', 'archive path': 'ARCHIVE_SHAPE', 'archive root/duplicate': 'ARCHIVE_SHAPE', 'archive type': 'ARCHIVE_SHAPE', 'byte input cap': 'MATERIALIZER_INPUT', 'callback-refused': 'OWNED_CONTEXT', 'combined output cap': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/COPYING': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/LICENSE.recipe': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/NOTICE': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/PKGBUILD': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/PUBLICATION.md': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/inputs.json': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/jbigkit-2.2-project-filtered.tar.gz': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/jbigkit-2.2-shared_lib.patch': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/jbigkit-project-filter-tests.patch': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/packaging-REUSE.toml': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/removal.md': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/source-check.py': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/source-filter.json': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/synthetic-0.pbm': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/synthetic-1.pbm': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/synthetic-2.pbm': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/synthetic-3.pbm': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/synthetic-4.pbm': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/synthetic-pbm.py': 'MATERIALIZER_OUTPUT', 'derived output pin: jbigkit/upstream-ANNOUNCE': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/LICENSE.MIT': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/PKGBUILD': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/PUBLICATION.md': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/UPSTREAM-NOTICES.txt': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/libtiff-project-4.7.2-source.tar.gz': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/source-filter.json': 'MATERIALIZER_OUTPUT', 'derived output pin: libtiff/stage-source.py': 'MATERIALIZER_OUTPUT', 'exact 27 output membership': 'MATERIALIZER_OUTPUT', 'exact shared patch scope': 'PATCH_SHAPE', 'expanded archive cap': 'ARCHIVE_SHAPE', 'filtered archive output cap': 'MATERIALIZER_OUTPUT', 'filtered file count': 'FILTERED_SOURCE', 'filtered member pin': 'FILTERED_SOURCE', 'grant-refused': 'OWNED_CONTEXT', 'input changed': 'MATERIALIZER_INPUT', 'library-GOODSIG-primary-refused': 'SIGNATURE_STATUS', 'library-command-failed-extension-signature': 'SIGNATURE_EXECUTION', 'library-deadline': 'FRAME', 'library-download-name': 'FETCH_GUARD', 'library-extension-package-inspection': 'PACKAGE_STATIC', 'library-finite-fetch-contract': 'FETCH_GUARD', 'library-fourteen-inputs-required': 'FETCH_COUNT', 'library-full-primary-signature-refused': 'SIGNATURE_STATUS', 'library-gpgv-runtime-drift': 'RUNTIME_BINDING', 'library-gpgv-runtime-identity': 'RUNTIME_BINDING', 'library-http-body-cap': 'FETCH_GUARD', 'library-http-body-pin': 'FETCH_GUARD', 'library-http-redirect-refused': 'FETCH_GUARD', 'library-http-status': 'FETCH_GUARD', 'library-http-write': 'FETCH_GUARD', 'library-invalid-signature-status': 'SIGNATURE_STATUS', 'library-keyring-write': 'PREPARE_GUARD', 'library-materialization-plan-pin': 'PREPARE_GUARD', 'library-private-gpgv-home': 'PREPARE_GUARD', 'library-public-armor-base64': 'CERTIFICATE', 'library-public-armor-format': 'CERTIFICATE', 'library-public-binary-certificate-pin': 'CERTIFICATE', 'library-public-certificate-pin': 'CERTIFICATE', 'library-signature-status-cap': 'SIGNATURE_STATUS', 'materialization plan pin': 'MATERIALIZER_INPUT', 'materialized output pin': 'MATERIALIZER_OUTPUT', 'member byte cap': 'ARCHIVE_SHAPE', 'member truncation/root file': 'ARCHIVE_SHAPE', 'notice output cap': 'MATERIALIZER_OUTPUT', 'notice separator': 'NOTICE_PIN', 'notice source pin': 'NOTICE_PIN', 'notice span': 'NOTICE_PIN', 'ordinary directory required': 'MATERIALIZER_INPUT', 'original-frame callback required': 'MATERIALIZER_INPUT', 'patch context': 'PATCH_SHAPE', 'patch counts': 'PATCH_SHAPE', 'patch file names': 'PATCH_SHAPE', 'patch file scope': 'PATCH_SHAPE', 'patch hunk': 'PATCH_SHAPE', 'patch line': 'PATCH_SHAPE', 'patch new offset': 'PATCH_SHAPE', 'patch order': 'PATCH_SHAPE', 'project Source pin: jbigkit/LICENSE.recipe': 'SOURCE_PIN', 'project Source pin: jbigkit/PKGBUILD': 'SOURCE_PIN', 'project Source pin: jbigkit/PUBLICATION.md': 'SOURCE_PIN', 'project Source pin: jbigkit/inputs.json': 'SOURCE_PIN', 'project Source pin: jbigkit/removal.md': 'SOURCE_PIN', 'project Source pin: jbigkit/source-check.py': 'SOURCE_PIN', 'project Source pin: jbigkit/source-filter.json': 'SOURCE_PIN', 'project Source pin: jbigkit/synthetic-pbm.py': 'SOURCE_PIN', 'project Source pin: libtiff/LICENSE.MIT': 'SOURCE_PIN', 'project Source pin: libtiff/PKGBUILD': 'SOURCE_PIN', 'project Source pin: libtiff/PUBLICATION.md': 'SOURCE_PIN', 'project Source pin: libtiff/source-filter.json': 'SOURCE_PIN', 'project Source pin: libtiff/stage-source.py': 'SOURCE_PIN', 'project directory scope': 'MATERIALIZER_INPUT', 'regular bounded input required': 'MATERIALIZER_INPUT', 'root test match': 'PATCH_SHAPE', 'short input': 'MATERIALIZER_INPUT', 'short output write': 'MATERIALIZER_OUTPUT', 'stage-deadline-exceeded': 'FRAME', 'supplied upstream scope': 'MATERIALIZER_INPUT', 'upstream pin: jbigkit': 'MATERIALIZER_INPUT', 'upstream pin: libtiff': 'MATERIALIZER_INPUT', 'upstream pin: reuse': 'MATERIALIZER_INPUT', 'upstream pin: shared_patch': 'MATERIALIZER_INPUT'}
MATERIALIZE_BOUNDARIES = frozenset(('UNKNOWN','PREPARE_GUARD','PREPARE_PINS','PREPARE_PLAN','PREPARE_FETCH',
    'FETCH_GUARD','FETCH_CONTRACT','FETCH_SUBMISSION','FETCH_OPENER','FETCH_FRAME','FETCH_OPEN','FETCH_STATUS',
    'FETCH_OUTPUT_OPEN','FETCH_READ','FETCH_WRITE','FETCH_BODY_PIN','FETCH_CLOSE','FETCH_RECEIPT',
    'MATERIALIZER','CERTIFICATE_READ','CERTIFICATE_DEARMOR','KEYRING_WRITE','KEYRING_MODE','CERTIFICATE_HOME',
    'STATIC_CHECKER','EXTENSION_ARCHIVE_FETCH','EXTENSION_SIGNATURE_FETCH','SIGNATURE_RUNTIME_IDENTITY',
    'SIGNATURE_RUNTIME_HASH','SIGNATURE_COMMAND','SIGNATURE_STATUS','PACKAGE_STATIC','EXTENSION_RECEIPT','FINAL_FETCH_COUNT'))
MATERIALIZE_EXCEPTION_TYPES = {ValueError:'VALUE_ERROR',TypeError:'TYPE_ERROR',KeyError:'KEY_ERROR',
    IndexError:'INDEX_ERROR',OSError:'OS_ERROR',FileNotFoundError:'FILE_NOT_FOUND_ERROR',
    PermissionError:'PERMISSION_ERROR',TimeoutError:'TIMEOUT_ERROR',UnicodeDecodeError:'UNICODE_DECODE_ERROR',
    json.JSONDecodeError:'JSON_DECODE_ERROR',KeyboardInterrupt:'KEYBOARD_INTERRUPT',SystemExit:'SYSTEM_EXIT'}


def materialize_diagnostic(error, boundary, checkpoint):
    """Fixed labels only; no str(), repr(), notes, paths or traceback traversal."""
    result = {'schema_version':1,'boundary':'UNKNOWN','checkpoint':'UNKNOWN','exception':'OTHER','reason':'UNKNOWN'}
    try:
        if type(boundary) is str and len(boundary) <= 64 and boundary in MATERIALIZE_BOUNDARIES:result['boundary'] = boundary
        if type(checkpoint) is str and len(checkpoint) <= 64 and checkpoint in MATERIALIZE_CHECKPOINTS | {'NONE','UNKNOWN'}:result['checkpoint'] = checkpoint
        result['exception'] = MATERIALIZE_EXCEPTION_TYPES.get(type(error),'OTHER')
        if type(error) is ValueError:
            args = BaseException.args.__get__(error,type(error))
            if type(args) is tuple and len(args) == 1 and type(args[0]) is str and len(args[0]) <= 512:
                result['reason'] = MATERIALIZE_REASONS.get(args[0],'UNKNOWN')
    except Exception:
        # Ordinary diagnostic uncertainty adds no new operational acceptance.
        return {'schema_version':1,'boundary':'UNKNOWN','checkpoint':'UNKNOWN','exception':'OTHER','reason':'UNKNOWN'}
    return result


MATERIALIZE_OUTPUT_NAMES = frozenset(reason.removeprefix('derived output pin: ')
    for reason in MATERIALIZE_REASONS if reason.startswith('derived output pin: '))


def validate_materialize_output_proof(value):
    """Closed failure facts, never an accepted output or path selector."""
    require(type(value) is dict and set(value) == {'schema_version','output','mismatch',
        'expected_bytes','observed_bytes','expected_sha256','observed_sha256'} and
        type(value['schema_version']) is int and value['schema_version'] == 1 and
        type(value['output']) is str and value['output'] in MATERIALIZE_OUTPUT_NAMES and
        type(value['mismatch']) is str and value['mismatch'] in ('LENGTH','SHA256') and
        all(type(value[key]) is int and 0 <= value[key] <= 8388608
            for key in ('expected_bytes','observed_bytes')), 'library-materialize-output-proof-schema')
    if value['mismatch'] == 'LENGTH':
        require(value['observed_bytes'] != value['expected_bytes'] and
            value['observed_sha256'] is value['expected_sha256'] is None,
            'library-materialize-output-proof-length')
    else:
        require(value['observed_bytes'] == value['expected_bytes'] and
            all(type(value[key]) is str and PIN.fullmatch(value[key])
                for key in ('expected_sha256','observed_sha256')) and
            value['observed_sha256'] != value['expected_sha256'],
            'library-materialize-output-proof-sha256')
    return dict(value)


def validate_materialize_diagnostic(value):
    require(type(value) is dict and {'schema_version','boundary','checkpoint','exception','reason'} <= set(value) <=
            {'schema_version','boundary','checkpoint','exception','reason','output_proof'} and
            type(value['schema_version']) is int and value['schema_version'] == 1 and
            type(value['boundary']) is str and len(value['boundary']) <= 64 and value['boundary'] in MATERIALIZE_BOUNDARIES and
            type(value['checkpoint']) is str and len(value['checkpoint']) <= 64 and value['checkpoint'] in MATERIALIZE_CHECKPOINTS | {'NONE','UNKNOWN'} and
            type(value['exception']) is str and len(value['exception']) <= 64 and value['exception'] in set(MATERIALIZE_EXCEPTION_TYPES.values()) | {'OTHER'} and
            type(value['reason']) is str and len(value['reason']) <= 64 and value['reason'] in set(MATERIALIZE_REASONS.values()) | {'UNKNOWN'},
            'library-materialize-diagnostic-schema')
    result = dict(value)
    if 'output_proof' in value:
        require((value['boundary'],value['checkpoint'],value['exception'],value['reason']) ==
            ('MATERIALIZER','before-output-byte-proof','VALUE_ERROR','MATERIALIZER_OUTPUT'),
            'library-materialize-output-proof-context')
        result['output_proof'] = validate_materialize_output_proof(value['output_proof'])
    require(len(json.dumps(value,ensure_ascii=True,sort_keys=True).encode()) <= 2048,
            'library-materialize-diagnostic-cap')
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError('library-http-redirect-refused')


def dearmor(raw):
    require(len(raw) == 3098 and hashlib.sha256(raw).hexdigest() ==
            '6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f', 'library-public-certificate-pin')
    lines = raw.decode('ascii').splitlines()
    require(lines[0] == '-----BEGIN PGP PUBLIC KEY BLOCK-----' and
            lines[-1] == '-----END PGP PUBLIC KEY BLOCK-----', 'library-public-armor-format')
    separator = lines.index(''); encoded = lines[separator + 1:-2]
    require(encoded and all(re.fullmatch('[A-Za-z0-9+/]+={0,2}', line) for line in encoded) and
            re.fullmatch('=[A-Za-z0-9+/]{4}', lines[-2]), 'library-public-armor-format')
    text = ''.join(encoded); binary = base64.b64decode(text, validate=True)
    require(base64.b64encode(binary).decode() == text, 'library-public-armor-base64')
    crc = 0xb704ce
    for byte in binary:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= 0x1864cfb
    require((crc & 0xffffff).to_bytes(3, 'big') == base64.b64decode(lines[-2][1:], validate=True) and
            len(binary) == 2228 and hashlib.sha256(binary).hexdigest() ==
            '9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae', 'library-public-binary-certificate-pin')
    return binary


def signature_status(text):
    require(len(text.encode('utf-8')) <= 65536, 'library-signature-status-cap')
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith('[GNUPG:] ')]
    require(not any(row and row[0] in {'BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','ERROR','NODATA','BADARMOR','UNEXPECTED','INV_SGNR','NO_SECKEY'} for row in rows), 'library-invalid-signature-status')
    good = [row for row in rows if row and row[0] == 'GOODSIG']
    require(len(good) == 1 and len(good[0]) >= 3 and good[0][1] == PRIMARY[-16:], 'library-GOODSIG-primary-refused')
    valid = [row for row in rows if row and row[0] == 'VALIDSIG']
    require(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == PRIMARY and
            valid[0][8] == '10', 'library-full-primary-signature-refused')
    return {'status': 'PASS', 'primary': PRIMARY, 'digest_algorithm': '10'}


def public_metadata(value):
    """Explicit positive projection. Internal paths, notes and records never pass."""
    require(value.get('stage') == STAGE and value.get('status') in ('PASS', 'FAIL') and
            value.get('public_promotion') is False and value.get('publication_license_acceptance') is False,
            'library-public-schema')
    phases = value.get('phases')
    require(type(phases) is dict and set(phases) == set(PHASES) and
            all(v in ('PASS','FAIL','NOT RUN') for v in phases.values()), 'library-public-phases')
    cleanup = value.get('cleanup', {})
    require(cleanup.get('status') in ('PASS','FAIL','NOT RUN') and type(cleanup.get('uncertainties')) is int and
            0 <= cleanup['uncertainties'] <= 128, 'library-public-cleanup')
    result = {'schema_version':1, 'stage':STAGE, 'status':value['status'], 'hardware_validation':'NOT RUN',
              'public_promotion':False, 'publication_license_acceptance':False, 'phases':dict(phases),
              'cleanup_status':cleanup['status'],
              'cleanup_uncertainty':'OWNED_CLEANUP_UNCERTAIN' if cleanup['uncertainties'] else 'NONE',
              'cancelled':value.get('cancelled') is True}
    if 'artifact_sha256' in value:
        rows = value['artifact_sha256']
        require(type(rows) is dict and set(rows) == set(PACKAGES) and all(type(row) is list and len(row) == 2 and
                all(type(pin) is str and PIN.fullmatch(pin) for pin in row) for row in rows.values()), 'library-public-artifact-pins')
        result['artifact_sha256'] = rows
    if 'failed_phase' in value:
        require(value['failed_phase'] in PHASES, 'library-public-failure-phase')
        result['failed_phase'] = value['failed_phase']
    if 'materialize_diagnostic' in value:
        require(value['status'] == 'FAIL' and result.get('failed_phase') in ('runtime-inputs','materialize'),
                'library-diagnostic-failure-only')
        result['materialize_diagnostic'] = validate_materialize_diagnostic(value['materialize_diagnostic'])
    if value['status'] == 'PASS':
        require(all(v == 'PASS' for v in phases.values()) and cleanup['status'] == 'PASS' and
                cleanup['uncertainties'] == 0 and result['cancelled'] is False and
                'artifact_sha256' in result and all(row[0] == row[1] for row in result['artifact_sha256'].values()) and
                'failed_phase' not in result, 'library-public-pass-contradiction')
    return result


def validate_public_metadata(value):
    required = {'schema_version','stage','status','hardware_validation','public_promotion','publication_license_acceptance',
                'phases','cleanup_status','cleanup_uncertainty','cancelled'}
    require(type(value) is dict and required <= set(value) <= required | {'artifact_sha256','failed_phase','materialize_diagnostic'} and
            value.get('schema_version') == 1 and value.get('hardware_validation') == 'NOT RUN' and
            type(value.get('cancelled')) is bool and value.get('cleanup_uncertainty') in ('NONE','OWNED_CLEANUP_UNCERTAIN'), 'library-public-schema')
    internal = dict(value, cleanup={'status':value['cleanup_status'], 'uncertainties':int(value['cleanup_uncertainty'] != 'NONE')})
    require(public_metadata(internal) == value, 'library-public-schema')
    return value


def package_lock(text):
    rows = [line.split() for line in text.splitlines()]
    require(rows and all(len(row) == 2 for row in rows) and len({row[0] for row in rows}) == len(rows), 'library-lock-invalid')
    values = dict(rows)
    require(text == ''.join(n + ' ' + v + '\n' for n, v in sorted(values.items())), 'library-lock-invalid')
    return values


def expected_layer_lock(text, extensions):
    rows = package_lock(text)
    require(rows.pop('jbigkit', None) == '2.1-8' and 'cachy-asahi-jbigkit' not in rows, 'library-baseline-provider-refused')
    rows['cachy-asahi-jbigkit'] = '2.2-1.1'
    require(type(extensions) is list and 1 <= len(extensions) <= 8 and
            any(row.get('name') == 'cmake' for row in extensions), 'library-cmake-extension-not-registered')
    names = set()
    for row in extensions:
        require(set(row) >= {'name', 'version', 'archive', 'signature', 'depends', 'provides'} and
                type(row['name']) is str and re.fullmatch('[a-z0-9][a-z0-9+_.-]*', row['name']) and
                row['name'] not in names and row['name'] != 'jbigkit' and
                type(row['version']) is str and re.fullmatch('[A-Za-z0-9+_.:~-]+', row['version']) and
                type(row['archive']['filename']) is str and re.fullmatch('[A-Za-z0-9+_.-]+[.]pkg[.]tar[.](?:xz|zst|gz)', row['archive']['filename']) and
                type(row['archive']['bytes']) is int and 0 < row['archive']['bytes'] <= 64 * 1024**2 and
                PIN.fullmatch(row['archive']['sha256']) and PIN.fullmatch(row['signature']['sha256']), 'library-extension-refused')
        require(row['name'] not in rows or rows[row['name']] == row['version'], 'library-extension-would-change-baseline')
        names.add(row['name']); rows[row['name']] = row['version']
    return ''.join(n + ' ' + v + '\n' for n, v in sorted(rows.items()))


def checked_pair(left, right):
    require(left['environment'] != right['environment'] and left['environment'] and
            left['filename'] == right['filename'] and left['sha256'] == right['sha256'], 'library-byte-rebuild-differs')


def dynamic_report(text, expected_hash, soname):
    lines = text.splitlines()
    require(lines and lines[0] == expected_hash + '  /tmp/library.so', 'library-probe-hash-refused')
    found = re.findall(r'\(SONAME\).*Library soname: \[([^\]]+)\]', text)
    needed = re.findall(r'\(NEEDED\).*Shared library: \[([^\]]+)\]', text)
    require(found == [soname] and len(needed) == len(set(needed)) and
            all(re.fullmatch('[A-Za-z0-9+_.-]+', n) for n in needed) and
            '(RPATH)' not in text and '(RUNPATH)' not in text, 'library-dynamic-tags-refused')
    return {'soname': soname, 'needed': sorted(needed), 'member_sha256': expected_hash,
            'rpath': [], 'runpath': [], 'runtime_abi': 'NOT RUN'}


def source_package_inventory(key, spec, members):
    prefix = ('usr/share/doc/' + spec['name'] + '/source/' if key == 'jbigkit' else
              'usr/share/' + spec['name'] + '/corresponding-source/')
    selected = {name[len(prefix):]:row for name,row in members.items() if name.startswith(prefix) and row['type'] == '0'}
    require(0 < len(selected) <= 64 and sum(row['size'] for row in selected.values()) <= 32 * 1024**2,
            'library-corresponding-source-inventory-cap')
    recipe_prefix = '' if key == 'jbigkit' else 'recipe/'
    require({name[len(recipe_prefix):] for name in selected if name.startswith(recipe_prefix)} == set(spec['inputs'])
            if recipe_prefix else set(selected) == set(spec['inputs']), 'library-corresponding-source-copyset')
    for name,pin in spec['inputs'].items():
        require(selected[recipe_prefix + name]['sha256'] == pin, 'library-corresponding-source-pin')
    if key == 'libtiff':
        generated = ('actual-build/libtiff/tif_config.h','actual-build/libtiff/tiffconf.h','actual-build/libtiff/tiffvers.h',
                     'actual-build/compile_commands.json','actual-build/CMakeCache.txt','actual-build/test-selection.json',
                     'inventory.json','release-association-status.json')
        require(set(selected) == {recipe_prefix+n for n in spec['inputs']} | set(generated),
                'library-corresponding-generated-files')
    return {name:{'sha256':row['sha256'],'bytes':row['size']} for name,row in sorted(selected.items())}


class Operations:
    def __init__(self, controller, root, output, cache, deadline, session, trusted_gpgv):
        self.controller, self.root, self.output, self.cache = controller, root, output, cache
        self.deadline, self.session = deadline, session
        self.counter, self.containers, self.layer = 0, {}, None
        self.fetch_count, self.fetch_bytes, self.accepted_extensions = 0, 0, {}
        self.materialized = None
        self.materialize_active = False
        self.materialize_boundary = 'UNKNOWN'
        self.materialize_checkpoint = 'NONE'
        self.materialize_failure = None
        self.materialize_first_failure = None
        self.materialize_secondary_control = None
        require(type(trusted_gpgv) is dict and set(trusted_gpgv) == {'path','sha256','identity'} and
                trusted_gpgv['path'] == '/usr/bin/gpgv' and PIN.fullmatch(trusted_gpgv['sha256']) and
                type(trusted_gpgv['identity']) is list and len(trusted_gpgv['identity']) == 9 and
                all(type(n) is int for n in trusted_gpgv['identity']), 'library-gpgv-runtime-binding-required')
        self.trusted_gpgv = dict(trusted_gpgv)
        self.nonce = os.urandom(16).hex()
        self.prefix = ['/usr/bin/docker', '--host', 'unix:///run/docker.sock']

    def guard(self, cleanup=False):
        check_deadline(self.deadline)
        context = self.session.project_library_context(deadline=self.deadline, controller=self.controller, cleanup=cleanup)
        if not cleanup and self.session.cancelled and self.session.cancelled():
            raise KeyboardInterrupt()
        return context

    def run(self, args, label, timeout=120, cleanup=False):
        context = self.guard(cleanup)
        require(self.counter < 128, 'library-command-cap')
        self.counter += 1
        log = self.output / ('private-' + str(self.counter) + '-' + label + '.log')
        code = command(args, log, timeout, deadline=self.deadline, cleanup_grace=5 if cleanup else 90, runtime_env=context['runtime_env'])
        self.guard(cleanup)
        require(code == 0, 'library-command-failed-' + label)
        return log

    def docker(self, args, label, **options):
        return self.run(self.prefix + args, label, **options)

    def build(self, key, number, spec, image, lock):
        self.guard()
        require(self.materialized is not None, 'library-materialization-required')
        directory = self.materialized / key
        require(not directory.is_symlink(), 'library-recipe-path-refused')
        require({p.name for p in directory.iterdir()} == set(spec['inputs']), 'library-exact-recipe-copyset-required')
        for name, pin in spec['inputs'].items():
            require('/' not in name and PIN.fullmatch(pin) and digest(directory / name, deadline=self.deadline) == pin, 'library-recipe-pin-refused')
        reviewed = self.output / (key + '-reviewed-inputs.json')
        if not reviewed.exists(): save(reviewed, spec['inputs'], deadline=self.deadline)
        attempt = self.output / (key + '-attempt-' + str(number))
        self.run([sys.executable, '-B', str(self.root / 'scripts/build/build.py'), str(directory),
                  '--image', image, '--mode', 'native', '--network', 'none', '--source-date-epoch', str(spec['epoch']),
                  '--expected-packages', str(lock), '--reviewed-inputs', str(reviewed), '--timeout', '1200', '--output', str(attempt)],
                 key + '-build-' + str(number), timeout=1260)
        return self.inspect(key, number, spec, image, lock, attempt)

    def inspect(self, key, number, spec, image, lock, attempt):
        self.guard()
        record = read_json(attempt / 'provenance.json', deadline=self.deadline)
        require(record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native' and
                record.get('image_id') == record.get('image') == image and record.get('recipe_inputs') == spec['inputs'] and
                record.get('source_date_epoch') == spec['epoch'] and
                record.get('expected_packages_sha256') == digest(lock, deadline=self.deadline), 'library-build-provenance-refused')
        for name, pin in record['files'].items():
            require('..' not in Path(name).parts and not Path(name).is_absolute() and PIN.fullmatch(pin) and
                    digest(attempt / name, deadline=self.deadline) == pin, 'library-build-evidence-drift')
        validation = read_json(attempt / 'validation.json', deadline=self.deadline)
        require(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'library-package-static-failed')
        package = validation['artifacts'][0]
        meta, members = package['metadata'], package['members']
        require(meta['.PKGINFO'].get('pkgname') == [spec['name']] and meta['.PKGINFO'].get('pkgver') == [spec['version']] and
                meta['.PKGINFO'].get('arch') == ['aarch64'] and
                sorted(meta['.PKGINFO'].get('provides', [])) == sorted(spec['provides']) and
                meta['.BUILDINFO'].get('pkgbuild_sha256sum') == [spec['inputs']['PKGBUILD']] and
                '.INSTALL' not in members, 'library-package-metadata-refused')
        require(package['elf'] and all(row.get('machine') == 183 and row.get('errors') == [] and
                row.get('load_segments', 0) > 0 for row in package['elf'].values()), 'library-ELF16K-static-refused')
        artifacts = record['artifacts']; require(len(artifacts) == 1, 'library-one-archive-required')
        filename, pin = next(iter(artifacts.items()))
        require(re.fullmatch(re.escape(spec['name'] + '-' + spec['version']) + r'-aarch64[.]pkg[.]tar[.](?:xz|zst|gz)', filename) and
                digest(attempt / 'artifacts' / filename, deadline=self.deadline) == pin, 'library-artifact-refused')
        libraries = {}
        for soname in spec['library_sonames']:
            candidates = [n for n in package['elf'] if n.startswith('usr/lib/') and
                          n.rsplit('/', 1)[1].startswith(soname) and members[n]['type'] == '0']
            require(len(candidates) == 1, 'library-selected-ELF-member-refused')
            member = candidates[0]
            libraries[soname] = self.probe(attempt / 'artifacts' / filename, member, members[member]['sha256'], soname, image)
        source_inventory = source_package_inventory(key, spec, members)
        return {'filename': filename, 'sha256': pin, 'environment': record['clean_environment_id'],
                'validation_sha256':digest(attempt / 'validation.json', deadline=self.deadline),
                'provenance_sha256':digest(attempt / 'provenance.json', deadline=self.deadline),
                'corresponding_source_members':source_inventory,
                'archive': str(attempt / 'artifacts' / filename), 'libraries': libraries,
                'recipe_sha256': spec['inputs']['PKGBUILD'], 'source_inputs': spec['inputs'],
                'buildinfo_sha256': members['.BUILDINFO']['sha256'], 'ELF16K_static': 'PASS'}

    def probe(self, archive, member, pin, soname, image):
        self.guard()
        require(re.fullmatch(r'usr/lib/[A-Za-z0-9+_.-]+', member), 'library-probe-member-refused')
        name = 'cachy-project-probe-' + self.nonce + '-' + str(len(self.containers))
        self.containers[name] = {'image': image, 'labels': {'org.cachy.private-project': self.nonce}}
        script = 'set -euo pipefail; bsdtar -xOf /artifact ' + member + ' > /tmp/library.so; sha256sum /tmp/library.so; readelf --wide --dynamic /tmp/library.so'
        log = self.docker(['run', '--rm', '--name', name, '--pull=never', '--platform', 'linux/arm64',
            '--network', 'none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
            '--pids-limit', '64', '--memory', '512m', '--cpus', '1', '--label', 'org.cachy.private-project=' + self.nonce,
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m', '--mount', 'type=bind,src=' + str(archive) + ',dst=/artifact,readonly',
            '--entrypoint', '/bin/bash', image, '-c', script], 'ELF-probe')
        return dynamic_report(read_regular(log, deadline=self.deadline).decode('utf-8'), pin, soname)

    def compare(self, key, left, right):
        self.guard(); checked_pair(left, right)
        log = self.run([sys.executable, '-B', str(self.root / 'scripts/build/compare.py'),
                       str(self.output / (key + '-attempt-1')), str(self.output / (key + '-attempt-2')), '--require-bytes'], key + '-compare')
        value = read_json(log, deadline=self.deadline)
        row = value.get('packages', {}).get(left['filename'], {})
        require(value.get('status') == 'contents-reproduced' and value.get('errors') == [] and
                all(row.get(k) is True for k in ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal')), 'library-rebuild-comparison-failed')

    def fetch(self, item, name):
        self.materialize_checkpoint = 'NONE'
        self.materialize_boundary = 'FETCH_GUARD'
        self.guard()
        self.materialize_boundary = 'FETCH_CONTRACT'
        require(self.fetch_count < 14 and type(item['bytes']) is int and 0 < item['bytes'] <= 32 * 1024**2 and
                PIN.fullmatch(item['sha256']) and item['url'].startswith(('https://www.cl.cam.ac.uk/', 'https://gitlab.com/', 'https://raw.githubusercontent.com/archlinuxarm/', 'https://mirror.archlinuxarm.org/')), 'library-finite-fetch-contract')
        require(re.fullmatch('[A-Za-z0-9+_.-]+', name), 'library-download-name')
        self.fetch_count += 1
        path = self.output / ('private-input-' + name)
        self.materialize_boundary = 'FETCH_SUBMISSION'
        save(self.output / ('private-input-' + name + '.json'), {'url':item['url'], 'expected_bytes':item['bytes'],
             'expected_sha256':item['sha256'], 'status':'SUBMITTED'}, deadline=self.deadline)
        self.materialize_boundary = 'FETCH_OPENER'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.materialize_boundary = 'FETCH_FRAME'
        started = time.monotonic(); timeout = min(30, self.deadline - started)
        require(timeout > 0, 'library-deadline')
        response = stream = None
        primary = None
        try:
            self.materialize_boundary = 'FETCH_OPEN'
            response = opener.open(urllib.request.Request(item['url'], method='GET'), timeout=timeout)
            self.materialize_boundary = 'FETCH_STATUS'
            self.guard(); require(response.status == 200, 'library-http-status')
            self.materialize_boundary = 'FETCH_OUTPUT_OPEN'
            stream = path.open('xb')
            total, hasher = 0, hashlib.sha256()
            while True:
                self.materialize_boundary = 'FETCH_READ'
                self.guard(); block = response.read(min(65536, item['bytes'] + 1 - total)); self.guard()
                if not block: break
                total += len(block); self.fetch_bytes += len(block)
                require(total <= item['bytes'] and self.fetch_bytes <= 64 * 1024**2, 'library-http-body-cap')
                self.materialize_boundary = 'FETCH_WRITE'
                require(stream.write(block) == len(block), 'library-http-write'); hasher.update(block)
            self.materialize_boundary = 'FETCH_BODY_PIN'
            require(total == item['bytes'] and hasher.hexdigest() == item['sha256'], 'library-http-body-pin')
        except BaseException as error:
            primary = error
            self.capture_materialize_failure(error)
        finally:
            for label, resource in (('stream', stream), ('response', response)):
                if resource is None: continue
                self.materialize_boundary = 'FETCH_CLOSE'
                try: resource.close()
                except BaseException as error:
                    if primary is None:
                        primary = error
                        self.capture_materialize_failure(error)
                    primary.add_note('HTTP ' + label + ' close uncertainty: ' + type(error).__name__ + ': ' + str(error))
        if primary is not None: raise primary
        self.guard()
        self.materialize_boundary = 'FETCH_RECEIPT'
        save(self.output / ('private-input-' + name + '.json'), {'url': item['url'], 'bytes': total, 'sha256': hasher.hexdigest(),
             'status': 200, 'elapsed_seconds': time.monotonic() - started}, deadline=self.deadline)
        return path

    def prepare(self, contract, materializer, phases):
        self.materialize_active = True
        try:
            self.materialize_boundary = 'PREPARE_GUARD'
            self.guard()
            self.materialize_boundary = 'PREPARE_PINS'
            require(contract.get('materialization_plan_sha256') == PLAN_SHA256 and
                    digest(self.root / PLAN_PATH, deadline=self.deadline) == PLAN_SHA256 and
                    digest(self.root / MATERIALIZER_PATH, deadline=self.deadline) == contract.get('materializer_source_sha256'),
                    'library-materialization-plan-pin')
            self.materialize_boundary = 'PREPARE_PLAN'
            plan = read_json(self.root / PLAN_PATH, deadline=self.deadline)
            self.materialize_boundary = 'PREPARE_FETCH'
            upstream = {key: self.fetch(row, key) for key, row in plan['upstream'].items()}
            self.materialized = self.output / 'materialized'
            phases['materialize'] = 'RUNNING'
            self.materialize_boundary = 'MATERIALIZER'
            materializer.prepare_sources(project_dirs={key: self.root / 'scripts/ci/development/project_library_sources' / key for key in PACKAGES},
                upstream=upstream, destination=self.materialized, check=self.materialize_check, plan_path=self.root / PLAN_PATH)
            phases['materialize'] = 'PASS'
            self.materialize_checkpoint = 'NONE'
            self.materialize_boundary = 'CERTIFICATE_READ'
            keyring = self.output / 'private-public-keyring.gpg'
            armor = read_regular(self.cache / 'archlinuxarm.gpg', 3098, deadline=self.deadline)
            self.materialize_boundary = 'CERTIFICATE_DEARMOR'
            binary = dearmor(armor)
            self.materialize_boundary = 'KEYRING_WRITE'
            with keyring.open('xb') as stream: require(stream.write(binary) == len(binary), 'library-keyring-write')
            self.materialize_boundary = 'KEYRING_MODE'
            keyring.chmod(0o600)
            self.materialize_boundary = 'CERTIFICATE_HOME'
            home = self.output / 'private-gpgv-home'; home.mkdir(mode=0o700)
            require(home.stat().st_uid == os.geteuid() and home.stat().st_mode & 0o777 == 0o700 and not home.is_symlink(), 'library-private-gpgv-home')
            self.materialize_boundary = 'STATIC_CHECKER'
            inspector = checker(self.root, deadline=self.deadline)
            for row in contract['builder_extensions']:
                self.materialize_boundary = 'EXTENSION_ARCHIVE_FETCH'
                package = self.fetch(row['archive'], row['archive']['filename'])
                self.materialize_boundary = 'EXTENSION_SIGNATURE_FETCH'
                signature = self.fetch(row['signature'], row['signature']['filename'])
                self.guard()
                self.materialize_boundary = 'SIGNATURE_RUNTIME_IDENTITY'
                node = Path(self.trusted_gpgv['path']).stat()
                require([node.st_dev,node.st_ino,node.st_mode,node.st_nlink,node.st_uid,node.st_gid,node.st_size,node.st_mtime_ns,node.st_ctime_ns] == self.trusted_gpgv['identity'], 'library-gpgv-runtime-identity')
                self.materialize_boundary = 'SIGNATURE_RUNTIME_HASH'
                require(digest(Path(self.trusted_gpgv['path']), deadline=self.deadline) == self.trusted_gpgv['sha256'], 'library-gpgv-runtime-drift')
                self.materialize_boundary = 'SIGNATURE_COMMAND'
                log = self.run([self.trusted_gpgv['path'], '--homedir', str(home), '--keyring', str(keyring), '--status-fd', '1', str(signature), str(package)], 'extension-signature')
                self.materialize_boundary = 'SIGNATURE_RUNTIME_HASH'
                require(digest(Path(self.trusted_gpgv['path']), deadline=self.deadline) == self.trusted_gpgv['sha256'], 'library-gpgv-runtime-drift')
                self.materialize_boundary = 'SIGNATURE_STATUS'
                accepted = signature_status(read_regular(log, 65536, deadline=self.deadline).decode('utf-8'))
                self.materialize_boundary = 'PACKAGE_STATIC'
                self.guard(); report = inspector.package(package); self.guard()
                meta = report['metadata']['.PKGINFO']
                require(report['errors'] == [] and meta.get('pkgname') == [row['name']] and meta.get('pkgver') == [row['version']] and
                        meta.get('arch') == ['aarch64'] and sorted(meta.get('depend', [])) == sorted(row['depends']) and
                        sorted(meta.get('provides', [])) == sorted(row['provides']) and '.INSTALL' not in report['members'] and
                        all(elf.get('machine') == 183 and not elf.get('errors') for elf in report['elf'].values()), 'library-extension-package-inspection')
                receipt = {**accepted, 'filename': row['archive']['filename'], 'sha256': row['archive']['sha256'],
                           'name': row['name'], 'version': row['version'], 'package_inspection': 'PASS'}
                self.materialize_boundary = 'EXTENSION_RECEIPT'
                save(self.output / ('private-extension-' + row['name'] + '.json'), receipt, deadline=self.deadline)
                self.accepted_extensions[row['name']] = package
            self.materialize_boundary = 'FINAL_FETCH_COUNT'
            require(self.fetch_count == 14, 'library-fourteen-inputs-required')
        except BaseException as error:
            self.capture_materialize_failure(error)
            raise
        finally:
            self.materialize_active = False

    def materialize_check(self, reason):
        self.materialize_boundary = 'MATERIALIZER'
        self.materialize_checkpoint = reason if type(reason) is str and len(reason) <= 64 and reason in MATERIALIZE_CHECKPOINTS else 'UNKNOWN'
        self.guard()

    def capture_materialize_failure(self, error):
        if self.materialize_active and self.materialize_first_failure is None:
            # Establish first cause and safe fallback before optional diagnostics.
            self.materialize_first_failure = error
            try:
                self.materialize_failure = {'schema_version':1,'boundary':'UNKNOWN',
                    'checkpoint':'UNKNOWN','exception':MATERIALIZE_EXCEPTION_TYPES.get(type(error),'OTHER'),'reason':'UNKNOWN'}
                self.materialize_failure = materialize_diagnostic(error,self.materialize_boundary,self.materialize_checkpoint)
                if type(error) is ValueError:
                    attributes = object.__getattribute__(error,'__dict__')
                    secondary = attributes.get('_materialize_output_control')
                    if isinstance(secondary,BaseException):self.materialize_secondary_control = secondary
                    proof = attributes.get('_materialize_output_proof')
                    if proof is not None and (self.materialize_failure['boundary'],self.materialize_failure['checkpoint'],
                        self.materialize_failure['exception'],self.materialize_failure['reason']) == (
                        'MATERIALIZER','before-output-byte-proof','VALUE_ERROR','MATERIALIZER_OUTPUT'):
                        self.materialize_failure['output_proof'] = validate_materialize_output_proof(proof)
            except BaseException as secondary:
                # Deferred controls remain distinct from the original failure.
                self.materialize_secondary_control = secondary
                if self.materialize_failure is None:
                    self.materialize_failure = {'schema_version':1,'boundary':'UNKNOWN',
                        'checkpoint':'UNKNOWN','exception':'OTHER','reason':'UNKNOWN'}
                prior = error.__cause__
                if secondary is not error and prior is not secondary:
                    error.__cause__ = secondary if prior is None else BaseExceptionGroup(
                        'materialization diagnostic secondary cause', [prior,secondary])

    def extension_inputs(self, extensions):
        result = []
        for row in extensions:
            self.guard()
            require(row['name'] in self.accepted_extensions, 'library-extension-not-accepted')
            path = self.accepted_extensions[row['name']]
            body = read_regular(path, row['archive']['bytes'], deadline=self.deadline)
            require(len(body) == row['archive']['bytes'] and hashlib.sha256(body).hexdigest() == row['archive']['sha256'], 'library-extension-cache-pin-refused')
            result.append(path)
        return result

    def layer_image(self, jbig, baseline, extensions):
        self.guard()
        lock_text = read_regular(Path(baseline['packages_lock']), deadline=self.deadline).decode('utf-8')
        wanted = expected_layer_lock(lock_text, extensions)
        sources = [Path(jbig['archive']), *self.extension_inputs(extensions)]
        context = self.output / 'private-layer-context'; context.mkdir(mode=0o700)
        for number, path in enumerate(sources): copy_regular(path, context / ('input-' + str(number) + '.pkg.tar'), 64 * 1024**2, deadline=self.deadline)
        tag = 'cachy-private-project-libraries:' + self.nonce
        query = self.docker(['image', 'ls', '--filter', 'reference=' + tag, '--format', '{{.ID}}'], 'layer-precheck')
        require(read_regular(query, deadline=self.deadline).strip() == b'', 'library-layer-tag-not-fresh')
        self.layer = {'tag': tag, 'base': self.controller.image, 'id': None, 'build_completed': False}
        paths = ' '.join('/private/input-' + str(n) + '.pkg.tar' for n in range(len(sources)))
        dockerfile = ('FROM ' + self.controller.image + '\nLABEL org.cachy.private-project="' + self.nonce + '"\n' +
            'COPY . /private/\nRUN pacman --noconfirm -Rdd jbigkit && pacman --noconfirm -U ' + paths + ' && rm -rf /private\n')
        (context / 'Dockerfile').write_text(dockerfile)
        iid = self.output / 'private-layer.iid'
        self.docker(['build', '--pull=false', '--no-cache', '--force-rm', '--network=none', '--iidfile', str(iid), '-t', tag, str(context)], 'layer-build', timeout=600)
        self.layer['build_completed'] = True
        actual = read_regular(iid, 128, deadline=self.deadline).decode().strip()
        require(IMAGE.fullmatch(actual) and actual != self.controller.image, 'library-layer-image-id-refused')
        self.layer['id'] = actual
        observed = read_json(self.docker(['image', 'inspect', tag, '--format', '{"id":{{json .Id}},"arch":{{json .Architecture}},"os":{{json .Os}},"labels":{{json .Config.Labels}}}'], 'layer-inspect'), deadline=self.deadline)
        require(observed.get('id') == actual and observed.get('arch') == 'arm64' and observed.get('os') == 'linux' and
                observed.get('labels', {}).get('org.cachy.private-project') == self.nonce, 'library-layer-identity-refused')
        name = 'cachy-project-lock-' + self.nonce
        self.containers[name] = {'image': actual, 'labels': {'org.cachy.private-project': self.nonce}}
        log = self.docker(['run', '--rm', '--name', name, '--pull=never', '--network', 'none', '--read-only', '--cap-drop=ALL',
                          '--label', 'org.cachy.private-project=' + self.nonce, '--entrypoint', '/usr/bin/pacman', actual, '-Q'], 'layer-package-lock')
        observed_lock = read_regular(log, deadline=self.deadline).decode('utf-8')
        require(''.join(sorted(observed_lock.splitlines(keepends=True))) == wanted, 'library-layer-inventory-drift')
        dependency_name = 'cachy-project-dependencies-' + self.nonce
        self.containers[dependency_name] = {'image':actual, 'labels':{'org.cachy.private-project':self.nonce}}
        self.docker(['run', '--rm', '--name', dependency_name, '--pull=never', '--network', 'none', '--read-only', '--cap-drop=ALL',
                     '--label', 'org.cachy.private-project=' + self.nonce, '--entrypoint', '/usr/bin/pacman', actual, '-Dk'],
                    'layer-package-dependencies')
        lock = self.output / 'private-layer-packages.lock'; lock.write_text(wanted)
        return actual, lock

    def cleanup(self):
        errors = []
        # Build.py writes the exact random name/argv before Docker submission.
        for key in PACKAGES:
            for number in (1, 2):
                path = self.output / (key + '-attempt-' + str(number)) / 'provenance.json'
                if path.exists() or path.is_symlink():
                    try:
                        record = read_json(path, deadline=self.deadline); name = record.get('clean_environment_id')
                        if name is not None:
                            require(re.fullmatch('cachy-asahi-[0-9a-f]{16}', name) and record['command'][record['command'].index('--name') + 1] == name and
                                    record['command'][-2] == record['image_id'], 'library-build-container-owner-refused')
                            self.containers[name] = {'image': record['image_id'], 'labels': None}
                    except BaseException as error: errors.append(type(error).__name__)
        for name, owner in self.containers.items():
            try:
                before = self.docker(['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'], 'cleanup-list', cleanup=True)
                if not read_regular(before, deadline=self.deadline).strip(): continue
                value = read_json(self.docker(['container', 'inspect', name, '--format', '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"labels":{{json .Config.Labels}}}'], 'cleanup-inspect', cleanup=True), deadline=self.deadline)
                require(value.get('name') == '/' + name and value.get('image') == owner['image'] and
                        re.fullmatch('[0-9a-f]{64}', value.get('id', '')) and
                        (owner['labels'] is None or all(value.get('labels', {}).get(k) == v for k, v in owner['labels'].items())), 'library-container-cleanup-owner-refused')
                self.docker(['container', 'rm', '-f', value['id']], 'cleanup-remove', cleanup=True)
                after = self.docker(['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'], 'cleanup-absence', cleanup=True)
                require(not read_regular(after, deadline=self.deadline).strip(), 'library-container-remains')
            except BaseException as error: errors.append(type(error).__name__)
        if self.layer is not None:
            if not self.layer['build_completed']:
                errors.append('layer-submission-completion-unknown')
            try:
                listing = self.docker(['image', 'ls', '--filter', 'reference=' + self.layer['tag'], '--format', '{{.ID}}'], 'cleanup-layer-list', cleanup=True)
                if read_regular(listing, deadline=self.deadline).strip():
                    value = read_json(self.docker(['image', 'inspect', self.layer['tag'], '--format', '{"id":{{json .Id}},"labels":{{json .Config.Labels}}}'], 'cleanup-layer-inspect', cleanup=True), deadline=self.deadline)
                    require(IMAGE.fullmatch(value.get('id', '')) and value['id'] != self.controller.image and
                            (self.layer['id'] is None or value['id'] == self.layer['id']) and
                            value.get('labels', {}).get('org.cachy.private-project') == self.nonce, 'library-image-cleanup-owner-refused')
                    self.docker(['image', 'rm', value['id']], 'cleanup-layer-remove', cleanup=True)
                    after = self.docker(['image', 'ls', '--filter', 'reference=' + self.layer['tag'], '--format', '{{.ID}}'], 'cleanup-layer-absence', cleanup=True)
                    require(not read_regular(after, deadline=self.deadline).strip(), 'library-image-remains')
            except BaseException as error: errors.append(type(error).__name__)
        return {'status': 'FAIL' if errors else 'PASS', 'uncertainties': len(errors), 'baseline_image_removed': False}


def execute(ops, contract, baseline, controller, phases):
    """Fixed finite schedule; fake ops exercise the identical business gates."""
    require(contract.get('schema_version') == 1 and contract.get('public_promotion') is False and
            set(contract.get('recipes', {})) == set(PACKAGES), 'library-contract-refused')
    expected_layer_lock(read_regular(Path(baseline['packages_lock']), deadline=ops.deadline).decode(), contract.get('builder_extensions'))
    rows = {}
    for key in PACKAGES:
        if key == 'jbigkit': image, lock = controller.image, Path(baseline['packages_lock'])
        else:
            phases['owned-builder-layer'] = 'RUNNING'
            image, lock = ops.layer_image(rows['jbigkit'][0], baseline, contract['builder_extensions'])
            phases['owned-builder-layer'] = 'PASS'
        rows[key] = []
        for number in (1, 2):
            phase = key + '-build-' + str(number); phases[phase] = 'RUNNING'
            rows[key].append(ops.build(key, number, contract['recipes'][key], image, lock))
            phases[phase] = 'PASS'
        phases[key + '-compare'] = 'RUNNING'
        ops.compare(key, *rows[key])
        phases[key + '-compare'] = 'PASS'
    phases['provider-SONAME-association'] = 'RUNNING'
    for row in rows['libtiff']:
        require('libjbig.so.2.2' in row['libraries']['libtiff.so.6']['needed'] and
                'libtiff.so.6' in row['libraries']['libtiffxx.so.6']['needed'], 'library-provider-SONAME-association-failed')
    phases['provider-SONAME-association'] = 'PASS'
    return rows


def run_libraries(controller, root, output, cache, *, deadline, session, materializer, trusted_gpgv):
    owned, ops, first = None, None, None
    result = {'stage': STAGE, 'status': 'FAIL', 'public': [], 'hardware_validation': 'NOT RUN',
              'public_promotion': False, 'publication_license_acceptance': False,
              'phases': {name: 'NOT RUN' for name in PHASES}}
    try:
        result['phases']['preflight'] = 'RUNNING'
        root, owned, initial = start(controller, root, output, STAGE, deadline=deadline)
        baseline = initial['prerequisite']
        session.original_context(deadline=deadline, controller=controller)
        contract = read_json(root / CONTRACT, deadline=deadline)
        require(contract.get('baseline_inputs_sha256') == 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f', 'library-baseline-contract-refused')
        ops = Operations(controller, root, owned, cache, deadline, session, trusted_gpgv)
        expected_layer_lock(read_regular(Path(baseline['packages_lock']), deadline=deadline).decode(), contract.get('builder_extensions'))
        result['phases']['preflight'] = 'PASS'
        result['phases']['runtime-inputs'] = 'RUNNING'
        ops.prepare(contract, materializer, result['phases'])
        result['phases']['runtime-inputs'] = result['phases']['materialize'] = 'PASS'
        rows = execute(ops, contract, baseline, controller, result['phases'])
        # Private exact post-build provider/source/output association, no bodies in public output.
        result['phases']['private-postbuild-association'] = 'RUNNING'
        save(owned / 'private-provider-source-association.json', {'artifacts': rows, 'baseline': baseline,
             'derived_image': ops.layer['id'], 'publication': 'NOT ACCEPTED'}, deadline=deadline)
        result['artifact_sha256'] = {key: [row['sha256'] for row in pairs] for key, pairs in rows.items()}
        result['phases']['private-postbuild-association'] = 'PASS'
        result['status'] = 'PASS'
    except BaseException as error:
        first = error
        if ops is not None and ops.materialize_failure is not None:
            result['materialize_diagnostic'] = dict(ops.materialize_failure)
        notes = getattr(error, '__notes__', [])
        result['private_failure'] = {'exception_type':type(error).__name__, 'message':str(error),
                                    'notes':notes if type(notes) is list and all(type(n) is str for n in notes) else ['invalid note type']}
        if 'materialize_diagnostic' in result:
            result['private_failure']['materialize_diagnostic'] = dict(result['materialize_diagnostic'])
        secondary = ops.materialize_secondary_control if ops is not None else None
        if secondary is not None:
            result['private_failure']['diagnostic_secondary_control'] = MATERIALIZE_EXCEPTION_TYPES.get(type(secondary),'OTHER')
        for phase, status in result['phases'].items():
            if status == 'RUNNING': result['phases'][phase] = 'FAIL'; result['failed_phase'] = phase
        result.update(status='FAIL', cancelled=isinstance(error, KeyboardInterrupt) or (secondary is not None and not isinstance(secondary, Exception)), error_code='cancelled' if isinstance(error, KeyboardInterrupt) else 'project-library-stage-failed', error_type=type(error).__name__)
        if str(error) in {'library-cmake-extension-not-registered', 'library-extension-not-accepted',
                          'library-extension-cache-pin-refused', 'library-layer-inventory-drift', 'library-command-failed-layer-build'}:
            result['error_code'] = str(error)
    finally:
        if ops is not None:
            errors = []
            result['phases']['cleanup'] = 'RUNNING'
            with defer_cleanup(first, errors) as events:
                result['cleanup'] = ops.cleanup()
            if errors or result['cleanup']['status'] != 'PASS': result['status'] = 'FAIL'
            if first is not None and any('uncertainty' in n for n in result.get('private_failure', {}).get('notes', [])):
                result['cleanup']['uncertainties'] += 1
                result['cleanup']['status'] = result['status'] = 'FAIL'
            result['phases']['cleanup'] = 'FAIL' if errors else result['cleanup']['status']
            if events: result.update(status='FAIL', cancelled=True)
        else: result['cleanup'] = {'status': 'NOT RUN', 'uncertainties': 0}
        if owned is not None:
            # Positive schema only: no build logs, package/source bytes, paths or arbitrary metadata.
            try:
                if 'private_failure' in result:
                    private = result['private_failure']
                    encoded_failure = json.dumps(private, ensure_ascii=True, sort_keys=True).encode()
                    if len(encoded_failure) > 65536:
                        private = {'exception_type':type(first).__name__, 'body_retention':'OVER_CAP_NOT_RETAINED',
                                   'bytes':len(encoded_failure), 'sha256':hashlib.sha256(encoded_failure).hexdigest()}
                    save(owned / 'private-first-cause.json', private, deadline=deadline)
                save(owned / 'private-command-caps.json', {'commands':ops.counter if ops else 0, 'command_limit':128,
                     'per_log_limit_bytes':4194304, 'aggregate_log_ceiling_bytes':536870912,
                     'fetches':ops.fetch_count if ops else 0, 'fetched_bytes':ops.fetch_bytes if ops else 0}, deadline=deadline)
                projection = public_metadata(result)
                validate_public_metadata(projection)
                public = owned / 'adapter-status'; public.mkdir(exist_ok=False)
                save(public / 'result.json', projection, deadline=deadline)
                save(owned / 'result.json', projection, deadline=deadline)
                result = {**projection, 'public':[str(public)]}
            except BaseException as error:
                result.update(status='FAIL', status_persistence='FAIL')
                if first is not None:
                    raise first
                raise
    if first is not None and not isinstance(first, Exception): raise first
    return result
