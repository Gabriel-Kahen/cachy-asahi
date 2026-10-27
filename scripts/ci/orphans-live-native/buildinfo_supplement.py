# SPDX-License-Identifier: MIT
"""Pure Setup190 BUILDINFO field join; no acquisition, execution or admission."""
import hashlib
import json
import re

LOCK = 'scripts/ci/maintained-desktop574-inputs.json'
LOCK_SHA256 = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
COUNT = 574


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expected(inputs):
    """Return all574 sorted name-version-arch rows from the pinned source lock.

    `inputs` contains the source reader's `body` bytes map and `base` version
    map. Architecture belongs to each lock row; it is never inferred from a
    package suffix or replaced by a host-wide architecture assumption.
    """
    need(type(inputs) is dict and type(inputs.get('body')) is dict,
         'source body map required')
    raw = inputs['body'].get(LOCK)
    need(type(raw) is bytes and 0 < len(raw) <= 2 * 1024**2,
         'bounded whole source574 lock bytes required')

    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate source lock JSON key')
            result[key] = value
        return result

    lock = json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'finite source lock JSON required'))
    need(type(lock) is dict and type(lock.get('packages')) is list and
         len(lock['packages']) == COUNT, 'whole574 source lock denominator required')
    versions, rendered = {}, []
    for row in lock['packages']:
        need(type(row) is dict, 'ordinary source lock row required')
        name, version, arch = (row.get(k) for k in ('name', 'version', 'arch'))
        need(type(name) is str and re.fullmatch(r'[a-z0-9][a-z0-9@._+\-]{0,255}', name),
             'exact source package name required')
        need(type(version) is str and re.fullmatch(r'[A-Za-z0-9@._+:\-]{1,255}', version),
             'exact source package version required')
        need(type(arch) is str and arch in ('any', 'aarch64'),
             'exact per-entry source architecture required')
        need(name not in versions, 'unique source574 package names required')
        versions[name] = version
        rendered.append(name + '-' + version + '-' + arch)
    base = inputs.get('base')
    need(type(base) is dict and len(base) == COUNT and
         all(type(k) is str and type(v) is str for k, v in base.items()) and
         base == versions, 'whole source574 names and base versions must agree')
    need(sha(raw) == LOCK_SHA256, 'exact pinned Setup190 source574 lock required')
    need(len(set(rendered)) == COUNT, 'unique full source574 BUILDINFO rows required')
    return sorted(rendered)


def verify(build, recipe, inputs):
    """Join parsed BUILDINFO to the exact recipe and all574 source input rows.

    Return finite DATA only. Other package metadata and all native, custody,
    lifecycle and Root acceptance gates remain the caller's responsibility.
    """
    wanted = expected(inputs)
    need(type(recipe) is bytes and 0 < len(recipe) <= 2 * 1024**2,
         'bounded exact source recipe bytes required')
    need(type(build) is dict and build.get('pkgbuild_sha256sum') == [sha(recipe)],
         'actual recipe BUILDINFO hash must agree')
    installed = build.get('installed')
    need(type(installed) is list and len(installed) == COUNT and
         all(type(row) is str and 0 < len(row) <= 1024 for row in installed),
         'whole574 installed BUILDINFO rows required')
    need(len(set(installed)) == COUNT and sorted(installed) == wanted,
         'exact full original574 name-version-arch BUILDINFO join required')
    return dict(status='DATA_EXACT_RECIPE_AND_SOURCE574_BUILDINFO_JOIN',
                installed=COUNT, architectures={'aarch64': 510, 'any': 64},
                source_lock_sha256=LOCK_SHA256, recipe_sha256=sha(recipe),
                installed_sha256=sha(('\n'.join(wanted) + '\n').encode()),
                actual=None, native='NOT_RUN', strict_replay='NOT_RUN', Root_acceptance=None)
