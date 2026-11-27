# SPDX-License-Identifier: MIT
"""Derive the two exact installed probes from the qualified probe source."""

import hashlib


PREDECESSOR_SHA256 = 'a63de05cbd02af8c59849353dc73eaac7389a28c54c912b6bd7845fd62f29354'
CORE_STEPS = ('cache-init', 'import-local', 'cache-verify', 'recipe-check',
              'preflight-baseline', 'preflight-lto')
CONSISTENCY_STEPS = ('consistency-match', 'consistency-mismatch', 'consistency-unsupported')
PROFILES = {'0.1.1-2': (False, 11), '0.2.0-2': (True, 12)}


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f'expected one probe source anchor: {old!r}')
    return source.replace(old, new, 1)


def remove_section(source, start, end, replacement=''):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError(f'expected exact probe section anchors: {start!r}, {end!r}')
    first, last = source.index(start), source.index(end)
    if last <= first:
        raise ValueError(f'probe section bounds out of order: {start!r}, {end!r}')
    return source[:first] + replacement + source[last:]


def adapt_probe(raw: bytes, spec: dict) -> bytes:
    """Keep the qualified probe's checks and specialize its release namespace."""
    if hashlib.sha256(raw).hexdigest() != PREDECESSOR_SHA256:
        raise ValueError('qualified installed probe digest differs')
    version = spec['version']
    consistency, payload_count = PROFILES[version]
    if spec['consistency'] is not consistency or spec['payload_count'] != payload_count:
        raise ValueError(f'installed probe profile differs for {version}')

    source = replace_once(raw.decode('utf-8'), "VERSION='0.2.0-1'", f'VERSION={version!r}')
    source = replace_once(source, "prefix=cli.parents[2];expected=policy['recipe']['payload_files']",
                          "need(policy['recipe']['version']==VERSION,'exact installed probe version')\n"
                          "    prefix=cli.parents[2];expected=policy['recipe']['payload_files']")
    if not consistency:
        old_steps = 'STEPS=(' + ','.join(map(repr, CORE_STEPS + CONSISTENCY_STEPS)) + ')'
        source = replace_once(source, old_steps, f'STEPS={CORE_STEPS!r}')
        source = replace_once(source, 'Six installed offline commands with nine caller-owned observations',
                              'Five installed offline commands with six caller-owned observations')
        source = remove_section(source, 'MATCH_RECIPE=', '\n\ndef need')
        source = remove_section(source, '    for case,code in(', '    need(tuple(r[0]for r in rows)')
        source = replace_once(source, 'exact nine-observation grammar', 'exact six-observation grammar')
        source = remove_section(source, "    else:\n        case=key[len('consistency-'):]", '    return value',
                                "    else:\n        need(False,'unexpected installed probe observation')\n")
        source = replace_once(source, 'every exact12 installed/moved payload byte/mode',
                              'every exact11 installed/moved payload byte/mode')
        source = replace_once(source, "need(len(expected)==12,'exact12 package payload');return dict(files=12,payload=expected)",
                              "need(len(expected)==11,'exact11 package payload');return dict(files=11,payload=expected)")
        source = remove_section(source, "    for case in('match','mismatch','unsupported'):", '    records=[]')
        source = replace_once(source, 'controls=9,commands_covered=6', 'controls=6,commands_covered=5')
    return source.encode('utf-8')
