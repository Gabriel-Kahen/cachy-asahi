# SPDX-License-Identifier: MIT
"""Exact predecessor transform: diagnostic observations only, never acceptance."""
import hashlib
import re

PIN = (8662, '565b6373d9feb9d37db048ad175b3f986af9e3bcf6ede413131f1cb05c508c11')
RETURN = re.compile(r'\breturn(?: ([12]))?\b')
STAGES = {7: 'ENTRY', 15: 'INPUTS', 33: 'GLOBAL_OWNERS', 46: 'METADATA',
          84: 'COLLECT', 90: 'STAT_STREAM', 101: 'PARENT_STREAM', 105: 'LINK_STREAM',
          113: 'OWNERSHIP', 120: 'HARDLINKS', 128: 'RECHECK', 135: 'INVENTORY',
          137: 'COMPLETE'}


def instrument(raw):
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PIN:
        raise ValueError('exact immutable installed-metadata predecessor required')
    rows = []; body = []; stages = {1: 'LOAD'}
    for number, line in enumerate(raw.decode().splitlines(keepends=True), 1):
        if number in STAGES:
            stage = len(stages) + 1; stages[stage] = STAGES[number]
            body.append(f' _im_diagnostic STAGE {stage}\n')
        def replace(match):
            ordinal = len(rows) + 1
            code = match.group(1)
            category = 'PREDICATE' if code else 'COMMAND'
            rows.append(dict(ordinal=ordinal, category=category, line=number,
                             original=line.rstrip('\n'), return_code=int(code) if code else 'UNCHANGED'))
            # Save a failing command status before the best-effort observation.
            # The local lives only in this original function's subshell.
            return (f'{{ _im_diagnostic {category} {ordinal};return {code}; }}' if code else
                    f'{{ local _im_diagnostic_rc=$?;_im_diagnostic {category} {ordinal};return "$_im_diagnostic_rc"; }}')
        body.append(RETURN.sub(replace, line))
    allowed = [f'{r["category"]}:{r["ordinal"]}' for r in rows]
    allowed += [f'STAGE:{n}' for n in stages]
    prefix = '''# SPDX-License-Identifier: MIT
# Fixed serial observations only; no pathname, command, value or private body.
# Direct console output is outside every unchanged PASS/HOLD protocol frame.
_im_diagnostic() {
 [[ $# == 2 ]] || return 0
 case "$1:$2" in
  ALLOWED) :;;
  *) return 0;;
 esac
 { builtin printf '\\nPERL5423_INSTALLED_METADATA_DIAGNOSTIC_V1 CATEGORY=%s ORDINAL=%s\\n' "$1" "$2" >> /dev/ttyAMA0; } 2>/dev/null || :
 return 0
}
_im_diagnostic STAGE 1
'''.replace('ALLOWED', '|'.join(allowed))
    return (prefix + ''.join(body)).encode(), dict(predecessor=dict(bytes=PIN[0], sha256=PIN[1]),
                                                 returns=rows, stages=stages)


def inverse(raw, diagnostic, mapping):
    """Review aid: require the complete expected derivative, then return original."""
    generated, expected = instrument(raw)
    if diagnostic != generated or mapping != expected:
        raise ValueError('exact diagnostic-only derivative and complete mapping required')
    return raw
