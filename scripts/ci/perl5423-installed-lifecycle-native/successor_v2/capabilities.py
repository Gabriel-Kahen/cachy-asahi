# SPDX-License-Identifier: MIT
"""Exact source edit for Docker's known capability-name serialization."""
OLD = b"set(host['CapAdd']) == set(domain['cap_add'])"
NEW = b"capability_names(host['CapAdd']) == capability_names(domain['cap_add'])"
HELPER = b'''def capability_names(values):
    known = {'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID', 'SETFCAP', 'SYS_CHROOT'}
    C.need(type(values) is list and len(values) == 7
           and all(type(value) is str for value in values), 'exact seven capability strings')
    C.need(len(set(values)) == 7, 'unique raw capability names')
    names = [value[4:] if value.startswith('CAP_') else value for value in values]
    C.need(len(set(names)) == 7 and set(names) == known,
           'exact unique reviewed capabilities; one optional CAP_ prefix only')
    return set(names)


'''


def patch(body):
    if body.count(OLD) != 1 or b'def capability_names(' in body:
        raise ValueError('exact original producer predicate required')
    marker = b'def inspect(row, a, sha, domain, container_id=None):'
    if body.count(marker) != 1:
        raise ValueError('exact original inspect entry required')
    return body.replace(marker, HELPER + marker).replace(OLD, NEW)


def inverse(body):
    if body.count(HELPER) != 1 or body.count(NEW) != 1:
        raise ValueError('exact successor producer edit required')
    return body.replace(HELPER, b'').replace(NEW, OLD)
