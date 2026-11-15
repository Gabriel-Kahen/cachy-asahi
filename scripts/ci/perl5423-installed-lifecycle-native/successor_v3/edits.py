# SPDX-License-Identifier: MIT
"""Exact actor/producer retention edits; no transaction or resource changes."""
RESULT_PARENT = '/cachy-asahi-perl-lifecycle'
RESULT_PATH = RESULT_PARENT + '/result'
ACTOR_OLD = b"out = Path('/work/result'); out.mkdir(mode=0o700)"
ACTOR_NEW = b"""out = retained_result(Path('/cachy-asahi-perl-lifecycle'), 0, 0)
    report['retained_output'] = dict(parent=str(out.parent), path=str(out), uid=0, gid=0,
        mode=0o700, storage='OWNED_CONTAINER_WRITABLE_LAYER', parent_absent_before_entry=True,
        same_filesystem_as_parent_root=True)"""
PRODUCER_OLD = b"container_id + ':/work/result'"
PRODUCER_NEW = b"container_id + ':/cachy-asahi-perl-lifecycle/result'"
GATE_OLD = b"and actor['cleanup']['failures'] == [], 'complete same-Source successful actual lifecycle')"
GATE_NEW = b"""and actor['cleanup']['failures'] == []
               and actor['retained_output'] == dict(parent='/cachy-asahi-perl-lifecycle',
                   path='/cachy-asahi-perl-lifecycle/result', uid=0, gid=0, mode=0o700,
                   storage='OWNED_CONTAINER_WRITABLE_LAYER', parent_absent_before_entry=True,
                   same_filesystem_as_parent_root=True), 'complete same-Source successful actual lifecycle')"""
HELPER = b'''def retained_result(parent, uid, gid):
    # Native caller supplies the fixed root-level path and exact Root identity.
    C.need(parent.is_absolute() and parent.name == 'cachy-asahi-perl-lifecycle'
           and parent.parent == parent.parent.resolve(), 'ordinary fixed output root name')
    C.need(not os.path.lexists(parent), 'retained output root must be absent before entry')
    parent.mkdir(mode=0o700)  # Atomic refusal if anything appeared after the absence check.
    out = parent / 'result'
    out.mkdir(mode=0o700)
    device = parent.parent.stat().st_dev
    for path in (parent, out):
        info = path.lstat()
        C.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
               and info.st_uid == uid and info.st_gid == gid and info.st_dev == device,
               'private owned result on the containing writable filesystem')
    return out


'''


def actor(body):
    marker = b'def execute(args):'
    if body.count(ACTOR_OLD) != 1 or body.count(marker) != 1 or b'def retained_result(' in body:
        raise ValueError('exact parent actor output definition required')
    return body.replace(marker, HELPER + marker).replace(ACTOR_OLD, ACTOR_NEW)


def producer(body):
    if body.count(PRODUCER_OLD) != 1 or body.count(GATE_OLD) != 1 or PRODUCER_NEW in body:
        raise ValueError('exact parent producer export path required')
    return body.replace(PRODUCER_OLD, PRODUCER_NEW).replace(GATE_OLD, GATE_NEW)


def actor_inverse(body):
    if body.count(HELPER) != 1 or body.count(ACTOR_NEW) != 1:
        raise ValueError('exact retained-output actor required')
    return body.replace(HELPER, b'').replace(ACTOR_NEW, ACTOR_OLD)


def producer_inverse(body):
    if body.count(PRODUCER_NEW) != 1 or body.count(GATE_NEW) != 1:
        raise ValueError('exact retained-output producer required')
    return body.replace(PRODUCER_NEW, PRODUCER_OLD).replace(GATE_NEW, GATE_OLD)
