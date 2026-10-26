# SPDX-License-Identifier: MIT
"""Exact two current-boot userspace probes are ANDed with original UART proof."""
import re

def validate(events):
    rows=[e for e in events if e.get('event')=='nomops_userspace']
    if len(rows)!=2 or [e['role']for e in rows]!=['root','user']:raise ValueError('two ordered actual root/user NOMOPS probes')
    boot=rows[0]['boot_id']
    if not re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',boot):raise ValueError('actual Linux boot epoch')
    for e,uid in zip(rows,(0,23001)):
        v=e['probe']
        if e['boot_id']!=boot or e['uid']!=uid or v['uid']!=uid or v['page_size']!=16384 or v['schema_version']!=1 or type(v['hwcap2'])is not int or not 0<=v['hwcap2']<2**64 or v['mops_mask']!=1<<43 or v['mops']is not False or v['hwcap2']&(1<<43):raise ValueError('actual sameepoch userspace HWCAP2_MOPS must be zero')
    return dict(status='PASS_SAME_EPOCH_ROOT_AND_USER_HWCAP2_MOPS_ZERO',boot_id=boot,probes=rows,actual_acceptance='REQUIRES_COMPLETE_NEW_PAIR_AND_ROOT')
