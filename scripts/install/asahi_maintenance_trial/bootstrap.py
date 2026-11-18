# SPDX-License-Identifier: MIT
"""Prepare the specific Asahi-target variant of the verified generic PID 1."""

import re


def project(T, raw, uuid, leaves):
    T.need(re.fullmatch("[a-f0-9-]{36}",uuid) and all(re.fullmatch(r"[a-z][a-z0-9.-]+",leaf) for leaf in leaves),
           "Literal target UUID and result evidence names required")
    text=raw.decode("ascii")

    def replace(before,after):
        nonlocal text
        T.need(text.count(before)==1,"Reviewed generic PID 1 seam changed")
        text=text.replace(before,after)

    replace('scratch=$(/usr/bin/blkid -c /dev/null -L OV583_WORK)',
            'scratch=$(/usr/bin/blkid -c /dev/null -U '+uuid+')')
    replace('mount -n -t ext4 -o rw,nosuid,nodev "$scratch" /trial-scratch\n'
            'mkdir -m 0700 /trial-scratch/work\nmount -n --bind /trial-scratch/work /trial-work',
            'phase=asahi-clone-filesystem\n'
            '/usr/bin/e2fsck -fn "$scratch"\n'
            '/usr/bin/resize2fs "$scratch"\n'
            '[[ $(/usr/bin/blkid -c /dev/null -s UUID -o value "$scratch") == '+uuid+' ]]\n'
            'mount -n -t ext4 -o rw,nosuid,nodev "$scratch" /trial-scratch\n'
            'mount -n -t tmpfs -o mode=0700,nosuid,nodev,noexec,size=128m tmpfs /trial-work')
    replace('/trial-code/trial.py guest "$plan" "$worker"',
            '/trial-code/asahi-guest.py "$plan" "$worker"')
    start='        case "$name" in\n'
    stop='        [[ -f $file && ! -L $file ]] || return 1'
    begin=text.index(start)
    end=text.index(stop,begin)
    allowed='|'.join(sorted(leaves))
    replace(text[begin:end],start+'            '+allowed+') ;;\n            *) return 1 ;;\n        esac\n')
    return text.encode("ascii")
