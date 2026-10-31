# Source-defined TPM default ACL

This source-derived conclusion is joined to Root-qualified failure DATA. It
does not issue new native acceptance. Source40 is exactly
536f96af5451697da2467e2e45e3129f32eed6d8, codex/core7-xattr-diagnostic-v1,
native run40170492959. The report has no top-level nonce; the genuine source
proof consumer_token equals report.wallclock.nonce. Root corrected the
passive report projection and qualified it exit0 in61.500571852s/300. The
exact corrected56 failure DATA/post-pins/status are pinned author inputs;
automatic hooks/two-boot success and native attribute acceptance remain unissued.

The genuine phase1-before graph has directory var/lib/tpm2-tss/system/keystore,
mode02775, uid972/gid972. Its TPM tmpfiles file is1441B,
a3c6fb9822f4a1f14ced8e17dd06eea0ee90bb63aaeeab31146dd1969990230e.
The local installed declaration has exactly those bytes. Its source4.2.0
upstream template expands @localstatedir@=/var and @runstatedir@=/run to
identical complete bytes. It declares d2775 tss:tss and the default group ACL.
The /run rule and /sys z- rules remain inside original runtime graph boundaries;
this successor grants no new boundary or path-prefix exemption.

[TPM4.2.0 declaration](https://raw.githubusercontent.com/tpm2-software/tpm2-tss/4.2.0/dist/tmpfiles.d/tpm2-tss-fapi.conf.in)
is pinned in primary-pins.json by exact URL, tag and SHA256. The genuine graph's
90B sysusers declaration54504ded... is also byte-identical to local installed
DATA. The upstream tag's sysusers line is u; the pinned installed line is u!.
This difference is recorded, not silently normalized. No claim is made that
local x86 package4.2.0-2.1 equals native package4.2.0-2. Only those exact files
match the genuine original graph. Runtime reads both complete source files
and complete passwd/group descriptors, joins their node hashes and requires
tss UID/GID972. No NSS lookup or host account value supplies runtime authority.

[Linux6.12 UAPI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/posix_acl_xattr.h)
sets version2, little-endian header32, then tag16/permission16/id32 entries;
[Linux validator](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/posix_acl.c)
checks tag order, permission bits and named-user/group mask. Local Linux API
headers7.1-1 are independently copied and pinned; their ACL layout matches.
The implementation is original Python from this documented wire layout; no
Linux GPL implementation is copied into successor source.

[systemd v257 ACL helper](https://raw.githubusercontent.com/systemd/systemd/v257/src/shared/acl-util.c)
shows default ACL parsing, adding base owner/group/other entries from the mode,
and calculating a group mask. It is corroborating source DATA (LGPL2.1+), not
an assertion that it equals native systemd262 or an executed runtime proof.

The exact declared vector is (tag,permissions,id):
(1,7,FFFFFFFF), (4,7,FFFFFFFF), (8,7,972), (16,7,FFFFFFFF),
(32,5,FFFFFFFF). Its44B SHA256 is
371f93a94c93284aeefacd8d3b58b96aff4d4d11e1eb750b460afbf756d0f576,
exactly the retained diagnostic. This was derived from public declaration,
mode and genuine node gid, not guessed from private attribute contents.

[TPM REUSE annotations](https://raw.githubusercontent.com/tpm2-software/tpm2-tss/4.2.0/REUSE.toml)
assign BSD-2-Clause:2020 Jonas Witschel,2022 Erik Larsson,2023 Dan De Meyer
for tmpfiles;2020 Jonas Witschel for sysusers. Exact notices and full upstream
BSD license are carried in successor acl_policy.py TPM_NOTICE and preserved
here. Research copies of Linux headers are LGPL2.1+ WITH Linux-syscall-note;
Linux posix_acl.c GPL2.0-only; systemd helper LGPL2.1-or-later. Their copyright
and SPDX notices remain intact. Research code is never loaded into a guest.
