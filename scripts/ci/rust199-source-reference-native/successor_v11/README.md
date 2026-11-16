# Rust rootfs readable DATA staging successor v11

Actual Source337 run43880777921 reached all three input carriers and native-base
acquisition. Both owned images were created and retired. Public normal-image
bootstrap.json records COMPLETE extraction:95577 members/4513461288 logical bytes,
then EACCES at usr/lib/dbus-daemon-launch-helper. Source337 bootstrap.run evaluates
`tree_digest(rootfs)` after extraction; that regular-file branch reopens every
host DATA file after export modes have already been restored. This is the exact
failing read stage, not an LLVM install/image build/copy failure. The actual file's
mode/owner was not retained and remains UNKNOWN.

An unprivileged MODEL tar uid0/file mode0111 reproduces complete extraction then
PermissionError13 in the old host tree hash. Host files in that model are self-
owned, not privileged/root-owned. It reproduces the failure class only.

The narrow fix changes only hosted/bootstrap.py extract_rootfs/tree_digest and
one hash-result callsite in run. Fresh0700 host DATA staging stays readable until
copying, hardlink materialization and canonical content hashing finish. The hash
uses the exact old path/kind/original-mode/content-SHA256 row format. No chmod
relaxation of existing permissions, image change or new actor is involved.
Original file/directory modes are applied ONCE, deepest first, through a verified
owned ordinary descriptor. Actual mode/inode/owner/link/size/mtime metadata is
verified after each finalization. Staging identity/namespace changes refuse.
The completed extraction hash is returned and used instead of reopening the now
restricted tree. Readable-case digest parity with the original is byte-exact.

The receipt explicitly states
PRIVATE_READABLE_STAGING_BEFORE_EXACT_MODE_FINALIZATION and final_modes_verified.
It does NOT claim a full post-mode host-content rehash or an atomic whole-filesystem
snapshot. Final image permissions/bytes and Dockerfile/install/actor semantics are
unchanged; this private host tree is later historical provenance, not the native
build root. Qualification/build still independently check stage0/LLVM and actual
immutable image identity. No sudo/Root privilege, broad recursive chmod, actor/
capability/resource policy or budget increase is introduced.

Exact parent337:42886171B/tree e9bf6161d48d85838a5a9b9c951b791a34e175c7,
map9a4855f84fb64ffb03e1a3691a57aeff860967890af84ce87b333ce73226f934.
The constructor archives old bootstrap.py and source-map.json under previous-v10/,
adds an unissued rootfs-readable-staging-v11.json and proves the complete337 body/
mode/namespace inverse. All other historical/HTTP/workflow/entry/recipe/policy/
Root template/LLVM/carrier/108-hold bytes remain unchanged. Source340 is42985162B,
tree596fe9277740365fa3e29ee11f2b75ae7ce8bbc8,
map66248B/3974a68677faadf1136f21539b595f3f0da85fa26bd72eb8d0fa8c6e922894f1.
All files are0644. The existing Source entry's whole-map gate binds the new body;
workflow aliases/entry are unchanged. All new actual/Root decision fields areNULL.

```
python3 -I -B -Werror::ResourceWarning scripts/ci/rust199-source-reference-native/successor_v11/test_data.py
python3 -I -B scripts/ci/rust199-source-reference-native/successor_v11/prepare.py \
  --parent /absolute/verified-files-only-Source337 \
  --output /absolute/fresh-private-Source340 \
  --profile-sha256 EXTERNALLY_SELECTED_WHOLE_PROFILE_SHA256
```

The14 fenced controls pass on3.12/3.14: old EACCES reproduction, readable whole-
digest parity, execute-only/zero-mode files, unreadable directory, restricted
hardlink source, exact once-only descriptor modes, content/namespace mutation,
failed-mode verification, cancellation/deadline/truncation/tail/alias/special-node
refusals, unchanged image/install/HTTP/resources, complete337 inverse/current
Source gate/external profile/fresh output and NULL authority. A known self-owned
MODEL directory mode000 is restored only for test cleanup; runtime never relaxes
final modes. Models do not establish actual native success or actual helper mode.

Root alone reviews/publishes/reads back a fresh340, binds a matching once operator,
Reader and actual admissions/resources/runtime/nonce/output and enters a new trial.
Source337/run43880777921 remain immutable and consumed. Existing337 Reader must
refuse340.606minute/8GiB resources and all108 historical holds remain unchanged.
No Root role, actor, network/Original GET, private home/secret/key/GPG, lease,
publication, package execution or grant occurred here. Runtime/M2/performance/
legal/release acceptance remains unfinished; no performance gain is claimed.
