# Full587 installation inside a generic ARM VM

[First actual38873658126](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38873658126)
**fails tooling acquisition before VM execution**. Source/workflow is
`7ba73cf1dbf8a396b0dd2598479817db97f1b161`. The producer reaches
READY_SIGNED_INITIAL587/export-completed. Its separate cleanup passes with no
reported failures; borrowed images and source cache remain preserved, and caller
private cleanup passes. No guest, fresh target transaction or VM acceptance is
established.

The retained error is HTTP404. The failed filename was not retained, so the
actual missing input is unknown. Source independently shows that the first
caller fetches21 historical tooling packages despite needing only16 additions.
Its union check also rejects the one snappy overlap: original574 has1.3.1-1,
while the historical tooling row is1.2.2-3. This is a proven prerequisite defect,
not proof that snappy produced this run's404.

The correction preserves every installed574 version, permits that exact known
snappy tuple only on the exact original574 inventory digest, and fetches/verifies
only the16 missing archives, their signatures and public keyring files. The
separate signed587 target remains unchanged. All85 focused controls pass.
[Retry38876211907](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38876211907)
fails before VM at Source/workflow`3ecef815e44c5d6c60f69897ee642e2ee2d92b4d`;
workflow SHA256 is
`17977d48d4a88b2df115fc5a9c5ea70ace96485281b848ce9088247e795db777`.
The unchanged non-cancelling concurrency group starts it after the first trial.

The corrected trial38876211907 reaches signed producer READY, then refuses
`duplicate/nonroot/sparse payload`; producer/private cleanup passes. A passive
hash-verified574-archive header audit finds six legitimate group-owned entries
across dbus, filesystem, polkit and util-linux, with groups81/11/50/102/5. No
batch duplicates or sparse members were found. The first actual member was not
retained. The current single-ID namespace and parent observer cannot preserve
those groups, including an unreadable04110 helper; a separate explicit fixture
mapping/verification adapter is under implementation. Group ownership will not
be flattened to pass the existing root-only route.

The implementation creates a fresh owned target inside an offline generic4KiB
QEMU guest and selects the existing installer isolation barrier, signed package
verification, dependency preparation and preservation checks. Full587 installation,
actual scoped VM retirement, subsequent upgrades and interrupted installation
remain pending. Earlier tiny17 VM acceptance and failed native-container P0
retain their separate results. No Mac partitioning, Asahi boot, physical M2,
production trust or complete M8 journey is accepted by this software lane.

The first run's once-collected log ZIP is3044535 bytes, SHA256
`849c47399e6964b45838d6390c9e35793ff33de4359406c39e0797f95530c3de`.
Only its dedicated full-installer-public frame is decoded:1150 compressed bytes,
SHA256`9f1d7d9072287e763c237d848b84f60f36a56d54e8bdddf318f6f8acb7325dbd`,
containing four declared bounded JSON files. Package archives/cache/private
workspaces are not exported.
