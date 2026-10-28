# Archive intake and spool bridge source proposal — 2026-10-13

The private executable increment at `artifacts/reviews/platform-archive-intake-proposal-20261013/` implements `.pkg.tar.xz` data intake, bounded owned regular-body spooling and streamed output through the pinned assembler's manifest/config policies. The executed lane uses synthetic archive/signature-marker fixtures only. No actual selected package archive, image, GPG, compiler, mount, package installation, boot/platform or system actor ran in this increment. The prior assembler receipt `f9649bbed45f89f5214a318d2214ae70cc5a11d6485354a252cf752168b4465b`, its 191 files and the frozen BLOCKED20 contract remain unchanged.

## Concrete APIs

`intake.inspect_archive(core, row, store, budget)` checks four independently pinned input references: archive, signature, authentication JSON and source-admission JSON, plus the exact package tuple. The raw-captured strict core SHA256 is `3a71ba896700f72130e35a56845516bd9c42de0b1b0fd782b79829b37ac262a7`. Its no-follow reference/open/hash, typed path/node/tuple, counted-decoder and deadline primitives are reused. Mode/UID/GID/size/link count and other source inode identity fields must match the selected references throughout successful intake. Source-file metadata is distinct from archive-declared payload metadata.

The source-admission/authentication schemas are closed, content-hash bound and explicitly `MODELED_NOT_CRYPTOGRAPHIC`, with expected primary `68B3537F39A313B3E574D06777193F152BDBE6A6`. A signature-marker file's custody/hash is checked, but no cryptographic verifier runs. Actual authentication scopes are refused. Signed-metadata expectations here are modeled data: exact name/version/architecture and sorted dependency/provides/conflicts/replaces/license lists, preserving multiplicity. A changed tuple, metadata digest, source-admission binding or signature reference fails; these assertions cannot accept the other 259 packages or 26 signer joins.

The parser handles a single XZ stream with an explicit 64 MiB decoder-memory limit and bounded output quanta. It walks 512-byte tar headers as data, strips one leading `./` and one directory suffix before strict canonical-path validation, rejects normalized duplicates and accepts only regular files, directories, symlinks and hardlinks. Sparse files, device/socket/FIFO types, PAX/GNU extension headers and xattr encodings are refused. Two zero end blocks and zero-only aligned remainder are required; truncation, nonzero remainder and concatenated compressed streams fail. This deliberately restricted parser has not established compatibility with all real ALARM packages.

Regular members stream to `Store.put()` under fixed storage names, never their archive paths. `.PKGINFO` has exact tuple/scalar checks and modeled metadata binding. `.BUILDINFO` is parsed as bounded inert fields with source correspondence still unaccepted. `.MTREE` remains a spooled gzip member; bounded internal decoding produces inert tokens, with semantic/xattr/payload correspondence unaccepted. `.INSTALL` is retained and hashed as data, marked unexecuted and hook closure false. Missing controls are reported. Hardlink chains are checked for cycles and same-package regular targets, then represented by their direct regular root. Full package hooks, install order, licensing and native file-metadata encoding remain separate requirements.

`spool.Store(root, core, budget)` creates a new private 0700 directory under a held parent and writes flat `body-00000001` names. Actual storage files are current UID/GID, 0600, ordinary and single-linked. Closed references contain only storage name, size, SHA256 and the complete selected inode identity. The package's declared UID/GID/mode stay in its node ledger; there is no host chown or package extraction. Files and the named root are checked before use, a hash-verification pass precedes streaming, and the consumed stream's size/hash and still-named metadata are checked afterward. Aliases, replacements, changed permissions, links and content drift fail. Cleanup removes only exactly matching owned references; an obstructing replacement is retained and reported rather than followed or deleted.

`bridge.assemble_streamed(core, assembler, packages, expected, recipes, epoch, destination, store, budget)` keeps body references in its maps and streams files through `Store.lookup()` into the output writer. The assembler source is pinned to `170b60eb8b314f99f883dfd155b918131fb23f7d6b6c6b299d19621c5a60f1d4`. Its two pure SourceManifest assignments are reused from that exact source, as are its tree checks and internally pinned configuration functions. All original package/config ownership, fstab factory preservation, literal recipe preconditions and false acceptance fields remain. The bridge adds its own source/spool identities and semantic intake/control provenance; physical spool names, inode identities and timestamps are excluded from the reproducible manifest.

The bundle retains `rootfs/` payload and separate `metadata/assembly.json`, fixed epoch, explicit declared metadata and deterministic ordering. A file body never becomes a whole in-memory byte value in the bridge; only small pinned config literals use bytes. The old latched writer is reused. Body-reader or cancellation failures are latched before tar cleanup too, so cleanup does not redispatch a failed destination or replace the first writer failure.

## Bounds and actual accounting

| Resource | Source limit / accounting |
| --- | --- |
| Body input/output request | 64 KiB; tar output uses bounded blocks |
| One body / total spooled writes | 512 MiB / 8 GiB |
| Spool logical I/O | 32 GiB total, including write, verification reread and consumed-stream reread; separate cumulative counters |
| XZ decoder dictionary | 64 MiB memlimit |
| Controls / decoded MTREE | 1 MiB raw per control / 16 MiB internal MTREE decode |
| Archive decode | Existing 1 GiB per-archive / 8 GiB aggregate core limits; includes internal MTREE expansion |
| Compressed work | Existing 2 GiB cumulative reservation for two hash passes plus one compressed decode pass; failure debt is retained |
| Semantic metadata | 32 MiB serialized-semantic budget for path/node/control/intake data before bundle encoding |
| Deadline | One shared core budget across intake, spool reads/writes and output; verified owned cleanup may proceed after expiry |

Compressed reservation is labeled `compressed_reserved_work_bytes`, not a measured disk-I/O count. Decoded bytes, spool writes/rereads and output bytes are reported separately; these can charge several payload passes. No counter is reset to hide failed work. Limits are checked before writes or requested reads. Metadata Python containers, transient encoded values and codec/runtime state remain resident. The fixture results prove chunk ceilings and debt accounting, not a total-process RAM bound, physical disk cost, full 4 GiB runtime or performance gain. The unchanged compressed-work cap may need a separately reviewed finite adjustment for a complete real inventory.

The spool uses a held directory descriptor because its own child creation changes directory timestamps. It does not pretend a writable directory retains an immutable full timestamp identity. Descriptor disposal still uses the captured core's primitives; this increment makes no generalized descriptor-generation or asynchronous custody guarantee. New cleanup priority is narrow: an original control keeps identity, a later control supersedes an earlier ordinary business error with that error as its cause, and ordinary cleanup obstructions are recorded. Acquisition/context-exit faults attempt disposal of the duplicated parent descriptor. Unknown/replaced files are never adopted as successful bodies.

## Actual checks

The intake worker passed 30 synthetic-fixture methods; the author spool/bridge suite passed ten methods; independent final controls passed seven methods. Successful final runs had zero skips/PYC. Checks cover exact tuples/metadata/admission references, XZ/tar/gzip truncation and remainder, unsupported types/extensions, hardlinks, multi-chunk bodies, source drift, typed spool references, mode/link/content changes, foreign replacements, duplicate-FD acquisition failure, cleanup cancellation priority, deadline disposal, charged debt and exact first writer failure.

Two fresh spools with independently reconstructed 327,683-byte fixture bodies produced byte-identical bundles and SourceManifests. Rebuilding after a payload change fails all three manifest/digest/bundle comparison fields. A separate full fixture path uses a synthetic XZ archive with `.PKGINFO`, `.BUILDINFO`, gzip `.MTREE`, inert `.INSTALL`, declared UID/GID 123/456 and a hardlink; it traverses the real parser and owned spool into the actual output stream. Serialized headers/bodies retain that declared metadata, while the physical spool remains current UID/GID and 0600. These are staging fixture comparisons, not clean native image builds.

The initial author eight-method run had four errors/two failures at `spool-root-ownership`: it assumed directories have two links, while a directly inspected new fixture directory reports one on this filesystem. `baseline/attempt01/` preserves that source/result and the actual metadata observation. The corrected code binds the observed positive directory link count without a two-link assumption. The intake worker's initial syntax typo and an incomplete expected exception set for malformed gzip remain in its notes. Independent attempt01 also remains: it expected readiness exit 20, but the bridge correctly returns exit 0 with BLOCKED20; the intake refusal CLI returns exit 20. No source policy was weakened to hide these failed fixtures.

Readiness still dispatches no archive intake:

```sh
python -I -B -S -Werror::ResourceWarning artifacts/reviews/platform-archive-intake-proposal-20261013/bridge.py --readiness
```

The actual frozen result stays 261 tuples, 259 retained metadata associations, 20 missing identifiers and nine false acceptance flags. Neither fixture signatures nor spool success can fill the real admission gap. Intake's own CLI refuses actual dispatch with exit 20.

## Separate two-package recovery fact

Root's separate recovery receipt `9407330375b60db80180abdbfffdd50bdd811c3269a9e665f8696efb8cbe223e` and actual receipt `53747d29b02c11517d3c330530f9a6de57afcd9575e0c75c8f23f2dbd7fb6b3c` record acquired exact NetworkManager `1.58.1-1 aarch64` and Perl `5.42.2-2 aarch64` archives, each with a fresh valid signature under primary `68B3537F39A313B3E574D06777193F152BDBE6A6`. Their archive SHA256 values are `5f88ab112b7e2aa714ed000dd1db0fe4b972b7f91f1450ece1481bc7c3207093` and `21c8efe3c10c0c12b8a9b1bb504e71a834f1685916a78da61f71d31e61125161` respectively.

Only those JSON receipts were read/copied here, under `recovery-status/`; no archive, signature or certificate bytes were read and no verification was repeated. Independent key-owner trust, signed-database association, all-261 acceptance and image/install/hardware acceptance remain false in that receipt. It does not rebind the frozen index, authenticate the remaining 259 inputs/26 joins, close source/build/license/hook facts or admit actual intake into this increment's modeled schema.

The next actual lane needs a separately Root-bound source/authentication projection for exact archive/signature/metadata inputs and complete inventory closure, plus compatibility decisions for currently refused archive extensions. Package database/libalpm/hooks/sysusers, remaining config recipes, native ext4/ESP encoding and two clean real image comparisons are still unfinished. Asahi boot, firmware, exact-machine installation/recovery, native runtime resource checks and performance remain distinct gates. No opaque image is imported or relabeled; f964 and the prior strict/observer evidence remain frozen.
