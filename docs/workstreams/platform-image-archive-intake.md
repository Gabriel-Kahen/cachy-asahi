# Portable archive intake

`scripts/platform/archive_intake.py` is the checkout entrypoint. It verifies the constant-pinned `archive_intake_bundle.json` and all 48 relative source leaves, then stages them in a fresh owned 0700 directory. Each original 0600/0644 leaf mode is restored there before the preserved engine is compiled. The tracked graph itself uses ordinary Git 100644 files and 0755 directories; the checkout is never chmodded. Held reader, assembler, policy, proof and guard bytes are unchanged. The engine remains SHA256 `57b555b2e93534ab0f38dd2f9f7775e00481ea333a9cc102f8bd517ee68c582d`; the bundle manifest is `8c3838da1bfd6d5e7683d3634ffec9d14a5ff6b07966b15c2b06dde5319c4f0d`.

Keep the entrypoint, manifest, entire `archive_intake_bundle/`, `verify_staging.py` and notice together. The pure tests require only this tracked tree plus Python's standard library:

```sh
python -I -B -S -Werror::ResourceWarning tests/platform/run_pure.py
python -I -B -S -Werror::ResourceWarning tests/platform/check_archive_intake_retained.py
```

The second command reports `NOT_RUN` without explicit local inputs. To actually parse retained archives, pass `--selection`, `--selection-sha256`, `--authentication`, `--authentication-sha256` and a nonexistent `--output` directory. Missing exact archives/signatures also report `NOT_RUN`; changed evidence refuses. No acquisition is performed. Real archive integration is separate from the default pure suite.

Public data API: `with prepared(selection, authentication, spool_parent, seconds=1200) as session: assemble(session, destination, epoch=0)`. The session contains complete selected node maps, regular body spool references, separate authentication envelopes and inert control/hook/config inventories. Spool references expire at context exit. `run()` additionally creates a private output directory and commits its receipt only after spool **and staged runtime** cleanup. It records portable source pins separately from the unchanged engine's serialized manifest. Output is a staging tar, never an image or installation.

The only supported authentication profile remains the exact retained NetworkManager `1.58.1-1 aarch64` and Perl `5.42.2-2 aarch64` historical signature-proof graph. Explicit authentication is required separately from local SHA matches. Code portability does not relocate its historically pinned archive paths or create a generic authenticated261 route. Missing other proof profiles, key-owner trust, source/license closure, generated state, native filesystem/ESP, physical M2 boot/install/recovery and release acceptance remain unfinished. No default test requires ignored artifacts, network, package actors or native tools.

Source guards still require ordinary single-link leaves and the original private directory/leaf modes. Corrupt, symlinked and hardlinked checkout sources refuse. Source/stage cleanup failures prevent successful receipt publication. Control exceptions retain priority over ordinary close failures. Same-UID adversarial concurrent filesystem mutation and crash-consistent parent-directory durability are not proven.

The rootless encoder consumes the assembler's `assembly.json`, **not** its enclosing receipt. Its CLI needs a prepared root directory, complete inode metadata, exact local tool pins and a nonexistent output directory; it does not accept `staging.tar` directly. Its API accepts a regular-body `bytes` map, at most 512 MiB and 20,000 nodes. Intake's 8 GiB/500,000-node bounds do not establish encoder capacity.

Data-only export contract: retain the intake receipt and exact bundle/manifest hashes; expose `manifest.output_nodes`, exact regular bodies, virtual link targets and ownership ledger. A future materializer must use a fresh owned namespace, preserve hardlink topology and never follow package symlinks into host state. It must not invent parents or transform file names. The encoder's mandatory sidecar is exactly `{schema_version:1, complete:true, root:{mode,uid,gid,acl,xattrs}, nodes:{path:{acl,xattrs}}}`, with every output path, null ACLs only and canonical base64 xattrs including capability bytes. Missing rows refuse.

Current bridge status is **BLOCKED_COMPLETE_INODE_METADATA_UNAVAILABLE**. Rejecting archive PAX headers and retaining unaccepted MTREE tokens does not authenticate absence of ACLs, xattrs or capabilities. Do not synthesize empty metadata rows, root metadata or corresponding-source/license acceptance. Root must supply independently bound complete metadata and select any encoder/native dispatch separately. No encoder was executed by this portability work.
