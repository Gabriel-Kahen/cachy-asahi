# Independent Perl 5.42.3 ARM16K retained-data reader

This additive reader checks retained evidence for the generic emulated ARM16K
Perl case. It imports only its own locked `joins.py`; controller Source, guest
scripts and artifact code are read as bytes. No raw image, QCOW, archive,
credential, package manager, compiler, Docker, VM, network, quota operation or
lease operation is opened or executed.

The supported branch is explicit: baseline111 without Perl or db5.3, normal
official db5.3 installation, exact native-built Perl `5.42.3-1.3` installation,
ordinary builder/PAM functional probes, removal of Perl and db5.3, and restoration
to111. It checks actual retained inventories111→112→113→111; it does not infer a
rollback branch or admit another dependency. Native pair Source25 and its exact
22,071,176-byte archive remain separate from installed-lifecycle Source445b and
the selected generic16K controller Source.

The reader independently joins complete controller Source and packet
membership/bytes/modes, case certificates, public TEST admission records, native
tuple and installed decision, prepared lineage, readonly baseline provider
receipts, actual pre-ALPM provider receipts, nonce serial/durable frames, ordinary
PAM/logind identity, PL031 epochs, all54 retained installed Perl ELF whole-byte
hashes, AArch64 ELF64 program headers and16K load geometry, DT_NEEDED/interpreter/
GNU version requirements, command-specific functional outputs, exact TCG QEMU
argv, natural command retirement, CID/container settings, cleanup and outer
same-FD/PIDFD/real-NB/close-only custody receipts. It never substitutes the81-row
expected provider projection for installed observations.

Full scope additionally requires the selected normal ALPM and preservation
receipt set named by `joins.RECEIPTS`: complete inventories, raw and normalized
database manifests, payload metadata/hash/xattrs, user metadata/hash/xattrs,
cache snapshots, normal log before/after and four install/remove logs. Only the
explicit `/proc/` live link count is normalized in owned metadata; database bytes
remain exact in this Perl-absent branch. No raw filesystem requalification is
claimed. The reader checks recorded producer readback and Root-selected receipts;
it does not repeat their filesystem or cryptographic observations.

`HOLD_MISSING_BOOT_EVIDENCE` means the complete boot evidence is absent.
`HOLD_MISSING_SELECTED_PRESERVATION_RECEIPTS` means narrower boot consistency
passed but full preservation scope is unavailable. Invalid or failed evidence
produces HOLD with a fixed check name, never an artifact body. A successful
report says only `PASS_PASSIVE_RETAINED_PERL5423_ARM16K_DATA_CONSISTENCY_ONLY`.
Every report keeps issuing authority, decision time, runtime/VM/Root acceptance
NULL. Native16K, M2, external XS, performance and release are not qualified here.

## Root-selected inputs

`request.TEMPLATE.json` and `grant.TEMPLATE.json` are unissued and refuse entry.
Root supplies actual selectors and a fresh exact grant; this family does not
create grants. `source` selects the reviewed controller directory and Source-lock
pin; `packet` selects its exact packet directory and packet pin. `prepared`,
`prepare_report`, `prepare_provider_observation`, `native_pair`, `prepare_outer`,
`boot_outer` and `boot_authority` are ordinary `{path,pin:{bytes,sha256}}` operands.
`boot` and `receipts` select `{directory,files:{relative_name:{bytes,sha256,mode}}}`.
The boot selection must include the Source46 `retained-data-manifest.json`.
Its exact `{schema,nonce,case_packet,Source_lock,files}` joins the selected
Source/case, every retained result, every used receipt, all host0600 modes and
the `preservation.retained_DATA` manifest pin/count/byte totals. The complete
manifest's receipt whitelist and pairwise saved/absent cache selections are
validated even when Root selects only the smaller preservation subset for
reading. Combined results/receipts plus64KiB manifest allowance must fit both
the certified guest-output and log budgets. Unselected public trust logs and
saved cache bodies are not opened by this reader.
The boot whitelist excludes raw images and sockets and reads no directory-wide
payload. `boot`, `boot_outer`, `boot_authority` and `receipts` may be NULL to
record an explicit missing-evidence HOLD. Relative receipt names are selected
within the exported host `receipts/` directory. All manifests and pins refer to
whole bytes; host retained modes are checked separately from guest ELF modes.

Each file is single-link ordinary DATA with no path aliases or group/other write
bits; every source and packet member must exist exactly. Limits are32MiB/file,
256MiB/pass,512 distinct selected files,128 members/tree and60 seconds. All bytes
and file identities are checked again before writing one fresh0600 report.
Root must supervise the operational process under its separately admitted
memory/CPU/time/cancellation/custody envelope. This reader has no lease API.

```sh
python3 -I -B scripts/port/perl5423-arm16k-independent-reader/reader.py \
  --execute-passive-reader \
  --request /absolute/private/request.json --request-sha256 ROOT_SELECTED_SHA256 \
  --grant /absolute/private/grant.json --grant-sha256 ROOT_ISSUED_SHA256 \
  --output /absolute/private/fresh-reader-report.json
```

## Source-local controls

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/port/perl5423-arm16k-independent-reader/test_reader.py
```

All test certificates, inventories, frames, containers, custody and ELF files are
explicit local fiction. They issue no actual Root role or acceptance. The actual
case-r2 boot refused before output/VM entry; no actual reader PASS is recorded by
this implementation. The Source45 preparation pin was7378 bytes SHA256
`1bcea63d6891a87823b90e4014d08c58d55fae32fbedaa6c2ec5fb5d0b06cc76`;
it has no complete host receipt export. The separately reviewed Source46 adds
that export. Later Source/case selectors must be issued separately; this reader
does not retag the original prepared case or claim it booted.
