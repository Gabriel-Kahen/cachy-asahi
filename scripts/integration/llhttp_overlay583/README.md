# Installed llhttp on generic ARM16K Overlay583

The optional `--llhttp` mode uses the existing offline Overlay583 controller,
trusted repository staging, QEMU TCG boot, guest-only pacman keyring, and
evidence retirement. It is exclusive with removal/reinstall, signature
recovery, the Setup predecessor upgrade, and first-login. A successful run
covers installed library behavior in an emulated AArch64 guest with 16 KiB pages.
It leaves Root acceptance, Asahi installation and M2 checks separate.

The guest installs exactly `cachy-asahi-llhttp-reference 9.3.1-1` using the
normal `Required TrustedOnly` policy and the selected dedicated TEST key. Its
installed Python resolves `libllhttp.so.9.3` through the standard loader.
The probe opens the archive-pinned library, confirms the mapped file and
installed hash, and checks a split POST request, an invalid content length,
and EOF on an incomplete body. The parser initialization ABI is pinned to
the exact 9.3.1 header. The two `llhttp_alloc` and `llhttp_free` declarations
are absent from the observed ARM library's dynamic symbol table. The probe
uses `llhttp_init` and `llhttp_settings_init`.

Pacman verifies the exact 583→584→583 inventories. Before install and after
removal a separate fresh process must fail to load the SONAME, and all eight
package-owned file or symlink paths must be absent. While installed, the
package database must own the exact payload and paths, and the guest compares
the installed bytes, modes, and both symlink targets with the selected
archive. The base ALPM database snapshot must restore byte-for-byte after
removal, including the existing file ownership and install reason metadata.
The guest returns a bounded original command ledger and the three loader receipts
on the existing evidence disk. The owner independently reopens the raw
pacman, GnuPG and loader outputs after guest retirement.

## Required inputs

Obtain two physically distinct retained exports of the same qualified native
AArch64 package from two clean builds of the reviewed native Source. Both
whole archives must be byte-identical, both makepkg checks must pass, and the
pair must have an independently closed Root receipt with structural 16 KiB
compatibility. The staging program caps and reads both original archives,
admits only their common whole-file pin, and keeps one read-only archive for
the guest.

Root supplies a canonical JSON qualification with these fields.

- `kind` is `ROOT_LLHTTP_REFERENCE_NATIVE_PAIR_FOR_DISPOSABLE_LIFECYCLE_V1`.
- `issuer` is `Root`, `status` is `PASS`, `architecture` is `aarch64`,
  and `structural_page_size` is `16384`.
- `source` is the reviewed 40-hex Source commit and `run` is the actual
  positive workflow run ID.
- `closure` gives the independently closed pair receipt's `bytes` and
  `sha256`.
- `builds` contains two rows ordered by `build` 1 then 2. Each row contains
  `checks` set to `PASS`, `clean` set to true, and
  `archive` with matching `bytes` and `sha256`.

The test signature must cover those exact original archive bytes. Supply only
the fresh detached signature and one binary public TEST certificate with a
signer UID containing TEST, no subkeys, and a finite lifetime of up to seven
days. The signer must have over one hour of remaining validity at bind and be
distinct from the three existing Overlay583 signers. Staging verifies the
public certificate shape and detached signature without configuring host
trust or reading a signing key.

## Prepare and bind

```sh
python3 -I -B scripts/integration/llhttp_overlay583/operands.py \
  --staging "$staging" --preflight "$preflight" \
  --archive "$build_1" --matching-archive "$build_2" \
  --qualification "$qualification" --qualification-sha256 "$qualification_sha256" \
  --signature "$test_signature" --public-key "$test_public_key" --output "$supplement"
```

In the existing qualified controller tool image, mount the supplement
read-only alongside the standard staging, receipt and boot operands. Use the
external whole `supplement.json` digest and a fresh nonce and output path.

```sh
python3 -I -B scripts/install/overlay583_trial/controller.py bind \
  --staging "$staging" --preflight "$preflight" --kernel "$kernel" \
  --config "$kernel_config" --baseline "$baseline" --output "$output" --nonce "$nonce" \
  --llhttp "$supplement" --llhttp-sha256 "$supplement_sha256"

python3 -I -B scripts/install/overlay583_trial/controller.py run \
  --authority "$root_issued_selection" --authority-sha256 "$root_issued_selection_sha256"
```

The bind operation is passive. The run requires separate Root issuance and
the normal offline actor boundaries. The optional mode keeps the same memory,
storage and time envelope as the verified base install. If the guest produces
a hold receipt, the controller retains its original evidence and scratch disk.

## Source and fixture checks

The retained hosted R124 build is an actual 30,828-byte single archive, SHA-256
`7fe05d7bfaf4545c7ae225dc75441ad0edaab493e7bb90bd47062864a84368a2`.
It demonstrated native GCC and makepkg/check with an AArch64 ELF and structural
16 KiB segment alignment. The original closure records the unresolved provides gate
and the absence of a native pair. The focused tests use its bytes only for
read-only static planning and fenced transactions. They issue no authority and
run no VM, pacman operation, or native library process.

```sh
CAA_R124_EVIDENCE_DIR="$r124_public_evidence_dir" \
  python3 -I -B scripts/integration/llhttp_overlay583/test_lifecycle.py
```
