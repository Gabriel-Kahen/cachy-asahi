# Experimental GLib upgrade for the ARM16K UI guest

The [new finite Source](../../scripts/integration/arm16k_first_login_ui_glib290_vm/README.md)
implements an explicit GLib2.90 guest-only successor. It has not been prepared,
installed or booted. The original111 raw, old UI Source/172 manifest, closed
markers/results and protected PAM/systemd/Asahi files remain unchanged at rest.

Root's preceding UI trial installed283 packages and passed all six independent
real-seat checks, then failed to import GTK4.24.1: its library referenced
`g_timeout_source_new_ns`, absent from baseline GLib2.88.3. Actual bounded ELF
DATA found another missing symbol, `g_markup_parse_context_get_attribute_position`.
That closed trial remains HOLD. Its QEMU retired naturally and actual4GiB counters
showed zero OOM events; an earlier SIGKILL's cause remains unmeasured.

The exact original official GLib2.88.3-1 archive/signature was retained in
`artifacts/platform/coordinated-python-20261012-recovery-auth-b/cache/`.
A separate bounded official intake acquired GLib2.90.1-1 and its signature.
Both genuinely verify using public-only gpgv against official primary
68B3537F39A313B3E574D06777193F152BDBE6A6; this grants no current production trust.
Archive/signature sizes, hashes, metadata and six-provider facts are pinned in
`data/glib-materials.json`; no package bytes or private key are committed.

The old six provider files exactly match original-rootfs GLib. New providers keep
all old exported symbols and SONAMEs, and supply all1515 actual GTK strong g_*
imports, including both misses. Both packages'18 ELF files pass static ARM16K
LOAD checks. The new Source recomputes this DATA gate before construction.
Full transitive symbol-version/loader/runtime ABI and corresponding-source/legal
acceptance remain separate holds.

Actual libalpm16.0.1 metadata preparation passes173 targets (172 additions plus
one GLib upgrade),1319 final dependency relations and zero errors/removals/
questions/conflicts. Modeled172 removal plus exact old-GLib downgrade preparation
passes one target and472 relations. An additional Source DATA join checks all
baseline/new relations and checksum-bound original172 ownership shards: new GLib
has no nondirectory collision outside its own original package ownership. Earlier
private proposal attempts missing real repository archive fields are retained as
failures; supplying the exact fields corrected the input without a helper waiver.
These are DATA results, not an actual removal/rollback or VM.

The new operation is `arm16k-first-login-ui-glib290-vm-v1`. It retains111 before,
allows exactly glib2:2.88.3-1→2.90.1-1, reaches283 after, and checks all173 touched
packages' ownership. Following the real GUI/user-edit checks, normal trusted ALPM
removes only the172 additions and installs the exact original signed GLib archive.
Old-GLib ownership, original namespace pins, all111 versions and user edits must
be restored; new-only GLib paths must be absent. Ordinary hooks/signatures,
RTC/current-time, PAM/logind/seat/keyboard, policy,4GiB confinement, durable memory
receipts, normal logout and natural process retirement remain mandatory.

61 fenced controls pass, plus actual retained material/symbol/namespace/dependency
DATA gates and Bash syntax checking. New authority kind/explicit GLib opt-in,
actor filename/Cmd, marker and success status are distinct. Public Source,
materialization, fresh trust/runtime admission and actual guest results remain
null. Root owns any next construction/boot. No native16K, physical hardware/M2,
performance or release acceptance is claimed.


## First GLib290 boot: closed parser HOLD

Root's first trial of this family closed HOLD with JSONDecodeError Extra data
at char10191. Exact UART76105B SHA256
`a37a0673696c226e1b1dbf78f9e6a517e7b1d45d71841bb950c3957d4821290e`
contains a complete10190B seat JSON followed by an actual systemd start-job
console line before SEAT_SESSION_END. The six independent seat checks and283
inventory are present. No UI frame was retained; GTK/removal/rollback/normal
logout are NOT ESTABLISHED. Original report/marker/logs remain closed and unchanged.

The Source successor filters only bounded line-boundary systemd status grammar
for the two known fixture unit descriptions, preserves exact JSON bytes and
invokes the frozen lower seat validator unchanged. Other trailing JSON/text,
unknown ANSI/unit text, duplicate/foreign/truncated/nested frames and interior
injection refuse. The sanitized minimum fixture retains the exact console status
line and private-original hash reference; it contains no credentials/properties.
71 fenced controls pass. Actual closed UART DATA passes the corrected codec and
unchanged validator, without any VM/lease/daemon/actor or acceptance claim. Root
owns fresh Source/publication/admission/preparation and any next trial.
