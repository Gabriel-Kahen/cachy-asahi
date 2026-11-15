# Separate ARM111 seat/policy metadata proposals

These DATA proposals preserve all 111 reference versions. They do not select a
production networking stack, install packages, enable services or manufacture a
Polkit action. The old 145-addition UI result and its missing Xvfb pin are unchanged.

| Proposal | Additions / final | Actual libalpm 16.0.1 result |
| --- | ---: | --- |
| Python / python-gobject / Polkit / NetworkManager, no explicit libxtables provider | 37 / 148 | HOLD: iproute2 requires libxtables.so=12-64; iptables/iptables-legacy ambiguous |
| Same four roots plus explicit official iptables | 44 / 155 | PASS metadata preparation, 662 satisfier relations |
| Original UI roots plus NM and explicit official iptables | 172 / 283 | PASS metadata preparation, 1,319 satisfier relations; old Xvfb archive still missing |

The proposed `iptables 1:1.8.13-1` provider is explicit, not an implicit resolver
choice or baseline change. Both passing preparations have zero errors, removals,
conflicts and questions. They retain the original graph's six unrelated malformed
catalog rows and inherited direct-name/provider ambiguity diagnostics separately.
No old resolver or libalpm ABI guard was changed. Every candidate archive identity
comes from actual pinned catalog metadata; none is a fabricated archive hash.

The minimal profile uses Python 3.14.8-1, python-gobject 3.58.1-1, Polkit 127-3,
NetworkManager 1.58.1-2 and the explicit provider. It needs no GTK, Xvfb or project
UI package. Its 44 archives total 31,146,616 bytes plus 24,904 signature bytes;
all have retained observations. That is availability/metadata evidence, not 44
new cryptographic authentications. The UI+NM proposal adds 27 identities to the
old 145: 14,758,184 archive bytes plus exact per-object signature pins. The full
27-name/version/architecture/size/hash list and expected signer policy are in
[actual-results.json](actual-results.json). Expected primary signer is
`68B3537F39A313B3E574D06777193F152BDBE6A6`; pending signers are not called verified.

## Reproduce only metadata preparation

Requires the existing exact libalpm 16.0.1/Python 3.14 environment and retained
input paths. Each output must be new; exit 2 denotes a held proposal.

```sh
python -I -B scripts/port/arm16k-first-login-ui-inputs/seat_proposals/propose.py \
  --proposal minimal-seat --libxtables-provider iptables --output /tmp/new-minimal-seat
python -I -B scripts/port/arm16k-first-login-ui-inputs/seat_proposals/propose.py \
  --proposal ui-with-NM --libxtables-provider iptables --output /tmp/new-ui-NM
python -I -B -m unittest discover \
  -s scripts/port/arm16k-first-login-ui-inputs/seat_proposals -p 'test_*.py' -v
```

The adapter verifies the original baseline/prepared111 join and existing engine
pins, reuses the original conservative graph, then the existing bounded genuine
libalpm child. It inherits the parent adapter's phased 256 MiB address-space
budget. No commit/upgrade/download/scriptlet/hook or target process is invoked.
Future real installation must retain ordinary trusted ALPM and normal hooks.

Actual fresh reports (full SHA256/size pins are committed in actual-results):

- `/tmp/cachy-asahi-arm16k-minimal-seat-iptables-proposal-20261115-v2/proposal.json`
- `/tmp/cachy-asahi-arm16k-ui-NM-iptables-proposal-20261115-v2/proposal.json`
- Original failing bare-four-roots report:
  `/tmp/cachy-asahi-arm16k-minimal-seat-proposal-20261115/proposal.json`

## Actual ARM policy provenance

`policy_audit.py` independently checked the retained ARM NetworkManager archive:
3,635,024 bytes, SHA256
`f33cae0f6f19f33eea879cec1db3fe7c90d0b80931e8f5b67b9391adf7185754`.
Its 566-byte detached signature matches the catalog pin and real host gpgv's
expected primary. Verification uses an empty private home and exact retained
public keyring, with no import, agent or trust mutation.

The actual archive's
`usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy` is 188,810 bytes,
SHA256 `6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446`:
**byte-identical to the supplied x86 source policy**, not inferred from name.
It contains 17 actions. The real `settings.modify.own` defaults are
`allow_any=auth_self_keep`, `allow_inactive=yes`, `allow_active=yes`.
No file was installed or altered to obtain these defaults.

The report is
`/tmp/cachy-asahi-arm16k-minimal-seat-NM-policy-20261115/policy-audit.json`.
This closes that package/policy byte correspondence only. The other 43 minimal
inputs were not newly authenticated by this one-package audit. All ELF16K,
transitive ABI/namespace, file ownership/hooks, corresponding source/license,
current key freshness and real session/authentication checks remain held.
The minimal155 manifest can be independently audited for Root's ARM virtio-seat
fixture without waiting for Xvfb; no guest/daemon/build/native/M2/release result
follows from metadata preparation or the policy's text.
