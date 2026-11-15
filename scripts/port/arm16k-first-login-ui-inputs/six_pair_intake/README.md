# Exact six ARM UI pairs: bounded DATA intake

This explicit adapter covers only the six missing identities in the parent
ARM111 metadata result. The first actual intake is **HOLD**: five archives and
their detached signatures matched all pins and passed real host `gpgv`; the exact
Xvfb archive returned 404. No alternative version, mirror search, signature request
for the unavailable archive, package execution, installation or VM followed.

Run only with a separately authorized finite acquisition budget:

```sh
python -I -B scripts/port/arm16k-first-login-ui-inputs/six_pair_intake/intake.py \
  --acquire-exact-six --output /tmp/new-owned-six-pair-intake
python -I -B -m unittest discover \
  -s scripts/port/arm16k-first-login-ui-inputs/six_pair_intake -p 'test_*.py' -v
```

`inputs.json` binds the original report/catalog, six exact names/versions,
aarch64 architecture, sizes/SHA256, detached signature pins, declared dependency
and license metadata, official source URLs and the retained official public key.
Direct exact-filename cache checks precede acquisition. HTTPS uses system TLS
verification and no ambient proxy, one initial GET per missing object, at most
three allowlisted official redirects preserving the exact path, no retry and no
version fallback. There are at most 12 initial GETs, 12 seconds per request and a
180-second whole-run alarm. Object bodies must match exact pinned sizes; total
response bodies have an additional 8 MiB cap. The receipt reports HTTP body bytes,
not an invented measurement of TLS/framing overhead. No error body is read.
The process has a 256 MiB address-space limit and requires a 2 GiB free reserve
plus the full intake cap before acquisition. Output is a newly owned private tree.

The public key is the retained `archlinuxarm.gpg.binary`, 2,228 bytes, SHA256
`9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae`.
It must equal the in-memory decoded pinned armored certificate. `gpgv` uses only
that exact keyring and a private empty home, with the expected primary signer
`68B3537F39A313B3E574D06777193F152BDBE6A6`. No key import, agent, ownertrust edit
or system trust mutation occurs. Mathematical signature verification does not
establish current revocation/freshness, source correspondence or release trust.

## Actual 2026-11-15 result

Receipt: `/tmp/cachy-asahi-arm16k-ui-six-pair-intake-20261115/receipt.json`,
22,292 bytes, SHA256
`b6ed01047226b0e89d22d0aaa13bcb7becb3e97d43ac6ce2f996db9ac2a55d7b`.
The exact code/descriptor pins and per-object receipts are in
[actual-result.json](actual-result.json). Archive bytes stay in its private
`archives/` directory and are not committed.

| Exact aarch64 identity | Result |
| --- | --- |
| gobject-introspection-runtime 1.86.0-2 | Size/SHA, metadata and signature PASS |
| libgirepository 1.86.0-2 | Size/SHA, metadata and signature PASS |
| libxmu 1.3.1-1 | Size/SHA, metadata and signature PASS |
| python-gobject 3.58.1-1 | Size/SHA, metadata and signature PASS |
| xorg-server-xvfb 21.1.25-1 | Exact official URL HTTP 404; stopped pair |
| xorg-xauth 1.1.5-1 | Size/SHA, metadata and signature PASS |

The five retained archives total 607,244 bytes plus 2,830 signature bytes.
Actual intake used 11 initial GETs, zero redirects and 610,074 response-body bytes
in 3.817 seconds. All five signatures selected the exact expected primary. Every
PKGINFO name/version/architecture, dependency/provides/conflicts/replaces and
license declaration matched the pinned catalog. Source/license correspondence
remains held. Seven focused controls passed; a separate owned one-byte-altered
copy of the newly acquired gobject archive produced actual `gpgv` exit 1/BADSIG,
and its temporary home/copy were retired.

The unavailable archive remains exactly 705,376 bytes, SHA256
`9799e250607b6ebe1b143138fe7cf64366fc94127bb5fbaea6c456c68c2bf715`;
its 566-byte signature SHA256 is
`62b1b083753f451ae512b37ee0478e47db63ef9f6dc10c5ef3e722d0f8ad4958`.
A further independently authorized exact-byte recovery is needed. This result
does not authenticate the other 139 retained observations, prepare an install,
prove ELF16K or dynamic ABI compatibility, or qualify ARM GUI/seat0/M2/release.
