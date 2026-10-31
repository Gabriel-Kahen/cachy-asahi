# Standalone development client v2

Run `python3 -B scripts/client/client_v2.py --help` for the standalone development CLI. Use `sources --help` for authenticated offline source lookup and optional export, or `build --help` to construct an unsigned development envelope for separate signing.

This entry point supports valid tilde versions such as `1.0~rc1-1` in package identities and filenames. It uses the same existing envelope/source-delivery formats and the exact sibling `scripts/release/source_delivery.py` helper. Signature, namespace, expiry, source association, payload integrity and checkpoint checks remain in force; `sources` never advances a checkpoint. Use a complete source checkout, or the opt-in `cachy-asahi-repository-client-v2` development companion with exact `cachy-asahi-repository-runtime=0.1.0-1`. The companion installs only the additional source at `/usr/share/cachy-asahi/repository-runtime/scripts/client/client_v2.py`; its sibling release helpers remain owned by the unchanged Runtime package. Invoke that path explicitly with Python. This package proposal does not establish native build or installed ALPM acceptance.

`client.py` and `test_client.py` remain the original source boundary used by pinned historical emitters and existing packaged payloads. Selecting v2 is explicit; it does not switch an installer, updater, package payload or CI emitter to v2. Existing callers can continue using v1. No installed, native-build or hardware acceptance is implied.

Run the v2 controls from a complete source checkout:

```sh
python3 -B -Werror::ResourceWarning scripts/client/test_client_v2.py
```

The tests use temporary TEST GPG homes and include genuine signed lookup/export, tamper refusal, unchanged checkpoint behavior, and the original release-stage adapter.
