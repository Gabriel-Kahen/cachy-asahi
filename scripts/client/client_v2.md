# Standalone development client v2

Run `python3 -B scripts/client/client_v2.py --help` for the standalone development CLI. Use `sources --help` for authenticated offline source lookup and optional export, or `build --help` to construct an unsigned development envelope for separate signing.

This entry point supports valid tilde versions such as `1.0~rc1-1` in package identities and filenames. It uses the same existing envelope/source-delivery formats and the exact sibling `scripts/release/source_delivery.py` helper. Signature, namespace, expiry, source association, payload integrity and checkpoint checks remain in force; `sources` never advances a checkpoint. A complete source checkout is required.

`client.py` and `test_client.py` remain the original source boundary used by pinned historical emitters and existing packaged payloads. Selecting v2 is explicit; it does not switch an installer, updater, package payload or CI emitter to v2. Existing callers can continue using v1. No installed, native-build or hardware acceptance is implied.

Run the v2 controls from a complete source checkout:

```sh
python3 -B -Werror::ResourceWarning scripts/client/test_client_v2.py
```

The tests use temporary TEST GPG homes and include genuine signed lookup/export, tamper refusal, unchanged checkpoint behavior, and the original release-stage adapter.
