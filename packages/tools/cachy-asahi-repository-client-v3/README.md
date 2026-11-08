# Maintained development client v3 0.1.0-1

This explicit successor preserves ClientV2's tilde package-version support and adds a final private state-directory identity check before checkpoint application. If --state-dir is replaced, removed, symlinked or loses private owner/mode while verification/cleanup runs, verify --apply refuses before changing the checkpoint. An unchanged directory applies normally. The final check does not prevent later filesystem changes.

Latest proposed user route after package integration:

```
cachy-asahi-repository-client verify --bundle /absolute/bundle --metadata /absolute/envelope.json --signature /absolute/envelope.json.sig --public-keyring /absolute/public.gpg --signer FULL_PRIMARY_FINGERPRINT --namespace dev.example --state-dir /absolute/private-state --minimum-sequence 1 --apply
```

The new launcher selects only the package's client_v3.py. Source checkouts can invoke python3 -I -B scripts/client/client_v3.py directly. Envelope/checkpoint formats, signature/key/namespace/expiry/sequence protections, limits and source lookup semantics remain unchanged; source lookup never changes the checkpoint. This remains a development client with no stable, installation, production trust, native, hardware or release acceptance.

The exact dependency cachy-asahi-repository-runtime=0.1.0-1 retains ownership and bytes of the original client.py, release.py and source_delivery.py. ClientV2, Apps7–15, historical recipes and native Sources are not redirected or requalified. The companion owns only client_v3.py, a new /usr/bin/cachy-asahi-repository-client launcher, three documentation records and two license records. No hooks, services or trust/package operations run during installation/removal. Explicit adoption of this latest command and inventory is a separate Root integration step; installing this unselected development companion does not switch existing callers.

NEW10 tests reproduce the old detached-state application and the new refusal using actual temporary filesystem checkpoint writes with cryptographic/bundle actors mocked. check_source.py checks exact11 source hashes, required dependency and seven declared payload files/modes. test_package.py checks private DATA staging, coexistence and installed-prefix launcher routing without host package installation. PKGBUILD check/package staging in CI is separate from a clean native build or installed ALPM lifecycle.
