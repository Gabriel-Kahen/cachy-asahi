# Enrollment 0.2.0-2: preserve frozen comparison consumers

Status: **PASS source controls and host package workflow**, November 14, 2026.
The earlier [0.2.0-1 host build](repository-enrollment-v2-host-20261114.md) remains
unchanged historical evidence. It is not the final revised payload or an ARM,
Asahi, M2, production-trust or release result.

Integration CI identified that extending `scripts/release/compare_releases.py`
changed bytes pinned by three existing native-role configurations. The correction
restores that file exactly from `origin/main`, SHA-256
`27086c7b0af74a1226deae7a6a71245882b82608a1fa9d33b68e657979c7d83c`.
The extended cross-key API lives in the new `compare_releases_v2.py` sibling, and
the new signing-transition code imports that sibling explicitly. Existing frozen
role sources, consumers, configurations and pins were not retargeted.

Source correction commit `f498daa98f7503989415a2a6dd9c423815875c3d` supplies the
new package's finite runtime. The unqualified recipe is now **0.2.0-2**. Its
private archive, payload map, provenance, PKGBUILD checksums and `.SRCINFO` were
updated together. The archive contains exactly eight runtime files totaling
129,321 bytes, with `compare_releases_v2.py` and no legacy comparison copy. The
private source archive SHA-256 is
`caac87988e949acc7155218bcc0f43e3387a16aebe4957b895b276cdf2949655`.
Every archived runtime body was independently joined back to the central source
and its provenance digest. `.SRCINFO` matches `makepkg --printsrcinfo` exactly.

All requested source controls passed:

```text
test_signing_transition.py        14 passed
repository/test_transition.py     13 passed
test_compare_releases.py          29 passed
test_frozen_export_consumers.py    6 passed
```

The transition suite explicitly checks the legacy whole-file digest and the
versioned import. Frozen-consumer controls include all three exact pin closures,
actual selected-API precommit/postcommit acceptance and exporter-drift refusals.

On the same Python 3.14.7 host, an owned temporary copy passed
`makepkg --verifysource` and
`makepkg --nodeps --cleanbuild --force --noconfirm`. The latter retained its
explicit skipped dependency-check warning and installed no missing dependencies.
The full package `check()` passed: actual stage/moved prefix, command help and
version, a real dual-signed synthetic release handoff with zstd package and
declared source associations, source trees hidden, loopback-only networking,
hostile Python environment isolation, unchanged target configuration/keyring,
bad-signature refusal and exact payload-removal inverse preserving foreign data.

The resulting archive is **49,859 bytes**, SHA-256
`92fe2bb9900916131b9d75d559d4b21fda5431c8e161e1e1341ce7b9883349be`.
Its temporary host build path is
`/tmp/cachy-asahi-enrollment-v2r2-build-s3rw8u2h/recipe/cachy-asahi-repository-enrollment-0.2.0-2-any.pkg.tar.zst`.
This is not permanent release retention. Independent archive inspection confirms
version 0.2.0-2, exactly 14 `/usr` payload files and the new comparison sibling.
Extracting the actual archive into another owned directory and invoking relocated
version/configure/rotate/transition help passed.

No production signing, trust distribution, snapshot upgrade, target ALPM
installation/removal, native ARM build, hardware or release acceptance was run.
