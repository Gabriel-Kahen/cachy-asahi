# Recover the frozen Qt signature offline

The retained public repository database also contains the exact missing Qt-base
detached signature in its `%PGPSIG%` field. Recover that DATA offline with:

```sh
python3 -I -B scripts/port/arm-rust-toolchain-inputs/recover_qt_signature.py \
  --database /retained/target-metadata-20261012/extra.db \
  --output /private/new-recovered-qt-signature
python3 -I -B -Werror::ResourceWarning \
  scripts/port/arm-rust-toolchain-inputs/test_recover_qt_signature.py
```

The output's existing parent must be owned by the caller with mode0700. Recovery
checks the frozen database and exact description-member hashes, package/version/
architecture, archive descriptor, declared license list and decoded signature
hash. It writes only the 566-byte signature and a held DATA receipt, using private
modes. No GPG, network, package payload or installer runs. Supply this output as
an additional `catalog.py --cache` directory. The archive remains required:
`qt6-base-6.12.0-2-aarch64.pkg.tar.xz`, 15,176,004 bytes, SHA256
`70f2bbce49fa82dee86074a7c96dcc1e43f54a1f82407bb8d855708932323abd`.
The retained 6.12.0-3 package cannot substitute. Historical missing-input results
remain unchanged; signature recovery supplies neither authentication nor catalog,
native, legal or release acceptance.
