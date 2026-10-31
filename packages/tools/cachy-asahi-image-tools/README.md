# cachy-asahi-image-tools 0.1.0-1

Original MIT, opt-in development candidate for offline, recipe-bound, policy-signed pristine archive payload ext4 images. It prepares regular image files as an ordinary user. It creates no package database, runs no package transaction, hook or scriptlet, and performs no installation, mount or boot operation. Do not use live host filesystem inputs.

The installed command resolves its complete private runtime from its own prefix. Move the whole bin/, lib/ and share/ prefix together; the checkout and working directory are unnecessary. Only cachy-asahi-policy-signed-payload-ext4-v1 recipes are exposed. All historical modules and the complete 48-leaf intake bundle retain their original bytes and pins. The old exact public two-package route is refused by this adapter. Dormant historical proof-source actors are never dispatched by the supported signed route.

```
cachy-asahi-image-tools plan --recipe /absolute/recipe.json --recipe-sha256 SHA256
cachy-asahi-image-tools assemble --recipe /absolute/recipe.json --recipe-sha256 SHA256 --output /absolute/fresh-output
cachy-asahi-image-tools verify --recipe /absolute/recipe.json --recipe-sha256 SHA256 --output /absolute/completed-output --receipt-sha256 SHA256
cachy-asahi-image-tools resume --recipe /absolute/recipe.json --recipe-sha256 SHA256 --output /absolute/completed-output --receipt-sha256 SHA256
```

Keep the recipe, all five input JSON files and all referenced operands at their pinned absolute paths. Moving the tool prefix does not rebind recipe inputs or native tool paths. Plan checks recipes/source/policy without archive parsing or native actors; native dependency identity is checked during assembly. Assemble requires an absent destination. Preserve an interrupted directory and retry at a fresh destination. Verify/resume require an externally pinned completed parent receipt, recheck the entire artifact ledger and independent raw inode/body readback, and rerun no GPG/filesystem actors. INCOMPLETE outputs refuse. Resume is completed-output verification, not continuation of a partly written image.

Inputs use the existing strict v1 schemas: schema_version=1, signed kind, epoch and inputs {selection,authentication,tool_pins,metadata_pins,root_policy}, each an absolute path/SHA256 reference. Selection contains exact ordinary-file identities, archive/signature sizes and hashes, expected package metadata and approved primary fingerprints. Authentication binds the canonical selection, exact gpg bytes, public keyring/trusted/revoked files, signer/time windows and policy expiry. Every archive receives fresh real signature verification before any payload parser runs. Operator TEST trust does not establish production signing trust or source/license acceptance of payloads. Root policy remains 0755 root:root with empty xattrs and no ACL. Input JSON must be canonical where the original signed intake requires it.

Runtime dependencies: Python >=3.14 (standard library ctypes/_ctypes/lzma), libarchive ABI 3 on Linux LP64, glibc/ldd, e2fsprogs (mke2fs/debugfs/e2fsck), GnuPG gpg. The recipe must retain captured v2 native profiles for actual executable paths, versions, dynamic libraries and Python/ctypes identity. Dependency declarations do not replace these hashes. The existing reserved supervisor is scripts/virtual/owned_process.py, SHA256 83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f; it reserves ownership with WNOWAIT and treats ECHILD as UNKNOWN. No scripts/shared/owned_process.py exists in the source snapshot.

Build: makepkg --nodeps --cleanbuild in this recipe directory (requires ordinary Arch packaging tools). check() runs original actor-free release-image/signed-intake controls plus focused packaging controls. package() copies only the literal file map; there are no hooks, services, scripts, mutable system defaults or post-install operations. Package removal deletes its listed files; user recipes, keys and output directories remain user-owned and must be outside the package prefix. Private staging/removal controls are not ALPM lifecycle acceptance.

Native ARM, installed Asahi, 16K pages, M2 hardware, bootability, performance, production trust and release acceptance remain NOT RUN/unaccepted. Root owns canonical adoption, manifest selection, native dispatch and publication.
