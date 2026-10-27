# Native fresh GUI TEST signer

This route creates a genuinely new one-day TEST-only signer for six exact
reviewed existing bodies: Welcome7 (legacy role `welcome5`),DNS2,Doctor,Orphans,
and the native/held carrier indexes. The four archive bytes stay unchanged.
`input-contract.json` binds all226/98/7 historical carrier files, exact bodies,
complete package metadata/expected ELF and prior native decisions. Those
decisions retain historical credit only. Existing private signers are retired;
this route never imports or changes them, extends an old certificate, patches
the clock, or alters historical/live GUI authentication.

The fixed plan SHA256 is
`f0160e53afea8d7116f0b7552514f753f6fd95ae2d58d1b30d4d3fe6d5b5ceda`.
Both the six bodies and complete source closure are checked before actors and
again before key generation. The original `sign_fixture.py` mount,capability,
network,device,TEST identity and public-certificate guards are reused unchanged.
Its generic eight-config-archive policy is not applied to these different GUI
inputs; the new finite plan instead requires exact names/versions/architectures,
MIT licenses, all PKGINFO/packaged metadata, no INSTALL and the exact reviewed
Welcome7 AArch64 ELF set. No archive is installed or executed.

The preferred source-built workflow runs on `ubuntu-24.04-arm` and defaults to
**no-key qualification**. Root supplies the exact sourceSHA and reviewed
`provision-plan.json` SHA256
`d62f13c376ea304dd550f44483800ee23326c0d92555fb504fbc8c1847a66b59`.
It acquires only the exact reviewed rootfs, Python/mpdecimal archives,
signatures and public keyring inputs. A scratch image keeps the165 registered
rootfs packages and adds only an explicitly unregistered Python/mpdecimal tool
payload overlay. There is no package install, recipe execution, keyring init,
host GPG, or TEST key generation during qualification. Original input signatures
are checked in a fresh public-only tmpfs home in the image.

The image ID is genuinely produced in the actual job. Its ownership, source,
reviewed build-plan/context/input pins, exact observed tool binaries and package
inventory join the retained production receipt. A caller-provided arbitrary
image ID cannot replace that receipt. No-key mode exports bounded production
and qualification receipts only, then retires the owned image. Explicit `sign`
mode must pass those same production checks first and uses the actual generated
same-job image contract; it requires no guessed or prefilled image identity.

An alternative workflow can use an already reviewed immutable OCI image.
That public image contract must supply:

* schema1,purpose `GUI-FRESH-TEST-SIGNER-IMAGE`, exact workflow `source_sha`;
* fully qualified OCI reference ending `@sha256:<64hex>` and exact expected
  local `image_id=sha256:<64hex>`;
* nonzero alarm UID/GID matching the runner's UID/GID;
* exact SHA256 of the complete sorted `pacman -Q` inventory;
* byte counts and SHA256 for `/usr/bin/python3`,`gpg`,`gpgconf`,`gpg-agent`
  and `pacman`, resolved to root-owned executables in that image.

No actual image identity has been established by local source tests. The
alternative OCI requirements therefore leave unresolved IDs NULL. Do not substitute
a floating tag, x86 image, tool download or latest package install. The route
accepts an explicitly hash-pinned public contract body at dispatch, qualifies
the exact image on real ARM under cap0/read-only/no-network/NNP guards, and
fails closed on any missing identity. Pulling the exact digest is the only
environment acquisition; no host package installation or production credential
is used. An empty owned Docker configuration excludes ambient registry keys.
Existing images are preserved; only the exact newly acquired unused sole-ref
image is eligible for bounded removal.

Private signing state exists only in a fresh0700 home in the first container's
owned tmpfs. The original GPG-home cleanup must succeed before PASS. The key is
new RSA2048, explicit TEST-only nonce UID, current creation time and one-day
expiry. Every detached signature receives real current GPG verification.
A newly generated `catalog.json` is separately labeled as new metadata and
signed; no pre-existing reviewed catalog body was found or invented.

A second fresh container of the same qualified image imports only the public
certificate into a new tmpfs home and independently re-verifies all six original
bodies plus the catalog. Host GPG/keyrings are never used. Both containers have
bounded resources/time, unique names and owned identity/absence cleanup checks.
Input/source/tool/body metadata is rejoined after signing and verification.

Export is allowed only after both container retirements and successful image
cleanup/preservation. It contains one public certificate, six detached input
signatures, the new signed catalog, bounded verification/provenance and a new
versioned index. No old archive body, GPG home, private/revocation key material,
Docker image or workspace is uploaded. Root must independently collect/review
those actual outputs and create new versioned GUI source/input references.
This does not make the old renewal carrier or any historical certificate current.

The alternative OCI workflow inputs are exact sourceSHA, fixed planSHA,
reviewed image contract SHA and its bounded JSON body. The source-built workflow
uses exact sourceSHA, fixed provisioning-plan SHA and explicit qualify/sign mode.
Source and all exact carrier checkouts needed for signing
are checked before image/signing actors. Credentials are disabled, actions are
pinned, concurrency does not cancel another signer, and upload selects only the
closed public directory. The workflow does not install packages or modify live
GUI policies. Local controls use synthetic mocked crypto/Docker only.

Actual ARM qualification, new keys/certificates/signatures, hosted execution,
new public refs, actual GUI runs, generic16K/M2/performance and release acceptance
remain NOT RUN / NOT GRANTED until Root performs the corresponding work.
