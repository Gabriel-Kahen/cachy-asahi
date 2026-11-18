# Matching Qt 6.12 native build adapter

The adapter builds GUI server, ShaderTools, SVG, Declarative, then Wayland.
Declarative needs both ShaderTools and SVG. Each component uses two clean
native attempts under the same exact image and inventory. The next stage
requires authenticated packages from the earlier stages.

The baseline is the unchanged 349-package inventory plus seven named additions.
Six addition pairs are available as pinned byte references. A matching signed
md4c >=0.5.3 and <0.6 remains required. The cached 0.6.0-2 fails that constraint.
The 206-package alternative lacks 25 direct dependencies and its transitive
graphics closure has not been established. See `dependency-audit.DATA.json`.

## Prepare and check locally

Copy `source-request.TEMPLATE.json` outside the checkout and fill in the
absolute paths from `family.lock.json`. Use this checkout for the framework
and all five provider roots. The family pins select Main's ShaderTools and
Declarative access-time repair at `3d2b6922`. Supply the five pinned upstream
archives from local storage.

Set `base_provider` to the historical baseline reference with `path`, `bytes`,
and `sha256`, and `candidate_map` to the six-addition candidate map path.
Leave `md4c` null until its archive, signature, and metadata are independently
selected. Source preparation can verify and stage the inputs with md4c pending.

```sh
adapter=scripts/ci/qt612-complete-family-native-source
request_sha=$(sha256sum "$REQUEST" | cut -d ' ' -f1)
python3 -I -B "$adapter/source.py" --request "$REQUEST" --request-sha256 "$request_sha" --output "$SOURCE_OUT"
python3 -I -B -Werror::ResourceWarning -m unittest discover -s "$adapter" -p 'test_*.py'
```

Use a fresh absolute `SOURCE_OUT` outside all input checkouts.
`source.prepare_cache` accepts that Source directory, its returned map SHA-256,
and a fresh output directory for the five reviewed offline archives. The
passive tests use inert fixtures and require no package tooling or archives.

For the project-built `md4c-0.5.3-1-aarch64.pkg.tar.xz` provider, pass the
independently selected exact byte counts and SHA-256s for the archive and its
detached signature:

```sh
python3 -I -B scripts/ci/qt612-complete-family-native-source/md4c_handoff.py \
  --archive "$ARCHIVE" --archive-bytes "$ARCHIVE_BYTES" --archive-sha256 "$ARCHIVE_SHA256" \
  --signature "$SIGNATURE" --signature-bytes "$SIGNATURE_BYTES" --signature-sha256 "$SIGNATURE_SHA256"
```

Use the JSON object on stdout as `md4c` in the family request, or as the
`--md4c-json` document for the reference producer with its whole SHA-256.
The helper binds byte pins, package identity, and the frozen `glibc` dependency.
Native pair qualification and detached-signature authentication remain Root inputs.

Set `consumer_root` to this checkout to include the desktop consumer. Its
interface binds all five pinned provider commits, including the repaired
ShaderTools and Declarative readers. The lock also binds the consumer's whole
file set. Earlier staged Source directories retain their original locks.

Once md4c is available, `pipeline.builder_image_plan` reopens the selected
dependency and preceding provider pairs and emits the normal signed package
transactions plus the complete expected inventory. Root's image builder
supplies the authenticated 349 image, trust configuration and signature
verification. `pipeline.stage_commands` checks every installed package row
against the unchanged baseline and ordered family providers. It emits both
builder invocations and the unchanged comparator argv.

For the installed family, select `desktop_consumer` in `builder_image_plan`.
Its predecessor set is all five qualified and separately authenticated
providers and its inventory is exactly 361 packages. `consumer.run_stage`
requires a matching Root binding and signed-image check. It launches the
frozen consumer in a network-disabled container with separate scratch. CMake
and CTest run serially and require the three expected checks and their
per-test success output. The reader joins the registered commands, original
JUnit report, verbose tool commands, per-process loader traces and installed
package ownership. It retains the observed object hashes for independent
image readback. The smoke scope is software QML/SVG rendering, qsb shader
reflection, and the anonymous in-process Wayland exchange.

The exact reversible package projection appends a success marker to the end of
each original check and sets CMake autogen parallelism to one. Normal makepkg
dependency and check phases run inside the network-disabled native container.
The entry retains stage, configuration, notice and shader proof before scratch
retirement. The qualifier reopens original operands and current archives,
reruns the pinned stage/configuration validators, checks the original smoke
markers where present, and replays ShaderTools reflection. These checks join
the recorded build and comparison evidence. Root's supervisor authenticates
the host, executor, signatures, installed ABI and private lifecycle.

`pipeline.run_stage` consumes an owned executor selected by Root. The executor
implements domain checks, confirmed empty container state, bounded command
execution, a separate passive qualifier worker, and the private package
lifecycle. The qualifier uses the supplied argv and writes its canonical
stdout to `qualification.json`. The lifecycle executor checks the signature
under the independently selected Required TrustedOnly configuration, mounts
the pinned archive at the fixed private path, and runs the supplied ledger in
a disposable ARM image. It sets `QT612_FAMILY_PRIVATE_LIFECYCLE=1` for the
installed library probe. Its canonical receipt records every command's natural
exit, reap and complete stdout. The adapter checks the exact inventory after
each install, reinstall, rollback and removal, plus the normal dependency
query, package-file check and installed SONAME loads. ShaderTools also checks
the installed qsb version. The original recipe checks execute the QML,
Wayland, SVG and shader smokes in both builds.

The five stages have separate deadlines and fresh Root bindings. The proposed
4 GiB memory and scratch bounds and 6,900-second build deadline are untested
for these components. Baseline authentication is a separately completed Root
procedure with its own measured budget. Failure exports retain a bounded
allowlist of available whole evidence before cleanup.

The original F69 transport contract remains specific to its original package
tuple and cap. The family stage retains its original files for independent
readback and later selection by Root. No family upload workflow is issued.

Run `test_pipeline.py`, `test_proof.py`, `test_qualify.py`, `test_consumer.py` and
`test_md4c_handoff.py` as separate
`python3 -I -B` invocations. Their inputs are passive source bytes and clearly
labelled inert models. Native builds, package transactions, signing and
actual capacity qualification require separately supplied Root inputs.
