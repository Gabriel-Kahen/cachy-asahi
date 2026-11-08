# SourceTools current package native input component v2

This is a source-only preparation component for the actual merged
`cachy-asahi-source-tools` **0.2.0-1** package. It does not construct a Git-root
native Source, select an image, invoke a native actor, sign/install a package,
run a reader, or fix the retained namespace failure. Every actual execution
selector is NULL and admission stays on Root's genuine cause/resource hold.

The caller-authenticated selection binds all **14 recipe sources**, plus
PKGBUILD and SRCINFO (**16 files**), and the complete **18-file payload**. Pins
come from merged Main `f15f487113ae14586b3b206bd2c0240483b82f28`, PR362 head
`cebc57effd170aacf145aaf3c3de9b5a3ee48360`. Git is descriptive provenance;
whole bytes/SHA256/canonical modes are the selection authority. Recipe bodies
are parsed as data without sourcing PKGBUILD or evaluating retained Python.

The eleven packed helpers, their `private-source.tar.gz` identity and provenance
stay byte-identical. The catalog helper remains a separately pinned source and
payload file. Actual private checkout modes0600/0700 are accepted as equivalents
of canonical source modes0644/0755; the input tar always uses canonical modes.

`recipe-inputs-v2.tar` is a canonical uncompressed USTAR of16 regular members
under `recipe/`, not a complete Source. `prepare_inputs.py` verifies it against
the live caller-selected recipe and produces exactly five flat input operands:
recipe tar, integration contract, mandatory-check makepkg configuration, current
check-output validator, and recipe binder. It refuses an existing destination.

```sh
python3 -I -B scripts/ci/source-tools-current-native-inputs-v2/prepare_inputs.py \
  --recipe-root /absolute/current-recipe \
  --selection-sha256 a1d0812b225b08d1db9c1c8cdd42a6e1897cc1d26a3a9c672c5ac5de0a272956 \
  --output /absolute/owned-parent/fresh-current-input-component
```

The versioned native integration contract binds two independent clean alarm
builds at one stable logical path with checks enabled, exact current archive
and PKGINFO identity, byte/payload/PKGINFO/BUILDINFO/MTREE comparison, and full
baseline inventory provenance. The retained349-row inventory is explicitly
historical baseline data; a changed image requires fresh Root inventory binding.
TEST-only scoped signing requires both signatures, explicit primary trust,
unknown-key/tamper negatives, Required/Required ALPM policy, all18 payload paths,
and exact inventory/reason/home/trust/cache/user-export restoration.

Current check() emits five ordered JSON objects: CLI9, catalog9, source check11,
staged payload18, and the inherited17-control moved/offline package check.
The first object is multiline. The old v1 line-by-line/three-object parser cannot
qualify this version. The v2 DATA validator parses complete bounded objects,
binds launcher/private/catalog hashes and strict counts, and returns
`native_acceptance=NOT_GRANTED`. Its positive parser fixtures are synthetic.

The future installed/moved probe must preserve the original17 controls with the
new global version, then add11 catalog-driven commands per location: list both
retained releases, materialize four listed selections, verify all four contexts,
and refuse a wrong catalog pin. All builder selectors remain NULL. These command
requirements are integration inputs; no new native probe was executed here.

Root must select a genuinely classified base and complete/review the enumerated
versioned owner, invocation/workflow, build/ALPM/probe, failed-result projection/
reader and closed-map seams before a dispatchable Source exists. This component
does not patch or relabel the v1 actors, Source419, or its old proof identities.
There is no constructor or dispatch capability for an immutable Source here.

Source-only controls (37 total):

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/source-tools-current-native-inputs-v2/test_current_package_inputs.py --recipe-root packages/tools/cachy-asahi-source-tools
python3 -I -B -Werror::ResourceWarning scripts/ci/source-tools-current-native-inputs-v2/test_check_current_makepkg.py
python3 -I -B -Werror::ResourceWarning scripts/ci/source-tools-current-native-inputs-v2/test_prepare_inputs.py
```

Native pair, signed ALPM lifecycle, Source publication, reader qualification,
native16K, M2, performance and release acceptance remain NOT_RUN/NOT_ADMITTED.
Namespace cause remains UNKNOWN. No shared manifest or existing native workflow
is edited by this additive maintainer candidate.
