# Maintained Core native source factory

This narrow factory turns the exact public373 Core source into the reviewed384 source. It applies19 maintained deltas covering the complete retained64 cache, full574 retained cache and legacy prefills, the source-derived path used after the original environment wipe, and the native-proven systemd-only Docker28 seccomp profile. The existing generic scripts/build/build.py remains unchanged.

Provide the complete public373 source from immutable commit9567ff78098f4a504575180e5a07150fbaafab8d (ref codex/target-core262-owned-tests-v1) as an explicit external fixture. Its entire373-file map is pinned in profile.json. Large recipe archives and repository metadata remain in that existing pinned source; this factory adds no package payload carrier or61MB duplicate runtime.

```sh
python3 -B scripts/ci/core-native-build-pairs/prepare.py \
  --runtime /absolute/path/to/exact-public373 \
  --output /absolute/path/to/fresh/source-default
```

The default output carries the exact unselected source/effective authorities. Only Root may supply its existing reviewed component selection with --binding. That JSON must contain exactly the two authority objects keyed by lane/root-source-authorization.json and lane/effective-source-authorization.json, byte-equivalent to the reviewed_selection in profile.json. Every other selection refuses before output creation. This explicit component selection does not select an actual run or grant build/test/hardware admission. Actual source/ref/run remain NULL.

The emitter reads and pins every373 input leaf, consumes every maintained delta/template, regenerates the complete manifest and both workflow stamps, requires the entire default/selected384 map, and checks every emitted byte. It executes no input source, Docker, Git, network, build, installation or native test. No emitter/runtime/default-test path references development artifacts. A .git directory at the explicit source root is excluded from the runtime map.

The selected map reproduces reviewed source755ee4e6ebbc7c1cb9298872f1b7a536aa76ec4a. Its original58 mechanism, full process-util assertions and all four matrix cells remain held. The systemd recipe and effective profile pins adopt the exact corrected testlog auditor: every command token remains a string, argv[0] stays nonempty, and later empty arguments are preserved and joined exactly to the complete plan. Bounded raw operands are exported before audit, while a positive audit receipt is written only after success. The offending definition in the earlier native run remains unknown because its old auditor exported no raw operands. Full build acceptance remains subject to the independent original metadata and reader gate; source emission grants none. The corrected full4 native run was pending at proposal freeze.

The systemd actor uses the exact Moby28.0.4 default plus argument-equality unshare(CLONE_NEWUSER) and chroot allowances. Ordinary UID, cap-dropALL, no-new-privileges, read-only root, no network and all original scratch/resource/cleanup/owner/job limits remain held. The single existing systemd container runs both original58 and the complete package tests; pacman remains on Docker default. A fresh10s Engine query requires28.0.4/linux/arm64, retains full raw query streams and selected profile, and the host-only loaded profile is rehashed after the package command. The two-rule mechanism passed native ARM run39571303203; this is mechanism evidence, not full package acceptance.

Prefetch ordering is intentional and source-held: exact legacy policy prefills and original CLIs; fresh private Core context; complete128 retained64 seed; unchanged acquire64 current signatures/metadata; original public14/rootfs companion (which clears the environment); complete574 join using the validated source root's parent. Retained64 resolves its fixed external carrier before that wipe. The late574 helper derives the carrier from C.ROOT.parent and never needs GITHUB_WORKSPACE to survive. All immutable carrier Git/blob/filesystem checks and original current GPG/metadata checks remain mandatory; caches are DATA, never authentication. Existing canonical retained-build-inputs documents these same carrier contracts; it is not used to rewrite a frozen lane or silently change the emitted384 bytes.

Portable controls need no external runtime or package payload:

```sh
python3 -B scripts/ci/core-native-build-pairs/test_factory.py
python3 -B scripts/ci/core-native-build-pairs/test_testlog.py
```

Six controls cover systemd-only profile/pacman default; fresh Engine/version/architecture/stderr refusal; real private path checks with the environment truly cleared; retained64 path and exact prefetch ordering; the two rules/original assertion pins/NULL clocks; and real tmpfs stale-atime refresh/profile tamper refusal. Engine calls are mocked. The late-cache control runs the actual helper and original common module through real private directory/path validation to the immutable carrier proof boundary, which is explicitly stubbed; it performs no copying or GPG checks.

The separate integration control requires its explicit pinned fixture and refuses when it is absent:

```sh
CORE_NATIVE_RUNTIME=/absolute/path/to/exact-public373 \
  python3 -B scripts/ci/core-native-build-pairs/test_emitter.py
```

It emits and compares both full384 maps, rejects changed Root selection and output reuse, and leaves no output behind. No tests are silently skipped. The public fixture may live anywhere; development artifacts are not a code dependency. test_support/common.py is the exact pinned original common module used only by portable controls, and every runtime payload/template is referenced by the profile and emitter.

Six additional testlog controls consume the pinned fixture produced by Meson1.12.1-2's actual serializer. These logs are synthetic, not native records. They reproduce the old typed-argv refusal, accept exact empty later arguments, reject argv/environment/count/process-util/marker drift, retain real raw files on failed audit without a positive receipt, reject pacman export, and prove the whole four-edit inverse and assertion suffix. The Meson source/package provenance and all fixture bytes are pinned; default tests require no Meson installation or artifact path.
