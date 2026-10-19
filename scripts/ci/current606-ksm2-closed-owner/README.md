# Optional KSM1→KSM2 on complete606

This is a new copied-root composition lane, not an overlay-only575 test. Its
source baseline is the Root-accepted complete606 DNS2/Sysctl2 sourcef3a30f2049f57d9f3cb2433fbd59af51d4cc5720.
The lock contains KSM0.1.0-1, Apps6, Welcome4, DNS2, Sysctl2 and Runtime1.
Only the same actual package `cachy-asahi-ksmctl` changes to0.1.0-2, retaining606.
The six checkpoints are original1, upgrade2, same-version2, removal605,
reinstall2, and exact-original1 archive restoration606. All other605 packages,
payload, rawDB, users, trust, capabilities and full physical/hardlink state stay
protected. Runtime1 is never reinstalled. The independent original606 source
and lifecycle remain held and separately observed.

Exact native KSM72ea5a1e81268f08da9b9cc04cdc7e23a1a9ff8a/run39139213293
qualifies the two-version574 upgrade and private suites only. Original1 restore
comes from the SAME current606 producer manifest/archive/signature/project row;
the newer standalone same-version1 build is not treated as a substitute.
Candidate2 is joined to both native archives, all14 recipe leaves, complete
payload/metadata/BUILDINFO and the exact whole Root decision. Its TEST signature
is verified in the future disposable worker, never promoted to release trust.

Native public input carrier approval is pending. Its source/ref are NULL; local
29-file DATA calibration is explicitly LOCAL_SOURCE_ONLY_NOT_PUBLIC. Default606
Root selection and all future actual source/ref/run IDs remain NULL. There is
no Apps7/Welcome5 qualification requirement or borrowed acceptance. Those tools
remain original6/4 protected packages in this independent lane.

Reproduce from the registered code-only dependency sources:

```sh
python3 -I -B scripts/ci/current606-ksm2-copy/prepare.py \
  --basis-source ABSOLUTE_9AF_SOURCE --native-source ABSOLUTE_72EA_SOURCE \
  --owner-source "$PWD/scripts/ci/current606-ksm2-closed-owner" \
  --output FRESH_ROLES
python3 -I -B scripts/ci/current606-ksm2-closed-owner/prepare.py \
  --held606-source FRESH_ROLES/held606 --bridge-source FRESH_ROLES/bridge \
  --copyworker-source FRESH_ROLES/copyworker --output FRESH_SOURCE \
  --authorization FRESH_AUTH_JSON
python3 -I -B FRESH_SOURCE/scripts/ci/current606-ksm2-closed-owner/test_owner.py
python3 -I -B FRESH_SOURCE/copyworker/scripts/ci/current606-ksm2-copy/test_worker.py
```

Use absolute paths. Historical9af is a whole pinned code basis only; it conveys
no copied-root Apps acceptance. All13 raw copy helpers remain byte-held. The
factory preserves the original four-builder→consumer→finalizer/worker/disposer
5→8 actor topology, owner6600/consumer1800/worker1800/copy600/cleanup60 and exact
six/five/eight capability profiles, network-none and five typed worker binds.
No broad privilege, mount, timeout or correctness exception is introduced.

Future activation additionally requires Root's real public-carrier publication
record (exact29 files/index) plus genuine606 decision selection. Optional emitter
`--selection` and `--publication` refuse missing/unpublished records before output.
Root alone supplies/publishes/dispatches those operands. The default dedicated
workflow refuses at its selection gate before secrets/actors or carrier checkout.
The registered main workflow alias is created only in emitted trial output.

Rooted ordinary fixtures run only installed reporters/helpers with --help and
--version, plus18 reporter controls and26 KSM2 private-file experiment controls
in both homes. No live `/sys`/`proc` value changes, automatic preset, service,
run2/unmerge or memory rollback occurs. Kernel KSM support, physical M2,16K,
performance and release qualification remain separate and unaccepted. A private
flock is not external-writer CAS. Do not infer live scanning behavior from the
model suites or package acceptance.
