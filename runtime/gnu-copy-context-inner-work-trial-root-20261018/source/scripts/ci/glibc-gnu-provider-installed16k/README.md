# Conventional GNU provider installed on generic16K

This separate private TEST lane implements the **normal** conventional-provider
ALPM lifecycle and outer-runtime rollback in a disk-backed generic AArch6416K VM.
It does not establish an interrupted transaction, an Asahi installation, either
M2 Air, performance, source-key authority or release admission. The policy stays
UNBOUND until Root accepts the actual native normal lifecycle. The genuine
system-path runtime decision from carrier
`808ce8fc5669d292e264fb7e109395a8ba73249c` is retained verbatim with its explicit
`DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION` qualification. That prerequisite
alone never authorizes this lane.

## Implemented execution

The workflow first reuses the existing original574 native producer, authenticated
packet, complete export/capability snapshot and original native lifecycle owner.
The new consumer receives that owner's complete root and privately bound native
runner/input index while holding the original producer directory lease.
It creates two ext4 file images with the existing full-root VM approach,
`cp -a --reflink=never` and `mkfs.ext4 -d`. The complete original574 payload, ALPM
database, ownership, modes, symlinks, internal hardlinks and capability xattrs
must survive serialization: the unchanged native observer and capability bridge
independently read them back inside the guest before any transaction. A copied
574-entry database with missing payload cannot pass the node-map binding.

The boot image contains the held full574 observer plus the finite source/input
closure, and is attached readonly. A separate writable data image contains the
complete held574 source and private work/output directories. PID1 mounts that
data image at `/volume`, binds `/volume/held` readonly at `/held`, binds its
disjoint work/output directories at `/work` and `/out`, and **unmounts `/volume`**.
There is no writable source alias. It then detaches devtmpfs and creates only
`null`, `zero`, `random` and `urandom` in a private tmpfs `/dev`; neither raw disk
node nor disk descriptor is given to the lifecycle child.

PID1 remains a privileged supervisor. It protects its own dumpability and starts
a separate process group for the child, reusing the existing bounded process
runtime. The child reuses the existing AArch64 service-IPC filter and capability
reduction function with the explicit GNU trial capability mask `0x802400fb`:
CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID, SYS_CHROOT, SYS_ADMIN, SETFCAP.
Effective, permitted and bounding sets must match; inheritable and ambient sets
must be zero; `no_new_privs=1` and seccomp filter mode2 must be observed.

The required SYS_ADMIN capability is fenced by an additional finite AArch64
syscall filter. Legacy `mount` is allowed only with exactly flags15
(readonly/nosuid/nodev/noexec) or4096 (bind). Remount, propagation and move flag
combinations are refused. New mount APIs return ENOSYS for legacy fallback;
namespace entry/creation, mknodat, pivot_root, ptrace, process_vm_writev and bpf
are refused. Thus a child cannot expose usable block devices by mounting
devtmpfs, clear readonly/nodev attributes, or reconstruct the detached RW source
view. PID1 retains mount-teardown/poweroff authority outside those child bounds.
The first native execution must still establish that the pinned util-linux
commands use their permitted legacy fallback; incompatibility remains a failure.

The four counted native source edits change the import location, one actual-page
expectation and its diagnostic, and the outer container/guest guard. Twenty
original function/class bodies remain byte-identical, including transaction,
dependency/conflict preparation, two configuration cases, complete payload and
hardlink checks, capability restoration, runtime mounts, user preservation,
config sidecars, precommit refusal, reinstall and outer ALPM recovery. Both
pristine and modified cases execute normal shell/pacman/locale/iconv plus all
eight parent runtime cases and their direct child at before/provider/reinstalled/
held checkpoints: **eight actual normal-interpreter observations**. The held
post_upgrade scriptlet is retained and explicitly executed after restoration,
exactly as in the native lane. No sole-provider removal or dependency bypass is
introduced. Interrupted replacement has a separate source and CI lane whose actual native interruption and normal installed16K prerequisites must both be accepted.

The exact existing managed diagnostic16K kernel receipt/Image/config verifier is
reused. QEMU has two CPUs,4096MiB, TCG, no network/display/monitor, a readonly boot
disk and a private writable data disk. The nonce-bound protocol requires actual
AArch64/16384-byte pages and the kernel-profile hash. Natural zero QEMU exit,
child-group absence, guest clone removal and mount retirement are all required.

## Resources, retention and cleanup

Require48GiB free at preparation; source staging is at most10GiB per image.
Boot/data virtual disks are16/24GiB. The VM deadline is10800seconds, its lifecycle
child10500seconds, preparation/export actor2400seconds, and UART16MiB. The
inherited native command/snapshot/copy deadlines and all payload/node budgets are
unchanged; slow TCG failures are failures. This lane introduces no host mounts,
host ALPM transaction or current-host system modification. The workflow's tool
provisioning is confined to its explicitly disposable GitHub runner.

Public evidence consists of existing native stdout/stderr, transaction logs,
results, isolation observations and16 compressed complete node-map snapshots.
Snapshots contain paths, hashes and metadata, **not file payloads**. Exact names
are allowlisted, at most64MiB each,512MiB aggregate and256files. Read-only debugfs
extracts only those manifest-bound members after QEMU group retirement. This consumer
never uploads its source export, disks, kernel Image, signing homes or filesystem
payloads. The inherited native owner separately retains its already public frozen
provider-input packet and native receipts in its existing artifact. A result cannot pass when evidence exceeds these limits.

Cleanup first retires QEMU groups and exact label/image/CID-bound consumer
containers. A failed preparation stage is removed only by its recorded inode
and nonce through an owned scrub actor. Owned disk/Image files are then removed.
Unknown process or actor absence preserves backing data and prevents the
original owner from retiring its producer. The producer and kernel build work
are borrowed: this consumer never deletes them. The original owner performs its
normal guarded producer cleanup after the consumer barrier. Failed kernel build
work is left for disposable-runner teardown; no active compiler-cancellation
claim is made.

## Controls and status

Run `python3 -B scripts/ci/glibc-gnu-provider-installed16k/test_lane.py` on the
proposed/adopted closure. Controls include source invariance, explicit UNBOUND
refusal, actual prerequisite identity, syscall program interpretation, protocol
rejections, evidence caps and a real rootless ext4 hardlink/file round trip.
The latter validates only the host fixture serialization, never native full574,
capability-xattr serialization, ALPM execution or16K boot.

Current status: source implemented and host controls exercised; **not built,
booted or installed in this lane**. Root must refresh exact native source
pins after any functional successor, accept the actual normal lifecycle,
bind its decision, then freeze source/workflow before dispatch. No future run
number, source commit or acceptance digest is invented by this implementation.

The owned lifecycle worker retains CAP_KILL so the unchanged supervisor can
signal and prove retirement of its UID65534 normal-probe process group. This
leaves PID1 authority unchanged; preparation, scrub and observer roles receive
no new capability.
Native run38995066761 exposed EPERM in killpg cleanup; the dedicated successor
still requires actual native execution and Root acceptance.

## Diagnostic-only progress and failed-disk readback

The original2992-byte worker and all full-root/ALPM/runtime bodies remain exact.
Its entry wrapper installs finite stage-function wrappers (8 owned stage calls
and outer snapshot observer calls, no per-node profiler). A source/nonce-bound
256-record/64KiB ledger uses the existing closed public-log slot
`pristine-guest-progress.log`; the slot name grants no pristine result. Records
carry only closed stage/case/phase/enter-or-leave/sequence labels. Call return can
also indicate exception unwinding; these records never claim stage completion.
PID1 polls the atomic ordinary0600 receipt in a bounded thread during the original
10500s child supervisor and emits distinct live `GNU_INSTALLED16K_PROGRESS` frames.
Missing, partial or changed progress cannot interrupt supervision. The original
boot/result/exit protocol and512KiB child/16MiB UART bounds stay unchanged.

Only after the host verifies its own QEMU group absent, the original export role
can inspect fixed result.json (8MiB readcap) and the64KiB phase receipt via readonly
debugfs before disk disposal. Each source-owned debugfs command uses the original
group supervisor,15s/64KiB output and child-only destination filesize cap. Public
facts contain raw lengths/hashes, a closed non-payload result projection and the
validated phase ledger; no raw worker maps, private paths, keys or error text.
Missing/invalid/partial/oversized receipts remain diagnostic-unavailable, never
acceptance. Original10800s QEMU and650s outer cleanup budgets are not increased.

The export role uses the exact retained ordinary host UID/GID with cap-dropALL
and no added caps. Its owner/source/nonce and caller-owned ordinary disk/output
modes are checked; existing mounts stay readonly except original public output.
Normal readback body is byteexact beyond this entry guard. This corrects a future
permission seam (capless root cannot write foreign0755 output or chown to its
owner); it is not the cause of the failed39022744025 QEMU deadline. Likewise the
boot parser now strictly validates the existing8192 observer readback before
comparing all original boot fields. That future parser seam was not reached by
the failed actual. No runtime/installation/hardware/performance credit results.
