# r86 public ld.so.cache recovery proposal

This is a tiny passive request/plan/decoder for Root execution, not an operator,
actor grant or a lifecycle guard waiver. r86 is a closed HOLD: all metadata stages
completed, then Source339 R21/index5 found a changed composite cache view. No
particular field, new cache body, provider relationship or final recovery state
has yet been observed here. The original strict339 case and all Sources remain
unchanged. Runtime/lifecycle/M2 acceptance is NOT RUN.

## Authoritative ALPM behavior

Fresh primary API/raw observations resolve installed pacman7.1.0.r9.g54d9411-2 to
54d94116164b0b2202c6061c4a59c6f3e70820d8. add.c invokes builtin _alpm_ldconfig after
normal successful installs/upgrades; remove.c invokes it after normal removals.
util.c checks root/etc/ld.so.conf and the configured executable and directly runs
ldconfig inside that root. ALARM recipefd636a0077db0efe900d67d4de910c0d270fc8c4
sets -Dldconfig=/usr/bin/ldconfig. This is independent of named .hook files and is
not disabled by hook-file suppression. Exact URLs/whole-source hashes and frozen
glibc-owned ldconfig865664B/8794bf13... version2.43+r22... are in provenance.DATA.json.
This is source/version correspondence, not a new reproducible binary proof.

A cache generation transition is legitimate in principle. Demanding its original
inode/mtime after normal replacement is not a viable lifecycle predicate. This
still does not prove which r86 fields changed or authorize arbitrary cache content.

## Root's narrow read-only recovery

request.TEMPLATE.json is unissued and default-refuses. Root supplies the exact
closed-overlay whole byte/hash pin, independently issued output/actor/runtime
selection and fresh custody. It binds Source339/7beb, image529, immutable qemu-img
and debugfs expected pins, the exact backing1610612736B/
49da69b9262e089e08aa84063ed14ca13e66189f9c1e396616ab5f5cb5e24b81 and fixed resources.
Overlay logical input cap4GiB is distinct from the proposed256MiB allocated cap;
Root must measure/review both, never equate sparse EOF with actual allocation.
A JSON issuer string is not an authenticated Root grant; Root's existing wrapper
must bind the exact request/Source/tool hashes and actual owned execution envelope.

Root should reuse its maintained owned subprocess/RSS/natural-retirement and
lease wrapper, not create a new executor. Existing metadata_raw_reader.py parsing
is retained here as a narrow parser-only derivative; its15-directory executor
includes root and is NOT reused. The initialized full scanner also inventories
private state and is outside this request.

Mount selected closed overlay read-only as /inputs/overlay.qcow2 and the exact
backing read-only at its ORIGINAL embedded path /prepared/guest.raw. No rebase,
backing-path rewrite, symlink substitution or extra file/device is allowed.
Hash/bind both inputs before and after the complete operation and retain their
stable inode/stat identities. Source inputs are never opened writable.

recovery.plan() emits precisely seven literal argv vectors:
1. qemu-img info --output=json --backing-chain -f qcow2 /inputs/overlay.qcow2.
2. ONLY AFTER recovery.chain() accepts exactly two bound nodes/formats/virtual
   sizes and no extra data/backing graph: qemu-img convert -f qcow2 -O raw -S4k
   /inputs/overlay.qcow2 /output/observation.raw, exclusively fresh output.
3. debugfs -R 'stat /etc/ld.so.cache' on that disposable raw.
4. debugfs -R 'stat /etc' on the disposable raw.
5. debugfs -R 'dump /etc/ld.so.cache /output/cache.bin' on the disposable raw.
6-7. Repeat both fixed stats, requiring exact stability across the dump.

No debugfs -w, mount, journal replay/fsck, directory enumeration, inventory,
other guest pathname, ldconfig execution, private child name or guest boot is
requested. Root must reject non-natural tool retirement or any diagnostic frame.
Combine each stat's separate stderr banner BEFORE stdout for the strict decoder;
retain both original streams and command receipts. Limit each frame to16KiB and
cache dump to1MiB. decode_outputs requires an ordinary root0644 single-link cache,
root0755 /etc, matching stat size/body hash and repeat metadata equality. It emits
only those two public metadata records, cache hash/size and baseline changed-field
names. Raw cache bytes stay in the selected public cache.bin output. Header tagging
is not cache semantic validation. Xattrs and provider correspondence remain
explicitly unobserved/pending, not assumed equal.

Proposed finite envelope for Root review:512MiB/1CPU/64PID/swap0,180seconds whole,
60convert,10info and10 per stat/dump; initial2GiB free and512MiB live reserve.
Fresh raw logical/allocated cap1610612736B; no source/image geometry increase.
Metadata outputs<=128KiB plus cache<=1MiB and bounded command streams. Actual
cgroup/RLIMIT_AS/CPU/PID/FSIZE/owned storage/retirement checks remain Root's
maintained wrapper responsibility. Root retains or removes ONLY the fresh
observation output under its own custody, never input overlay/backing.

## Specific next lifecycle predicate

baseline-public.DATA.json contains only the two selected r76-derived baseline
public records from the current frozen descriptor (cache17551B/SHA0128a732...).
First qualify actual changed cache/parent fields from this recovery. If bytes
changed, Root must join decoded cache entries and a reference generation by the
exact frozen ldconfig/configuration to the independently frozen baseline plus
candidate/dependency provider namespace. Do not promote the observed failing
cache into its own expected reference. After normal ALPM recovery, require exact
baseline cache content/attributes and provider correspondence; accept only the
explicitly scoped natural replacement identity/time transition, with stable
current inode during each observation. /etc must retain inode/type/mode/owner/
links/xattrs and unchanged unrelated namespace; only its documented transaction
mtime transition may be scoped. No timestamp reset, cache overwrite/deletion,
pre-state fabrication or private-node relaxation is proposed. New guest and host
preservation predicates require a separately reviewed case/descriptor.

Focused pure DATA tests exercise strict requests, two-node backing-chain refusal,
literal argv scope, public stat parsing, field differences, cache/body matching,
repeat-stability, aliases/caps/duplicate/malformed frames and default refusal.
No actor/tool/VM/Docker/GPG/raw/credential/key/lease operation is run by these tests.
