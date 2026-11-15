# UI172 retained materials: DATA staging

`materialize.py` stages only the sealed
`manifest_constructor/results/materials-plan.DATA.json`: 348 files totaling
157,222,100 bytes. Its whole byte/SHA pin is fixed in the source. This comprises
172 original archive/signature pairs, two templates and two public keyrings.
It does not parse, import or execute payloads, run GPG, acquire inputs, or invoke
a daemon, lease, preparation, guest or ABI check.

The requested fresh destination is
`/dev/shm/cachy-asahi-arm16k-ui172-materials-DATA-20261115-r1`.
The directory is owned by the copying user with mode 0700; successful files
have mode 0644 without execute bits. Original source permissions and paths are
never changed. Existing destinations refuse; partial DATA is retained with a
failure receipt rather than overwritten or silently substituted.

Before creating the destination, the reader validates every unique flat name,
pin, count and size cap, then preflights all original paths. Missing or refused
paths are collected explicitly. Every parent is opened through directory file
descriptors using `O_DIRECTORY|O_NOFOLLOW`; leaves use `O_NOFOLLOW|O_NONBLOCK`
and must be ordinary files of the exact size. Each source descriptor's device,
inode, size, mode, owner/group, link count and content timestamps are compared
before and after. Reopening the absolute path also verifies its association
and ancestor identities after the copy.

Destination files are created exclusively. Copying hashes the complete source
while streaming bounded chunks; each destination is then reread and fully
hashed. Both must match the sealed pin. Destination path/descriptor identities,
file modes and exact final directory membership are checked. The directory
contains exactly the 348 material files; metadata receipts stay outside it.

Limits are 256MiB for the aggregate file set, 64MiB per archive, 64KiB per signature
or keyring, 1MiB per template, 512MiB total input/verification read I/O, 128MiB
process address space and 120s wall. File-set bytes differ from I/O: the source
and destination full-hash passes each read 157,222,100 bytes; sealed plan and
unissued-manifest metadata add 2,389,816 bytes. Failed attempts charge observed
reads and reserve the full active file; no retry resets counters in-process.

Run the script with no arguments for the exact requested destination and a
fresh `/tmp/cachy-ui172-materialization-DATA-20261115-r1` receipt directory.
Optional destination/receipt paths are restricted to the same dated DATA
namespace and must be fresh. No arbitrary plan, approval or trust argument is
accepted. The receipt pins membership and the unchanged unissued manifest,
records source/destination custody and byte accounting, and preserves null
Root approval, trust horizon, public Source selector and runtime authority.
DATA hash equality does not establish current signature trust or runtime
qualification. Existing UI172 and earlier audit reports remain unchanged.

Actual copy: all 348 files completed, 157,222,100 staged bytes, with no missing
or substituted paths. Source and destination each read 157,222,100 bytes;
including metadata, input/verification I/O was 316,834,016 bytes. Execution
took 0.434s under the stated caps. Every full hash and final pathname, mode,
identity and exact-membership check passed. Membership JSON is 53,381 bytes,
SHA256 `24a4b55a5897209efee54fab4a807962cfc412e70fb0034c926525ff6aa1b349`.
The private directory contains material files only. Retained membership,
per-file custody and DATA receipts are committed under
`manifest_constructor/results/materialization-DATA-20261115-r1/`.

Twelve synthetic controls passed on actual Python 3.12.13 and 3.14.7, including
tamper/identity changes, missing and linked paths, special files, exclusive
creation, partial reads/writes, destination corruption and resource refusal
accounting. They never access original materials. An additional postcopy
metadata-only check confirmed all 348 names, sizes, modes and ownership without
rehashing payloads. Root approval and all admission selectors remain null.
