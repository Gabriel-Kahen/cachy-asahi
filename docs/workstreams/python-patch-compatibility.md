# Python 3.14.7 to 3.14.8: protected firmware-consumer source audit

October 12, 2026. **Source/API audit only; no target interpreter, firmware tool,
installer, package scriptlet or target workload was executed.** This work owns
this new document and ignored private
`artifacts/platform/python-compatibility-20261012/` evidence only. The strict
201-package protection, original inventories, transaction report and other
frozen sources remain unchanged.

The evidence supports testing a narrowly coordinated Python patch update. It
does not establish runtime compatibility or authorize treating a changed tuple
as the accepted baseline. The existing 55-target transaction remains FAIL:
its requested Python `3.14.8-1` differs from protected `3.14.7-1`.

## Actual affected baseline

The checksum-bound image has 261 packages; its protected dependency graph has
201. Across the complete baseline metadata, `asahi-fwextract` is the sole direct
Python/libpython dependency consumer. Reverse witness traversal gives exactly:

| Protected package | Retained version | Connection |
| --- | --- | --- |
| `python` | `3.14.7-1` | Proposed changed node: `3.14.8-1` |
| `asahi-fwextract` | `0.9.2-1` | Unversioned `python` dependency, witnessed by the retained interpreter |
| `asahi-meta` | `5-6` | Depends on `asahi-fwextract`; no direct Python dependency |

The affected incoming edges are `asahi-fwextract → python` and
`asahi-meta → asahi-fwextract`. Python's eleven outgoing witnesses are bzip2
`1.0.8-6`, expat `2.8.5-1`, gdbm `1.26-2`, libffi `3.8.0-1`, libnsl `2.0.1-2`,
libxcrypt `4.5.2-1`, openssl `3.6.5-1`, zlib `1:1.3.2-3`, tzdata `2026e-1`,
mpdecimal `4.0.1-3` and zstd `1.5.7-3`. These are observed baseline versions,
not a guarantee that the candidate interpreter can reuse their bytes.

An additional operational consumer is protected `asahi-scripts`
`20260127.1-1`: its `asahi-fwupdate` shell entrypoint invokes `asahi-fwextract`.
This call is absent from its declared Python dependency metadata. The fwextract
package's install/upgrade scriptlet calls that updater, which can mount the
installation ESP and replace vendor firmware. Those paths were read as data.
The extractor also depends on `asahi-scripts>=20230606-1` and `lzfse` `1.0-1`.

The smallest proposed change to the **protected version graph** is one node,
`python`. The three metadata reverse-closure packages plus the shell updater
need compatibility review. This scope excludes newly selected Python consumers
in the 624-package tentative desktop inventory; those require their own expanded
audit. Neither unchanged versions nor unversioned dependencies prove behavior.

## Source and package correspondence

The retained signed fwextract archive is
`asahi-fwextract-0.9.2-1-any.pkg.tar.xz`, SHA256
`d0fa3c2d07be69a5df47d18467f81199d439b245bc0dda32fac6265eee7813ae`.
Its signature was checked again against the pinned community certificate.
This establishes signature consistency with that certificate; independent
owner/custody acceptance remains false.

Its `.BUILDINFO` declares recipe SHA256
`1c0af072cd38a2667ba63ed0a919343542b097cfca6b7e2ee3445ecf2f220a34`
and build input Python `3.14.7-1`. That recipe is the
[pinned Asahi ALARM recipe](https://github.com/asahi-alarm/PKGBUILDs/blob/1c6daffd905c1b8f76202949ed48b80a4759ab73/asahi-fwextract/PKGBUILD).
The [actual installer-source fork](https://github.com/asahi-alarm/asahi-alarm-installer/tree/3cfef52bc372a7b84b59823027c75327e129d6ec)
at tag `v0.9.2` resolves to `3cfef52bc372a7b84b59823027c75327e129d6ec`.
Its 61,564-byte source archive matches both recipe SHA256
`2d4f049d618aa7592db0f6b0bfca1f4485bb2244c74c4d5038681b4b36e305e4`
and BLAKE2b; its archive PAX commit annotation matches the resolved tag commit.
All thirteen packaged Python source modules match the corresponding
archive members byte for byte. This is source correspondence, not a rebuild.

The wheel declares purelib and `py3-none-any`; the inspected package contains
Python source and 26 `cpython-314` caches, with no compiled Python extension.
That declaration does not validate native FFI calls or M2 compatibility.

## Interpreter pins and compatibility policy

[Python 3.14.7](https://www.python.org/downloads/release/python-3147/) was released
August 5; [3.14.8](https://www.python.org/downloads/release/python-3148/) was
released September 30 as a security maintenance release. The audited official
CPython source pins are `823f0323ee6ec1402088b73bce1a38473cac36dc` and
`8e6e75d9102e39bed2a2b279203a396741180f12`, respectively.

The pinned `Doc/c-api/stable.rst` copies are identical, SHA256
`8bdca4cface0f81dc2c569ea87a2004e11956ac7d66104ce759507762166337f`.
[CPython's documented ABI rule](https://docs.python.org/3.14/c-api/stable.html)
covers forward/backward compatibility within a minor series when builds use
compatible platform/compiler/library/settings. Private C APIs can change even
in patch releases. ABI compatibility does not establish unchanged behavior or
validate an external library call. [PEP 387](https://peps.python.org/pep-0387/)
protects public APIs while allowing bug fixes and exceptional incompatibilities.

Both pinned `Include/internal/pycore_magic_number.h` files are identical,
SHA256 `bb62ef60ff8151ef269d61455d86c8f0d0d402d300e17df226380a75ba2a7a66`:
magic number 3627. All 26 packaged caches have matching first-four-byte value
`2b0e0d0a`. The import cache tag remains associated with Python 3.14. This
supports cache-format continuity; cache validation/import/recompilation and
package hook behavior were not exercised.

The retained root image was rehashed to
`76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db` before
bounded read-only `debugfs` member reads. AST literal parsing of its sysconfig
module and JSON parsing of its sysconfig data agree on the selected build fields:
SOABI `cpython-314-aarch64-linux-gnu`, empty ABIFLAGS, MULTIARCH
`aarch64-linux-gnu`, `Py_DEBUG=0`, `Py_GIL_DISABLED=0` and `Py_ENABLE_SHARED=1`.
Installed headers independently declare a shared, non-debug, GIL-enabled
3.14.7 build with eight-byte pointers and longs. Full CFLAGS/configure arguments
are retained as data. No sysconfig module was imported.

The coordinated signed candidate `python-3.14.8-1-aarch64.pkg.tar.xz` is
13,588,352 bytes, SHA256
`5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984`.
Its checksum-bound receipt is SHA256
`1405be1d5b1f814a81c33604d466ecaf1d0e69d915badfb25183cc4fef7fc35d`.
Fresh independent read-only `gpgv` verification in private scratch succeeds
against pinned ALARM certificate fingerprint
`68B3537F39A313B3E574D06777193F152BDBE6A6`; independent certificate-owner trust
remains unaccepted. Its `.PKGINFO` declares `PSF-2.0` and the same eleven
unversioned dependency names as the old interpreter.

Both versions have 1,106 sysconfig build fields. Exactly seven differ, all
substituting the source-build directory `Python-3.14.7` with `Python-3.14.8`
in coverage/test/build-path fields. SOABI, ABIFLAGS, debug/GIL/shared flags,
MULTIARCH, compiler command, CFLAGS, configure arguments and library/extension
names are identical. `pyconfig.h` is byte-identical; `patchlevel.h` declares
3.14.8 in the candidate. The Python and JSON sysconfig data agree on the
selected ABI fields; both JSON files additionally resolve `srcdir` to the
installed config directory and include derived context fields.

This verifies recorded platform/settings correspondence, not compiler-binary
or lower-library identity. The new `.BUILDINFO` declares Expat `2.9.0-1`,
where the old protected graph retains `2.8.5-1`; it also declares GCC
`16.1.1+r12+g301eb08fa2c5-1` and glibc `2.43+r22+g8362e8ce10b2-2`.
The old compiler's exact build identity was not recovered. CPython's conditional
ABI policy therefore supplies supporting evidence, not a completed distributor
or firmware compatibility proof.

A bounded static check narrows the Expat concern. The exact old image library
`libexpat.so.1.12.5`, SHA256
`a950488bf7f69ec589170b0548f3a8a850dad39f060b33a5b3c9e079abdb4730`, exports
all 57 unversioned `XML_*` symbols required by the signed candidate's `pyexpat`
extension. That extension declares `libexpat.so.1` as a needed library.
`_elementtree` has no direct undefined `XML_*` symbols or Expat needed-library
entry. The extensions and old library are ELF64 AArch64. There is therefore no
missing Expat symbol requiring an additional protected-package change in these
inspected ELF objects. This does not test XML behavior, dynamic loading, capsule
interfaces or native firmware conversion. The audit used bounded read-only
`debugfs` and host `readelf`; it never loaded a library or executed a target ELF.

## Examined interfaces and patch differences

The private member audit records every import and static call expression.
Imports cover argparse, base64, builtins, collections, ctypes, enum, hashlib, io,
logging, numbers, os/os.path, pathlib, plistlib, pprint, re, statistics, struct,
subprocess, sys, tempfile and ElementTree, plus bundled firmware modules and ASN.1.
No direct private CPython C API invocation was found in these source modules.

| Actual firmware interface | Audited patch observation |
| --- | --- |
| `argparse` CLI with source/destination `Path` arguments; pathlib, tempfile, os/posixpath | Examined implementation files identical across both pins; no removed directly invoked public interface found |
| `ctypes.CDLL` and `create_string_buffer`; Linux `liblzfse.so.1` or `.so` | Loading/allocation interfaces remain; changes include static-interpreter import handling and pointer/attribute deletion fixes. Existing FFI calls leave argument/return typing implicit; native correctness is untested |
| `struct.pack/unpack` for binary firmware fields | The examined `_struct` patch repairs zero-length Pascal-string packing. Extractor format strings do not use the `p` code |
| `plistlib.loads`, ElementTree `fromstring/tostring` | plistlib changes affect writing mixed-key dictionaries; extractor calls loads. XML parser/encoding/whitespace behavior changes require representative firmware XML comparison |
| `subprocess.run` | Signature remains; examined change alters formatting of unusual `CalledProcessError.returncode` values |
| `tarfile.open` in write mode, `TarInfo`, `addfile` | Extractor writes archives. Patch changes sparse reading and extraction filters; raw firmware unpacking uses external `tar`, whose behavior is a separate input |
| logging | Examined change concerns file-handler open errors; extractor uses basic configuration and ordinary log methods |

Patch observations derive from the pinned
[3.14.8 NEWS](https://github.com/python/cpython/blob/8e6e75d9102e39bed2a2b279203a396741180f12/Misc/NEWS.d/3.14.8.rst)
and exact source comparisons. The changed paths, both source hashes and diff
sizes are retained privately. This is a targeted interface audit rather than
an exhaustive proof of all interpreter internals.

The normal Linux CLI invokes external `tar` on supplied firmware input, builds
firmware collections, then writes tar/CPIO/manifest output. Its ALS path receives
collected input. The macOS collection branch additionally invokes `ioreg` and
can load `libcompression.dylib`; it is distinct from the Linux liblzfse path.
No branch was executed. Firmware inputs, native library calls, output equality,
privileged updater/ESP behavior and both-model boot recovery remain unverified.

## Evidence and disposition

Private evidence includes the preserved `capture.json`, its extended
`capture-b.json`, the final `capture-c.json`, `api-comparison.json` and
`affected-graph.json`, alongside bounded official-source/document snapshots and
the installer-source archive. `old-python-build-settings.json` and
`python-build-settings-comparison.json` bind the image reads and signed package
member reads. The latter SHA256 is
`1b18c64b0d3ef1e560769241610adc613bce67410fbf2a96cab8c8d79743fed3`;
its archive scan covered 3,201 members and 82,534,355 declared decoded bytes
under a 128-MiB bound, retaining only six bounded data members. Files use mode
0600 in a mode-0700 ignored
directory; no third-party source is copied into tracked documents or packages.
`expat-static-abi.json` retains the static symbol comparison, SHA256
`0099dcae72bb52c17cce08020145cc063080352ae14cdf9c094dd828d1de84fa`.
The final capture SHA256 is
`70df91bc90d6591910311009038847290eb13413753ef31ac599391664b4b648`.
It binds the extended evidence without replacing prior receipts; all 94
referenced file hashes and byte lengths were rechecked. Total private evidence
is 4,714,422 bytes, below the 256-MiB evidence ceiling.
The graph is bound to image inventory SHA256
`5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941` and original
tuple report SHA256 `92c53bc28d5442ac1780c0b54094a3bd99eb5a3dd89d069e94da82a2e8fc0030`.

**High confidence:** recorded graph scope, exact source-member correspondence,
public interface presence, observed cache magic and compared distributor build
declarations. **Conditional source-level
compatibility evidence:** same-minor policy and the examined patch differences.
**NOT RUN:** imports/CLI execution under candidate Python, firmware conversion
comparisons, native FFI, coordinated installation/upgrade/recovery and M2 tests.

The strict old tuple remains authoritative. A separate candidate still needs
complete dependency/ownership/hook and lower-library compatibility analysis,
controlled non-hardware behavior checks and subsequent exact-machine platform
acceptance. This audit establishes a bounded candidate rationale; it changes no
guard and does not turn the existing failed proposal into PASS.
