# Exact auxiliary-provider result, 2026-11-14

The two original missing providers are now joined as data:

| Consumer | Required SONAME | Exact frozen provider | Resolved payload |
| --- | --- | --- | --- |
| glibc `memusagestat` | `libgd.so.3` | gd 2.3.3-9 | `/usr/lib/libgd.so.3.0.11` |
| libmount Python extension | `libpython3.14.so.1.0` | python 3.14.8-1 | `/usr/lib/libpython3.14.so.1.0` |

Both associations also match the consumer's actual `.PKGINFO` optional dependency.
The Python requirement is unversioned in that metadata and asks for the 3.14
SONAME in ELF. The selected archive is the exact retained frozen-catalog
3.14.8-1 provider; the extension's `.BUILDINFO` records Python 3.14.7-1. This is
a structural association, with runtime/ABI compatibility NOT RUN. It does not
reconstruct the consumer's original build environment.

The command now refuses any change/removal of the original 84 package
descriptors, or an unexpected path, package, version or SONAME for either named
provider. The unchanged original lock and finite result are retained under
`history/`; its original private prepared cache and catalog remain separate.

## Finite recursive result

Inspecting complete added payloads exposes optional helpers and plugins, so the
catalog includes the exact frozen providers for GD's image libraries, HEIF/AVIF
codecs, FFmpeg plugins, SDL, Tk/Tcl, RRD/Lua/Ruby bindings and their declared
dependencies. No payload members are removed to obtain a passing result.

The current selected catalog contains **271 verified archive/signature pairs**,
with all original descriptors unchanged and 187 additions. It checks 1,154
distinct package dependency expressions, preserving raw repeated `.PKGINFO`
dependency records. The actual preparation retains 542 files/355,001,497 bytes:
354,848,112 archive bytes and 153,385 signature bytes. All 271 detached
signatures verify mathematically under the pinned ALARM primary.

There are 59,141 archive members/1,732,443,138 expanded file bytes, 2,076 AArch64
ELF records, nine separately identified BPF objects and 7,868 direct ELF joins.
Both named provider joins and Bankstown's original 137-file Rust association
pass. Thirty-two focused controls pass. A recheck using only the prepared cache
produces identical catalog bytes. These results remain data inspection and
archive-only preparation; no package or BPF code is executed or installed.
Read-only host `readelf` independently agrees on fourteen supplemental files:
the two original provider libraries, both Qt-dependent V4L consumers, all nine
BPF objects and VapourSynth's empty RUNPATH, using non-executable memory files.

`supplemental-inputs.json` retains every added input's exact archive/signature
pins, frozen database entry pin and transport provenance. Of the 187 additions,
129 use retained local archives and 58 were acquired with explicit size/hash,
count/byte/time limits and required signature mathematics. Forty-two downloads
use the official mirror; sixteen use third-party transport of exact ALARM bytes
from the retained snapshot after the official exact path returned 404. The
third-party transport is not described as an official-owned endpoint. No moving
repository metadata or alternative version supplies a replacement input.

Virtual package bindings are explicit: JACK uses frozen `pipewire-jack`
1:1.6.9-1, `libgl` uses libglvnd and SDL2 uses sdl2-compat. These are data-catalog
choices, not host/target package selections, service changes or installations.

V4L's nine `usr/lib/udev/rc_keymaps/protocols/*.o` files are ELF machine 247
(BPF), not AArch64 compiler tools. The catalog permits only their individually
pinned paths/bytes, ELF64 little-endian relocatable type and absence of program
headers. Unlisted BPF, other architectures, and BPF used as native tool/library
providers remain refused. The BPF objects are retained, not loaded.

## Remaining gates

The command still exits **2 / structural closure INCOMPLETE**. Eleven NEEDED
edges from V4L's `qv4l2`/`qvidcap` require six Qt SONAMEs. Exact candidates from
the already-pinned frozen `extra.db` are recorded in `remaining-inputs.json`:

| Candidate | Archive bytes | Archive SHA256 |
| --- | ---: | --- |
| qt6-base 6.12.0-2 | 15,176,004 | `70f2bbce49fa82dee86074a7c96dcc1e43f54a1f82407bb8d855708932323abd` |
| qt6-5compat 6.12.0-1 | 521,852 | See pinned remaining-input descriptor |

No exact Qt-base archive/signature filename was found in the readable inspected
development caches. The tested official and non-rate-limited dated routes
returned 404; three other dated routes returned 429, whose availability remains
unknown. Qt 5compat acquisition was not attempted after the Qt-base gate failed.
Their payloads, signatures over those archive bytes and transitive dependencies
remain uninspected. No substitute version is used or complete closure claimed.

The twelfth unresolved record is VapourSynth's empty RUNPATH. It remains a
visible current-directory loader-search policy gate even though its literal
NEEDED file joins exist. The tool does not assume an ambient working directory
or silently omit this record.

All four historical compiler/LLVM recipe hashes remain unmatched. Complete
compiler/Cargo/LLVM and the expanded runtime corresponding source, source/legal
and relinking acceptance, key freshness/revocation/current policy, compiler
child/linker-script/object and dynamic-loader/symbol-version review remain open.
No accepted native tools profile is produced: its purpose/schema remain
deliberately different from Bankstown's required native profile. Native/Actions/
Root/Original/Reader execution, installation, live trust/services/boot/devices,
16K/M2/performance and release acceptance are NOT RUN here.
