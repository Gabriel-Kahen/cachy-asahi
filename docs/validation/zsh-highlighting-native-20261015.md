# Zsh syntax highlighting: native build and installed lifecycle, 2026-10-15

[Run38802848134](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38802848134),
attempt1, succeeded on generic `ubuntu-24.04-arm`. Exact Source/workflow is
`e486ee56ceaac16d558e896b94f515ada19000a4` on
`codex/zsh-highlighting-native-v1`. **Two native builds, one exact-byte pair,
four signed-install/removal checkpoints and ten installed terminal-group
passes** completed. This is disposable native software evidence, not target
Asahi/M2 installation, physical16KiB validation, release trust or performance.

## Source and retained evidence

The recipe is `cachy-asahi-zsh-syntax-highlighting` version
`0.8.1.dev.e6683f2-1`, `arch=any`, dependency `zsh>=4.3.11`. It packages unchanged
upstream revision `e6683f20e5c38d3e5447f45845d04ddda75d0f23` under BSD-3-Clause,
plus the original MIT wrapper/integration and complete notices. Its provenance
pins source archive SHA256
`6e8258a74e6f3cac03e1bb5ee72504bc4d819904e9aa742d62f60833168db265`.
Preparation-time NOT RUN statements in the tested recipe documentation/provenance
remain historical; those bytes were not rewritten after validation.

Root retained once:

| Retained object | Bytes | SHA256 |
| --- | ---: | --- |
| [logs.zip](../../artifacts/development/zsh-highlighting-run38802848134/logs.zip) |14,995 |`f64312987f636e11dcf682b9844766557e1a8fbec1f33b8c577ece080eedb85c` |
| [Artifact12005621219.zip](../../artifacts/development/zsh-highlighting-run38802848134/12005621219.zip) |152,986 |`a2ad27b66236003cd0bed186d3df7bc8e8de45cae8155aed9cd277038c939dd5` |

Both ZIP CRC checks pass. The artifact digest/size and Source match retained
artifacts.json and the Actions upload record. The
[readout](../../artifacts/development/zsh-highlighting-run38802848134/review/readout.json)
checks all20 recipe input hashes against exact Source, both build provenance
records, all18 exported output-file digests, actual archive members and the
matching lifecycle.log/lifecycle.json result. Two duplicate per-build
expected-packages.lock files are not exported; their declared hashes agree
with the retained574 inventory. No recollection, rebuild or fixture replay was
performed for this review.

The previously reviewed held8d8 helper/input pair created the exact574 native
builder: host and Docker server report aarch64, kernel6.17.0-1022-azure,
4,096-byte pages, Zsh5.9.2-1 and makepkg7.1.0. The report records1,153 acquired
objects and PASS_NATIVE_OFFLINE_574_TRANSACTION. Both build containers use
native linux/arm64, UID/GID1001, networknone, read-only roots, dropped capabilities
and no-new-privileges. Distinct container runs share one runner/image; this is
not independent-machine reproduction.

## Native pair and strict payload

Both builds execute recipe check(), including syntax checks on the flat local
Zsh source inputs. Static validation reports zero errors. Each archive
`cachy-asahi-zsh-syntax-highlighting-0.8.1.dev.e6683f2-1-any.pkg.tar.xz` is
**35,720 bytes**, SHA256
`1b253d7676a4ab48f1c423d163f5a4614a01fac9d884d3c253db84c6a72b84a6`.
The comparison reports equal archive bytes, installed contents, PKGINFO and
BUILDINFO, with no errors. These bytes also equal the preceding failed-lifecycle
run's successful native pair; this actual completes the corrected caller path.

The package contains exactly17 regular0644 root-owned files and16 directory
members, all0755 root-owned. Every regular member's hash matches the selected
Source input, including the seven highlighters restored into their upstream
runtime directories. There are no ELF files, symlinks, executable-mode payload
files, .INSTALL, ALPM hooks or service units. The mode0644 Zsh files are
interpreted runtime code when explicitly sourced, not inert configuration.
Package installation edits no user startup file and does not opt a user in.

## Signed ordinary package lifecycle

A temporary ed25519 TEST signer
`2F115C7F878AE408FEE2292BBFEE8DC9A22D9F8B` signs the exact copied build1 archive.
The private public-only verifier imports its public key and fixture ownertrust;
GPG verification precedes pacman. The reported detached-signature hash is
`09f56f26213a43d8f08929b790077dff7fa0abe526afeca3d66fc4ee6d39362e`.
Private pacman configuration requires local package signatures, has no remote
repositories, masks preexisting hooks and disables scriptlets for mutations.
This establishes TEST-signed local installation, not production repository or
key enrollment. It does not authenticate a new repository database.

| Checkpoint | Exact inventory | Enforced result |
| --- | ---: | --- |
| Install, ordinary -U |575 | Required-signature install; database/integrity checks and all17 installed hashes/modes/root UID/GID/package owners pass; terminal groups pass. |
| Remove, ordinary -R |574 | All17 package-owned files absent; guarded opt-in is harmless in fresh shells; user fixture files preserved. |
| Reinstall, ordinary -U |575 | Same archive/signature; full installed payload/integrity and terminal checks repeat successfully. |
| Final remove, ordinary -R |574 | Original exact inventory restored, payload files absent and fixture files preserved. |

No dependency bypass, recursive removal or changed-version upgrade is used.
The baseline/final inventory SHA256 is
`cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.
At all four checkpoints, file-path sets and file hashes/modes/UID/GID match for
an unprivileged alarm-owned fresh home and an existing home containing .zshrc
and .zsh_history. This is the implemented finite file comparison; it does not
claim directory metadata or whole-base/cache restoration. Masked hooks and
--noscriptlet do not suppress libalpm's existing implicit ldconfig helper on
eligible roots; these four mutations may update loader caches. No cache equality
or helper execution result is separately asserted.

## Installed native terminal behavior

The installed wrapper is tested as unprivileged alarm in private synthetic
homes after install and reinstall. Each invocation passes the same five groups:

| Group, passed twice | Concrete behavior |
| --- | --- |
| Noninteractive no-op | Repeated sourcing leaves highlighting unloaded. |
| Existing user module wins | An existing _zsh_highlight function survives repeated sourcing and the new module loader is not introduced. |
| Real ZLE editing, colours, bindings and hooks | Typed `print -r -- 'hello'` produces blue builtin/cyan quoted-argument regions; an unknown command is red; backspace changes its buffer; the preexisting custom widget sets `print -r -- custom` once and its redraw hook runs. Repeated opt-in preserves hook-array/binding and user style/highlighter choices. |
| Autosuggestions before highlighting | Typed `print -r -- fix` has POSTDISPLAY `ture-suggestion`; right-arrow accepts `print -r -- fixture-suggestion` and clears POSTDISPLAY; the custom widget and redraw hook remain functional. |
| Guarded opt-in simulated removal/reinstall | A separate copied runtime directory is moved away/back; the user source line and controlled history remain byte-identical. Actual package removal/reinstall is the separate four-checkpoint sequence above. |

There are **four real disposable PTY sessions and14 snapshots**, two sessions
and seven snapshots per installed invocation. The other three groups use
controlled Zsh -c processes. Startup marker files remain absent and controlled
history is preserved. Typed/accepted history and custom-widget buffers receive
no Enter; only fixed setup-source/exit commands are submitted. These finite
fixtures do not prove arbitrary plugin order, all7 highlighters' semantics,
older Zsh compatibility, a graphical terminal workflow or every user's config.
Already loaded functions in an old shell are not unloaded on package removal;
the absent-package checks use fresh shells and a guarded opt-in line.

## Cleanup and adoption boundary

The successful path stops the two private GPG homes' agents and exits its
TemporaryDirectory. Coordinator cleanup verifies absence of lifecycle container
`cachy-asahi-highlight-4d56d0ffae6f478d`, build containers
`cachy-asahi-378599727a622fb1` and `cachy-asahi-07c737b8fd80165b`, and newly created
image `sha256:c2144dd5fb8185bf2c6cad846aea88f6916623eabb3c755b0eb3c14144e4d5b1`.
This is scoped cleanup, not erasure of runner caches, Docker layers, retained
public archives or all host state.

The held8d8 bootstrap helper has a known interrupted-bootstrap/unnamed-probe
ownership limit: if bootstrap starts but does not complete, the caller reports
UNKNOWN retirement/FAIL cleanup and does not use an image ID as proof of safe
retirement. This actual completed bootstrap and cleanup; it does not validate
that interrupted failure path.

[Adoption map](../../artifacts/development/zsh-highlighting-run38802848134/review/adoption-map.json)
contains25 exact tested files:20 recipe inputs, three Zsh helpers and the two
absent held574 dependencies selected by Root. Existing eight shared dependency
files match tested Source and are unchanged. Workflow, existing selected10
recipes/locks, manifests and selection flags are outside this adoption. Generic
native testing here does not select this package for a release or close either
M2 Air's target terminal/install/hardware acceptance.
