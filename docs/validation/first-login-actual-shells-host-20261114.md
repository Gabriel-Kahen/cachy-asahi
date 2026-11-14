# Extracted first-login package: actual developer-shell journey

November 14, 2026. **PASS: finite software journey on the x86_64/4096-page
host.** This uses four actual unsigned host-assembled packages, their delivered
payloads, Fish 4.9.3 and Zsh 5.9.2. No project template or program-availability
substitute is used. Native ARM, package-manager installation, graphical login,
macOS installation, M2 hardware and release acceptance remain **NOT RUN**.

## Delivered inputs and dependency correction

The new opt-in first-login package is now `0.1.0-2` and requires
`cachy-asahi-setup>=0.3.0`. Its recipe, `.SRCINFO`, provenance, notice and guide
agree. This selects the Setup8 status/recovery contract instead of allowing an
older setup package to satisfy an unversioned dependency. No shared selection or
previously qualified recipe was changed.

All four archives were assembled from private copies of the actual recipes with
`makepkg --nodeps --noconfirm`, without installation or dependency acquisition.
Their declared source checksums and recipe checks pass. First-login runs its
14 focused/delivery cases; Setup8 runs its existing 29 migration and four package
cases. Fish and Zsh execute their recipe syntax checks. These are unsigned host
builds, not native builds or a reproducible-build pair. Bypassed dependency
checking does not qualify a target dependency transaction.

| Package | Bytes | Archive SHA-256 |
| --- | ---: | --- |
| `cachy-asahi-first-login 0.1.0-2` | 19471 | `d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839` |
| `cachy-asahi-setup 0.3.0-1` | 43046 | `175b11130bbe66f97cdef32c9e81aa5509390263dbd7c4d1470b9893946eb289` |
| `cachy-asahi-fish-config 0.1.0-1` | 13518 | `21f4ca0ab90c66b131673f2cb2c6caf85b72e2872777481d8118d9264b3d0c02` |
| `cachy-asahi-zsh-config 0.1.0-1` | 14474 | `0e88f366d93de023007a290678e38c37dda64d2c10036f763e4ee0c4de4cc9c0` |

The ignored local selection is
`work/first-login-real-inputs-20261114/inputs.json`, SHA-256
`d9357f36f0ebb2b4fa67b7cfae44c95928a8954eb8f1ebb0eab1580c57e5fce9`.
It contains exactly `first_login`, `setup`, `fish` and `zsh`; each entry provides
an absolute archive `path` and its reviewed `sha256`. First-login's archive is
in `work/first-login-build-20261114-r2/`; the other archives are in the selection
directory's `setup8/`, `fish/` and `zsh/` build directories.

## Actual execution

The new `scripts/integration/first_login.py` reads only explicitly selected
archive members. All six first-login payload files, the actual Setup8 command,
and the two actual package templates are staged in one owned temporary prefix.
No archive is installed on the host. The actual relocated first-login launcher
runs against this extracted setup command and template root.

The 41 recorded commands include these transitions:

1. Inspect an empty ordinary-user home and preview explicit Fish/Zsh activation;
   verify neither operation creates user files.
2. Apply through the real extracted first-login and Setup8 payloads. Start real
   interactive Fish and Zsh in PTYs. Exercise `caa_ll`, create/enter a directory
   with a space using `caa_mcd`, and verify Zsh's loaded flag and `cd` completion.
3. Append explicit user settings to both generated shell files. Repeat
   activation and verify the files remain byte-identical. Start fresh shells and
   verify both project behavior and the user's new settings.
4. Preview and apply deactivation with the real setup command. Start fresh shells
   and verify project functions/flags are absent while user settings still load.
5. Import the actual delivered Setup8 command in a child process and inject
   `os._exit(75)` immediately after its first durable Fish configuration write.
   This is a deterministic process-death injection, not an operator SIGTERM,
   power-loss or physical recovery test. The real pending journal remains.
6. Inspect that journal, refuse a new activation selection, and preview recovery;
   verify these three calls leave the pending home byte-identical. Explicitly
   apply recovery, confirm the real journal is removed, and verify both actual
   shells work with project behavior and preserved user settings.
7. Deactivate once more and verify both fresh shells retain only the user edits.

Ten actual shell startups pass across those five shell phases. Each command
uses the existing onboarding process/PTY runner's 20-second deadline and owned
process-group cleanup. Commands run with an explicit temporary HOME/XDG/ZDOTDIR,
minimal environment and private workspace. Program and payload digests, command
arguments, actual/expected exit codes, stdout/stderr and the result are retained.
All private home, prefix and workspace directories are removed after the journey.
The output directory retains logs only.

The recorded result is in the worktree's ignored
`work/first-login-actual-20261114/result.json`; `first-login-commands.json` has all
41 successful records, including the expected interruption exit `75` and
pending-state refusals `2`.

## Repeating the explicit check

Supply a reviewed four-archive selection using the same structure and a new
absolute output directory:

```sh
python3 -B scripts/integration/first_login.py \
  --inputs /absolute/inputs.json --inputs-sha256 REVIEWED_SHA256 \
  --output /absolute/new-evidence --run-temporary-journey
python3 -B -Werror::ResourceWarning scripts/integration/first_login_test.py \
  --inputs /absolute/inputs.json --inputs-sha256 REVIEWED_SHA256 -v
```

The explicit integration test file ends in `_test.py`, so ordinary
`test_*.py` source discovery does not execute extracted packages unexpectedly.
Its actual-journey case requires real programs and supplied archives; it does not
substitute availability or skip missing prerequisites. All three integration
cases pass with zero skips: the complete actual journey; wrong-package refusal
with private-state cleanup; and refusal to execute without the explicit flag.
The journey case also independently compares all four critical payload hashes
with the actual checked-in first-login, Setup8 and shell-package sources.

The script permits at most four 8-MiB archives, 100 unique member names per
archive, and nine selected runtime payloads of at most 1 MiB each. Archive
identities, selection and archive checksums are checked; no package scriptlet,
repository command, system installation or service operation is invoked.
This finite test does not qualify a complete release/base transaction, terminal
emulator usability, a real graphical session, target recovery or both M2 models.
