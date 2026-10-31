<!-- SPDX-License-Identifier: MIT -->
# Maintained current607 generic16K updater source factory

This directory contains a portable source constructor. It requires explicitly
supplied, complete source trees; it does not need an author's development packet,
an evidence directory, historical execution artifacts, or an external framework.
It reads its inputs as DATA and launches no package, Docker, QEMU or network actors.

The unchanged `factory-manifest.json` pins 22 members; with the manifest itself,
the original factory has 23 immutable files. This maintenance README is outside
that manifest and is not emitted. Keep those 23 files byte-identical: changing a
template, constructor, profile or test requires a separately reviewed factory.

Default construction reproduces the complete 360-file generic4K parent.
Explicit `generic16k` construction reproduces the complete 709-file source
published as `ae2ec5afbff72cfa20639feda54425b9b3cbe838` on
`codex/updater607-generic16k-path-v2`. Its full `parent360/` inverse remains held.
These are source identities, not execution or acceptance results.

| Explicit source operand | Immutable revision | Files |
| --- | --- | ---: |
| `--source` | `c6a5de859c3f190d47a5aef30962d2c3b50eaf8d` | 360 |
| `--fresh16k` | `0db9341521b5cb5d9022715b5ba638b3e4018462` | 1203 |
| `--held` | `b21a5864d5a4610b9181a1c270ac8821d8448a17` | 489 |

`profile.json` records every dependency member's byte count and SHA256. Supply
ordinary trees with exactly those payload maps; top-level Git metadata is ignored.
Symlinks and hardlinked source files are refused. Output must be fresh and
disjoint from all supplied source roles. The constructor rechecks complete inputs
and its own manifest before writing any output.

From a checkout containing this maintained directory:

```sh
python3 -I -B scripts/ci/updater607-generic16k-source/prepare.py \
  --source /ABS/UPDATER360 --output /ABS/FRESH_DEFAULT360

python3 -I -B scripts/ci/updater607-generic16k-source/prepare.py \
  --source /ABS/UPDATER360 --page-profile generic16k \
  --fresh16k /ABS/FRESH16K1203 --held /ABS/HELD489 \
  --output /ABS/FRESH_GENERIC16K709
```

The generic4K default refuses unused generic16K operands. Generic16K requires
both additional complete inputs. Its emitted profile keeps actual source/run/ref
and Root acceptance selectors NULL. No supplied source code is executed by
construction, and no dependency or kernel is acquired automatically.

Kernel DATA is a separate explicit input to the emitted runtime and controls:
exactly `Image`, `config` and `kernel-input.json`. `kernel-descriptor.json` and
`templates/kernel_data.py.in` hold the independent complete descriptor and byte
pins for `7.1.13-generic16k-managed-gui`, Linux/aarch64/16384-byte pages, with
modules disabled. The descriptor identifies a build-only artifact from source
`4056e2505ed7081674e949e0460258672cce14ff`, run `39156901928`; those bytes and
configuration geometry grant no boot result. An explicitly published three-file
checkout can be exported with emitted `kernel_stage.py --source /ABS/DATA_CHECKOUT
--revision EXACT_40_HEX_DATA_COMMIT --output /ABS/FRESH_DATA3`; that stage uses
read-only Git object checks and does not acquire inputs.

The retained `tests/test_vm_run.py` exercises the actual `transport.run` call,
using the real pinned three-file DATA input, and stops at the first Docker-inspect
command boundary. It covers all three fixed cases, signer-path refusal and Image/
config tampering. `OLD_UPDATER16K_SOURCE` must explicitly identify the genuine
`b042…` production counterfactual: its `bytes`/`str` path-shadowing `TypeError`
occurs before external commands. This is a full run-prefix regression, not a
helper-only substitute, and it does not execute a VM.

Run the original pinned controls only after independently provisioning all roots:

```sh
UPDATER_SOURCE=/ABS/UPDATER360 FRESH16K_SOURCE=/ABS/FRESH16K1203 \
HELD_SOURCE=/ABS/HELD489 EMITTED_SOURCE=/ABS/FRESH_GENERIC16K709 \
KERNEL_DATA_SOURCE=/ABS/DATA3 OLD_UPDATER16K_SOURCE=/ABS/EXACT_B042_SOURCE \
python3 -I -B -m unittest discover \
  -s scripts/ci/updater607-generic16k-source/tests -p 'test_*.py' -v
```

Source construction, source controls and an intercepted run prefix establish no
current generic16K transaction result. Native/VM normal, precommit-exit86 and
postcommit-exit87 execution, natural exits, retirement, M2 hardware, performance
and release admission remain separate gates. The enclosing transaction stays
3900 seconds and the outer worker 15600 seconds; deadline fit remains unmeasured.
