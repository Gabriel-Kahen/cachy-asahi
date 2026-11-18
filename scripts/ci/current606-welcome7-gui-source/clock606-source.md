# Current606 16 KiB guest clock source emitter

The emitter reproduces [source 542b9247](https://github.com/Gabriel-Kahen/cachy-asahi/tree/542b9247ef45ab70c918991f415821d178d5da86)
from the ordinary 591-file tree of [source f4153868](https://github.com/Gabriel-Kahen/cachy-asahi/tree/f41538685c55b744410b657506745d654e142d09).
It checks the complete parent manifest, every original file body and mode,
and the parent Git tree. It writes a fresh 592-file directory and verifies
the exact published Git tree and successor manifest. A copy of the parent
with different file timestamps produces identical bodies and modes.

Given an owned extraction of the exact parent commit, run the emitter from
the maintained repository. Use a fresh output path outside the parent tree.
An existing local Git object store or the retained source bundle can provide
the parent through `git archive`. Preserve the archive's file modes when
extracting it under a restrictive umask.

```sh
lane=scripts/ci/current606-welcome7-gui-source
parent_commit=f41538685c55b744410b657506745d654e142d09
git -c tar.umask=0022 --git-dir="$local_source_git" archive "$parent_commit" | tar -xp -C "$parent_dir"
python3 -I -B -Werror "$lane/clock606_source.py" \
  --parent "$parent_dir" --output "$fresh_successor"
```

The successor adds `factory/guest_clock606.py` and changes only
`admission.py`, `factory/factory.py`, `factory/service_capacity.py`,
`native.py`, and `source-manifest.json`. The 586 other parent files
retain their exact bytes and modes, including the package inventory,
kernel inputs, TEST signer selection, public key, and workflow.

The clock helper is copied as source data. During a later owned
generic16k attempt, it records a controller clock sample and stages
systemd's fixture-local clock floor. The generated guest checks that
floor before its first pacman command. The service wrapper can invert
the source changes to verify its original factory. The native exporter
joins the clock observations to the existing ownership record.

The emitter runs independently of the TEST certificate's date window.
Its output carries the same source-only status and empty run binding.
Clock execution, signature verification, publication, and the hosted
reader and site run have separate entry points.

Run the offline controls against the exact parent and an optional
reference extraction of the successor.

```sh
python3 -I -B -Werror "$lane/test_current606_clock_source.py" \
  --parent "$parent_dir" --reference "$published_successor"
```
