# Development onboarding example

Use this exercise after the accepted installation and first login. From an
ordinary terminal, you will clone a reviewed local Git revision, build and run
the pinned MIT-licensed C example, edit your own copy, then rebuild and run it.

You need an already installed Git, Python 3, a C compiler available as `cc`, and
an editor such as Vim or Nano. Run without `sudo`. From the reviewed project
checkout, choose a fresh path outside that checkout. Resolve any missing tools
through the accepted base transaction before beginning the exercise.

```sh
work="$HOME/cachy-asahi-development"
revision=$(git rev-parse HEAD)
python3 examples/development/onboarding.py prepare "$work" --revision "$revision"
```

The command takes a shallow, sparse local clone into `$work/checkout`, verifies
the original `hello.c`, and runs the baseline. Expect `Hello from cachy-asahi`.

Open the copy in your editor. In the `puts` call, change the greeting to
`Hello from my installed terminal`, then save it and close the editor.

```sh
vim "$work/checkout/examples/development/hello.c"
python3 examples/development/onboarding.py rebuild "$work" \
  --expect "Hello from my installed terminal"
```

You can choose a different greeting and pass that same line to `--expect`.
Both builds use `cc -Wall -Wextra -Werror -O2`. The exercise keeps the edited clone
and creates a separate directory for each build report, source snapshot and
available executable under `$work/evidence`. The reports include the exact Git
commit and source and binary hashes, compiler version, and compile and run
commands, outputs and exit codes. A failed rebuild leaves your edit and previous
evidence available so you can correct the source and try again.

To review a completed exercise, use the `rebuild-*` directory from the successful
command's printed evidence path. A second operator can copy that directory and
its sibling `baseline` into the same parent directory, keeping both names.

```sh
python3 examples/development/onboarding.py verify "$work/evidence/rebuild-REPLACE"
```

The readback checks both saved sources and executables against their reports,
the recorded commands and output, and the shared source revision. It prints
both report SHA-256 values for comparison with the producer's copy. The readback
uses the saved files and leaves both executables unrun. Review the reports for
local paths before sharing them.

For the independent installation exercise, record the exact machine, installed
base and overlay versions and whether you used a real desktop terminal and edited
the example yourself. The script records build and run observations. It leaves
editor behavior, lock and resume, and M2 acceptance to the target exercise.
Development-host execution and scripted-editor smoke are separate evidence.
