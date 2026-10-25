# Fixed producer failure diagnostic source

This source-only factory reproduces public1185
`2235c1d3c3b3de6d8a2ff30f66c5fd0df56c2ef6` from only public1182
`9a67f3e507c57f68ece48c253cdade47648f970c`. It holds 1,177 files,
changes five seals/integration operands and adds three source helpers. The
readable transform restores the complete original run body. The emitted guard
reconstructs and executes the entire1182→1180→1178 source entry, including its
older source guards. Package versions, target lock, workflow template, runtime
clocks, security and positive acceptance criteria are unchanged.

```sh
python3 -I -B -Werror scripts/ci/fresh607-producer-diagnostic-source/prepare.py \
  --source /ABS/public1182 --output /ABS/fresh-source \
  --authorization /ABS/fresh-authorization.json --context known
```

Output and authorization must be absent and disjoint from each other, the input
and this factory; their canonical ordinary parents must already exist. Use
`--context null` for the same exact source bytes without the output publication
identity in the receipt. Neither receipt confers source/run, fresh installer,
baseline, cleanup, native, hardware or release authority.

The source-owned runtime helper captures only the fixed producer updater build
role and its six fixed bounded private logs into the existing failed JSON report,
before original cleanup. Original failures, retirement, positive return and report
bytes remain authoritative. Captured tails are DATA with no acceptance or cleanup
authority. There is no collected-code execution or new native actor.

`input-source.json` and `output-source.json` cover every source file.
`parent-codecs.json` retains the five published historical codec DATA streams:
linked zlib versions need not emit identical compressed bytes. The factory
requires bounded complete decoding to equal each exact readable supplied parent
file before using this metadata. It never executes compressed metadata. Templates
and metadata are individually pinned by `profile.json`, itself pinned by the
entry point. The actual command tested by the runtime controls comes from the
supplied public1182 `installer604` namespace, not a development artifact.

The read-only hosted matrix exports ordinary trees from the two pinned public
commits, then runs both source and private host controls on Python3.12 and3.14.
Locally, set `FRESH607_DIAGNOSTIC_INPUT` and `FRESH607_DIAGNOSTIC_EXPECTED` to those
ordinary source trees, then run `test_source.py` and `test_runtime.py` with
`python3 -I -B -Werror`. These controls neither install packages nor run native
VM actors. Native diagnostic source execution and any eventual installer or
hardware acceptance remain separate evidence.
