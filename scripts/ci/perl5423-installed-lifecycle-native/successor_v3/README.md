# Retained installed-lifecycle results, v3

Native run43728748795/job132856306730 reached a naturally exited non-OOM actor,
then failed exporting `/work/result`. The actual 143-byte missing-file diagnostic
and empty run streams are retained. `/work` was a tmpfs, and Source exported only
after stop. That retention mismatch supports this correction; actual tmpfs unmount
and transient result contents were not observed. Exit0 gives no lifecycle credit.
`data/installed241-failure.json` pins the actual DATA and independent diagnosis.

The actor now creates `/cachy-asahi-perl-lifecycle/result` in the already-owned
writable container layer. The parent must be absent; mkdir refuses races. Both new
directories must be ordinary0700 directories with Root0:0 ownership on the containing
root filesystem. Native caller path/UID/GID are fixed in Source. The helper's owned
temporary tests use the caller's ordinary UID and do not touch host root paths.
The actor records `retained_output`; producer export uses the identical path and
requires the exact report proof. Basename `result`, TAR shape and64MiB export/
16MiB report/<160member reader limits stay unchanged. These are existing read/export
limits, not a new filesystem quota. `/work`, `/run`, `/tmp` scratch tmpfs and all
mount/capability/resource/normalALPM/hook/trust/rollback policy remain unchanged.
The retained directory disappears only with the exact owned container.

Only actor/producer and their two capsule copies change; ten parent core files and
seventeen capsule members stay exact. `contract.json` explicitly declares retention
revisionv3 and preserves the prior capability adapter as historical metadata.
Changed small metadata/old actor/producer/inner map support full252→241→232 and
original200 inverses. Old capsules are reconstructed deterministically; no extra
40MiB capsule is archived. All new Source actual selectors remain null.

The constructor imports the exact read-only siblingv2 DATA helper (pinned in code),
which uses the existing passive filesystem helper. In an isolated checkout lacking
that parent helper, supply its exact bytes using `CACHY_PERL_INSTALLED_V2_FILESYSTEM`
as documented by successor_v2. No package or input Source module is imported.

```sh
python3 -I -B -m unittest discover \
  -s scripts/ci/perl5423-installed-lifecycle-native/successor_v3 -p 'test_*.py' -v

# Explicit finite retained-parent DATA check; does not write an export.
python3 -I -B scripts/ci/perl5423-installed-lifecycle-native/successor_v3/check_parent.py \
  --previous-source /absolute/path/to/the/exact241/source-tree
```

Twelve fenced controls cover creation/alias/race/ownership/mode/filesystem refusal,
unchanged code, exact producer proof and a focused positive/negative unmodified
Reader predicate seam. That seam uses synthetic DATA only; it does not run a Reader
role or its complete bootstrap/removal/acceptance checks. Hosted Reader and capsule
read_result.py are unchanged and use the same result/report.json namespace.
No actor, ALPM, GPG, network, lease, POST, operational Reader or Source export ran.
Root must separately export/publish a fresh Source/ref and bind updated once/Reader
contracts and explicit output retention review before another actual attempt.
