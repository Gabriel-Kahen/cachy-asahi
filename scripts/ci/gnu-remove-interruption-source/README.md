# GNU766 remove-interruption source factory proposal

This standalone factory reproduces every file of public
`cc04fe3a57bac24a516004dfb670a172e76ac517`. Its explicit ordinary-directory inputs
are public749 `de1aab259df6bda8ad36f959392e3fc4eb35b622` and the 13-file normal
record `7ba9a2d8da09e17b0204546219d55cff414fcb8d`. All 766 output files must match
the pinned target map before staging and again before publishing the local
directory. All output file modes are 0644, including under a restrictive umask.

```sh
python3 -I -B -Werror prepare.py \
  --parent /absolute/ordinary/public749-export \
  --normal-record /absolute/ordinary/public13-export \
  --output /absolute/fresh/gnu766-source --known-context
```

Omit `--known-context` for the default NULL context. Both contexts emit exactly
the same 766 bytes and paths. Only the returned JSON's `known_parent_context`
boolean changes. Its `current_source`, `current_ref`, `current_run` and
`Root_acceptance` remain NULL in both contexts. `expected_source` identifies the
public reproduction target, not a new publication or acceptance. The returned
`files` object is the full flat output map; stdout may be retained outside the
input/factory/output namespaces by the caller.

All paths must be canonical absolute paths without symlink components. Inputs,
factory and output must be mutually disjoint. The output must be absent and its
ordinary parent must already exist. Supply Git exports without `.git` metadata.
The factory does not fetch inputs, run Git, start native/VM actors or install
packages. It never imports, executes, evaluates or compiles supplied source.

`profile.json` is hard-pinned by `prepare.py`. It holds the complete before,
after, normal-record and payload maps, nine changed leaves, 17 additions and
740 byte-held leaves. `payload/` contains three readable public source files and
`profile-operands.json`, the public interruption profile's remaining JSON DATA.
Counted text edits transform the five existing routes/test/template files;
the factory joins the normal record, assembles the exact interruption profile,
appends its deploy seal and regenerates manifest/workflow seals. It independently
inverts every edit and regenerates the old seals to recover every original749
byte. No complete historical source tree or compressed executable is bundled.

The runtime-profile maps and finite predecessor map in `profile-operands.json`
are pinned public DATA copied from the published target profile. Generation does
not recompute them by executing their source. Full target equality verifies their
reproduction; it does not execute the target's source guards or prove runtime
behavior. Source/record/payload bytes and file/directory identities are reread
immediately before staging, so same-byte inode replacement also refuses.

All 667 raw runtime leaves and the normal `fixed_case.py` remain byte-identical.
The exact output retains `validation_operation=normal` and case `both` defaults,
the explicit interruption case restriction, all existing deadline/security
predicates and the corrected ten-route deployment test. The existing
`gnu-fixed-case-cleanup-source` factory and its public747-to749 behavior are
unchanged; this proposal is independently installable beside it.

Run the focused tests with explicit ordinary public fixtures:

```sh
GNU_REMOVE_PARENT=/absolute/ordinary/public749-export \
GNU_REMOVE_NORMAL_RECORD=/absolute/ordinary/public13-export \
GNU_REMOVE_EXPECTED=/absolute/ordinary/public766-export \
python3 -I -B -Werror test_prepare.py
```

Tests compare every emitted byte to the independent target fixture, run real
known/NULL CLIs, check modes, forbid execution/process/network APIs during real
generation, and exercise input/payload/profile drift, alias/overlap/foreign-node,
late inode replacement and wrong-target refusals. They execute no supplied
source guards, native lifecycle, package transaction or VM. Native/M2/performance
and paired interruption acceptance remain outside this factory's authority.

The factory code is MIT-licensed under the repository LICENSE. Public source
payloads retain their SPDX notices. No package archive, private input or signing
key is included.
