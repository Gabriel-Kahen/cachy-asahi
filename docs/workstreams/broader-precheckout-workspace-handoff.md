# Private precheckout workspace handoff

The retained launcher now reserves an owned fresh sibling of the existing
Actions workspace before bootstrap preparation. This is an executable private
correction with filesystem fixtures and actor models. It has not run against an
Actions runner, network, Git, Docker, native build, real grant or real clock.
Root owns primary workflow adoption, final code/data commits, maps and dispatch.

The new packet is
[`artifacts/reviews/broader-precheckout-workspace-handoff-20261013`](../../artifacts/reviews/broader-precheckout-workspace-handoff-20261013/).
Its `launcher.py` is **25,691 bytes**, SHA256
`a0df5e194c975812af9413cbd6d494c0e50bea6e892a0685377e8f01f6f0c60c`.
The prior launcher `5f4d1fe40f84c515f4a8e959eb09d19cbc43ff0dafadadcdd015b7df4db508b8`
and receipt `d491f816f16374e412f51f58a123d177572eef067ecef5cb9c663b5e052c572a`
remain unchanged. The original 75 tests replay successfully against the new
library's retained no-owner branch; 16 original definitions are identical by
AST. Only `run`, `checkout`, and `_launch` gain the private custody forwarding.
The new composed branch has separate focused and independent peer coverage.

## Concrete selection and custody

`launch_composed()` captures its actual monotonic entry or accepts the trusted
inline first-step entry, requiring a finite positive non-boolean value no later
than actual entry. Selection, body delivery and bootstrap preparation share
that entry's original 60-second endpoint. An old entry shortens this interval;
a future entry is refused. The selection does not issue a clock.

Given the existing `GITHUB_WORKSPACE`, the sole selected path is

```
original.parent / (original.name + '.composed-' + run_id + '-' + run_attempt)
```

The run and attempt use the accepted closed decimal patterns: positive digits,
at most 20 and 10 characters respectively, with no leading zero. Workspace and
runner-temp paths must be canonical absolute paths, with no dot/dot-dot/NUL,
at most 4,096 characters and 64 components. Every component is opened using
directory-relative `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` traversal. Missing
future parents and symlink components are refused rather than created or
resolved. The original directory and runner-temp directory must belong to the
runner UID; the held original parent must also belong to that UID and have no
group/other write permission.

Both the original and selected workspace must be disjoint from `RUNNER_TEMP`.
Adjacent sibling temporary directories are allowed. Selection refuses every
existing leaf entry, including an empty directory, regular file or symlink.
It then creates the single sibling at mode 0700, compares its named creation
identity to the opened descriptor, and retains that descriptor plus original,
parent and temporary ancestry descriptors. It never removes or moves the
existing default workspace or any foreign entry. Failure may leave the newly
created private sibling; the implementation performs no recursive deletion.

The owner returns a narrow copy of the job environment, changing only
`GITHUB_WORKSPACE`. Run/attempt, source/workflow SHA, `GITHUB_ENV`, repository and
all other entries retain their values. The caller's environment and
`os.environ` are not rewritten. Accepted bootstrap preparation, the one issuer,
the six Git commands, checkout verification, packet authentication, controller
argv/environment and cwd all use that selected path. A private
`prepared['workspace_owner']` reference forwards custody inside the process;
it is not serialized into an actor contract or given authority to select
Source.

Checkout accepts only this owned empty inode in the composed branch. It checks
all retained named and descriptor identities before and after each Git command.
`run()` receives the same private owner and checks it after argument/environment
materialization immediately before `Popen`. The same checks precede bootstrap
verification and controller launch, and follow child exit. Directory identity
excludes link count because checkout legitimately creates child directories.
Emptiness checks rewind the retained directory FD before listing: initial
testing exposed a real directory-offset bug that could otherwise miss a file
added between checks. The old failing body and corrected regression evidence
are retained; reconstructed historical bytes are explicitly labeled.

All allocations and registration occur while controls are deferred. Both an
inner selector unmask failure and an outer return/assignment unmask failure
attempt retirement of every held descriptor. Retirement verifies descriptor
identity and makes one close attempt per owned FD, preserves the first execution
failure, and refuses a healthy result when close identity/faults are ambiguous.
Descriptors remain held until the sole controller has exited. Successful
completion checks the unchanged workflow endpoint after retirement and after
timer/handler restoration.

## Existing execution boundaries

This correction retains the pinned bootstrap
`507e5ac1cecbb1a82d38f2bdee077d24cc73e69b4f9f4f8ae1cbbaab05ee92d4`
and issuer
`9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581`.
It preserves grant17, runtime3, clock12, the 10,800-second allowance, six
path/hash bindings, the exact `repository-svg`258 and `installer-preflight`265
modes, and one issuer/controller invocation. It creates no Source copy/view
other than the existing canonical checkout and no second Source authority.

Checkout, verification and final pre-spawn eligibility still use
`J = min(workflow_end - 120, early_entry + 10080)`. Controller publication and
final retirement use the original workflow endpoint. Neither the workspace
selection nor the 180-minute scheduler cap renews the clock. The fixed Git
origin, pin checks, sanitized environment and command/output limits are retained.

`root-first-step.py` embeds the exact separately hashed new body and calls
`launch_composed()` with its original pre-import preparation entry.
`workflow-excerpt.yml` contains that identical inline step before checkout.
Manual Root inputs remain environment values, without raw shell interpolation.
No selected data commit or default pin is supplied. The header and excerpt were
compiled/authenticated as data, not dispatched.

Read-only hashing found the live controller and its test identical to Root's
selected early-entry sources:
`2bba69dd425cb9a8dd0f246e293c3091487f1367504860f7cad8a345e5d0cd61`
and `28a9f098694c92a6c168530db07b6fd738485368fb272dcc4c21832c01ae65bf`.
This worker did not rerun their controller suite. Root's reported selected
258/265 source-packet pins are recorded in the parent receipt, not treated as
final workflow-bound packets. The retained library's historical scope string
describes the bridge dependency; it does not override these verified source
hashes or establish end-to-end admission. Final code/source/peer registration,
the later data-only commit and manual pins, primary workflow adoption and actual
private-runner/interpreter verification remain with Root.

## Finite evidence and limits

The test-author receipt records 25 focused checks. The parent repeats the 75
held original tests once against the new library. Independent peer controls
exercise owned filesystem custody, the genuine directory-offset regression,
inner/outer cancellation, post-creation leaf replacement, six-command owner
forwarding and the unchanged deadline/environment handoff. These counts can
overlap and are not added into a claim of unique tests. Historical incomplete
API and fixture diagnostics remain distinguishable from source failures.

No pathname checks, mkdir/open pairing or held FD provide atomic protection
against a concurrent privileged or same-UID namespace attacker. The finite
checks detect observed substitutions at the specified gates. Persistent close
faults, physical OS scheduling and actual process descendants remain unproved.
The retained sibling and descriptors are custody evidence, not physical
filesystem disposal or revocation. Package, Asahi hardware, ARM build,
performance and full-port acceptance remain governed by the current outline
and roadmap; this handoff marks none of those gates passed.
