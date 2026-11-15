# Rust work-volume Source successor

This is a narrow, unexecuted successor to the old 277-file Rust Source DATA
checkpoint from development commit `0e89be82`. The old constructor, profile,
Source output, candidate, source/intake records, licenses, recipe, Rust flags and
resource proposal remain unchanged. The successor has its own constructor,
profile, inverse, DATA controls and validation record.

LLVM v1 run `43712154101` built its 349-package image and its Root0 chown CLI
returned zero, then the nonroot builder failed creating `/work/home`. Actual
ownership at that boundary was not captured. Copy-up is an unproven possible
explanation. The source lesson comes from corrected LLVM Source
`724f6b74ebd7c42dfae1d607e28d81a734538b80`; this Rust change does not claim that
Source or this route has passed a native trial.

The old Rust producer has the same risk pattern: it starts initialization before
creating preparation, omits `volume-nocopy`, and records no actual owner state.
This successor creates and inspects preparation and initializer before the final
ownership mutation. Every reference to the work volume uses `NoCopy`, including
the two read-only stage0 subpath mounts. Main is created after preparation because
those subpaths must exist first. Reinspection binds the already-created actors
to stable IDs, exact Source/image/token labels and unchanged mount/cap domains.

A single Root0 initializer retains the existing 60-second, two-CPU, 128-MiB,
zero-swap, 32-PID proposal, with CHOWN as its only capability. It opens the empty
Root-owned volume through a held ordinary directory descriptor, sets mode 0700
before changing ownership to 1001:1001, and records actual before/after device,
inode, owner and mode. It does not recurse. The receipt must join the exact
Source, image, Root-admission hash and volume binding and a naturally retired
initializer with stable container ID. No additional actor or budget is added.

Before the first work-directory write, preparation verifies the same initialized
inode, actual nonroot identity, owner, 0700 mode, emptiness and write access.
Main verifies the same root after preparation and requires it to be nonempty.
These checks do not create a probe file. Raw work-root stat observations are
emitted to stderr before open/verification, so failed pre-entry still retains
observed ownership in the host-owned command logs. Successful observations are retained
in output DATA. Nested build/package entries rejoin the volume proof and retain
the original phase checks; their libc ownership check is delegated to outer main
to avoid treating fakeroot's reported uid zero as actual kernel ownership.

The new deterministic volume admission is separately pinned before preparation
is created. The subsequent actual initializer receipt is joined through that
binding; no future receipt hash is invented. Input snapshots reserve exactly the
two new evidence names. Their bytes and host observations are retained with the
existing finite artifact paths. Forced cleanup, identity drift, initialization
failure or missing final absence remains FAIL, including after diagnostic export.

Only the work-volume producer, outer entry checks, contract/audit metadata and
retention operands change in generated Source. The entire old 277-file checkpoint
is recoverable with the successor inverse. The native operation, alias, shared
lane, package/source/Root qualification gates and all existing holds are kept.
In particular, accepted LLVM material is still separately gated by the old exact
LLVM Source pin; this volume-only revision does not promote the newer LLVM Source
or supply an accepted package. Root must explicitly reconcile that material pin
when a successful accepted LLVM Original exists. External material transport,
normal image/stage0 qualification and all current Rust Source/run/job bindings
remain NULL. No worker, compiler, daemon, network acquisition or lease ran here.
