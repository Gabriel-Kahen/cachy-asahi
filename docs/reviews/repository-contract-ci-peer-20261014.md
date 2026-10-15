# Repository contract CI review

PASS for the corrected workflow logic; current product failures remain exposed
and must be fixed before a green complete CI result. Root owns all workflow edits.
This peer edited only its new capsule and this guide.

The initial provisioning command omitted `makepkg` with
`--no-install-recommends`. Ubuntu Noble's
[vercmp manual](https://manpages.ubuntu.com/manpages/noble/man8/vercmp.8.html)
assigns that binary to `makepkg`; the
[pacman-package-manager package](https://packages.ubuntu.com/noble/pacman-package-manager)
only recommends it. Root corrected the command and version capture to name
`makepkg` explicitly. Both packages are available as `6.0.2-6ubuntu2` in Noble's
universe repository; [makepkg details](https://packages.ubuntu.com/noble/makepkg)
and [repo-add manual](https://manpages.ubuntu.com/manpages/noble/man8/repo-add.8.html)
support the package/tool split. Current workflow SHA256 is
`e9a137b6accc99ca1ad80af6af613984f25a5844057fb2371afc4d84f7d99096`.

The apt step runs in the declared disposable `ubuntu-24.04` GitHub runner and
provisions gnupg, libarchive-tools, pacman-package-manager and makepkg. It checks
all five required executable names and records installed package versions. It
does not invoke pacman, change production signing custody or install packages
onto an Asahi target. No host package install or live API operation was performed
by this peer. Availability is supported by official Ubuntu sources; actual hosted
apt resolution and runner execution remain CI observations to be made after
publication, not a local Ubuntu-runner result.

The release suite moves from permissive discovery into the new explicit runner,
alongside the client suite. Each directory gets a new `TestLoader`, avoiding its
retained top-level-directory state. Current test basenames are disjoint; a
future duplicate basename causes standard discovery to refuse rather than
silently select the wrong file. Failures, errors, skipped tests (including
class-level skips) and empty suites fail the inline process. A successful first
directory cannot mask failure in the second. Its heredoc indentation and Python
syntax were checked directly; the shell prerequisite loop passes Bash syntax.
No dedicated YAML parser is installed locally, so this report does not claim an
independent parser run. The structure is the existing valid workflow plus two
ordinary steps; GitHub workflow parsing remains an external check.

Thirteen inert controls execute the exact extracted inline Python or prerequisite
loop: successful two-directory execution with distinct loaders; test/class skips;
failure; error; empty suite; all tools present; each of five missing tools; and
actual loader basename collision behavior. All pass. They perform no package,
native actor, GPG, network or system-trust operation.

Root's exact local runner log is retained separately: release 82 PASS, client
107 tests with 1 failure and 7 errors. The client failures expose the native
stage adapter's historical frozen client37/source hashes disagreeing with current
client48 Source. They are not waived, skipped or attributed to workflow logic.
That adapter needs a separately reviewed explicit Source rebase. Historical
native37 evidence remains historical. Root's local endpoint20 and prior release/
exporter crypto results are real no-skip runs; old hosted CI skipped those tests
when required tools were absent. The new workflow's eventual CI result must be
read for actual counts/skips, not inferred from discovery or overall success.

Capsule: `artifacts/reviews/repository-contract-ci-peer-20261014/`. It preserves
the initial faulty workflow, corrected exact workflow/inline bytes, official
source observations, inert controls and Root's failing full-suite log. Its
read-only seal check authenticates the finite review; it proves no native ARM,
M2 hardware, production trust, full-port admission or currently green hosted CI.
