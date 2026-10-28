# Retained systemd-hook and sysusers body semantics

This is a passive text/data audit. Root's retained actual intake completion
`be51827b075220b6b8a7f40234c91dc7c0e26a902b269206ce46610b267963c1`
and all nine indexed leaves authenticate. Its 19 bodies total 6,953 bytes from
nine archives: the 1,799-byte systemd-hook and 18 sysusers configurations totaling
5,154 bytes. Every proof hex body matches its recorded length, SHA256 and UTF-8
text. This audit did not repeat intake, signature verification or native
cleanup. No host account files, raw archives, network, target interpreters,
hooks, installation, image or target-library actors were used.

The independent actual02 peer receipt
`4df7f32712d2ddd626813b0d37c1a1e5ead65c0baa4d40b7ef2f176951cb17c5`
and its 29 indexed artifacts were also authenticated and privately copied.
Its natural-completion/reaping statements remain retained observations;
this audit does not replay live cleanup or promote its false non-data flags.

The prior dependency/hook author receipt
`1464521766250160bc8787c36a1c4e6caad11322ceec013c87834a58004180e5`
and its 13 indexed leaves, plus Root peer
`7b2affa6fff87c8126d4816cf5e8fe24b32b7bd281fe4f7d96f24fbf8f37ea74`
and four indexed leaves, were authenticated and privately copied. The original
45,966,493-byte retained payload **JSON** was separately hashed against
`7df4b87a2d8d31455fa0e8cf30e2f53eed65cacbb2d2dbe7dd395b9484ecf314`.
Its 31 hook and 23 INSTALL texts were extracted as inert data, with every
20,885 aggregate text byte bound to the prior exact tuple/path/node hash and
length. No package archive was opened to do this.

The review artifacts are under
`artifacts/reviews/platform-systemd-sysusers-body-semantics-proposal-20261013/`.
`authentication.json` records capture checks; `inputs/prior-control-texts.json`
retains the 54 old control texts; `hook/` maps commands and joins; `sysusers/`
contains the 64-rule table and unresolved collision/allocation cases.

## Callable hook routes

The selected systemd 262-1 helper body has SHA256
`90e00dd01359565be85a8cdd93b424b4c1c89563300d16eaf0e7eedc349bf9fc`.
It declares `#!/bin/sh -e`, copies the first positional argument to `op`, shifts
it, and dispatches 13 named operations. Only `reload` and `restart` forward the
remaining quoted arguments to systemctl. Other branches do not consume those
arguments as selectors. Actual shell resolution, ALPM invocation, stdin,
environment, error handling and root/CWD behavior need pinned runtime evidence.

| Operation | Literal action after declared guards |
| --- | --- |
| binfmt | `/usr/lib/systemd/systemd-binfmt` |
| catalog | `/usr/bin/journalctl --update-catalog` |
| daemon-reload-system | `/usr/bin/systemctl --system daemon-reload` |
| daemon-reload-user | `/usr/bin/systemctl reload 'user@*.service'` |
| hwdb | `/usr/bin/systemd-hwdb --usr update` |
| sysctl | `/usr/lib/systemd/systemd-sysctl` |
| sysusers | `/usr/bin/systemd-sysusers` |
| tmpfiles | `/usr/bin/systemd-tmpfiles --create` |
| update | `touch -c /usr` |
| udev-reload | reload; conditionally trigger change then settle |
| enqueue-marked | `/usr/bin/systemctl enqueue-marked` |
| reload | `/usr/bin/systemctl try-reload-or-restart "$@"` |
| restart | `/usr/bin/systemctl try-restart "$@"` |

The live guard first calls PATH-resolved `systemd-detect-virt --chroot`, then
`systemd-notify --booted`. The udev branch also checks `/run/udev/control` for a
socket and conditionally skips trigger/settle when
`/etc/systemd/do-not-udevadm-trigger-on-update` exists. These are branches in
text, not observed outcomes. Catalog, hwdb, sysusers, tmpfiles and update lack
the live/chroot guards. In particular, sysusers and tmpfiles are direct calls
with no explicit `--root` or selected-file arguments. Root isolation therefore
cannot be inferred from the helper. Unknown operations echo an error and exit
1; successful textual paths reach exit 0, subject to the actual shell/runtime.

Thirteen of the retained 31 hook actions name this helper: 11 from systemd,
dbus with `reload dbus`, and openssh with `restart sshd.service`. The sysusers
hook is `20-systemd-sysusers.hook`, PostTransaction for installed/upgraded
`usr/lib/sysusers.d/*.conf`. Filename presentation order alone does not prove
effective ALPM ordering, override selection, dependency readiness or triggers.
Other hooks include protected Asahi/boot/kernel and cache actions; those remain
separately unaccepted.

The raw systemd INSTALL adds a second route: `post_common` calls PATH-resolved
`systemd-sysusers`. `post_install` first calls `systemd-machine-id-setup`, then
`post_common`, then enables getty, remote-fs and userdbd units. `post_upgrade`
calls `post_common` before its booted-system guard. The script also writes
`etc/shells`; upgrade reexec/reload/restart markers and removal edits require
their own effect review. Its Bash shebang/constructs do not prove the interpreter
used by libalpm's callback dispatcher. Bootloader-related echo text does not
authorize changing the Asahi boot path.

Thus sysusers may be called at scriptlet and post-transaction phases, with
different visible configuration files and account preimages. A final-only
configuration pass cannot establish dynamic IDs, idempotence or actual effects.

## Account declarations and ordering gaps

The 18 configs contain 64 lexical rules: 38 `g`, three `u`, 18 `u!` and five `m`.
There are 32 literal dash IDs: 20 group and 12 user declarations. All 21 user
rules omit a shell token; 18 lack an explicit colon-form primary-group token.
Omission and `-` remain distinct. No locking, default home/shell, automatic
group, allocation range or precedence behavior is inferred without the exact
systemd 262 parser/manual and packaging/build correspondence.

Group `root`/GID 0 appears in both arch.conf and basic.conf. This is a repeated
same-name/same-ID declaration. No distinct-name explicit numeric UID or GID
collision was found within either namespace. That is not a collision-free
runtime proof. User mail's UID 8 versus group mem's GID 8 is cross-namespace;
mail UID 8 versus its named group GID 12, and ftp UID 14 versus its named group
GID 11, require primary-group semantics and prestate. No implicit GIDs were
invented. The five membership lines likewise do not establish actual members.

The retained graph remains metadata: 261 nodes, 1,020 runtime relations,
152 versioned relations and 259 components. Its cycle is gdk-pixbuf2/glycin/
librsvg. Provider alternatives remain curl's ca-certificates and systemd's
dbus-units. No provider preference, cycle break, comparator replay or executable
transaction order was selected. Older payload coverage remains 258 exact rows;
current NetworkManager, Perl and Python control coverage must be reconciled.

## Smallest next action

`remaining-inputs.json` identifies six finite input groups. First supply the
corresponding pinned systemd 262 parser/manual/packaging subset and pacman/
libalpm dispatch semantics as inert source evidence. Confirm rule defaults,
implicit groups, allocation/lookup, duplicate handling and effective config
ordering before proposing any execution.

Then Root must select a retained or disposable target account prestate for
passwd/group/shadow/gshadow, or witnessed absence, with content/metadata custody;
the complete effective config namespace at **both sysusers call phases**;
provider/cycle/bootstrap decisions and exact package-operation sequence;
effective ALPM flags, hook overrides, trigger/callback arguments, root/CWD and
environment; and the first-action interpreter/executable/library/source/license/
crypto closure. This audit requests no host account-file reads and invents no
preimages. Selecting a whole INSTALL also requires machine-id, shells and unit
enablement expectations, beyond the account-only hook.

Only a separately selected isolated trial with finite before/after,
repeat/interruption/upgrade/removal/recovery oracles can establish account and
trigger effects. The 39 tmpfiles bodies, other hook/scriptlet effects and
current-tuple gaps remain separate required work. All Source, license, crypto,
runtime, account-policy, installation, image, recovery and hardware acceptance
flags remain false. This narrows R1/M5 bootstrap and R5/M8 inputs; it does not
complete R1–R5, M5–M9, or the full installation gate.
