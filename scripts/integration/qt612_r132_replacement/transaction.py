# SPDX-License-Identifier: MIT
"""Swap the Qt provider and reverse it on the existing disposable Asahi629 target.

Run after the R132-derived Asahi629 runner has checked its rollback lock,
while its target API mounts and private, reviewed public keyring are active.
The caller owns the one-use authority, target isolation and retirement.
This module has no command-line entry point.
"""

from contextlib import contextmanager
import ctypes as ct
import json
import os
from pathlib import Path
import re
from runpy import run_path
import subprocess
import time


P = run_path(str(Path(__file__).with_name("prepare.py")))
A = P["A"]
need, pin = P["need"], P["C"].pin
OFFICIAL, PROJECT, VERSION = (P[key] for key in ("OFFICIAL", "PROJECT", "VERSION"))
TARGET, MEDIA, WORK = map(Path, ("/trial-scratch", "/trial-inputs", "/trial-work"))
RECEIPT = "QT629_PROVIDER_TRANSACTION_V1"
PASS = "PASS_QT629_PROVIDER_ROUND_TRIP"
HOLD_BASELINE = "HOLD_QT629_BASELINE_PRECOMMIT"
HOLD_RESTORED = "HOLD_QT629_OFFICIAL_RESTORATION_VERIFIED"
HOLD_DISCARD = "HOLD_QT629_DISCARD_CLONE"
REQUIRED_TRUSTED = 1  # ALPM_SIG_PACKAGE, with no optional or trust-relaxing bits.
CONFLICT_PKG = 1 << 2
DEPENDENCY = 1
AS_DEPS = 1 << 8  # ALPM_TRANS_FLAG_ALLDEPS, used only for the one incoming provider.
NONCE = re.compile(r"[0-9a-f]{32}")
FINGERPRINT = re.compile(r"[A-F0-9]{40}")


class List(ct.Structure):
    pass


Ptr = ct.POINTER(List)
List._fields_ = [("data", ct.c_void_p), ("prev", Ptr), ("next", Ptr)]


class Question(ct.Structure):
    _fields_ = [("type", ct.c_int), ("answer", ct.c_int)]


class Conflict(ct.Structure):
    _fields_ = [("incoming", ct.c_void_p), ("installed", ct.c_void_p), ("reason", ct.c_void_p)]


class ConflictQuestion(ct.Structure):
    _fields_ = [("base", Question), ("conflict", ct.POINTER(Conflict))]


Ask = ct.CFUNCTYPE(None, ct.c_void_p, ct.POINTER(Question))
# The unused log format/va_list are opaque ABI values. Only the error level is needed.
Log = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_void_p)


def packages(entries):
    for _ in range(4096):
        if not entries:
            return
        yield entries.contents.data
        entries = entries.contents.next
    raise ValueError("ALPM package list exceeded the bound")


def resolve_conflict(expected, get_identity, questions, question):
    """Record every question and consent once to the exact ordered Qt pair."""
    question.contents.answer = 0
    kind = question.contents.type
    observed = None
    if kind == CONFLICT_PKG:
        conflict = ct.cast(question, ct.POINTER(ConflictQuestion)).contents.conflict
        if conflict:
            observed = (get_identity(conflict.contents.incoming), get_identity(conflict.contents.installed))
    accepted = observed is not None and observed == expected and not questions
    questions.append(dict(type=kind, pair=observed, accepted=accepted))
    question.contents.answer = int(accepted)


class Alpm:
    """Minimal libalpm 16 adapter for the locally signed, locked package operations."""

    def __init__(self, keyring, log, *, project_version=VERSION):
        self.versions = P["provider_versions"](project_version)
        p, i, s = ct.c_void_p, ct.c_int, ct.c_char_p
        lib = ct.CDLL("/usr/lib/libalpm.so.16")
        api = {
            "version": (s, []), "strerror": (s, [i]),
            "initialize": (p, [s, s, ct.POINTER(i)]), "release": (i, [p]), "errno": (i, [p]),
            "option_add_architecture": (i, [p, s]), "option_set_gpgdir": (i, [p, s]),
            "option_set_logfile": (i, [p, s]), "option_add_hookdir": (i, [p, s]), "option_add_cachedir": (i, [p, s]),
            "option_set_checkspace": (i, [p, i]), "option_set_default_siglevel": (i, [p, i]),
            "option_set_local_file_siglevel": (i, [p, i]),
            "option_set_questioncb": (i, [p, Ask, p]), "option_set_logcb": (i, [p, Log, p]),
            "get_localdb": (p, [p]), "db_get_valid": (i, [p]), "db_get_pkgcache": (Ptr, [p]),
            "db_get_pkg": (p, [p, s]), "pkg_get_name": (s, [p]), "pkg_get_version": (s, [p]),
            "pkg_get_arch": (s, [p]), "pkg_get_reason": (i, [p]),
            "pkg_load": (i, [p, s, i, i, ct.POINTER(p)]), "pkg_free": (i, [p]), "add_pkg": (i, [p, p]),
            "trans_init": (i, [p, i]), "trans_prepare": (i, [p, ct.POINTER(Ptr)]),
            "trans_commit": (i, [p, ct.POINTER(Ptr)]), "trans_release": (i, [p]),
            "trans_get_add": (Ptr, [p]), "trans_get_remove": (Ptr, [p]),
        }
        for name, (result, arguments) in api.items():
            function = getattr(lib, "alpm_" + name)
            function.restype, function.argtypes = result, arguments
            setattr(self, "_" + name, function)
        need(self._version() == b"16.0.1", "Unexpected libalpm version")
        db = TARGET / "var/lib/pacman"
        need((db / "local").is_dir() and db.resolve() == db and (db / "local").resolve() == db / "local",
             "Expected the existing regular target package database")
        error = i()
        self.handle = self._initialize(os.fsencode(TARGET), os.fsencode(db), ct.byref(error))
        need(self.handle, "ALPM initialize: " + self._strerror(error.value).decode())
        self.errors = []
        self.log_callback = Log(self._log_error)
        try:
            for name, value in (
                ("add_architecture", b"aarch64"), ("set_gpgdir", os.fsencode(keyring)),
                ("set_logfile", os.fsencode(log)), ("add_hookdir", os.fsencode(TARGET / "etc/pacman.d/hooks")),
                ("add_cachedir", os.fsencode(WORK / "cache")),
                ("set_checkspace", 1), ("set_default_siglevel", REQUIRED_TRUSTED),
                ("set_local_file_siglevel", REQUIRED_TRUSTED),
            ):
                self.ok(getattr(self, "_option_" + name)(self.handle, value), "configure " + name)
            self.ok(self._option_set_logcb(self.handle, self.log_callback, None), "configure ALPM error log")
        except Exception:
            self.close()
            raise

    def _log_error(self, _context, level, _format, _args):
        if level == 1:  # ALPM_LOG_ERROR
            self.errors.append(level)

    def ok(self, result, operation):
        if result != 0:
            error = self._strerror(self._errno(self.handle)).decode()
            raise ValueError(f"ALPM {operation}: {error}")

    def close(self):
        need(self._release(self.handle) == 0, "ALPM failed to release its handle")

    def identity(self, package):
        return self._pkg_get_name(package).decode("ascii"), self._pkg_get_version(package).decode("ascii")

    def rows(self, entries):
        entries = [self.identity(package) for package in packages(entries)]
        need(len(dict(entries)) == len(entries), "ALPM returned duplicate package names")
        return dict(entries)

    def inventory(self):
        db = self._get_localdb(self.handle)
        self.ok(self._db_get_valid(db), "validate local database")
        rows = self.rows(self._db_get_pkgcache(db))
        return "".join(f"{name} {version}\n" for name, version in sorted(rows.items())).encode("ascii")

    def local(self, owner):
        package = self._db_get_pkg(self._get_localdb(self.handle), owner.encode("ascii"))
        need(package and self.identity(package) == (owner, self.versions[owner]), "Wrong installed Qt provider")
        return package

    def reason(self, owner):
        return self._pkg_get_reason(self.local(owner))

    @contextmanager
    def loaded(self, archive, owner):
        package = ct.c_void_p()
        self.ok(self._pkg_load(self.handle, os.fsencode(archive), 1, REQUIRED_TRUSTED, ct.byref(package)),
                f"load trusted local archive for {owner}")
        owned = False

        def add():
            nonlocal owned
            self.ok(self._add_pkg(self.handle, package), "add exact local Qt archive")
            owned = True  # Ownership transfers to the transaction on success.

        try:
            need(self.identity(package) == (owner, self.versions[owner]) and self._pkg_get_arch(package) == b"aarch64",
                 "Loaded archive does not have the exact Qt package identity")
            yield add
        finally:
            if not owned:
                self.ok(self._pkg_free(package), "free unqueued package")

    @contextmanager
    def prepare(self, archive, incoming, outgoing, expected, reason):
        questions = []

        @Ask
        def ask(_context, question):
            try:
                resolve_conflict(((incoming, self.versions[incoming]), (outgoing, self.versions[outgoing])),
                                 self.identity, questions, question)
            except Exception:
                question.contents.answer = 0
                questions.append(dict(type=-1, pair=None, accepted=False))

        self.ok(self._option_set_questioncb(self.handle, ask, None), "set exact conflict policy")
        try:
            flags = AS_DEPS if reason == DEPENDENCY else 0
            self.ok(self._trans_init(self.handle, flags), "lock local database")
            try:
                before = self.inventory()
                need(before == expected, "Locked pre-transaction inventory differs")
                need(self.reason(outgoing) == reason, "Locked provider installation reason differs")
                with self.loaded(archive, incoming) as add:
                    add()
                details = Ptr()
                self.ok(self._trans_prepare(self.handle, ct.byref(details)), "prepare Qt provider conflict")
                add = self.rows(self._trans_get_add(self.handle))
                remove = self.rows(self._trans_get_remove(self.handle))
                check_prepared(add, remove, questions, incoming, outgoing, project_version=self.versions[PROJECT])
                need(not self.errors, "ALPM logged an error during preparation")
                yield dict(add=add, remove=remove, questions=list(questions), install_reason=reason)
            finally:
                self.ok(self._trans_release(self.handle), "release transaction and database lock")
        finally:
            self.ok(self._option_set_questioncb(self.handle, Ask(), None), "clear exact conflict policy")
        need(not self.errors and len(questions) == 1, "ALPM logged an error or asked another question")

    def commit(self, owner, reason):
        details = Ptr()
        self.ok(self._trans_commit(self.handle, ct.byref(details)), "commit provider transaction")
        need(not self.errors, "ALPM logged an error during commit")
        need(self.reason(owner) == reason, "Installed Qt package reason differs")


def check_prepared(add, remove, questions, incoming, outgoing, *, project_version=VERSION):
    versions = P["provider_versions"](project_version)
    need({incoming, outgoing} == versions.keys(), "Expected the exact official and project Qt providers")
    added, removed = versions[incoming], versions[outgoing]
    conflict = dict(type=CONFLICT_PKG, pair=((incoming, added), (outgoing, removed)), accepted=True)
    need(add == {incoming: added} and remove == {outgoing: removed} and questions == [conflict],
         "ALPM must prepare exactly the one approved Qt provider conflict")


def signature(path, owner, verification, keyring):
    archive, detached = verification["archive"], verification["signature"]
    with A["opened"](path, archive) as data, A["opened"](Path(str(path) + ".sig"), detached) as sig:
        command = ["/usr/bin/gpg", "--batch", "--no-options", "--no-auto-key-retrieve", "--homedir", str(keyring),
                   "--status-fd", "1", "--verify", "--", f"/proc/self/fd/{sig.fileno()}", f"/proc/self/fd/{data.fileno()}"]
        check = subprocess.run(command, env=A["ENV"], pass_fds=(sig.fileno(), data.fileno()),
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    status = [row.split() for row in check.stdout.splitlines() if row.startswith(b"[GNUPG:] ")]
    need(all(len(row) >= 2 for row in status), "Malformed GnuPG signature status")
    valid = [row for row in status if row[1] == b"VALIDSIG"]
    good = [row for row in status if row[1] == b"GOODSIG"]
    fingerprint = verification["fingerprint"]
    need(check.returncode == 0 and len(valid) == len(good) == 1 and len(valid[0]) == 12 and len(good[0]) >= 3
         and re.fullmatch(rb"[A-F0-9]{40}", valid[0][2]) and valid[0][-1] == fingerprint.encode("ascii")
         and good[0][2] == valid[0][2][-16:] and all(re.fullmatch(rb"[0-9]{1,12}", valid[0][i]) for i in (4, 5))
         and not any(A["REFUSAL"].fullmatch(row[1]) or row[1] in (b"FAILURE", b"ERROR", b"NODATA", b"UNEXPECTED")
                     for row in status), f"Exact detached signature refused for {owner}")
    return dict(archive=archive, signature=detached, fingerprint=fingerprint, status=pin(check.stdout)), check.stdout


def checked_review(project_review):
    return P["test_review"](project_review)


def checked_nonce(nonce, predecessor):
    need(type(nonce) is str and NONCE.fullmatch(nonce) and nonce != predecessor,
         "Fresh selected Qt run nonce required")


def certificate(path, review, keyring):
    with A["opened"](path, review["certificate"]) as selected:
        body = selected.read()
        command = ["/usr/bin/gpg", "--batch", "--no-options", "--no-autostart", "--no-auto-key-retrieve",
                   "--homedir", str(keyring), "--with-colons", "--fingerprint", "--show-keys", "--",
                   f"/proc/self/fd/{selected.fileno()}"]
        # The descriptor path opens the pinned bytes independently of the current file offset.
        check = subprocess.run(command, env=A["ENV"], pass_fds=(selected.fileno(),),
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
    rows = [row.split(":") for row in check.stdout.decode("utf-8").splitlines()]
    primary = [i for i, row in enumerate(rows) if row[0] == "pub"]
    need(check.returncode == 0 and len(primary) == 1 and primary[0] + 1 < len(rows)
         and all(row[0] not in {"sec", "ssb"} for row in rows), "Expected one public Qt TEST primary")
    pub, fpr = rows[primary[0]:primary[0] + 2]
    need(len(pub) > 6 and len(fpr) > 9 and fpr[0] == "fpr" and pub[1] not in {"e", "r", "d", "i"}
         and all(re.fullmatch(r"[0-9]{1,12}", pub[i]) for i in (5, 6))
         and FINGERPRINT.fullmatch(fpr[9]) and pub[4] == fpr[9][-16:], "Malformed or unusable Qt TEST primary")
    observed = dict(pin=pin(body), fingerprint=fpr[9], not_before=int(pub[5]), not_after=int(pub[6]))
    need(observed == dict(pin=review["certificate"], fingerprint=review["fingerprint"],
                         not_before=review["not_before"], not_after=review["not_after"])
         and observed["not_before"] <= int(time.time()) < observed["not_after"],
         "Qt TEST certificate identity or current validity differs from review")
    return observed, body


class Backend:
    def __init__(self, paths, verification, trust_homes, log, certificate_path, review, *, project_version=VERSION):
        self.paths, self.verification = paths, verification
        self.trust_homes, self.log = trust_homes, log
        self.keyring = trust_homes["pacman"]
        self.certificate_path, self.review = certificate_path, review
        self.project_version = project_version

    @contextmanager
    def open(self):
        alpm = Alpm(self.keyring, self.log, project_version=self.project_version)
        try:
            yield alpm
        finally:
            alpm.close()

    def inventory(self, owner):
        with self.open() as alpm:
            inventory = alpm.inventory()
            reason = alpm.reason(owner)
        pacman = ["/usr/bin/pacman", "--config", str(WORK / "pacman.conf"), "--root", str(TARGET),
                  "--dbpath", str(TARGET / "var/lib/pacman"), "--gpgdir", str(self.keyring)]
        for check in (["--database", "--check"], ["--query", "--check", "--", owner]):
            checked = subprocess.run([*pacman, *check], env=A["ENV"], stdin=subprocess.DEVNULL,
                                     capture_output=True, timeout=90)
            need(checked.returncode == 0, f"pacman {' '.join(check)} failed: " +
                 (checked.stderr or checked.stdout).decode(errors="replace")[:384])
        return inventory, reason

    def authenticate(self):
        receipts = {}
        verified_certificate = certificate(self.certificate_path, self.review, self.trust_homes[PROJECT])
        # Verify the reversal operand before the first possible commit, including
        # ALPM's own Required TrustedOnly check of both original archive bodies.
        with self.open() as alpm:
            for owner in (OFFICIAL, PROJECT):
                path = self.paths[owner]
                receipts[owner] = signature(path, owner, self.verification[owner], self.trust_homes[owner])
                with alpm.loaded(path, owner):
                    pass
            need(not alpm.errors, "ALPM logged an error during trust preflight")
        return receipts, verified_certificate

    @contextmanager
    def prepare(self, incoming, outgoing, before, reason):
        path = self.paths[incoming]
        A["verify"](path, self.verification[incoming]["archive"])
        A["verify"](Path(str(path) + ".sig"), self.verification[incoming]["signature"])
        with self.open() as alpm, alpm.prepare(path, incoming, outgoing, before, reason) as prepared:
            yield prepared, alpm.commit


class Journal:
    """Append and sync the commit boundary before ALPM may change any files.

    Complete sequence: entry, baseline, trust, replacement-prepare,
    replacement-commit-start, replacement-commit-done, replacement, probe,
    restoration-prepare, restoration-commit-start, restoration-commit-done,
    restoration, terminal. The parity journal adds restoration-probe before
    terminal. Each inventory row binds an adjacent named lock, a boot/mount
    snapshot and the Qt provider's installation reason.
    The entry records the selected run nonce. The trust row binds the verified
    TEST certificate pin, fingerprint and validity window. Each prepare row
    specifies the operand, removal and one conflict answer.
    The outer receipt must also bind the ALPM log and independent readback.
    """

    def __init__(self, directory):
        self.directory = directory
        self.path = directory / "transaction.jsonl"

    def record(self, phase, **data):
        with self.path.open("ab") as stream:
            row = dict(phase=phase, at_ns=time.time_ns(), **data)
            stream.write((json.dumps(row, sort_keys=True) + "\n").encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def write(self, name, raw):
        with (self.directory / name).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    def inventory(self, phase, raw, reason, platform):
        self.write(phase + ".lock", raw)
        self.write(phase + "-platform.json", platform)
        self.record(phase, inventory=pin(raw), install_reason=reason, platform=pin(platform))


def _run(backend, journal, baseline, probe, platform, platform_pin, nonce, *, project_version=VERSION,
         profile_pin=None, restored_probe=None):
    need((profile_pin is None and restored_probe is None) or (profile_pin is not None and callable(restored_probe)),
         "Parity transactions require a restored runtime probe")
    replacement, restored = P["project"](baseline, project_version=project_version)
    phase, known = "baseline", None

    def observe(label, owner, expected, reason=None):
        raw, actual_reason = backend.inventory(owner)
        need(raw == expected and actual_reason in (0, 1) and (reason is None or actual_reason == reason),
             f"{label}: exact inventory or installed provider reason differs")
        snapshot = platform()
        need(type(snapshot) is bytes and pin(snapshot) == platform_pin, f"{label}: protected boot/mount state differs")
        journal.inventory(label, raw, actual_reason, snapshot)
        return actual_reason

    def swap(label, outgoing, incoming, before, after, reason):
        nonlocal phase, known
        phase = label + "-prepare"
        with backend.prepare(incoming, outgoing, before, reason) as (prepared, commit):
            check_prepared(prepared["add"], prepared["remove"], prepared["questions"], incoming, outgoing,
                           project_version=project_version)
            need(prepared["install_reason"] == reason, "Locked provider installation reason differs")
            journal.record(phase, **prepared)
            phase = label + "-commit-start"
            journal.record(phase)
            known = None
            commit(incoming, reason)
        journal.record(label + "-commit-done")
        phase = label
        observe(label, incoming, after, reason)
        known = label

    def run_probe(label, callback, *, retain_pin=False):
        evidence, failure = None, None
        try:
            if retain_pin:
                report, error = callback()
                need(P["C"].check_pin(report, 2 << 20) and report["bytes"] > 0
                     and (error is None or isinstance(error, Exception)),
                     "Restored runtime probe must return an evidence pin and optional failure")
                evidence, failure = report, error
            else:
                need(callback() is None, "Probe must return None on success")
        except Exception as error:
            failure = error
        structured = None if failure is None else {"error_type": type(failure).__name__, "error": str(failure)[:512]}
        journal.record(label, status="PASS" if structured is None else "HOLD", error=structured)
        return evidence, structured

    entry = dict(kind=RECEIPT, nonce=nonce)
    if profile_pin is not None:
        entry["parity_profile"] = profile_pin
    journal.record("entry", **entry)
    try:
        reason = observe("baseline", OFFICIAL, baseline)
        known = "baseline"
        phase = "trust"
        verified, verified_certificate = backend.authenticate()
        test_certificate, certificate_body = verified_certificate
        signers = {}
        for owner, label in ((PROJECT, "replacement"), (OFFICIAL, "restoration")):
            signers[owner], status = verified[owner]
            journal.write(label + "-signature.status", status)
        need(test_certificate["fingerprint"] == signers[PROJECT]["fingerprint"],
             "Qt TEST signer differs from verified certificate")
        journal.write("test-certificate.gpg", certificate_body)
        journal.record(phase, policy="Required TrustedOnly", signers=signers, test_certificate=test_certificate)
        swap("replacement", OFFICIAL, PROJECT, baseline, replacement, reason)
        phase = "probe"
        _, probe_error = run_probe(phase, probe)
        failure_phase = phase if probe_error is not None else None
        swap("restoration", PROJECT, OFFICIAL, replacement, restored, reason)
        if restored_probe is not None:
            phase = "restoration-probe"
            restored_pin, restored_error = run_probe(phase, restored_probe, retain_pin=True)
            if restored_error is not None and probe_error is None:
                probe_error, failure_phase = restored_error, phase
        result = dict(status=PASS if probe_error is None else HOLD_RESTORED, error=probe_error,
                      failure_phase=failure_phase)
        if restored_probe is not None:
            result["restored_runtime_probe"] = restored_pin
    except Exception as error:
        result = dict(status=HOLD_BASELINE if known == "baseline" else HOLD_DISCARD,
                      error={"error_type": type(error).__name__, "error": str(error)[:512]}, failure_phase=phase)
    result.update(kind=RECEIPT, last_verified=known)
    journal.record("terminal", **result)
    return result


def run(project_review, probe, platform, *, nonce, profile=None, restored_probe=None):
    """Run inside the owned 16 KiB guest with its prepared public keyring.

    Media supplies `qt-replacement/` with the retained `rollback.lock` and
    `result.json`, the two exact archives and adjacent signatures, and
    `test-certificate.gpg`. The caller passes the selected boot-plan nonce.
    `project_review` supplies the independently authenticated candidate
    `fingerprint`, `certificate` and `signature` pins, and UNIX seconds
    `not_before` and `not_after`. The existing Asahi guest platform snapshot
    function returns the same canonical JSON bytes.
    A HOLD, missing terminal row or uncaught interruption requires retirement
    of the writable clone. Only a clean candidate commit and exact readback
    permit the single ordinary official reversal, even if the probe fails.
    For parity, restored_probe runs after the verified reversal and returns
    the completed report pin and optional coverage failure. Errors before
    a report completes raise and leave the report pin unset.
    """
    need(os.geteuid() == 0 and os.uname().machine == "aarch64" and os.sysconf("SC_PAGE_SIZE") == 16384,
         "Expected the owned AArch64 16 KiB guest")
    mounts = {fields[4]: (set(fields[5].split(",")), fields[fields.index("-") + 1])
              for row in Path("/proc/self/mountinfo").read_text().splitlines() if (fields := row.split())}
    for path, mode, filesystem in ((Path("/"), "ro", "ext4"), (MEDIA, "ro", "ext4"),
                                   (TARGET, "rw", "ext4"), (WORK, "rw", "tmpfs")):
        modes, actual = mounts.get(str(path), (set(), None))
        need(mode in modes and actual == filesystem, f"Unexpected guest mount: {path}")
    need(not any(path.startswith(str(MEDIA) + "/") for path in mounts), "Qt inputs must share the read-only media mount")
    need(set(os.listdir("/sys/class/net")) == {"lo"}, "Expected an offline guest")
    media, evidence = MEDIA / "qt-replacement", WORK / "qt-replacement-evidence"
    trust_homes = {OFFICIAL: WORK / "verify-vendor", PROJECT: WORK / "verify-project-test", "pacman": WORK / "trust"}
    need(all(path.is_dir() and path.resolve() == path for path in (media, *trust_homes.values())),
         "Expected the isolated Qt media and public keyrings")
    checked_review(project_review)
    P["choose_review"](profile, project_review)
    pins = P["profile_pins"](profile)
    version = VERSION if profile is None else profile["project_version"]
    baseline = P["read"]("rollback_lock", media / "rollback.lock")
    retained = P["C"].json_body(P["read"]("rollback_result", media / "result.json"))
    checked_nonce(nonce, retained["nonce"])
    platform_pin = retained["platform"]["rollback"]
    paths = {OFFICIAL: media / P["OFFICIAL_NAME"], PROJECT: media / P["project_name"](profile)}
    verification = {
        OFFICIAL: dict(archive=P["PINS"]["official_archive"], signature=P["PINS"]["official_signature"],
                       fingerprint=A["FINGERPRINT"]),
        PROJECT: dict(archive=pins["project_archive"], signature=project_review["signature"],
                      fingerprint=project_review["fingerprint"]),
    }
    evidence.mkdir(mode=0o700)
    backend = Backend(paths, verification, trust_homes, evidence / "pacman.log", media / "test-certificate.gpg",
                      project_review, project_version=version)
    profile_pin = None if profile is None else pin(P["C"].wire(profile))
    return _run(backend, Journal(evidence), baseline, probe, platform, platform_pin, nonce,
                project_version=version, profile_pin=profile_pin, restored_probe=restored_probe)
