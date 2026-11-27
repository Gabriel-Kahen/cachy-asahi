# SPDX-License-Identifier: MIT
"""Run exactly one two-provider ALPM replacement and its inverse."""

from contextlib import contextmanager
import ctypes as ct
import os
from pathlib import Path
import shutil

TARGET = Path("/trial-scratch")
WORK = Path("/trial-work")
CONFLICT = 1 << 2
AS_DEPS = 1 << 8
REQUIRED_TRUSTED = 1  # ALPM_SIG_PACKAGE, with no trust-relaxing flags.
PASS = "PASS_ASAHI629_JBIG_TIFF_ROUND_TRIP"
HOLD_BASELINE = "HOLD_ASAHI629_JBIG_TIFF_BASELINE"
HOLD_RESTORED = "HOLD_ASAHI629_JBIG_TIFF_RESTORED"
HOLD_DISCARD = "HOLD_ASAHI629_JBIG_TIFF_DISCARD_CLONE"


def need(condition, message):
    if not condition:
        raise ValueError(message)


class Link(ct.Structure):
    pass


List = ct.POINTER(Link)
Link._fields_ = [("data", ct.c_void_p), ("prev", List), ("next", List)]


class Question(ct.Structure):
    _fields_ = [("type", ct.c_int), ("answer", ct.c_int)]


class Conflict(ct.Structure):
    _fields_ = [("incoming", ct.c_void_p), ("installed", ct.c_void_p), ("reason", ct.c_void_p)]


class ConflictQuestion(ct.Structure):
    _fields_ = [("base", Question), ("conflict", ct.POINTER(Conflict))]


Ask = ct.CFUNCTYPE(None, ct.c_void_p, ct.POINTER(Question))
Log = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_void_p)


def approved_pairs(incoming, outgoing):
    def base(name):
        return name.removeprefix("cachy-asahi-")

    result = {((name, version), (old, old_version)) for name, version in incoming.items()
              for old, old_version in outgoing.items() if base(name) == base(old)}
    need(len(result) == len(incoming) == len(outgoing) == 2, "Exactly two matching provider roles required")
    return result


def answer(question, identity, allowed, records):
    question.contents.answer = 0
    observed = None
    if question.contents.type == CONFLICT:
        conflict = ct.cast(question, ct.POINTER(ConflictQuestion)).contents.conflict
        if conflict:
            observed = (identity(conflict.contents.incoming), identity(conflict.contents.installed))
    accepted = observed in allowed and all(row["pair"] != observed and row["accepted"] for row in records)
    records.append(dict(type=question.contents.type, pair=observed, accepted=accepted))
    question.contents.answer = int(accepted)


def check_prepared(add, remove, records, incoming, outgoing):
    expected = approved_pairs(incoming, outgoing)
    need(add == incoming and remove == outgoing and len(records) == 2
         and all(row["type"] == CONFLICT and row["accepted"] for row in records)
         and {row["pair"] for row in records} == expected,
         "ALPM must prepare exactly the two approved provider replacements")


class Alpm:
    def __init__(self, keyring, log):
        p, i, s = ct.c_void_p, ct.c_int, ct.c_char_p
        library = ct.CDLL("/usr/lib/libalpm.so.16")
        functions = {
            "version": (s, ()), "strerror": (s, (i,)), "errno": (i, (p,)),
            "initialize": (p, (s, s, ct.POINTER(i))), "release": (i, (p,)),
            "option_add_architecture": (i, (p, s)), "option_set_gpgdir": (i, (p, s)),
            "option_set_logfile": (i, (p, s)), "option_add_hookdir": (i, (p, s)),
            "option_add_cachedir": (i, (p, s)), "option_set_checkspace": (i, (p, i)),
            "option_set_default_siglevel": (i, (p, i)), "option_set_local_file_siglevel": (i, (p, i)),
            "option_set_questioncb": (i, (p, Ask, p)), "option_set_logcb": (i, (p, Log, p)),
            "get_localdb": (p, (p,)), "db_get_valid": (i, (p,)), "db_get_pkgcache": (List, (p,)),
            "db_get_pkg": (p, (p, s)), "pkg_get_name": (s, (p,)), "pkg_get_version": (s, (p,)),
            "pkg_get_arch": (s, (p,)), "pkg_get_reason": (i, (p,)),
            "pkg_load": (i, (p, s, i, i, ct.POINTER(p))), "pkg_free": (i, (p,)),
            "add_pkg": (i, (p, p)), "trans_init": (i, (p, i)), "trans_release": (i, (p,)),
            "trans_prepare": (i, (p, ct.POINTER(List))), "trans_commit": (i, (p, ct.POINTER(List))),
            "trans_get_add": (List, (p,)), "trans_get_remove": (List, (p,)),
        }
        for name, (returns, args) in functions.items():
            function = getattr(library, "alpm_" + name)
            function.restype, function.argtypes = returns, args
            setattr(self, "_" + name, function)
        need(self._version() == b"16.0.1", "Expected Asahi629 libalpm 16.0.1")
        db = TARGET / "var/lib/pacman"
        need((db / "local").is_dir() and (db / "local").resolve() == db / "local",
             "Expected the regular disposable target local database")
        error = i()
        self.handle = self._initialize(os.fsencode(TARGET), os.fsencode(db), ct.byref(error))
        need(self.handle, "ALPM initialize: " + self._strerror(error.value).decode())
        self.errors = []
        self.logcb = Log(self.log_error)
        try:
            for option, value in (
                ("add_architecture", b"aarch64"), ("set_gpgdir", os.fsencode(keyring)),
                ("set_logfile", os.fsencode(log)), ("add_hookdir", os.fsencode(TARGET / "etc/pacman.d/hooks")),
                ("add_cachedir", os.fsencode(WORK / "cache")), ("set_checkspace", 1),
                ("set_default_siglevel", REQUIRED_TRUSTED), ("set_local_file_siglevel", REQUIRED_TRUSTED),
            ):
                self.ok(getattr(self, "_option_" + option)(self.handle, value), option)
            self.ok(self._option_set_logcb(self.handle, self.logcb, None), "record ALPM errors")
        except BaseException:
            self.close()
            raise

    def log_error(self, _context, level, _message, _args):
        if level & 1:
            self.errors.append(level)

    def ok(self, code, action):
        if code != 0:
            error = self._strerror(self._errno(self.handle)).decode()
            raise ValueError(f"ALPM {action}: {error}")

    def close(self):
        need(self._release(self.handle) == 0, "ALPM could not release its handle")

    def identity(self, package):
        return self._pkg_get_name(package).decode("ascii"), self._pkg_get_version(package).decode("ascii")

    def rows(self, head):
        result = {}
        while head:
            name, version = self.identity(head.contents.data)
            need(name not in result and len(result) < 1024, "ALPM list has a duplicate or exceeds its bound")
            result[name] = version
            head = head.contents.next
        return result

    def inventory(self):
        db = self._get_localdb(self.handle)
        self.ok(self._db_get_valid(db), "validate local package database")
        rows = self.rows(self._db_get_pkgcache(db))
        return "".join(f"{name} {version}\n" for name, version in sorted(rows.items())).encode("ascii")

    def reasons(self, providers):
        db = self._get_localdb(self.handle)
        result = {}
        for name, version in providers.items():
            package = self._db_get_pkg(db, name.encode("ascii"))
            need(package and self.identity(package) == (name, version), "Installed provider differs: " + name)
            result[name] = self._pkg_get_reason(package)
        need(set(result.values()) == {1}, "Expected both providers installed as dependencies")
        return result

    def load(self, path, name, version, *, enqueue=False):
        package = ct.c_void_p()
        self.ok(self._pkg_load(self.handle, os.fsencode(path), 1, REQUIRED_TRUSTED, ct.byref(package)),
                "load signed archive " + name)
        transferred = False
        try:
            need(self.identity(package) == (name, version) and self._pkg_get_arch(package) == b"aarch64",
                 "Signed archive has the wrong package identity: " + name)
            if enqueue:
                self.ok(self._add_pkg(self.handle, package), "enqueue signed archive " + name)
                transferred = True
        finally:
            if not transferred:
                self.ok(self._pkg_free(package), "release unqueued archive")

    def refuse_unsigned(self, path, expected):
        package = ct.c_void_p()
        need(self.inventory() == expected, "Exact inventory required before unsigned control")
        result = self._pkg_load(self.handle, os.fsencode(path), 1, REQUIRED_TRUSTED, ct.byref(package))
        error = self._strerror(self._errno(self.handle)).decode()
        if package:
            self.ok(self._pkg_free(package), "release unexpected control archive")
        need(result == -1 and error == "package missing required signature"
             and self.inventory() == expected, "Unsigned control was not refused without changing the inventory")
        return error

    @contextmanager
    def prepared(self, paths, incoming, outgoing, before):
        allowed, records = approved_pairs(incoming, outgoing), []

        @Ask
        def callback(_context, question):
            try:
                answer(question, self.identity, allowed, records)
            except Exception:
                question.contents.answer = 0
                records.append(dict(type=-1, pair=None, accepted=False))

        self.ok(self._option_set_questioncb(self.handle, callback, None), "set exact pair conflict policy")
        try:
            self.ok(self._trans_init(self.handle, AS_DEPS), "lock package database")
            try:
                need(self.inventory() == before, "Locked pre-transaction inventory differs")
                self.reasons(outgoing)
                for name, version in incoming.items():
                    self.load(paths[name], name, version, enqueue=True)
                details = List()
                self.ok(self._trans_prepare(self.handle, ct.byref(details)), "prepare signed provider pair")
                add, remove = self.rows(self._trans_get_add(self.handle)), self.rows(self._trans_get_remove(self.handle))
                check_prepared(add, remove, records, incoming, outgoing)
                need(not self.errors, "ALPM reported a preparation error")
                yield dict(add=add, remove=remove, conflicts=records.copy())
                need(not self.errors and len(records) == 2, "ALPM commit logged an error or a further question")
            finally:
                self.ok(self._trans_release(self.handle), "release transaction and database lock")
        finally:
            self.ok(self._option_set_questioncb(self.handle, Ask(), None), "clear conflict policy")

    def commit(self):
        details = List()
        self.ok(self._trans_commit(self.handle, ct.byref(details)), "commit exact signed provider pair")


class Backend:
    def __init__(self, keyring, log, paths):
        self.keyring, self.log, self.paths = keyring, log, paths

    @contextmanager
    def open(self):
        alpm = Alpm(self.keyring, self.log)
        try:
            yield alpm
        finally:
            alpm.close()

    def authenticate(self, providers):
        with self.open() as alpm:
            for name, version in providers.items():
                alpm.load(self.paths[name], name, version)

    def negative_control(self, name, baseline):
        with self.open() as alpm:
            scratch = WORK / "jbig-tiff-unsigned"
            scratch.mkdir(mode=0o700)
            try:
                archive = scratch / self.paths[name].name
                shutil.copyfile(self.paths[name], archive)
                return alpm.refuse_unsigned(archive, baseline)
            finally:
                shutil.rmtree(scratch)

    def inventory(self, providers):
        with self.open() as alpm:
            return alpm.inventory(), alpm.reasons(providers)

    @contextmanager
    def prepared(self, incoming, outgoing, before):
        with self.open() as alpm, alpm.prepared(self.paths, incoming, outgoing, before) as record:
            yield record, alpm.commit


def lifecycle(backend, official, project, baseline, replacement, observe, probe, authenticate, current, report):
    """Preserve the exact last known transaction state and try the inverse after a probe failure."""
    state, phase = None, "baseline"

    def snapshot(providers, expected, label):
        raw, reasons = backend.inventory(providers)
        need(raw == expected, "Complete installed inventory differs: " + label)
        return observe(label, providers, reasons, raw)

    def swap(incoming, outgoing, before, label):
        nonlocal state, phase
        phase = label + "-prepare"
        current()
        with backend.prepared(incoming, outgoing, before) as (record, commit):
            report["transactions"][label] = record
            phase, state = label + "-commit", None
            commit()

    def exercise(label, soname):
        try:
            report["phases"][label]["runtime"] = probe(soname)
        except Exception as error:
            evidence = getattr(error, "runtime_evidence", None)
            if evidence is not None:
                report["phases"][label]["runtime"] = evidence
            raise

    report.update(phases={}, transactions={}, probe_failure=None, failure=None)
    try:
        report["phases"]["baseline"] = snapshot(official, baseline, "baseline")
        state = "baseline"
        phase = "trust"
        report["trust"] = authenticate()
        backend.authenticate(official | project)
        report["unsigned_control"] = backend.negative_control(next(iter(project)), baseline)
        phase = "baseline-probe"
        exercise("baseline", "2.1")
        swap(project, official, baseline, "replacement")
        phase = "replacement"
        try:
            report["phases"]["replacement"] = snapshot(project, replacement, "replacement")
            exercise("replacement", "2.2")
        except Exception as error:
            report["probe_failure"] = str(error)[:640]
        # The inverse itself locks and rechecks the exact candidate inventory.
        swap(official, project, replacement, "restoration")
        phase = "restoration"
        report["phases"]["restoration"] = snapshot(official, baseline, "restoration")
        state = "restored"
        phase = "restoration-probe"
        exercise("restoration", "2.1")
        current()
        report["status"] = PASS if report["probe_failure"] is None else HOLD_RESTORED
    except Exception as error:
        report["failure"] = dict(phase=phase, message=str(error)[:640])
        report["status"] = {None: HOLD_DISCARD, "baseline": HOLD_BASELINE, "restored": HOLD_RESTORED}[state]
    return report
