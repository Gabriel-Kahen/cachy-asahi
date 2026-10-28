#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare a private libalpm metadata transaction; never commit or download."""
import argparse
import ctypes as C
import ctypes.util
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


HERE = Path(__file__).resolve().parent
preview = module("platform_transaction_preview", HERE.parent / "port/preview.py")
tuple_audit = module("platform_transaction_tuple", HERE / "tuple_audit.py")
LIMIT = 20 * 1024**2
DECODED_LIMIT = 256 * 1024**2
ADDITIONAL = {"asahi-audio": "asahi-alarm", "speakersafetyd": "asahi-alarm",
              "bankstown": "asahi-alarm", "triforce-lv2": "asahi-alarm",
              "asahi-desktop-meta": "asahi-alarm", "vulkan-asahi": "extra"}


def bound(reference):
    if set(reference) != {"path", "sha256", "size"}:
        raise ValueError("input reference must have path, sha256, size")
    path = Path(reference["path"])
    if not path.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]):
        raise ValueError("input path/checksum refused")
    size = reference["size"]
    if type(size) is not int or not 0 < size <= LIMIT:
        raise ValueError("input size refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular input required")
        data = stream.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != reference["sha256"]:
        raise ValueError("input size/checksum mismatch: " + str(path))
    return data


def clean(record):
    preview.check(record)
    for key, values in record.items():
        if key == "repo":
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not isinstance(values, list) or len(values) > 256:
            raise ValueError("unsafe descriptor field")
        if any(not isinstance(v, str) or len(v) > 16384 or re.search(r"[\n\r\x00]", v) for v in values):
            raise ValueError("unsafe descriptor value")
    return record


def repository_records(data, diagnostics=None, repo="repository"):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        decoded = stream.read(DECODED_LIMIT + 1)
    if len(decoded) > DECODED_LIMIT:
        raise ValueError("repository decode bound exceeded")
    grouped, blocked = {}, set()
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        for index, member in enumerate(archive):
            if index >= 100000 or member.size > 131072:
                raise ValueError("repository member bound exceeded")
            if member.isdir():
                continue
            if not member.isfile() or not re.fullmatch(r"[^/]+/(desc|depends)", member.name):
                raise ValueError("unsafe repository member")
            entry_name = member.name.rsplit("/", 1)[0]
            if member.sparse is not None or any(k.startswith("GNU.sparse.") for k in member.pax_headers):
                blocked.add(entry_name)
                grouped.pop(entry_name, None)
                if diagnostics is not None:
                    diagnostics.append({"entry": repo + "/" + entry_name, "repo": repo,
                                        "reason": "sparse-unavailable; never reconstructed", "selectable": False})
                continue
            if entry_name in blocked:
                continue
            fields = preview.desc(archive.extractfile(member).read().decode())
            entry = grouped.setdefault(entry_name, {})
            if set(entry) & set(fields):
                raise ValueError("duplicate repository fields")
            entry.update(fields)
    return grouped


def write_bytes(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def write_metadata_archive(path, entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:") as archive:
        for entry_name, record in entries:
            text = "".join("%" + k + "%\n" + "\n".join(v) + "\n\n"
                           for k, v in record.items() if k != "repo").encode()
            member = tarfile.TarInfo(entry_name + "/desc")
            member.size = len(text)
            archive.addfile(member, io.BytesIO(text))
    write_bytes(path, gzip.compress(raw.getvalue(), mtime=0))


def write_catalog(path, records):
    entries = []
    for name, record in sorted(records.items()):
        clean(record)
        entries.append((name + "-" + record["VERSION"][0], record))
    write_metadata_archive(path, entries)


def local_files(document, image, inventory_sha256):
    if (document["inventory_sha256"] != inventory_sha256 or document["schema_version"] != 1
            or document["kind"] != "observed-image-local-file-ownership-metadata"):
        raise ValueError("local files/image inventory binding refused")
    if document["physical_target"] is not False or document["installed_payload_verified"] is not False:
        raise ValueError("image file metadata must not claim target/payload verification")
    records = document["packages"]
    if not isinstance(records, list) or len(records) != len(image):
        raise ValueError("complete image local file metadata required")
    result = {}
    for entry in records:
        name = entry["name"]
        if name in result or name not in image or entry["directory"] != name + "-" + image[name]["VERSION"][0]:
            raise ValueError("local files/package identity mismatch")
        data = entry["text"].encode()
        if len(data) > LIMIT or len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("local file metadata checksum/size mismatch")
        fields = tuple_audit.parse_desc(entry["text"])
        if fields != entry["fields"] or not set(fields) <= {"FILES", "BACKUP"}:
            raise ValueError("local file metadata parsed fields mismatch")
        paths = fields.get("FILES", [])
        if entry["empty_filelist"] is not (not paths) or len(paths) > 100000 or len(set(paths)) != len(paths):
            raise ValueError("invalid/duplicate image file list")
        for value in paths + fields.get("BACKUP", []):
            path = value.split("\t")[0]
            if not path or path.startswith("/") or ".." in Path(path).parts or re.search(r"[\x00\r\n]", value):
                raise ValueError("unsafe image file metadata path")
        result[name] = data
    return result


def write_local_files(directory, records, versions, image):
    for name, data in records.items():
        if versions.get(name, {}).get("VERSION") == image[name]["VERSION"]:
            path = directory / (name + "-" + image[name]["VERSION"][0]) / "files"
            path.unlink()  # only a synthetic file created in this run's private directory
            write_bytes(path, data)


class List(C.Structure):
    pass


Ptr = C.POINTER(List)
List._fields_ = [("data", C.c_void_p), ("prev", Ptr), ("next", Ptr)]


class Missing(C.Structure):
    _fields_ = [("target", C.c_char_p), ("depend", C.c_void_p), ("causingpkg", C.c_char_p)]


class Conflict(C.Structure):
    _fields_ = [("package1", C.c_void_p), ("package2", C.c_void_p), ("reason", C.c_void_p)]


class Question(C.Structure):
    _fields_ = [("type", C.c_int), ("answer", C.c_int)]


class ProviderQuestion(C.Structure):
    _fields_ = [("type", C.c_int), ("index", C.c_int), ("providers", Ptr), ("depend", C.c_void_p)]


def pointers(entries):
    for count in range(100000):
        if not entries:
            return
        yield entries.contents.data
        entries = entries.contents.next
    raise ValueError("libalpm result list bound exceeded")


class Alpm:
    """The exposed symbol allowlist deliberately excludes mutation/download APIs."""
    SYMBOLS = {
        "alpm_version": (C.c_char_p, []),
        "alpm_initialize": (C.c_void_p, [C.c_char_p, C.c_char_p, C.POINTER(C.c_int)]),
        "alpm_release": (C.c_int, [C.c_void_p]),
        "alpm_errno": (C.c_int, [C.c_void_p]), "alpm_strerror": (C.c_char_p, [C.c_int]),
        "alpm_option_add_architecture": (C.c_int, [C.c_void_p, C.c_char_p]),
        "alpm_option_add_ignorepkg": (C.c_int, [C.c_void_p, C.c_char_p]),
        "alpm_option_set_logfile": (C.c_int, [C.c_void_p, C.c_char_p]),
        "alpm_option_set_gpgdir": (C.c_int, [C.c_void_p, C.c_char_p]),
        "alpm_option_add_cachedir": (C.c_int, [C.c_void_p, C.c_char_p]),
        "alpm_option_add_hookdir": (C.c_int, [C.c_void_p, C.c_char_p]),
        "alpm_option_set_questioncb": (C.c_int, [C.c_void_p, C.c_void_p, C.c_void_p]),
        "alpm_register_syncdb": (C.c_void_p, [C.c_void_p, C.c_char_p, C.c_int]),
        "alpm_db_get_pkg": (C.c_void_p, [C.c_void_p, C.c_char_p]),
        "alpm_pkg_get_name": (C.c_char_p, [C.c_void_p]),
        "alpm_pkg_get_version": (C.c_char_p, [C.c_void_p]),
        "alpm_pkg_get_db": (C.c_void_p, [C.c_void_p]),
        "alpm_db_get_name": (C.c_char_p, [C.c_void_p]),
        "alpm_trans_init": (C.c_int, [C.c_void_p, C.c_int]),
        "alpm_add_pkg": (C.c_int, [C.c_void_p, C.c_void_p]),
        "alpm_trans_prepare": (C.c_int, [C.c_void_p, C.POINTER(Ptr)]),
        "alpm_trans_get_add": (Ptr, [C.c_void_p]),
        "alpm_trans_get_remove": (Ptr, [C.c_void_p]),
        "alpm_trans_release": (C.c_int, [C.c_void_p]),
        "alpm_dep_compute_string": (C.c_void_p, [C.c_void_p]),
        "alpm_depmissing_free": (None, [C.c_void_p]),
        "alpm_conflict_free": (None, [C.c_void_p]),
        "alpm_list_free": (None, [Ptr]),
    }

    def __init__(self):
        library = C.util.find_library("alpm")
        if not library:
            raise ValueError("preinstalled libalpm required")
        self.library = C.CDLL(library)
        for name, (result, args) in self.SYMBOLS.items():
            function = getattr(self.library, name)
            function.restype, function.argtypes = result, args
            setattr(self, name, function)
        self.version = self.alpm_version().decode()
        if self.version != "16.0.1":
            raise ValueError("unreviewed libalpm ABI: " + self.version)
        self.libc = C.CDLL(C.util.find_library("c"))
        self.libc.free.argtypes = [C.c_void_p]
        self.libc.free.restype = None

    def dependency(self, pointer):
        value = self.alpm_dep_compute_string(pointer)
        if not value:
            raise ValueError("libalpm dependency serialization failed")
        try:
            return C.string_at(value).decode()
        finally:
            self.libc.free(value)

    def package(self, pointer):
        db = self.alpm_pkg_get_db(pointer)
        return {"name": self.alpm_pkg_get_name(pointer).decode(),
                "version": self.alpm_pkg_get_version(pointer).decode(),
                "repo": self.alpm_db_get_name(db).decode() if db else None}


def prepare(work, image, protected, catalogs, targets):
    alpm, questions, callback_errors, errors = Alpm(), [], [], []
    error = C.c_int()
    handle = alpm.alpm_initialize(os.fsencode(work / "root"), os.fsencode(work / "db"), C.byref(error))
    if not handle:
        raise ValueError("private libalpm initialization failed")
    started = False
    root_choices = {(t["name"], t["version"]) for t in targets}
    Callback = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p)

    @Callback
    def answer(context, pointer):
        try:
            question = C.cast(pointer, C.POINTER(Question)).contents
            question.answer = 0
            record = {"type": question.type, "answer": 0, "policy": "deny"}
            if question.type == 32:
                provider = C.cast(pointer, C.POINTER(ProviderQuestion)).contents
                choices = [alpm.package(p) for p in pointers(provider.providers)]
                allowed = [i for i, p in enumerate(choices) if (p["name"], p["version"]) in root_choices]
                provider.index = allowed[0] if len(allowed) == 1 else 0
                record.update({"requires": alpm.dependency(provider.depend), "providers": choices,
                               "answer": provider.index, "policy": "explicit-root-provider" if len(allowed) == 1
                               else "unapproved-provider-selection; whole result fails"})
            questions.append(record)
        except Exception as exc:
            callback_errors.append(str(exc)[:1000])

    try:
        for function, value in ((alpm.alpm_option_add_architecture, b"aarch64"),
                                (alpm.alpm_option_set_logfile, os.fsencode(work / "alpm.log")),
                                (alpm.alpm_option_set_gpgdir, os.fsencode(work / "gpg")),
                                (alpm.alpm_option_add_cachedir, os.fsencode(work / "cache")),
                                (alpm.alpm_option_add_hookdir, os.fsencode(work / "hooks"))):
            if function(handle, value):
                raise ValueError("private libalpm option rejected")
        for name in protected:
            if alpm.alpm_option_add_ignorepkg(handle, name.encode()):
                raise ValueError("IgnorePkg registration failed")
        if alpm.alpm_option_set_questioncb(handle, C.cast(answer, C.c_void_p), None):
            raise ValueError("question callback registration failed")
        databases = {}
        for name in catalogs:
            db = alpm.alpm_register_syncdb(handle, name.encode(), 0)
            if not db:
                raise ValueError("private sync catalog registration failed")
            databases[name] = db
        # NOLOCK, NEEDED, NOSCRIPTLET, NOHOOKS; never disable dependencies/conflicts.
        flags = (1 << 17) | (1 << 13) | (1 << 10) | (1 << 7)
        if alpm.alpm_trans_init(handle, flags):
            raise ValueError("private transaction initialization failed")
        started = True
        for target in targets:
            name, version, repo = target["name"], target["version"], target["repo"]
            if name in protected and protected[name] != version:
                errors.append({"target": target, "kind": "protected-root-version-rejected",
                               "protected_version": protected[name]})
                continue
            if image.get(name, {}).get("VERSION") == [version]:
                continue
            db = databases.get(repo)
            package = alpm.alpm_db_get_pkg(db, name.encode()) if db else None
            if not package or alpm.alpm_pkg_get_version(package).decode() != version:
                errors.append({"target": target, "kind": "pinned-target-unavailable-in-filtered-catalog"})
                continue
            if alpm.alpm_add_pkg(handle, package):
                code = alpm.alpm_errno(handle)
                errors.append({"target": target, "kind": "add-target-error", "errno": code,
                               "diagnostic": alpm.alpm_strerror(code).decode()})
        details = Ptr()
        result = alpm.alpm_trans_prepare(handle, C.byref(details))
        code = alpm.alpm_errno(handle) if result else 0
        try:
            for pointer in pointers(details):
                if code == 45:  # reviewed libalpm 16.0.1 ALPM_ERR_UNSATISFIED_DEPS
                    missing = C.cast(pointer, C.POINTER(Missing)).contents
                    errors.append({"kind": "unsatisfied-dependency", "target": missing.target.decode(),
                                   "requires": alpm.dependency(missing.depend),
                                   "causing_package": missing.causingpkg.decode() if missing.causingpkg else None})
                    alpm.alpm_depmissing_free(pointer)
                elif code == 46:  # ALPM_ERR_CONFLICTING_DEPS
                    conflict = C.cast(pointer, C.POINTER(Conflict)).contents
                    errors.append({"kind": "package-conflict", "package1": alpm.package(conflict.package1),
                                   "package2": alpm.package(conflict.package2), "reason": alpm.dependency(conflict.reason)})
                    alpm.alpm_conflict_free(pointer)
                else:
                    errors.append({"kind": "unparsed-prepare-error-data", "errno": code})
        finally:
            alpm.alpm_list_free(details)
        return {"libalpm_version": alpm.version, "flags": flags, "prepare_exit": result,
                "prepare_errno": code, "prepare_diagnostic": alpm.alpm_strerror(code).decode(),
                "add": [alpm.package(p) for p in pointers(alpm.alpm_trans_get_add(handle))],
                "remove": [alpm.package(p) for p in pointers(alpm.alpm_trans_get_remove(handle))],
                "questions": questions, "callback_errors": callback_errors, "errors": errors}
    finally:
        if started:
            alpm.alpm_trans_release(handle)
        alpm.alpm_release(handle)


def run(contract_path, contract_sha256, output_path):
    contract_path = Path(contract_path)
    contract = tuple_audit.load_json(bound({"path": str(contract_path.absolute()), "sha256": contract_sha256,
                                          "size": contract_path.stat().st_size}))
    required = {"schema_version", "image_inventory", "tuple_report", "proposal", "repositories", "additional_roots"}
    if not required <= set(contract) or set(contract) - required - {"local_files"} or contract["schema_version"] != 1:
        raise ValueError("contract schema refused")
    raw = {name: bound(contract[name]) for name in ("image_inventory", "tuple_report", "proposal")}
    image_doc, tuple_report, proposal = [tuple_audit.load_json(raw[k]) for k in ("image_inventory", "tuple_report", "proposal")]
    image = tuple_audit.packages([p["metadata"] for p in image_doc["packages"]])
    for p in image.values():
        clean(p)
    if tuple_report["kind"] != "offline-platform-metadata-witnesses" or tuple_report["input_sha256"]["image"] != contract["image_inventory"]["sha256"]:
        raise ValueError("tuple/image binding refused")
    protected = {}
    for p in tuple_report["proposed_installed_dependency_graph"]:
        if p["name"] in protected or image.get(p["name"], {}).get("VERSION") != [p["version"]]:
            raise ValueError("protected tuple/image version mismatch")
        protected[p["name"]] = p["version"]
    if not protected or len(protected) > 4096:
        raise ValueError("finite protected tuple required")
    file_records = local_files(tuple_audit.load_json(bound(contract["local_files"])), image,
                               contract["image_inventory"]["sha256"]) if "local_files" in contract else {}
    refs = contract["repositories"]
    if not isinstance(refs, list) or [r["name"] for r in refs] != ["asahi-alarm", "core", "extra"]:
        raise ValueError("ordered community/core/extra repositories required")
    if any(set(r) != {"name", "path", "sha256", "size"} for r in refs):
        raise ValueError("repository reference fields refused")
    repository_bytes = {r["name"]: bound({k: r[k] for k in ("path", "sha256", "size")}) for r in refs}
    if sum(map(len, repository_bytes.values())) > 2 * LIMIT:
        raise ValueError("aggregate repository input bound exceeded")
    roots = proposal["roots"] + proposal["provider_constraints"]
    if not isinstance(roots, list) or not 1 <= len(roots) <= 100:
        raise ValueError("finite source targets required")
    additional = contract["additional_roots"]
    if len(additional) != len(ADDITIONAL) or {r["name"] for r in additional} != set(ADDITIONAL):
        raise ValueError("complete additional Asahi/audio/Vulkan root set required")
    for root in additional:
        if set(root) != {"name", "version", "repo"} or root["repo"] != ADDITIONAL[root["name"]]:
            raise ValueError("additional root repository refused")
    with tempfile.TemporaryDirectory(prefix="cachy-platform-transaction-", dir="/tmp") as temporary:
        work = Path(temporary)
        for name in ("inputs", "root", "db/sync", "cache", "gpg", "hooks"):
            (work / name).mkdir(parents=True, mode=0o700)
        catalogs, diagnostics = {}, []
        for name, data in repository_bytes.items():
            grouped = repository_records(data, diagnostics, name)
            if name in ("core", "extra"):
                # Existing parser sees only regular serialized metadata, never sparse source members.
                path = work / "inputs" / (name + ".db")
                write_metadata_archive(path, sorted(grouped.items()))
                derived = {"name": name, "sha256": preview.digest(path), "size": path.stat().st_size}
                records = preview.databases(work / "inputs", [derived], diagnostics)
            else:
                records = {}
                for entry_name, entry in grouped.items():
                    try:
                        clean(entry)
                    except ValueError as error:
                        diagnostics.append({"entry": name + "/" + entry_name,
                                            "declared_name": entry.get("NAME", []), "repo": name,
                                            "reason": str(error), "selectable": False,
                                            "classification": "unsupported-by-preview-metadata-grammar"})
                        continue
                    name_ = entry["NAME"][0]
                    if name_ in records:
                        raise ValueError("duplicate community package")
                    records[name_] = entry | {"repo": name}
            catalogs[name] = {}
            for package, data_ in records.items():
                if data_.get("_invalid"):
                    diagnostics.append({"name": package, "reason": data_["_invalid"], "repo": name})
                    continue
                try:
                    clean(data_)
                except ValueError as error:
                    diagnostics.append({"name": package, "repo": name, "reason": str(error),
                                        "selectable": False,
                                        "classification": "unsupported-by-preview-metadata-grammar"})
                    continue
                if package == "mesa-dummy" or package in protected and data_["VERSION"] != [protected[package]]:
                    diagnostics.append({"name": package, "version": data_["VERSION"][0], "repo": name,
                                        "reason": "mesa-dummy/protected-version filtered"})
                    continue
                catalogs[name][package] = data_
        targets, seen = [], set()
        for root in roots:
            if set(root) != {"name", "version"}:
                raise ValueError("source root fields refused")
            name = root["name"]
            repo = "extra" if name == "mesa" else next((r for r in ("core", "extra")
                         if name in catalogs[r]), "core")
            targets.append(root | {"repo": repo, "origin": "unchanged-generic-proposal"})
        targets.extend(r | {"origin": "explicit-Asahi-addition"} for r in additional)
        for target in targets:
            clean({"NAME": [target["name"]], "VERSION": [target["version"]], "ARCH": ["aarch64"]})
            if target["name"] in seen:
                raise ValueError("duplicate target")
            seen.add(target["name"])
        preview.write_local(work / "db/local", image)
        write_local_files(work / "db/local", file_records, image, image)
        for name, records in catalogs.items():
            write_catalog(work / "db/sync" / (name + ".db"), records)
        result = prepare(work, image, protected, catalogs, targets)
        for item in result["add"]:
            old_version = image.get(item["name"], {}).get("VERSION", [None])[0]
            item.update({"old_version": old_version, "change_kind": "add" if old_version is None else "change"})
        final = dict(image)
        for item in result["remove"]:
            final.pop(item["name"], None)
        for item in result["add"]:
            data_ = catalogs.get(item["repo"], {}).get(item["name"])
            if not data_ or data_["VERSION"] != [item["version"]]:
                raise ValueError("libalpm addition/catalog identity mismatch")
            final[item["name"]] = data_
        audit_work = work / "final-audit"
        (audit_work / "root").mkdir(parents=True, mode=0o700)
        preview.write_local(audit_work / "db/local", final)
        write_local_files(audit_work / "db/local", file_records, final, image)
        relations, conflicts = preview.alpm_audit(audit_work, final)
        preservation = [{"name": name, "expected": version,
                         "final": final.get(name, {}).get("VERSION", [None])[0],
                         "preserved": final.get(name, {}).get("VERSION") == [version]}
                        for name, version in sorted(protected.items())]
        target_checks = [t | {"final_version": final.get(t["name"], {}).get("VERSION", [None])[0],
                             "satisfied": final.get(t["name"], {}).get("VERSION") == [t["version"]]}
                         for t in targets]
        rejected_questions = [q for q in result["questions"] if q["type"] == 32 and q["policy"] != "explicit-root-provider"]
        failed = bool(result["prepare_exit"] or result["errors"] or result["callback_errors"] or conflicts
                      or rejected_questions or any(not r["provider"] for r in relations)
                      or any(not p["preserved"] for p in preservation) or any(not t["satisfied"] for t in target_checks))
        report = {"schema_version": 1, "kind": "private-Asahi-metadata-transaction-prepare",
                  "status": "FAIL-incomplete-or-policy-rejected" if failed else "PASS-private-metadata-prepare",
                  "contract_sha256": contract_sha256, "input_references": contract,
                  "source_sha256": {"transaction.py": preview.digest(__file__),
                                    "tuple_audit.py": preview.digest(tuple_audit.__file__),
                                    "preview.py": preview.digest(preview.__file__)},
                  "image_package_count": len(image), "protected_package_count": len(protected),
                  "source_root_count": len(proposal["roots"]), "targets": target_checks,
                  "catalog_diagnostics": diagnostics, "transaction": result,
                  "catalog_derivation": "bounded regular source metadata; sparse, unsupported, protected-update and mesa-dummy entries excluded",
                  "proposed_final_count": len(final), "dependency_relationships": relations,
                  "proposed_final_inventory_scope": "tentative/partial on FAIL; metadata only on PASS",
                  "proposed_final_inventory": [{"name": n, "version": p["VERSION"][0],
                                                "repo": p.get("repo", "installed"), "metadata": p}
                                               for n, p in sorted(final.items())],
                  "image_local_file_metadata_loaded": bool(file_records),
                  "image_local_file_metadata_package_count": len(file_records),
                  "package_conflicts": conflicts, "protected_preservation": preservation,
                  "all_protected_versions_preserved": all(p["preserved"] for p in preservation),
                  "all_targets_satisfied": all(t["satisfied"] for t in target_checks),
                  "commit_called": False, "downloads_or_repository_updates": False,
                  "host_database_used": False, "dependency_transaction_accepted": False,
                  "file_conflicts_checked": False, "package_signatures_verified_by_this_run": False,
                  "repository_signatures_verified_by_this_run": False,
                  "image_authentication_accepted": False, "installation_accepted": False, "hardware_accepted": False,
                  "limitations": ["Actual libalpm prepare reads synthetic local and filtered sync metadata only.",
                                  "A rejected target makes the entire result FAIL; remaining targets are diagnostics.",
                                  "File ownership/conflicts, hooks, scriptlets, installed-byte identity and runtime ABI are not validated.",
                                  "Unsigned ALARM DB input and separately authenticated archives are distinct evidence.",
                                  "No package payload, trust state, boot policy or target system is changed."]}
    tuple_audit.write_private(output_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.contract, args.contract_sha256, args.output)
    except (ValueError, OSError, KeyError, TypeError, EOFError, tarfile.TarError) as error:
        parser.exit(2, "transaction prepare refused: " + str(error) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output.absolute()),
                      "commit_called": False}, sort_keys=True))
    return 0 if report["status"].startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
