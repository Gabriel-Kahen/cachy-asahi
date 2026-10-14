# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Prepare exact frozen inputs from supplied bytes. No HTTP, build or source execution.

The caller owns one existing deadline/cancellation frame and supplies check(label).
Every effect and bounded data step checks that frame; this module never renews it.
Exceptions leave any partial private destination unaccepted for caller custody.
"""
import difflib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

PLAN_SHA256 = "557214038227f80762cec07a2b98cbb66d4a6ea9a0bc12ee3679a842fa6ddb96"
CHUNK = 65536


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def close_owned(fd, primary, operation):
    try:
        os.close(fd)
    except BaseException as uncertainty:
        if primary is None:
            raise
        # Preserve the first exception object/traceback. The caller must retain
        # these separate uncertainty notes; closing is not claimed successful.
        BaseException.add_note(primary, "preparation " + operation + " close uncertainty: " + type(uncertainty).__name__ + ": " + str(uncertainty))


def parents(path, check):
    for parent in (path, *path.parents):
        check("before-directory-observation")
        mode = parent.lstat().st_mode
        check("after-directory-observation")
        need(stat.S_ISDIR(mode), "ordinary directory required")


def read(value, cap, check):
    check("before-input-read")
    if type(value) is bytes:
        need(len(value) <= cap, "byte input cap")
        check("after-byte-input")
        return value
    owned = not (type(value) is int)
    if owned:
        path = Path(value).absolute()
        parents(path.parent, check)
        check("before-input-open")
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    else:
        fd = value  # Borrowed regular-file descriptor; no caller offset changes.
    primary = None
    try:
        check("after-input-open")
        facts = os.fstat(fd)
        check("after-input-fstat")
        need(stat.S_ISREG(facts.st_mode) and 0 <= facts.st_size <= cap, "regular bounded input required")
        chunks, offset = [], 0
        while offset < facts.st_size:
            check("before-input-pread")
            chunk = os.pread(fd, min(CHUNK, facts.st_size - offset), offset)
            check("after-input-pread")
            need(chunk, "short input")
            chunks.append(chunk)
            offset += len(chunk)
        check("before-input-final-fstat")
        final = os.fstat(fd)
        check("after-input-final-fstat")
        need((facts.st_dev, facts.st_ino, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns) ==
             (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns), "input changed")
        return b"".join(chunks)
    except BaseException as failure:
        primary = failure
        raise
    finally:
        if owned:
            close_owned(fd, primary, "read")


def unpack(body, specification, check):
    check("before-gzip-open")
    decoded, count = [], 0
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
        while True:
            check("before-gzip-read")
            chunk = stream.read(min(CHUNK, specification["expanded_cap"] - count + 1))
            check("after-gzip-read")
            count += len(chunk)
            need(count <= specification["expanded_cap"], "expanded archive cap")
            if not chunk:
                break
            decoded.append(chunk)
    raw = b"".join(decoded)
    check("before-tar-open")
    files, seen, prefix = {}, set(), None
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|") as stream:
        for member in stream:
            check("after-tar-member")
            name = member.name
            need(len(seen) < specification["member_cap"], "archive member cap")
            need(name and "\\" not in name and all(x not in ("", ".", "..") for x in name.split("/")), "archive path")
            root, _, relative = name.partition("/")
            prefix = prefix or root
            need(root == prefix and name not in seen, "archive root/duplicate")
            seen.add(name)
            need(member.isdir() or member.isfile(), "archive type")
            need(0 <= member.size <= 1048576 and (member.isfile() or member.size == 0), "member byte cap")
            if member.isfile():
                check("before-member-read")
                data = stream.extractfile(member).read(member.size + 1)
                check("after-member-read")
                need(relative and len(data) == member.size, "member truncation/root file")
                files[relative] = {"body": data, "mode": member.mode}
    check("after-tar-close")
    return files


def pack(files, selected, root, epoch, directories_first, check):
    need(0 < len(selected) <= 318, "filtered file count")
    directories = {root}
    for name, row in selected.items():
        check("before-filter-member-proof")
        body = files[name]["body"]
        need(len(body) == row["bytes"] and sha(body) == row["sha256"], "filtered member pin")
        directories.update(root + "/" + "/".join(name.split("/")[:i]) for i in range(1, len(name.split("/"))))
    names = sorted(directories) + [root + "/" + n for n in sorted(selected)] if directories_first else sorted(directories | {root + "/" + n for n in selected})
    output = io.BytesIO()
    check("before-filtered-gzip-open")
    with gzip.GzipFile(fileobj=output, filename="", mode="wb", mtime=epoch, compresslevel=9) as zipped:
        with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as stream:
            for full in names:
                check("before-filtered-tar-member")
                info = tarfile.TarInfo(full)
                info.mtime = epoch
                if full in directories:
                    info.mode, info.type = 0o755, tarfile.DIRTYPE
                    stream.addfile(info)
                else:
                    name = full[len(root) + 1:]
                    info.mode = selected[name]["mode"]
                    body = files[name]["body"]
                    info.size = len(body)
                    stream.addfile(info, io.BytesIO(body))
                check("after-filtered-tar-member")
    check("after-filtered-gzip-close")
    result = output.getvalue()
    need(len(result) <= 8388608, "filtered archive output cap")
    return result


def notices(layout, files, jbigkit, check):
    output = bytearray(layout["project_authored_prefix"].encode())
    for row in layout["members"]:
        check("before-notice-member")
        body = files[row["member"]]["body"]
        need(sha(body) == row["source_sha256"], "notice source pin")
        if jbigkit:
            output += b"\n" + row["member"].encode() + b"\n"
            parts = [{"offset": row["offset"], "length": row["length"]}, {"whitespace": "\n"}]
        else:
            output += ("\n===== " + row["member"] + " / SHA256 " + row["source_sha256"] + " =====\n").encode()
            parts = row["parts"]
        for part in parts:
            check("before-notice-span")
            if "whitespace" in part:
                value = part["whitespace"].encode("ascii")
                need(not value.strip() and len(value) <= 16, "notice separator")
            else:
                start, size = part["offset"], part["length"]
                need(type(start) is int and type(size) is int and 0 <= start <= start + size <= len(body), "notice span")
                value = body[start:start + size]
            output += value
            need(len(output) <= 1048576, "notice output cap")
    return bytes(output)


def shared_makefiles(files, patch, check):
    changed = {}
    for section in patch.decode("utf-8").split("diff --git ")[1:]:
        check("before-shared-patch-section")
        lines = section.splitlines(keepends=True)
        a, b = lines[0].rstrip("\n").split(" ")
        need(a.startswith("a/") and b == "b/" + a[2:], "patch file names")
        name = a[2:]
        need(name in ("Makefile", "libjbig/Makefile", "pbmtools/Makefile") and name not in changed, "patch file scope")
        old = files[name]["body"].decode().splitlines(keepends=True)
        cursor, result, i = 0, [], 4
        while i < len(lines):
            check("before-shared-patch-hunk")
            m = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@[^\n]*\n", lines[i])
            need(m is not None, "patch hunk")
            start, old_n, new_start, new_n = map(int, m.groups())
            need(start - 1 >= cursor, "patch order")
            result.extend(old[cursor:start - 1]); cursor = start - 1
            need(len(result) == new_start - 1, "patch new offset")
            before, after = 0, 0
            i += 1
            while i < len(lines) and not lines[i].startswith("@@ "):
                line = lines[i]
                need(line and line[0] in " +-", "patch line")
                if line[0] in " -":
                    need(cursor < len(old) and old[cursor] == line[1:], "patch context")
                    cursor += 1; before += 1
                if line[0] in " +":
                    result.append(line[1:]); after += 1
                i += 1
            need((before, after) == (old_n, new_n), "patch counts")
        result.extend(old[cursor:])
        changed[name] = "".join(result)
    need(set(changed) == {"Makefile", "libjbig/Makefile", "pbmtools/Makefile"}, "exact shared patch scope")
    return changed


def project_patch(files, patch, check):
    shared = shared_makefiles(files, patch, check)
    output = ["# SPDX-License-Identifier: GPL-2.0-or-later\n",
              "# Copyright (c) 2026 cachy-asahi contributors\n",
              "# Modified 2026-10-13: dated shared-build notices; tests use covered code and original synthetic fixtures.\n"]
    for name in sorted(shared):
        check("before-project-patch-transform")
        text = shared[name]
        at = text.index("\n") + 1
        modified = text[:at] + "# Modified 2026-10-13 by cachy-asahi contributors.\n# Shared-library build uses the retained vendor patch; project checks use synthetic fixtures.\n" + text[at:]
        if name == "Makefile":
            need(modified.count("\tcd pbmtools && $(MAKE) test\n") == 1, "root test match")
            modified = modified.replace("\tcd pbmtools && $(MAKE) test\n", "\t@echo 'Project synthetic conversion tests run from PKGBUILD check().'\n")
        if name == "pbmtools/Makefile":
            begin, end = modified.index("test: test82 test85\n"), modified.index("MAN2TXT=")
            modified = modified[:begin] + "# External example-image/fuzz test targets are omitted from this filtered source.\ntest:\n\t@echo 'Project synthetic conversion tests run from PKGBUILD check().'\n\n" + modified[end:]
        output.extend(difflib.unified_diff(text.splitlines(keepends=True), modified.splitlines(keepends=True), fromfile="a/" + name, tofile="b/" + name))
        check("after-project-patch-transform")
    return "".join(output).encode()


def synthetic(check):
    output = {}
    for number, (width, height, pattern) in enumerate(((1, 1, 0), (1, 1, 1), (13, 7, 2), (32, 9, 3), (17, 11, 4))):
        check("before-synthetic-fixture")
        raster = bytearray(((width + 7) // 8) * height)
        for y in range(height):
            for x in range(width):
                if (0, 1, (x + y) % 2, y % 2, (x * 3 + y * 5) % 7 < 3)[pattern]:
                    raster[y * ((width + 7) // 8) + x // 8] |= 128 >> (x % 8)
        output[f"synthetic-{number}.pbm"] = f"P4\n{width} {height}\n".encode() + raster
    return output


def write(path, body, mode, check):
    check("before-output-open")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    primary = None
    try:
        check("after-output-open")
        offset = 0
        while offset < len(body):
            check("before-output-write")
            count = os.write(fd, body[offset:offset + CHUNK])
            check("after-output-write")
            need(count > 0, "short output write")
            offset += count
        check("before-output-mode")
        os.fchmod(fd, mode)
        check("after-output-mode")
    except BaseException as failure:
        primary = failure
        raise
    finally:
        close_owned(fd, primary, "write")


def prepare_sources(project_dirs, upstream, destination, check, plan_path=None):
    """Create destination/{jbigkit,libtiff}, exactly 27 files, or raise without PASS.

    upstream has four supplied pinned bodies/paths/borrowed regular fds:
    jbigkit, libtiff, shared_patch, reuse. project_dirs maps the two package names
    to caller-owned authenticated project-only asset directories (13 files).
    check must raise whenever the caller's original deadline/cancel frame closes.
    """
    need(callable(check), "original-frame callback required")
    check("preparation-entry")
    need(set(project_dirs) == {"jbigkit", "libtiff"}, "project directory scope")
    need(set(upstream) == {"jbigkit", "libtiff", "shared_patch", "reuse"}, "supplied upstream scope")
    plan_body = read(plan_path or Path(__file__).with_name("materialization-plan.json"), 131072, check)
    need(sha(plan_body) == PLAN_SHA256, "materialization plan pin")
    plan = json.loads(plan_body)
    supplied = {}
    for name, specification in plan["upstream"].items():
        supplied[name] = read(upstream[name], specification["bytes"], check)
        need(len(supplied[name]) == specification["bytes"] and sha(supplied[name]) == specification["sha256"], "upstream pin: " + name)
    files = {name: unpack(supplied[name], plan["upstream"][name], check) for name in ("jbigkit", "libtiff")}
    output = {}
    for row in plan["outputs"]:
        if row["kind"] == "project_asset":
            name = row["package"] + "/" + row["filename"]
            output[name] = read(Path(project_dirs[row["package"]]) / row["filename"], row["bytes"], check)
            need(len(output[name]) == row["bytes"] and sha(output[name]) == row["sha256"], "project Source pin: " + name)
    jfilter = json.loads(output["jbigkit/source-filter.json"])
    selected = {row["name"].removeprefix("jbigkit-2.2/"): {"bytes": row["size"], "sha256": row["sha256"], "mode": 0o644} for row in jfilter["included_files"]}
    output["jbigkit/jbigkit-2.2-project-filtered.tar.gz"] = pack(files["jbigkit"], selected, "jbigkit-2.2", 1791585070, False, check)
    tfilter = json.loads(output["libtiff/source-filter.json"])
    output["libtiff/libtiff-project-4.7.2-source.tar.gz"] = pack(files["libtiff"], tfilter["allowlist"], "libtiff-project-4.7.2", 1782568888, True, check)
    output["jbigkit/COPYING"] = files["jbigkit"]["COPYING"]["body"]
    output["jbigkit/upstream-ANNOUNCE"] = files["jbigkit"]["ANNOUNCE"]["body"]
    output["jbigkit/jbigkit-2.2-shared_lib.patch"] = supplied["shared_patch"]
    output["jbigkit/packaging-REUSE.toml"] = supplied["reuse"]
    output["jbigkit/jbigkit-project-filter-tests.patch"] = project_patch(files["jbigkit"], supplied["shared_patch"], check)
    output["jbigkit/NOTICE"] = notices(plan["jbig_notice"], files["jbigkit"], True, check)
    output["libtiff/UPSTREAM-NOTICES.txt"] = notices(plan["tiff_notice"], files["libtiff"], False, check)
    output.update({"jbigkit/" + n: b for n, b in synthetic(check).items()})
    expected = {row["package"] + "/" + row["filename"]: row for row in plan["outputs"]}
    need(set(output) == set(expected) and len(output) == 27, "exact 27 output membership")
    need(sum(map(len, output.values())) <= 8388608, "combined output cap")
    for name, body in output.items():
        check("before-output-byte-proof")
        observed_bytes, expected_bytes = len(body), expected[name]["bytes"]
        observed_sha256 = expected_sha256 = None
        if observed_bytes == expected_bytes:
            observed_sha256, expected_sha256 = sha(body), expected[name]["sha256"]
        try:
            need(observed_bytes == expected_bytes and observed_sha256 == expected_sha256,
                 "derived output pin: " + name)
        except ValueError as error:
            try:
                error._materialize_output_proof = {
                    "schema_version": 1, "output": name,
                    "mismatch": "LENGTH" if observed_bytes != expected_bytes else "SHA256",
                    "expected_bytes": expected_bytes, "observed_bytes": observed_bytes,
                    "expected_sha256": expected_sha256, "observed_sha256": observed_sha256}
            except BaseException as secondary:
                error._materialize_output_control = secondary
                prior = error.__cause__
                if secondary is not error and prior is not secondary:
                    error.__cause__ = secondary if prior is None else BaseExceptionGroup(
                        "materialized output diagnostic secondary cause", [prior, secondary])
            raise
    destination = Path(destination).absolute()
    parents(destination.parent, check)
    check("before-fresh-destination")
    destination.mkdir(mode=0o700)
    check("after-fresh-destination")
    for package in ("jbigkit", "libtiff"):
        check("before-package-directory")
        (destination / package).mkdir(mode=0o700)
        check("after-package-directory")
    for name in sorted(output):
        write(destination / name, output[name], expected[name]["mode"], check)
    result = {}
    for name, row in sorted(expected.items()):
        body = read(destination / name, row["bytes"], check)
        need(len(body) == row["bytes"] and sha(body) == row["sha256"], "materialized output pin")
        result[name] = {"bytes": len(body), "sha256": sha(body), "mode": row["mode"]}
    check("preparation-completion")
    return {"files": result, "files_count": 27, "plan_sha256": PLAN_SHA256,
            "HTTP_build_GPG_or_upstream_code_execution": False,
            "public_promotion_or_native_build_admission": False}
