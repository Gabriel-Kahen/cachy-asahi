#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acquire pinned public Qt family leaves inside an existing owned ext4 volume."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import signal
import ssl
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


R = module("qt_acquisition_runner", HERE / "runner_inputs.py")
K = module("qt_acquisition_publish", HERE.parents[1] / "release" / "offline_kit.py")
C, M, P, need = R.C, R.M, R.P, R.need
ARCHIVE = R.md4c.PACKAGE
CERT = "md4c-r128-TEST-public.gpg"
R128_ORIGINAL = dict(bytes=2_255_414, sha256="ec0b1d79132cb9bcb2e5646ac2e70f675c57b8747f60cdab2737dc5bacc4d734")
R128_TAR = dict(bytes=1_197_476, sha256="aba33b1f9b8bc0abe178aea2ab448c900ca25e052b5a4b7f808a471120b9f678")
R128_PACKAGE = dict(bytes=74_076, sha256="19149e51f05a7d93426dda7a66fd80d67bd235cab7ac4505130f7de6d40b5b95")
R128_EXPORT = "llhttp-reference-owned-public-j6k_b1ih"
R128_MEMBER = f"{R128_EXPORT}/evidence/build-1/artifacts/{ARCHIVE}"
ROOTFS = re.compile(r"ArchLinuxARM-[0-9]{4}\.[0-9]{2}-aarch64-rootfs\.tar\.gz(?:\.sig)?")
REPO = "https://raw.githubusercontent.com/Gabriel-Kahen/cachy-asahi/"
ALARM = "https://ca.us.mirror.archlinuxarm.org/os/multi/"
KEYRING = "https://raw.githubusercontent.com/archlinuxarm/PKGBUILDs/"
QT_MIRROR = "https://qt.mirror.constant.com/archive/qt/6.12/6.12.0/submodules/"
LIMIT = 2 * 1024**3
PUBLIC_HOSTS = {"raw.githubusercontent.com", "ca.us.mirror.archlinuxarm.org", "qt.mirror.constant.com"}


class AcquisitionError(ValueError):
    """Only bounded, safe acquisition diagnostics reach stderr."""


def diagnostic(error):
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP_{error.code}"
    message = str(error)
    return message if re.fullmatch("[A-Z0-9_]{1,128}", message) else type(error).__name__


def git_url(commit, path):
    need(isinstance(commit, str) and re.fullmatch("[0-9a-f]{40}", commit), "FULL_PUBLIC_GIT_REVISION_REQUIRED")
    need(isinstance(path, str) and all(re.fullmatch("[A-Za-z0-9._+@~:-]+", part)
         and part not in {".", ".."} for part in path.split("/")), "RELATIVE_PUBLIC_GIT_LEAF_REQUIRED")
    return REPO + commit + "/" + urllib.parse.quote(path, safe="/")


def exact_map(rows):
    indexed = {row["id"]: row for row in rows}
    need(len(indexed) == len(rows), "DUPLICATE_PUBLIC_ROUTE")
    return indexed


def public_targets(portable, selection, routes):
    """Join untrusted route declarations to independently selected bytes and names."""
    need(selection["kind"] == R.KIND and selection["schema"] == 1 and selection["Root_acceptance"] is None
         and selection["historical_candidate_map"] == P.CANDIDATE_MAP
         and selection["official_dependency_lock"] == P.DEPENDENCIES
         and routes["kind"] == "Qt-Family-Transport-Public-Routes-DATA", "EXACT_QT_ACQUISITION_SELECTION")
    mapping = M.load(portable / R.ORIGINAL, selection["original_source_map"], {})
    need(mapping["input_plan_complete"] is True and mapping["Root_acceptance"] is None
         and R.pin(mapping["files"][R.INPUTS]) == selection["original_family_inputs"]
         and R.mapped_git_paths(mapping) == selection["public_git"], "EXACT_ORIGINAL_FAMILY_PIN")
    official = exact_map(routes["routes"])
    retained = exact_map(routes["exact_retained574_index_leaf_routes"])
    revision = routes["public_Git_main"]
    targets = {}

    def add(path, expected, url):
        need(path not in targets, "DUPLICATE_ACQUISITION_LEAF")
        M.descriptor(expected, LIMIT)
        targets[path] = dict(pin=expected, url=url)

    def retained_url(leaf, expected):
        row = retained[leaf]
        need(row["git_path"] == "packages/" + leaf and R.pin(row) == expected,
             "EXACT_IMMUTABLE_PACKAGE_ROUTE")
        url = git_url(row["git_commit"], row["git_path"])
        need(urllib.parse.unquote(url) == row["git_immutable_url"], "INCONSISTENT_IMMUTABLE_PACKAGE_URL")
        return url

    for group, folder in R.BASE_GROUPS.items():
        for leaf, expected in selection["base_materials"][group].items():
            R.local_ref(Path("/"), folder, leaf, expected)
            if group == "keyring_materials":
                row = official[leaf]
                url = row["url"]
                suffix = "/core/archlinuxarm-keyring/" + leaf
                need(R.pin(row) == expected and re.fullmatch(re.escape(KEYRING) + "[0-9a-f]{40}" + re.escape(suffix), url),
                     "EXACT_PUBLIC_ALARM_KEYRING_ROUTE")
            elif ROOTFS.fullmatch(leaf):
                row = official[leaf]
                url = ALARM + leaf
                need(R.pin(row) == expected and row["url"] == url, "EXACT_DATED_ALARM_ROOTFS_ROUTE")
            else:
                url = retained_url(leaf, expected)
            add("operands/" + folder + "/" + leaf, expected, url)

    for role, leaf in R.BASE_META.items():
        row = routes["public_base349_metadata"][leaf]
        expected = selection["base_metadata"][role]
        need(R.pin(row) == expected and row["git_commit"] == revision, "EXACT_BASE_METADATA_ROUTE")
        url = git_url(revision, row["git_path"])
        need(url == row["git_immutable_url"], "INCONSISTENT_BASE_METADATA_URL")
        add("operands/metadata/" + leaf, expected, url)

    for name, row in selection["dependencies"].items():
        if name == "md4c":
            continue
        for role, suffix in (("archive", ""), ("signature", ".sig")):
            leaf = row["filename"] + suffix
            add("operands/dependencies/" + leaf, row[role], retained_url(leaf, row[role]))
    for member, leaf in R.mapped_archive_paths().items():
        expected = R.pin(mapping["files"][member])
        row = official[leaf]
        need(R.pin(row) == expected and re.fullmatch(
             r"https://download\.qt\.io/(?:archive/qt|official_releases/qt)/6\.12/6\.12\.0/submodules/" + re.escape(leaf),
             row["url"]), "EXACT_OFFICIAL_QT_SOURCE_ROUTE")
        add("operands/qt-upstream/" + leaf, expected, QT_MIRROR + leaf)
    for member, rel in selection["public_git"].items():
        add("framework/" + rel, R.pin(mapping["files"][member]), git_url(revision, rel))

    need(len(targets) == 517 + 3 + 12 + 5 + len(selection["public_git"])
         and sum(row["pin"]["bytes"] for row in targets.values()) <= LIMIT, "BOUNDED_COMPLETE_PUBLIC_ACQUISITION")
    return targets


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def open_public():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context())).open


def receive(open_url, url, expected, target):
    """Bound response framing and count bytes before a result is published."""
    parsed = urllib.parse.urlsplit(url)
    need(parsed.scheme == "https" and parsed.netloc in PUBLIC_HOSTS
         and not parsed.query and not parsed.fragment, "EXACT_PUBLIC_HTTPS_ROUTE_REQUIRED")
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity",
                                                    "User-Agent": "cachy-asahi-qt612-pinned-inputs/1"})
    with open_url(request, timeout=30) as response:
        need(response.status == 200 and response.geturl() == url
             and response.headers.get("Content-Encoding", "identity").lower() == "identity", "EXACT_HTTP_BODY_REQUIRED")
        lengths = response.headers.get_all("Content-Length", [])
        need(not lengths or lengths == [str(expected["bytes"])], "HTTP_CONTENT_LENGTH_MISMATCH")
        total = 0
        digest = hashlib.sha256()
        while block := response.read1(min(65_536, expected["bytes"] - total + 1)):
            total += len(block)
            need(total <= expected["bytes"], "HTTP_BODY_OVER_LIMIT")
            digest.update(block)
            target.write(block)
        need(dict(bytes=total, sha256=digest.hexdigest()) == expected, "HTTP_WHOLE_INPUT_PIN_MISMATCH")


def materialize(writer, name, fetch):
    """Create the streamed leaf directly under the retained private directory FD."""
    # Arch epoch separators may occur in archive basenames.
    need(all(re.fullmatch(r"[A-Za-z0-9._+@~:-]+", part) and part not in {".", ".."}
             for part in name.split("/")), "SAFE_ACQUIRED_RELATIVE_PATH")
    path = writer.root / name
    writer.check()
    parent = writer.directory(path.parent)
    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as target:
        fetch(target)
        os.fchmod(target.fileno(), 0o644)
        target.flush()
        opened = os.fstat(target.fileno())
    need(M.identity(opened) == M.identity(path.lstat()), "ACQUIRED_LEAF_REPLACED")
    writer.files[path] = M.identity(opened)
    writer.check()


def r128_package(raw, expected):
    need(C.pin(raw) == R128_ORIGINAL and expected == R128_PACKAGE, "EXACT_R128_ORIGINAL_AND_PACKAGE_PIN")
    clean = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", raw)
    lines = [re.sub(rb"^\d{4}-\d\d-\d\dT[0-9:.]+Z\s+", b"", line.removeprefix(b"\xef\xbb\xbf")).strip()
             for line in clean.splitlines()]
    tag = R128_EXPORT.encode()
    begin = b"CACHY_ASAHI_EVIDENCE_BEGIN " + tag + b" sha256=" + R128_TAR["sha256"].encode() + b" bytes=" + str(R128_TAR["bytes"]).encode()
    end = b"CACHY_ASAHI_EVIDENCE_END " + tag
    starts = [i for i, line in enumerate(lines) if line.startswith(b"CACHY_ASAHI_EVIDENCE_BEGIN ")]
    ends = [i for i, line in enumerate(lines) if line.startswith(b"CACHY_ASAHI_EVIDENCE_END ")]
    need(len(starts) == len(ends) == 1 and starts[0] < ends[0] and lines[starts[0]] == begin and lines[ends[0]] == end,
         "EXACT_R128_EXPORT_ENVELOPE")
    compressed = base64.b64decode(b"".join(lines[starts[0] + 1:ends[0]]), validate=True)
    need(C.pin(compressed) == R128_TAR, "EXACT_R128_COMPRESSED_INPUT")
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
        count, expanded, body = 0, 0, None
        for row in archive:
            count += 1
            expanded += row.size
            need(count <= 4096 and 0 <= row.size and expanded <= 16 * 1024**2 and row.isfile(),
                 "BOUNDED_R128_ORDINARY_MEMBERS")
            if row.name == R128_MEMBER:
                need(body is None and row.size == expected["bytes"], "ONE_EXACT_R128_PACKAGE_CHILD")
                with archive.extractfile(row) as child:
                    body = child.read(expected["bytes"] + 1)
    need(body is not None and C.pin(body) == expected, "EXACT_R128_PACKAGE_CHILD_BYTES")
    return body


@contextmanager
def time_limit(seconds):
    def expired(_signal, _frame):
        raise TimeoutError("QT_ACQUISITION_DEADLINE")
    need(1 <= seconds <= 1800 and signal.getitimer(signal.ITIMER_REAL) == (0, 0), "BOUNDED_ACQUISITION_DEADLINE")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def acquire(args, workspace, open_url):
    portable, plan, md4c, output = map(M.ordinary, (args.portable, args.route_plan, args.md4c_input, args.output))
    log = M.ordinary(args.r128_job_log) if args.r128_job_log else None
    operands = (portable, plan, md4c) + ((log,) if log else ())
    need(all(path.is_relative_to(workspace) and path != workspace for path in (*operands, output))
         and all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in operands)
         and not output.exists(), "FRESH_DISJOINT_IN_VOLUME_ACQUISITION")
    observed = {}
    selection = M.load(portable / R.SELECTION, R.external_pin(portable / R.SELECTION, args.selection_sha256), observed)
    route_pin = R.external_pin(plan, args.route_plan_sha256)
    routes = M.load(plan, route_pin, observed)
    targets = public_targets(portable, selection, routes)
    chosen = selection["dependencies"]["md4c"]
    cert_pin = dict(bytes=args.md4c_cert_bytes, sha256=args.md4c_cert_sha256)
    M.descriptor(cert_pin, 65_536)
    need(cert_pin["bytes"] > 0 and chosen["filename"] == ARCHIVE, "EXACT_MD4C_WITH_PUBLIC_CERT_REQUIRED")
    M.stream(md4c / CERT, cert_pin, observed, cap=65_536)
    M.stream(md4c / (ARCHIVE + ".sig"), chosen["signature"], observed, cap=65_536)
    if log:
        need(not (md4c / ARCHIVE).exists(), "EXACTLY_ONE_MD4C_BODY_SOURCE")
        raw = M.stream(log, R128_ORIGINAL, observed, cap=R128_ORIGINAL["bytes"], collect=True)
        body = r128_package(raw, chosen["archive"])
    else:
        body = M.stream(md4c / ARCHIVE, chosen["archive"], observed, cap=4 * 1024**2, collect=True)

    with tempfile.TemporaryDirectory(prefix=".qt-acquisition-", dir=workspace) as temporary:
        writer = M.Writer(Path(temporary) / "ready")
        try:
            for name, row in sorted(targets.items()):
                try:
                    materialize(writer, name, lambda out: receive(open_url, row["url"], row["pin"], out))
                except (OSError, ValueError) as error:
                    raise AcquisitionError(f"{name}: {diagnostic(error)}") from None
            writer.put(f"operands/dependencies/{ARCHIVE}", raw=body)
            writer.put(f"operands/dependencies/{ARCHIVE}.sig", source=md4c / (ARCHIVE + ".sig"),
                       expected=chosen["signature"], observed=observed)
            writer.put(f"trust/{CERT}", source=md4c / CERT, expected=cert_pin, observed=observed)
            receipt = dict(status="ACQUIRED_QT_RUNNER_INPUT_BYTES_ONLY", route_plan=route_pin,
                           selection_sha256=args.selection_sha256, public_files=len(targets),
                           public_bytes=sum(row["pin"]["bytes"] for row in targets.values()),
                           md4c_body="exact-R128-job-134591565463" if log else "external-pinned-package",
                           md4c_public_certificate=cert_pin, GPG="NOT_RUN", Root_acceptance=None)
            writer.put("acquisition.DATA.json", raw=C.encoded(receipt))
            M.unchanged(observed)
            info = writer.root.stat()
            parent = K.c.directory(output.parent)
            try:
                K.publish(writer.root, parent, output, (info.st_dev, info.st_ino))
            finally:
                os.close(parent)
            return receipt
        finally:
            writer.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("workspace", "portable", "selection-sha256", "route-plan", "route-plan-sha256",
                 "md4c-input", "md4c-cert-sha256", "output"):
        p.add_argument("--" + name, required=True)
    for name in ("workspace-device", "workspace-inode", "workspace-mount-id", "md4c-cert-bytes", "timeout-seconds"):
        p.add_argument("--" + name, required=True, type=int)
    p.add_argument("--r128-job-log")
    args = p.parse_args()
    try:
        with time_limit(args.timeout_seconds), R.owned_workspace(
                args.workspace, args.workspace_device, args.workspace_inode, args.workspace_mount_id) as workspace:
            receipt = acquire(args, workspace, open_public())
        print(C.encoded(receipt).decode(), end="")
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        # Runtime exceptions can contain URL fragments or raw request details.
        detail = str(error) if isinstance(error, AcquisitionError) else diagnostic(error)
        print(f"Qt input acquisition refused: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
