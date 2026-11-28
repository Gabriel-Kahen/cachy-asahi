#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Clone, build and run the pinned development example in a user-owned workspace."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
from tempfile import mkdtemp

EXAMPLE = "examples/development/hello.c"
EXAMPLE_SHA = "fc4d365017395544876cf526639d8dfa1b4f6784d7f92887ee35c40146f749b5"
GREETING = "Hello from cachy-asahi"
ORIGIN = Path(__file__).resolve().parents[2]
FLAGS = ("-Wall", "-Wextra", "-Werror", "-O2")
LOCAL_UPLOAD = "git -c uploadpack.allowFilter=true upload-pack"
REPORT_LIMIT = 4 * 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def git(repo, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    command = ["git", "-C", str(repo), "-c", f"core.hooksPath={os.devnull}", "-c", "gc.auto=0",
               "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", *args]
    return subprocess.run(command, env=env, check=True, capture_output=True).stdout


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def retained(path, read):
    """Read one ordinary saved file without following a link or blocking on a pipe."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size == 0:
            raise ValueError(f"Saved evidence must be a nonempty regular file: {path}")
        result = read(stream)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat()):
            raise ValueError(f"Saved evidence changed while reading: {path}")
    return result


def success_evidence(directory, phase):
    if not directory.is_dir() or directory.resolve() != directory:
        raise ValueError(f"Use an ordinary saved {phase} evidence directory.")
    raw = retained(directory / "report.json", lambda stream: stream.read(REPORT_LIMIT + 1))
    if len(raw) > REPORT_LIMIT:
        raise ValueError("The saved report exceeds the readback limit.")
    report = json.loads(raw)
    if (not isinstance(report, dict) or type(report.get("schema")) is not int or report["schema"] != 1
            or report.get("phase") != phase or report.get("status") != "PASS"):
        raise ValueError(f"A successful {phase} report is required.")
    if not all(isinstance(report.get(key), str) and COMMIT.fullmatch(report[key])
               for key in ("source_revision", "checkout_head")):
        raise ValueError("The saved report must record both full Git commits.")
    origin = report.get("source_repository")
    if not isinstance(origin, str) or not Path(origin).is_absolute():
        raise ValueError("The saved report must record the source repository.")
    expected = report.get("expected_stdout")
    for role in ("compiler", "compile", "run"):
        row = report.get(role)
        if not isinstance(row, dict) or type(row.get("exit")) is not int or row["exit"] != 0:
            raise ValueError(f"The saved {phase} report must record a successful {role} command.")
    argv = report["compile"].get("argv")
    if (not isinstance(argv, list) or len(argv) != len(FLAGS) + 4 or
            argv[:-1] != ["cc", *FLAGS, EXAMPLE, "-o"] or not isinstance(argv[-1], str)):
        raise ValueError(f"The saved {phase} report has a different build command.")
    binary = Path(argv[-1])
    if (not binary.is_absolute() or binary.name != "hello" or binary.parent.name != directory.name
            or report["compiler"].get("argv") != ["cc", "--version"]
            or report["run"].get("argv") != [argv[-1]] or not isinstance(expected, str)
            or not expected.endswith("\n") or report["run"].get("stdout") != expected):
        raise ValueError(f"The saved {phase} report has inconsistent tool, executable or output records.")
    if phase == "baseline" and (report["checkout_head"] != report["source_revision"]
                                or report.get("source_sha256") != EXAMPLE_SHA or expected != GREETING + "\n"):
        raise ValueError("A successful pinned baseline is required.")
    for leaf, key in (("hello.c", "source_sha256"), ("hello", "binary_sha256")):
        observed = retained(directory / leaf, lambda stream: hashlib.file_digest(stream, "sha256").hexdigest())
        if observed != report.get(key):
            raise ValueError(f"Saved {phase} {leaf} differs from its report.")
    return report, sha(raw)


def verify(rebuild_directory):
    if not rebuild_directory.name.startswith("rebuild-"):
        raise ValueError("Select a rebuild-* evidence directory beside its baseline directory.")
    baseline, baseline_sha = success_evidence(rebuild_directory.parent / "baseline", "baseline")
    edited, edited_sha = success_evidence(rebuild_directory, "rebuild")
    if (edited["source_revision"] != baseline["source_revision"]
            or edited["source_repository"] != baseline["source_repository"]
            or edited["source_sha256"] == baseline["source_sha256"]):
        raise ValueError("The saved rebuild must use the same source revision and an edited example.")
    print(json.dumps(dict(status="PASS", scope="retained-build-evidence", source_revision=baseline["source_revision"],
                          baseline_report_sha256=baseline_sha, rebuild_report_sha256=edited_sha), indent=2))
    return 0


def example(checkout):
    source = checkout / EXAMPLE
    if source.resolve() != source or not source.is_file():
        raise ValueError("The example must be a regular file inside the exercise clone.")
    return source.read_bytes()


def command(argv, cwd):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, encoding="utf-8", errors="replace")
    return dict(argv=argv, exit=result.returncode, stdout=result.stdout, stderr=result.stderr)


def build(checkout, evidence, revision, expected, source, *, phase, origin):
    (evidence / "hello.c").write_bytes(source)
    binary = evidence / "hello"
    version = command(["cc", "--version"], checkout)
    built = command(["cc", *FLAGS, EXAMPLE, "-o", str(binary)], checkout)
    ran = command([str(binary)], checkout) if built["exit"] == 0 else None
    passed = (version["exit"] == built["exit"] == 0 and ran["exit"] == 0
              and ran["stdout"] == expected + "\n" and example(checkout) == source)
    report = dict(
        schema=1, phase=phase, status="PASS" if passed else "FAILED",
        edit="user-managed between commands" if phase == "rebuild" else "none",
        source_repository=str(origin), source_revision=revision,
        checkout_head=git(checkout, "rev-parse", "HEAD").decode().strip(),
        architecture=platform.machine(), page_size=os.sysconf("SC_PAGE_SIZE"),
        effective_uid=os.geteuid(), observed_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256=sha(source), binary_sha256=sha(binary.read_bytes()) if binary.is_file() else None,
        expected_stdout=expected + "\n", compiler=version, compile=built, run=ran,
    )
    path = evidence / "report.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    if ran is not None:
        print(ran["stdout"], end="")
    print(f"Evidence: {path}")
    if not passed:
        print("The build/run or expected output check failed. See the retained evidence.", file=sys.stderr)
    return 0 if passed else 1


def prepare(work, source, revision):
    source = source.resolve(strict=True)
    source = Path(os.fsdecode(git(source, "rev-parse", "--show-toplevel").rstrip(b"\n"))).resolve()
    commit = git(source, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
    if work.is_relative_to(source) or work.is_relative_to(ORIGIN):
        raise ValueError("Choose a fresh workspace outside the source repositories.")
    if sha(git(source, "show", f"{commit}:{EXAMPLE}")) != EXAMPLE_SHA:
        raise ValueError("The selected revision does not contain the pinned development example.")

    work.mkdir(mode=0o700)
    checkout = work / "checkout"
    object_format = git(source, "rev-parse", "--show-object-format").decode().strip()
    git(source, "init", f"--object-format={object_format}", "--", str(checkout))
    git(checkout, "remote", "add", "--no-tags", "origin", str(source))
    # Filter the initial pack and subsequent lazy blob fetches from the local source.
    git(checkout, "config", "remote.origin.uploadpack", LOCAL_UPLOAD)
    git(checkout, "fetch", "--depth=1", "--filter=blob:none", "origin", commit)
    git(checkout, "sparse-checkout", "set", EXAMPLE.rsplit("/", 1)[0])
    git(checkout, "checkout", "--detach", commit)
    raw = example(checkout)
    if sha(raw) != EXAMPLE_SHA:
        raise ValueError("The checked-out example differs from the pinned C file.")
    evidence = work / "evidence/baseline"
    evidence.mkdir(mode=0o700, parents=True)
    return build(checkout, evidence, commit, GREETING, raw, phase="baseline", origin=source)


def rebuild(work, expected):
    checkout, evidence = work / "checkout", work / "evidence"
    if not all(path.is_dir() and path.resolve() == path for path in (checkout, evidence)):
        raise ValueError("Choose the existing local exercise workspace.")
    baseline, _ = success_evidence(evidence / "baseline", "baseline")
    revision = baseline["source_revision"]
    git(checkout, "merge-base", "--is-ancestor", revision, "HEAD")
    raw = example(checkout)
    if sha(raw) == EXAMPLE_SHA:
        raise ValueError("Save an edit to the example in the exercise clone first.")
    target = Path(mkdtemp(prefix="rebuild-", dir=evidence))
    return build(checkout, target, revision, expected, raw, phase="rebuild", origin=baseline["source_repository"])


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    phases = cli.add_subparsers(dest="phase", required=True)
    first = phases.add_parser("prepare", help="clone the source and build/run the pinned baseline")
    first.add_argument("workspace", type=Path, help="fresh directory for the clone and evidence")
    first.add_argument("--source", type=Path, default=ORIGIN, help="reviewed local Git repository")
    first.add_argument("--revision", default="HEAD", help="reviewed Git commit or local ref")
    second = phases.add_parser("rebuild", help="build and run after saving your edit")
    second.add_argument("workspace", type=Path)
    second.add_argument("--expect", required=True, help="expected output line after your edit")
    check = phases.add_parser("verify", help="check a saved baseline and selected rebuild")
    check.add_argument("rebuild_directory", type=Path, help="rebuild-* directory beside the saved baseline")
    args = cli.parse_args()
    try:
        if args.phase == "verify":
            return verify(args.rebuild_directory.absolute())
        work = args.workspace.resolve()
        if args.phase == "prepare":
            return prepare(work, args.source, args.revision)
        return rebuild(work, args.expect)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        message = error.stderr.decode(errors="replace").strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(message or str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
