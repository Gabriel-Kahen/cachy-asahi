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
import subprocess
import sys
from tempfile import mkdtemp

EXAMPLE = "examples/development/hello.c"
EXAMPLE_SHA = "fc4d365017395544876cf526639d8dfa1b4f6784d7f92887ee35c40146f749b5"
GREETING = "Hello from cachy-asahi"
ORIGIN = Path(__file__).resolve().parents[2]
FLAGS = ("-Wall", "-Wextra", "-Werror", "-O2")
LOCAL_UPLOAD = "git -c uploadpack.allowFilter=true upload-pack"


def git(repo, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    command = ["git", "-C", str(repo), "-c", f"core.hooksPath={os.devnull}", "-c", "gc.auto=0",
               "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", *args]
    return subprocess.run(command, env=env, check=True, capture_output=True).stdout


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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
    # Configure the local server as well as the client to avoid copying unused blobs.
    git(source, "clone", "--no-local", "--no-checkout", "--depth=1", "--no-tags", "--filter=blob:none",
        "--sparse", f"--upload-pack={LOCAL_UPLOAD}", "-c", f"remote.origin.uploadpack={LOCAL_UPLOAD}",
        "--", str(source), str(checkout))
    if git(checkout, "rev-parse", "HEAD").decode().strip() != commit:
        git(checkout, "fetch", "--no-tags", "--depth=1", "--filter=blob:none", "origin", commit)
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
    baseline = json.loads((evidence / "baseline/report.json").read_bytes())
    if baseline["status"] != "PASS" or baseline["source_sha256"] != EXAMPLE_SHA:
        raise ValueError("A successful pinned baseline is required before the rebuild.")
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
    args = cli.parse_args()
    work = args.workspace.resolve()
    try:
        if args.phase == "prepare":
            return prepare(work, args.source, args.revision)
        return rebuild(work, args.expect)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        message = error.stderr.decode(errors="replace").strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(message or str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
