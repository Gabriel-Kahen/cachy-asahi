#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the exact Current606 16 KiB clock successor from the closed parent tree."""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
PARENT = "f41538685c55b744410b657506745d654e142d09"
PARENT_TREE = "05e6eb01b303898a1aced5d716d03079788c23fe"
CANDIDATE = "542b9247ef45ab70c918991f415821d178d5da86"
CANDIDATE_TREE = "f0c3fda73486024e8a53e796e97803a4c005e213"
PARENT_REF = "refs/heads/codex/current606-apps16-progress-fresh-test-20261118-r1"
CANDIDATE_REF = "refs/heads/codex/current606-apps16-16k-clock-epoch-20261118-r2"
MANIFEST = "source-manifest.json"
CLOCK = "factory/guest_clock606.py"
PAYLOAD = HERE / "clock606-payload" / "guest_clock606.py"
PARENT_COUNT, CANDIDATE_COUNT = 591, 592
PARENT_BYTES, CANDIDATE_BYTES = 23946528, 23955952
MODE = 0o644
PARENT_MANIFEST = (103301, "41b13a35cdbe809eb868ecd041b3e14eaaf850467310d69f3d9d4a21de7c7a56")
EXPECTED = {
    "admission.py": (46448, "ec4dbd7198a75aef5156f735c2e7f60c7e64f7c31e9006a9e49de4292eb41fbf"),
    "factory/factory.py": (21277, "8a8bd5a83744ac8b9b3c039cfa66437fea1076ca1f9a85bf22c27c35bf284f10"),
    CLOCK: (8680, "6675352f4fae070843229d55de914a7c66c1f403a2a312bd40f0ac5e09e127e6"),
    "factory/service_capacity.py": (7234, "6d8b2e3477e3a9cd6afb06189cb609281dd7661f1332e58ddab06d0a8cb59241"),
    "native.py": (14549, "488ac394148649cb5f4abf9ac0010a56ff64502eb4aa6928d79b59973b9586de"),
    MANIFEST: (103447, "54bba76dcb350accadc12293b6c1861f6538801ceed1cefc7cd0244d87846dcc"),
}
CHANGED = frozenset(EXPECTED)
INGRESS_NAMES = ("_TEST_INGRESS_ADDED", "_TEST_INGRESS_NEW", "_TEST_INGRESS_COUNT")

CLOCK_LINE = b"    if mode=='generic16k':changes['guest_clock606']=load('_guest_clock606',HERE/'guest_clock606.py').apply(out,pin,once)\n"
NATIVE_LINE = b"  if p['mode']=='generic16k':v['guest_clock_handoff']=load('_current606_guest_clock_retention',ROOT/'factory/guest_clock606.py').verify(g,p)\n"
SERVICE = b""" p=profile();need(selected=='tcg1800','explicit fixed service profile only')
 raw=read(Path(namespace['__file__']))
 progress=b"    changes['installed606_progress']=load('_installed606_progress',HERE/'installed606_progress.py').apply(out,pin)\\n"
 ingress=b";load('_current606_fresh_ingress',HERE/'fresh606.py').prepare_code(held,root,assets,out,selected)\\n"
 clock=b"    if mode=='generic16k':changes['guest_clock606']=load('_guest_clock606',HERE/'guest_clock606.py').apply(out,pin,once)\\n"
 need(raw.count(progress)==raw.count(ingress)==raw.count(clock)==1,'exact observer, TEST ingress and 16 KiB clock factory seams')
 raw=raw.replace(progress,b'',1).replace(clock,b'',1).replace(ingress,b';held.prepare(root,assets,out,selected)\\n',1)
 need(raw.endswith(FACTORY_FOOTER.encode())and pin(raw[:-len(FACTORY_FOOTER.encode())])==p['original_helpers']['factory.py'],'entire original factory before finite opt-in footer')
"""


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def exact(body, pair):
    return (len(body), hashlib.sha256(body).hexdigest()) == pair


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def read_leaf(path, size, mode=MODE):
    need(path == path.resolve(strict=True), "Canonical ordinary source leaf required: " + path.name)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOATIME
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and (mode is None or stat.S_IMODE(before.st_mode) == mode)
             and before.st_nlink == 1 and before.st_size == size, "Exact ordinary leaf size and mode required: " + path.name)
        raw = stream.read(size + 1)
        after = os.fstat(stream.fileno())
        current = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        need(len(raw) == size and all(getattr(before, field) == getattr(after, field) == getattr(current, field)
                                     for field in fields), "Original leaf changed while reading: " + path.name)
    return raw


def parent_manifest(body):
    need(exact(body, PARENT_MANIFEST), "Exact f4153868 source manifest required")
    value = json.loads(body)
    need(encoded(value) == body and set(value) == {"actual_ref", "actual_run", "actual_source", "files", "status"}
         and all(value[key] is None for key in ("actual_ref", "actual_run", "actual_source"))
         and len(value["files"]) == PARENT_COUNT - 1 and MANIFEST not in value["files"] and CLOCK not in value["files"],
         "Exact unissued parent file map required")
    return value


def layout(bodies):
    """Compute the canonical SHA-1 Git tree using only the pinned file bodies and modes."""
    root = {}
    for leaf, data in bodies.items():
        path = PurePosixPath(leaf)
        need(path.parts and not path.is_absolute() and ".." not in path.parts and path.as_posix() == leaf,
             "Canonical relative Git member required")
        directory = root
        for part in path.parts[:-1]:
            directory = directory.setdefault(part, {})
        directory[path.name] = data

    def git_object(kind, body):
        return hashlib.sha1(kind + b" " + str(len(body)).encode("ascii") + b"\0" + body).digest()

    def finish(directory):
        entries = []
        for name, value in directory.items():
            raw = name.encode("utf-8")
            if isinstance(value, dict):
                entries.append((raw + b"/", b"40000 " + raw + b"\0" + finish(value)))
            else:
                entries.append((raw, b"100644 " + raw + b"\0" + git_object(b"blob", value)))
        return git_object(b"tree", b"".join(row for _, row in sorted(entries)))

    return finish(root).hex()


def read_tree(root, pins):
    need(root.is_absolute() and root == root.resolve(strict=True) and root.is_dir(), "Canonical ordinary source root required")
    directories = {part.as_posix() for key in pins for part in PurePosixPath(key).parents} - {"."}
    expected = set(pins)
    seen = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            leaf = Path(parent) / name
            relative = leaf.relative_to(root).as_posix()
            meta = leaf.lstat()
            need(not stat.S_ISLNK(meta.st_mode) and (relative in directories if name in dirs else relative in expected),
                 "Unexpected source member: " + relative)
            if name in files:
                seen.add(relative)
    need(seen == expected, "Incomplete exact source namespace")
    bodies = {}
    for leaf, expected_pin in pins.items():
        body = read_leaf(root / leaf, expected_pin["bytes"])
        need(pin(body) == expected_pin, "Source body pin differs: " + leaf)
        bodies[leaf] = body
    return bodies


def once(body, old, new):
    need(body.count(old) == 1, "Exact single source transformation seam required")
    return body.replace(old, new, 1)


def admission(body, updated):
    values = {}
    wanted = set(INGRESS_NAMES)
    for item in ast.parse(body).body:
        if not isinstance(item, ast.Assign) or len(item.targets) != 1 or not isinstance(item.targets[0], ast.Name):
            continue
        name = item.targets[0].id
        if name in wanted:
            need(name not in values, "Unique existing ingress binding required")
            values[name] = ast.literal_eval(item.value)
    need(set(values) == wanted and values["_TEST_INGRESS_COUNT"] == PARENT_COUNT,
         "Exact original ingress bindings required")
    added, new, count = (values[name] for name in INGRESS_NAMES)
    pins = new | {name: pin(raw) for name, raw in updated.items()}
    replacements = (sorted([*added, CLOCK]), dict(sorted(pins.items())), count + 1)
    for name, replacement in zip(INGRESS_NAMES, replacements, strict=True):
        body = once(body, f"{name}={values[name]!r}\n".encode(), f"{name}={replacement!r}\n".encode())
    return body


def transform(bodies):
    need(MANIFEST in bodies, "Exact parent manifest required")
    manifest = parent_manifest(bodies[MANIFEST])
    pins = manifest["files"]
    need(set(bodies) == pins.keys() | {MANIFEST} and sum(map(len, bodies.values())) == PARENT_BYTES
         and all(pin(bodies[name]) == expected for name, expected in pins.items())
         and layout(bodies) == PARENT_TREE, "Exact f4153868 public Git tree required")
    clock = read_leaf(PAYLOAD, EXPECTED[CLOCK][0], mode=None)
    need(exact(clock, EXPECTED[CLOCK]), "Exact maintained clock helper source required")
    factory = b"    changes=transform(out,mode)\n"
    changed = {
        CLOCK: clock,
        "factory/factory.py": once(bodies["factory/factory.py"], factory, factory + CLOCK_LINE),
    }
    raw = bodies["factory/service_capacity.py"]
    anchor = b"def factory(namespace,selected):\n"
    need(raw.count(anchor) == 1, "Exact service wrapper factory required")
    line = raw.split(anchor, 1)[1].splitlines(keepends=True)[0]
    need(line.startswith(b" p=profile();need(selected=='tcg1800',"), "Exact original service wrapper seam required")
    changed["factory/service_capacity.py"] = once(raw, anchor + line, anchor + SERVICE)
    anchor = b"  sys.path.insert(0,str(runner));K=load('_current606_source_regenerated_export_contract'"
    changed["native.py"] = once(bodies["native.py"], anchor, NATIVE_LINE + anchor)
    changed["admission.py"] = admission(bodies["admission.py"], changed)
    pins.update({name: pin(raw) for name, raw in changed.items()})
    changed[MANIFEST] = encoded(manifest)
    candidate = bodies | changed
    need(set(changed) == CHANGED and all(exact(changed[name], expected) for name, expected in EXPECTED.items())
         and len(candidate) == CANDIDATE_COUNT and sum(map(len, candidate.values())) == CANDIDATE_BYTES
         and layout(candidate) == CANDIDATE_TREE, "Exact published 542b9247 body and mode tree required")
    for name, raw in changed.items():
        if name.endswith(".py"):
            compile(raw, name, "exec")
    return candidate


def emit(parent, output):
    need(parent.is_absolute() and parent == parent.resolve(strict=True) and parent.is_dir()
         and output.is_absolute() and output == output.resolve() and output.parent.is_dir()
         and not output.is_relative_to(parent) and not os.path.lexists(output),
         "Select a fresh canonical output disjoint from the original source")
    manifest = read_leaf(parent / MANIFEST, PARENT_MANIFEST[0])
    pins = parent_manifest(manifest)["files"] | {MANIFEST: pin(manifest)}
    candidate = transform(read_tree(parent, pins))
    with TemporaryDirectory(prefix=".clock606-source-", dir=output.parent) as directory:
        staged = Path(directory) / "source"
        staged.mkdir(mode=0o700)
        for name, raw in candidate.items():
            leaf = staged / name
            leaf.parent.mkdir(parents=True, exist_ok=True)
            with leaf.open("xb") as stream:
                stream.write(raw)
            leaf.chmod(MODE)
        verified = read_tree(staged, {name: pin(raw) for name, raw in candidate.items()})
        need(layout(verified) == CANDIDATE_TREE, "Staged body or file mode differs")
        output.mkdir(mode=0o700)
        try:
            staged.rename(output)
        except OSError:
            output.rmdir()
            raise
    return dict(status="PASS_CURRENT606_CLOCK_SOURCE_ONLY", parent=PARENT, parent_tree=PARENT_TREE,
                parent_ref=PARENT_REF, parent_files=PARENT_COUNT, source=CANDIDATE, tree=CANDIDATE_TREE,
                ref=CANDIDATE_REF, files=CANDIDATE_COUNT, bytes=CANDIDATE_BYTES, changed=sorted(CHANGED),
                unchanged_parent_files=PARENT_COUNT - (len(CHANGED) - 1),
                manifest=pin(candidate[MANIFEST]), actual=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=lambda value: Path(value).absolute(), required=True)
    parser.add_argument("--output", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    try:
        sys.stdout.buffer.write(encoded(emit(args.parent, args.output)))
    except (OSError, ValueError) as error:
        sys.exit("Current606 clock source refused: " + str(error))


if __name__ == "__main__":
    main()
