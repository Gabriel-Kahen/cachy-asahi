# SPDX-License-Identifier: MIT
"""Enter the reviewed JBIG/TIFF extension from the existing offline Asahi629 actor."""

import argparse
import hashlib
from itertools import islice
import os
from pathlib import Path
from runpy import run_path
import stat
import sys
from types import FunctionType, SimpleNamespace

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "stage.py")))
R = SimpleNamespace(**run_path(str(HERE / "readback.py")))
KIND = "ROOT_ASAHI629_JBIG_TIFF_SELECTION_V1"


def canonical(T, path, expected, cap):
    raw = T.read(path, cap=cap)
    value = T.decode(raw)
    T.need(raw == T.encoded(value) and T.pin(raw)["sha256"] == expected, "Selected canonical input digest differs")
    return value, T.pin(raw)


def checked_stage(L, stage, expected, nonce):
    T = L.T
    record = T.decode(T.read(stage / S.STAGE, expected, cap=S.CAP))
    T.need(record.keys() == {"kind", "nonce", "authority", "execution", "plan", "base_plan", "source", "entries"}
           and record["kind"] == S.KIND and record["nonce"] == nonce
           and record["authority"] is None and record["execution"] == "NOT RUN" and record["source"] == S.host_sources(T),
           "Selected unissued pair stage or host source differs")
    raw = T.read(stage / S.PLAN, record["plan"], cap=S.CAP)
    plan = T.decode(raw)
    entries = {"code/" + name: pin for name, pin in plan["code"].items()} | {
        "inputs/" + name: pin for name, pin in plan["jbig_tiff_media"].items()}
    T.need(raw == T.encoded(plan) and record["entries"] == entries and plan["nonce"] == nonce,
           "Scoped plan metadata or file pins differ")
    wanted = set(entries) | {S.PLAN, S.STAGE}
    directories = {parent.as_posix() for name in wanted for parent in Path(name).parents if parent != Path(".")}
    observed = {}
    for path in islice(stage.rglob("*"), len(wanted | directories) + 1):
        leaf = path.relative_to(stage).as_posix()
        T.need(not path.is_symlink() and (leaf in wanted and path.is_file() or leaf in directories and path.is_dir()),
               "Unexpected path in the scoped stage: " + leaf)
        observed[leaf] = None
    T.need(observed.keys() == wanted | directories, "Scoped stage is missing a selected file or directory")
    for leaf, pin in entries.items():
        T.read(stage / leaf, pin, cap=2 << 20, collect=False)
    return record, plan


def packed_transport(L, stage, record, plan, staging, base, root):
    T = L.T
    expected, code = S.derive(L, base, plan["jbig_tiff"]["test_review"])
    T.need(expected == plan and record["base_plan"] == T.pin(T.encoded(base))
           and record["plan"]["bytes"] <= S.CAP, "Scoped plan differs from the revalidated Asahi629 binding")
    files, aliases, _ = L.copy_transport(staging, base, root)
    overrides = [root / "code/plan.json", *(root / "code" / name for name in base["code"])]
    for path in overrides:
        path.unlink()
    for leaf, pin in record["entries"].items():
        L.C.checked_copy(stage / leaf, root / leaf, pin)
    S.put(root / "code/plan.json", T.encoded(plan))
    files |= record["entries"] | {"code/plan.json": record["plan"]}
    T.need({name: T.pin(body) for name, body in code.items()} == plan["code"], "Scoped guest source derivation changed")
    directories = {str(path.relative_to(root)) for path in root.rglob("*") if not path.is_symlink() and path.is_dir()}
    return files, aliases, directories


def rehash_image(T, path, expected):
    path = T.ordinary(path)
    chunk_size = 1 << 20
    page_size = os.sysconf("SC_PAGE_SIZE")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = os.fstat(fd)
        T.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size > 0
               and before.st_size % page_size == chunk_size % page_size == 0,
               "Expected an ordinary page-aligned image with one link: " + path.name)
        T.need(type(expected) is dict and expected.keys() == {"bytes", "sha256"}
               and type(expected["bytes"]) is int and expected["bytes"] == before.st_size
               and type(expected["sha256"]) is str and T.HEX.fullmatch(expected["sha256"]),
               "Expected image length or digest differs: " + path.name)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_RANDOM)
        digest = hashlib.sha256()
        for offset in range(0, before.st_size, chunk_size):
            length = min(chunk_size, before.st_size - offset)
            chunk = stream.read(length)
            T.need(len(chunk) == length, "Short pinned image read: " + path.name)
            digest.update(chunk)
            os.posix_fadvise(fd, offset, length, os.POSIX_FADV_DONTNEED)
        T.need(not stream.read(1), "Pinned image grew: " + path.name)
        pin = dict(bytes=before.st_size, sha256=digest.hexdigest())
        T.need(pin == expected and T.identity(before) == T.identity(os.fstat(fd)) == T.identity(path.lstat()),
               "Changed pinned image bytes or identity: " + path.name)
    return pin


def image_reader(T, images):
    def read(path, expected=None, *, cap=T.MAX_MEMBER, collect=True, observed=None, allowed_links=(1,)):
        selected = images.get(Path(path))
        if selected is None:
            return T.read(path, expected, cap=cap, collect=collect, observed=observed, allowed_links=allowed_links)
        T.need(expected == selected and cap == selected["bytes"] and collect is False and observed is None
               and allowed_links == (1,), "Unexpected pinned image check: " + str(path))
        return rehash_image(T, path, selected)

    return read


def with_globals(original, **overrides):
    scoped = FunctionType(original.__code__, original.__globals__ | overrides,
                          original.__name__, original.__defaults__, original.__closure__)
    scoped.__kwdefaults__ = original.__kwdefaults__
    return scoped


def image_reads(L, paths, refs, *, out=None):
    images = {paths["control"] / L.CONTROL_FILES / "guest.raw": refs["baseline"], paths["seed"]: refs["seed"]}
    if out is not None:
        images |= {out / "reference.raw": refs["baseline"], out / "scratch.raw": refs["seed"]}
    T = SimpleNamespace(**(vars(L.T) | {"read": image_reader(L.T, images)}))
    return dict(T=T, control_refs=with_globals(L.control_refs, T=T))


def scoped_controller(L, stage, record, plan):
    T = L.T

    class ScopedController(L.Controller):
        def run_asahi629(self, authority_path, authority_digest):
            binding = with_globals(L.binding, **image_reads(L, self.paths, self.authority["references"]))
            run = with_globals(L.Controller.run_asahi629, binding=binding)
            return run(self, authority_path, authority_digest)

        def command(self, label, name, args, seconds, deadline):
            if label == "clone-control-root":
                source = self.paths["control"] / L.CONTROL_FILES / "guest.raw"
                destination = self.out / "reference.raw"
            elif label == "clone-asahi-target":
                source = self.paths["seed"]
                destination = self.out / "scratch.raw"
            else:
                return super().command(label, name, args, seconds, deadline)
            T.need(name == "cp" and args == ["--sparse=always", "--reflink=never", source, destination],
                   f"Unexpected owned clone command for {label}")
            # GNU cp requires sparse=auto when a reflink is mandatory.
            return super().command(label, name, ["--sparse=auto", "--reflink=always", source, destination],
                                   seconds, deadline)

        def rehearse(self, actual, base, authority_path, authority_digest):
            T.need(base["nonce"] == plan["nonce"] and T.pin(T.encoded(base)) == record["base_plan"],
                   "Base authority and scoped stage refer to different guests")
            S.host_test(L, stage / "inputs/jbig-tiff", plan["jbig_tiff"]["test_review"])

            def copy(staging, selected, root):
                T.need(selected == plan, "Unexpected plan supplied by the retained packer")
                return packed_transport(L, stage, record, selected, staging, base, root)

            def review(out, selected, *, held):
                return R.review(L, out, selected, held=held)

            # The pinned controller still owns the disk geometry, boot, supervision and export.
            owned = with_globals(L.Controller.rehearse, copy_transport=copy, review=review,
                                 **image_reads(L, self.paths, actual["references"], out=self.out))
            receipt = owned(self, actual | {"plan": record["plan"]}, plan, authority_path, authority_digest)
            if receipt["status"] == L.G.PASS:
                start, end = (receipt["host_realtime"][key] for key in ("before", "after"))
                T.need(all(start - 3 <= signed["observed_at"] <= end
                           for signed in receipt["jbig_tiff_checkpoint"]["trust"]["signatures"].values()),
                       "Pair signature observations fall outside the owned QEMU window")
            return receipt

    return ScopedController


def run(L, *, authority, authority_sha256, stage, selection, selection_sha256):
    T = L.T
    T.need(sys.flags.isolated and sys.dont_write_bytecode, "Use isolated no-bytecode Python")
    issued, selection_pin = canonical(T, selection, selection_sha256, 128 << 10)
    original, original_pin = canonical(T, authority, authority_sha256, 128 << 10)
    T.need(issued.keys() == {"kind", "issuer", "approval_status", "nonce", "authority", "stage"}
           and issued["kind"] == KIND and issued["issuer"] == original["issuer"] == "Root"
           and issued["approval_status"] == original["approval_status"] == "UNAPPROVED"
           and issued["nonce"] == original["nonce"] and S.LHEX.fullmatch(issued["nonce"])
           and issued["authority"] == original_pin and original["kind"] == L.KIND,
           "Exact separately issued pair authority and original Asahi629 binding required")
    L.C.actor_boundary({**{key: Path(value) for key, value in original["paths"].items()},
                        "pair_stage": stage, "pair_selection": selection, "authority": authority})
    L.disjoint(Path(original["paths"]["output"]), (stage, selection))
    record, plan = checked_stage(L, stage, issued["stage"], issued["nonce"])
    report = scoped_controller(L, stage, record, plan)(original).run_asahi629(authority, authority_sha256)
    T.read(selection, selection_pin, cap=128 << 10, collect=False)
    T.read(stage / S.STAGE, issued["stage"], cap=S.CAP, collect=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("authority", "stage", "selection"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("authority-sha256", "selection-sha256"):
        parser.add_argument("--" + name, required=True)
    L = S.legacy()
    try:
        report = run(L, **vars(parser.parse_args()))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Scoped Asahi629 owner refused: {error}\n")
    print(L.T.encoded(report).decode(), end="")
    return int(report["status"] != L.G.PASS)


if __name__ == "__main__":
    raise SystemExit(main())
