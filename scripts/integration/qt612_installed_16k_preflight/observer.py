# SPDX-License-Identifier: MIT
"""Observe actual ALPM and loader state through the installed Qt guest callbacks."""

from itertools import islice
import os
from pathlib import Path, PurePosixPath
import re
from runpy import run_path
import stat
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
W = SimpleNamespace(**run_path(str(HERE / "worker.py")))
P, T = W.P, W.T
PROBE = P.MEDIA + "/loader_probe.py"
DSO_CAP = 128 << 20
VIEW_CAP = 16 << 20
LEAVES = 32768
TRACE = re.compile(rb"\s*([0-9]+):\s+calling init: (/[^\x00-\x20]+)\s*")
OPEN = re.compile(rb"\s*([0-9]+):\s+opening file=(/[^\x00-\x20]+) \[0\]; direct_opencount=[1-9][0-9]*\s*")
PROGRAM = re.compile(rb"\s*([0-9]+):\s+initialize program: ([^\x00\r\n]+?)\s*")


def input_evidence(media=Path(P.MEDIA), work=Path(P.WORK)):
    operands = {"archive": media / Path(P.ARCHIVE).name, "signature": media / (Path(P.ARCHIVE).name + ".sig"),
                "certificate": media / Path(P.CERT).name}
    observed = {}
    bodies = {name: T.read(operands[name], cap=W.INPUT_LIMITS[name], observed=observed)
              for name in ("certificate", "signature")}
    pins = {"archive": T.read(operands["archive"], cap=W.INPUT_LIMITS["archive"], collect=False, observed=observed)}
    pins.update({name: T.pin(raw) for name, raw in bodies.items()})
    config = T.read(work / "pacman.conf", cap=4096, observed=observed)
    T.unchanged(observed)
    return dict(input_pins=pins, config_raw=config, **{name + "_raw": raw for name, raw in bodies.items()})


def path_shape(name, parent):
    T.need(type(name) is str and name.startswith(parent) and str(PurePosixPath(name)) == name
           and ".." not in PurePosixPath(name).parts and len(name) <= 1024
           and all(32 < ord(ch) < 127 for ch in name), "Expected canonical observed guest path")
    return Path(name)


def protected_view(paths):
    """Capture the supervisor's selected protected paths with stable original metadata."""
    rows, opened = {}, {}
    pending = list(paths)
    while pending:
        path = pending.pop()
        T.need(len(rows) + len(pending) < LEAVES, "Protected snapshot exceeds finite namespace")
        if str(path) in rows:
            continue
        T.ordinary(path.parent)
        try:
            status = path.lstat()
        except FileNotFoundError:
            rows[str(path)] = {"type": "absent"}
            continue
        opened[str(path)] = T.identity(status)
        row = dict(mode=stat.S_IMODE(status.st_mode), uid=status.st_uid, gid=status.st_gid)
        if stat.S_ISDIR(status.st_mode):
            rows[str(path)] = row | {"type": "directory"}
            pending.extend(islice(path.iterdir(), LEAVES))
        elif stat.S_ISLNK(status.st_mode):
            rows[str(path)] = row | {"type": "symlink", "target": os.readlink(path)}
        else:
            rows[str(path)] = row | {"type": "file", "pin": T.read(path, cap=DSO_CAP, collect=False, observed=opened)}
    for name, identity in opened.items():
        T.need(T.identity(Path(name).lstat()) == identity, "Protected observation changed during capture")
    raw = T.encoded(rows)
    T.need(0 < len(raw) <= VIEW_CAP, "Bounded protected snapshot required")
    return raw


def plugin_trace(raw, program, offscreen=W.OFFSCREEN):
    """Observe the normal glibc link-map initialization and actual plugin open."""
    T.need(0 < len(raw) <= W.MAX_STREAMS, "Bounded original consumer loader trace required")
    init, opened, programs = {}, set(), {}
    for line in raw.splitlines():
        match = PROGRAM.fullmatch(line)
        if match:
            programs.setdefault(match[1], []).append(os.fsdecode(match[2]))
        match = TRACE.fullmatch(line)
        if match and match[2].startswith((b"/usr/lib/", b"/lib/")):
            init.setdefault(match[1], set()).add(os.fsdecode(match[2]))
        match = OPEN.fullmatch(line)
        if match and os.fsdecode(match[2]) == offscreen:
            opened.add(match[1])
    subjects = [pid for pid, names in programs.items() if program in names]
    T.need(len(subjects) == 1, "Normal installed consumer did not map and open the exact offscreen plugin")
    pid, = subjects
    T.need(programs[pid] == [program], "Competing executable generations in consumer loader trace")
    T.need(pid in opened and offscreen in init.get(pid, ()),
           "Normal installed consumer did not map and open the exact offscreen plugin")
    result = init[pid]
    T.need(len(result) <= 512, "Bounded consumer provider map required")
    return result


def named_payload(stdout, package):
    paths, seen = {}, set()
    for line in stdout.decode("ascii").splitlines():
        directory = line.endswith("/")
        name = line.removesuffix("/")
        T.need(name not in seen and len(seen) < LEAVES, "Duplicate or excessive ALPM payload paths")
        seen.add(name)
        if directory and name in {"/usr", "/usr/lib", "/usr/share", "/usr/bin"}:
            continue
        path = path_shape(name, "/usr/")
        T.ordinary(path.parent)
        row = path.lstat()
        if directory:
            T.need(stat.S_ISDIR(row.st_mode), "ALPM payload directory differs")
            continue
        if stat.S_ISLNK(row.st_mode):
            paths[name] = dict(type="symlink", owner=package, target=os.readlink(path))
        else:
            paths[name] = dict(type="file", owner=package, pin=T.read(path, cap=DSO_CAP, collect=False))
    return paths


def mapped_identity(stat_result):
    return [os.major(stat_result.st_dev), os.minor(stat_result.st_dev), stat_result.st_ino]


def read_map(row, soname):
    T.need(row.keys() == {"soname", "path", "maps", "loaded"} and row["soname"] == soname and type(row["maps"]) is dict
           and len(row["maps"]) <= 512 and type(row["loaded"]) is list and len(row["loaded"]) <= len(row["maps"])
           and all(type(path) is str and path in row["maps"] for path in row["loaded"])
           and len(row["loaded"]) == len(set(row["loaded"])), "Exact normal-loader probe result required")
    if row["path"] is None:
        T.need(row["maps"] == {}, "An absent SONAME cannot supply mappings")
        return None, {}, []
    result = {}
    for name, identity in row["maps"].items():
        path = path_shape(name, "/usr/lib/")
        T.need(type(identity) is list and len(identity) == 3 and all(type(x) is int and x >= 0 for x in identity)
               and path.resolve(strict=True) == path and mapped_identity(path.lstat()) == identity,
               "Mapped device/inode no longer identifies installed library")
        result[name] = identity
    T.need(row["path"] in result, "Selected SONAME not in its original map")
    return row["path"], result, row["loaded"]


def closure(roots, mapped, details):
    """Walk actual ELF dependencies, resolving only into the probe's live map."""
    queue, closed = list(roots), set()
    while queue:
        name = queue.pop()
        if name in closed:
            continue
        T.need(name in mapped and name.startswith("/usr/lib/") and len(closed) < 512,
               "Normal-loader mapping does not contain the full dependency closure")
        closed.add(name)
        for dependency in details(name)["needed"]:
            direct = str((Path("/usr/lib") / dependency).resolve())
            if direct in mapped:
                queue.append(direct)
                continue
            candidates = [path for path in mapped if Path(path).name == dependency or details(path)["soname"] == dependency]
            T.need(len(candidates) == 1, "Could not identify one actual mapped dependency: " + dependency)
            queue.append(candidates[0])
    return closed


class Observer:
    """Adapter for worker.exercise with the same supervisor-owned command recorder."""

    def __init__(self, plan, selection, run, protected_paths):
        self.plan, self.selection, self.execute = plan, selection, run
        self.stages = {stage["name"]: stage for stage in plan["stages"]}
        self.protected = tuple(Path(path) for path in (*protected_paths, *selection["providers"]))
        self.streams, self.traces = {}, {}
        raw = T.read(P.RECIPE / "check_stage.py", P.Q.file_record(P.RECIPE_INPUTS["check_stage.py"]), cap=32 << 10)
        scope = {"__name__": "qtbase_installed_elf", "__file__": str(P.RECIPE / "check_stage.py")}
        exec(compile(raw, scope["__file__"], "exec"), scope)
        self.elf_info = scope["elf_info"]

    def run(self, role, argv, *, timeout, stdin, env):
        mark = role.removesuffix("-consumer-run")
        consumer = role.endswith("-consumer-run") and mark in self.stages
        if consumer:
            T.need(argv == self.plan["consumer"]["run"] and env == self.plan["consumer"]["environment"],
                   "Exact installed consumer and standard loader environment required")
            env = env | {"LD_DEBUG": "files"}
        row = self.execute(role, argv, timeout=timeout, stdin=stdin, env=env)
        if consumer:
            self.traces[mark] = row["stderr"]
        if role.endswith("-inventory"):
            self.streams[role.removesuffix("-inventory")] = row["stdout"]
        return row

    def call(self, stage, role, argv):
        return W.command(self.execute, stage + "-observe-" + role, argv)["stdout"]

    def observe(self, stage_name):
        stage = self.stages[stage_name]
        package = self.plan["package"]
        installed = stage["state"] == "installed"
        lock = T.sorted_rows(self.streams.pop(stage_name))
        versions = T.canonical_lock(lock, 357 if installed else 356)
        protected = protected_view(self.protected)
        sonames, providers, files = {}, {}, {}
        observed, libraries = {}, {}
        versions_by_path = {}

        def details(name):
            if name not in libraries:
                body = T.read(Path(name), cap=DSO_CAP, observed=observed)
                libraries[name] = self.elf_info(body) | {"pin": T.pin(body)}
            return libraries[name]

        mapped = set()
        for index, soname in enumerate(package["sonames"]):
            raw = self.call(stage_name, f"soname-{index}", ["/usr/bin/python3", "-I", "-B", PROBE, soname])
            path, live, loaded = read_map(T.decode(raw), soname)
            T.need((path is not None) == installed, "Unexpected normal-loader Qt visibility")
            if path is None:
                sonames[soname] = None
                continue
            row = details(path)
            T.need(row["soname"] == soname, "Actually mapped Qt SONAME differs")
            sonames[soname] = {"path": path, **row["pin"]}
            mapped.update(closure([path, *loaded], live, details))
        offscreen = None
        if installed:
            name = package["package"]
            output = self.call(stage_name, "package-files", P.PACMAN + ["-Qlq", "--", name])
            files = named_payload(output, name)
            for sight in plugin_trace(self.traces.pop(stage_name), self.plan["consumer"]["run"][0]):
                canonical = str(Path(sight).resolve(strict=True))
                path_shape(canonical, "/usr/lib/")
                mapped.add(canonical)
            T.need(W.OFFSCREEN in mapped and files[W.OFFSCREEN]["type"] == "file",
                   "Installed ALPM offscreen payload did not map")
            offscreen = {"path": W.OFFSCREEN, **details(W.OFFSCREEN)["pin"]}
            owned = sorted(mapped)
            for first in range(0, len(owned), 64):
                batch = owned[first:first+64]
                owners = self.call(stage_name, f"owners-{first//64}", P.PACMAN + ["-Qoq", "--", *batch])
                owners = owners.decode("ascii").splitlines()
                T.need(len(owners) == len(batch) and all(owner in versions for owner in owners),
                       "Actual loaded libraries lack unambiguous ALPM owners")
                versions_by_path.update(zip(batch, owners, strict=True))
            for path, owner in versions_by_path.items():
                pin = details(path)["pin"]
                if owner == name:
                    T.need(files[path] == {"type": "file", "owner": name, "pin": pin},
                           "Loaded Qt object does not match actual package payload")
                else:
                    providers[path] = dict(owner=owner, version=versions[owner], pin=pin)
        else:
            T.need(all(not os.path.lexists(path) for path in self.selection["payload"]),
                   "A selected Qt payload leaf survived removal or preexisted")
        T.unchanged(observed)
        return dict(protected=protected, database=None if installed else W.stopped_database(Path("/")),
                    payload=files, sonames=sonames, offscreen=offscreen, providers=providers)
