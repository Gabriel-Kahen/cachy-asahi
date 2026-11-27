# SPDX-License-Identifier: MIT
"""Synthetic control-flow test with actual 629 counts and reverse invariants."""

from collections import defaultdict, deque
from pathlib import Path
import runpy
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch


def exercise(T, G, O, root, *, expired):
    start = int(time.time()) - 60
    ops = SimpleNamespace(**vars(O))
    ops.IN, ops.TARGET, ops.WORK = (root / name for name in ("media", "target", "work"))
    for directory in (ops.IN, ops.TARGET, ops.WORK):
        directory.mkdir()
    baseline = {f"fixture-base-{number:03}": "1" for number in range(258)}
    reverse = {name: pair[0] for name, pair in O.REVERSED.items()}
    baseline.update(reverse)
    additions = {f"fixture-forward-{number:03}": "1" for number in range(363)}
    additions.update(O.PROJECTS)
    additions.update({name: pair[1] for name, pair in O.REVERSED.items()})
    locks = {
        "baseline.lock": baseline,
        "forward.lock": baseline | additions,
        "rollback.lock": baseline | additions | reverse,
        "forward-preview.lock": additions,
        "rollback-preview.lock": reverse,
    }
    for leaf, inventory in locks.items():
        body = "".join(f"{name} {version}\n" for name, version in sorted(inventory.items())).encode()
        (ops.IN / leaf).write_bytes(body)
    ops.lock_ref = lambda name: T.pin((ops.IN / name).read_bytes())
    ops.locks = lambda _T, root: {
        leaf: _T.canonical_lock(_T.read(root / leaf, ops.lock_ref(leaf)), count)
        for leaf, (count, _, _) in O.REFS.items()
    }
    ops.rehash = lambda T, root, *_args, **_kwargs: O.check_delta(T, ops.locks(T, root))

    keys = {
        "alarm": dict(scope="vendor", fingerprint="AA" * 20),
        "community": dict(scope="vendor", fingerprint="BB" * 20),
        "preview-test": dict(scope="project-test", fingerprint="CC" * 20,
                             not_before=start, not_after=start + 7200),
    }
    files = {}
    for name, key in keys.items():
        key["file"] = f"keys/{name}.gpg"
        leaf = ops.IN / key["file"]
        leaf.parent.mkdir(exist_ok=True)
        leaf.write_bytes(name.encode())
        files[key["file"]] = T.pin(name.encode())
    packages = {"forward": {}, "rollback": {}}
    for phase, inventory in (("forward", additions), ("rollback", reverse)):
        for name, version in inventory.items():
            key = keys["preview-test" if name in O.PROJECTS else "alarm"]
            packages[phase][name] = dict(archive=f"{phase}/{name}-{version}-aarch64.pkg.tar.xz",
                                         scope=key["scope"], signer=key["fingerprint"])
    media = dict(keys=keys, packages=packages, files=files)
    plan = dict(nonce="0" * 32, media=media)
    commands = G.command_plan(ops, media) | G.trust_commands(ops, media)
    order = ["query-baseline", "check-baseline", *G.trust_commands(ops, media)]
    for phase in ("forward", "rollback"):
        order.extend(verb + "-" + phase for verb in ("preview", "apply", "query", "check"))
    pending = defaultdict(deque)
    for role in order:
        pending[tuple(commands[role])].append(role)
    signed = {f"verify-{phase}-{name}": row
              for phase, inventory in packages.items() for name, row in inventory.items()}
    mutations = []

    class Process:
        returncode = 0

        def __enter__(self):
            return self

        def __exit__(self, *_error):
            pass

        def communicate(self, **_kwargs):
            pass

    def popen(argv, *, stdout, **_kwargs):
        role = pending[tuple(argv)].popleft()
        verb, _, phase = role.partition("-")
        if verb in ("preview", "query"):
            leaf = phase + ("-preview.lock" if verb == "preview" else ".lock")
            stdout.write((ops.IN / leaf).read_bytes())
        elif verb == "keys":
            for key in keys.values():
                if phase in (key["scope"], "pacman"):
                    full = key["fingerprint"]
                    end = key.get("not_after", "")
                    stdout.write((f"pub:-:255:22:{full[-16:]}:{start}:{end}:::-:::scSC:\n"
                                  f"fpr:::::::::{full}:\n").encode())
        elif role in signed:
            row = signed[role]
            full = row["signer"]
            tag = "EXPKEYSIG" if expired and row["scope"] == "project-test" else "GOODSIG"
            stdout.write((f"[GNUPG:] {tag} {full[-16:]} Fixture\n"
                          f"[GNUPG:] VALIDSIG {full} 2026-11-18 {start} 0 4 0 22 8 00 {full}\n").encode())
        elif verb == "apply":
            mutations.append(phase)
            before = locks["baseline.lock" if phase == "forward" else "forward.lock"]
            log = ops.WORK / "evidence/pacman.log"
            with log.open("a") as stream:
                for name, version in locks[phase + ".lock"].items():
                    prior = before.get(name)
                    if prior is None:
                        stream.write(f"[fixture] [ALPM] installed {name} ({version})\n")
                    elif version != prior:
                        changed = "upgraded" if phase == "forward" else "downgraded"
                        stream.write(f"[fixture] [ALPM] {changed} {name} ({prior} -> {version})\n")
        return Process()

    platform = {"boot": {"type": "directory"}, "etc/fstab": None, "etc/crypttab": None}
    with (patch.object(T, "target_api_mounts"), patch.object(G.base, "platform", return_value=platform),
          patch.object(G.base, "initramfs", return_value=(b"", {}, 0)),
          patch.object(G.base, "preserve_initramfs"),
          patch.object(G.os, "statvfs", return_value=SimpleNamespace(f_bavail=1 << 30, f_frsize=16)),
          patch.object(G.subprocess, "Popen", side_effect=popen), patch.object(G.subprocess, "run")):
        code = G.execute(T, ops, plan)
    evidence = ops.WORK / "evidence"
    result = T.decode((evidence / "result.json").read_bytes())
    seen = {row["role"]: row for row in T.decode((evidence / "commands.json").read_bytes())}
    G.review_extra(T, ops, evidence, plan, result, seen, held=expired)
    return ops, plan, evidence, result, seen, code, mutations


def modules():
    values = runpy.run_path(str(Path(__file__).resolve().with_name("controller.py")))
    return values["T"], values["G"], values["O"]


class GuestControlFlow(TestCase):
    def test_reverses_only_declared_versions_and_rejects_bad_cleanup(self):
        T, G, O = modules()
        with TemporaryDirectory(prefix="asahi629-mocked-flow-") as tmp:
            ops, plan, evidence, result, seen, code, mutations = exercise(T, G, O, Path(tmp), expired=False)
            self.assertEqual((code, result["status"], mutations), (0, G.PASS, ["forward", "rollback"]))
            self.assertFalse(any(home.exists() for home in G.trust_homes(ops).values()))
            self.assertEqual(result["inventory"].keys(), {"baseline", "forward", "rollback"})
            leaf = evidence / "cleanup.json"
            cleanup = T.decode(leaf.read_bytes())
            cleanup["keyrings"]["project-test"] = "failed"
            raw = T.encoded(cleanup)
            leaf.write_bytes(raw)
            result["cleanup"] = T.pin(raw)
            with self.assertRaisesRegex(ValueError, "keyrings and target API mounts"):
                G.review_extra(T, ops, evidence, plan, result, seen, held=False)

    def test_expired_signature_never_reaches_apply(self):
        T, G, O = modules()
        with TemporaryDirectory(prefix="asahi629-mocked-flow-") as tmp:
            ops, _, _, result, _, code, mutations = exercise(T, G, O, Path(tmp), expired=True)
            self.assertEqual((code, result["status"], mutations), (75, G.HOLD, []))
            self.assertEqual(result["phase"], "verify-forward-cachy-asahi-first-login")
            self.assertFalse(any(home.exists() for home in G.trust_homes(ops).values()))


if __name__ == "__main__":
    main()
