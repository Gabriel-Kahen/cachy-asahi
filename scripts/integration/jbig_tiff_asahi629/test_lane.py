# SPDX-License-Identifier: MIT

from contextlib import contextmanager
import ctypes as ct
from pathlib import Path
from runpy import run_path
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "stage.py")))
R = SimpleNamespace(**run_path(str(HERE / "readback.py")))
OWNER = SimpleNamespace(**run_path(str(HERE / "runner.py")))
RUNTIME_FIXTURE = run_path(str(HERE / "test_runtime.py"))
TX = R.TX
L = S.legacy()
T = L.T
NONCE = "a" * 32


def prepare_record(incoming, outgoing):
    return dict(add=incoming, remove=outgoing, conflicts=[
        dict(type=TX.CONFLICT, pair=pair, accepted=True) for pair in sorted(TX.approved_pairs(incoming, outgoing))
    ])


class Backend:
    def __init__(self, failure=None):
        self.actual = b"baseline"
        self.events = []
        self.failure = failure

    def inventory(self, providers):
        self.events.append(("inventory", providers))
        return self.actual, dict.fromkeys(providers, 1)

    def authenticate(self, providers):
        self.events.append(("authenticate", providers))

    def negative_control(self, project, baseline):
        assert self.actual == baseline
        self.events.append(("unsigned", project))
        return "package missing required signature"

    @contextmanager
    def prepared(self, incoming, outgoing, before):
        assert self.actual == before
        self.events.append(("prepare", incoming))

        def commit():
            self.events.append(("commit", incoming))
            if self.failure == len([event for event, _ in self.events if event == "commit"]):
                raise RuntimeError("commit ambiguous")
            self.actual = b"project" if incoming == S.I.PROJECT else b"baseline"

        yield prepare_record(incoming, outgoing), commit


class LaneTests(unittest.TestCase):
    def review(self):
        return dict(certificate=T.pin(b"test-cert"), fingerprint="A" * 40, not_before=1, not_after=2,
                    signatures={name: T.pin(b"signature") for name in S.I.PROJECT})

    def test_conflict_scope_rejects_duplicate_unrelated_or_nonconflict_questions(self):
        approved = TX.approved_pairs(S.I.PROJECT, S.I.OFFICIAL)
        pairs = sorted(approved)
        identities = {idx: pair for idx, pair in enumerate([*pairs[0], *pairs[1]], 1)}
        for scope, wanted in (([(1, 2), (3, 4)], [1, 1]), ([(1, 2), (1, 2)], [1, 0]),
                              ([(1, 4), (3, 4)], [0, 0]), ([(1, 2), (0, 0)], [1, 0])):
            records, answers = [], []
            for incoming, outgoing in scope:
                conflict = TX.Conflict(incoming, outgoing, None)
                request = TX.ConflictQuestion(TX.Question(TX.CONFLICT if incoming else 2, 999), ct.pointer(conflict))
                TX.answer(ct.cast(ct.pointer(request), ct.POINTER(TX.Question)), identities.__getitem__, approved, records)
                answers.append(request.base.answer)
            self.assertEqual(answers, wanted)
            if wanted == [1, 1]:
                TX.check_prepared(S.I.PROJECT, S.I.OFFICIAL, records, S.I.PROJECT, S.I.OFFICIAL)
            else:
                with self.assertRaisesRegex(ValueError, "exactly the two"):
                    TX.check_prepared(S.I.PROJECT, S.I.OFFICIAL, records, S.I.PROJECT, S.I.OFFICIAL)

    def lifecycle(self, backend, broken=None):
        calls = []

        def probe(soname):
            calls.append(soname)
            if broken == len(calls):
                raise R.RUNTIME.RuntimeFailure({"status": "FAIL", "failure": "unavailable probe", "commands": ["fixture"]})
            return soname

        def observe(label, _providers, _reasons, raw):
            return dict(label=label, inventory=raw.hex())

        result = TX.lifecycle(backend, S.I.OFFICIAL, S.I.PROJECT, b"baseline", b"project", observe, probe,
                              lambda: "scope-verified", lambda: None, {})
        return result, calls

    def test_three_probes_and_atomic_commits(self):
        backend = Backend()
        result, calls = self.lifecycle(backend)
        self.assertEqual(result["status"], TX.PASS)
        self.assertEqual(calls, ["2.1", "2.2", "2.1"])
        self.assertEqual([payload for kind, payload in backend.events if kind == "commit"], [S.I.PROJECT, S.I.OFFICIAL])
        self.assertEqual(backend.actual, b"baseline")
        self.assertEqual(backend.events[2][0], "unsigned")

    def test_failure_disposition_tracks_verified_restoration(self):
        for broken, wanted, commits in ((1, TX.HOLD_BASELINE, 0), (2, TX.HOLD_RESTORED, 2), (3, TX.HOLD_RESTORED, 2)):
            with self.subTest(failed_probe=broken):
                backend = Backend()
                result, calls = self.lifecycle(backend, broken)
                self.assertEqual(result["status"], wanted)
                self.assertEqual(len([kind for kind, _ in backend.events if kind == "commit"]), commits)
                self.assertEqual(backend.actual, b"baseline")
                self.assertEqual(len(calls), 1 if broken == 1 else 3)
                label = ("baseline", "replacement", "restoration")[broken - 1]
                self.assertEqual(result["phases"][label]["runtime"]["commands"], ["fixture"])

    def test_ambiguous_commit_discards_clone(self):
        for commit in (1, 2):
            with self.subTest(ambiguous_commit=commit):
                result, _ = self.lifecycle(Backend(failure=commit))
                self.assertEqual(result["status"], TX.HOLD_DISCARD)
                self.assertIn("-commit", result["failure"]["phase"])

    def test_review_requires_exact_two_project_signatures(self):
        review = self.review()
        self.assertEqual(S.ENTRY.review_shape(T, review, S.I.PROJECT), review)
        review["signatures"].pop(next(iter(S.I.PROJECT)))
        with self.assertRaisesRegex(ValueError, "two detached"):
            S.ENTRY.review_shape(T, review, S.I.PROJECT)

    def test_scope_patches_only_reviewed_insertion_points(self):
        media = {}
        base = dict(kind=L.G.BOOT, nonce=NONCE, code=S.BASE_CODE, manifest=T.pin(T.encoded(media)), media=media)
        plan, code = S.derive(L, base, self.review())
        self.assertIsNot(plan["code"], base["code"])
        self.assertEqual({key for key in S.BASE_CODE if plan["code"][key] != base["code"][key]},
                         {"operands.py", "asahi-guest.py"})
        self.assertEqual(len(plan["jbig_tiff_media"]), 9)
        worker = code["asahi-guest.py"]
        self.assertLess(worker.index(b"query(stage)"), worker.index(b'phase = "jbig-tiff-checkpoint"'))
        self.assertLess(worker.index(b'phase = "jbig-tiff-checkpoint"'), worker.index(b'phase = "seal"'))
        self.assertLess(worker.index(b'phase = "seal"'), worker.index(b'result["jbig_tiff_checkpoint"]'))
        original = L.selection()[0]
        with self.assertRaisesRegex(ValueError, "retained worker insertion"):
            S.extend(T, original["asahi-guest.py"].read_bytes().replace(b"query(stage)", b"query(other)"),
                     original["operands.py"].read_bytes(), plan["jbig_tiff_media"])
        self.assertNotIn(b"qt_replacement", worker)

    def test_actor_rejects_drift_and_unknown_stage_paths(self):
        raw = b"staged test bytes"
        plan = dict(nonce=NONCE, code={"asahi-guest.py": T.pin(raw)}, jbig_tiff_media={})
        record = dict(kind=S.KIND, nonce=NONCE, authority=None, execution="NOT RUN", plan=T.pin(T.encoded(plan)),
                      base_plan=T.pin(b"original"), source=S.host_sources(T),
                      entries={"code/asahi-guest.py": T.pin(raw)})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            S.put(root / S.PLAN, T.encoded(plan))
            S.put(root / S.STAGE, T.encoded(record))
            S.put(root / "code/asahi-guest.py", raw)
            pin = T.pin(T.encoded(record))
            self.assertEqual(OWNER.checked_stage(L, root, pin, NONCE), (record, plan))
            S.put(root / "unexpected", b"x")
            with self.assertRaisesRegex(ValueError, "Unexpected path"):
                OWNER.checked_stage(L, root, pin, NONCE)
            (root / "unexpected").unlink()
            (root / "code/asahi-guest.py").chmod(0o600)
            (root / "code/asahi-guest.py").write_bytes(b"staged corrupted!")
            with self.assertRaisesRegex(ValueError, "Changed pinned bytes"):
                OWNER.checked_stage(L, root, pin, NONCE)

    def test_readback_rejects_extra_or_out_of_order_package_mutation(self):
        blocks = []
        for remove, install in ((S.I.OFFICIAL, S.I.PROJECT), (S.I.PROJECT, S.I.OFFICIAL)):
            rows = [f"removed {name} ({version})" for name, version in remove.items()]
            rows += [f"installed {name} ({version})" for name, version in install.items()]
            blocks.append("\n".join("[ALPM] " + line for line in ("transaction started", *rows, "transaction completed")))
        log = "\n".join(blocks)
        self.assertEqual(len(S.ENTRY.check_log(T, log, S.I.OFFICIAL, S.I.PROJECT)), 2)
        with self.assertRaisesRegex(ValueError, "does not show exactly"):
            S.ENTRY.check_log(T, "\n".join(reversed(blocks)), S.I.OFFICIAL, S.I.PROJECT)
        with self.assertRaisesRegex(ValueError, "outside the selected"):
            S.ENTRY.check_log(T, log + "\n[ALPM] installed unrelated (1-1)", S.I.OFFICIAL, S.I.PROJECT)

    def test_readback_requires_all_seven_direct_loaders_and_pipewire(self):
        fixture = RUNTIME_FIXTURE
        runtime = R.RUNTIME.Probe(fixture["ROOT"], fixture["SCRATCH"], executor=fixture["successful"]).receipt("2.2")
        R.read_runtime(T, runtime, "2.2")
        del runtime["loaders"][R.RUNTIME.PIPEWIRE]["span"]
        with self.assertRaisesRegex(ValueError, "Runtime summary differs"):
            R.read_runtime(T, runtime, "2.2")
        runtime["commands"].pop(5)
        with self.assertRaisesRegex(ValueError, "Unexpected runtime command"):
            R.read_runtime(T, runtime, "2.2")


if __name__ == "__main__":
    unittest.main()
