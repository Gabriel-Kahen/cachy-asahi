# SPDX-License-Identifier: MIT
"""Inert installed-reader controls for original guest command and loader evidence."""

from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


R = SimpleNamespace(**run_path(str(Path(__file__).with_name("readback.py"))))
C, W, H = R.C, R.W, R.H
SHA = "a" * 64
PACKAGE = "inert-qtbase"
SONAME = "libQt6Core.so.6"
LIBRARY = "/usr/lib/libQt6Core.so.6.12.0"
PROVIDER = "/usr/lib/libfixture.so.1.2.3"
USER_CONFIG = "/home/builder/.config"
LOCK = b"fixture 1-1\n"


class ReceiptFixture:
    def __init__(self, plan):
        self.files = {}
        self.reader = R.OriginalCommands(plan, self.files, self.get)

    def get(self, name, limit):
        if name not in self.files:
            raise ValueError("Original fixture evidence member missing")
        body = self.files[name]
        assert len(body) <= limit
        return body

    def command(self, role, argv, *, code=0, stdout=b"", stderr=b"", stdin=None, env=None):
        prefix = R.COMMAND_PREFIX + role
        if env is None:
            env = W.NORMAL_ENV
        wrapped = self.reader.wrapper.command_argv(role, argv, env)
        receipt = dict(argv=wrapped, exit=code, passed=code == 0, ownership="REAPED",
                       group_census="EMPTY_TWICE", reaped=True, output_complete=True, timeout=False,
                       command_timed_out=False, original_budget_overrun=False, emergency_retirement=False,
                       signals=[], command_cancelled=[], error=None, emergency_retirement_cap_seconds=None,
                       child_file_size_cap=None, operation_seconds=0.2, operation_cap_seconds=10.0)
        for suffix, raw in (("json", C.wire(receipt)), ("stdout", stdout), ("stderr", stderr), ("log", stdout + stderr)):
            self.files[f"{prefix}.{suffix}"] = raw
        if stdin is not None:
            self.files[f"{prefix}.stdin"] = stdin


def consumer():
    return dict(run=["/qt-install-work/consumer/qt612-smoke"],
                environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                             "QT_QPA_PLATFORM": "offscreen", "HOME": "/qt-install-work/home"})


class OriginalReadback(unittest.TestCase):
    def test_ordinary_user_scope_and_exact_private_stream_merge(self):
        plan = {"consumer": consumer()}
        cmd = plan["consumer"]["run"]
        env = plan["consumer"]["environment"] | {"LD_DEBUG": "files"}
        for change in ("none", "root", "merge"):
            with self.subTest(change=change):
                fixture = ReceiptFixture(plan)
                fixture.command("install-consumer-run", cmd, stdout=b"marker\n", env=env)
                prefix = R.COMMAND_PREFIX + "install-consumer-run"
                if change == "root":
                    document = C.json_body(fixture.files[prefix + ".json"], canonical=True)
                    document["argv"] = document["argv"][len(R.G.DROP):]
                    fixture.files[prefix + ".json"] = C.wire(document)
                elif change == "merge":
                    fixture.files[prefix + ".log"] = b"different stream\n"
                if change == "none":
                    self.assertEqual(fixture.reader("install-consumer-run", cmd, env=env)["stdout"], b"marker\n")
                    fixture.reader.finish()
                else:
                    with self.assertRaises(ValueError):
                        fixture.reader("install-consumer-run", cmd, env=env)

    def test_positive_loader_reopens_emitted_probes_and_provider_batch(self):
        plan = dict(consumer=consumer(), package=dict(package=PACKAGE, sonames=[SONAME]))
        argv = plan["consumer"]["run"]
        env = plan["consumer"]["environment"] | {"LD_DEBUG": "files"}
        payload = {path: dict(type="file", owner=PACKAGE, pin=C.pin(path.encode()))
                   for path in (LIBRARY, W.OFFSCREEN)}
        providers = {PROVIDER: dict(owner="fixture", version="1-1", pin=C.pin(b"provider"))}
        selection = dict(payload=payload, providers=providers)
        view = dict(sonames={SONAME: dict(path=LIBRARY, **payload[LIBRARY]["pin"])},
                    offscreen=dict(path=W.OFFSCREEN, **payload[W.OFFSCREEN]["pin"]))
        for change in ("none", "provider", "trace"):
            with self.subTest(change=change):
                fixture = ReceiptFixture(plan)
                trace = (f"42: initialize program: {argv[0]}\n"
                         f"42: opening file={W.OFFSCREEN} [0]; direct_opencount=1\n"
                         f"42: calling init: {W.OFFSCREEN}\n").encode()
                if change == "trace":
                    trace = trace.replace(b"opening file", b"ignored file")
                fixture.command("install-consumer-run", argv, stderr=trace, env=env)
                fixture.reader("install-consumer-run", argv, env=env)
                maps = {LIBRARY: [0, 42, 10], PROVIDER: [0, 42, 12]} if change != "provider" else {LIBRARY: [0, 42, 10]}
                raw = C.wire(dict(soname=SONAME, path=LIBRARY, maps=maps, loaded=sorted(maps)))
                fixture.command("install-observe-soname-0", ["/usr/bin/python3", "-I", "-B", R.O.PROBE, SONAME],
                                stdout=raw)
                fixture.command("install-observe-package-files", H.P.PACMAN + ["-Qlq", "--", PACKAGE],
                                stdout=(LIBRARY + "\n" + W.OFFSCREEN + "\n").encode())
                paths = sorted((LIBRARY, PROVIDER, W.OFFSCREEN))
                owners = ["fixture" if path == PROVIDER else PACKAGE for path in paths]
                fixture.command("install-observe-owners-0", H.P.PACMAN + ["-Qoq", "--", *paths],
                                stdout=("\n".join(owners) + "\n").encode())
                stage = dict(name="install", state="installed")
                if change == "none":
                    R.replay_loaders(fixture.reader, plan, selection, stage, view)
                    fixture.reader.finish()
                else:
                    with self.assertRaises(ValueError):
                        R.replay_loaders(fixture.reader, plan, selection, stage, view)

    def test_selected_paths_and_provider_content_use_original_baseline(self):
        pin = C.pin(b"provider")
        paths = [USER_CONFIG, "/home/builder/.local/share"]
        rows = {USER_CONFIG: dict(type="absent"), paths[1]: dict(type="directory", uid=1000, gid=1000, mode=0o700),
                PROVIDER: dict(type="file", uid=0, gid=0, mode=0o755, pin=pin)}
        self.assertEqual(R.protection(C.wire(rows), paths, {PROVIDER: {"pin": pin}}),
                         dict(selected=paths, baseline={USER_CONFIG: {"present": False},
                                                       paths[1]: {"present": True, "type": "directory"}}))
        with self.assertRaises(ValueError):
            R.protection(C.wire(rows), [*paths, "/etc/pacman.conf"], {PROVIDER: {"pin": pin}})
        with self.assertRaises(ValueError):
            R.protection(C.wire(rows), paths, {PROVIDER: {"pin": C.pin(b"substitute")}})

    def test_full_main_replays_worker_timeline_with_raw_commands(self):
        definition = run_path(str(Path(__file__).with_name("test_worker.py")))
        model = definition["Worker"]()
        model.setUp()
        self.addCleanup(model.doCleanups)
        plan, selection = model.plan, model.selection
        fixture = ReceiptFixture(plan)
        program = plan["consumer"]["run"][0]
        trace = (f"42: initialize program: {program}\n"
                 f"42: opening file={W.OFFSCREEN} [0]; direct_opencount=1\n"
                 f"42: calling init: {W.OFFSCREEN}\n").encode()
        provider, = selection["providers"]
        provider_pin = selection["providers"][provider]["pin"]
        protected = C.wire({USER_CONFIG: dict(type="directory", uid=1000, gid=1000, mode=0o700),
                            provider: dict(type="file", uid=0, gid=0, mode=0o755, pin=provider_pin)})
        for role, view in model.observations.items():
            view["protected"] = protected
            if view["payload"]:
                model.override[role + "-consumer-run"] = {"stderr": trace}
        report = model.exercise()
        for role, argv, stdin, env in list(model.called):
            result = model.callback(role, argv, timeout=90, stdin=stdin, env=env)
            if role.endswith("-consumer-run"):
                env |= {"LD_DEBUG": "files"}
            fixture.command(role, argv, code=result["exit_code"], stdout=result["stdout"], stderr=result["stderr"],
                            stdin=stdin, env=env)
        for stage in plan["stages"]:
            role, view = stage["name"], dict(model.observations[stage["name"]])
            installed = stage["state"] == "installed"
            owned = {provider, W.OFFSCREEN} if installed else set()
            for index, soname in enumerate(plan["package"]["sonames"]):
                selected = view["sonames"][soname]
                name = selected["path"] if installed else None
                maps = {name: [0, 42, index + 1], provider: [0, 42, 100]} if installed else {}
                fixture.command(f"{role}-observe-soname-{index}", ["/usr/bin/python3", "-I", "-B", R.O.PROBE, soname],
                                stdout=C.wire(dict(soname=soname, path=name, maps=maps, loaded=sorted(maps))))
                if installed:
                    owned.add(name)
            if installed:
                pkg = plan["package"]["package"]
                fixture.command(role + "-observe-package-files", H.P.PACMAN + ["-Qlq", "--", pkg],
                                stdout=("\n".join(sorted(view["payload"])) + "\n").encode())
                paths = sorted(owned)
                owners = [selection["providers"][name]["owner"] if name == provider else pkg for name in paths]
                fixture.command(role + "-observe-owners-0", H.P.PACMAN + ["-Qoq", "--", *paths],
                                stdout=("\n".join(owners) + "\n").encode())
            for key in ("protected", "database"):
                if view[key] is not None:
                    fixture.files[f"evidence/{role}-{key}.json"] = view[key]
                    view[key] = C.pin(view[key])
            fixture.files[f"evidence/{role}-observed.json"] = C.wire(view)
        fixture.files["evidence/result.json"] = C.wire(report)
        signed = C.wire(selection)
        media = dict(case="main", plan=C.pin(model.raw), selection=C.pin(signed))
        operands = dict(config_raw=H.P.CONFIG.encode(), input_pins=model.inputs,
                        certificate_raw=model.certificate, signature_raw=model.signature)

        def review():
            return R.review_case(media, plan, selection, fixture.files, fixture.get,
                                 controls=(model.raw, model.base, signed), operands=operands,
                                 paths=[USER_CONFIG], epoch=definition["NOW"])

        with patch.dict(H.P.make_plan.__globals__, Q3_INVENTORY=C.pin(model.base)), \
                patch.object(H.P, "Q3_INVENTORY", C.pin(model.base)):
            database, protection = review()
            self.assertEqual(database, C.pin(model.observations["baseline"]["database"]))
            self.assertEqual(protection["baseline"][USER_CONFIG], {"present": True, "type": "directory"})
            fixture.files.pop(R.COMMAND_PREFIX + "install-consumer-run.json")
            with self.assertRaisesRegex(ValueError, "member missing"):
                review()

    def negative(self, case, *, wrong_status=False, wrong_trust=False, missing=False):
        fingerprint = "A" * 40
        key = dict(fingerprint=fingerprint, created=100, expires=300, test_only=True)
        signed_pin, bad_pin = C.pin(b"123"), C.pin(b"abc")
        signature = bad_pin if case == "tampered_signature" else signed_pin
        media = dict(case=case, clone="2" * 32, plan={"sha256": SHA}, selection={"sha256": SHA}, signature=signature)
        argv = H.P.PACMAN + ["--noconfirm", "-U", "--", H.P.ARCHIVE]
        inventory = H.P.PACMAN + ["-Q"]
        plan = dict(nonce="1" * 32, consumer=consumer(), stages=[{"inventory_query": inventory}],
                    negative_trials={case: {"command": argv}})
        selection = dict(key=key, inputs=dict(archive=C.pin(b"unsigned data"), signature=signed_pin))
        fixture = ReceiptFixture(plan)
        db, empty = b"original database", b"tru::::::::\n"
        diagnostic = (b"error: invalid or corrupted package (PGP signature)\n" if case == "tampered_signature"
                      else b"error: required key missing from keyring\n")
        fixture.command("inventory-before", inventory, stdout=LOCK)
        fixture.command("keyring-before", W.KEYRING_LIST, stdout=empty)
        if case == "tampered_signature":
            fields = f"pub:::::100:300:\nuid:::::::::Qt TEST:\nfpr:::::::::{fingerprint}:\n".encode()
            fixture.command("test-certificate", W.CERTIFICATE_SHOW, stdout=fields)
            fixture.command("key-import", W.GPG + ["--import", "--", H.P.CERT])
            fixture.command("imported-keyring", W.KEYRING_LIST, stdout=fields)
            status = (f"[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED {fingerprint} 0\n"
                      f"[GNUPG:] {'ERRSIG' if wrong_status else 'BADSIG'} {fingerprint[-16:]} Qt TEST\n").encode()
            fixture.command("tampered-signature-gpg", W.SIGNATURE_VERIFY, code=1, stdout=status)
            trust = b"different\n" if wrong_trust else (fingerprint + ":6:\n").encode()
            fixture.command("key-trust", W.GPG + ["--import-ownertrust"], stdin=trust)
        fixture.command("signature-refusal", argv, code=1, stderr=diagnostic)
        fixture.command("inventory-after", inventory, stdout=LOCK)
        if case == "unknown_key":
            fixture.command("keyring-after", W.KEYRING_LIST, stdout=empty)
        if not missing:
            fixture.command("trust-retirement", W.RETIRE)
        fixture.files["evidence/database-before.json"] = fixture.files["evidence/database-after.json"] = db
        fixture.files["evidence/result.json"] = C.wire(dict(
            clone=media["clone"], scratch=H.P.Q3_SCRATCH, configuration=C.pin(H.P.CONFIG.encode()),
            archive=selection["inputs"]["archive"], signature=signature, argv=argv, exit_code=1, natural=True,
            group_empty=True, stderr=C.pin(diagnostic), database_before=C.pin(db), database_after=C.pin(db),
            kind="QTBASE16K_INSTALLED_NEGATIVE_RESULT_V1", status="SIGNATURE_REFUSAL_VERIFIED_ONLY", case=case,
            nonce=plan["nonce"], plan_sha256=SHA, selection_sha256=SHA,
            inventory_before=C.pin(LOCK), inventory_after=C.pin(LOCK)))
        with patch.object(H.P, "Q3_INVENTORY", C.pin(LOCK)):
            return R.review_case(media, plan, selection, fixture.files, fixture.get, controls=None, operands=None,
                                 paths=[], epoch=200)

    def test_retained_negative_prerequisites_and_refusal_are_replayed(self):
        for role in ("unknown_key", "tampered_signature"):
            with self.subTest(role=role):
                self.assertEqual(self.negative(role), (C.pin(b"original database"), None))
        with self.assertRaisesRegex(ValueError, "member missing"):
            self.negative("unknown_key", missing=True)
        with self.assertRaisesRegex(ValueError, "BADSIG"):
            self.negative("tampered_signature", wrong_status=True)
        with self.assertRaisesRegex(ValueError, "key-trust input"):
            self.negative("tampered_signature", wrong_trust=True)


if __name__ == "__main__":
    unittest.main()
