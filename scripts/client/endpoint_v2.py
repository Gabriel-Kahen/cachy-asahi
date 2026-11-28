#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify one locally copied retained-recovery endpoint generation."""
import argparse
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("endpoint_v1", HERE / "endpoint.py")
v1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v1)
c, e = v1.c, v1.e
v2 = v1.module("endpoint_export_v2", HERE.parent / "release/export_repository_v2.py")
PLAN = "recovery-plan.json"
SIGNATURE = PLAN + ".sig"
FIELDS = {"schema_version", "purpose", "signer", "expected_current", "current_release_id",
          "current_release_sha256", "target_release_id", "target_release_sha256",
          "target_promotion_sha256", "base_sha256", "withdrawal_files", "reason"}


def recovery_check(fd, plan, generation_id, verifier):
    files = plan["files"]
    raw = c.read_member(fd, PLAN)
    signature = c.read_member(fd, SIGNATURE, c.MAX_SIGNATURE)
    c.need(c.digest(raw) == files[PLAN] and c.digest(signature) == files[SIGNATURE],
           "recovery plan or signature differs from the generation inventory")
    snapshot = verifier.temp / PLAN
    snapshot.write_bytes(raw)
    verifier.verify(snapshot, signature)
    value = c.decode(raw)
    c.need(e.encoded(value) == raw and set(value) == FIELDS and type(value["schema_version"]) is int
           and value["schema_version"] == 1 and value["purpose"] == "local-retained-stable-recovery"
           and value["signer"] == verifier.signer, "invalid canonical recovery authorization schema/signer")
    current = value["expected_current"]
    current_release = e.r.valid_name(value["current_release_id"])
    current_digest = value["current_release_sha256"]
    reason = value["reason"]
    c.need(isinstance(current, str) and e.GENERATION.fullmatch(current) and current != "generations/" + generation_id
           and current_release != plan["selected_release"] and isinstance(current_digest, str)
           and c.HEX.fullmatch(current_digest) and current_digest != files["release/release.json"]
           and isinstance(reason, str) and reason.strip() and len(reason) <= 4096,
           "invalid expected-current recovery lineage or reason")
    c.need(value["target_release_id"] == plan["selected_release"]
           and value["target_release_sha256"] == files["release/release.json"]
           and value["target_promotion_sha256"] == files["promotion.json"]
           and value["base_sha256"] == files["release/base.json"]
           and value["withdrawal_files"] == {name: pin for name, pin in files.items() if name.startswith("withdrawals/")},
           "recovery authorization differs from selected release, promotion, base or withdrawals")
    return current


def verify(generation, expected_generation, public_keyring, signer):
    generation = e.canonical(generation)
    e.managed_directory(generation)
    signer = c.fingerprint(signer)
    c.need(isinstance(expected_generation, str) and c.HEX.fullmatch(expected_generation), "full generation SHA256 required")
    keyring = c.read_path(public_keyring, c.MAX_KEYRING)
    fd = c.directory(generation)
    try:
        initial = os.fstat(fd)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        raw = c.read_member(fd, "export.json")
        c.need(c.digest(raw) == expected_generation, "generation differs from independently supplied identity")
        plan = c.decode(raw)
        c.need(e.encoded(plan) == raw, "noncanonical endpoint inventory")
        files = plan["files"]
        c.need(isinstance(files, dict) and {PLAN, SIGNATURE} <= files.keys() and plan["selected_release"] is not None,
               "retained recovery requires a selected release and a complete signed plan")
        c.need(all(isinstance(files[name], str) and c.HEX.fullmatch(files[name]) for name in (PLAN, SIGNATURE)),
               "invalid recovery plan or signature digest")
        ordinary_files = {name: pin for name, pin in files.items() if name not in (PLAN, SIGNATURE)}
        withdrawals = v1.plan_check(dict(plan, files=ordinary_files), signer)
        e.generation_check(generation, plan)
        for path in files:
            if path.endswith(".sig"):
                c.need((generation / path).stat().st_size <= c.MAX_SIGNATURE, "signature byte bound exceeded")
        with tempfile.TemporaryDirectory(prefix="cachy-asahi-recovery-recipient-", dir="/tmp") as temporary:
            verifier = c.Verifier(temporary, keyring, signer, datetime.now(timezone.utc))
            previous = recovery_check(fd, plan, expected_generation, verifier)
            home = verifier.home
            (home / "gpg.conf").write_text(f"no-default-keyring\nkeyring {verifier.keyring}\n"
                                           "no-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\n"
                                           "disable-dirmngr\nno-autostart\nno-auto-check-trustdb\n")
            env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "GNUPGHOME": str(home), "LC_ALL": "C"}
            for wid in withdrawals:
                v1.withdrawal_check(generation / "withdrawals" / (wid + ".json"), wid, signer, env)
            release_files, release_links = (
                {name.removeprefix("release/"): pin for name, pin in plan[field].items() if name.startswith("release/")}
                for field in ("files", "symlinks")
            )
            promoted = v2.stable(generation / "release", generation / "promotion.json", signer, env,
                                 plan["selected_release"], release_files, release_links)
            c.need(all(files[name] == pin for name, (_, pin) in promoted.items()), "promotion differs from generation inventory")
            spec_raw = c.read_member(fd, "release/spec.json")
            c.need(c.digest(spec_raw) == release_files["spec.json"], "selected release spec changed during verification")
            repo = "release/repo/" + e.r.valid_name(json.loads(spec_raw)["repo_name"]) + ".db"
        e.generation_check(generation, plan)
        c.need(c.read_member(fd, "export.json") == raw, "inventory changed during verification")
        final = generation.stat(follow_symlinks=False)
        c.need((initial.st_dev, initial.st_ino) == (final.st_dev, final.st_ino), "generation directory replaced")
        return {"status": "verified-local-endpoint", "generation": expected_generation, "signer": signer,
                "selected_release": plan["selected_release"], "withdrawn_releases": withdrawals,
                "repository_relative_path": repo, "stable_contract_checked": True,
                "authorization_sha256": files[PLAN], "previous_selection": previous,
                "freshness_established": False, "installation_authorized": False, "production_accepted": False,
                "network_used": False, "trust_changed": False, "state_changed": False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("generation", "expected-generation", "public-keyring", "signer"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.generation, args.expected_generation, args.public_keyring, args.signer)
    except (c.Error, e.r.Error, v2.R.Error, v2.C.r.Error, OSError, ValueError, TypeError, KeyError,
            RecursionError, subprocess.TimeoutExpired) as error:
        print(f"recovery endpoint verification error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
