#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Read-only verification of one copied endpoint generation; never installs or fetches."""
import argparse
from datetime import datetime, timedelta
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


c = module("endpoint_client_inputs", HERE / "client.py")
e = module("endpoint_release_export", HERE.parent / "release/export_repository.py")
WITHDRAWAL = re.compile(r"withdrawals/([A-Za-z0-9][A-Za-z0-9._+-]*)\.json(?:\.sig)?\Z")
FIELDS = {"schema_version", "purpose", "selected_release", "signer", "files", "symlinks"}


def plan_check(plan, signer):
    c.need(set(plan) == FIELDS and type(plan["schema_version"]) is int and plan["schema_version"] == 1
           and plan["purpose"] == "local-repository-endpoint" and plan["signer"] == signer,
           "endpoint inventory schema/signer mismatch")
    files, links, rid = plan["files"], plan["symlinks"], plan["selected_release"]
    c.need(isinstance(files, dict) and isinstance(links, dict) and 0 < len(files)
           and len(files) + len(links) <= e.MAX_FILES, "bounded complete endpoint inventory required")
    withdrawals = set()
    for path, pin in files.items():
        c.relative(path)
        c.need(isinstance(pin, str) and c.HEX.fullmatch(pin), "invalid endpoint file digest")
        match = WITHDRAWAL.fullmatch(path)
        if match:
            withdrawals.add(e.r.valid_name(match[1]))
        else:
            c.need(rid is not None and (path.startswith("release/") or path in {"promotion.json", "promotion.json.sig"}),
                   "unrecognized endpoint member")
    for path, target in links.items():
        c.relative(path)
        c.need(rid is not None and path.startswith("release/") and isinstance(target, str)
               and "/" not in target and target not in {"", ".", ".."}, "invalid endpoint alias")
    for wid in withdrawals:
        c.need(all("withdrawals/" + wid + suffix in files for suffix in (".json", ".json.sig")),
               "incomplete withdrawal pair")
    if rid is None:
        c.need(withdrawals and not links, "withdrawal-only generation needs signed incident records")
    else:
        e.r.valid_name(rid)
        c.need(rid not in withdrawals and all(p in files for p in ("release/release.json", "release/release.json.sig",
                                                                 "promotion.json", "promotion.json.sig")),
               "selected release withdrawn or incomplete")
    return sorted(withdrawals)


def withdrawal_check(path, wid, signer, env):
    e.r.verify_signature(path, signer, env)
    value = c.decode(c.read_path(path, c.MAX_JSON))
    c.need(set(value) == {"schema_version", "release_id", "signer", "withdrawn_utc", "reason", "reason_sha256",
                          "packages_retained"} and type(value["schema_version"]) is int and value["schema_version"] == 1
           and value["release_id"] == wid and value["signer"] == signer and value["packages_retained"] is True
           and isinstance(value["reason"], str) and value["reason"] and isinstance(value["reason_sha256"], str)
           and c.HEX.fullmatch(value["reason_sha256"]), "invalid signed withdrawal identity/record")
    c.need(isinstance(value["withdrawn_utc"], str)
           and datetime.fromisoformat(value["withdrawn_utc"]).utcoffset() == timedelta(0),
           "withdrawal timestamp must use UTC")


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
        withdrawals = plan_check(plan, signer)
        e.generation_check(generation, plan)
        for path in plan["files"]:
            if path.endswith(".sig"):
                c.need((generation / path).stat().st_size <= c.MAX_SIGNATURE, "signature byte bound exceeded")
        with tempfile.TemporaryDirectory(prefix="cachy-asahi-endpoint-", dir="/tmp") as temporary:
            home = Path(temporary)
            (home / "pubring.gpg").write_bytes(keyring)
            (home / "pubring.gpg").chmod(0o600)
            # Only the supplied public certificate is copied; no caller home/config,
            # key import, key discovery, agent or dirmngr operation is permitted.
            (home / "gpg.conf").write_text("no-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\n"
                                           "disable-dirmngr\nno-autostart\nno-auto-check-trustdb\n")
            env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "GNUPGHOME": str(home), "LC_ALL": "C"}
            for wid in withdrawals:
                withdrawal_check(generation / "withdrawals" / (wid + ".json"), wid, signer, env)
            repo = None
            if plan["selected_release"] is not None:
                # Existing complete semantic, signature, source-delivery and actual
                # promotion/hardware gates remain mandatory, with no CLI override.
                e.stable(generation / "release", generation / "promotion.json", signer, env, plan["selected_release"])
                spec = e.r.load(generation / "release/spec.json")
                repo = "release/repo/" + e.r.valid_name(spec["repo_name"]) + ".db"
        e.generation_check(generation, plan)
        c.need(c.read_member(fd, "export.json") == raw, "inventory changed during verification")
        final = generation.stat(follow_symlinks=False)
        c.need((initial.st_dev, initial.st_ino) == (final.st_dev, final.st_ino), "generation directory replaced")
        return {"status": "verified-local-endpoint", "generation": expected_generation, "signer": signer,
                "selected_release": plan["selected_release"], "withdrawn_releases": withdrawals,
                "repository_relative_path": repo, "stable_contract_checked": repo is not None,
                "freshness_established": False, "installation_authorized": False, "production_accepted": False,
                "network_used": False, "trust_changed": False, "state_changed": False}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("generation", "expected-generation", "public-keyring", "signer"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.generation, args.expected_generation, args.public_keyring, args.signer), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (c.Error, e.r.Error, ValueError, TypeError, KeyError, OSError) as error:
        print(f"endpoint verification error: {error}", file=sys.stderr)
        sys.exit(1)
