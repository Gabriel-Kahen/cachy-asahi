#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify Q2's exact detached Arch Linux ARM root filesystem signature offline."""

import argparse
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import re
import tempfile
import time

REPO = Path(__file__).resolve().parents[3]
ARCHIVE = "rootfs.tar.gz"
SIGNATURE = ARCHIVE + ".sig"
ARMOR = "official/archlinuxarm.gpg"
TRUSTED = "official/archlinuxarm-trusted"
REVOKED = "official/archlinuxarm-revoked"
PLAN_KIND = "QTBASE_16K_OFFLINE_OPERANDS_V1"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


public = load("arch_arm_public", "scripts/port/minimal-native-builder-input-authentication/verify.py")
lifecycle = load("qt_trust_process", "scripts/integration/lifecycle.py")
native = public.module(REPO / "scripts/ci/native_arm.py",
                       public.ENGINES["scripts/ci/native_arm.py"], "native_arm_signature")


def selected_inputs(media, plan_sha256):
    """Join the Qt DATA projection to the independently pinned builder operands."""
    public.need(re.fullmatch("[a-f0-9]{64}", plan_sha256), "Exact plan SHA-256 required")
    plan_path = public.ordinary(media / "plan.json")
    plan_pin = dict(bytes=plan_path.stat().st_size, sha256=plan_sha256)
    plan = public.decode(public.read_pinned(plan_path, plan_pin, limit=512 * 1024))
    public.need(plan.get("kind") == PLAN_KIND and plan.get("Root_authority", False) is None,
                "Expected unissued Qt offline operands")
    builder_path = REPO / "scripts/port/minimal-native-builder-inputs/builder.lock.json"
    builder = public.decode(public.read_pinned(builder_path, public.BUILDER))
    public.need(builder["signer_fingerprint"] == public.SIGNER, "Exact official signing primary required")
    rootfs = builder["rootfs"]
    materials = {
        ARCHIVE: dict(bytes=rootfs["size"], sha256=rootfs["sha256"]),
        SIGNATURE: dict(bytes=rootfs["signature_size"], sha256=rootfs["signature_sha256"]),
    }
    for row in builder["keyring_files"]:
        name = "official/" + row["filename"]
        materials[name] = dict(bytes=row["size"], sha256=row["sha256"])
    files = plan.get("files")
    public.need(set(materials) == {ARCHIVE, SIGNATURE, ARMOR, TRUSTED, REVOKED}
                and isinstance(files, dict) and all(files.get(name) == pin for name, pin in materials.items()),
                "Qt media differs from the exact independent rootfs and official trust pins")
    return plan_pin, materials


def verify(media, plan_sha256):
    media = public.ordinary(media)
    plan_pin, materials = selected_inputs(media, plan_sha256)
    deadline = time.monotonic() + 90
    with ExitStack() as stack:
        held = {}
        for name, pin in materials.items():
            leaf = public.Held(media / name, pin, deadline=deadline)
            stack.callback(leaf.close)
            held[name] = leaf
        armor = held[ARMOR].raw()
        key = public.public_key(armor, held[TRUSTED].raw(), held[REVOKED].raw())
        algorithms = public.signature_algorithms(held[SIGNATURE].raw())
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="qt-rootfs-public-")))
        home = tmp / "home"
        home.mkdir(mode=0o700)
        original = tmp / "archlinuxarm.gpg"
        original.write_bytes(armor)
        binary = tmp / "official-binary.gpg"
        wrong_archive = tmp / "wrong-input.tar.gz"
        wrong_archive.write_bytes(b"Qt rootfs detached signature negative control\n")
        environment = dict(HOME=str(home), GNUPGHOME=str(home), PATH="/nonexistent",
                           LC_ALL="C", LANG="C", TZ="UTC")

        def checked_process(argv):
            remaining = deadline - time.monotonic()
            public.need(remaining > 0, "Rootfs verification exceeded its total time limit")
            for leaf in held.values():
                leaf.stable()
            observed = lifecycle.bounded_process(
                argv, timeout=min(30, remaining), stdout_limit=16 * 1024,
                stderr_limit=16 * 1024, env=environment, preexec_fn=public.child_limits,
            )
            local_state = {path.name for path in home.iterdir()}
            public.need(observed["reason"] == "exit" and observed["cleanup"]["reaped"]
                        and not observed["cleanup"]["term_sent"] and not observed["cleanup"]["kill_sent"]
                        and local_state <= {"trustdb.gpg"},
                        "Public verifier did not retire naturally or left unexpected private state")
            for leaf in held.values():
                leaf.stable()
            return dict(exit=observed["returncode"], stdout=observed["stdout"].decode("ascii"),
                        stderr=observed["stderr"].decode("utf-8").replace(str(tmp), "<private-public-check>"))

        converter = checked_process([
            "/usr/bin/gpg", "--no-options", "--batch", "--no-tty", "--no-autostart",
            "--disable-dirmngr", "--homedir", str(home), "--dearmor", "--output", str(binary), str(original),
        ])
        public.need(converter["exit"] == 0 and public.read_pinned(binary, public.BINARY_KEY, limit=4096) == key,
                    "GnuPG normalization differs from the independently pinned official binary key")
        status = checked_process([
            "/usr/bin/gpg", "--no-options", "--batch", "--no-tty", "--no-autostart",
            "--disable-dirmngr", "--homedir", str(home), "--no-default-keyring", "--keyring", str(binary),
            "--no-auto-check-trustdb", "--no-auto-key-retrieve", "--no-auto-key-import",
            "--with-colons", "--fixed-list-mode", "--with-fingerprint", "--with-subkey-fingerprint",
            "--list-options", "show-unusable-uids,show-unusable-subkeys", "--show-keys", str(binary),
        ])
        now = int(time.time())
        public.need(status["exit"] == 0, "Public key inspection failed")
        public.key_status(status["stdout"], now)

        def check_detached(ring, data):
            return checked_process(["/usr/bin/gpgv", "--homedir", str(home), "--keyring", str(ring),
                                    "--status-fd", "1", "--", str(held[SIGNATURE].path), str(data)])

        legacy = check_detached(original, held[ARCHIVE].path)
        if legacy["exit"] == 0:
            public.signature_status(legacy["stdout"], now, native, algorithms)
        exact = check_detached(binary, held[ARCHIVE].path)
        public.need(exact["exit"] == 0, "Normalized official rootfs signature was refused")
        public.signature_status(exact["stdout"], now, native, algorithms)

        wrong = check_detached(binary, wrong_archive)
        public.need(wrong["exit"] != 0 and "[GNUPG:] BADSIG " in wrong["stdout"]
                    and "[GNUPG:] VALIDSIG " not in wrong["stdout"],
                    "The original signature must reject a different payload")
        for leaf in held.values():
            leaf.digest(deadline)
        public.read_pinned(media / "plan.json", plan_pin, limit=512 * 1024)

    return dict(status="PASS_QT_ROOTFS_DETACHED_SIGNATURE", normalized=public.BINARY_KEY,
                primary_fingerprint=public.SIGNER, plan=plan_pin, materials=materials,
                converter=converter, public_key_status=status, direct_armored=legacy, normalized_detached=exact,
                wrong_payload=wrong, guest_started=False, Root_authority=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    print(public.encoded(verify(args.media, args.plan_sha256)).decode(), end="")


if __name__ == "__main__":
    main()
