# SPDX-License-Identifier: MIT
"""Verify codec cache pins and derive the TIFF builder lock from Minimal206."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from materialize import need, read, sha


CONTRACT = Path(__file__).with_name("minimal206-extension.json")
JBIG_PROVIDER = ("cachy-asahi-jbigkit", "2.2-1.1")


def derive(base_lock, contract):
    need(sha(base_lock) == contract["base_lock_sha256"], "Minimal206 baseline lock pin")
    rows = dict(line.split() for line in base_lock.decode("ascii").splitlines())
    need(len(rows) == contract["base_package_count"], "Minimal206 baseline package count")
    additions = {**contract["codec_versions"], JBIG_PROVIDER[0]: JBIG_PROVIDER[1]}
    need(not rows.keys() & (additions.keys() | {"jbigkit", "libtiff", "cachy-asahi-libtiff"}),
         "builder already has a codec or library provider")
    rows.update(additions)
    lock = "".join(f"{name} {version}\n" for name, version in sorted(rows.items())).encode()
    need(len(rows) == contract["tiff_package_count"] and sha(lock) == contract["tiff_lock_sha256"],
         "derived TIFF builder lock pin")
    return lock


def verify_codecs(cache, keyring, contract):
    pins = contract["codec_files"]
    with tempfile.TemporaryDirectory(prefix="project-library-codecs-") as temporary:
        snapshot = Path(temporary).resolve()
        for filename, pin in pins.items():
            body = read(cache / filename, pin["bytes"], lambda label: None)
            need(len(body) == pin["bytes"] and sha(body) == pin["sha256"], f"codec transport pin: {filename}")
            (snapshot / filename).write_bytes(body)
        fingerprint = contract["signer_fingerprint"]
        for filename in pins:
            if not filename.endswith(".sig"):
                continue
            process = subprocess.run(
                ["gpgv", "--homedir", str(snapshot), "--keyring", str(keyring.resolve(strict=True)),
                 "--status-fd", "1", str(snapshot / filename),
                 str(snapshot / filename.removesuffix(".sig"))],
                capture_output=True, text=True, timeout=10,
            )
            signatures = [line.split()[2] for line in process.stdout.splitlines()
                          if line.startswith("[GNUPG:] VALIDSIG ")]
            need(process.returncode == 0 and signatures == [fingerprint],
                 f"codec signature verification: {filename}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-lock", type=Path, required=True)
    parser.add_argument("--codec-cache", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True, help="dearmored reviewed ALARM public keyring")
    parser.add_argument("--output", type=Path, required=True, help="new TIFF pacman -Q lock file")
    args = parser.parse_args()
    try:
        contract = json.loads(CONTRACT.read_text())
        lock = derive(args.base_lock.read_bytes(), contract)
        verify_codecs(args.codec_cache.resolve(strict=True), args.keyring, contract)
        with args.output.open("xb") as stream:
            stream.write(lock)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Builder inputs failed: {error}\n")


if __name__ == "__main__":
    main()
