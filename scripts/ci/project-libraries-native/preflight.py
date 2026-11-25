# SPDX-License-Identifier: MIT
"""Check whether a fresh runner can recover the missing Minimal206 kernel pin."""

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from native_arm import ROOT, sha, valid_signature

PRODUCER = "1604862d09fb04e471da03df2e2a98a5c05a77bf"
PRODUCER_BASE = "held-source/scripts/ci/llhttp-minimal-builder-source/base"
INPUTS_PIN = "629ef92976d17f13443897b0711a54ecb3e404eea4d0d997447407d76a9baf16"
KERNEL = "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz"
ARCHIVE = "https://pkgmirror.sametimetomorrow.net/aarch64/"


def producer_blob(path):
    return subprocess.check_output(
        ["git", "show", f"{PRODUCER}:{PRODUCER_BASE}/{path}"], cwd=ROOT, timeout=10,
    )


def kernel_inputs():
    raw = producer_blob("runtime/scripts/ci/inputs.lock.json")
    if hashlib.sha256(raw).hexdigest() != INPUTS_PIN:
        raise ValueError("Minimal206 input lock SHA-256 mismatch")
    inputs = json.loads(raw)
    kernel, = (row for row in inputs["packages"] if row["filename"] == KERNEL)
    keyring, = (row for row in inputs["keyring_files"] if row["filename"] == "archlinuxarm.gpg")
    profile = json.loads(producer_blob("profile.json"))
    signature = base64.b64decode(profile["minimal_public_signatures"][KERNEL + ".sig"], validate=True)
    if (len(signature) != kernel["signature_size"]
            or hashlib.sha256(signature).hexdigest() != kernel["signature_sha256"]):
        raise ValueError("Minimal206 embedded kernel signature differs from its transport pin")
    return kernel, signature, keyring, inputs["signer_fingerprint"]


def kernel_urls(kernel):
    return (
        kernel["url"],
        kernel["url"].replace("ca.us.", "fl.us.", 1),
        ARCHIVE + "packages/l/linux-aarch64/" + KERNEL,
        ARCHIVE + "repos/2026/11/15/core/" + KERNEL,
        ARCHIVE + "repos/2026/11/23/core/" + KERNEL,
    )


def download(url, path, limit):
    result = subprocess.run(
        ["curl", "-q", "--fail", "--location", "--silent", "--proto", "=https",
         "--proto-redir", "=https", "--max-redirs", "3", "--connect-timeout", "8",
         "--max-time", "20", "--max-filesize", str(limit), "--output", str(path),
         "--write-out", "%{http_code}", url],
        capture_output=True, text=True, timeout=25,
    )
    return result.returncode, result.stdout


def acquire(item, urls, directory, attempts):
    path = directory / item["filename"]
    for url in urls:
        code, status = download(url, path, item["size"])
        row = {"url": url, "http": status, "curl_exit": code}
        attempts.append(row)
        if code == 0 and status == "200" and path.stat().st_size == item["size"] and sha(path) == item["sha256"]:
            row["matched_pin"] = True
            return path
        row["matched_pin"] = False
        path.unlink(missing_ok=True)
    return None


def recheck():
    kernel, signature, keyring, signer = kernel_inputs()
    report = {"producer": PRODUCER, "inputs_sha256": INPUTS_PIN, "package": KERNEL,
              "expected_bytes": kernel["size"], "expected_sha256": kernel["sha256"],
              "kernel_attempts": [], "status": "HOLD", "native_build": "NOT RUN"}
    with tempfile.TemporaryDirectory(prefix="project-libraries-native-") as scratch:
        directory = Path(scratch)
        package = acquire(kernel, kernel_urls(kernel), directory, report["kernel_attempts"])
        if package is None:
            report["reason"] = "No checked route supplied the pinned kernel archive"
            return report
        report["keyring_attempts"] = []
        public_key = acquire(keyring, (keyring["url"],), directory, report["keyring_attempts"])
        if public_key is None:
            report["reason"] = "Pinned ALARM keyring acquisition failed"
            return report
        keyring_path = directory / "alarm-keyring.gpg"
        subprocess.run(
            ["gpg", "--batch", "--no-options", "--homedir", scratch,
             "--dearmor", "--output", str(keyring_path), str(public_key)],
            capture_output=True, check=True, timeout=10,
        )
        detached = directory / (KERNEL + ".sig")
        detached.write_bytes(signature)
        result = subprocess.run(
            ["gpgv", "--homedir", scratch, "--keyring", str(keyring_path), "--status-fd", "1",
             str(detached), str(package)],
            capture_output=True, text=True, timeout=10,
        )
        try:
            result.check_returncode()
            valid_signature(result.stdout, signer)
        except (subprocess.CalledProcessError, ValueError):
            report["reason"] = "Pinned ALARM signer verification failed"
            return report
    report["status"] = "KERNEL_PIN_RECOVERED"
    return report


def main():
    try:
        report = recheck()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report = {"status": "HOLD", "native_build": "NOT RUN", "error_type": type(error).__name__}
    print(json.dumps(report, indent=2))
    return int(report["status"] == "HOLD")


if __name__ == "__main__":
    sys.exit(main())
