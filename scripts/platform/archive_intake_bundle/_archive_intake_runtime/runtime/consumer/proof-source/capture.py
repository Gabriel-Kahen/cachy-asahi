#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain upstream platform data; never install, mount or execute image content."""
import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
LIMIT = 8 * 1024**3
FINGERPRINT = "12CE6799A94A3F1B5DDFFE88F576553597FB8FEB"
ALARM_PIN = "9821995723fa3326553d0d942d0b900173462ea8"
KEY_PIN = "5103f1eb621b54d7e6fe87070042c2d297878456"
INSTALLER_PIN = "dffbb38ef0c00c0431c609ecd8a00f42deb5b24c"
RECIPE_PIN = "1c6daffd905c1b8f76202949ed48b80a4759ab73"
PLATFORM = {
    "asahi-meta", "linux-asahi", "uboot-asahi", "m1n1", "asahi-scripts",
    "asahi-alarm-keyring", "asahi-fwextract", "asahi-firmware", "asahi-configs",
    "asahi-audio", "alsa-ucm-conf-asahi", "speakersafetyd", "tiny-dfr",
    "bankstown", "triforce-lv2", "lsp-plugins-lv2", "pipewire", "wireplumber",
    "mesa", "mesa-asahi", "vulkan-asahi", "libglvnd", "libdrm", "grub",
}
NAME = re.compile(r"[A-Za-z0-9@._+:-]+\Z")
PINS = {"community": ALARM_PIN, "installer": INSTALLER_PIN,
        "keyring": KEY_PIN, "recipes": RECIPE_PIN}
IMAGE_FILES = {"asahi-base.zip", "root.img", "esp-boot.bin", "esp-BOOTAA64.EFI", "image-inventory.json"}


def load_json(path, maximum=4 * MIB):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("JSON input bound exceeded")
    return json.loads(data, object_pairs_hook=unique)


def load_sources():
    sources = load_json(Path(__file__).parent / "sources.json")
    if not isinstance(sources, dict) or not sources or len(sources) > 100:
        raise ValueError("invalid source manifest")
    for name, spec in sources.items():
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", "..", "capture.json"} or name in IMAGE_FILES:
            raise ValueError("invalid source filename")
        if set(spec) - {"url", "max_bytes", "sha256"} or not {"url", "max_bytes"} <= set(spec):
            raise ValueError("invalid source specification")
        if type(spec["max_bytes"]) is not int or not 0 < spec["max_bytes"] <= 32 * MIB:
            raise ValueError("invalid source bound")
        if "sha256" in spec and not re.fullmatch(r"[a-f0-9]{64}", spec["sha256"]):
            raise ValueError("invalid source digest")
        parsed = urllib.parse.urlsplit(spec["url"])
        if parsed.scheme != "https" or parsed.hostname not in {"asahi-alarm.org", "github.com", "raw.githubusercontent.com"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("unexpected source origin")
    return sources


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as src:
        for block in iter(lambda: src.read(MIB), b""):
            h.update(block)
    return h.hexdigest()


def regular(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError(f"not a single-link regular file: {path.name}")


def private_destination(path):
    if not Path(path).is_absolute():
        raise ValueError("absolute capture destination required")
    path = Path(os.path.abspath(path))
    path.relative_to(ROOT / "artifacts")
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise ValueError("symlink destination component")
    if path.exists():
        raise ValueError("capture destination must be absent")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(path.parent).free < LIMIT + 256 * MIB:
        raise ValueError("8 GiB plus reserve required before capture")
    path.mkdir(mode=0o700)
    return path


def download(url, path, maximum, expected=None, deadline=600):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("HTTPS source required")
    started = time.monotonic()
    temporary = path.with_name(path.name + ".partial")
    size = 0
    h = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200 or urllib.parse.urlsplit(response.url).scheme != "https":
                raise ValueError("unexpected response or insecure redirect")
            advertised = response.headers.get("Content-Length")
            if advertised and (not advertised.isdigit() or int(advertised) > maximum):
                raise ValueError("advertised source exceeds limit")
            observed = {"last_modified": response.headers.get("Last-Modified"),
                        "advertised_bytes": int(advertised) if advertised else None}
            # Do not retain ephemeral redirect query strings or response credentials.
            final = urllib.parse.urlsplit(response.url)
            observed["transport_host"] = final.hostname
            with temporary.open("xb") as target:
                os.chmod(temporary, 0o600)
                while True:
                    if time.monotonic() - started > deadline:
                        raise ValueError("download deadline exceeded")
                    # One socket read lets the overall deadline be checked even
                    # when a peer continually trickles less than a full block.
                    block = response.read1(min(MIB, maximum - size + 1))
                    if not block:
                        break
                    size += len(block)
                    if size > maximum:
                        raise ValueError("source exceeds byte limit")
                    target.write(block)
                    h.update(block)
            if advertised and size != int(advertised):
                raise ValueError("short or inconsistent source response")
        sha = h.hexdigest()
        if expected and sha != expected:
            raise ValueError("source pin mismatch: " + path.name)
        temporary.rename(path)
        return {"url": url, "bytes": size, "sha256": sha,
                "predeclared_sha256": expected, **observed}
    finally:
        temporary.unlink(missing_ok=True)


def bounded_command(argv, timeout=20, limit=8 * MIB):
    def bounds():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        resource.setrlimit(resource.RLIMIT_AS, (512 * MIB, 512 * MIB))
        resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(argv, stdout=out, stderr=err, timeout=timeout,
                                preexec_fn=bounds, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(limit + 1), err.read(limit + 1)
    if result.returncode or len(stdout) >= limit or len(stderr) >= limit:
        raise ValueError("bounded read-only command failed: " + Path(argv[0]).name)
    return stdout, stderr


def verify_signature(directory, certificate, signature, payload):
    # Fresh private scratch only; never use/import into the user's GPG home.
    with tempfile.TemporaryDirectory(prefix="verify-", dir=directory) as scratch:
        home = Path(scratch)
        key = home / "public.gpg"
        bounded_command(["gpg", "--no-options", "--batch", "--homedir", str(home),
                         "--dearmor", "--output", str(key), str(certificate)])
        status, _ = bounded_command(["gpgv", "--homedir", str(home), "--keyring", str(key),
                                     "--status-fd", "1", str(signature), str(payload)])
        valid = []
        bad = {"BADSIG", "ERRSIG", "EXPKEYSIG", "EXPSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED"}
        for line in status.decode("ascii").splitlines():
            fields = line.split()
            if len(fields) > 1 and fields[0] == "[GNUPG:]":
                if fields[1] in bad:
                    raise ValueError("unacceptable signature status")
                if fields[1] == "VALIDSIG":
                    valid.append(fields)
        if len(valid) != 1 or len(valid[0]) < 11:
            raise ValueError("one complete VALIDSIG required")
        fields = valid[0]
        primary = fields[11] if len(fields) > 11 else fields[2]
        if primary != FINGERPRINT or fields[9] not in {"8", "9", "10", "11"}:
            raise ValueError("unexpected primary signer or weak digest")
        return {"status": "cryptographic-signature-valid", "primary_fingerprint": primary,
                "owner_authentication": "same-organization-pinned-source-only",
                "independent_owner_trust_accepted": False}


def parse_desc(data):
    if len(data) > 256 * 1024:
        raise ValueError("descriptor too large")
    fields = {}
    key = None
    for line in data.decode("utf-8").splitlines():
        if line.startswith("%") and line.endswith("%"):
            key = line[1:-1]
            if not re.fullmatch(r"[A-Z0-9_]+", key) or key in fields:
                raise ValueError("invalid or repeated descriptor field")
            fields[key] = []
        elif line:
            if key is None or "\x00" in line:
                raise ValueError("invalid descriptor value")
            fields[key].append(line)
    for key in ["NAME", "VERSION", "ARCH"]:
        if len(fields.get(key, [])) != 1 or not NAME.fullmatch(fields[key][0]):
            raise ValueError("invalid descriptor identity")
    return fields


def unpack_image(archive, directory=None):
    allowed = {"esp/", "esp/EFI/", "esp/EFI/BOOT/", "esp/m1n1/",
               "esp/EFI/BOOT/BOOTAA64.EFI", "esp/m1n1/boot.bin", "root.img"}
    extracted = {}
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) != len(allowed) or {x.filename for x in members} != allowed:
            raise ValueError("unexpected minimal image ZIP layout")
        if sum(x.file_size for x in members) > 4 * 1024**3:
            raise ValueError("image unpack budget exceeded")
        for item in members:
            mode = item.external_attr >> 16
            if mode and (mode & 0o170000) not in {0, 0o040000, 0o100000}:
                raise ValueError("special ZIP member refused")
            if item.is_dir():
                if mode and mode & 0o170000 not in {0, 0o040000}:
                    raise ValueError("invalid directory ZIP member")
                continue
            if mode and mode & 0o170000 not in {0, 0o100000}:
                raise ValueError("invalid regular ZIP member")
            maximum = 4 * 1024**3 if item.filename == "root.img" else 16 * MIB
            if item.file_size > maximum or item.flag_bits & 1:
                raise ValueError("oversized or encrypted image member")
            name = {"root.img": "root.img", "esp/m1n1/boot.bin": "esp-boot.bin",
                    "esp/EFI/BOOT/BOOTAA64.EFI": "esp-BOOTAA64.EFI"}[item.filename]
            target = directory / name if directory else None
            h = hashlib.sha256(); size = 0; started = time.monotonic()
            with source.open(item) as src, (target.open("xb") if target else contextlib.nullcontext()) as out:
                if target:
                    os.chmod(target, 0o600)
                for block in iter(lambda: src.read(MIB), b""):
                    size += len(block)
                    if size > maximum or time.monotonic() - started > 180:
                        raise ValueError("image extraction bound exceeded")
                    if out:
                        out.write(block)
                    h.update(block)
            if size != item.file_size:
                raise ValueError("short ZIP member")
            extracted[name] = {"zip_member": item.filename, "bytes": size, "sha256": h.hexdigest()}
    if directory:
        with (directory / "root.img").open("rb") as root:
            root.seek(1024 + 56)
            if root.read(2) != b"\x53\xef":
                raise ValueError("expected ext filesystem image")
    return extracted


def image_inventory(image):
    def read(command, limit=8 * MIB):
        output, errors = bounded_command(["debugfs", "-R", command, str(image)], limit=limit)
        diagnostics = errors.decode("utf-8").strip().splitlines()
        if any(not re.fullmatch(r"debugfs [0-9][^\r\n]*", line) for line in diagnostics):
            raise ValueError("debugfs image read diagnostic")
        return output
    listing = read("ls -p /var/lib/pacman/local")
    packages = []; directories = set(); started = time.monotonic(); descriptor_bytes = 0
    for line in listing.decode("utf-8").splitlines():
        if not line:
            continue
        parts = line.split("/")
        if len(parts) != 8 or parts[0] or parts[7] or not all(x.isdigit() for x in [parts[1], parts[2], parts[3], parts[4]]):
            raise ValueError("malformed image package listing")
        kind = int(parts[2], 8) & 0o170000
        if not parts[6].isdigit() and not (not parts[6] and kind == 0o040000):
            raise ValueError("malformed image entry size")
        if parts[5] in {".", "..", "ALPM_DB_VERSION"}:
            continue
        name = parts[5]
        if not NAME.fullmatch(name) or int(parts[2], 8) & 0o170000 != 0o040000:
            raise ValueError("unsafe local database entry")
        if name in directories or len(directories) >= 2048:
            raise ValueError("duplicate or excessive package directories")
        directories.add(name)
        if time.monotonic() - started > 180:
            raise ValueError("inventory read deadline exceeded")
        data = read(f"cat /var/lib/pacman/local/{name}/desc", limit=MIB)
        descriptor_bytes += len(data)
        if descriptor_bytes > 4 * MIB:
            raise ValueError("aggregate image package metadata bound exceeded")
        metadata = parse_desc(data)
        if metadata["ARCH"][0] not in {"any", "aarch64"}:
            raise ValueError("non-ARM package in minimal image inventory")
        packages.append({"directory": name, "descriptor_sha256": hashlib.sha256(data).hexdigest(),
                         "metadata": metadata})
    names = [x["metadata"]["NAME"][0] for x in packages]
    if not packages or len(set(names)) != len(names):
        raise ValueError("empty or duplicate installed package inventory")
    result = {"kind": "observed-image-local-package-metadata", "packages": sorted(packages, key=lambda x:x["metadata"]["NAME"]),
            "platform": {x["metadata"]["NAME"][0]: x["metadata"] for x in packages if x["metadata"]["NAME"][0] in PLATFORM},
            "dependency_transaction_accepted": False, "hardware_accepted": False}
    if len((json.dumps(result, indent=2, sort_keys=True) + "\n").encode()) > 8 * MIB:
        raise ValueError("image inventory metadata bound exceeded")
    return result


def installer_inventory(archive, expected_main):
    with gzip.open(archive, "rb") as src:
        data = src.read(128 * MIB + 1)
    if len(data) > 128 * MIB:
        raise ValueError("installer decoded budget exceeded")
    members = {}; main = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as src:
        for count, member in enumerate(src, 1):
            if count > 4096 or len(member.name) > 4096:
                raise ValueError("installer member inventory bound exceeded")
            name = member.name.removeprefix("./")
            is_main = name in {"src/main.py", "main.py"} or name.endswith("/src/main.py")
            if member.isfile() and (is_main or name == "LICENSE" or name.endswith("/LICENSE")):
                if member.size > MIB:
                    raise ValueError("selected installer source member too large")
                blob = src.extractfile(member).read(MIB + 1)
                members[member.name] = hashlib.sha256(blob).hexdigest()
                if is_main:
                    main.append(blob)
    if len(main) != 1:
        raise ValueError("one installer main source required")
    return {"selected_member_sha256": members,
            "main_equals_upstream_tag": main[0] == expected_main.read_bytes(),
            "complete_source_correspondence_accepted": False,
            "installer_executed": False}


def write_json(path, value):
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if len(encoded.encode()) > 8 * MIB:
        raise ValueError("serialized metadata bound exceeded")
    with path.open("x", encoding="utf-8") as target:
        os.chmod(path, 0o600)
        target.write(encoded)


def capture(output, image=False):
    sources = load_sources()
    # Upper bounds include all source bytes, ZIP + decoded image, and 8 MiB metadata.
    budget = sum(x["max_bytes"] for x in sources.values()) + (6 * 1024**3 + 8 * MIB if image else 0)
    if budget > LIMIT:
        raise ValueError("aggregate capture upper bound exceeds 8 GiB")
    directory = private_destination(output)
    receipt = {"schema_version": 1, "status": "capture-started", "files": {},
               "source_pins": PINS,
               "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "system_mutation": False, "installation_accepted": False, "hardware_accepted": False}
    try:
        for name, spec in sources.items():
            receipt["files"][name] = download(spec["url"], directory / name, spec["max_bytes"], spec.get("sha256"))
        receipt["installer_inventory"] = installer_inventory(directory / "installer-v0.9.2.tar.gz", directory / "installer-main.py")
        receipt["repository_signatures"] = {}
        for name in ["asahi-alarm.db", "asahi-alarm.files"]:
            receipt["repository_signatures"][name] = verify_signature(directory, directory / "asahi-alarm.asc", directory / (name + ".sig"), directory / name)
        if image:
            receipt["files"]["asahi-base.zip"] = download("https://asahi-alarm.org/asahi-base.zip", directory / "asahi-base.zip", 2 * 1024**3, deadline=2400)
            extracted = unpack_image(directory / "asahi-base.zip", directory)
            receipt["files"].update(extracted)
            inventory = image_inventory(directory / "root.img")
            write_json(directory / "image-inventory.json", inventory)
            receipt["files"]["image-inventory.json"] = {"bytes": (directory / "image-inventory.json").stat().st_size, "sha256": digest(directory / "image-inventory.json")}
            receipt["image_authentication"] = "observed-HTTPS-bytes-no-independent-image-signature"
        if sum(x["bytes"] for x in receipt["files"].values()) > LIMIT:
            raise ValueError("total retained budget exceeded")
        receipt["status"] = "data-captured-not-installation-accepted"
    except Exception as error:
        receipt["status"] = "capture-incomplete"
        receipt["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        write_json(directory / "capture.json", receipt)
    return receipt


def validate(directory, pending=False):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise ValueError("private absolute capture directory required")
    for parent in directory.parents:
        if parent.is_symlink():
            raise ValueError("symlink capture ancestor")
    regular(directory / "capture.json")
    if (directory / "capture.json").stat().st_size > 4 * MIB:
        raise ValueError("receipt exceeds limit")
    receipt = load_json(directory / "capture.json")
    sources = load_sources()
    if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1 or receipt.get("source_pins") != PINS:
        raise ValueError("capture schema/source pins mismatch")
    status = "capture-incomplete" if pending else "data-captured-not-installation-accepted"
    if receipt.get("status") != status or any(receipt.get(x) is not False for x in ["system_mutation", "installation_accepted", "hardware_accepted"]):
        raise ValueError("incomplete or misclassified capture")
    names = set(receipt["files"])
    image_files = IMAGE_FILES - {"image-inventory.json"} if pending else IMAGE_FILES
    if pending and "asahi-base.zip" not in names:
        raise ValueError("retained full image required for metadata completion")
    expected = set(sources) | (image_files if "asahi-base.zip" in names else set())
    if "capture-incomplete.json" in names:
        expected.add("capture-incomplete.json")
    if names != expected or {x.name for x in directory.iterdir()} != expected | {"capture.json"}:
        raise ValueError("incomplete or extra retained file set")
    total = 0
    for name, reference in receipt["files"].items():
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", "..", "capture.json"}:
            raise ValueError("unsafe retained filename")
        path = directory / name; regular(path)
        total += path.stat().st_size
        if total > LIMIT or path.stat().st_size != reference["bytes"] or digest(path) != reference["sha256"]:
            raise ValueError("retained byte mismatch")
        if name in sources:
            spec = sources[name]
            if reference.get("url") != spec["url"] or reference.get("predeclared_sha256") != spec.get("sha256") or reference["bytes"] > spec["max_bytes"] or (spec.get("sha256") and reference["sha256"] != spec["sha256"]):
                raise ValueError("retained source does not match pinned manifest")
        if name == "asahi-base.zip" and (reference.get("url") != "https://asahi-alarm.org/asahi-base.zip" or reference["bytes"] > 2 * 1024**3 or reference.get("predeclared_sha256") is not None):
            raise ValueError("unexpected minimal image origin or size")
        if name == "image-inventory.json" and reference["bytes"] > 8 * MIB:
            raise ValueError("image inventory metadata bound exceeded")
        if name == "capture-incomplete.json" and reference["bytes"] > 4 * MIB:
            raise ValueError("prior receipt bound exceeded")
    for name in ["asahi-alarm.db", "asahi-alarm.files"]:
        actual = verify_signature(directory, directory / "asahi-alarm.asc", directory / (name + ".sig"), directory / name)
        if actual != receipt["repository_signatures"][name]:
            raise ValueError("signature receipt mismatch")
    actual = installer_inventory(directory / "installer-v0.9.2.tar.gz", directory / "installer-main.py")
    if actual != receipt["installer_inventory"]:
        raise ValueError("installer source receipt mismatch")
    if "asahi-base.zip" in names:
        if not pending and receipt.get("image_authentication") != "observed-HTTPS-bytes-no-independent-image-signature":
            raise ValueError("unaccepted image authentication claim")
        bindings = unpack_image(directory / "asahi-base.zip")
        if any(receipt["files"][name] != binding for name, binding in bindings.items()):
            raise ValueError("retained image ZIP derivation mismatch")
        actual = image_inventory(directory / "root.img")
        if not pending and actual != load_json(directory / "image-inventory.json", 8 * MIB):
            raise ValueError("image inventory receipt mismatch")
    result = {"status": "retained-bytes-and-repository-signatures-verified", "bytes": total,
            "installation_accepted": False, "hardware_accepted": False}
    if pending:
        result["inventory"] = actual
    return result


def complete_image_metadata(directory):
    """Finish metadata after a failed read, without redownloading/changing inputs."""
    directory = Path(directory)
    result = validate(directory, pending=True)
    receipt_path = directory / "capture.json"
    previous = receipt_path.read_bytes()
    receipt = json.loads(previous)
    prior = directory / "capture-incomplete.json"
    if prior.exists():
        raise ValueError("prior completion receipt already exists")
    write_json(directory / "image-inventory.json", result.pop("inventory"))
    with prior.open("xb") as target:
        os.chmod(prior, 0o600); target.write(previous)
    for name in ["image-inventory.json", "capture-incomplete.json"]:
        path = directory / name
        receipt["files"][name] = {"bytes": path.stat().st_size, "sha256": digest(path)}
    receipt["previous_error"] = receipt.pop("error", None)
    receipt["metadata_completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    receipt["image_authentication"] = "observed-HTTPS-bytes-no-independent-image-signature"
    receipt["status"] = "data-captured-not-installation-accepted"
    replacement = directory / "capture.json.new"
    write_json(replacement, receipt)
    os.replace(replacement, receipt_path)
    return {"status": "retained-image-metadata-completed", "installation_accepted": False,
            "hardware_accepted": False, "previous_error": receipt["previous_error"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    take = sub.add_parser("capture")
    take.add_argument("--output", required=True)
    take.add_argument("--capture-upstream-data", action="store_true", required=True)
    take.add_argument("--capture-image", action="store_true")
    check = sub.add_parser("validate"); check.add_argument("--directory", required=True)
    finish = sub.add_parser("complete-image-metadata"); finish.add_argument("--directory", required=True)
    args = parser.parse_args()
    try:
        if args.command == "capture":
            result = capture(args.output, args.capture_image)
        elif args.command == "complete-image-metadata":
            result = complete_image_metadata(args.directory)
        else:
            result = validate(args.directory)
        print(json.dumps({k:v for k,v in result.items() if k != "files"}, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"status": "refused", "error": type(error).__name__ + ": " + str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
