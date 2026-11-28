#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the exact retained Asahi629 JBIG/TIFF operands without installing them."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
from runpy import run_path
import stat
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


def pin(size, sha256):
    return {"bytes": size, "sha256": sha256}


def body_pin(body):
    return pin(len(body), hashlib.sha256(body).hexdigest())


COUNT = 629
ALARM_FINGERPRINT = "68B3537F39A313B3E574D06777193F152BDBE6A6"
ALARM_KEY = pin(2228, "9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae")
ALARM_TRANSPORT_KEY = pin(3098, "6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f")
BASELINE = pin(12346, "f335e8430a1d6f8463e95e16524cf78fc224c24fb31cf8717723370490bae9fa")
HISTORICAL_REPLACEMENT = pin(12374, "1e69e2ebe1f1d021fe85a1b0a0f0aaddc8897ff142e7783197419bd8f093b9a6")
# Set only after reviewing the successor archive, provider payloads and projected lock.
# Required keys are provider (package() row), payloads (path-to-pin map), and replacement (lock pin).
QUALIFICATION_TIFF = {
    "provider": {
        "version": "4.7.2-1.2",
        "filename": "cachy-asahi-libtiff-4.7.2-1.2-aarch64.pkg.tar.xz",
        "archive": pin(861952, "f6df34ab9ddd3496407a9dd4707abd44a2270a3abbd3fe6e27862db4dda59e4f"),
        "signature": None,
    },
    "payloads": {
        "usr/lib/libtiff.so.6.3.0": pin(591976, "1c11df5fcd30e0b8ad285083bff41f7d017670e8f6f94750b70147884141ace4"),
        "usr/lib/libtiffxx.so.6.3.0": pin(67592, "6f38e390028607be4d3482ae49ba772ba5eceb78554529ce947e79414838bb73"),
    },
    "replacement": pin(12374, "78ec10f8d52103af3ab41d6460f63848ac525a447d7e8eb2904e4a1a824a57d8"),
}
REPLACEMENT = HISTORICAL_REPLACEMENT if QUALIFICATION_TIFF is None else QUALIFICATION_TIFF["replacement"]
PLATFORM = pin(88933, "b4d84a4eacba5e57264bdaca91b68034e87cbd4d997975c55e1f2da3688218a7")
ASAHI_RESULT = pin(1954, "7acb1874ae50cd41910e3bc420e67afbb63147d93140ed7e482faa52e860987b")
ASAHI_TERMINAL = pin(2092, "d32b162c363160e8a7f36794019cbf94b76ba45dcc91b843583660d450c85435")
ASAHI_STAGE = pin(200263, "11959697e9dd4dcce85d1d7878504c57bf3a74e22b04649b9c2056028deda89a")
ASAHI_SEED = pin(3680501760, "76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db")
ASAHI_PASS = "PASS_DISPOSABLE_ASAHI_629_THREE_VERSION_REVERSE"
ROUNDTRIP_SOURCE = pin(2147, "631664b28853fd1dccd5fdef355cf5626f719147f9b4c781093760c992a47d58")
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}

OFFICIAL = {"jbigkit": "2.1-8", "libtiff": "4.7.2-1"}
PROJECT_TIFF = "cachy-asahi-libtiff"
HISTORICAL_PROJECT = {"cachy-asahi-jbigkit": "2.2-1.1", PROJECT_TIFF: "4.7.2-1.1"}
RETIRING_JBIG = ("libjbig.so.2.1", "libjbig85.so.2.1")
JPEG_PACKAGE = "libjpeg-turbo"
JPEG_PROVIDER_VERSION = "3.2.0-2"
JPEG_DESCRIPTOR = "var/lib/pacman/local/libjpeg-turbo-3.2.0-2/desc"
JPEG_PAYLOAD = "usr/lib/libjpeg.so.8.3.2"
JPEG_PROVIDER_FILES = {
    JPEG_DESCRIPTOR: pin(480, "9b6993129ba972b10606a6c8618d952c5efe84ebe2d0ac7761dd40b4244e015a"),
    JPEG_PAYLOAD: pin(526400, "ac27ab464ab783be9cf059ac16ea577427a7bce10406121eb34c34b2031158b3"),
}


def package(name, version, size, digest, signature=None):
    return dict(version=version, filename=f"{name}-{version}-aarch64.pkg.tar.xz",
                archive=pin(size, digest), signature=pin(566, signature) if signature else None)


HISTORICAL_PROVIDERS = {
    "jbigkit": package("jbigkit", OFFICIAL["jbigkit"], 48816,
                       "ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db",
                       "f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f"),
    "libtiff": package("libtiff", OFFICIAL["libtiff"], 354480,
                       "02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd",
                       "8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa"),
    "cachy-asahi-jbigkit": package("cachy-asahi-jbigkit", HISTORICAL_PROJECT["cachy-asahi-jbigkit"], 143352,
                                  "98636579a9653b64987646ab2066fb0e4d9763ae44d52984c7d4677827a2af97"),
    PROJECT_TIFF: package(PROJECT_TIFF, HISTORICAL_PROJECT[PROJECT_TIFF], 861864,
                                  "085e8293b170ef5fa30febd3f7d4079da69b4b104c0e91733a30640e2e3f8875"),
}
PROVIDERS = HISTORICAL_PROVIDERS if QUALIFICATION_TIFF is None else (
    HISTORICAL_PROVIDERS | {PROJECT_TIFF: QUALIFICATION_TIFF["provider"]})
PROJECT = {name: PROVIDERS[name]["version"] for name in HISTORICAL_PROJECT}
CONSUMER_ARCHIVES = {
    "lcms2": package("lcms2", "2.19.1-1", 205460,
                     "5f93d01820b4e1a463f3cb11e19916bb3761b4faca20d4e1f0854329ba3f46f8",
                     "3e35d43d7cd15dc360e2c250b32610f97330b239ba30d2917d6998c1d337dd5c"),
    "gtk4": package("gtk4", "1:4.24.1-1", 10656560,
                    "a9c34b926a251f4d610ede9bd4f38d61a2097358ba477a743ff72a882f5278d2",
                    "53b25890ae4490dd6a4c04ee9ef24a92b16cf78d31ff8cac77c14c1a5bd996dd"),
    "openjpeg2": package("openjpeg2", "2.5.4-1", 942812,
                         "aa64049214538bcb2830415891af2d494dfdbb1b930b0f251da4f99acf231f47",
                         "239b5b6d9db12968fe298b93dc34b1a18770a92aef917c1c2912fd469c937b18"),
    "spandsp": package("spandsp", "0.0.6-7", 393812,
                       "c3fef8569a60a66dc9605b476a9032031c91fc566a994741836dc622b8bbb7d9",
                       "dad72905341e687d158efff714dc3fe606abe876dcae14a8d5ddfb6435b86084"),
    "pipewire-audio": package("pipewire-audio", "1:1.6.9-1", 1135688,
                             "7c302284562d8f43f2c515a3a3f1f6ae19a353816309b8345991ebc4de526287",
                             "54ceb1d7a7e0cd891e9ef59400e51b624bdf250ca891bd9b08e05e1ffaf1d693"),
}
TIFF_LIBRARY = "usr/lib/libtiff.so.6.3.0"
TIFFXX_LIBRARY = "usr/lib/libtiffxx.so.6.3.0"
TIFFGT = "usr/bin/tiffgt"
HISTORICAL_PROVIDER_FILES = {
    "jbigkit": {
        "usr/lib/libjbig.so.2.1": pin(49776, "a2e8fac677530e375bd369f1e46fb773e95baa88b6995e5687f6dadf3a0e985d"),
        "usr/lib/libjbig85.so.2.1": pin(18280, "7543b356c4604cccb0aa5eff1f5f7ae5cd665853051419f9b280efd6eda2cf40"),
    },
    "libtiff": {
        TIFF_LIBRARY: pin(657488, "4064091c7e7d227a278decfd68198b5248565b70bc4fd6809683b68f4bd8ef9f"),
        TIFFXX_LIBRARY: pin(67568, "7ca32e78dd4d77bd23c533f6c60b123501edbef5f11bdeb69b79264575d52c32"),
        TIFFGT: pin(67800, "c5b6f82a163bd3d2cd107f976ee278c37d9b880100a97117ccd38cd113b4bf91"),
    },
    "cachy-asahi-jbigkit": {
        "usr/lib/libjbig.so.2.2": pin(78608, "6889273144dd76d0e00516a971bac18363e98746dde99a079ae26c2a44d95d6c"),
        "usr/lib/libjbig85.so.2.2": pin(67592, "448c9393e65bd855749d3007d707c9ebf760413e7543cb3aa97378b86bff7479"),
    },
    PROJECT_TIFF: {
        TIFF_LIBRARY: pin(591976, "1c11df5fcd30e0b8ad285083bff41f7d017670e8f6f94750b70147884141ace4"),
        TIFFXX_LIBRARY: pin(67592, "6f38e390028607be4d3482ae49ba772ba5eceb78554529ce947e79414838bb73"),
    },
}
PROVIDER_FILES = HISTORICAL_PROVIDER_FILES if QUALIFICATION_TIFF is None else (
    HISTORICAL_PROVIDER_FILES | {PROJECT_TIFF: QUALIFICATION_TIFF["payloads"]})


def consumer(name, size, digest, imports):
    return dict(package=name, version=CONSUMER_ARCHIVES[name]["version"], pin=pin(size, digest), tiff_imports=imports)


PIPEWIRE = "usr/lib/spa-0.2/bluez5/libspa-codec-bluez5-hfp-msbc.so"
CONSUMERS = {
    "usr/bin/tificc": consumer("lcms2", 67728, "3a37c49bdb26c46f87543d3feff4328823485a19e0f57f3958296ae4bff37a58", 20),
    "usr/bin/gtk4-rendernode-tool":
        consumer("gtk4", 14601456, "8ef075c6ddde9751f2ecd2a3cb08f4c74296275be169e508bb05853c524a85d5", 14),
    "usr/lib/libgtk-4.so.1.2400.1":
        consumer("gtk4", 14797720, "323903a925a86d2a21b51eb0484e94efeca57a7f819cba9a0f82b63fea7167b5", 14),
    "usr/bin/opj_compress":
        consumer("openjpeg2", 133712, "3cb40eaa460b2148504c5d94c3a3477651ee49ca8dfc1c197e5ed922d98403a0", 9),
    "usr/bin/opj_decompress":
        consumer("openjpeg2", 133432, "727f839692fd246e45957ff623d087ea6e1c512c3bc7feeabfa4f65052e61f00", 9),
    "usr/bin/opj_dump":
        consumer("openjpeg2", 133200, "eb2afb0d96ed64bf286d0e6ab2526a5bffbdde0fbd1012a845d2b7408194ab51", 9),
    "usr/lib/libspandsp.so.2.0.0":
        consumer("spandsp", 854016, "71b727385379f5c70aa245de278e9c216aae58cf5b88743b787f1ffb99d115fd", 9),
    PIPEWIRE: consumer("pipewire-audio", 67848, "6f9b1e2d10c0a76b5df4e949405e8307654cae6eab2533c72d671d83cdc0db8d", 0),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


@contextmanager
def opened(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size == expected["bytes"], f"{path}: wrong type or size")
        require(hashlib.file_digest(file, "sha256").hexdigest() == expected["sha256"], f"{path}: SHA-256 mismatch")
        file.seek(0)
        yield file


def read(path, expected):
    with opened(path, expected) as stream:
        data = stream.read(expected["bytes"] + 1)
    require(body_pin(data) == expected, f"{path}: bytes changed after verification")
    return data


def inventory(raw):
    rows = raw.splitlines(keepends=True)
    require(len(rows) == COUNT and rows == sorted(rows)
            and all(re.fullmatch(rb"[a-z0-9_.+@-]+ [A-Za-z0-9_.+:~@-]+\n", row) for row in rows),
            f"Expected {COUNT} canonically sorted package rows")
    result = dict(row.decode("ascii").split() for row in rows)
    require(len(result) == COUNT, "Duplicate inventory name")
    return result


def project(raw, *, historical=False):
    require(body_pin(raw) == BASELINE, "Unexpected rollback lock pin")
    candidates, target = (HISTORICAL_PROJECT, HISTORICAL_REPLACEMENT) if historical else (PROJECT, REPLACEMENT)
    rows = inventory(raw)
    require(all(rows.get(name) == version for name, version in OFFICIAL.items())
            and not rows.keys() & candidates.keys(), "Unexpected installed pair")
    replacement = {name: version for name, version in rows.items() if name not in OFFICIAL} | candidates
    projected = "".join(f"{name} {version}\n" for name, version in sorted(replacement.items())).encode("ascii")
    require(body_pin(projected) == target, "Unexpected projected replacement lock")
    return projected, raw


def run(argv, *fds, timeout=45):
    process = subprocess.run(argv, pass_fds=fds, env=ENV, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=timeout)
    require(process.returncode == 0, f"{argv[0]} refused its input: {process.stderr[:384]!r}")
    return process.stdout


@contextmanager
def memory_file(body):
    fd = os.memfd_create("asahi629-622-audit")
    with os.fdopen(fd, "w+b") as stream:
        stream.write(body)
        stream.flush()
        stream.seek(0)
        yield fd, f"/proc/self/fd/{fd}"


def verify_alarm(body, signature, home):
    with memory_file(body) as (data_fd, data), memory_file(signature) as (sig_fd, sig):
        output = run(["/usr/bin/gpgv", "--homedir", str(home), "--keyring", str(home / "alarm.gpg"),
                      "--status-fd", "1", "--", sig, data], data_fd, sig_fd)
    status = [line.split() for line in output.splitlines()]
    valid = [row for row in status if row[:2] == [b"[GNUPG:]", b"VALIDSIG"]]
    refused = {b"BADSIG", b"ERRSIG", b"EXPSIG", b"EXPKEYSIG", b"REVKEYSIG", b"NO_PUBKEY"}
    fingerprint = ALARM_FINGERPRINT.encode("ascii")
    require(len(valid) == 1 and len(valid[0]) == 12 and valid[0][2] == valid[0][-1] == fingerprint
            and not any(len(row) > 1 and row[1] in refused for row in status), "Unexpected ALARM signature status")
    return body_pin(output)


def alarm_key(stage, manifest, public_key):
    if public_key is not None:
        return read(public_key, ALARM_KEY)
    name = "keys/alarm.gpg"
    require(manifest["files"][name] == ALARM_TRANSPORT_KEY, "Retained ALARM key pin differs")
    lines = read(stage / name, ALARM_TRANSPORT_KEY).splitlines()
    require(lines[:2] == [b"-----BEGIN PGP PUBLIC KEY BLOCK-----", b""]
            and lines[-1] == b"-----END PGP PUBLIC KEY BLOCK-----"
            and re.fullmatch(rb"=[A-Za-z0-9+/]{4}", lines[-2]), "Unexpected ALARM public key armor")
    decoded = base64.b64decode(b"".join(lines[2:-2]), validate=True)
    require(body_pin(decoded) == ALARM_KEY, "Dearmored ALARM public key pin differs")
    return decoded


def selected_members(body, expected, *, forbidden=()):
    members = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode="r|xz") as archive:
        for entry in archive:
            name = entry.name.removeprefix("./")
            require(name not in forbidden, f"Unexpected packaged member: {name}")
            if name not in expected:
                continue
            maximum = expected[name]["bytes"] if expected[name] else 32768
            require(entry.isfile() and name not in members and 0 < entry.size <= maximum,
                    f"Missing unique bounded regular member: {name}")
            members[name] = archive.extractfile(entry).read()
            if expected[name]:
                require(body_pin(members[name]) == expected[name], f"Member digest mismatch: {name}")
    require(members.keys() == expected.keys(), f"Missing archive members: {sorted(expected.keys() - members.keys())}")
    return members


def metadata_values(body, key):
    prefix = key + " = "
    return [line.removeprefix(prefix) for line in body.decode("utf-8").splitlines() if line.startswith(prefix)]


def jpeg_recipe():
    return run_path(str(Path(__file__).with_name("jpeg_recipe.py")))


def jpeg_requirement(metadata, buildinfo, recipe):
    required = {
        "pkgname": PROJECT_TIFF,
        "pkgver": recipe["VERSION"],
        "arch": "aarch64",
    }
    require(all(metadata_values(metadata, key) == [value] for key, value in required.items()),
            "Unexpected JPEG-corrected TIFF package identity")
    dependencies = metadata_values(metadata, "depend")
    require(dependencies.count("libjpeg-turbo") == 1 and dependencies.count(recipe["JPEG_DEPENDENCY"]) == 1,
            "Qualification requires the exact libjpeg.so=8-64 package dependency")
    require(metadata_values(buildinfo, "pkgbuild_sha256sum") == [recipe["PKGBUILD_PIN"]["sha256"]],
            "JPEG-corrected TIFF archive was built from a different recipe")
    return dict(version=recipe["VERSION"], dependency=recipe["JPEG_DEPENDENCY"], recipe=recipe["PKGBUILD_PIN"])


def require_qualified_tiff(path):
    recipe = jpeg_recipe()
    row = PROVIDERS[PROJECT_TIFF]
    require(row["version"] == recipe["VERSION"],
            "Guest qualification awaits an audited pin for the JPEG-corrected TIFF 4.7.2-1.2 archive")
    require(path.name == row["filename"], "Unexpected JPEG-corrected TIFF archive name")
    members = selected_members(read(path, row["archive"]), {".PKGINFO": None, ".BUILDINFO": None})
    return jpeg_requirement(members[".PKGINFO"], members[".BUILDINFO"], recipe)


def jpeg_provider(raw, dependency):
    marker = b"%PROVIDES%\n"
    rows = raw.split(b"\n\n")
    require(b"%NAME%\n" + JPEG_PACKAGE.encode() in rows
            and b"%VERSION%\n" + JPEG_PROVIDER_VERSION.encode() in rows
            and sum(block.startswith(marker) and dependency.encode() in block.splitlines()[1:]
                    for block in rows) == 1, "Asahi629 JPEG provider metadata differs")
    return dict(package=JPEG_PACKAGE, version=JPEG_PROVIDER_VERSION, provides=dependency)


def package_members(path, name, row, members, home, *, forbidden=()):
    require(path.name == row["filename"], f"Unexpected archive name: {path.name}")
    body = read(path, row["archive"])
    status = None
    if row["signature"] is not None:
        signature = read(path.with_name(path.name + ".sig"), row["signature"])
        status = verify_alarm(body, signature, home)
    result = selected_members(body, {".PKGINFO": None, **members}, forbidden=forbidden)
    metadata = result.pop(".PKGINFO")
    for key, value in (("pkgname", name), ("pkgver", row["version"]), ("arch", "aarch64")):
        require(metadata_values(metadata, key) == [value],
                f"Incorrect {key} in {name}")
    return result, status


def elf(body):
    with memory_file(body) as (fd, path):
        raw = run(["/usr/bin/readelf", "-W", "-h", "-d", "--dyn-syms", "--version-info", path], fd)
    text = raw.decode("ascii")
    require(re.search(r"^\s*Machine:\s+AArch64\s*$", text, re.MULTILINE), "Expected an AArch64 ELF")
    return text


def tiff_imports(elf_text):
    needed = set(re.findall(r"\(NEEDED\).*?\[([^]]+)\]", elf_text))
    text = elf_text.split("Version needs section", 1)[-1]
    soname = None
    versions = {}
    # The numeric version index ties each undefined symbol to the supplying SONAME.
    for line in text.splitlines():
        if match := re.search(r"File: (\S+)\s+Cnt:", line):
            soname = match[1]
        elif match := re.search(r"Name: (\S+)\s+Flags: \S+\s+Version: (\d+)", line):
            if soname == "libtiff.so.6":
                versions[match[2]] = match[1]
    imports = [
        (name, version)
        for name, version, index in re.findall(r"\bUND\s+(\S+?)@(\S+) \((\d+)\)", elf_text)
        if index in versions and version == versions[index]
    ]
    return needed, imports


def check_abi(blobs, tiff):
    text = elf(tiff)
    needed, _ = tiff_imports(text)
    require({"libjbig.so.2.2", "libjpeg.so.8"} <= needed and not needed.intersection(RETIRING_JBIG)
            and re.search(r"\(SONAME\).*\[libtiff\.so\.6\]", text), "Unexpected project TIFF linkage")
    exports = set(re.findall(r"^\s*\d+:\s+\w+\s+\d+\s+\S+\s+(?:GLOBAL|WEAK)\s+"
                             r"(?:DEFAULT|PROTECTED)\s+\d+\s+(\S+?)@@?(\S+)$", text, re.MULTILINE))
    checks = {}
    for path, row in CONSUMERS.items():
        needed, imports = tiff_imports(elf(blobs[path]))
        count = row["tiff_imports"]
        require(len(imports) == count and ("libtiff.so.6" in needed) == bool(count)
                and not any(name.startswith(("libjbig.so.", "libjbig85.so.")) for name in needed),
                f"{path}: direct ELF dependency or reference count differs")
        if path == PIPEWIRE:
            require("libspandsp.so.2" in needed, "PipeWire plugin is missing its SpanDSP edge")
        require(set(imports) <= exports and all(name == "LIBTIFF_4.0" for _, name in imports),
                f"{path}: unresolved TIFF imports: {sorted(set(imports) - exports)}")
        checks[path] = dict(package=row["package"], version=row["version"], member=row["pin"],
                            needed=sorted(needed), tiff_imports=[list(ref) for ref in sorted(imports)])
    return checks


def predecessor(result, terminal):
    require(result["status"] == ASAHI_PASS and result["inventory"]["rollback"] == BASELINE
            and result["platform"]["rollback"] == PLATFORM and result["nonce"] == terminal["nonce"]
            and terminal["status"] == "PASS_ASAHI629_OFFLINE_FORWARD_AND_DECLARED_REVERSE_ONLY"
            and terminal["controller_result"]["status"] == ASAHI_PASS
            and terminal["retained_result_files"]["evidence/result.json"] == ASAHI_RESULT
            and terminal["outer_container_absent_twice"] is True and terminal["inputs_reverified_after"] is True,
            "Expected the exact successful, retired Asahi629 rollback")


def prove_seed(seed, members):
    jpeg_desc = None
    with opened(seed, ASAHI_SEED) as image:
        fd = image.fileno()
        for name, expected in members.items():
            raw = run(["/usr/bin/debugfs", "-R", f"cat /{name}", f"/proc/self/fd/{fd}"], fd)
            require(body_pin(raw) == expected, f"Seed payload mismatch: {name}")
            if name == JPEG_DESCRIPTOR:
                jpeg_desc = raw
    return jpeg_desc


def audit(stage, official_cache, project_jbig, project_tiff, rollback_evidence, terminal, seed, public_key=None,
          *, qualification=False):
    lock = read(rollback_evidence / "rollback.lock", BASELINE)
    projected, restored = project(lock, historical=not qualification)
    providers = PROVIDERS if qualification else HISTORICAL_PROVIDERS
    payloads = PROVIDER_FILES if qualification else HISTORICAL_PROVIDER_FILES
    tiff_metadata = require_qualified_tiff(project_tiff) if qualification else None
    predecessor(json.loads(read(rollback_evidence / "result.json", ASAHI_RESULT)),
                json.loads(read(terminal, ASAHI_TERMINAL)))
    manifest = json.loads(read(stage / "manifest.json", ASAHI_STAGE))
    require(manifest["seed"] == ASAHI_SEED, "Retained transport binds a different seed")
    rows = inventory(lock)
    paths = {name: official_cache / PROVIDERS[name]["filename"] for name in OFFICIAL}
    paths.update({"cachy-asahi-jbigkit": project_jbig, "cachy-asahi-libtiff": project_tiff})
    signers, consumers = {}, {}
    with TemporaryDirectory(prefix="asahi629-622-public-") as folder:
        home = Path(folder)
        (home / "alarm.gpg").write_bytes(alarm_key(stage, manifest, public_key))
        for name, path in paths.items():
            members, signers[name] = package_members(
                path, name, providers[name], payloads[name], home,
                forbidden=(TIFFGT,) if name == PROJECT_TIFF else ())
            if name == PROJECT_TIFF:
                project_tiff_body = members[TIFF_LIBRARY]
        for name, spec in CONSUMER_ARCHIVES.items():
            require(rows[name] == spec["version"], f"{name}: wrong exact lock version")
            if name == "lcms2":
                path = official_cache / spec["filename"]
            else:
                member = "forward/" + spec["filename"]
                require(manifest["packages"]["forward"][name] ==
                        dict(archive=member, scope="vendor", signer=ALARM_FINGERPRINT)
                        and manifest["files"][member] == spec["archive"]
                        and manifest["files"][member + ".sig"] == spec["signature"],
                        f"{name}: exact retained transport operand differs")
                path = stage / member
            wanted = {member: row["pin"] for member, row in CONSUMERS.items() if row["package"] == name}
            members, signers[name] = package_members(path, name, spec, wanted, home)
            consumers.update(members)
    require(rows[JPEG_PACKAGE] == JPEG_PROVIDER_VERSION, "Unexpected exact Asahi629 JPEG package")
    jpeg = prove_seed(seed, PROVIDER_FILES["jbigkit"] | PROVIDER_FILES["libtiff"] | JPEG_PROVIDER_FILES |
                      {"usr/bin/tificc": CONSUMERS["usr/bin/tificc"]["pin"]})
    return dict(kind="ASAHI629_JBIG_TIFF_PASSIVE_AUDIT_V1", authority=None, issued_signatures=None,
                baseline=BASELINE, replacement=body_pin(projected), restoration=body_pin(restored),
                platform=PLATFORM, source_transport=ASAHI_STAGE, seed=ASAHI_SEED,
                predecessor=dict(result=ASAHI_RESULT, terminal=ASAHI_TERMINAL), alarm_key=ALARM_KEY,
                provider_archives=providers, provider_payloads=payloads, qualification_tiff_metadata=tiff_metadata,
                consumer_archives=CONSUMER_ARCHIVES, verified_alarm_status=signers,
                retiring_jbig=dict(sonames=RETIRING_JBIG, scope="NAMED_OBJECTS_ONLY", members=sorted(CONSUMERS)),
                jpeg_provider=jpeg_provider(jpeg, jpeg_recipe()["JPEG_DEPENDENCY"]),
                consumers=check_abi(consumers, project_tiff_body),
                package_parity_gap=dict(path=TIFFGT, original=True, candidate=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "official-cache", "project-jbig", "project-tiff", "rollback-evidence",
                 "terminal", "seed"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--public-key", type=Path, help="Pinned dearmored ALARM key. Defaults to the retained transport key.")
    parser.add_argument("--qualification", action="store_true", help="Require the JPEG-corrected qualification archive.")
    try:
        print(json.dumps(audit(**vars(parser.parse_args())), sort_keys=True))
    except (KeyError, OSError, ValueError, lzma.LZMAError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit(f"Asahi629 JBIG/TIFF passive audit refused: {error}")


if __name__ == "__main__":
    main()
