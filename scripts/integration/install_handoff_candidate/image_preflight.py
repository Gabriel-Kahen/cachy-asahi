#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only image admission for the host-x86 install-handoff TEST controller."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import tarfile

RUNTIME = Path(__file__).resolve().parents[2] / "port/supported-composition/ci-runtime"
BASE = "sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae"
DOCKERFILE_SHA = "a12fec52ac579ea00c6a0acd9032a9c4902caa18c894e0b2c682f0daa7f3b816"
INPUT_LOCK_SHA = "9e5ac7bd49ca8dc35c8e8531d5ad1c1464d1719a7c501e2e8ff5836ae61ea152"
BASELINE_SHA = "7bf67c52b08149e012d385d818395b096f7eb0794806d03c025ceae4c855b091"
ADDITIONS = {"mpdecimal": "4.0.1-3", "python": "3.14.9-1"}
MIB = 1024 * 1024
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_.@+:!~-]+\Z")
OCI = "application/vnd.oci.image."
INDEX = OCI + "index.v1+json"
MANIFEST = OCI + "manifest.v1+json"
CONFIG = OCI + "config.v1+json"
LAYER = OCI + "layer.v1.tar+gzip"
DB_DIR = "var/lib/pacman/local"
VERSIONS = "opt/composition-runtime-packages.txt"
PLATFORM = {"architecture": "amd64", "os": "linux"}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def decode(raw):
    def unique(items):
        value = {}
        for key, item in items:
            need(key not in value, "Duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def open_input(path):
    return os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), "rb")


def read(path, cap, expected=None):
    with open_input(path) as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, "Bounded regular input required")
        raw = handle.read(before.st_size + 1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(handle.fileno()))
             == identity(path.lstat()), "Input changed during read")
    need(expected is None or digest(raw) == expected, "Whole input digest differs")
    return raw


def image_json(blobs, pin, size=None):
    need(type(pin) is str and SHA.fullmatch(pin), "An exact OCI SHA-256 digest is required")
    raw = read(blobs / pin[7:], 256 * 1024, pin[7:])
    need(size is None or type(size) is int and len(raw) == size, "OCI descriptor size differs")
    return decode(raw)


def image_objects(blobs, pin):
    manifest_pin = pin
    manifest = image_json(blobs, pin)
    if manifest.get("mediaType") == INDEX:
        members = manifest["manifests"]
        need(manifest["schemaVersion"] == 2 and type(members) is list and len(members) <= 32,
             "Bounded OCI index required")
        selected = [row for row in members if row.get("platform") == PLATFORM]
        need(len(selected) == 1 and selected[0]["mediaType"] == MANIFEST,
             "One Linux amd64 execution manifest required")
        descriptor = selected[0]
        manifest_pin = descriptor["digest"]
        manifest = image_json(blobs, manifest_pin, descriptor["size"])
    need(manifest["schemaVersion"] == 2 and manifest["mediaType"] == MANIFEST, "OCI image manifest required")
    config_role = manifest["config"]
    need(config_role["mediaType"] == CONFIG, "OCI image config required")
    config = image_json(blobs, config_role["digest"], config_role["size"])
    layers = manifest["layers"]
    rootfs = config["rootfs"]
    diffs = rootfs["diff_ids"]
    need(all(config[key] == want for key, want in PLATFORM.items())
         and rootfs["type"] == "layers" and 2 <= len(layers) == len(diffs) <= 6
         and len({row["digest"] for row in layers}) == len(set(diffs)) == len(layers)
         and not config["config"].get("Volumes"), "Linux amd64, bounded distinct layers and no image volumes required")
    return manifest_pin, config_role["digest"], layers, diffs


class LayerHash:
    def __init__(self, stream, cap):
        self.stream = stream
        self.cap = cap
        self.bytes = 0
        self.hash = hashlib.sha256()

    def read(self, size):
        need(0 < size <= 4 * MIB, "Bounded layer read required")
        data = self.stream.read(size)
        self.bytes += len(data)
        need(self.bytes <= self.cap, "Layer is larger than its bound")
        self.hash.update(data)
        return data

    def matches(self, expected):
        return "sha256:" + self.hash.hexdigest() == expected


def package_fields(path, raw):
    # Only the versioned desc pathname and single-value identity fields are used.
    fields = {}
    for part in raw.decode("utf-8").strip().split("\n\n"):
        key, *value = part.splitlines()
        need(key.startswith("%") and key.endswith("%") and key not in fields, "Canonical ALPM desc required")
        fields[key] = value
    name, version = (fields[key] for key in ("%NAME%", "%VERSION%"))
    need(len(name) == len(version) == 1 and TOKEN.fullmatch(name[0]) and TOKEN.fullmatch(version[0])
         and path == f"{DB_DIR}/{name[0]}-{version[0]}/desc", "Exact ALPM desc pathname and identity required")
    return name[0], version[0]


def version_rows(raw):
    pairs = [line.split() for line in raw.decode("ascii").splitlines()]
    rows = dict(pairs)
    need(len(rows) == len(pairs) and all(TOKEN.fullmatch(item) for row in pairs for item in row),
         "Unique runtime inventory rows required")
    return rows


def protected_member(member):
    name = member.name.removeprefix("./").rstrip("/")
    path = PurePosixPath(name)
    need(not path.is_absolute() and ".." not in path.parts and (name in ("", ".") or path.as_posix() == name),
         "Canonical OCI layer member path required")
    parent, _, leaf = name.rpartition("/")

    def ancestors_or_self(path):
        return any(path == role or role.startswith(path + "/") for role in (DB_DIR, VERSIONS))

    if leaf == ".wh..wh..opq":
        need(parent and not ancestors_or_self(parent) and not parent.startswith(DB_DIR + "/"),
             "Image opaque whiteout affects the reviewed inventory")
    elif leaf.startswith(".wh."):
        target = str(PurePosixPath(parent, leaf.removeprefix(".wh.")))
        need(not ancestors_or_self(target) and not target.startswith(DB_DIR + "/"),
             "Image whiteout affects the reviewed inventory")
    if name != VERSIONS and ancestors_or_self(name):
        need(member.isdir(), "Inventory ancestor must be a directory")
    if name.startswith(DB_DIR + "/"):
        need(member.isdir() or member.isfile(), "ALPM inventory symlink or special member")
        if parent == DB_DIR and leaf != "ALPM_DB_VERSION":
            need(member.isdir(), "ALPM package directory required")
    return name


def layer_inventory(blobs, layer, diff):
    pin, size = layer["digest"], layer["size"]
    need(layer["mediaType"] == LAYER and SHA.fullmatch(pin) and SHA.fullmatch(diff)
         and type(size) is int and 0 < size <= 192 * MIB, "Bounded gzip layer required")
    path = blobs / pin[7:]
    installed, declared = {}, None
    with open_input(path) as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size == size, "Layer extent differs")
        compressed = LayerHash(handle, size)
        with gzip.GzipFile(fileobj=compressed) as expanded:
            plain = LayerHash(expanded, 768 * MIB)
            with tarfile.open(fileobj=plain, mode="r|") as archive:
                for member in archive:
                    name = protected_member(member)
                    if name != VERSIONS and not (name.startswith(DB_DIR + "/") and name.endswith("/desc")):
                        continue
                    need(member.isfile() and 0 < member.size <= 64 * 1024, "Bounded regular inventory member required")
                    with archive.extractfile(member) as source:
                        content = source.read()
                    if name == VERSIONS:
                        need(declared is None, "Repeated runtime inventory manifest")
                        declared = version_rows(content)
                    else:
                        package, version = package_fields(name, content)
                        need(package not in installed, "Repeated ALPM package in one layer")
                        installed[package] = version
            while plain.read(MIB):
                pass
        need(compressed.bytes == size and compressed.matches(pin) and plain.matches(diff)
             and identity(before) == identity(os.fstat(handle.fileno())) == identity(path.lstat()),
             "Whole compressed and uncompressed layer digest required")
    return installed, declared


def inventory(blobs, layers, diffs):
    installed, declared = {}, None
    for layer, diff in zip(layers, diffs, strict=True):
        rows, snapshot = layer_inventory(blobs, layer, diff)
        need(not (installed.keys() & rows.keys()), "Rebuild may only add packages to the pinned base")
        installed.update(rows)
        if snapshot is not None:
            need(declared is None, "Repeated runtime inventory manifest")
            declared = snapshot
    return installed, declared


def selected_context(context_file, daemon_file):
    raw_context, raw_daemon = read(context_file, MIB), read(daemon_file, MIB)
    contexts, daemon = decode(raw_context), decode(raw_daemon)
    need(type(contexts) is list and len(contexts) == 1, "One selected Docker context required")
    context = contexts[0]
    name = context["Name"]
    endpoint = context["Endpoints"]["docker"]["Host"]
    socket_path = endpoint.removeprefix("unix://")
    socket = PurePosixPath(socket_path)
    need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name)
         and re.fullmatch(r"unix:///[A-Za-z0-9_./-]+", endpoint)
         and socket.parts[0] == "/" and socket.as_posix() == socket_path and ".." not in socket.parts,
         "An ordinary local Unix Docker context is required")
    need(daemon["ClientInfo"]["Context"] == name and daemon["OSType"] == "linux"
         and daemon["Architecture"] == "x86_64" and "name=rootless" in daemon["SecurityOptions"],
         "The same selected rootless Linux x86_64 daemon is required")
    return dict(context=name, endpoint=endpoint, context_sha256=digest(raw_context), daemon_sha256=digest(raw_daemon))


def observe_image(path, pin, diffs):
    raw = read(path, MIB)
    rows = decode(raw)
    need(type(rows) is list and len(rows) == 1, "One image inspection required")
    row = rows[0]
    need(row["Id"] == pin and row["Os"] == "linux" and row["Architecture"] == "amd64"
         and row["RootFS"] == {"Type": "layers", "Layers": diffs} and not row["Config"].get("Volumes"),
         "Image inspection must match the exact Linux amd64 OCI rootfs and volume policy")
    return digest(raw)


def validate_context(context):
    """Check the same staged source roles as the maintained composition builder."""
    need(context.is_dir() and not context.is_symlink() and {p.name for p in context.iterdir()} == {"inputs", "inputs.lock"},
         "Exact offline composition context required")
    role_dir = context / "inputs"
    need(role_dir.is_dir() and not role_dir.is_symlink(), "Ordinary context input directory required")
    lock = read(context / "inputs.lock", 16 * 1024, INPUT_LOCK_SHA)
    need(read(RUNTIME / "inputs.lock", 16 * 1024, INPUT_LOCK_SHA) == lock, "Maintained and staged locks differ")
    read(RUNTIME / "Dockerfile", 16 * 1024, DOCKERFILE_SHA)
    acquire = runpy.run_path(str(RUNTIME / "acquire.py"))
    rows = acquire["load_lock"](raw=lock)
    need({p.name for p in role_dir.iterdir()} == set(rows), "Exactly the five pinned source files are required")
    files = {name: read(role_dir / name, row["bytes"], row["sha256"]) for name, row in rows.items()}
    signatures = acquire["database"](rows, files["core.db"])
    need(all(files[name] == body for name, body in signatures.items()), "Detached signature packets differ from the pinned DB")
    return dict(dockerfile_sha256=DOCKERFILE_SHA, input_lock_sha256=INPUT_LOCK_SHA,
                source_files={name: {key: row[key] for key in ("bytes", "sha256")} for name, row in rows.items()},
                signatures="REQUIRED_TRUSTED_PACKAGE_VERIFICATION_IN_OFFLINE_BUILD")


def rebuild_plan(blobs, context, daemon, base_inspect):
    source = validate_context(context)
    manifest, _, layers, diffs = image_objects(blobs, BASE)
    inspect_pin = observe_image(base_inspect, BASE, diffs)
    base, snapshot = inventory(blobs, layers, diffs)
    need(len(base) == 137 and snapshot is None and not (base.keys() & ADDITIONS.keys())
         and digest(encode(base | ADDITIONS)) == BASELINE_SHA,
         "Pinned base and exact package additions must derive the accepted 139-package inventory")
    return dict(status="PASS_INSTALL_HANDOFF_X86_REBUILD_INPUTS_DATA_ONLY", base_image=BASE,
                base_manifest=manifest, base_inspect_sha256=inspect_pin, daemon=daemon, source=source,
                docker_build=["docker", "--context", daemon["context"], "build", "--pull=false", "--network=none",
                              "--file", str(RUNTIME / "Dockerfile"), str(context.resolve())],
                inventory={"count": 139, "sha256": BASELINE_SHA}, authority=None, installation="NOT RUN")


def image_check(blobs, image, inspect, daemon):
    manifest, config, layers, diffs = image_objects(blobs, image)
    _, _, base_layers, base_diffs = image_objects(blobs, BASE)
    need(len(layers) > len(base_layers) and layers[:len(base_layers)] == base_layers
         and diffs[:len(base_diffs)] == base_diffs, "Exact pinned base layers required in the selected image")
    inspect_pin = observe_image(inspect, image, diffs)
    installed, declared = inventory(blobs, layers, diffs)
    need(installed == declared and len(installed) == 139 and digest(encode(installed)) == BASELINE_SHA,
         "Image must contain the exact accepted ALPM and 139-package runtime inventories")
    return dict(status="PASS_INSTALL_HANDOFF_X86_IMAGE_PREFLIGHT_DATA_ONLY", image=image, manifest=manifest, config=config,
                layers=[row["digest"] for row in layers], diff_ids=diffs, base_image=BASE, daemon=daemon,
                image_inspect_sha256=inspect_pin, inventory={"count": 139, "sha256": BASELINE_SHA},
                authority=None, installation="NOT RUN")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    build = modes.add_parser("rebuild-plan")
    build.add_argument("--context", type=Path, required=True, help="retained offline composition build context")
    image = modes.add_parser("image-check")
    image.add_argument("--image-id", required=True, help="whole immutable daemon image ID")
    for mode in (build, image):
        mode.add_argument("--blobs", type=Path, required=True, help="ordinary OCI sha256 blobs directory")
        mode.add_argument("--context-inspect", type=Path, required=True)
        mode.add_argument("--daemon-info", type=Path, required=True)
        mode.add_argument("--image-inspect", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        need(args.blobs.is_dir() and not args.blobs.is_symlink(), "Ordinary OCI blobs directory required")
        daemon = selected_context(args.context_inspect, args.daemon_info)
        result = (rebuild_plan(args.blobs, args.context, daemon, args.image_inspect) if args.mode == "rebuild-plan"
                  else image_check(args.blobs, args.image_id, args.image_inspect, daemon))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError) as error:
        parser.exit(1, f"Image preflight refused: {error}\n")
    print(encode(result).decode(), end="")


if __name__ == "__main__":
    main()
