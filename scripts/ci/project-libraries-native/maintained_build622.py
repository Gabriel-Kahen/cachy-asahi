#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the #622 pairs and test provider replacement on the locked native 341 base."""

import argparse
from contextlib import chdir
import hashlib
import json
import os
from pathlib import Path
import re
from runpy import run_path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build622 as B
from inputs622 import stage_object
from migration622 import HISTORICAL


KERNEL = B.ROOT / "scripts/port/kernel-native-job"
BASE_SHA = "fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25"
INPUTS_SHA = "beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f"
ORIGINAL = {"jbigkit": "2.1-8", "libtiff": "4.7.2-1", "lcms2": "2.19.1-1",
            "libdeflate": "1.26-1", "libjpeg-turbo": "3.2.0-2", "libwebp": "1.6.0-2"}
TOOLS = {"cmake": "4.4.4-1", "cppdap": "1.58.0-3", "jsoncpp": "1.9.8-1",
         "libuv": "1.52.1-2", "rhash": "1.4.6-1"}
PROJECT = {"jbigkit": ("cachy-asahi-jbigkit", "2.2-1.1"), "libtiff": ("cachy-asahi-libtiff", "4.7.2-1.1")}
TIFICC = "usr/bin/tificc"
SONAMES = {"jbigkit": ("libjbig.so.", "libjbig85.so."),
           "libtiff": ("libtiff.so.6", "libtiffxx.so.6")}
MIB = 1 << 20
PKG = SimpleNamespace(**run_path(str(B.ROOT / "scripts/checks/package_checks.py")))


GUARD = """#!/bin/bash
set -euo pipefail
umask 022
export LC_ALL=C
[[ $(id -u) == 0 && $(uname -m) == aarch64 && -f /.dockerenv ]]
test "$(grep -Fxc 'SigLevel = Required' /etc/pacman.conf)" = 1
test "$(grep -Fxc 'LocalFileSigLevel = Required' /etc/pacman.conf)" = 1
test "$(grep -Fxc 'HookDir = /builder-disabled-hooks' /etc/pacman.conf)" = 1
cd /inputs
sha256sum --strict --check --quiet SHA256SUMS
work=$(mktemp -d /tmp/maintained-622.XXXXXXXX)
finish() {
    local status=$?
    trap - EXIT
    if ! gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent; then status=1; fi
    for socket in /etc/pacman.d/gnupg/S.gpg-agent{,.browser,.extra,.ssh}; do
        if [[ -e $socket || -L $socket ]]; then status=1; fi
    done
    rm -rf -- "$work" || status=1
    if [[ $status == 0 ]]; then printf '%s\\n' "${terminal:?}"; fi
    exit "$status"
}
trap finish EXIT

inventory() {
    pacman -Q | sort > "$work/inventory"
    diff -u "$1" "$work/inventory"
    pacman -Dk
    printf 'INVENTORY %s %s\\n' "$2" "$(sha256sum "$work/inventory" | cut -d' ' -f1)"
}
trust_test() {
    [[ $1 =~ ^[A-F0-9]{40}$ ]]
    pacman-key --add TEST-public.gpg
    pacman-key --lsign-key "$1"
}
owns() { test "$(pacman -Qoq "$1")" = "$2"; }
absent() { [[ ! -e $1 && ! -L $1 ]]; }
"""

PROVISION = GUARD + """
inventory base.lock base
trust_test "$1"
shift
while IFS= read -r hook; do
    ln -sf -- /dev/null "/builder-disabled-hooks/$hook"
done < hooks
pacman -U --noconfirm --noscriptlet --ask 4 "$@"
ldconfig
inventory tiff.lock tiff
owns /usr/lib/libjbig.so.2.2 cachy-asahi-jbigkit
absent /usr/lib/libjbig.so.2.1
pacman -T 'jbigkit=2.2' 'libjbig.so=2.2-64' libtiff cmake
cmake --version >/dev/null
cp -- "$work/inventory" /builder-packages.lock
terminal=MAINTAINED_TIFF_BUILDER_PASSED
"""

MIGRATE = GUARD + """
fingerprint=$1
shift
original=("$1" "$2")
project=("$3" "$4")
[[ $# == 4 ]]
consumer_record=/var/lib/pacman/local/lcms2-2.19.1-1
consumer_metadata() {
    (cd "$consumer_record" && sha256sum -- desc files mtree)
}

prove_provider() {
    local role=$1 jbig=$2 tiff=$3 soname=$4 stale=$5
    if [[ $role == project ]]; then
        inventory project.lock "$role"
        pacman -T 'jbigkit=2.2' 'libjbig.so=2.2-64' 'libjbig85.so=2.2-64' \
                  'libtiff=4.7.2' 'libtiff.so=6-64' 'libtiffxx.so=6-64' 'libtiff=4.7.2-1'
        printf 'TIFF_UPSTREAM_ONLY_ALIAS_ACCEPTS_ORIGINAL_PKGREL\\n'
    else
        inventory base.lock "$role"
        pacman -T 'libtiff=4.7.2-1' 'jbigkit=2.1-8'
    fi
    pacman -T libtiff jbigkit lcms2
    pacman -Qk "$jbig" "$tiff" lcms2
    owns "/usr/lib/libjbig.so.$soname" "$jbig"
    owns "/usr/lib/libjbig85.so.$soname" "$jbig"
    owns /usr/lib/libtiff.so.6 "$tiff"
    owns /usr/lib/libtiffxx.so.6 "$tiff"
    owns /usr/bin/tificc lcms2
    absent "/usr/lib/libjbig.so.$stale"
    absent "/usr/lib/libjbig85.so.$stale"
    sha256sum --strict --check --quiet "$role.sha256"
    consumer_metadata > "$work/current-consumer"
    cmp "$work/original-consumer" "$work/current-consumer"

    ldd /usr/bin/tificc > "$work/loader"
    grep -Eq '^[[:space:]]+libtiff[.]so[.]6 => /(usr/)?lib/libtiff[.]so[.]6[[:space:]]' "$work/loader"
    grep -Eq "^[[:space:]]+libjbig[.]so[.]${soname/./[.]} => /(usr/)?lib/libjbig[.]so[.]${soname/./[.]}[[:space:]]" "$work/loader"
    ! grep -Fq 'not found' "$work/loader" || return 1

    gcc -Wall -Wextra -Werror /inputs/roundtrip.c -ltiff -o "$work/roundtrip"
    "$work/roundtrip" "$work/roundtrip.tif"
    tiffinfo "$work/roundtrip.tif" > "$work/roundtrip-info"
    grep -Eq '^  Image Width: 32 Image Length: 4$' "$work/roundtrip-info"
    grep -Fq 'Compression Scheme: ISO JBIG' "$work/roundtrip-info"

    printf 'P6\\n2 2\\n255\\n\\377\\000\\000\\000\\377\\000\\000\\000\\377\\100\\200\\377' > "$work/rgb.ppm"
    ppm2tiff "$work/rgb.ppm" "$work/rgb.tif"
    tificc "$work/rgb.tif" "$work/converted.tif"
    tiffinfo "$work/converted.tif" > "$work/converted-info"
    grep -Eq '^  Image Width: 2 Image Length: 2$' "$work/converted-info"
    rm -- "$work/roundtrip.tif" "$work/rgb.tif" "$work/converted.tif"
    printf 'PROVIDER %s UNCHANGED_TIFICC\\n' "$role"
}

consumer_metadata > "$work/original-consumer"
prove_provider before jbigkit libtiff 2.1 2.2
trust_test "$fingerprint"
pacman -U --noconfirm --noscriptlet --ask 4 "${project[@]}"
ldconfig
prove_provider project cachy-asahi-jbigkit cachy-asahi-libtiff 2.2 2.1
pacman -U --noconfirm --noscriptlet --ask 4 "${original[@]}"
ldconfig
prove_provider restored jbigkit libtiff 2.1 2.2
absent /usr/share/doc/cachy-asahi-jbigkit/source/PKGBUILD
absent /usr/share/cachy-asahi-libtiff/corresponding-source/inventory.json
terminal=MAINTAINED_SIGNED_MIGRATION_PASSED
"""


def digest(body):
    return hashlib.sha256(body).hexdigest()


def lock_bytes(rows):
    return "".join(f"{name} {version}\n" for name, version in sorted(rows.items())).encode()


def inventory(path, count):
    raw = path.read_bytes()
    B.require(0 < len(raw) <= 128 << 10, "bounded installed inventory")
    rows = {}
    for line in raw.decode("ascii").splitlines():
        B.require(re.fullmatch(r"[a-zA-Z0-9@_.+:-]+ [a-zA-Z0-9@_.+:-]+", line), "canonical installed package row")
        name, version = line.split(" ")
        B.require(name not in rows, "duplicate installed package")
        rows[name] = version
    B.require(len(rows) == count and raw == lock_bytes(rows), "exact sorted, unique installed package inventory")
    return rows


def maintained_inventories(prepared):
    base = inventory(prepared.base_lock, 341)
    B.require(B.sha(prepared.base_lock) == BASE_SHA and all(base.get(name) == version for name, version in ORIGINAL.items())
              and not (TOOLS.keys() | {item[0] for item in PROJECT.values()}) & base.keys(),
              "required original 341 and historical provider inventory")
    tiff = inventory(prepared.tiff_lock, 346)
    expected = dict(base)
    del expected["jbigkit"]
    expected.update(dict([PROJECT["jbigkit"]]) | TOOLS)
    B.require(tiff == expected, "346 TIFF builder must replace only JBIG and add five reviewed tools")
    project = dict(base)
    for name, (replacement, version) in PROJECT.items():
        del project[name]
        project[replacement] = version
    return base, tiff, project


def maintained_dependencies(prepared, base):
    lock = prepared.producer_source / "scripts/ci/inputs.lock.json"
    raw = lock.read_bytes()
    B.require(0 < len(raw) <= 2 * MIB and digest(raw) == INPUTS_SHA, "exact original maintained dependency metadata")
    doc = json.loads(raw)
    rows = {row["name"][0]: (row["version"][0], row["depends"]) for row in doc["rootfs_packages"]}
    rows.update({row["name"]: (row["version"], row["depends"]) for row in doc["packages"]})
    B.require({name: version for name, (version, _) in rows.items()} == base,
              "maintained dependency metadata must cover the exact 341")
    relevant = {"jbigkit", "libtiff", "libtiff.so", "libtiffxx.so", "libjbig.so", "libjbig85.so"}
    selected = {}
    for name, (_, dependencies) in rows.items():
        matches = [dep for dep in dependencies if re.split(r"[<>=]", dep, maxsplit=1)[0] in relevant]
        if matches:
            selected[name] = matches
    B.require(selected == {"lcms2": ["libtiff"], "libtiff": ["jbigkit"]},
              "unexpected maintained dependency on the selected provider names")
    return selected


def inspect_build_inventory(archive, rows):
    result = PKG.package(archive)
    B.require(not result["errors"], "passive package fixture")
    installed = [item.rsplit("-", 1) for item in result["metadata"][".BUILDINFO"]["installed"]]
    B.require(all(len(parts) == 2 and parts[1] in ("aarch64", "any") for parts in installed)
              and sorted(parts[0] for parts in installed) == sorted(f"{p}-{v}" for p, v in rows.items()),
              "archive BUILDINFO must match its complete selected build inventory")
    return result["metadata"][".PKGINFO"]


def historical_facts(cache):
    """Read the approved rollback archives before building/migrating the pair."""
    data = {}
    parser = run_path(str(B.ROOT / "scripts/platform/elf_audit.py"))["parse_elf"]
    for name in ("jbigkit", "libtiff", "lcms2"):
        filename = f"{name}-{ORIGINAL[name]}-aarch64.pkg.tar.xz"
        package = cache / filename
        for leaf in (package, cache / (filename + ".sig")):
            expected_bytes, expected_sha = HISTORICAL[leaf.name]
            B.require(not leaf.is_symlink() and leaf.is_file() and leaf.stat().st_size == expected_bytes
                      and B.sha(leaf) == expected_sha, "exact signed maintained rollback/consumer archive")
        with tarfile.open(package, "r:xz") as archive:
            members = {item.name.removeprefix("./"): item for item in archive}
            B.require(len(members) == len(archive.getmembers()) <= 8192, "finite historical package members")

            def read(leaf):
                item = members[leaf]
                B.require(item.isfile() and 0 < item.size <= 8 * MIB, "bounded original archive member")
                with archive.extractfile(item) as stream:
                    return stream.read()

            metadata = PKG.metadata(read(".PKGINFO").decode())
            B.require(metadata["pkgname"] == [name] and metadata["pkgver"] == [ORIGINAL[name]]
                      and metadata["arch"] == ["aarch64"], "historical package identity")
            leaves = (TIFICC,) if name == "lcms2" else tuple(
                "usr/lib/" + soname + ("2.1" if name == "jbigkit" else "") for soname in SONAMES[name])
            selected = {}
            for leaf in leaves:
                member = members[leaf]
                target = leaf
                if member.issym():
                    B.require(re.fullmatch(re.escape(Path(leaf).name) + r"(?:\.[0-9]+)+", member.linkname),
                              "versioned original SONAME alias")
                    target = str(Path(leaf).with_name(member.linkname))
                body = read(target)
                elf = parser(body)
                B.require(elf and elf["classification"] == "aarch64-loadable-elf", "original AArch64 ELF member")
                if name != "lcms2":
                    B.require(elf["soname"] == Path(leaf).name, "exact original library SONAME")
                selected["/" + leaf] = dict(sha256=digest(body), needed=elf["needed"])
            data[name] = dict(filename=filename, metadata=metadata, selected=selected)
    B.require("jbigkit" in data["libtiff"]["metadata"]["depend"]
              and not any(row.startswith(("jbigkit=", "libjbig.so"))
                          for row in data["libtiff"]["metadata"]["depend"])
              and "libjbig.so.2.1" in data["libtiff"]["selected"]["/usr/lib/libtiff.so.6"]["needed"]
              and "libtiff" in data["lcms2"]["metadata"]["depend"]
              and "libtiff.so.6" in data["lcms2"]["selected"]["/usr/bin/tificc"]["needed"],
              "original TIFF/JBIG and unchanged tificc dependency proof")
    return data


def stage_pinned_copy(path, destination):
    B.require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 128 * MIB,
              "bounded ordinary selected package or control")
    shutil.copyfile(path, destination)
    B.require(B.sha(path) == B.sha(destination), "selected package changed during private copy")


def checksums(tree):
    (tree / "SHA256SUMS").write_text("".join(f"{B.sha(path)}  {path.name}\n" for path in sorted(tree.iterdir())))


def readback_inventory(docker, image, lock, role):
    scope = docker.container_args(f"cachy-622-{role}-read-{docker.nonce}")
    observed = docker.call("run", "--rm", *scope, "--pull=never", "--platform", "linux/arm64",
                           "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                           "--read-only", "--memory=512m", "--memory-swap=512m", "--cpus=1",
                           "--pids-limit=32", "--entrypoint", "/bin/bash", image,
                           "-ec", "set -o pipefail; pacman -Q | LC_ALL=C sort", seconds=60).stdout
    B.require(observed == lock.read_bytes() and not list(docker.owned_containers()),
              "independent complete maintained builder inventory readback")


def container_args(docker, tree, role):
    B.require("," not in str(tree) and "\n" not in str(tree), "unambiguous private bind path")
    return [*docker.container_args(f"cachy-622-{role}-{docker.nonce}"), "--pull=never", "--platform", "linux/arm64",
            "--network=none", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=2g",
            "--memory-swap=2g", "--cpus=2", "--user=0:0", "--mount", f"type=bind,src={tree},dst=/inputs,readonly",
            "--entrypoint", "/bin/bash"]


def provision(docker, prepared, base, jbig, scratch):
    tree = scratch / "tiff346"
    tree.mkdir(mode=0o700)
    expected = {f"{name}-{version}-aarch64.pkg.tar.xz" for name, version in TOOLS.items()}
    B.require({path.name for path in prepared.extensions.iterdir()} ==
              expected | {name + ".sig" for name in expected}, "closed five-tool archive/signature namespace")
    hooks = set()
    for filename in sorted(expected):
        path = prepared.extensions / filename
        with tarfile.open(path, "r|xz") as archive:
            for item in archive:
                name = item.name.removeprefix("./")
                if name.startswith(("usr/share/libalpm/hooks/", "etc/pacman.d/hooks/")) and name.endswith(".hook"):
                    B.require(item.isfile() and re.fullmatch(r"[A-Za-z0-9_.@+-]+\.hook", Path(name).name),
                              "ordinary reviewed tools hook filename")
                    hooks.add(Path(name).name)
        for name in (filename, filename + ".sig"):
            stage_pinned_copy(prepared.extensions / name, tree / name)
    (tree / "hooks").write_text("".join(name + "\n" for name in sorted(hooks)))
    stage_pinned_copy(jbig, tree / jbig.name)
    fingerprint, signature = B.sign_test(tree / jbig.name, tree, scratch / "test-key")
    shutil.copyfile(prepared.base_lock, tree / "base.lock")
    shutil.copyfile(prepared.tiff_lock, tree / "tiff.lock")
    (tree / "provision.sh").write_text(PROVISION)
    checksums(tree)
    cid = docker.call("create", *container_args(docker, tree, "tiff346"), base, "/inputs/provision.sh",
                      fingerprint, *(f"/inputs/{name}" for name in [*sorted(expected), jbig.name])).stdout.decode().strip()
    B.require(re.fullmatch(B.CONTAINER_ID, cid), "immutable TIFF layer container ID")
    run = docker.call("start", "--attach", cid, seconds=480)
    (scratch / "tiff346-provision.log").write_bytes(run.stdout + run.stderr)
    row, = list(docker.owned_containers())
    B.require(row["Id"] == cid and row["Image"] == base and row["State"]["Status"] == "exited"
              and row["State"]["ExitCode"] == 0 and run.stdout.splitlines()[-1:] == [b"MAINTAINED_TIFF_BUILDER_PASSED"],
              "maintained TIFF provisioning retired naturally")
    # The parent scope's role key is its existing cleanup slot.
    role = "tiff210"
    image = docker.call("commit", "--change", "USER alarm", "--change", 'CMD ["/bin/bash"]',
                        "--change", f"LABEL {B.ROLE}={role}", cid, docker.tags[role]).stdout.decode().strip()
    docker.check_image(image, role)
    docker.images[role] = image
    docker.remove_container(row)
    readback_inventory(docker, image, prepared.tiff_lock, "tiff346")
    return image, fingerprint, dict(jbig_archive_sha256=B.sha(jbig), jbig_signature_sha256=signature,
                                    inventory_sha256=B.sha(prepared.tiff_lock), official_tools=sorted(TOOLS),
                                    packages=346, private_builder_only=True)


def review_migration_output(raw, base_sha, project_sha):
    lines = raw.splitlines()
    expected = [(b"before", base_sha), (b"project", project_sha), (b"restored", base_sha)]
    inventories = [line for line in lines if line.startswith(b"INVENTORY ")]
    B.require(inventories == [b"INVENTORY " + role + b" " + sha.encode() for role, sha in expected]
              and [line for line in lines if line.startswith(b"PROVIDER ")] ==
                  [b"PROVIDER " + role + b" UNCHANGED_TIFICC" for role, _ in expected]
              and lines.count(b"TIFF JBIG roundtrip passed") == 3
              and lines.count(b"TIFF_UPSTREAM_ONLY_ALIAS_ACCEPTS_ORIGINAL_PKGREL") == 1
              and lines[-1:] == [b"MAINTAINED_SIGNED_MIGRATION_PASSED"],
              "complete signed migration, restoration and unchanged consumer receipt")
    return [sha for _, sha in expected]


def migration(docker, prepared, base, jbig, tiff, report, scratch, original, project, inspection, fingerprint):
    tree = scratch / "migration"
    tree.mkdir(mode=0o700)
    pairs = [original[name]["filename"] for name in ("jbigkit", "libtiff")]
    for name in pairs:
        for leaf in (name, name + ".sig"):
            size, sha = HISTORICAL[leaf]
            stage_object(tree, leaf, dict(bytes=size, sha256=sha), prepared.cache)
    signed = scratch / "tiff346"
    stage_pinned_copy(signed / jbig.name, tree / jbig.name)
    stage_pinned_copy(signed / (jbig.name + ".sig"), tree / (jbig.name + ".sig"))
    stage_pinned_copy(signed / "TEST-public.gpg", tree / "TEST-public.gpg")
    stage_pinned_copy(tiff, tree / tiff.name)
    B.require(B.sha(tree / jbig.name) == inspection["jbigkit"]["archive_sha256"]
              and B.sha(tree / tiff.name) == inspection["libtiff"]["archive_sha256"],
              "migration archives equal the inspected passing pairs")
    tiff_signature = B.sign_archive(tree / tiff.name, tree / "TEST-public.gpg", scratch / "test-key", fingerprint)
    tificc = original["lcms2"]["selected"]["/usr/bin/tificc"]["sha256"]
    before = {path: row["sha256"] for name in ("jbigkit", "libtiff")
              for path, row in original[name]["selected"].items()} | {"/usr/bin/tificc": tificc}
    after = {"/usr/lib/" + soname: row["sha256"] for name in ("jbigkit", "libtiff")
             for soname, row in inspection[name]["libraries"].items()} | {"/usr/bin/tificc": tificc}
    for role, selected in (("before", before), ("project", after), ("restored", before)):
        (tree / f"{role}.sha256").write_text("".join(f"{sha}  {path}\n" for path, sha in sorted(selected.items())))
    shutil.copyfile(prepared.base_lock, tree / "base.lock")
    (tree / "project.lock").write_bytes(lock_bytes(project))
    shutil.copyfile(B.PROJECT / "tiff-jbig-roundtrip.c", tree / "roundtrip.c")
    (tree / "migrate.sh").write_text(MIGRATE)
    checksums(tree)
    try:
        run = docker.call("run", "--rm", *container_args(docker, tree, "maintained-migration"), base,
                          "/inputs/migrate.sh", fingerprint,
                          *(f"/inputs/{name}" for name in [*pairs, jbig.name, tiff.name]), seconds=420)
    except subprocess.CalledProcessError as error:
        body = (error.stdout or b"") + (error.stderr or b"")
        (scratch / "migration.log").write_bytes(body)
        report["migration_failure"] = dict(exit_code=error.returncode, diagnostic_sha256=digest(body))
        raise
    body = run.stdout + run.stderr
    (scratch / "migration.log").write_bytes(body)
    rows = review_migration_output(run.stdout, B.sha(tree / "base.lock"), B.sha(tree / "project.lock"))
    B.require(not list(docker.owned_containers()), "maintained migration container retired")
    return dict(status="PASS", scope="exact maintained341 with lcms2 already installed", inventory_sequence=rows,
                signed_replace_and_restore=True, unchanged_tificc_sha256=tificc, unchanged_tificc_checks=3,
                tiff_jbig_roundtrips=3, tiff_signature_sha256=tiff_signature,
                original_tiff_pkgrel_alias="SATISFIED_BY_UPSTREAM_ONLY_VIRTUAL_PROVIDE", log_sha256=digest(body))


class MaintainedScope(B.DockerScope):
    def call(self, *args, seconds=60):
        # The original maintained producer image is untagged.
        if args[:2] == ("image", "rm") and "--no-prune" not in args:
            args = (*args[:2], "--no-prune", *args[2:])
        return super().call(*args, seconds=seconds)


def runner_env(docker, scratch, commit):
    home = scratch / "home"
    home.mkdir(mode=0o700)
    names = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_ARCH", "RUNNER_OS", "ImageVersion", "ImageOS")
    return dict(PATH="/usr/bin:/bin", HOME=str(home), DOCKER_CONFIG=str(docker.config),
                DOCKER_HOST="unix:///run/docker.sock", DOCKER_BUILDKIT="0", LC_ALL="C", LANG="C.UTF-8",
                GITHUB_SHA=commit, PYTHONDONTWRITEBYTECODE="1",
                **{name: os.environ[name] for name in names if name in os.environ})


def retire(docker, k, baseline, network, env, scratch, base, report):
    cleanup = {"status": "HOLD"}
    report["cleanup"] = cleanup
    if not baseline.ready:
        cleanup["producer"] = {"status": "NOT_STARTED"}
        return None

    failure = None
    try:
        cleanup["scoped"] = docker.retire()
    except Exception as error:
        cleanup["scoped"] = {"status": "HOLD", "error_type": type(error).__name__}
        failure = error
    try:
        runner = k.runtime.Runner(150, env, scratch / "cleanup-logs")
        cleanup["producer"] = k.cleanup_base(network, runner, scratch, base, base is not None, baseline)
        baseline.observe(runner, "after_cleanup")
        B.require(cleanup["producer"]["status"] == "PASS", "same-job maintained producer cleanup")
    except k.runtime.Cancelled:
        cleanup.setdefault("producer", {})["error_type"] = "InterruptedError"
        failure = failure or InterruptedError("maintained producer cleanup interrupted")
    except Exception as error:
        cleanup.setdefault("producer", {})["error_type"] = type(error).__name__
        failure = failure or error
    if failure is None:
        cleanup["status"] = "PASS"
    return failure


def native_run(prepared, args, scratch, report, inputs, base_rows, tiff_rows, project_rows):
    k = B.load(KERNEL / "job.py", "_maintained622_kernel_host")
    docker = MaintainedScope(scratch)
    env = runner_env(docker, scratch, args.reviewed_head)
    docker_pin = B.sha(Path(B.DOCKER))
    host = SimpleNamespace(docker_binary=Path(B.DOCKER), docker_endpoint=env["DOCKER_HOST"],
                           docker_sha256=docker_pin, source_commit=args.reviewed_head,
                           packet_sha256=B.sha(KERNEL / "packet.lock.json"))
    network = k.Docker(host)
    baseline = k.Baseline(host, network, scratch, report.setdefault("daemon_baseline", {}))
    setup = k.runtime.Runner(2200, env, scratch / "producer-logs")
    base = None
    try:
        docker.probe()
        baseline.start(setup)

        def run_producer(argv, *, cwd):
            try:
                with chdir(cwd):
                    return setup.run(argv, timeout=2050, log="maintained-producer.log")
            except k.runtime.Cancelled as error:
                raise InterruptedError("maintained producer interrupted") from error

        report["phase"] = "maintained341-bootstrap"
        candidate = inputs.bootstrap_maintained(prepared, scratch, report, run_producer=run_producer, commit=args.reviewed_head)
        B.require(re.fullmatch(B.IMAGE_ID, candidate) and candidate not in baseline.protected(),
                  "fresh immutable maintained producer image")
        observed = network.image(setup, candidate)
        B.require(observed["architecture"] == "arm64" and observed["os"] == "linux"
                  and not observed["repo_tags"] and not observed["repo_digests"], "owned unreferenced native producer image")
        k.save(scratch / "base-ownership.json", dict(image_id=candidate, daemon=network.daemon, producer_finished=True,
               source_commit=args.reviewed_head, producer_sha256=k.packet.HELPERS["scripts/ci/native_arm.py"][0],
               nonce=baseline.record["nonce"], baseline_identity_sha256=baseline.record["identity_sha256"]))
        base = candidate
        docker.images["maintained341"] = base
        baseline.observe(setup, "before_build_pairs")
        readback_inventory(docker, base, prepared.base_lock, "maintained341")
        report["native_page_size"] = os.sysconf("SC_PAGE_SIZE")
        original = historical_facts(prepared.cache)

        report["phase"] = "maintained-jbig-pair"
        jbig, runs = B.build_pair(docker, "jbigkit", base, prepared.base_lock, scratch, report)
        inspect_build_inventory(jbig, base_rows)
        report["jbigkit"] = dict(archive_sha256=B.sha(jbig), archive_bytes=jbig.stat().st_size, pair="BYTE_IDENTICAL", runs=runs)

        report["phase"] = "private-signed-tiff346"
        try:
            layer, fingerprint, stats = provision(docker, prepared, base, jbig, scratch)
        except subprocess.CalledProcessError as error:
            observed = (error.stdout or b"") + (error.stderr or b"")
            report["tiff346_failure"] = dict(exit_code=error.returncode, diagnostic_sha256=digest(observed))
            raise
        report["tiff346"] = stats | {"signature_policy": "Required"}

        report["phase"] = "maintained-tiff-pair"
        tiff, runs = B.build_pair(docker, "libtiff", layer, prepared.tiff_lock, scratch, report)
        metadata = inspect_build_inventory(tiff, tiff_rows)
        B.require("jbigkit=2.2" in metadata["depend"] and "libtiff=4.7.2" in metadata["provides"],
                  "exact maintained project TIFF dependency metadata")
        report["libtiff"] = dict(archive_sha256=B.sha(tiff), archive_bytes=tiff.stat().st_size, pair="BYTE_IDENTICAL", runs=runs)
        inspection = B.inspect_packages(scratch, jbig, tiff)
        B.require(inspection["jbigkit"]["archive_sha256"] == B.sha(jbig)
                  and inspection["libtiff"]["archive_sha256"] == B.sha(tiff), "passive checks bound to exact passing packages")
        report["passive_inspection"] = inspection

        report["phase"] = "maintained-signed-provider-migration"
        report["migration"] = migration(docker, prepared, base, jbig, tiff, report, scratch, original, project_rows,
                                        inspection, fingerprint)
    except k.runtime.Cancelled as error:
        raise InterruptedError("maintained host verification interrupted") from error
    finally:
        failed = sys.exception()
        cleanup_failed = retire(docker, k, baseline, network, env, scratch, base, report)
        if failed is None and cleanup_failed is not None:
            raise cleanup_failed


def execute(args, scratch, report, inputs):
    try:
        prepared = inputs.prepare_maintained(args, scratch, report)
        B.require(prepared.recipes == scratch / "recipes", "reviewed build recipes must be staged in private scratch")
        base, tiff, project = maintained_inventories(prepared)
        report["maintained_provider_dependencies"] = maintained_dependencies(prepared, base)
        if args.inputs_only:
            inputs.audit_maintained(prepared, scratch, report)
            original = historical_facts(prepared.cache)
            report["historical_tificc_sha256"] = original["lcms2"]["selected"]["/usr/bin/tificc"]["sha256"]
            report.update(status="MAINTAINED_INPUT_PREFLIGHT_PASSED", phase="complete",
                          native_build="NOT RUN", maintained_migration="NOT RUN")
            return
        native_run(prepared, args, scratch, report, inputs, base, tiff, project)
        report.update(status="NATIVE_MAINTAINED_BUILD_PAIRS_AND_SIGNED_MIGRATION_PASSED", phase="complete")
    finally:
        failed = sys.exception()
        gpg_failure = None
        for home in (scratch / "test-key", scratch / "producer/gpg"):
            if home.is_dir():
                try:
                    B.command(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])
                except Exception as error:
                    gpg_failure = gpg_failure or error
        if gpg_failure is not None:
            report.setdefault("cleanup", {})["status"] = "HOLD"
            report["cleanup"]["gpg"] = {"status": "HOLD", "error_type": type(gpg_failure).__name__}
            if failed is None:
                raise gpg_failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inputs-only", action="store_true")
    mode.add_argument("--native", action="store_true")
    cache = parser.add_mutually_exclusive_group(required=True)
    cache.add_argument("--maintained-cache", type=Path)
    cache.add_argument("--retained-cache", type=Path)
    parser.add_argument("--maintained-extension-cache", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path)
    parser.add_argument("--reviewed-head")
    args = parser.parse_args()
    if args.native:
        if not (args.reviewed_head and re.fullmatch(r"[a-f0-9]{40}", args.reviewed_head)):
            parser.error("--native requires --reviewed-head with the full selected commit")
    os.umask(0o077)
    os.environ["DOCKER_BUILDKIT"] = "0"
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
        os.environ.pop(name, None)
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(number, B.stop)
    signal.alarm(100 * 60)
    report = dict(status="HOLD", phase="intake", hardware="NOT RUN", release="NOT ADMITTED")
    try:
        import maintained_inputs622 as inputs

        if args.native:
            report["phase"] = "runner-admission"
            B.qualify_runner(Path(tempfile.gettempdir()))
            B.require(os.environ.get("GITHUB_SHA") == os.environ.get("GITHUB_WORKFLOW_SHA") == args.reviewed_head
                      and B.command(["git", "rev-parse", "HEAD"], cwd=B.ROOT).stdout.decode().strip() == args.reviewed_head,
                      "exact hosted workflow and #622 reviewed checkout")
        with tempfile.TemporaryDirectory(prefix="maintained-native622-") as folder:
            execute(args, Path(folder), report, inputs)
    except Exception as error:
        report.update(status="HOLD", error_type=type(error).__name__)
        if isinstance(error, B.GuardFailure):
            report["reason"] = str(error)
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True), flush=True)
    return int(report["status"] == "HOLD")


if __name__ == "__main__":
    sys.exit(main())
