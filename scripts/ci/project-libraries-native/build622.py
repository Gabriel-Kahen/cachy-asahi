# SPDX-License-Identifier: MIT
"""Build the #622 JBIG/TIFF pairs on one disposable native Actions runner.

The hosted workflow stages the 14 private r12 bodies in a separate SSH
step. Remaining inputs use pinned public routes and the r12 signature seed.

For local data validation, use --inputs-only with --minimal-cache and the
optional --codec-cache and --upstream-dir. The hosted log records a bounded
JSON result. Private scratch and the TEST key are retired at exit.
"""
import argparse
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inputs622 import GuardFailure, PROJECT, ROOT, command, load, prepare_inputs, require, sha

DOCKER = "/usr/bin/docker"
LABEL = "org.cachy-asahi.project-libraries.scope"
ROLE = "org.cachy-asahi.project-libraries.builder"
IMAGE_ID = r"sha256:[0-9a-f]{64}"
CONTAINER_ID = r"[0-9a-f]{64}"
EPOCH = {"jbigkit": "1791585070", "libtiff": "1782568888"}
LIFECYCLE_LOCK_SHA256 = "3293e438f049763a200dbc4016beaae00a778518946d99ef280c40e5af686a4e"
BUILD = ROOT / "scripts/build"
GPG = ["gpg", "--batch", "--no-options", "--no-auto-key-retrieve"]

# Entrypoint runs only inside the owned, offline TIFF provisioning container.
INSTALL = """#!/bin/bash
set -euo pipefail
umask 022
export LC_ALL=C
test -z "$(pacman -Qq jbigkit libtiff cachy-asahi-jbigkit cachy-asahi-libtiff 2>/dev/null || :)"
test "$(grep -Fxc 'SigLevel = Required' /etc/pacman.conf)" = 1
test "$(grep -Fxc 'LocalFileSigLevel = Required' /etc/pacman.conf)" = 1
pacman -Q | sort > /tmp/observed.lock
diff -u /extension/expected206.lock /tmp/observed.lock
while IFS= read -r hook; do
  ln -sf -- /dev/null "/builder-disabled-hooks/$hook"
done < /extension/hooks
pacman-key --add /extension/TEST-public.gpg
pacman-key --lsign-key "$1"
shift
pacman -U --noconfirm --noscriptlet "$@"
ldconfig
pacman -Q | sort > /tmp/observed.lock
diff -u /extension/expected210.lock /tmp/observed.lock
mv -- /tmp/observed.lock /builder-packages.lock
gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent
for socket in /etc/pacman.d/gnupg/S.gpg-agent{,.browser,.extra,.ssh}; do
  test ! -e "$socket" && test ! -L "$socket" || exit 1
done
"""


LIFECYCLE = """#!/bin/bash
set -euo pipefail
umask 022
export LC_ALL=C
test "$(grep -Fxc 'SigLevel = Required' /etc/pacman.conf)" = 1
test "$(grep -Fxc 'LocalFileSigLevel = Required' /etc/pacman.conf)" = 1
inventory() {
  pacman -Q | sort > /tmp/observed.lock
  diff -u "$1" /tmp/observed.lock
}
inventory /extension/expected206.lock
while IFS= read -r hook; do
  ln -sf -- /dev/null "/builder-disabled-hooks/$hook"
done < /extension/hooks
pacman-key --add /extension/TEST-public.gpg
pacman-key --lsign-key "$1"
shift
tiff=${@: -1}
mkdir /tmp/unsigned
unsigned=/tmp/unsigned/${tiff##*/}
cp -- "$tiff" "$unsigned"
if pacman -U --noconfirm --noscriptlet "${@:1:$#-1}" "$unsigned" > /tmp/unsigned.log 2>&1; then
  exit 1
fi
grep -Fq 'missing required signature' /tmp/unsigned.log
inventory /extension/expected206.lock
packages=(cachy-asahi-libtiff cachy-asahi-jbigkit libdeflate libjpeg-turbo libwebp)
check_pair() {
  inventory /extension/expected211.lock
  pacman -Qk "${packages[@]}"
  test "$(pacman -Qoq /usr/lib/libjbig.so.2.2)" = cachy-asahi-jbigkit
  test "$(pacman -Qoq /usr/lib/libjbig85.so.2.2)" = cachy-asahi-jbigkit
  test "$(pacman -Qoq /usr/lib/libtiff.so.6)" = cachy-asahi-libtiff
  test "$(pacman -Qoq /usr/lib/libtiffxx.so.6)" = cachy-asahi-libtiff
  [[ ! -e /usr/lib/libjbig.so.2.1 && ! -L /usr/lib/libjbig.so.2.1 ]]
  ldd /usr/lib/libtiff.so.6 > /tmp/tiff-loader
  grep -Eq '^[[:space:]]+libjbig[.]so[.]2[.]2 => /(usr/)?lib/libjbig[.]so[.]2[.]2[[:space:]]' /tmp/tiff-loader
  gcc -Wall -Wextra -Werror /extension/roundtrip.c -ltiff -o /tmp/roundtrip
  /tmp/roundtrip "$1"
  tiffinfo "$1" > /tmp/tiffinfo
  grep -Eq '^  Image Width: 32 Image Length: 4$' /tmp/tiffinfo
  grep -Fq 'Compression Scheme: ISO JBIG' /tmp/tiffinfo
}
pacman -U --noconfirm --noscriptlet "$@"
ldconfig
check_pair /tmp/first.tif
pacman -Qlq "${packages[@]}" > /tmp/owned
remove_pair() {
  pacman -R --noconfirm --nosave --noscriptlet "${packages[@]}"
  ldconfig
  inventory /extension/expected206.lock
  while IFS= read -r path; do
    case "$path" in
      */) continue ;;
      /usr/*) [[ ! -e "$path" && ! -L "$path" ]] ;;
      *) exit 1 ;;
    esac
  done < /tmp/owned
}
remove_pair
pacman -U --noconfirm --noscriptlet "$@"
ldconfig
check_pair /tmp/reinstalled.tif
remove_pair
gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent
echo NATIVE_SIGNED_LIFECYCLE_PASSED
"""


class DockerScope:
    def __init__(self, scratch):
        self.nonce = uuid.uuid4().hex
        self.config = scratch / "docker-config"
        self.config.mkdir()
        self.tags = {role: f"cachy-project-libraries-{role}:{self.nonce}" for role in ("minimal206", "tiff210")}
        self.names = set()
        self.images = {}
        self.imported = None
        self.forced = 0

    def __call__(self, argv, seconds=60, **options):
        require(argv[0] in ("docker", DOCKER), "scoped Docker command")
        if not options:
            options = {"check": True, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        return subprocess.run([DOCKER, "--config", str(self.config), "--host", "unix:///run/docker.sock",
                               *argv[1:]], timeout=seconds, **options)

    def call(self, *args, seconds=60):
        return self([DOCKER, *args], seconds, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def probe(self):
        socket = Path("/run/docker.sock")
        require(socket == socket.resolve() and socket.is_socket() and socket.stat().st_uid == 0,
                "root-owned local Docker socket")
        info = json.loads(self.call("info", "--format", "{{json .}}").stdout)
        require(info["OSType"] == "linux" and info["Architecture"] in ("aarch64", "arm64")
                and info["MemoryLimit"] is True and info["SwapLimit"] is True and info["PidsLimit"] is True
                and info["CpuCfsQuota"] is True, "qualified native local Docker runtime")

    def tag_args(self, role):
        return ["--label", f"{LABEL}={self.nonce}", "--label", f"{ROLE}={role}"]

    def container_args(self, name):
        require(name not in self.names, "fresh container name")
        self.names.add(name)
        return ["--name", name, "--label", f"{LABEL}={self.nonce}"]

    def image_rows(self, selector):
        ids = self.call("image", "ls", "--all", "--no-trunc", "--quiet", "--filter", selector).stdout.splitlines()
        return [image.decode("ascii") for image in dict.fromkeys(ids)]

    def check_image(self, image, role):
        require(re.fullmatch(IMAGE_ID, image), "immutable builder ID")
        row, = json.loads(self.call("image", "inspect", image).stdout)
        labels = row["Config"]["Labels"]
        require(row["Id"] == image and row["Architecture"] == "arm64" and row["Os"] == "linux"
                and labels.get(LABEL) == self.nonce and labels.get(ROLE) == role
                and (row.get("RepoTags") or []) in ([self.tags[role]], [])
                and not row.get("RepoDigests"), "same scoped ARM64 builder image")
        return row

    def owned_containers(self):
        ids = self.call("container", "ls", "--all", "--no-trunc", "--quiet",
                        "--filter", f"label={LABEL}={self.nonce}").stdout.decode().splitlines()
        for container in ids:
            require(re.fullmatch(CONTAINER_ID, container), "complete scoped container ID")
            row, = json.loads(self.call("container", "inspect", container).stdout)
            require(row["Id"] == container and row["Name"].removeprefix("/") in self.names
                    and row["Config"]["Labels"].get(LABEL) == self.nonce, "same scoped container")
            yield row

    def remove_container(self, row):
        if row["State"]["Running"]:
            self.call("container", "rm", "--force", row["Id"])
            self.forced += 1
        else:
            self.call("container", "rm", row["Id"])

    def build_v2_capture(self, argv, *, text):
        return self(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text).stdout

    def build_v2_run(self, argv, **options):
        if argv[:3] == ["docker", "run", "--rm"] and argv[3] == "--name":
            name, *rest = argv[4:]
            require(re.fullmatch(r"cachy-asahi-[0-9a-f]{16}", name)
                    and "--pull=never" in rest and "--network" in rest
                    and rest[rest.index("--network") + 1] == "none"
                    and rest[-2] in self.images.values(), "fixed offline build_v2 container")
            return self([*argv[:3], *self.container_args(name), "--memory-swap=4g", *rest],
                        options.pop("timeout"), **options)
        require(len(argv) == 4 and argv[:3] == ["docker", "rm", "-f"] and argv[3] in self.names,
                "only own build_v2 timeout cleanup")
        for row in list(self.owned_containers()):
            if row["Name"] == "/" + argv[3]:
                self.remove_container(row)
        return subprocess.CompletedProcess(argv, 0)

    def retire(self):
        for row in list(self.owned_containers()):
            self.remove_container(row)
        require(not list(self.owned_containers()), "owned container census is empty")
        for role in ("tiff210", "minimal206"):
            selector = f"label={LABEL}={self.nonce}"
            tagged = self.image_rows("reference=" + self.tags[role])
            selected = self.image_rows(f"label={ROLE}={role}")
            labelled = [image for image in self.image_rows(selector) if image in selected]
            require(len(labelled) <= 1 and (not tagged or tagged == labelled), "same scoped builder tag")
            for image in labelled:
                require(self.images.get(role, image) == image, "same submitted builder")
                self.check_image(image, role)
                self.call("image", "rm", image)
        require(not self.image_rows(f"label={LABEL}={self.nonce}")
                and not any(self.image_rows("reference=" + tag) for tag in self.tags.values()),
                "owned builder label and tag censuses are empty")
        imported = self.imported.cleanup() if self.imported else None
        require(self.forced == 0, "forced container retirement")
        return {"owned_containers_absent": True, "owned_builders_absent": True, "rootfs": imported,
                "daemon_build_cache": "NOT VERIFIED"}


def bootstrap(docker, native, entry, core, inputs, scratch, lock):
    boot = scratch / "bootstrap"

    def run(argv, log=None, timeout=1800):
        if argv[:2] == ["docker", "build"]:
            entry.prepare_offline_pacman_conf(boot / "context")
            argv = [*argv[:-1], "--quiet", "--no-cache", "--force-rm", "--memory=4g", "--memory-swap=4g",
                    "--tag", docker.tags["minimal206"],
                    *docker.tag_args("minimal206"), argv[-1]]
        if argv[:2] == ["docker", "run"]:
            require(argv[-3] == "--entrypoint=/bin/cat" and argv[-1] == "/builder-packages.lock",
                    "fixed r12 inventory readback")
            docker.check_image(argv[-2], "minimal206")
            argv = [*argv[:2], *docker.container_args("cachy-622-base-read-" + docker.nonce),
                    "--cpus=1", "--memory=512m", "--memory-swap=512m", "--pids-limit=32", *argv[2:]]
        result = docker.call(*argv[1:], seconds=timeout)
        if log:
            log.write_bytes(result.stdout + result.stderr)
        return result.stdout.decode().strip()

    native.run = run
    docker.imported = core.SignedRootfsBootstrap(native, docker, boot, docker.nonce, operation="project-libraries")
    image = native.build(inputs, scratch / "cache", boot, {})
    require(docker.imported.submitted and docker.imported.image is not None, "r12 signed rootfs import")
    require((boot / "packages.lock").read_bytes() == lock.read_bytes(), "independent r12 inventory readback")
    docker.check_image(image, "minimal206")
    docker.images["minimal206"] = image
    return image


def build_pair(docker, name, image, lock, scratch):
    recipe = scratch / "recipes" / name
    builder = load(BUILD / "build_v2.py", "_native622_build_v2")
    builder.subprocess = SimpleNamespace(check_output=docker.build_v2_capture, run=docker.build_v2_run,
                                         STDOUT=subprocess.STDOUT, DEVNULL=subprocess.DEVNULL,
                                         TimeoutExpired=subprocess.TimeoutExpired,
                                         SubprocessError=subprocess.SubprocessError)
    paths = []
    for attempt in (1, 2):
        out = scratch / f"{name}-{attempt}"
        argv = [str(BUILD / "build_v2.py"), str(recipe), "--image", image, "--mode", "native",
                "--network", "none", "--timeout", "900", "--source-date-epoch", EPOCH[name],
                "--expected-packages", str(lock), "--output", str(out),
                "--reviewed-inputs", str(recipe.parent / f"{name}-reviewed-inputs.json")]
        previous = sys.argv
        try:
            sys.argv = argv
            with (scratch / f"{name}-{attempt}-driver.log").open("x") as log:
                with redirect_stdout(log), redirect_stderr(log):
                    status = builder.main()
        finally:
            sys.argv = previous
        require(status == 0 and not list(docker.owned_containers()), f"{name} isolated build {attempt}")
        require(list((out / "artifacts").glob("*-check.log")), f"{name} actual makepkg check phase")
        paths.append(out)
    result = command([sys.executable, "-I", "-B", str(BUILD / "compare_v2.py"),
                      *map(str, paths), "--require-bytes"], timeout=180)
    comparison = json.loads(result.stdout)
    artifact, = comparison["packages"]
    require(comparison["status"] == "contents-reproduced" and
            all(comparison["packages"][artifact].values()), f"{name} byte and metadata identity")
    require(re.fullmatch(rf"cachy-asahi-{name}-[0-9.]+-1\.1-aarch64\.pkg\.tar\.(xz|zst)", artifact),
            f"{name} exact AArch64 package family")
    observations = []
    for output in paths:
        artifacts = output / "artifacts"
        check_log, = artifacts.glob("*-check.log")
        observed_page_size = int((artifacts / "environment.txt").read_text().splitlines()[1])
        require(check_log.stat().st_size > 0 and observed_page_size == os.sysconf("SC_PAGE_SIZE"),
                f"{name} test log and native page-size evidence")
        observations.append({"check_log_sha256": sha(check_log), "build_log_sha256": sha(output / "build.log"),
                             "page_size": observed_page_size})
    return paths[0] / "artifacts" / artifact, observations


def sign_archive(package, public, keyhome, fingerprint):
    signature = package.with_name(package.name + ".sig")
    command([*GPG, "--homedir", str(keyhome), "--pinentry-mode", "loopback", "--passphrase", "",
             "--local-user", fingerprint, "--output", str(signature), "--detach-sign", str(package)])
    verified = command(["gpgv", "--homedir", str(keyhome), "--keyring", str(public), "--status-fd", "1",
                        str(signature), str(package)])
    matches = [line.split()[2] for line in verified.stdout.decode().splitlines()
               if line.startswith("[GNUPG:] VALIDSIG ")]
    require(matches == [fingerprint], "TEST signature over the exact passing archive")
    return sha(signature)


def sign_test(package, extension, keyhome):
    keyhome.mkdir(mode=0o700)
    gpg = [*GPG, "--homedir", str(keyhome)]
    # gpg never receives a project signing key. This throwaway TEST key stays
    # in scratch, and only its public export is mounted in the container.
    uid = "Cachy-Asahi #622 builder TEST"
    command([*gpg, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
             uid, "ed25519", "sign", "1d"])
    listing = command([*gpg, "--with-colons", "--list-secret-keys", uid]).stdout.decode()
    fingerprint, = (row.split(":")[9] for row in listing.splitlines() if row.startswith("fpr:"))
    require(re.fullmatch(r"[A-F0-9]{40}", fingerprint), "ephemeral TEST signer fingerprint")
    public = extension / "TEST-public.gpg"
    command([*gpg, "--output", str(public), "--export", fingerprint])
    return fingerprint, sign_archive(package, public, keyhome, fingerprint)


def extend(docker, base, jbig, lock, scratch, native):
    extension = scratch / "extension"
    shutil.copytree(scratch / "codecs", extension)
    package = extension / jbig.name
    shutil.copyfile(jbig, package)
    require(sha(package) == sha(jbig), "TIFF install member equals the passing JBIG archive")
    fingerprint, signature = sign_test(package, extension, scratch / "test-key")
    codecs = sorted((scratch / "codecs").glob("*.pkg.tar.xz"))
    require(len(codecs) == 3, "three pinned official codec archives")
    hooks = set()
    for codec in codecs:
        with tarfile.open(codec, "r|xz") as archive:
            for item in archive:
                name = item.name.removeprefix("./")
                if name.startswith(("usr/share/libalpm/hooks/", "etc/pacman.d/hooks/")) and name.endswith(".hook"):
                    require(item.isfile(), "ordinary codec package hook")
                    hooks.add(Path(name).name)
    (extension / "hooks").write_text(native.hook_masks(hooks))
    for input_lock in (lock, scratch / "expected210.lock"):
        shutil.copyfile(input_lock, extension / input_lock.name)
    (extension / "install.sh").write_text(INSTALL)
    name = "cachy-622-extend-" + docker.nonce
    scope = docker.container_args(name)
    container = docker.call("create", *scope, "--pull=never", "--platform", "linux/arm64",
                            "--network=none", "--security-opt=no-new-privileges", "--pids-limit=128",
                            "--memory=2g", "--memory-swap=2g", "--cpus=2", "--user=0:0",
                            "--mount", f"type=bind,src={extension},dst=/extension,readonly",
                            base, "/bin/bash", "/extension/install.sh", fingerprint,
                            *(f"/extension/{path.name}" for path in [*codecs, package])).stdout.decode().strip()
    require(re.fullmatch(CONTAINER_ID, container), "immutable TIFF provisioning container ID")
    started = docker.call("start", "--attach", container, seconds=420)
    (scratch / "tiff210-install.log").write_bytes(started.stdout + started.stderr)
    row, = list(docker.owned_containers())
    require(row["Id"] == container and row["Image"] == base and row["State"]["Status"] == "exited"
            and row["State"]["ExitCode"] == 0, "offline Required-signature TIFF provisioning passed")
    role = "tiff210"
    image = docker.call("commit", "--change", "USER alarm", "--change", 'CMD ["/bin/bash"]',
                        "--change", f"LABEL {ROLE}={role}", container, docker.tags[role]).stdout.decode().strip()
    docker.check_image(image, role)
    docker.images[role] = image
    docker.remove_container(row)

    scope = docker.container_args("cachy-622-tiff-read-" + docker.nonce)
    observed = docker.call("run", "--rm", *scope, "--pull=never", "--platform", "linux/arm64",
                           "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                           "--read-only", "--memory=512m", "--memory-swap=512m", "--cpus=1",
                           "--pids-limit=32", "--entrypoint", "/bin/bash", image,
                           "-ec", "set -o pipefail; pacman -Q | LC_ALL=C sort").stdout
    expected = scratch / "expected210.lock"
    require(observed == expected.read_bytes(), "independent TIFF inventory readback")
    return image, {"jbigkit_sha256": sha(jbig), "test_signer": fingerprint, "test_signature_sha256": signature,
                   "inventory_sha256": sha(expected)}


def lifecycle(docker, base, jbig, tiff, scratch, fingerprint):
    extension = scratch / "extension"
    require(sha(extension / jbig.name) == sha(jbig), "lifecycle install member equals the passing JBIG archive")
    package = extension / tiff.name
    shutil.copyfile(tiff, package)
    require(sha(package) == sha(tiff), "lifecycle install member equals the passing TIFF archive")
    signed = sign_archive(package, extension / "TEST-public.gpg", scratch / "test-key", fingerprint)
    inventory = (scratch / "expected210.lock").read_text().splitlines()
    inventory.append("cachy-asahi-libtiff 4.7.2-1.1")
    lock = extension / "expected211.lock"
    lock.write_text("".join(row + "\n" for row in sorted(inventory)))
    require(len(inventory) == 211 and sha(lock) == LIFECYCLE_LOCK_SHA256, "exact signed lifecycle inventory")
    shutil.copyfile(PROJECT / "tiff-jbig-roundtrip.c", extension / "roundtrip.c")
    (extension / "lifecycle.sh").write_text(LIFECYCLE)
    scope = docker.container_args("cachy-622-lifecycle-" + docker.nonce)
    codecs = sorted((scratch / "codecs").glob("*.pkg.tar.xz"))
    result = docker.call("run", "--rm", *scope, "--pull=never", "--platform", "linux/arm64",
                         "--network=none", "--security-opt=no-new-privileges", "--pids-limit=128",
                         "--memory=2g", "--memory-swap=2g", "--cpus=2", "--user=0:0",
                         "--mount", f"type=bind,src={extension},dst=/extension,readonly",
                         "--entrypoint", "/bin/bash", base, "/extension/lifecycle.sh", fingerprint,
                         *(f"/extension/{path.name}" for path in [*codecs, jbig, package]), seconds=360)
    (scratch / "lifecycle.log").write_bytes(result.stdout + result.stderr)
    require(result.stdout.splitlines()[-1:] == [b"NATIVE_SIGNED_LIFECYCLE_PASSED"]
            and not list(docker.owned_containers()), "signed lifecycle and scoped container exit")
    return {"status": "PASSED", "scope": "fresh Minimal206", "restored_packages": 206,
            "installed_packages": 211, "tiff_signature_sha256": signed,
            "installed_inventory_sha256": sha(lock), "unsigned_refusal": True,
            "installed_roundtrips": 2, "removal_and_reinstall": True,
            "old_provider_replacement": "NOT RUN", "log_sha256": sha(scratch / "lifecycle.log")}


def inspect_packages(scratch, jbig, tiff):
    verifier = load(PROJECT / "verify_packages.py", "_native622_verify_packages")
    archives = {"jbigkit": jbig, "libtiff": tiff}
    # Reuse the candidate's checks with Python tar readers on the hosted
    # image, whose preinstalled tools need not include bsdtar.
    with ExitStack() as stack:
        members = {}
        for key, path in archives.items():
            if path.suffix == ".zst":
                raw = scratch / f"{key}.tar"
                with raw.open("xb") as output:
                    subprocess.run(["zstd", "-dc", "--", str(path)], stdout=output,
                                   stderr=subprocess.PIPE, check=True, timeout=30)
            else:
                raw = path
            archive = stack.enter_context(tarfile.open(raw, "r:*"))
            members[path] = (archive, {item.name.removeprefix("./"): item for item in archive})

        def member_bytes(path, name, metadata):
            archive, by_name = members[path]
            item = by_name[name]
            require(item.isfile() and 0 < item.size <= 8 * 2**20 and item.size == metadata["size"],
                    "bounded passive package member")
            with archive.extractfile(item) as stream:
                body = stream.read()
            require(verifier.sha(body) == metadata["sha256"], "passive package member custody")
            return body

        verifier.member_bytes = member_bytes
        return verifier.inspect(archives, scratch / "recipes")


def actor(scratch, args, report):
    docker = None
    try:
        root, inputs, native, entry, core = prepare_inputs(args, scratch, report)
        if args.inputs_only:
            report["status"] = "INPUTS_AUTHENTICATED"
            return
        report["phase"] = "runner"
        scope = DockerScope(scratch)
        scope.probe()
        docker = scope
        report.update(native_page_size=os.sysconf("SC_PAGE_SIZE"), phase="minimal206-builder")
        lock = root / "expected206.lock"
        with (scratch / "rootfs-import.log").open("x") as log, redirect_stdout(log):
            base = bootstrap(docker, native, entry, core, inputs, scratch, lock)
        report["minimal206"].update(image=base, inventory_sha256=sha(lock))
        report["phase"] = "jbigkit-pair"
        jbig, jbig_attempts = build_pair(docker, "jbigkit", base, lock, scratch)
        report["jbigkit"] = {"archive_sha256": sha(jbig), "archive_bytes": jbig.stat().st_size,
                             "pair": "BYTE_IDENTICAL", "runs": jbig_attempts}
        report["phase"] = "signed-tiff-builder"
        tiff_image, signed = extend(docker, base, jbig, lock, scratch, native)
        report["tiff210"] = dict(signed, image=tiff_image, signature_policy="Required")
        report["phase"] = "libtiff-pair"
        tiff, tiff_attempts = build_pair(docker, "libtiff", tiff_image, scratch / "expected210.lock", scratch)
        report["libtiff"] = {"archive_sha256": sha(tiff), "archive_bytes": tiff.stat().st_size,
                             "pair": "BYTE_IDENTICAL", "runs": tiff_attempts}
        report["phase"] = "passive-package-inspection"
        report["passive_inspection"] = inspect_packages(scratch, jbig, tiff)
        report["phase"] = "signed-disposable-lifecycle"
        report["lifecycle"] = lifecycle(docker, base, jbig, tiff, scratch, signed["test_signer"])
        report["phase"] = "cleanup"
        report["status"] = "NATIVE_BUILD_PAIRS_AND_FRESH_LIFECYCLE_PASSED"
    finally:
        try:
            if docker:
                try:
                    report["cleanup"] = docker.retire()
                except Exception:
                    report["cleanup"] = {"status": "HOLD"}
                    raise
        finally:
            for home in (scratch / "bootstrap/gpg", scratch / "test-key"):
                if home.is_dir():
                    command(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])


def qualify_runner(scratch):
    env = os.environ
    require(env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REPOSITORY") == "Gabriel-Kahen/cachy-asahi"
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("RUNNER_ARCH") == "ARM64", "explicit hosted Actions ARM64 execution")
    require(platform.system() == "Linux" and platform.machine() in ("aarch64", "arm64")
            and os.getuid() == os.geteuid() > 0, "native Linux ARM64 unprivileged host")
    memory = Path("/proc/meminfo").read_text()
    available = int(re.search(r"^MemAvailable:\s+(\d+) kB$", memory, re.MULTILINE)[1]) * 1024
    require(available >= 7 * 2**30 and shutil.disk_usage(scratch).free >= 10 * 2**30,
            "disposable runner requires 7 GiB available RAM and 10 GiB free storage")
    for tool in (DOCKER, "zstd", "gpg", "gpgv", "gpgconf", "curl"):
        require(shutil.which(tool), "existing runner prerequisite: " + tool)


def stop(signum, _frame):
    raise InterruptedError(f"interrupted by signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-only", action="store_true", help="authenticate data without running Docker")
    cache = parser.add_mutually_exclusive_group(required=True)
    cache.add_argument("--minimal-cache", type=Path, help="flat r12 object cache")
    cache.add_argument("--retained-cache", type=Path, help="private directory staged by the SSH carrier step")
    parser.add_argument("--codec-cache", type=Path, help="flat official codec cache")
    parser.add_argument("--upstream-dir", type=Path, help="four upstream inputs named by materialization-plan keys")
    parser.add_argument("--export-retained", type=Path, help="new private directory for the 14 retained bodies")
    args = parser.parse_args()
    if args.export_retained and not (args.inputs_only and args.minimal_cache):
        parser.error("--export-retained requires --inputs-only and --minimal-cache")
    os.umask(0o077)
    os.environ["DOCKER_BUILDKIT"] = "0"
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"):
        os.environ.pop(name, None)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGALRM, stop)
    if not args.minimal_cache:
        signal.alarm(78 * 60)
    report = dict(status="HOLD", phase="intake", hardware="NOT RUN", release="NOT ADMITTED")
    try:
        if not args.inputs_only:
            report["phase"] = "runner-admission"
            qualify_runner(Path(tempfile.gettempdir()))
        with tempfile.TemporaryDirectory(prefix="native622-") as directory:
            actor(Path(directory), args, report)
    except Exception as error:
        report.update(status="HOLD", error_type=type(error).__name__)
        if isinstance(error, GuardFailure):
            report["reason"] = str(error)
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True), flush=True)
    return int(report["status"] == "HOLD")


if __name__ == "__main__":
    sys.exit(main())
