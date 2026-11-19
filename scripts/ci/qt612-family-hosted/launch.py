# SPDX-License-Identifier: MIT
"""Compose the retained native349 runtime and the first Qt hosted stage."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from types import ModuleType

import capacity
import executor
import evidence

need = executor.need
R128_MAP_SHA256 = "42bffdd05941787940bbc5a459cb4ce66cf26b0b01b6e5ebdb96e3d1b2e9d473"
R128_READER_SHA256 = "c9db2bc79af4e2bd8c9cb02ab07c33f8fa4417deda35b5a7f704e33eadb18b1f"
FILE_TRANSFER_SECONDS = 240
SIGNED_BOOTSTRAP_SECONDS = 2700
COMPONENT_SECONDS = 18000
CLEANUP_SECONDS = 90
OWNER_WORK_SECONDS = FILE_TRANSFER_SECONDS + SIGNED_BOOTSTRAP_SECONDS + COMPONENT_SECONDS
CONTROLLER_SCOPE_SECONDS = OWNER_WORK_SECONDS + CLEANUP_SECONDS


def load_retained_runtime(source_root):
    """Select only the complete R128 controller and signed349 program bodies."""
    root = Path(source_root)
    owner = root/"scripts/ci/llhttp-reference-native-source/owner"
    reader = owner/"data.py"
    need(root.is_absolute() and root == root.resolve(strict=True) and reader == reader.resolve(strict=True)
         and reader.stat().st_size < 65536
         and hashlib.sha256(reader.read_bytes()).hexdigest() == R128_READER_SHA256,
         "Exact independently selected R128 whole-source reader required")
    data = executor.load(reader, "qt612_hosted_r128_source_reader")
    data.source(root, R128_MAP_SHA256)
    controller = executor.load(owner/"hosted_owner.py", "qt612_hosted_r128_controller")
    base = root/"held-source"/data.BASE_PREFIX
    entry_path = base/"entry.py"
    entry = ModuleType("qt612_hosted_r128_entry")
    entry.__file__ = str(entry_path)
    projected = controller.N.project_entry(data.projected_entry(data.read(entry_path)).encode())
    exec(compile(projected, str(entry_path), "exec"), entry.__dict__)
    runtime = base/"runtime"
    return dict(controller=controller, policy=data.decode(data.read(owner/"policy.json")),
                entry=entry, carrier=controller.N,
                rootfs=executor.load(base/"rootfs_bootstrap_core.py", "qt612_hosted_r128_rootfs"),
                native=executor.load(runtime/"scripts/ci/native_arm.py", "qt612_hosted_r128_native"),
                container_runtime=executor.load(runtime/"reference_controller.py", "qt612_hosted_r128_container"),
                owned_process=executor.load(runtime/"owned_process.py", "qt612_hosted_r128_owned_process"))


def first_stage_controller(retained, runtime_root, output, nonce, uid, gid):
    """Bind the verified controller to one finite longer first-stage lifetime."""
    module = retained["controller"]
    previous = retained["policy"]
    need((previous["pair_seconds"], previous["controller_work_seconds"], previous["controller_scope_seconds"],
          previous["cleanup_seconds"]) == (1200, 1650, 1740, CLEANUP_SECONDS),
         "Exact retained host scope before the first-stage duration projection")
    policy = dict(previous, pair_seconds=OWNER_WORK_SECONDS, controller_work_seconds=OWNER_WORK_SECONDS,
                  controller_scope_seconds=CONTROLLER_SCOPE_SECONDS)
    units = {"--unit="+module.D.unit(nonce, kind) for kind in ("owner","daemon")}
    before = "--property=RuntimeMaxSec=1290s"
    after = f"--property=RuntimeMaxSec={CONTROLLER_SCOPE_SECONDS}s"

    class Controller(module.Controller):
        def run(self, argv, *args, **kwargs):
            if Path(argv[0]).name == "systemd-run":
                need(len(units.intersection(argv)) == 1 and argv.count(before) == 1 and after not in argv,
                     "Only one current owner or daemon service duration may change")
                projected = [after if token == before else token for token in argv]
                need([before if token == after else token for token in projected] == argv,
                     "Whole retained host service argv outside duration")
                argv = projected
            return super().run(argv, *args, **kwargs)

    return Controller(Path(runtime_root), Path(output), policy, nonce, uid, gid)


def expose_readonly_tree(root):
    need(root.is_dir() and not root.is_symlink(), "Verified copied public inputs required")
    for index, (path, _, _) in enumerate(os.walk(root, topdown=False, followlinks=False), 1):
        entry = Path(path)
        info = entry.lstat()
        need(index <= 512 and info.st_uid == 0 and (info.st_mode & 0o777) == 0o700,
             "Only fresh Root-owned public Source directories are exposed")
        entry.chmod(0o555)


def reserve_and_bind(controller, runner_inputs, transfer, *, selection_sha256, logical_bytes, stage):
    """Enter the exact owned controller, then acquire and bind inside its volume."""
    need(os.getuid() == os.geteuid() == 0, "Root-owned native controller required")
    output, policy = Path(controller.out), controller.policy
    need(policy["minimum_disk_bytes"] == capacity.MINIMUM_BYTES
         and policy["storage_bytes"] == capacity.STORAGE_BYTES
         and policy["host_reserve_bytes"] == capacity.RESERVE_BYTES
         and policy["minimum_available_bytes"] == 10 * capacity.GIB,
         "Unchanged native hosted memory, disk reservation and reserve required")
    evidence = {}
    original_run = controller.run
    image = output/"storage.img"
    stage("STORAGE_FRESHNESS")
    fresh = capacity.require_before(output)

    def observe_allocation(argv, *args, **kwargs):
        if Path(argv[0]).name != "fallocate":
            return original_run(argv, *args, **kwargs)
        stage("STORAGE_ALLOCATION_ADMISSION")
        need(not evidence and argv == [controller.tool("fallocate"), "--length",
             str(capacity.STORAGE_BYTES), "--", str(image)],
             "One exact naturally supervised storage allocation")
        # Inherited setup's O_EXCL open has just created its empty private file.
        current = capacity.observe(output)
        before = image.lstat()
        need(all(current[key] == fresh[key] for key in ("path", "device", "inode", "mount"))
             and not current["readonly"] and current["free_bytes"] >= capacity.MINIMUM_BYTES
             and stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
             and before.st_uid == 0 and before.st_dev == current["device"]
             and before.st_nlink == 1 and before.st_size == 0 and before.st_blocks == 0,
             "Same verified filesystem and exact fresh private allocation file")
        evidence["before"] = current
        stage("STORAGE_ALLOCATION")
        result = original_run(argv, *args, **kwargs)
        stage("STORAGE_ALLOCATION_READBACK")
        after = capacity.require_after(output, current)
        found = image.lstat()
        need((before.st_dev,before.st_ino) == (found.st_dev,found.st_ino), "Same allocation file after reservation")
        evidence["after"] = after
        stage("OWNED_HOST_SETUP")
        return result

    controller.run = observe_allocation
    try:
        stage("OWNED_HOST_SETUP")
        daemon, memory, disk = controller.setup()
    finally:
        controller.run = original_run
    stage("OWNED_VOLUME_JOIN")
    owned = capacity.require_transfer_volume(output, evidence["after"], logical_bytes)
    layout = output/"volume"
    work = layout/"work"
    identity = owned["volume"]
    # The transfer owner receives only these in-volume destinations. The
    # separately admitted transport must retire its credential and temp store.
    portable, acquired = work/"portable", work/"acquired"
    operands, framework = acquired/"operands", acquired/"framework"
    need(all(not os.path.lexists(path) for path in (portable, acquired)),
         "Fresh bulk transfer destinations on the loop")
    with runner_inputs.owned_workspace(layout, identity["device"], identity["inode"], identity["mount"]):
        stage("INPUT_ACQUISITION")
        acquisition = transfer(owned_workspace=layout, device=identity["device"], inode=identity["inode"],
                               mount_id=identity["mount"], portable=portable, output=acquired)
        need(acquisition["status"] == "ACQUIRED_QT_RUNNER_INPUT_BYTES_ONLY"
             and acquisition["selection_sha256"] == selection_sha256
             and acquisition["GPG"] == "NOT_RUN" and acquisition["Root_acceptance"] is None,
             "Complete scoped acquisition byte receipt required")
        stage("INPUT_BINDING")
        receipt = runner_inputs.bind_inputs(portable, selection_sha256, operands, framework, work/"bound", layout)
    need(receipt["status"] == "BOUND_RUNNER_SOURCE_DATA_ONLY" and receipt["base_roles"] == 517
         and receipt["packages"] == 7 and receipt["GPG"] == "NOT_RUN",
         "Exact selected 517 and seven dependency input bindings required")
    stage("INPUT_EXPOSURE")
    bound = work/"bound"
    source = bound/"Source-DATA"
    for public in (source, operands, acquired/"trust"):
        expose_readonly_tree(public)
    acquired.chmod(0o711)
    bound.chmod(0o711)
    return dict(daemon=daemon, work=work, bound=work/"bound", operands=operands, acquisition=acquisition,
                input_test_certificate=acquired/"trust/md4c-r128-TEST-public.gpg",
                source=source, input_receipt=receipt, storage=evidence,
                transfer_budget=owned, empty_inner_bytes=disk, admitted_memory_bytes=memory)


EPOCH_PACKAGE = re.compile(
    r"[a-z0-9][a-z0-9._+@-]*-(?:0|[1-9][0-9]*):[A-Za-z0-9._+~]+"
    r"-[1-9][0-9]*(?:\.[0-9]+)*-(?:aarch64|any)\.pkg\.tar\.xz(?:\.sig)?"
)


def cache_roster(M, provider):
    refs = {}
    for group in ("base_materials", "supplemental_materials", "keyring_materials"):
        records = provider[group]
        for name, ref in records.items():
            need(name not in refs and Path(name).name == name and Path(ref["path"]).name == name,
                 "Unique exact flat baseline cache leaf required")
            if ":" in name:
                counterpart = name.removesuffix(".sig") if name.endswith(".sig") else name+".sig"
                need(group != "keyring_materials" and len(name) <= 255 and EPOCH_PACKAGE.fullmatch(name)
                     and counterpart in records, "Exact paired epoch-bearing ALPM cache leaf required")
            else:
                M.member(name)
            refs[name] = ref
    need(len(refs) == 517, "Complete signed349 cache required")
    return refs


def cache_epoch_package(M, writer, name, ref, observed):
    # The provider already authenticated this archive/signature slot. Keep this
    # flat ALPM name out of the generic relative Source member grammar.
    need(len(name) <= 255 and EPOCH_PACKAGE.fullmatch(name) and Path(ref["path"]).name == name,
         "Exact flat epoch-bearing package output required")
    writer.check()
    path = writer.root/name
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=writer.directory(writer.root))
    with os.fdopen(fd, "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        M.stream(Path(ref["path"]), {key:ref[key] for key in ("bytes", "sha256")}, observed,
                 cap=2*capacity.GIB, target=output)
        output.flush()
        info = os.fstat(output.fileno())
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and M.identity(info) == M.identity(path.lstat()), "Same private epoch cache output")
        writer.files[path] = M.identity(info)
    writer.check()


def base_cache(M, provider, path):
    """Materialize the independently authenticated flat cache in the owned loop."""
    refs = cache_roster(M, provider)
    writer = M.Writer(path)
    observed = {}
    try:
        for name, ref in sorted(refs.items()):
            if ":" in name:
                cache_epoch_package(M, writer, name, ref, observed)
            else:
                writer.put(name, source=Path(ref["path"]), expected={k:ref[k] for k in ("bytes", "sha256")},
                           observed=observed, cap=2*capacity.GIB, mode=0o600)
        M.unchanged(observed)
    finally:
        writer.close()
    return refs

def scoped_runner(commands, socket):
    """Give the exact inherited bootstrap only its selected local daemon."""
    endpoint, identity = executor.private_socket(str(socket))

    def run(argv, seconds=60, check=True, env=None):
        if argv[0] == executor.DOCKER:
            need(executor.private_socket(str(endpoint))[1] == identity,
                 "Same observed private socket for signed image transaction")
            argv = [argv[0], "--host=unix://" + str(endpoint), *argv[1:]]
        return commands(argv, seconds, check=check, env={"DOCKER_BUILDKIT": "0", **(env or {})})

    return run


class SignedBase:
    """Use the exact retained R128 bootstrap callbacks and source operands."""

    def __init__(self, *, pipeline, entry, carrier, rootfs, native, container_runtime,
                 runner, source, source_map_sha256, output, nonce):
        self.C = pipeline.C
        self.entry, self.carrier, self.rootfs, self.native = entry, carrier, rootfs, native
        self.runtime, self.runner, self.nonce = container_runtime, runner, nonce
        self.source, self.source_map_sha256, self.output = source, source_map_sha256, output
        self.scopes = []
        self.imported = self.image = None
        self.tag = None

    def construct(self, stage=lambda _: None):
        stage("SIGNED349_PROVIDER")
        C, M = self.C, self.C.M
        source = M.ordinary(self.source)
        mapping = C.read_source(source, self.source_map_sha256)
        selected = mapping["files"]["family-inputs.DATA.json"]
        observed = {}
        data = M.load(source/"family-inputs.DATA.json", {k:selected[k] for k in ("bytes", "sha256")}, observed)
        dep = C.P.selected(C.PARENT/"dependency-candidates.lock.json", C.P.DEPENDENCIES, observed)
        C.P.validate_base_provider(data["base_provider"], dep, observed)
        provider = M.decode(C.P.reference(data["base_provider"], observed, collect=True))
        lock = C.P.reference(provider["base_lock"], observed, collect=True)
        inventory = C.P.reference(provider["baseline_inventory"], observed, collect=True)
        M.unchanged(observed)

        stage("SIGNED349_CACHE")
        work = M.ordinary(self.output)
        need(work.name == "llhttp-reference-native" and work.parent.name == "work"
             and not work.exists(), "Fresh private inherited baseline transaction output required")
        work.mkdir(mode=0o700)
        out, cache = work/"bootstrap", work/"cache"
        out.mkdir(mode=0o700)
        if capacity.observe(work)["free_bytes"] < sum(
                p["bytes"] for group in ("base_materials", "supplemental_materials", "keyring_materials")
                for p in provider[group].values()):
            raise ValueError("Insufficient loop space for temporary signed349 bootstrap materials")
        refs = base_cache(M, provider, cache)
        stage("SIGNED349_INPUTS")
        lock_path = out/"inputs.lock.json"
        with lock_path.open("xb") as f:
            f.write(lock)
        native = self.native
        inputs, extension = self.carrier.extend_bootstrap_inputs(M.decode(lock), lock_path, inventory)

        def fetch(item, cache_path):
            name = item["filename"]
            ref = refs.get(name)
            need(cache_path == cache and ref is not None
                 and (item["size"], item["sha256"]) == (ref["bytes"], ref["sha256"]),
                 "Complete selected offline native input required")
            path = cache_path/name
            M.stream(path, {k:ref[k] for k in ("bytes", "sha256")}, {}, cap=2*capacity.GIB)
            return path

        stage("SIGNED349_AUDIT")
        native.fetch = fetch
        self.entry.C.audit_adapter(native, self.entry.C.read(Path(native.__file__)))
        def build_run(argv, *args, **kwargs):
            if argv[:3] == [executor.DOCKER, "image", "import"]:
                stage("SIGNED349_ROOTFS_IMPORT")
            elif argv[:2] == [executor.DOCKER, "build"]:
                stage("SIGNED349_IMAGE_BUILD")
            elif argv[:2] == [executor.DOCKER, "run"] and argv[-1] == "/builder-packages.lock":
                stage("SIGNED349_INVENTORY")
            return self.runner(argv, *args, **kwargs)

        self.tag = self.entry.bootstrap_adapter(native, build_run, out, self.nonce, self.scopes, self.runtime)
        need(native.audit(inputs, cache, out) == 256, "Actual 256 packages and signed rootfs required")
        checks = M.decode((out/"cache-checksums.json").read_bytes())
        need(len(checks) == len(refs) == 517, "Complete 517 audited inputs required")
        stage("SIGNED349_CONTEXT")
        handoff = self.carrier.install_context_handoff(native, inputs, cache, out)
        fresh = [executor.DOCKER, "image", "ls", "-a", "--quiet", "--no-trunc", "--filter"]
        for selector in ("reference="+self.tag, "label="+self.entry.LABEL+"="+self.nonce):
            need(self.runner([*fresh, selector], 15).stdout == b"", "Fresh exclusively owned signed349 image")
        shell = {}

        def probe(image, labels):
            stage("SIGNED349_ROOTFS_SHELL")
            shell.update(self.entry.probe_signed_rootfs(self.runner, out, self.nonce,
                         self.scopes, self.runtime, image, labels))

        self.imported = self.rootfs.SignedRootfsBootstrap(native, build_run, out, self.nonce,
                                                        operation=self.entry.ROOTFS_OPERATION, probe=probe)
        self.image = native.build(inputs, cache, out, {})
        need(shell.get("status") == "SHELL_PASS" and (out/"packages.lock").read_bytes() == inventory
             and re.fullmatch(r"sha256:[0-9a-f]{64}", self.image), "Exact actual native signed349 result required")
        stage("SIGNED349_CONTEXT_RETIRE")
        handoff.retire_context()
        return dict(image=self.image, inventory=C.pin(inventory), shell=shell, input_count=len(checks),
                    official_signature_count=257, inventory_extension=extension)

    def retire(self):
        if self.imported is None or not self.imported.submitted:
            return

        def docker(*args):
            return self.runner([executor.DOCKER, *args], 30).stdout

        for _ in range(2):
            need(docker("container", "ls", "-a", "--quiet", "--no-trunc") == b"",
                 "Retire owned signed349 images only after all containers are absent")
        label = self.entry.LABEL
        listing = ("image", "ls", "-a", "--quiet", "--no-trunc", "--filter", "label="+label+"="+self.nonce)
        images = docker(*listing).decode("ascii").splitlines()
        if images:
            image, = images
            row, = json.loads(docker("image", "inspect", image))
            need(re.fullmatch(r"sha256:[0-9a-f]{64}", image) and self.image in (None, image)
                 and row["Id"] == image and row["Config"]["Labels"].get(label) == self.nonce
                 and (row.get("RepoTags") or []) == [self.tag] and not row.get("RepoDigests"),
                 "Only the same tagged signed349 derived image may retire")
            docker("image", "rm", image)
        for _ in range(2):
            need(docker(*listing) == b"", "Owned signed349 image remains")
        if self.imported:
            self.imported.cleanup()


PACMAN_CONFIG = "/qt612.pacman.conf"
GPGDIR = "/run/cachy-qt612-deps/gnupg"
TEST_CERT = "/qt612-test-public.gpg"


def trusted_dockerfile(plan, base_image, auth):
    """Project only the local immutable FROM and the temporary ALPM trust seam."""
    fp, expiration = auth["fingerprint"], auth["expires_epoch"]
    need(re.fullmatch(r"[0-9A-F]{40}", fp or "") and type(expiration) is int and time.time() < expiration,
         "Current selected TEST signer required")
    need(re.fullmatch(r"sha256:[0-9a-f]{64}", base_image), "Immutable local signed349 image required")
    original = plan["dockerfile"]
    header = "FROM " + base_image + "\n"
    seam = "RUN pacman --config " + PACMAN_CONFIG + " -U "
    need(original.startswith(header) and original.count(seam) == 1
         and original.count(" && pacman -Q | LC_ALL=C sort > /qt612.actual.lock") == 1
         and plan["normal_signature_policy"] == "Required TrustedOnly"
         and "GPGDir" not in plan["pacman_config"], "Exact maintained signed dependency transaction required")
    time_check = f'test "$(date -u +%s)" -lt {expiration}'
    pk = "pacman-key --gpgdir " + GPGDIR
    listing = ("gpg --batch --no-options --homedir " + GPGDIR +
               " --with-colons --fingerprint --list-keys " + fp)
    primary = "awk -F: '$1 == \"fpr\" { print $10; exit }'"
    trust = ("COPY md4c-test-public.gpg " + TEST_CERT + "\nRUN " + time_check +
             " && install -d -m 700 " + GPGDIR +
             f" && {pk} --init && {pk} --populate archlinuxarm && {pk} --add {TEST_CERT}" +
             f' && test "$({listing} | {primary})" = {fp} && {pk} --lsign-key {fp}' +
             f" && {time_check} && " + seam.removeprefix("RUN "))
    retirement = (f" && gpgconf --homedir {GPGDIR} --kill all"
                  f" && test ! -S {GPGDIR}/S.gpg-agent && rm -r {GPGDIR} && rm {TEST_CERT}"
                  " && pacman -Q | LC_ALL=C sort > /qt612.actual.lock")
    projected = original.replace(header, "FROM " + base_image.removeprefix("sha256:") + "\n", 1)
    projected = projected.replace(seam, trust, 1)
    projected = projected.replace(" && pacman -Q | LC_ALL=C sort > /qt612.actual.lock", retirement, 1)
    return projected, plan["pacman_config"] + "GPGDir = " + GPGDIR + "\n"


class SignedDependencies:
    """Build and reopen the exact signed356 inventory on the same owned daemon."""

    def __init__(self, pipeline, runner, nonce, output):
        self.pipeline, self.runner, self.nonce, self.out = pipeline, runner, nonce, output
        need(re.fullmatch(r"[0-9a-f]{32}", nonce), "Exact first-stage nonce required")
        self.tag = "cachy-qt612-native-" + nonce + ":gui-server356"
        self.image = None
        self.submitted = False

    def docker(self, *args, seconds=15):
        return self.runner([executor.DOCKER, *args], seconds).stdout

    def construct(self, *, source, source_map_sha256, baseline, auth, authenticate):
        C, M = self.pipeline.C, self.pipeline.C.M
        base_image = baseline["image"]
        need(type(auth) is dict and set(auth) == {"certificate", "fingerprint", "expires_epoch", "archive",
             "signature", "root_evidence"} and baseline["input_count"] == 517
             and baseline["official_signature_count"] == 257 and baseline["shell"]["status"] == "SHELL_PASS",
             "Current selected TEST trust and successful signed349 receipt required")
        authenticate(auth)
        plan = self.pipeline.builder_image_plan(source=source, source_map_sha256=source_map_sha256,
            component=executor.COMPONENT, baseline_image=base_image, previous={}, uid=os.getuid(), gid=os.getgid())
        inventory = plan["expected_inventory"].encode("ascii")
        need(plan["expected_packages"] == 356 and len(inventory.splitlines()) == 356
             and C.pin(inventory) == plan["inventory_pin"], "Exact signed356 inventory plan required")
        md4c, = [name for name in plan["archives"] if name.startswith("md4c-")]
        refs = plan["signed_context"]
        pin = lambda row: {key:row[key] for key in ("bytes", "sha256")}
        need(set(refs) == {name+suffix for name in plan["archives"] for suffix in ("", ".sig")}
             and pin(refs[md4c]) == auth["archive"] and pin(refs[md4c+".sig"]) == auth["signature"],
             "Same seven signed pairs and exact TEST md4c authority required")
        dockerfile, config = trusted_dockerfile(plan, base_image, auth)
        out = M.ordinary(self.out)
        out.mkdir(mode=0o700)
        inside = out/"context"
        writer = M.Writer(inside)
        observed = {}
        try:
            for name, ref in sorted(refs.items()):
                writer.put("signed-dependencies/"+name, source=Path(ref["path"]), expected=pin(ref),
                           observed=observed, cap=32*1024**2)
            cert = auth["certificate"]
            writer.put("md4c-test-public.gpg", source=Path(cert["path"]), expected=pin(cert),
                       observed=observed, cap=65536)
            writer.put("qt612.pacman.conf", raw=config.encode())
            writer.put("expected356.lock", raw=inventory)
            writer.put("Dockerfile", raw=dockerfile.encode())
            M.unchanged(observed)
        finally:
            writer.close()

        need(self.docker("container", "ls", "-a", "--quiet", "--no-trunc") == b""
             and self.docker("image", "ls", "-a", "--quiet", "--no-trunc", "--filter", "reference="+self.tag) == b"",
             "Empty owned daemon and fresh signed356 tag required")
        iid = out/"image-id"
        self.submitted = True
        self.docker("build", "--network=none", "--pull=false", "--platform=linux/arm64",
                    "--quiet", "--tag", self.tag, "--label", executor.LABEL+"="+self.nonce,
                    "--iidfile", str(iid), str(inside), seconds=600)
        self.image = M.stream(iid, None, {}, collect=True, cap=128).decode("ascii").strip()
        row = self.inspect()
        need(row["Config"]["User"] == f"{os.getuid()}:{os.getgid()}", "Ordinary signed356 image user required")
        name = "cachy-qt612-family-" + self.nonce + "-inventory356"
        raw = self.docker("run", "--rm", "--pull=never", "--platform=linux/arm64", "--network=none",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpus=1",
            "--memory=512m", "--memory-swap=512m", "--pids-limit=32", "--name", name,
            "--entrypoint=/bin/sh", self.image, "-ec",
            f"test -r /etc/pacman.conf && test ! -e {GPGDIR} && test ! -e {TEST_CERT}"
            " && pacman -Q | LC_ALL=C sort", seconds=30)
        need(raw == inventory, "Actual ordinary-user signed356 inventory differs")
        for _ in range(2):
            need(self.docker("container", "ls", "-a", "--quiet", "--no-trunc") == b"",
                 "Natural signed356 inventory reader retirement required")
        with (out/"packages.lock").open("xb") as stream:
            stream.write(raw)
        return dict(image=self.image, inventory=plan["inventory_pin"], signature_policy="Required TrustedOnly",
                    base_image=base_image, md4c_archive=auth["archive"], md4c_signature=auth["signature"])

    def inspect(self):
        need(re.fullmatch(r"sha256:[0-9a-f]{64}", self.image or ""), "Complete immutable signed356 image ID required")
        row, = json.loads(self.docker("image", "inspect", self.image))
        need(row["Id"] == self.image and row["Architecture"] == "arm64" and row["Os"] == "linux"
             and row["Config"]["Labels"].get(executor.LABEL) == self.nonce
             and (row.get("RepoTags") or []) == [self.tag] and not row.get("RepoDigests"),
             "Exact owned native signed356 image tag, label and ID required")
        return row

    def retire(self):
        if not self.submitted:
            return
        listing = ("image", "ls", "-a", "--quiet", "--no-trunc", "--filter", "reference="+self.tag)
        found = self.docker(*listing).decode("ascii").splitlines()
        if found:
            image, = found
            need(self.image in (None, image), "Same owned signed356 image must retire")
            self.image = image
            self.inspect()
            self.docker("image", "rm", self.image, seconds=30)
        for _ in range(2):
            need(self.docker(*listing) == b"", "Owned signed356 image tag remains")


def run_owned_payload(*, pipeline, family_source, bootstrap, supervisor, commands,
                      prepared, socket, nonce, auth, stage_mode, lifecycle_credential=None, stage=lambda _: None):
    """Start after the controller has launched its authenticated ordinary service."""
    need(os.getuid() == os.geteuid() > 0, "The authenticated ordinary payload owns the Qt build")
    need(stage_mode in ("pair-only", "signed-lifecycle")
         and (stage_mode == "pair-only") == (lifecycle_credential is None),
         "Choose the exact hosted stage mode and optional lifecycle credential before any build")
    need(Path(auth["certificate"]["path"]) == prepared["input_test_certificate"],
         "Use the independently verified certificate in the exact acquired volume")
    need({k:auth["certificate"][k] for k in ("bytes", "sha256")} == prepared["acquisition"]["md4c_public_certificate"],
         "Same certificate selected and acquired for the seven-pair image")
    source, work = prepared["source"], prepared["work"]
    source_map_sha256 = prepared["input_receipt"]["new_source_map"]["sha256"]
    need(not os.access(source, os.W_OK), "The live runner Source must be read-only to the payload")
    supervisor.require_domain(pipeline.POLICY)
    runner = scoped_runner(commands, socket)
    temporary = work/"tmp"
    need(temporary.is_dir() and not temporary.is_symlink() and temporary.stat().st_uid == os.getuid(),
         "Exact ordinary owner temporary directory required")
    os.environ.update(CACHY_LLHTTP_REFERENCE_OWNED_DOCKER_HOST="unix://"+str(socket),
                      CACHY_LLHTTP_REFERENCE_OWNED_TMPDIR=str(temporary))
    baseline = SignedBase(pipeline=pipeline, runner=runner, source=source, source_map_sha256=source_map_sha256,
                          output=work/"llhttp-reference-native", nonce=nonce, **bootstrap)
    dependencies = SignedDependencies(pipeline, runner, nonce, work/"signed356")
    outputs = work/"gui-output"
    errors = []
    try:
        stage("SIGNED349_BUILD")
        base = baseline.construct(stage=stage)
        stage("SIGNED356_BUILD")
        selected = dependencies.construct(source=source, source_map_sha256=source_map_sha256, baseline=base,
                                          auth=auth, authenticate=supervisor.authenticate_md4c_input)
        stage("SOURCE_CACHE")
        cache = work/"source-cache"
        family_source.prepare_cache(source=source, source_map_sha256=source_map_sha256, output=cache)
        # The concrete image ID is available only after the signed transaction.
        # The independent supervisor supplies the already authenticated binding.
        stage("REQUEST_HANDOFF")
        binding, binding_sha256 = supervisor.select_stage_binding(
            image=selected["image"], inventory_pin=selected["inventory"], source_map_sha256=source_map_sha256,
            component=executor.COMPONENT, nonce=nonce, mode=stage_mode)
        os.environ.update(QT612_FAMILY_SOURCE_ROOT=str(source), QT612_FAMILY_SOURCE_MAP_SHA256=source_map_sha256,
                          QT612_FAMILY_BINDING_PATH=str(binding), QT612_FAMILY_BINDING_SHA256=binding_sha256)
        scratch = work/"qualifier-scratch"
        scratch.mkdir(mode=0o700)
        result = executor.run_first_pair(trusted_pipeline=pipeline, owner_commands=commands, supervisor=supervisor,
            source=source, source_map_sha256=source_map_sha256, output=outputs, image=selected["image"],
            inventory=source/"expected356.lock", cache=cache, nonce=nonce, work=scratch/"work",
            failure_output=work/"gui-hold", socket=socket, binding=binding, binding_sha256=binding_sha256,
            pair_only=stage_mode == "pair-only", lifecycle_credential=lifecycle_credential)
        if stage_mode == "pair-only":
            C = pipeline.C
            raw = C.M.stream(outputs/"owned-pair.json", None, {}, collect=True)
            witness = C.M.decode(raw)
            operands = dict(source_map=prepared["input_receipt"]["new_source_map"],
                            qualification=C.pin(C.encoded(result["qualification"])), owner=C.pin(raw),
                            stage_binding_sha256=binding_sha256, dispatch=witness["dispatch"])
            root = work/"gui-pair-evidence"
            manifest = evidence.export_pair(C, stage=outputs, commands=commands.out, source=source,
                                            output=root, selected=operands)
            result["passive_export"] = dict(path=str(root), manifest_pin=manifest, selected=operands)
    except BaseException as error:
        errors.append(error)
    for close in (dependencies.retire, baseline.retire,
                  lambda: supervisor.retain_owner_evidence(work=work, commands=commands)):
        try:
            close()
        except BaseException as error:
            errors.append(error)
    if errors:
        raise BaseExceptionGroup("Held Qt stage or owned retirement", errors)
    return result
