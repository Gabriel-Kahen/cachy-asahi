# SPDX-License-Identifier: MIT
"""Prepare exact retained inputs for the #622 maintained-builder lane."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import SimpleNamespace

from inputs622 import GuardFailure, PROJECT, ROOT, command, read_pin, require, stage_object, stage_set


LOCK_SHA256 = "74bf957c5c579b4cb1a6523df11d265ab9f44450c3a71c226b4b9b7a3b65f89b"
KERNEL_PACKET = "scripts/port/kernel-native-job/packet"
KERNEL_RUNTIME = "scripts/port/kernel-native-job/runtime.py"
INPUTS = "scripts/ci/inputs.lock.json"
PRODUCER = "scripts/ci/native_arm.py"
CHECKER = "scripts/checks/package_checks.py"
HELD_CHECKER = ("scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source/"
                "scripts/ci/llhttp-reference-native-source/base/runtime/" + CHECKER)
BASE_LOCK = "scripts/ci/maintained-native/locks/builder-successor.lock"
PACMAN_CONFIG = (b"[options]\nArchitecture = aarch64\nSigLevel = Required\n"
                 b"LocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n")
PACMAN_PERMISSION_LINES = frozenset((
    b"error: config file /etc/pacman.conf could not be read: Permission denied",
    b"sha256sum: /etc/pacman.conf: Permission denied",
    b"cp: cannot open '/etc/pacman.conf' for reading: Permission denied",
))


@dataclass(frozen=True)
class PreparedMaintained:
    producer_source: Path
    cache: Path
    extensions: Path
    base_lock: Path
    tiff_lock: Path
    recipes: Path


def locked():
    return read_pin(Path(__file__).with_suffix(".lock.json"), LOCK_SHA256)


def extension_pins():
    return {entry["filename"]: {key: entry[key] for key in ("bytes", "sha256")}
            for row in locked()["extension"]["rows"]
            for entry in (row["archive"], row["signature"])}


def bind_recipe_tree(expected):
    directory = PROJECT.relative_to(ROOT)
    tree = command(["git", "--no-replace-objects", "rev-parse", f"HEAD:{directory}"], cwd=ROOT).stdout
    changes = command(["git", "--no-replace-objects", "status", "--porcelain=v1", "--untracked-files=all", "--",
                       str(directory)], cwd=ROOT).stdout
    require(tree.strip() == expected.encode("ascii") and not changes, "exact maintained #622 recipe tree")


def module_bytes(path, body):
    scope = {"__file__": str(path), "__name__": "_maintained_622"}
    exec(compile(body, str(path), "exec"), scope)
    return SimpleNamespace(**scope)


def packet_tools(contract):
    path = ROOT / (KERNEL_PACKET + ".py")
    pin = contract["references"][KERNEL_PACKET + ".py"]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == pin["bytes"],
                "ordinary maintained producer packet reader required")
        body = stream.read(pin["bytes"] + 1)
    require(len(body) == pin["bytes"] and hashlib.sha256(body).hexdigest() == pin["sha256"],
            "exact maintained producer packet reader required")
    return module_bytes(path, body)


def producer_git(*args):
    try:
        return command(["git", "--no-replace-objects", "-c", "protocol.allow=never", *args],
                       cwd=ROOT, timeout=10).stdout
    except subprocess.CalledProcessError as error:
        raise GuardFailure("missing or unreadable maintained producer Git object") from error


def stage_producer(scratch, contract, packet):
    name = KERNEL_PACKET + ".lock.json"
    manifest = packet.load(ROOT / name, contract["references"][name]["sha256"])["files"]
    reference = contract["reference_commit"]
    require(re.fullmatch(r"[0-9a-f]{40}", reference), "exact maintained producer reference")
    selected = set(packet.HELPERS) | {INPUTS, packet.RECIPES_LOCK}
    table = producer_git("ls-tree", "-rlz", "--full-tree", reference, "--",
                         *sorted(selected | packet.RECIPE_BASES))
    blobs = {}
    for entry in table.split(b"\0")[:-1]:
        header, leaf = entry.split(b"\t", 1)
        git_mode, kind, oid, size = header.split()
        name = leaf.decode("ascii")
        pin = manifest.get(name)
        require(pin and kind == b"blob" and git_mode in (b"100644", b"100755")
                and int(git_mode, 8) == (stat.S_IFREG | pin["mode"]) and int(size) == pin["bytes"],
                f"maintained producer byte/mode pin: {name}")
        blobs[name] = oid.decode("ascii")

    require(packet.RECIPES_LOCK in blobs, "exact maintained original recipe lock")
    recipe_lock = producer_git("cat-file", "blob", blobs[packet.RECIPES_LOCK])
    require(packet.sha(recipe_lock) == contract["recipe_lock_sha256"], "exact maintained original recipe lock")
    recipes = packet.decode(recipe_lock)
    require(set(recipes) == packet.RECIPE_BASES and sum(map(len, recipes.values())) == packet.RECIPE_COUNT,
            "exact maintained original recipe closure")
    for directory, leaves in recipes.items():
        selected.update(directory + "/" + str(packet.relative(leaf)) for leaf in leaves)
    require(selected == blobs.keys(), "maintained producer exact source membership")

    output = scratch / "maintained-producer-source"
    output.mkdir(mode=0o700)
    for name in sorted(selected):
        mode = manifest[name]["mode"]
        if name == CHECKER:
            raw, mode = packet.capture(ROOT / HELD_CHECKER)
        else:
            raw = recipe_lock if name == packet.RECIPES_LOCK else producer_git("cat-file", "blob", blobs[name])
        require(packet.row(raw, mode) == manifest[name], f"maintained producer byte/mode pin: {name}")
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(mode)
    return output


def transport_pins(inputs):
    rows = {}
    for item in (inputs["rootfs"], *inputs["keyring_files"], *inputs["packages"]):
        name = item["filename"]
        require(re.fullmatch(r"[A-Za-z0-9_.+:\-]+", name) and name not in rows,
                "maintained transport basename")
        rows[name] = dict(bytes=item["size"], sha256=item["sha256"], url=item["url"])
        if "signature_sha256" in item:
            rows[name + ".sig"] = dict(bytes=item["signature_size"], sha256=item["signature_sha256"])
    return rows


def private_directory(path):
    require(path is not None, "required maintained input directory")
    path = Path(path)
    info = path.lstat()
    require(path == path.resolve(strict=True) and stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            "owned canonical maintained input directory")
    return path


def cache_names(path):
    names = set()
    for entry in path.iterdir():
        require(len(names) < 501, "maintained input count bound")
        info = entry.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "maintained input must be single-link ordinary file")
        names.add(entry.name)
    return names


def selected_cache_pins(local, baseline, pins, *, full):
    names = cache_names(local)
    require(len(pins) == baseline["transport_files"] and names <= pins.keys(), "maintained input namespace")
    if full:
        require(names == pins.keys(), "full maintained cache membership")
    else:
        packed = ("\n".join(sorted(names)) + "\n").encode("ascii")
        require(len(names) == baseline["retained_files"]
                and hashlib.sha256(packed).hexdigest() == baseline["retained_names_sha256"],
                "exact #623 retained baseline membership")
    return {name: pins[name] for name in sorted(names)}


def derive_locks(base, extension, packet):
    rows = dict(line.split() for line in base.decode("ascii").splitlines())
    require(rows.get("jbigkit") == "2.1-8" and rows.get("libtiff") == "4.7.2-1"
            and rows.get("lcms2") == "2.19.1-1", "exact maintained provider inventory")
    del rows["jbigkit"]
    additions = {row["name"]: row["version"] for row in extension["rows"]}
    additions["cachy-asahi-jbigkit"] = "2.2-1.1"
    require(not rows.keys() & additions.keys(), "maintained TIFF extension must preserve base versions")
    rows.update(additions)
    result = "".join(f"{name} {version}\n" for name, version in sorted(rows.items())).encode("ascii")
    require(len(rows) == extension["tiff_packages"] and packet.sha(result) == extension["tiff_packages_lock_sha256"],
            "exact maintained TIFF inventory")
    return result


def verify_extensions(directory, rows, checker, signature_check):
    signature_check()
    for row in rows:
        observed = checker.package(directory / row["archive"]["filename"])
        metadata = observed["metadata"][".PKGINFO"]
        expected = {"pkgname": [row["name"]], "pkgver": [row["version"]], "arch": [row["arch"]],
                    "depend": row["depends"], "provides": row["provides"], "license": row["license"],
                    "conflict": row["conflicts"], "replaces": row["replaces"]}
        require(not observed["errors"] and ".INSTALL" not in observed["members"]
                and all(elf["machine"] == 183 and not elf["errors"] for elf in observed["elf"].values())
                and all(sorted(metadata.get(field, [])) == sorted(values) for field, values in expected.items()),
                "maintained extension package metadata or ELF differs")


def prepare_maintained(args, scratch, report):
    """Stage #622 inputs and authenticate the extension without allocating a builder."""
    scratch = private_directory(scratch)
    spec = locked()
    baseline, extension = spec["baseline"], spec["extension"]
    packet = packet_tools(baseline)
    bind_recipe_tree(spec["recipe_tree"])
    full, retained = getattr(args, "maintained_cache", None), getattr(args, "retained_cache", None)
    require((full is None) != (retained is None), "select one maintained input transport")
    local = private_directory(full if full is not None else retained)
    official = private_directory(args.maintained_extension_cache)
    report["phase"] = "maintained-inputs"
    source = stage_producer(scratch, baseline, packet)
    inputs = packet.load(source / INPUTS, baseline["input_lock_sha256"])
    pins = transport_pins(inputs)
    selected = selected_cache_pins(local, baseline, pins, full=full is not None)
    extensions = extension_pins()
    require(cache_names(official) == extensions.keys(), "exact maintained extension membership")
    prepared = PreparedMaintained(source, scratch / "alarm-cache",
                                  scratch / "maintained-extension", scratch / "expected341.lock",
                                  scratch / "expected346.lock", scratch / "recipes")
    stage_set(prepared.cache, selected, local)
    # The original producer authenticates the full private/public union before
    # allocation. The extension audit needs this one public key first.
    if full is None:
        stage_object(prepared.cache, "archlinuxarm.gpg", pins["archlinuxarm.gpg"])
    stage_set(prepared.extensions, extensions, official)
    base = packet.read(ROOT / BASE_LOCK, 128 * 1024)
    require(packet.sha(base) == baseline["packages_lock_sha256"] and len(base.splitlines()) == baseline["packages"],
            "exact maintained base inventory")
    prepared.base_lock.write_bytes(base)
    prepared.tiff_lock.write_bytes(derive_locks(base, extension, packet))

    report["phase"] = "maintained-extension-authentication"
    sys.path.insert(0, str(PROJECT))
    import baseline as codec_baseline
    import prepare

    keyhome = scratch / "extension-gnupg"
    keyhome.mkdir(mode=0o700)
    keyring = keyhome / "alarm.gpg"
    command(["gpg", "--batch", "--no-options", "--no-autostart", "--homedir", str(keyhome),
             "--dearmor", "--output", str(keyring), str(prepared.cache / "archlinuxarm.gpg")])
    checker_path = prepared.producer_source / CHECKER
    checker = module_bytes(checker_path, packet.read(checker_path))
    verify_extensions(prepared.extensions, extension["rows"], checker,
                      lambda: codec_baseline.verify_codecs(prepared.extensions, keyring,
                          {"codec_files": extensions, "signer_fingerprint": inputs["signer_fingerprint"]}))
    report["maintained_extension"] = {"verified_signatures": len(extension["rows"]),
                                      "inventory_sha256": extension["tiff_packages_lock_sha256"]}

    report["phase"] = "recipe-materialization"
    upstream = scratch / "upstream"
    plan = prepare.load_plan(lambda _: None)
    stage_set(upstream, plan["upstream"], args.upstream_dir)
    sources = {name: upstream / name for name in prepare.UPSTREAM}
    second = scratch / "recipes-recheck"
    first_report = prepare.prepare(sources, prepared.recipes, lambda _: None)
    require(first_report == prepare.prepare(sources, second, lambda _: None), "two recipe materializations agree")
    for package in prepare.PACKAGES:
        filename = f"{package}-reviewed-inputs.json"
        require((prepared.recipes / filename).read_bytes() == (second / filename).read_bytes(),
                "reviewed recipe hash maps agree")
    report["recipe_tree"] = spec["recipe_tree"]
    report["recipe_materializations"] = {"runs": 2, "pinned_files": first_report["files_count"],
                                         "plan_sha256": first_report["plan_sha256"]}
    return prepared


def verify_audit(output, cache, source, binding, packet):
    result = packet.load(output / "result.json")
    inputs = packet.load(source / INPUTS, binding["input_lock_sha256"])
    packages = inputs["packages"]
    checksum = packet.HELPERS[PRODUCER][0]
    checksums = {name: row["sha256"] for name, row in transport_pins(inputs).items()}
    require(result.get("mode") == "audit" and result.get("status") == "signed-input-audit-pass"
            and result.get("native_build") == "NOT RUN" and result.get("hardware_validation") == "NOT RUN"
            and result.get("verified_signed_packages") == len(packages)
            and result.get("bootstrap_script_sha256") == checksum
            and result.get("reviewed_inputs_sha256") == binding["input_lock_sha256"]
            and packet.sha(packet.read(output / "inputs.lock.json")) == binding["input_lock_sha256"]
            and packet.load(output / "cache-checksums.json") == checksums
            and packet.load(output / "acquisition.json")["counts"] == {
                "total": len(checksums), "pass": len(checksums), "fail": 0, "pending": 0},
            "exact maintained input audit result")
    signatures = packet.load(output / "signatures.json")
    require(len(signatures) == binding["signatures"] and set(signatures) == {
        row["filename"] for row in (inputs["rootfs"], *packages)}, "exact maintained signature inventory")
    saved_path = sys.path[:]
    try:
        native = module_bytes(source / PRODUCER, packet.read(source / PRODUCER))
    finally:
        sys.path[:] = saved_path
    for name, row in signatures.items():
        require(type(row["exit_code"]) is int and row["exit_code"] == 0
                and row["command"][-2:] == [str(cache / (name + ".sig")), str(cache / name)],
                "exact maintained signature return and operands")
        native.valid_signature(row["status"], inputs["signer_fingerprint"])
    metadata = packet.decode(packet.read(output / "package-audit.json", 64 * 1024**2))
    require(set(metadata) == {row["filename"] for row in packages}
            and json.loads(packet.read(output / "rootfs-inventory.json")) == inputs["rootfs_packages"],
            "exact maintained signed package and rootfs metadata inventory")


def audit_maintained(prepared, scratch, report):
    """Run the original signed-input audit through the reviewed process supervisor."""
    binding = locked()["baseline"]
    packet = packet_tools(binding)
    scratch = private_directory(scratch)
    source, cache = prepared.producer_source, prepared.cache
    require(source == scratch / "maintained-producer-source" and cache == scratch / "alarm-cache",
            "exact maintained audit scratch paths")
    manifest = KERNEL_PACKET + ".lock.json"
    rows = packet.load(ROOT / manifest, binding["references"][manifest]["sha256"])["files"]
    path = ROOT / KERNEL_RUNTIME
    body, mode = packet.capture(path)
    require(packet.row(body, mode) == rows[KERNEL_RUNTIME], "exact maintained audit process supervisor")
    runtime = module_bytes(path, body)

    home = scratch / "audit-home"
    home.mkdir(mode=0o700)
    output = scratch / "maintained-audit"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C", "TZ": "UTC",
           "PYTHONDONTWRITEBYTECODE": "1"}
    argv = ["/usr/bin/python3", "-I", "-B", str(source / PRODUCER), "audit",
            "--inputs", str(source / INPUTS), "--inputs-sha256", binding["input_lock_sha256"],
            "--cache", str(cache), "--output", str(output)]
    require(not os.path.lexists(output), "fresh maintained audit output")
    report["phase"] = "maintained-input-authentication"
    try:
        runner = runtime.Runner(1210, env, scratch / "audit-logs")
        natural = runner.run(argv, timeout=1200, log="maintained-audit.log")
        require(type(natural.returncode) is int and natural.returncode == 0, "maintained audit natural exit")
        verify_audit(output, cache, source, binding, packet)
    except runtime.Cancelled as error:
        raise InterruptedError("maintained input audit interrupted") from error
    finally:
        primary = sys.exc_info()[1]
        gpg = output / "gpg"
        if os.path.lexists(gpg):
            try:
                private_directory(gpg)
                runner = runtime.Runner(40, env, scratch / "audit-cleanup-logs")
                cleanup = runner.run(["/usr/bin/gpgconf", "--homedir", str(gpg), "--kill", "gpg-agent"], timeout=30)
                require(cleanup.returncode == 0 and not any(p.name.startswith("S.gpg-agent") for p in gpg.iterdir()),
                        "maintained audit private gpg-agent retirement")
            except (Exception, runtime.Cancelled) as error:
                if primary is None:
                    if isinstance(error, runtime.Cancelled):
                        raise InterruptedError("maintained audit private gpg-agent retirement interrupted") from error
                    raise
                primary.add_note("maintained audit private gpg-agent retirement failed: " + type(error).__name__)
    report["maintained_input_authentication"] = {"pinned_objects": binding["transport_files"],
                                               "verified_signatures": binding["signatures"],
                                               "signed_package_metadata": True}


def producer_command_failure(output, error, packet):
    """Recognize only the original producer's fixed log destinations."""
    match = re.fullmatch(r"command failed \((-?[0-9]{1,3})\); see ([^\n]+)", error)
    if match is None or not -64 <= int(match[1]) <= 255 or int(match[1]) == 0:
        return None, None
    known = {str(output / "bootstrap.log"): ("BOOTSTRAP", None, None, output / "bootstrap.log")}
    for base in sorted(packet.RECIPE_BASES):
        recipe = Path(base).name
        known[str(output / (recipe + "-compare.json"))] = ("RECIPE_COMPARE", recipe, None, None)
        for attempt in (1, 2):
            tag = f"{recipe}-{attempt}"
            known[str(output / (tag + "-driver.log"))] = ("RECIPE_BUILD", recipe, attempt, output / tag / "build.log")
    if match[2] not in known:
        return None, None
    role, recipe, attempt, log = known[match[2]]
    return {"role": role, "recipe": recipe, "attempt": attempt, "exit_code": int(match[1])}, log


def maintained_producer_failure(natural, argv, source, output, packet, observer):
    """Capture only exact completed-process evidence before caller retirement."""
    disposition = {"exit_code": natural.returncode, "observation": None, "command": None,
                   "pacman_conf_mode": None, "pacman_permission": "NOT_OBSERVED"}
    if observer is None or natural.returncode != 1:
        return disposition
    try:
        observed = {}
        observer(observed, natural, argv, source, output)
        group = observed["producer_failure"]
        disposition["observation"] = group
        if group["availability"] != "VERIFIED" or group["diagnostic"]["phase"] != "BUILD":
            return disposition
        result = packet.decode(packet.read(output / "result.json", 16 * 1024))
        require(natural.stdout.rsplit(b"\n", 2)[-2:] == [json.dumps(result, sort_keys=True).encode(), b""],
                "maintained producer diagnostic echo changed")
        disposition["command"], log = producer_command_failure(output, result["error"], packet)
    except Exception:
        # A missing or rejected diagnostic cannot replace the original failure.
        disposition.update(observation=None, command=None)
        return disposition

    try:
        config, mode = packet.capture(output / "context/pacman.conf", 4096)
        if config == PACMAN_CONFIG:
            disposition["pacman_conf_mode"] = mode
    except (OSError, ValueError):
        pass
    if log is not None:
        try:
            body = packet.read(log, 256 * 1024)
            disposition["pacman_permission"] = ("OBSERVED" if any(line in PACMAN_PERMISSION_LINES
                for line in body.split(b"\n")) else "ABSENT_IN_BOUNDED_LOG")
        except (OSError, ValueError):
            pass
    return disposition


def bootstrap_maintained(prepared, scratch, report, *, run_producer, commit, observe_failure=None):
    """Launch only the original producer through the caller's native scope."""
    require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit), "exact maintained source commit")
    binding = locked()["baseline"]
    packet = packet_tools(binding)
    scratch = private_directory(scratch)
    source = prepared.producer_source
    output = scratch / "producer"
    require(source == scratch / "maintained-producer-source" and prepared.cache == scratch / "alarm-cache"
            and not os.path.lexists(output), "exact maintained producer scratch paths")
    argv = ["/usr/bin/python3", "-I", "-B", str(source / PRODUCER), "build",
            "--inputs", str(source / INPUTS), "--inputs-sha256", binding["input_lock_sha256"],
            "--recipes", str(source / packet.RECIPES_LOCK), "--recipes-sha256", binding["recipe_lock_sha256"],
            "--cache", str(prepared.cache), "--output", str(output)]
    report["phase"] = "maintained-producer"
    natural = run_producer(argv, cwd=source)
    require(type(natural) is subprocess.CompletedProcess and natural.args == argv and type(natural.returncode) is int
            and -64 <= natural.returncode <= 255, "maintained producer natural exit")
    if natural.returncode != 0:
        report["maintained_producer_failure"] = maintained_producer_failure(
            natural, argv, source, output, packet, observe_failure)
        require(False, "maintained producer natural exit")
    result, bootstrap, runner = (packet.load(output / name) for name in ("result.json", "bootstrap.json", "runner.json"))
    image = packet.read(output / "image-id", 128).decode("ascii").strip()
    checksum = packet.HELPERS[PRODUCER][0]
    inputs = packet.load(source / INPUTS, binding["input_lock_sha256"])
    expected = {name: row["sha256"] for name, row in transport_pins(inputs).items()}
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image)
            and result.get("mode") == "build" and result.get("status") == "native-builds-and-byte-comparison-pass"
            and result.get("native_build") == "PASS" and result.get("hardware_validation") == "NOT RUN"
            and result.get("verified_signed_packages") == len(inputs["packages"])
            and result.get("reviewed_inputs_sha256") == binding["input_lock_sha256"]
            and result.get("reviewed_recipes_sha256") == binding["recipe_lock_sha256"]
            and result.get("bootstrap_script_sha256") == checksum,
            "exact maintained producer result")
    require(bootstrap.get("status") == "image-provisioned" and bootstrap.get("image_id") == image
            and bootstrap.get("inputs_sha256") == packet.sha(packet.read(output / "inputs.lock.json")) == binding["input_lock_sha256"]
            and bootstrap.get("packages_lock_sha256") == packet.sha(packet.read(output / "packages.lock", 128 * 1024))
            == binding["packages_lock_sha256"] and packet.load(output / "cache-checksums.json") == expected
            and runner.get("commit") == commit and runner.get("runner_arch") == "ARM64"
            and runner.get("uid") == os.getuid() and runner.get("bootstrap_script_sha256") == checksum,
            "maintained same-job image, inventories and input bindings")
    report["maintained_base"] = {"image": image, "packages": binding["packages"],
                                 "inventory_sha256": binding["packages_lock_sha256"],
                                 "input_lock_sha256": binding["input_lock_sha256"],
                                 "pinned_objects": binding["transport_files"], "verified_signatures": binding["signatures"]}
    return image
