# SPDX-License-Identifier: MIT
"""Trial-only replacement for the signed349 legacy dependency COPY layer."""

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import time


DOCKER = "/usr/bin/docker"
BASE_LABEL = "org.cachy-asahi.md4c053-reference.signed-rootfs"
IMAGE_LABEL = "org.cachy-asahi.llhttp-reference.nonce"
IID = re.compile(r"sha256:[0-9a-f]{64}")
CID = re.compile(r"[0-9a-f]{64}")
NONCE = re.compile(r"[0-9a-f]{32}")
MIB = 1024**2
MEMORY = 4 * 1024 * MIB
# Legacy Docker's non-network default capabilities, including the shadow audit path.
CAPS = ("AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
        "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT")
KEYS = ("archlinuxarm.gpg", "archlinuxarm-trusted", "archlinuxarm-revoked")
CONFIG = (b"[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n"
          b"HookDir = /builder-disabled-hooks\n")
ROLES = ("Dockerfile", "disabled-hooks.txt", "pacman.conf", "deps", "keys")
HELD_RUN_SHA256 = "47d0a5dd262e66e667088a11a7fb6785ec7bc089ff133077eca9aa89f7950883"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


@dataclass(frozen=True)
class Plan:
    context: Path
    iidfile: Path
    cidfile: Path
    base: str
    tag: str
    name: str
    nonce: str
    command: str

    def create(self):
        return [DOCKER, "container", "create", "--pull=never", "--platform=linux/arm64",
                "--network=none", "--cgroupns=private", "--init=false", "--restart=no",
                "--cap-drop=ALL", *["--cap-add="+cap for cap in CAPS],
                "--security-opt=no-new-privileges", "--cpus=2", "--memory=4g",
                "--memory-swap=4g", "--pids-limit=256", "--user=0:0", "--workdir=/",
                "--name", self.name, "--cidfile", str(self.cidfile),
                "--mount", f"type=bind,src={self.context},dst=/mnt,readonly,bind-propagation=rprivate",
                self.base, "/bin/sh", "-ec", self.command]

    def commit(self, cid):
        return [DOCKER, "container", "commit", "--pause=false",
                "--change", f'LABEL {BASE_LABEL}=""',
                "--change", f"LABEL {IMAGE_LABEL}={self.nonce}",
                "--change", "USER alarm", "--change", "WORKDIR /tmp",
                "--change", 'CMD ["/bin/false"]', cid, self.tag]


def make_plan(argv, *, out, base, nonce, uid, gid, dockerfile):
    """Join the retained post-import Dockerfile and alter only the cache transport."""
    need(NONCE.fullmatch(nonce) and IID.fullmatch(base)
         and type(uid) is type(gid) is int and uid > 0 and gid > 0,
         "Exact admitted signed349 image, nonce and ordinary builder identity")
    context, iid = out/"context", out/"image-id"
    tag = "cachy-llhttp-reference-bootstrap:" + nonce
    label = IMAGE_LABEL+"="+nonce
    need(out.is_absolute() and out == out.resolve() and out.name == "bootstrap"
         and out.parent.name == "llhttp-reference-native"
         and re.fullmatch(r"/[A-Za-z0-9._/-]+", str(out))
         and argv == [DOCKER, "build", "--network=none", "--pull=false", "--platform=linux/arm64",
                      "--iidfile", str(iid), "--quiet", "--tag", tag, "--label", label, str(context)],
         "Exact post-import signed349 build command")
    lines = dockerfile.decode("ascii").splitlines()
    prefix = ["FROM "+base.removeprefix("sha256:"), f'LABEL {BASE_LABEL}=""',
              "COPY keys/ /usr/share/pacman/keyrings/", "COPY deps/ /tmp/deps/",
              "COPY pacman.conf /etc/pacman.conf", "COPY disabled-hooks.txt /tmp/disabled-hooks.txt"]
    need(len(lines) == 9 and lines[:6] == prefix and lines[6].startswith("RUN mkdir -p /builder-disabled-hooks ")
         and lines[7:] == ["USER alarm", "WORKDIR /tmp"] and dockerfile.endswith(b"\n"),
         "Only the retained signed349 install Dockerfile is eligible")
    install = lines[6].removeprefix("RUN ")
    identity = f"groupmod -g {gid} alarm && usermod -u {uid} -g alarm alarm"
    template = install.replace(identity, "groupmod -g %GID% alarm && usermod -u %UID% -g alarm alarm", 1)
    need(install.count(identity) == 1 and sha256(template.encode()).hexdigest() == HELD_RUN_SHA256,
         "Whole retained signed transaction, keyring and inventory program")
    for before, after in (("/tmp/disabled-hooks.txt", "/mnt/disabled-hooks.txt"),
                          ("/tmp/deps/*.pkg.tar.xz", "/mnt/deps/*.pkg.tar.xz"),
                          ("rm -rf /tmp/deps /var/cache", "rm -rf /var/cache")):
        need(install.count(before) == 1 and after not in install, "Exact read-only cache path seam")
        install = install.replace(before, after, 1)
    setup = ["install -m 0644 /mnt/pacman.conf /etc/pacman.conf",
             "install -m 0600 -- "+' '.join("/mnt/keys/"+name for name in KEYS)+" /usr/share/pacman/keyrings/"]
    return Plan(context, iid, out/"signed349-install.cid", base, tag,
                "cachy-qt612-signed349-"+nonce, nonce, " && ".join([*setup, install]))


def read_metadata(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and not info.st_mode & 0o022 and 0 < info.st_size <= maximum,
             "Ordinary bounded signed349 assembly metadata")
        raw = stream.read(maximum+1)
        need(len(raw) == info.st_size and same_stat(info, os.fstat(stream.fileno()))
             and same_stat(info, path.lstat()), "Stable signed349 assembly metadata")
        return raw


def same_stat(left, right):
    keys = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(left, key) == getattr(right, key) for key in keys)


def audit_context(carrier, handoff, plan, dockerfile):
    """Reuse the exact authoritative post-audit context stat identities."""
    context = plan.context
    need(not handoff.pending and handoff.context == context and len(handoff.verified) == 516
         and not os.path.lexists(handoff.rootfs) and {p.name for p in context.iterdir()} == set(ROLES),
         "Complete authenticated context after the original signed-rootfs import")
    verified = {path for path in handoff.verified if path != handoff.rootfs}
    found = set()
    for name in ("deps", "keys"):
        leaf = context/name
        info = leaf.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
             and info.st_dev == context.stat().st_dev and not info.st_mode & 0o022,
             "Same owned ordinary package bind directory")
        found.update(leaf.iterdir())
    need(found == verified and {p.name for p in (context/"keys").iterdir()} == set(KEYS),
         "Only the complete audited package/signature pairs and three keyring files")
    for path, identity in handoff.verified.items():
        if path in verified:
            need(carrier.identity(path.lstat()) == identity, "Same exact authenticated cache leaf")
    hooks = read_metadata(context/"disabled-hooks.txt", 64*1024)
    need(read_metadata(context/"Dockerfile", 16*1024) == dockerfile
         and read_metadata(context/"pacman.conf", 1024) == CONFIG
         and hooks == b"".join(line+b"\n" for line in sorted(set(hooks.splitlines())))
         and all(re.fullmatch(rb"[A-Za-z0-9_.@+-]+\.hook", line) for line in hooks.splitlines()),
         "Exact Required configuration and bounded audited hook masks")
    return hooks


def inspect_install(row, plan):
    config, host = row["Config"], row["HostConfig"]
    need(CID.fullmatch(row["Id"]) and row["Name"] == "/"+plan.name and row["Image"] == plan.base
         and config["Labels"] == {BASE_LABEL:plan.nonce} and config["User"] == "0:0"
         and config["WorkingDir"] == "/" and config["Cmd"] == ["/bin/sh", "-ec", plan.command]
         and not any(config.get(key) for key in ("Entrypoint", "Tty", "OpenStdin", "Volumes")),
         "Exact owned signed349 package installer")
    caps = [name.removeprefix("CAP_") for name in host["CapAdd"]]
    need(host["NetworkMode"] == "none" and host["CgroupnsMode"] == "private"
         and host["ReadonlyRootfs"] is False and not host["Privileged"] and not host.get("Devices")
         and not host.get("DeviceRequests") and not host.get("Init") and not host.get("AutoRemove")
         and host["RestartPolicy"]["Name"] == "no" and host["CapDrop"] == ["ALL"]
         and len(caps) == len(CAPS) and set(caps) == set(CAPS)
         and host["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges=true"])
         and host["Memory"] == host["MemorySwap"] == MEMORY and host["NanoCpus"] == 2*10**9
         and host["PidsLimit"] == 256 and not host.get("PortBindings"),
         "Exact offline signed349 sandbox and bounded install resources")
    mount, = row["Mounts"]
    need((mount["Type"], mount["Source"], mount["Destination"], mount["RW"], mount["Propagation"])
         == ("bind", str(plan.context), "/mnt", False, "rprivate"),
         "The authenticated package cache must be the sole read-only bind")


def inspect_image(row, plan, image, base_layer):
    config = row["Config"]
    labels = {BASE_LABEL:"", IMAGE_LABEL:plan.nonce}
    layers = row["RootFS"]["Layers"]
    need(row["Id"] == image and row["Architecture"] == "arm64" and row["Os"] == "linux"
         and row["RepoTags"] == [plan.tag] and not row.get("RepoDigests")
         and config["Labels"] == labels and config["User"] == "alarm" and config["WorkingDir"] == "/tmp"
         and config["Cmd"] == ["/bin/false"]
         and not any(config.get(key) for key in ("Volumes", "Entrypoint", "Tty", "OpenStdin"))
         and len(layers) == 2 and layers[0] == base_layer and layers[1] != base_layer
         and IID.fullmatch(layers[1]), "Exact offline derived image and one installed layer")


def assemble(baseline, argv, seconds, *, out, handoff, stage, classify, retirement):
    """Called only by the existing owned runner after exact import and shell readback."""
    need(seconds == 1800 and baseline.imported.submitted
         and baseline.imported.labels == {BASE_LABEL:baseline.nonce},
         "Retained finite same-owner signed349 image assembly interval")
    deadline = time.monotonic()+seconds
    work_end = deadline-40
    raw = read_metadata(out/"context/Dockerfile", 16*1024)
    plan = make_plan(argv, out=out, base=baseline.imported.image, nonce=baseline.nonce,
                     uid=os.getuid(), gid=os.getgid(), dockerfile=raw)
    hooks = audit_context(baseline.carrier, handoff, plan, raw)
    need(not os.path.lexists(plan.iidfile) and not os.path.lexists(plan.cidfile),
         "Fresh signed349 image and container receipts")
    base_layer = baseline.rootfs.ROOTFS_DIFF_ID

    def run(command, end=work_end, limit=15, *, check=True):
        cap = min(limit, end-time.monotonic())
        need(cap > 1, "Finite remaining signed349 assembly interval")
        return baseline.runner(command, cap, check=check)

    def produce(command, limit):
        try:
            result = run(command, limit=limit, check=False)
        except ValueError as error:
            if str(error) == "natural owned command retirement required":
                raise ValueError("IMAGE_BUILD_RETIREMENT") from None
            raise
        if result.returncode:
            raise ValueError(classify(result))
        return result

    class Installer(baseline.runtime.OwnedContainer):
        def call(self, command, cutoff):
            return run([DOCKER, *command[1:]], cutoff, 8, check=False)

        def validate(self, row):
            inspect_install(row, plan)

    owner = Installer(plan.name, plan.cidfile, plan.base, {BASE_LABEL:plan.nonce}, plan.context, out)
    need(owner.listing(work_end) is None, "Fresh owned signed349 installer name")
    stage("SIGNED349_IMAGE_BUILD")
    owner.submitted = True
    errors = []
    try:
        created = produce(plan.create(), 15).stdout.decode("ascii").strip()
        need(CID.fullmatch(created), "Complete immutable signed349 installer CID")
        row = owner.recover(work_end)
        need(row is not None and row["Id"] == created and row["State"]["Status"] == "created",
             "Same private signed349 installer CID and initial state")
        produce([DOCKER, "container", "start", "--attach", created], 1760)
        state = owner.recover(work_end)["State"]
        need(state["Status"] == "exited" and state["ExitCode"] == 0 and not state["Running"]
             and not state["OOMKilled"] and not state["Error"], "Natural stopped signed349 installer before commit")
        need(audit_context(baseline.carrier, handoff, plan, raw) == hooks,
             "Same selected package and hook inputs through signed349 installation")
        result = produce(plan.commit(created), 180)
        image = result.stdout.decode("ascii").strip()
        need(IID.fullmatch(image), "Immutable committed signed349 image ID")
        stage("SIGNED349_IMAGE_READBACK")
        row, = json.loads(run([DOCKER, "image", "inspect", image]).stdout)
        inspect_image(row, plan, image, base_layer)
    except BaseException as error:
        errors.append(error)
    try:
        with retirement():
            close = min(deadline, time.monotonic()+30)
            row = owner.recover(close)
            if row is not None:
                forced = ["--force"] if row["State"]["Running"] else []
                run([DOCKER, "container", "rm", *forced, row["Id"]], close, 12)
            for _ in range(2):
                need(owner.listing(close) is None, "Owned signed349 installer absence after retirement")
    except BaseException as error:
        errors.append(error)
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup("Signed349 install and owned installer retirement", errors)
    fd = os.open(plan.iidfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(image+"\n")
    return result
