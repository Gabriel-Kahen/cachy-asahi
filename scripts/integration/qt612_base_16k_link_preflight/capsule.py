# SPDX-License-Identifier: MIT
"""Pinned inputs, resource bounds and issuance contract for the local QtCore capsule."""

import importlib.util
import os
from pathlib import Path
import re
import stat
import struct
import time
from uuid import UUID

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
LANE = HERE.relative_to(SOURCE).as_posix()
PORTABLE = "scripts/integration/qt612_md4c_compile"
PORTABLE_COMMIT = "ac9ed3ceb1df938473a6a9bfe4dcd941120c923a"
PORTABLE_HASHES = {PORTABLE + "/" + name: digest for name, digest in {
    "actor.py": "69ec1bde10f36ff727dda51a80d354b6265b8a2295b46fdc1f86838382191f22",
    "common.py": "c83ff6391a56c05fbae56668af8f3f020c739531488eedb99b0309dc54465ddf",
    "prepare.py": "e0212da30780cdf3507c796f6f523d4c5e0e37716395b3477fc66b8daa0e2740",
    "guest.sh": "4c9f3c4f19ab72474091eb65ff2f4970635e70fd91c5fce143802b46b466d485",
}.items()}
ACTOR_PATH = "/src/" + LANE + "/actor.py"
SCOPE = "cachy-asahi-qtbase16k-qtcore-link.scope"
PAYLOAD = "/qtcore-link"
RESULT_LABEL = "QT16K_CORE"
PLAN_LEAF = "PLAN.UNISSUED.json"
HANDOFF_LEAF = "HANDOFF.UNISSUED.json"
HANDOFF_KIND = "QTCORE_LINK_HANDOFF_UNISSUED_V2"

SHARED = {
    PORTABLE + "/" + leaf for leaf in ("actor.py", "common.py", "prepare.py", "guest.sh")
} | {
    "scripts/install/overlay583_trial/controller.py",
    "scripts/install/overlay583_trial/trial.py",
    "scripts/integration/arm16k_perl5423_vm/contracts.py",
    "scripts/integration/arm16k_perl5423_vm/runtime.py",
    "scripts/integration/arm16k_perl5423_vm/helper-origin.json",
    "scripts/integration/arm16k_perl5423_vm/frozen/owned_process.py",
    "scripts/integration/arm16k_perl5423_vm/frozen/independent_readback.py",
    "packages/port/qt612-gui-server-source-reference/check_stage.py",
}
SOURCE_FILES = SHARED | {
    LANE + "/" + leaf for leaf in ("actor.py", "capsule.py", "guest.sh", "preflight.py", "readback.py", "site.py")
}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


B = module("qtcore_app_b_actor", SOURCE / PORTABLE / "actor.py")
F = module("qtcore_passive_graph", HERE / "preflight.py")
O, T, P = B.O, B.T, B.P
IMAGE = O.ACTOR_IMAGE
LIMITS = F.CORE_LIMITS
ATTACH_SECONDS = LIMITS["attach_seconds"]
CPUS = LIMITS["vcpus"]
RAM_GATE = LIMITS["actor_memory_bytes"] + LIMITS["host_memory_reserve_bytes"]
OUTPUT_BYTES = sum(LIMITS[key] for key in ("overlay_file_bytes", "result_bytes", "reports_bytes"))
DISK_GATE = OUTPUT_BYTES + LIMITS["live_disk_reserve_bytes"]
RESULT_BYTES = LIMITS["result_bytes"]
HEX = re.compile("[a-f0-9]{64}")
NONCE = re.compile("[a-f0-9]{32}")
Q3_TERMINAL = F.file_record(F.Q3_TERMINAL)
R4_TERMINAL = F.file_record((3598, "c930b0cd60456d7f7e756829f71a72c8b7bad7faa3ab5664bb4f60c4c541f9b3"))
ORIGINALS = {
    "Image": F.file_record((9019400, "36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494")),
    "boot.raw": F.file_record((1611661312, "007b552b6bb66ffe9cd84a21baac3a5477dfd6a2fba3aeefeacdf30db32ea7df")),
    "scratch.raw": F.file_record(F.Q3_SCRATCH),
}
TOOLS = {"/usr/bin/" + leaf: F.file_record(pair) for leaf, pair in {
    "cp": (129336, "3a597f7c21f2922e97bc1607f111ee15d2ed71998570d8a152d1e40aedfa2035"),
    "debugfs": (202328, "9b27184084383c8607eee03b43c80eca4ef912acf4887b40a7cc420e267ad8a8"),
    "e2fsck": (356568, "a9ea133a844edd695b5172abadc8bbbbb03aaedad80fc24d039bdbf4563a125c"),
    "mke2fs": (141672, "0ad4756fd858ee0a3a7fcaa34875af0c1050b9bccaf0d363c242d87d70575657"),
    "qemu-img": (2567104, "2139b2c8d5a9f28dbef2c5cdb663ce842648105fa76720ec691f8f5cddc8b002"),
    "qemu-system-aarch64": (34622584, "6f16cea44da813a65a1076886f63687350a0173e188873ba227dcc06f5c16b27"),
}.items()}
DOCKER_KIND = "QTCORE_ROOTLESS_DOCKER_BINDING_V1"
DOCKER_CAP = 64 << 20
HOST_PATH = re.compile(r"/[A-Za-z0-9_./-]+")


def validate_docker(binding):
    T.need(type(binding) is dict and set(binding) == {"kind", "uid", "client", "socket"}
           and binding["kind"] == DOCKER_KIND and type(binding["uid"]) is int and binding["uid"] > 0,
           "Explicit ordinary-user rootless Docker binding required")
    client, socket, uid = binding["client"], binding["socket"], binding["uid"]
    identity_fields = {"device", "inode", "uid", "gid", "mode"}
    T.need(type(client) is dict and set(client) == {"path", "bytes", "sha256", "identity"}
           and type(socket) is dict and set(socket) == {"path", "endpoint", "identity"},
           "Exact configured Docker executable and Unix socket required")
    for item in (client, socket):
        path, identity = item["path"], item["identity"]
        T.need(type(path) is str and HOST_PATH.fullmatch(path) and str(Path(path)) == path
               and len(path) <= 4096 and ".." not in Path(path).parts
               and type(identity) is dict and set(identity) == identity_fields
               and all(type(x) is int and x >= 0 for x in identity.values()) and identity["inode"] > 0,
               "Canonical local Docker path and filesystem identity required")
    c, s = client["identity"], socket["identity"]
    T.need(type(client["bytes"]) is int and 0 < client["bytes"] <= DOCKER_CAP
           and type(client["sha256"]) is str and HEX.fullmatch(client["sha256"])
           and stat.S_ISREG(c["mode"]) and c["mode"] & 0o111 and not c["mode"] & 0o6022
           and c["uid"] in (0, uid) and stat.S_ISSOCK(s["mode"]) and s["uid"] == uid
           and socket["endpoint"] == "unix://" + socket["path"] and len(socket["path"].encode()) < 108
           and client["path"] != socket["path"], "Pinned executable and owned rootless Unix endpoint required")
    return binding


def docker_identity(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid, mode=info.st_mode)


def check_docker(binding, *, hash_client=False):
    validate_docker(binding)
    client, socket = binding["client"], binding["socket"]
    T.need(os.getuid() == os.geteuid() == binding["uid"], "Exact ordinary rootless host user required")
    cli_path, socket_path = T.ordinary(client["path"]), T.ordinary(socket["path"])
    info = cli_path.lstat()
    T.need(docker_identity(info) == client["identity"] and info.st_size == client["bytes"]
           and docker_identity(socket_path.lstat()) == socket["identity"],
           "Reviewed Docker executable or socket identity changed")
    if hash_client:
        T.read(cli_path, ref_pin(client), cap=DOCKER_CAP, collect=False)
        T.need(T.identity(cli_path.lstat()) == T.identity(info)
               and docker_identity(socket_path.lstat()) == socket["identity"],
               "Docker executable or socket changed during pin verification")
    return T.identity(info)


def seal_docker(client, socket, size, digest):
    client, socket = T.ordinary(client), T.ordinary(socket)
    binding = dict(kind=DOCKER_KIND, uid=os.getuid(),
                   client=dict(path=str(client), bytes=size, sha256=digest, identity=docker_identity(client.lstat())),
                   socket=dict(path=str(socket), endpoint="unix://" + str(socket), identity=docker_identity(socket.lstat())))
    check_docker(binding, hash_client=True)
    return binding


def check_pinned_file(path, expected):
    return T.read(path, expected, cap=expected["bytes"], collect=False)


def read_original(path, expected):
    with F.open_original(path) as stream:
        before = F.verify_original(stream, path, expected["bytes"])
        raw = stream.read(expected["bytes"] + 1)
        T.need(T.pin(raw) == expected and F.identity(os.fstat(stream.fileno())) == before == F.identity(path.lstat()),
               "Original input bytes or metadata changed")
    return raw


def ref_pin(reference):
    return {key: reference[key] for key in ("bytes", "sha256")}


def validate_prior(closures):
    T.need(set(closures) == {"q3", "r4"}, "Exact Q3 and R4 closure references required")
    for role, pin in (("q3", Q3_TERMINAL), ("r4", R4_TERMINAL)):
        ref = closures[role]
        T.need(set(ref) == {"path", "bytes", "sha256"} and ref_pin(ref) == pin,
               "Exact independent predecessor pin required")
    attempt = F.verify_terminal(Path(closures["q3"]["path"]))
    r4 = T.decode(read_original(Path(closures["r4"]["path"]), R4_TERMINAL))
    T.need(r4["status"] == "CLOSED_QT_MD4C_COMPILE_R4_IMPORTER_OBJECT_PASS" and r4["issuer"] == "Root"
           and r4["container_exit"] == r4["qemu_exit"] == 0 and r4["release"] == "CLOSE_ONLY"
           and r4["observations"] == [dict(container_absent=True, scope_absent=True)] * 2,
           "Exact independently closed R4 importer result required")
    return attempt


def guest_files():
    guest = (HERE / "guest.sh").read_bytes()
    T.need(0 < len(guest) <= 128 << 10, "Bounded QtCore guest required")
    return {"guest.sh": guest, "MANIFEST.sha256": P.checksums({"guest.sh": P.sha(guest)})}


def actor_policy():
    profile = dict(kind=P.TOOL_PROFILE_KIND, actor_image=IMAGE, tools=TOOLS)
    policy = P.actor_policy(profile, sum(value["bytes"] for value in ORIGINALS.values()))
    return policy | dict(admission_disk_bytes=DISK_GATE, child_file_size_cap=LIMITS["overlay_file_bytes"],
                         watched_tree=["/out", OUTPUT_BYTES, LIMITS["live_disk_reserve_bytes"]],
                         watched_paths=[["/out/overlay.qcow2", LIMITS["overlay_file_bytes"]],
                                        ["/out/result.raw", RESULT_BYTES]])


def qemu_argv(nonce, manifest):
    return P.vm_argv("/inputs/Image", P.boot_cmdline(nonce, PAYLOAD + "/guest.sh") +
                     f" cachy_qt_compile_nonce={nonce} cachy_qt_compile_plan={manifest}" +
                     P.storage_args(nonce, F.SCRATCH_UUID), "qtcore-" + nonce, (
                         ("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
                         ("scratch", "file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore"),
                         ("result", "file=/out/result.raw,format=raw,readonly=off"),
                     ))


def plan_data(nonce, inputs):
    payload = {leaf: P.sha(raw) for leaf, raw in guest_files().items()}
    return dict(kind="QTCORE_LINK_PLAN_UNISSUED_V1", authority=None, nonce=nonce, q3_terminal=Q3_TERMINAL,
                inputs=inputs, qemu_argv=qemu_argv(nonce, payload["MANIFEST.sha256"]),
                qemu_seconds=LIMITS["qemu_seconds"], actor=actor_policy(),
                result_uuid=P.result_uuid(nonce), guest_payload=payload)


def load_plan(path, digest):
    raw = T.read(path, cap=32 << 10)
    T.need(HEX.fullmatch(digest) and P.sha(raw) == digest, "Exact independent QtCore plan pin required")
    plan = T.decode(raw)
    nonce, inputs = plan["nonce"], plan["inputs"]
    sizes = {name: pair["bytes"] for name, pair in ORIGINALS.items()} | {"result.raw": RESULT_BYTES}
    T.need(type(nonce) is str and NONCE.fullmatch(nonce) and set(inputs) == set(sizes)
           and all(isinstance(inputs[name], dict) and set(inputs[name]) == {"bytes", "sha256"}
                   and type(inputs[name]["bytes"]) is int and inputs[name]["bytes"] == size
                   and HEX.fullmatch(inputs[name]["sha256"]) for name, size in sizes.items())
           and all(inputs[name] == ORIGINALS[name] for name in ("Image", "scratch.raw"))
           and inputs["boot.raw"] != ORIGINALS["boot.raw"]
           and raw == T.encoded(plan_data(nonce, inputs)), "Exact bounded unissued plan required")
    return plan


def load_handoff(path, digest):
    raw = T.read(path, cap=64 << 10)
    doc = T.decode(raw)
    keys = {"kind", "authority", "scope", "actor_image", "plan", "source", "source_tree_sha256",
            "prior_closures", "docker", "portable_commit"}
    T.need(HEX.fullmatch(digest) and P.sha(raw) == digest and raw == T.encoded(doc) and set(doc) == keys
           and doc["kind"] == HANDOFF_KIND and doc["authority"] is None
           and doc["scope"] == SCOPE and doc["actor_image"] == IMAGE
           and doc["portable_commit"] == PORTABLE_COMMIT and set(doc["source"]) == SOURCE_FILES
           and all(doc["source"][name]["sha256"] == expected for name, expected in PORTABLE_HASHES.items())
           and P.sha(T.encoded(doc["source"])) == doc["source_tree_sha256"]
           and set(doc["prior_closures"]) == {"q3", "r4"},
           "Exact unissued local QtCore handoff required")
    validate_docker(doc["docker"])
    return doc


def verify_source(handoff, source):
    source = T.ordinary(source)
    tree = handoff["source"]
    leaves = list(source.rglob("*"))
    T.need(set(tree) == SOURCE_FILES and len(leaves) <= 96 and stat.S_IMODE(source.stat().st_mode) == 0o555
           and not any(path.is_symlink() for path in leaves)
           and {path.relative_to(source).as_posix() for path in leaves if not path.is_dir()} == set(tree),
           "Exact immutable capsule source tree required")
    for path in leaves:
        mode = stat.S_IMODE(path.lstat().st_mode)
        expected = tree.get(path.relative_to(source).as_posix())
        if expected is None:
            T.need(path.is_dir() and mode == 0o555, "Exact source directory mode required")
        else:
            T.need(mode == expected["mode"] == 0o444, "Exact source leaf mode required")
            check_pinned_file(path, ref_pin(expected))


def result_uuid(path):
    info = B.clean_file(path)
    T.need(info.st_size == RESULT_BYTES, "Exact finite result geometry required")
    with F.open_original(path) as stream:
        before = F.verify_original(stream, path, RESULT_BYTES)
        body = os.pread(stream.fileno(), 1024, 1024)
        T.need(F.identity(os.fstat(stream.fileno())) == before == F.identity(path.lstat()), "Result geometry changed")
    T.need(len(body) == 1024 and body[56:58] == b"\x53\xef" and body[120:136].rstrip(b"\0") == RESULT_LABEL.encode()
           and struct.unpack_from("<I", body, 24)[0] == 2 and struct.unpack_from("<I", body, 4)[0] * 4096 == RESULT_BYTES
           and struct.unpack_from("<I", body, 336)[0] == 0, "Expected fixed 4K-block QtCore result volume")
    return str(UUID(bytes=body[104:120]))


def capacity(path):
    f = os.statvfs(T.ordinary(path))
    free = f.f_bavail * f.f_frsize
    mem = int(re.search(r"^MemAvailable:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)[1]) * 1024
    cpus = len(os.sched_getaffinity(0))
    return dict(free_bytes=free, memory_available_bytes=mem, allowed_cpus=cpus,
                required_bytes=DISK_GATE, minimum_memory_bytes=RAM_GATE, minimum_cpus=CPUS,
                fits=free >= DISK_GATE and mem >= RAM_GATE and cpus >= CPUS)


def binding(handoff, plan, handoff_sha):
    return dict(kind="ROOT_QTCORE_LINK_SELECTION_V1", issuer=None, approved=None, created_utc=None, expires_utc=None,
                actor_image=IMAGE, scope=SCOPE, nonce=plan["nonce"], handoff_sha256=handoff_sha,
                plan_sha256=handoff["plan"]["sha256"], prior_closures={
                    key: ref_pin(ref) for key, ref in handoff["prior_closures"].items()})


def verify_selection(raw, digest, handoff, plan, handoff_sha, *, live=True):
    T.need(P.sha(raw) == digest, "Exact independent Root selection pin required")
    issued = T.decode(raw)
    created, expires = issued["created_utc"], issued["expires_utc"]
    T.need(type(created) is type(expires) is int and 0 < expires - created <= 3600
           and (not live or created <= int(time.time()) < expires), "Fresh finite Root entry window required")
    expected = binding(handoff, plan, handoff_sha) | dict(issuer="Root", approved=True, created_utc=created, expires_utc=expires)
    T.need(raw == T.encoded(expected), "Selection differs from the sealed unissued QtCore binding")
    return issued


def preflight_root(root, handoff, plan):
    root = T.ordinary(root)
    T.need(stat.S_IMODE(root.stat().st_mode) == 0o700, "Private capsule root required")
    attempt = validate_prior(handoff["prior_closures"])
    verify_source(handoff, root / "source")
    inputs = T.ordinary(root / "inputs")
    templates = T.ordinary(root / "templates")
    T.need({path.name for path in inputs.iterdir()} == set(ORIGINALS)
           and {path.name for path in templates.iterdir()} == {"result.raw"}
           and inputs.stat().st_dev == templates.stat().st_dev, "Exact private staged carrier set required")
    for name, expected in plan["inputs"].items():
        leaf = (templates if name == "result.raw" else inputs) / name
        before = B.clean_file(leaf)
        T.need(stat.S_IMODE(before.st_mode) == 0o444
               and not leaf.samefile(attempt / "output/qtbase16k" / name), "Staged carrier must be read-only and distinct")
        check_pinned_file(leaf, expected)
    T.need(result_uuid(templates / "result.raw") == plan["result_uuid"], "Exact empty result template UUID required")
    check_docker(handoff["docker"], hash_client=True)
    return capacity(root)
