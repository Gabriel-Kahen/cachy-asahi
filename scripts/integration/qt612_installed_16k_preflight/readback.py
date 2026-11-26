#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reopen one retired installed Qt trial result without mounting the guest filesystem."""

import argparse
from contextlib import contextmanager
import math
import os
from pathlib import Path, PurePosixPath
import re
from runpy import run_path
import sys
from types import SimpleNamespace

H = SimpleNamespace(**run_path(str(Path(__file__).with_name("owned.py"))))
C, W, T = H.C, H.W, H.T
G = SimpleNamespace(**run_path(str(Path(__file__).with_name("guest.py"))))
O = G.O
ROOT_DIRS = {".", "lost+found", "evidence", "evidence/commands"}
LEAF = re.compile(r"evidence/(?:commands/)?[a-z][a-z0-9.-]{0,95}")
STREAM_CAP = 1 << 20
COMMAND_PREFIX = "evidence/commands/"


@contextmanager
def file_views(path, result):
    C.read(path, H.RESULT_BYTES, result, collect=False)
    original = C.identity(path.lstat())
    disk = C.ext4_reader()(path, max_nodes=905, max_file_bytes=128 << 20)
    with disk as fs:
        nodes = fs.inventory()["nodes"]
        C.need(ROOT_DIRS <= nodes.keys() and "rtc-clock.env" in nodes, "Installed result namespace missing")
        leaves = {}
        for name, node in nodes.items():
            C.need(node["uid"] == node["gid"] == 0 and not node["xattrs"], "Unowned installed result entry")
            if name in ROOT_DIRS:
                C.need(node["type"] == "directory" and node["mode"] == (0o755 if name == "." else 0o700),
                       "Unexpected installed result directory")
            else:
                limit = STREAM_CAP if name.startswith(COMMAND_PREFIX) else 128 << 20
                C.need((name == "rtc-clock.env" or LEAF.fullmatch(name)) and node["type"] == "file"
                       and node["links"] == 1 and node["mode"] == 0o600 and node["size"] <= limit,
                       "Unbounded installed result member")
                leaves[name] = dict(bytes=node["size"], sha256=node["sha256"])
        C.need(sum(pin["bytes"] for pin in leaves.values()) < 768 << 20,
               "Installed result data exceeds the export budget")

        def get(name, cap):
            pin = leaves[name]
            C.need(pin["bytes"] <= cap, "Installed result member exceeds role limit")
            body = b"".join(fs.chunks(*fs.inode(nodes[name]["inode"])))
            C.need(C.pin(body) == pin and C.identity(path.lstat()) == original,
                   "Installed result file changed during readback")
            return body

        yield leaves, get
    C.need(C.identity(path.lstat()) == original, "Installed result carrier changed")


def read_operands(path, media, plan, selection):
    before = C.identity(path.lstat())
    expected = selection["inputs"] | {"signature": media["signature"]}
    names = {name: "media/" + leaf for name, leaf in (
        ("archive", Path(H.P.ARCHIVE).name), ("signature", Path(H.P.ARCHIVE).name + ".sig"),
        ("certificate", Path(H.P.CERT).name))}
    with C.ext4_reader()(path, max_nodes=512, max_file_bytes=W.INPUT_LIMITS["archive"]) as fs:
        nodes = fs.inventory()["nodes"]

        def check(name, pin):
            node = nodes[name]
            C.need(node["type"] == "file" and node["links"] == 1 and not node["xattrs"]
                   and dict(bytes=node["size"], sha256=node["sha256"]) == pin,
                   "Original installed operand differs")
            return node

        def body(name, pin):
            node = check(name, pin)
            data = b"".join(fs.chunks(*fs.inode(node["inode"])))
            C.need(C.pin(data) == pin, "Original installed operand changed during readback")
            return data

        for name, pin in media["source"].items():
            check(f"source/{name}", pin)
        for name, pin in plan["consumer"]["files"].items():
            check(f"media/consumer/{name}", pin)
        probe_path = "scripts/integration/qt612_installed_16k_preflight/loader_probe.py"
        check("media/loader_probe.py", media["source"][probe_path])
        for name, pin in (("PLAN.json", media["plan"]), ("SELECTION.json", media["selection"]),
                          ("expected356.lock", H.P.Q3_INVENTORY)):
            check(f"media/{name}", pin)
        check(names["archive"], expected["archive"])
        result = dict(input_pins=expected, config_raw=body("pacman.conf", C.pin(H.P.CONFIG.encode())),
                      certificate_raw=body(names["certificate"], expected["certificate"]),
                      signature_raw=body(names["signature"], expected["signature"]))
        C.need(C.identity(os.fstat(fs.fd)) == C.identity(path.lstat()) == before,
               "Original installed operand carrier changed")
    W.check_signed_inputs(expected, **result)
    return result


def selected_paths(path, media):
    before = C.identity(path.lstat())
    with H.M.boot_filesystem(path) as fs:
        _, root = H.F.boot_directory(fs, 2)
        _, payload = H.F.boot_directory(fs, root[H.BOOT_DIR.lstrip("/").encode()][0])
        node, kind = payload[b"protect.list"]
        inode, raw = fs.inode(node)
        body = b"".join(fs.chunks(inode, raw))
        C.need(kind == 1 and C.pin(body) == media["boot_payload"]["protect.list"]
               and C.identity(os.fstat(fs.fd)) == C.identity(path.lstat()) == before,
               "Original installed protection selection changed")
    if media["case"] != "main":
        C.need(body == b"\n", "Installed negative case does not select protected paths")
        return []
    paths = list(map(str, G.protected_paths(body.decode("ascii").splitlines())))
    C.need(body == "".join(path + "\n" for path in paths).encode(), "Exact protection path encoding required")
    return paths


class OriginalCommands:
    def __init__(self, plan, files, get):
        self.files, self.get = files, get
        self.wrapper = G.Runner(None, None, None, plan["consumer"])
        self.results = {}
        self.extra = set()

    def report(self, role):
        return C.json_body(self.get(f"{COMMAND_PREFIX}{role}.json", 128 << 10), canonical=True)

    def __call__(self, role, argv, *, timeout=90, stdin=None, env=None):
        C.need(role not in self.results, "Original installed command was reused")
        if env is None:
            env = W.NORMAL_ENV
        wrapped = self.wrapper.command_argv(role, argv, env)
        row = self.report(role)
        code = row["exit"]
        C.need(row["argv"] == wrapped and type(code) is int and 0 <= code <= 255
               and row["passed"] is (code == 0) and row["ownership"] == "REAPED"
               and row["group_census"] == "EMPTY_TWICE" and row["reaped"] is row["output_complete"] is True
               and row["timeout"] is row["command_timed_out"] is row["original_budget_overrun"] is
               row["emergency_retirement"] is False and row["signals"] == row["command_cancelled"] == []
               and row["error"] is row["emergency_retirement_cap_seconds"] is row["child_file_size_cap"] is None
               and all(type(row[key]) in (float, int) and math.isfinite(row[key])
                       for key in ("operation_seconds", "operation_cap_seconds"))
               and 0 < row["operation_seconds"] <= row["operation_cap_seconds"] <= timeout,
               "Exact natural installed guest command required")
        stdout = self.get(f"{COMMAND_PREFIX}{role}.stdout", STREAM_CAP)
        stderr = self.get(f"{COMMAND_PREFIX}{role}.stderr", STREAM_CAP)
        C.need(len(stdout) + len(stderr) <= STREAM_CAP
               and self.get(f"{COMMAND_PREFIX}{role}.log", STREAM_CAP) == stdout + stderr,
               "Original installed guest command streams differ")
        if stdin is not None:
            leaf = f"{COMMAND_PREFIX}{role}.stdin"
            C.need(role == "key-trust" and self.get(leaf, 128) == stdin,
                   "Original public key-trust input differs")
            self.extra.add(leaf)
        result = dict(exit_code=code, stdout=stdout, stderr=stderr, natural=True, group_empty=True, overflow=False)
        self.results[role] = result
        return result

    def finish(self):
        expected = {f"{COMMAND_PREFIX}{role}.{suffix}" for role in self.results
                    for suffix in ("json", "stdout", "stderr", "log")}
        C.need({name for name in self.files if name.startswith(COMMAND_PREFIX)} == expected | self.extra,
               "Exact installed command evidence namespace required")


def read_view(role, get):
    view = C.json_body(get(f"evidence/{role}-observed.json", W.MAX_SELECTION), canonical=True)
    for name, limit in (("protected", 16 << 20), ("database", 128 << 20)):
        if view[name] is not None:
            data = get(f"evidence/{role}-{name}.json", limit)
            C.need(C.pin(data) == view[name], "Original installed-stage observation differs")
            view[name] = data
    return view


def protection(raw, paths, providers):
    rows = C.json_body(raw, canonical=True)
    roots = [PurePosixPath(path) for path in paths]
    C.need(0 < len(rows) < O.LEAVES and set(paths) | providers.keys() <= rows.keys(),
           "Original baseline must cover all selected protected and provider paths")
    for path, row in rows.items():
        node = PurePosixPath(path)
        C.need(node.is_absolute() and str(node) == path and not path.startswith("//") and ".." not in node.parts
               and (path in providers or any(node.is_relative_to(root) for root in roots))
               and type(row) is dict, "Unexpected original protected path")
        kind = row["type"]
        if kind == "absent":
            C.need(row.keys() == {"type"}, "Exact absent protected path required")
            continue
        base = {"type", "mode", "uid", "gid"}
        C.need(row.keys() == base | {"file": {"pin"}, "directory": set(), "symlink": {"target"}}[kind]
               and all(type(row[key]) is int and 0 <= row[key] for key in ("mode", "uid", "gid"))
               and row["mode"] <= 0o7777, "Unexpected original protected path metadata")
        if kind == "file":
            C.need(C.check_pin(row["pin"], O.DSO_CAP), "Exact protected file pin required")
        elif kind == "symlink":
            C.need(type(row["target"]) is str and 0 < len(row["target"]) <= 4096,
                   "Exact protected symlink target required")
    C.need(all(rows[path]["type"] == "file" and rows[path]["pin"] == provider["pin"]
               for path, provider in providers.items()), "Original protected provider pins differ")
    return dict(selected=paths, baseline={name: ({"present": False} if rows[name]["type"] == "absent"
                else {"present": True, "type": rows[name]["type"]}) for name in paths})


def replay_loaders(commands, plan, selection, stage, view):
    role = stage["name"]
    package = plan["package"]["package"]
    installed = stage["state"] == "installed"
    seen, required_mappings = set(), set()
    for index, soname in enumerate(plan["package"]["sonames"]):
        data = W.command(commands, f"{role}-observe-soname-{index}",
                         ["/usr/bin/python3", "-I", "-B", O.PROBE, soname])["stdout"]
        row = C.json_body(data)
        maps, path, loaded = row["maps"], row["path"], row["loaded"]
        C.need(row.keys() == {"soname", "path", "maps", "loaded"} and row["soname"] == soname
               and type(maps) is dict and len(maps) <= 512 and type(loaded) is list and len(loaded) <= len(maps)
               and all(type(name) is str and name in maps for name in loaded)
               and loaded == sorted(set(loaded)), "Unexpected original ordinary-user loader map")
        if not installed:
            C.need(path is None and not maps and not loaded, "Qt mapped after original package removal")
            continue
        C.need(path == view["sonames"][soname]["path"] and path in maps,
               "Original loader selected a different Qt SONAME path")
        for mapped, identity in maps.items():
            O.path_shape(mapped, "/usr/lib/")
            C.need(type(identity) is list and len(identity) == 3 and all(type(value) is int and value >= 0
                   for value in identity) and identity[-1] > 0, "Original loader mapping lacks an inode")
        seen.update(maps)
        required_mappings.update((path, *loaded))
    if not installed:
        return

    payload = selection["payload"]
    inventory = W.command(commands, role + "-observe-package-files",
                          H.P.PACMAN + ["-Qlq", "--", package])["stdout"]
    listed = inventory.decode("ascii").splitlines()
    C.need(len(listed) == len(set(listed)) <= O.LEAVES and
           {line for line in listed if not line.endswith("/")} == payload.keys(),
           "Original package-owned path list differs")
    trace = commands.results[role + "-consumer-run"]["stderr"]
    observed_trace = O.plugin_trace(trace, plan["consumer"]["run"][0])
    provider_paths = set(selection["providers"])
    expected_files = {name for name, row in payload.items() if row["type"] == "file"}
    candidates = expected_files | provider_paths
    for raw in observed_trace:
        path = "/usr" + raw if raw.startswith("/lib/") else raw
        O.path_shape(path, "/usr/lib/")
        alias = payload.get(path)
        if alias and alias["type"] == "symlink":
            path = str(PurePosixPath(path).with_name(alias["target"]))
        # ld.so can print a versioned lookup alias. The canonical path must
        # still come from the pinned package/provider set.
        if path in candidates:
            seen.add(path)
        else:
            aliases = {name for name in candidates if name.startswith(path + ".")}
            C.need(len(aliases) <= 1, "Consumer loader trace has an ambiguous installed alias")
            seen.update(aliases)
    C.need(W.OFFSCREEN in seen, "Original consumer did not map the selected offscreen plugin")

    prefix = H.P.PACMAN + ["-Qoq", "--"]
    batches = []
    for name in commands.files:
        match = re.fullmatch(rf"{COMMAND_PREFIX}({re.escape(role)}-observe-owners-([0-9]{{1,2}}))\.json", name)
        if match:
            batches.append((int(match[2]), match[1]))
    batches.sort()
    C.need([index for index, _ in batches] == list(range(len(batches))) and 0 < len(batches) <= 8,
           "Missing original installed library ownership batches")
    owned = []
    for index, label in batches:
        wrapped = commands.report(label)["argv"]
        start = commands.wrapper.command_argv(label, prefix, W.NORMAL_ENV)
        paths = wrapped[len(start):]
        C.need(wrapped[:len(start)] == start and 0 < len(paths) <= 64
               and (index == len(batches) - 1 or len(paths) == 64)
               and set(paths) <= (seen & candidates),
               "Original ownership command includes unobserved installed paths")
        owners = W.command(commands, label, prefix + paths)["stdout"].decode("ascii").splitlines()
        expected_owners = [selection["providers"][path]["owner"] if path in provider_paths else package for path in paths]
        C.need(owners == expected_owners, "Original normal-loader package ownership differs")
        owned.extend(paths)
    C.need(owned == sorted(set(owned)) and required_mappings | provider_paths | {W.OFFSCREEN} <= set(owned),
           "Original installed owner observations omit a selected mapped library")


def review_main(media, plan, selection, report, commands, get, *, controls, operands, paths, epoch):
    baseline = None

    def run(role, argv, *, timeout, stdin, env):
        if role.endswith("-consumer-run"):
            env = env | {"LD_DEBUG": "files"}
        return commands(role, argv, timeout=timeout, stdin=stdin, env=env)

    def observe(role):
        nonlocal baseline
        stage = next(stage for stage in plan["stages"] if stage["name"] == role)
        view = read_view(role, get)
        replay_loaders(commands, plan, selection, stage, view)
        if baseline is None:
            baseline = view
        return view

    plan_raw, inventory, selection_raw = controls
    replayed = W.exercise(plan_raw, media["plan"]["sha256"], inventory, selection_raw, media["selection"]["sha256"],
                          now=epoch, **operands, verify_boundary=lambda *_: True, run=run, observe=observe)
    C.need(C.wire(report) == C.wire(replayed), "Original installed command timeline differs from the worker result")
    return C.pin(baseline["database"]), protection(baseline["protected"], paths, selection["providers"])


def review_negative(media, plan, selection, report, commands, get, *, epoch):
    case = media["case"]
    stage = plan["stages"][0]

    def command(role, argv, **kwargs):
        return W.command(commands, role, argv, **kwargs)

    def inventory(point):
        body = command("inventory-" + point, stage["inventory_query"])["stdout"]
        return C.pin(T.sorted_rows(body))

    before_inventory = inventory("before")
    W.verify_empty_keyring(command("keyring-before", W.KEYRING_LIST)["stdout"])
    if case == "tampered_signature":
        key = selection["key"]
        W.verify_test_certificate(command("test-certificate", W.CERTIFICATE_SHOW)["stdout"], key, epoch)
        command("key-import", W.GPG + ["--import", "--", H.P.CERT])
        W.verify_test_certificate(command("imported-keyring", W.KEYRING_LIST)["stdout"], key, epoch)
        denied = command("tampered-signature-gpg", W.SIGNATURE_VERIFY, accepted=(1,))
        W.verify_bad_signature(denied["stdout"], key)
        command("key-trust", W.GPG + ["--import-ownertrust"], data=(key["fingerprint"] + ":6:\n").encode())
    argv = plan["negative_trials"][case]["command"]
    denied = command("signature-refusal", argv, timeout=240, accepted=(1,))
    after_inventory = inventory("after")
    if case == "unknown_key":
        W.verify_empty_keyring(command("keyring-after", W.KEYRING_LIST)["stdout"])
    command("trust-retirement", W.RETIRE)
    before = get("evidence/database-before.json", 128 << 20)
    after = get("evidence/database-after.json", 128 << 20)
    reviewed = dict(clone=media["clone"], scratch=H.P.Q3_SCRATCH, configuration=C.pin(H.P.CONFIG.encode()),
                    archive=selection["inputs"]["archive"], signature=media["signature"], argv=argv,
                    database_before=before, database_after=after,
                    **{name: denied[name] for name in ("exit_code", "natural", "group_empty", "stderr")})
    W.review_negative(plan, selection, before, {plan["nonce"]}, case, reviewed)
    for name in ("database_before", "database_after", "stderr"):
        reviewed[name] = C.pin(reviewed[name])
    replayed = reviewed | dict(kind="QTBASE16K_INSTALLED_NEGATIVE_RESULT_V1", status="SIGNATURE_REFUSAL_VERIFIED_ONLY",
                              case=case, nonce=plan["nonce"], plan_sha256=media["plan"]["sha256"],
                              selection_sha256=media["selection"]["sha256"], inventory_before=before_inventory,
                              inventory_after=after_inventory)
    C.need(before_inventory == after_inventory == H.P.Q3_INVENTORY and C.wire(report) == C.wire(replayed),
           "Original signature refusal evidence differs")
    return C.pin(before), None


def review_case(media, plan, selection, files, get, *, controls, operands, paths, epoch):
    report = C.json_body(get("evidence/result.json", 256 << 10), canonical=True)
    commands = OriginalCommands(plan, files, get)
    result = (review_main(media, plan, selection, report, commands, get,
                          controls=controls, operands=operands, paths=paths, epoch=epoch)
              if media["case"] == "main" else review_negative(media, plan, selection, report, commands, get, epoch=epoch))
    commands.finish()
    return result


def readback(root, media_sha, site, site_sha, authority_sha, retirement, retirement_sha):
    raw, _ = C.external(root / H.MEDIA_NAME, 128 << 10, media_sha)
    media = H.load_media(raw, media_sha)
    raw, post_pin = C.external(retirement, 16 << 10, retirement_sha)
    post = C.json_body(raw, canonical=True)
    attempt = root / H.CLAIM
    authority_path = attempt / "selection.json"
    replay_host = run_path(str(Path(__file__).with_name("site.py")))["replay_host"]
    host = replay_host(root, media_sha, site, site_sha, authority_path, authority_sha)
    C.need(post == host | dict(observations=[dict(scope_absent=True, container_absent=True)] * 2)
           and type(host["exit_code"]) is int and host["exit_code"] == 0,
           "Exact successful retired installed scope and original host receipt required")
    authority_raw, _ = C.external(authority_path, 16 << 10, authority_sha)
    authority = H.read_authority(authority_raw, authority_sha, media, media_sha, site_sha=site_sha)
    stage = root / "control"
    # replay_host reopens the pinned source, input carriers and result template.
    carriers = root / "inputs"
    plan_raw, _ = C.read(stage / "PLAN.json", 64 << 10, media["plan"])
    inventory, _ = C.read(stage / "expected356.lock", 16 << 10, H.P.Q3_INVENTORY)
    selection_raw, _ = C.read(stage / "SELECTION.json", W.MAX_SELECTION, media["selection"])
    plan = W.read_plan(plan_raw, media["plan"]["sha256"], inventory)
    output = attempt / "output"
    C.need(C.check_pin(post["actor_result"], 16 << 10), "Exact original installed actor receipt required")
    report = C.json_body(C.read(output / "actor-result.json", 16 << 10, post["actor_result"])[0], canonical=True)
    C.need(report.keys() == {"kind", "status", "case", "clone", "media_sha256", "authority_sha256", "plan",
                            "selection", "qemu_argv", "result_uuid", "qemu", "serial", "fsck", "create", "inspect",
                            "overlay", "result", "allocation_peak"}
           and report["kind"] == H.RESULT_KIND and report["status"] == "PASS" and report["case"] == media["case"]
           and report["clone"] == media["clone"] and report["media_sha256"] == media_sha
           and report["authority_sha256"] == authority_sha and report["plan"] == media["plan"]
           and report["selection"] == media["selection"], "Exact successful installed actor report required")
    argv = report["qemu_argv"]
    epoch, = re.findall(r"(?:^| )arm16k_rtc_host_epoch=([0-9]{9,12})(?: |$)", argv[argv.index("-append") + 1])
    epoch = int(epoch)
    selection = W.read_selection(selection_raw, media["selection"]["sha256"], media["plan"]["sha256"], epoch)
    role = H.role(plan["nonce"], media["case"], media["clone"], media["boot_manifest"], media["plan"]["sha256"],
                  media["selection"]["sha256"], media["signature"]["sha256"], epoch)
    C.need(argv == role["qemu_argv"] and role["result_uuid"] == report["result_uuid"]
           and authority["created_utc"] <= epoch < authority["expires_utc"], "Exact installed boot identity required")
    verify_child(output, media, report)
    qemu, serial = C.command_receipt(output, "qemu", report["qemu"], argv, H.QEMU_SECONDS, H.WRITER_CAP, STREAM_CAP)
    C.need(qemu["stdout"] == report["serial"] and H.terminal(serial, media["clone"]) == "PASS",
           "Exact retired installed guest terminal required")
    C.command_receipt(output, "fsck-result", report["fsck"], ["/usr/bin/e2fsck", "-fn", "/out/result.raw"],
                      60, None, STREAM_CAP)
    result = output / "result.raw"
    C.need(report["result"] != media["result"], "Installed result did not change from its original template")
    H.M.verify_result(result, role["result_uuid"])
    operands = read_operands(carriers / "operands.raw", media, plan, selection)
    paths = selected_paths(carriers / "boot.raw", media)
    with file_views(result, report["result"]) as (files, get):
        database, protected = review_case(media, plan, selection, files, get, controls=(plan_raw, inventory, selection_raw),
                                          operands=operands, paths=paths, epoch=epoch)
        rtc = get("rtc-clock.env", 4096)
        C.need(f"HOST_BOOT_UTC={epoch}\n".encode() in rtc and b"RTC_CLOCK_ADVANCED=yes\n" in rtc
               and b"CLOCK_SETTING=none\n" in rtc, "Installed result lacks the original RTC guard")
    return dict(kind="QTBASE16K_INSTALLED_CASE_READBACK_V2", status="PASS_INSTALLED_CASE_READBACK_ONLY",
                case=media["case"], clone=media["clone"], plan=media["plan"], selection=media["selection"],
                scratch=H.P.Q3_SCRATCH, retirement=post_pin, baseline_database=database, original_files=files,
                protection=protected, media_sha256=media_sha, site_sha256=site_sha, authority_sha256=authority_sha,
                physical_M2="NOT_RUN")


def verify_child(output, media, report):
    actor = run_path(str(Path(__file__).with_name("actor.py")))
    policy = actor["runner_plan"](media)["actor"]
    C.command_receipt(output, "overlay-create", report["create"], policy["overlay_create"], 10, None, STREAM_CAP)
    _, inspect = C.command_receipt(output, "overlay-inspect", report["inspect"], policy["overlay_inspect"],
                                   10, None, STREAM_CAP)
    nodes = T.decode(inspect)
    initial = nodes[0]["children"][0]["info"]["virtual-size"]
    H.F.B.validate_empty_overlay(inspect, initial)
    image = output / "overlay.qcow2"
    _, child = C.read(image, H.WRITER_CAP, report["overlay"], collect=False)
    H.F.K.inspect_overlay(image, child, "/inputs/scratch.raw", "raw")
    peak = report["allocation_peak"]
    caps = {"tree_allocated": policy["watched_tree"][1], "overlay_allocated": H.WRITER_CAP,
            "overlay_eof": H.WRITER_CAP, "result_allocated": H.RESULT_BYTES}
    C.need(peak.keys() == caps.keys() | {"free"}
           and all(type(peak[key]) is int and 0 < peak[key] <= cap for key, cap in caps.items())
           and peak["tree_allocated"] >= max(peak["overlay_allocated"], peak["result_allocated"])
           and type(peak["free"]) is int and peak["free"] >= policy["watched_tree"][2]
           and initial < child["bytes"] <= peak["overlay_eof"], "Original installed child or allocation differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for leaf in ("media", "site", "retirement"):
        parser.add_argument("--" + leaf, type=Path, required=True)
        parser.add_argument("--" + leaf + "-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    args = parser.parse_args()
    try:
        sys.addaudithook(C.audit_fence)
        sys.stdout.buffer.write(C.wire(readback(args.media, args.media_sha256, args.site, args.site_sha256,
                                               args.authority_sha256, args.retirement, args.retirement_sha256)))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
        sys.exit("Qtbase installed result readback refused")


if __name__ == "__main__":
    main()
