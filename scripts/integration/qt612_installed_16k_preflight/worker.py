# SPDX-License-Identifier: MIT
"""Drive the exact installed Qtbase lifecycle through an admitted guest supervisor.

No command, filesystem capture, or signing operation has a default executor.
The supervisor owns the guest boundary, signed package custody, process groups,
and separate evidence from the positive and negative clones.
"""

from pathlib import Path, PurePosixPath
import re
from runpy import run_path
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
P = SimpleNamespace(**run_path(str(HERE / "preflight.py")))
T = P.T
L = SimpleNamespace(**run_path(str(P.PROJECT / "llhttp_overlay583/operands.py")))
F = SimpleNamespace(**run_path(str(P.PROJECT / "fish_config_overlay583/guest.py")))
GPGDIR = P.WORK + "/gnupg"
GPG = ["/usr/bin/gpg", "--batch", "--no-options", "--homedir", GPGDIR]
RETIRE = ["/usr/bin/gpgconf", "--homedir", GPGDIR, "--kill", "all"]
NORMAL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GNUPGHOME": GPGDIR}
MAX_STREAMS = 8 << 20
MAX_SELECTION = 16 << 20
OFFSCREEN = "/usr/lib/qt6/plugins/platforms/libqoffscreen.so"
VERSION_REFUSAL = b"qt6-base=6.12.0-3\n"
INPUT_LIMITS = {"archive": 512 << 20, "certificate": 128 << 10, "signature": 32 << 10}


def pin_shape(pin, maximum, *, minimum=1):
    T.need(type(pin) is dict and pin.keys() == {"bytes", "sha256"}
           and type(pin["bytes"]) is int and minimum <= pin["bytes"] <= maximum
           and isinstance(pin["sha256"], str) and T.HEX.fullmatch(pin["sha256"]),
           "Exact bounded input pin required")


def read_plan(raw, sha, inventory):
    T.need(type(raw) is bytes and 0 < len(raw) <= 64 << 10 and T.pin(raw)["sha256"] == sha,
           "Exact externally selected install plan required")
    plan = T.decode(raw)
    baseline = plan["baseline"]
    pins = {"inventory": P.Q3_INVENTORY, "scratch": P.Q3_SCRATCH, "terminal": P.Q3_TERMINAL}
    T.need(baseline.keys() == pins.keys(), "Exact Q3 plan operands required")
    for name, pin in pins.items():
        path = baseline[name]["path"]
        value = PurePosixPath(path)
        T.need(value.is_absolute() and path == str(value) and not path.startswith("//")
               and ".." not in value.parts and baseline[name] == pin | {"path": path},
               "Exact Q3 operand reference required")
    plan = P.make_plan(inventory, plan["nonce"], baseline, P.recipe_inputs())
    T.need(T.encoded(plan) == raw, "Installed Qtbase plan differs from its original source")
    return plan


def read_selection(raw, expected_sha, plan_sha, now):
    T.need(type(raw) is bytes and 0 < len(raw) <= MAX_SELECTION and T.pin(raw)["sha256"] == expected_sha,
           "Exact admitted actor selection required")
    selection = T.decode(raw)
    T.need(T.encoded(selection) == raw and selection.keys() ==
           {"kind", "plan_sha256", "packaging_receipt", "key", "inputs", "payload", "providers"},
           "Exact installed-trial selection fields required")
    T.need(selection["kind"] == "QTBASE16K_INSTALLED_GUEST_SELECTION_V1" and selection["plan_sha256"] == plan_sha
           and L.valid_key(selection["key"], now), "Current dedicated public TEST signer and selected plan required")
    pin_shape(selection["packaging_receipt"], 256 << 10)
    T.need(selection["inputs"].keys() == INPUT_LIMITS.keys(), "Complete archive and signature input set required")
    for name, maximum in INPUT_LIMITS.items():
        pin_shape(selection["inputs"][name], maximum)
    return selection


def payload_requirements(plan):
    package = plan["package"]
    symlinks = {}
    libraries = {}
    for soname in package["sonames"]:
        alias = "/usr/lib/" + soname
        base = alias.removesuffix(".6")
        full = alias + ".12.0"
        libraries[soname] = full
        symlinks[alias] = PurePosixPath(full).name
        symlinks[base] = soname
    return libraries, symlinks, set(package["plugins"] + package["tools"]) | set(libraries.values())


def check_payload_selection(plan, payload):
    _, symlinks, files = payload_requirements(plan)
    T.need(type(payload) is dict and 0 < len(payload) <= 32768 and (files | symlinks.keys()) <= payload.keys(),
           "Complete installed Qtbase payload list required")
    for path, row in payload.items():
        value = PurePosixPath(path)
        T.need(path == str(value) and path.startswith("/usr/") and ".." not in value.parts
               and len(path) <= 1024 and all(32 <= ord(ch) < 127 for ch in path)
               and row["owner"] == P.M.PACKAGE, "Expected selected package-owned payload path")
        kind = row["type"]
        if kind == "file":
            T.need(row.keys() == {"type", "owner", "pin"}, "Exact installed file fields required")
            pin_shape(row["pin"], 128 << 20, minimum=0)
        else:
            T.need(kind == "symlink" and row.keys() == {"type", "owner", "target"}
                   and type(row["target"]) is str and 0 < len(row["target"]) <= 1024
                   and all(32 <= ord(ch) < 127 for ch in row["target"]), "Expected exact installed symlink")
    T.need(all(payload[path]["type"] == "file" for path in files)
           and all(payload[path] == dict(type="symlink", owner=P.M.PACKAGE, target=target)
                   for path, target in symlinks.items()), "Expected exact regular Qt libraries, tools, plugins and aliases")


def check_provider_selection(inventory, providers):
    packages = T.canonical_lock(inventory, 356)
    T.need(type(providers) is dict and 0 < len(providers) <= 512, "Finite signed provider closure required")
    for path, row in providers.items():
        value = PurePosixPath(path)
        T.need(path == str(value) and path.startswith("/usr/lib/") and ".." not in value.parts
               and len(path) <= 1024 and all(32 <= ord(ch) < 127 for ch in path)
               and row.keys() == {"owner", "version", "pin"} and row["owner"] in packages
               and row["version"] == packages[row["owner"]], "Expected unchanged Q3 provider ownership and version")
        pin_shape(row["pin"], 128 << 20)


def command(run, role, argv, *, timeout=90, accepted=(0,), data=None, env=None):
    response = run(role, argv, timeout=timeout, stdin=data, env=NORMAL_ENV.copy() if env is None else env.copy())
    T.need(response.keys() == {"exit_code", "stdout", "stderr", "natural", "group_empty", "overflow"}
           and type(response["exit_code"]) is int and response["exit_code"] in accepted
           and response["natural"] is response["group_empty"] is True and response["overflow"] is False
           and type(response["stdout"]) is type(response["stderr"]) is bytes
           and len(response["stdout"]) + len(response["stderr"]) <= MAX_STREAMS,
           "Missing bounded original command and cleanup: " + role)
    T.need(not T.HOOK_FAILURE.search(response["stderr"]), "Reported ALPM hook failure: " + role)
    return response


def stopped_database(target):
    """Read the existing bounded ALPM byte map for a retired 356-package clone."""
    return T.local_database_snapshot(target / "var/lib/pacman/local", count=356)


def check_view(plan, stage, payload, providers, observation, baseline=None):
    installed = stage["state"] == "installed"
    base_sonames = {name: None for name in plan["package"]["sonames"]}
    T.need(observation.keys() == {"protected", "database", "payload", "sonames", "offscreen", "providers"}
           and type(observation["protected"]) is bytes and 0 < len(observation["protected"]) <= 16 << 20,
           "Complete protected-data, payload and loader observations required")
    if baseline is not None:
        T.need(observation["protected"] == baseline["protected"], "Protected user or platform data changed")
    if installed:
        libraries, _, _ = payload_requirements(plan)
        maps = {name: dict(path=path, **payload[path]["pin"]) for name, path in libraries.items()}
        expected_plugin = dict(path=OFFSCREEN, **payload[OFFSCREEN]["pin"])
        T.need(observation["payload"] == payload and observation["sonames"] == maps
               and observation["offscreen"] == expected_plugin and observation["database"] is None
               and observation["providers"] == providers,
               "Exact installed payload and normal loader mapping required")
    else:
        T.need(observation["payload"] == {} and observation["sonames"] == base_sonames
               and observation["offscreen"] is None and observation["providers"] == {}
               and type(observation["database"]) is bytes and 0 < len(observation["database"]) <= 128 << 20
               and (baseline is None or observation["database"] == baseline["database"]),
               "Exact baseline local database and absence of installed Qt payload/loaders required")


def exercise(plan_raw, plan_sha, inventory, selection_raw, selection_sha, *, now, config_raw, input_pins,
             certificate_raw, signature_raw, verify_boundary, run, observe):
    """Exercise model or admitted-guest callbacks. Neither callback is supplied here."""
    plan = read_plan(plan_raw, plan_sha, inventory)
    selection = read_selection(selection_raw, selection_sha, plan_sha, now)
    payload, key = selection["payload"], selection["key"]
    check_payload_selection(plan, payload)
    providers = selection["providers"]
    check_provider_selection(inventory, providers)
    T.need(input_pins == selection["inputs"] and config_raw == P.CONFIG.encode(),
           "Exact signed staged inputs and private Required TrustedOnly policy required")
    T.need(type(certificate_raw) is bytes and len(certificate_raw) <= INPUT_LIMITS["certificate"]
           and T.pin(certificate_raw) == input_pins["certificate"] and L.packet_tags(certificate_raw) == [6, 13, 2]
           and type(signature_raw) is bytes and len(signature_raw) <= INPUT_LIMITS["signature"]
           and T.pin(signature_raw) == input_pins["signature"] and L.packet_tags(signature_raw) == [2],
           "Only the exact public TEST certificate and detached signature may enter the guest")
    T.need(verify_boundary(plan["nonce"], plan["guest"]) is True,
           "Exact isolated AArch64 16 KiB guest boundary required")
    manager = plan["package_manager"]
    calls = []

    def call(role, argv, **kwargs):
        row = command(run, role, argv, **kwargs)
        calls.append(dict(role=role, argv=argv, exit_code=row["exit_code"],
                          stdout=T.pin(row["stdout"]), stderr=T.pin(row["stderr"])))
        return row["stdout"]

    def check_stage(stage, baseline=None):
        role = stage["name"]
        current = T.sorted_rows(call(role + "-inventory", stage["inventory_query"]))
        T.need(T.pin(current) == stage["inventory"], "Unexpected inventory: " + role)
        call(role + "-database", stage["database_check"])
        if stage["state"] == "installed":
            call(role + "-payload", stage["payload_check"])
            T.need(call(role + "-dependencies", stage["dependency_check"]) == b"", "Installed Qt dependencies differ")
            refusal = call(role + "-official-version", stage["version_refusal"], accepted=(1, 127))
            T.need(refusal == VERSION_REFUSAL, "Official exact dependency must be unresolved")
            consumer = plan["consumer"]
            steps = ("configure", "build", "run") if role == "install" else ("run",)
            for step in steps:
                stdout = call(role + "-consumer-" + step, consumer[step], timeout=600, env=consumer["environment"])
            T.need(stdout.splitlines().count(consumer["marker"].encode()) == 1, "Expected exact installed offscreen API marker")
        sight = observe(role)
        check_view(plan, stage, payload, providers, sight, baseline)
        return sight

    before, *next_stages = plan["stages"]
    baseline = check_stage(before)
    primary = None
    try:
        shown = call("test-certificate", GPG + ["--with-colons", "--show-keys", "--", P.CERT])
        F.test_key(T, shown, key["fingerprint"], now)
        call("key-import", GPG + ["--import", "--", P.CERT])
        checked = call("signature", GPG + ["--status-fd", "1", "--verify", "--", P.ARCHIVE + ".sig", P.ARCHIVE])
        T.need(L.signed(checked, key), "Exact current selected TEST signature required")
        call("key-trust", GPG + ["--import-ownertrust"], data=(key["fingerprint"] + ":6:\n").encode())
        T.need(call("base-dependencies", manager["installed_dependency_preflight"]) == b"", "Q3 dependencies not satisfied")
        for stage in next_stages:
            role = stage["name"]
            if stage["state"] == "installed":
                expect = (manager["prepare_expected"] + "\n").encode()
                T.need(call(role + "-prepare", manager["prepare_addition"]) == expect, "Exactly one Qtbase package expected")
            call(role + "-mutation", stage["mutation"], timeout=240)
            check_stage(stage, baseline)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            call("trust-retirement", RETIRE)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note("Owned TEST trust retirement also failed: " + str(error))
    return dict(status="LIFECYCLE_CALLBACKS_VERIFIED_ONLY", plan_sha256=plan_sha, selection_sha256=selection_sha,
                timeline=calls, negatives="SEPARATE_CLONES_REQUIRED", physical_M2="NOT_RUN")


def review_negatives(plan, selection, baseline_database, main_clone, rows):
    """Require distinct sibling ALPM refusal receipts and exact local DB equality."""
    T.need(type(rows) is dict and rows.keys() == plan["negative_trials"].keys(),
           "Both sibling signature-refusal trials required")
    clones = {main_clone}
    for role, row in rows.items():
        T.need(row.keys() == {"clone", "scratch", "configuration", "archive", "signature", "argv", "exit_code",
                              "natural", "group_empty", "stderr", "database_before", "database_after"}
               and type(row["clone"]) is str and re.fullmatch("[0-9a-f]{32}", row["clone"])
               and row["clone"] not in clones and row["scratch"] == P.Q3_SCRATCH
               and row["configuration"] == T.pin(P.CONFIG.encode())
               and row["archive"] == selection["inputs"]["archive"]
               and row["argv"] == plan["negative_trials"][role]["command"]
               and type(row["exit_code"]) is int and row["exit_code"] == 1
               and row["natural"] is row["group_empty"] is True
               and row["database_before"] == row["database_after"] == baseline_database,
               "Exact offline sibling refusal and clean database required: " + role)
        clones.add(row["clone"])
        pin_shape(row["signature"], INPUT_LIMITS["signature"])
        stderr = row["stderr"]
        T.need(type(stderr) is bytes and 0 < len(stderr) <= MAX_STREAMS and not T.HOOK_FAILURE.search(stderr),
               "Finite original ALPM diagnostic required")
        signature = selection["inputs"]["signature"]
        if role == "tampered_signature":
            T.need(row["signature"]["bytes"] == signature["bytes"] and row["signature"] != signature
                   and b"invalid or corrupted package (PGP signature)" in stderr,
                   "Expected invalid detached-signature refusal")
        else:
            T.need(row["signature"] == signature
                   and (b"required key missing from keyring" in stderr or b"is unknown trust" in stderr),
                   "Expected the selected signature to be refused without its TEST key")
    return dict(status="SIG_REFUSALS_REVIEWED_ONLY", siblings=sorted(clones - {main_clone}))
