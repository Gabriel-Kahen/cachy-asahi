# SPDX-License-Identifier: MIT
"""Project the exact held 629 selection and a separately reviewed TEST role."""

from itertools import islice
from pathlib import Path
import re

KIND = "ASAHI629_DISPOSABLE_TRANSPORT_V1"
TEST_REVIEW_KIND = "ASAHI629_EXACT_PREVIEW_TEST_REVIEW_V1"
TRUST_ALLOWANCE = 5820
PLAN_LIMIT = 512 * 1024
SIZE = 16 * 1024**3
IN = Path("/trial-inputs")
TARGET = Path("/trial-scratch")
WORK = Path("/trial-work")
UUID = "725346d2-f127-47bc-b464-9dd46155e8d6"
SEED = dict(bytes=3680501760, sha256="76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db")
GEOMETRY = dict(bytes=SEED["bytes"], block_size=4096, free_bytes=514011136, uuid=UUID)
RUNTIME = {
    "base-repository/repo/python-3.14.8-1-aarch64.pkg.tar.xz":
        dict(bytes=13588352, sha256="5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984"),
    "base-repository/repo/mpdecimal-4.0.1-3-aarch64.pkg.tar.xz":
        dict(bytes=93808, sha256="388611eba7f9b0dddcc03adb4f28bcb8fd2c42fbd8c930ca6b9b0f9e4ece0f1e"),
}
REFS = {
    "baseline.lock": (261, 5104, "279fba6cfd35bee27b8ba2d42337bd51be8258ed137e3b814b2a18e1bda4f34d"),
    "forward.lock": (629, 12346, "79d123ff09023cf96b7a6523f27fd36294b92779f043fff6ac9c40912e28fe95"),
    "rollback.lock": (629, 12346, "f335e8430a1d6f8463e95e16524cf78fc224c24fb31cf8717723370490bae9fa"),
    "forward-preview.lock": (371, 7296, "58e3f6ad10cef5dc8ab5cac8bc90b53a3cb2a2b14cd326cc67d5ac574276c445"),
    "rollback-preview.lock": (3, 54, "8acb5bd24b577522253d6618ddbb821a0b3c35bd6422366714846f34ecc635be"),
}
REVERSED = {
    "networkmanager": ("1.58.1-1", "1.58.1-2"),
    "perl": ("5.42.2-2", "5.42.3-1"),
    "python": ("3.14.7-1", "3.14.8-1"),
}
PROJECTS = {
    "cachy-asahi-first-login": "0.1.0-3",
    "cachy-asahi-fish-config": "0.1.0-2",
    "cachy-asahi-hyprland-settings": "0.1.0-3",
    "cachy-asahi-setup": "0.3.0-1",
    "cachy-asahi-zsh-config": "0.1.0-1",
}
PREFLIGHT = "evidence/archive-and-certificate-preflight.json"
OWNERSHIP = "evidence/ownership.json"
ORIGINAL = "evidence/r132-transport-manifest.json"
PROVENANCE = {
    PREFLIGHT: dict(bytes=208738, sha256="0ff4c9cb9679525c3aa982d9bfc06106c208f876ba6c07581fb0c12413e92793"),
    OWNERSHIP: dict(bytes=142491, sha256="6afb50be120c9bc831184b68c872210776560f0b371f760b6483ebdbf9dae686"),
    ORIGINAL: dict(bytes=197340, sha256="08a1f949794b085158608c9577476574514fa963a8168554ca523c2242f35178"),
    "evidence/selection.json": dict(bytes=1787, sha256="aeb0536068e09140bbf577ee36beec960520ca4415f095c30d77379bc2302cfc"),
    "evidence/inventory.json": dict(bytes=1366008, sha256="077a3f89121fbdc4659c1b42666e054bb1e87bf462626530aeff96bd92253f79"),
    "evidence/prior-inventory.json": dict(bytes=1359833, sha256="24855027b3a138382bda9e862b94a21cf478490fb456232641e4f820fa22f9dd"),
    "evidence/proposal.json": dict(bytes=2524, sha256="f328dfc93c15c52b525a66abbfd2bdaeb16a4bc939d0a1789f64670516cec8d0"),
    "evidence/preview-archive-source-joins.json": dict(bytes=4845, sha256="4517e48eb55f2077cba2be53536d42550965626f2fb59d494123d56a67e42b40"),
}
REVIEW = "evidence/test-review.json"
TEST_KEY = "keys/preview-test.gpg"
KEY_IDS = {"alarm", "community", "preview-test"}
HISTORICAL_TEST = {
    "3F31C957865CD10AF794C90D177CA1397E0C5806",
    "B2FF1CB3893EF0B7CE42081CB32824D914A38770",
    "C908F19D5618FE95F08864A8E397439FC7A7980D",
}
PHASES = {"forward": 371, "rollback": 3}


def relative(T, name):
    T.need(type(name) is str and all(T.NAME.fullmatch(part) and part not in (".", "..") for part in name.split("/")),
           "Finite relative media path required")
    return Path(name)


def valid_pin(T, ref, maximum):
    return (type(ref) is dict and set(ref) == {"bytes", "sha256"} and type(ref["bytes"]) is int
            and 0 < ref["bytes"] <= maximum and type(ref["sha256"]) is str and T.HEX.fullmatch(ref["sha256"]))


def pin(ref):
    return {name: ref[name] for name in ("bytes", "sha256")}


def lock_ref(name):
    _, size, sha256 = REFS[name]
    return dict(bytes=size, sha256=sha256)


def locks(T, root):
    return {name: T.canonical_lock(T.read(root / name, lock_ref(name), cap=64 * 1024), count)
            for name, (count, _, _) in REFS.items()}


def check_delta(T, rows):
    T.need(set(rows) == set(REFS), "Exact five inventory and preview locks required")
    before, forward, rollback = (rows[name + ".lock"] for name in ("baseline", "forward", "rollback"))
    additions, replacements = (rows[name + "-preview.lock"] for name in PHASES)
    T.need(all(len(rows[name]) == count for name, (count, _, _) in REFS.items())
           and before | additions == forward and forward | replacements == rollback
           and set(before) & set(additions) == set(replacements) == set(REVERSED)
           and all((before[name], forward[name]) == versions and before[name] == replacements[name]
                   for name, versions in REVERSED.items())
           and all(forward.get(name) == rollback.get(name) == version for name, version in PROJECTS.items()),
           "Exact 261/629/629 selection and three inverse versions required")


def test_window(T, key):
    T.need(type(key["not_before"]) is type(key["not_after"]) is int
           and 0 < key["not_before"] < key["not_after"] and
           key["not_before"] + TRUST_ALLOWANCE < key["not_after"],
           "A finite TEST certificate interval covering the rehearsal is required")


def check_current_trust(T, value, now):
    key = value["keys"]["preview-test"]
    test_window(T, key)
    T.need(type(now) is int and key["not_before"] <= now and now + TRUST_ALLOWANCE < key["not_after"],
           "Current TEST trust does not cover the full 629 rehearsal allowance")


def decode_review(T, raw, project_archives, vendor_fingerprints):
    review = T.decode(raw)
    T.need(T.encoded(review) == raw and set(review) == {
        "kind", "issuer", "scope", "approval_status", "provenance", "key", "operands"
    } and review["kind"] == TEST_REVIEW_KIND and review["issuer"] == "Root"
           and review["scope"] == "project-test" and review["approval_status"] == "UNAPPROVED"
           and review["provenance"] == PROVENANCE,
           "Exact Root-reviewed 629 TEST-only selection required")
    key = review["key"]
    T.need(set(key) == {"fingerprint", "certificate", "not_before", "not_after"}
           and re.fullmatch("[A-F0-9]{40}", key["fingerprint"])
           and key["fingerprint"] not in HISTORICAL_TEST | vendor_fingerprints
           and valid_pin(T, key["certificate"], 64 * 1024),
           "Distinct current project TEST certificate required")
    test_window(T, key)
    T.need(set(review["operands"]) == set(project_archives)
           and all(set(row) == {"archive", "signature"} and row["archive"] == project_archives[name]
                   and valid_pin(T, row["signature"], 64 * 1024) for name, row in review["operands"].items()),
           "Reviewed detached signatures must cover all five exact project archive bodies")
    return review


def build_manifest(T, preflight, ownership, original, review_raw):
    """Derive selection from the independently pinned run records each time."""
    files = PROVENANCE | RUNTIME | {name: lock_ref(name) for name in REFS}
    vendor_keys = {name: original["keys"][name] for name in ("alarm", "community")}
    vendor_fingerprints = {key["fingerprint"] for key in vendor_keys.values()}
    files.update({key["file"]: original["files"][key["file"]] for key in vendor_keys.values()})
    rows = {(record["phase"], record["name"]): record for record in preflight["package_rows"]}
    projects = {row["name"]: row for row in ownership["projects"]}
    vendor = {(row["phase"], row["name"]): row for row in ownership["vendor_archives"]}
    T.need(len(rows) == len(preflight["package_rows"]) == 374
           and set(projects) == set(PROJECTS) and set(vendor) == set(rows) - {("forward", n) for n in PROJECTS}
           and ownership["seed_pin"] == SEED and ownership["profile_pin"] == PROVENANCE[PREFLIGHT]
           and ownership["status"] == "PASS_BOUNDED_PROJECT_PATH_COMPARISON",
           "Complete joined archive and seed ownership provenance required")
    review = decode_review(T, review_raw, {n: projects[n]["pin"] for n in PROJECTS}, vendor_fingerprints)
    key = review["key"]
    files[REVIEW] = T.pin(review_raw)
    files[TEST_KEY] = key["certificate"]
    keys = vendor_keys | {"preview-test": dict(file=TEST_KEY, scope="project-test", fingerprint=key["fingerprint"],
                                              not_before=key["not_before"], not_after=key["not_after"])}
    packages = {phase: {} for phase in PHASES}
    for (phase, name), row in sorted(rows.items()):
        archive_pin = row["archive_pin"]
        if phase == "forward" and name in PROJECTS:
            source = projects[name]
            signature = review["operands"][name]["signature"]
            leaf = phase + "/" + source["archive"]
            signer, scope = key["fingerprint"], "project-test"
            T.need(source["pin"] == archive_pin and Path(row["archive"]).name == source["archive"]
                   and source["version"] == row["version"] == PROJECTS[name],
                   "Project archive source and path-ownership records differ")
        else:
            source = vendor[(phase, name)]
            leaf = row["archive"]
            signature, signer, scope = row["signature_pin"], row["signer"], "vendor"
            expected = dict(archive=leaf, signer=signer, scope=scope)
            T.need(original["packages"][phase][name] == expected and original["files"][leaf] == archive_pin
                   and original["files"][leaf + ".sig"] == signature
                   and source["pin"] == archive_pin and source["version"] == row["version"]
                   and source["archive"] == Path(leaf).name and not source["path_overlaps"],
                   "Vendor archive, signature and path-ownership records differ")
        files.update({leaf: archive_pin, leaf + ".sig": signature})
        packages[phase][name] = dict(archive=leaf, signer=signer, scope=scope)
    value = dict(kind=KIND, approval_status="UNAPPROVED", Root_acceptance=None, seed=SEED, geometry=GEOMETRY,
                 preflight=PROVENANCE[PREFLIGHT], test_review=files[REVIEW], packages=packages, keys=keys, files=files)
    check_manifest(T, value)
    return value


def check_manifest(T, value):
    T.need(set(value) == {"kind", "approval_status", "Root_acceptance", "seed", "geometry", "preflight", "test_review",
                          "packages", "keys", "files"} and value["kind"] == KIND
           and value["approval_status"] == "UNAPPROVED" and value["Root_acceptance"] is None
           and value["seed"] == SEED and value["geometry"] == GEOMETRY and value["preflight"] == PROVENANCE[PREFLIGHT],
           "Exact unapproved 629 transport profile required")
    keys = value["keys"]
    T.need(set(keys) == KEY_IDS and all(re.fullmatch("[A-F0-9]{40}", row["fingerprint"]) for row in keys.values())
           and len({row["fingerprint"] for row in keys.values()}) == len(keys),
           "Three distinct public rehearsal roles required")
    test_window(T, keys["preview-test"])
    for name, key in keys.items():
        test = name == "preview-test"
        expected_fields = {"file", "fingerprint", "scope"} | ({"not_before", "not_after"} if test else set())
        T.need(set(key) == expected_fields and key["file"] == "keys/" + name + ".gpg"
               and key["scope"] == ("project-test" if test else "vendor"), "Exact disjoint certificate roles required")
    fixed = PROVENANCE | RUNTIME | {name: lock_ref(name) for name in REFS}
    files = value["files"]
    T.need(all(files[name] == pin for name, pin in fixed.items()) and files[REVIEW] == value["test_review"]
           and valid_pin(T, value["test_review"], 64 * 1024), "Exact staged provenance and runtime required")
    expected = set(fixed) | {REVIEW} | {row["file"] for row in keys.values()}
    T.need(set(value["packages"]) == set(PHASES), "Exact forward and rollback phases required")
    vendor_fingerprints = {keys[name]["fingerprint"] for name in ("alarm", "community")}
    for phase, count in PHASES.items():
        packages = value["packages"][phase]
        T.need(len(packages) == count, "Exact phase archive count required")
        for name, row in packages.items():
            file = relative(T, row["archive"])
            project = phase == "forward" and name in PROJECTS
            signers = {keys["preview-test"]["fingerprint"]} if project else vendor_fingerprints
            T.need(set(row) == {"archive", "scope", "signer"} and file.parent == Path(phase)
                   and file.name.startswith(name + "-") and str(file) not in expected and row["signer"] in signers
                   and row["scope"] == ("project-test" if project else "vendor"), "Archive signer scope or path differs")
            expected.update((str(file), str(file) + ".sig"))
    T.need(set(PROJECTS) <= set(value["packages"]["forward"])
           and set(value["packages"]["rollback"]) == set(REVERSED)
           and set(files) == expected and len(files) == 767, "Exact media file selection required")
    for name, ref in files.items():
        relative(T, name)
        T.need(valid_pin(T, ref, 512 * 1024**2), "Finite media file pin required")
    T.need(sum(ref["bytes"] for ref in files.values()) < 1024**3, "629 media budget exceeded")


def project(T, preflight_dir, ownership_receipt, original_transport, test_review, test_review_sha256, test_inputs):
    """Return the manifest and exact public source references for passive copying."""
    preflight_path = preflight_dir / Path(PREFLIGHT).name
    preflight = T.decode(T.read(preflight_path, PROVENANCE[PREFLIGHT]))
    ownership = T.decode(T.read(ownership_receipt, PROVENANCE[OWNERSHIP]))
    original_path = original_transport / "manifest.json"
    original = T.decode(T.read(original_path, PROVENANCE[ORIGINAL]))
    review_raw = T.read(test_review, cap=64 * 1024)
    T.need(T.pin(review_raw)["sha256"] == test_review_sha256, "Reviewed TEST document hash differs")
    value = build_manifest(T, preflight, ownership, original, review_raw)
    composition_dir = Path(preflight["inventory"]["path"]).parents[2]
    paths = {
        PREFLIGHT: preflight_path, OWNERSHIP: ownership_receipt, ORIGINAL: original_path, REVIEW: test_review,
        "evidence/selection.json": composition_dir / "qt-alternative-preview1-selection.ACTUAL.json",
        "evidence/preview-archive-source-joins.json": composition_dir / "preview1-archive-source-joins.ACTUAL.json",
        "evidence/inventory.json": Path(preflight["inventory"]["path"]),
        "evidence/prior-inventory.json": Path(preflight["prior_inventory"]["path"]),
        "evidence/proposal.json": Path(preflight["proposal"]["path"]),
        TEST_KEY: test_inputs / Path(TEST_KEY).name,
    }
    for row in preflight["package_rows"]:
        if row["scope"] == "vendor":
            continue
        name = row["name"]
        leaf = value["packages"]["forward"][name]["archive"]
        paths[leaf] = Path(row["source_archive"])
        paths[leaf + ".sig"] = test_inputs / (Path(leaf).name + ".sig")
    expected_test = {paths[TEST_KEY].name} | {path.name for leaf, path in paths.items() if leaf.startswith("forward/") and leaf.endswith(".sig")}
    T.need({node.name for node in islice(test_inputs.iterdir(), len(expected_test) + 1)} == expected_test,
           "TEST input directory must contain exactly five signatures and one public certificate")
    for name in REFS:
        if name not in ("baseline.lock", "rollback-preview.lock"):
            paths[name] = preflight_dir / name.replace(".lock", ".projected.lock")
    return value, {name: dict(pin, path=str(paths.get(name, original_transport / name)))
                   for name, pin in value["files"].items()}


def rehash(T, root, value, observed=None):
    check_manifest(T, value)
    files = value["files"] | {"manifest.json": T.pin(T.encoded(value))}
    directories = {str(parent) for name in files for parent in Path(name).parents if parent != Path(".")}
    nodes = list(islice(root.rglob("*"), 2048))
    T.need(len(nodes) == len(files) + len(directories)
           and all(not path.is_symlink() and ((str(path.relative_to(root)) in directories and path.is_dir())
                   or (str(path.relative_to(root)) in files and path.is_file())) for path in nodes),
           "Exact ordinary media path census required")
    for name, ref in files.items():
        T.read(root / name, ref, collect=False, observed=observed)
    raw = {name: T.read(root / name, files[name], observed=observed)
           for name in (PREFLIGHT, OWNERSHIP, ORIGINAL, REVIEW)}
    expected = build_manifest(T, *(T.decode(raw[name]) for name in (PREFLIGHT, OWNERSHIP, ORIGINAL)), raw[REVIEW])
    T.need(value == expected, "Staged media diverges from reviewed provenance and TEST selection")
    inventory = locks(T, root)
    check_delta(T, inventory)
    for phase, packages in value["packages"].items():
        preview = inventory[phase + "-preview.lock"]
        T.need(set(packages) == set(preview) and all(
            any(re.fullmatch(re.escape(name + "-" + version) + r"-(?:aarch64|any)\.pkg\.tar\.(?:xz|zst)",
                             Path(packages[name]["archive"]).name)
                for version in {preview[name], preview[name].split(":", 1)[-1]}) for name in preview),
            "Exact locked name, version and archive architecture required")
