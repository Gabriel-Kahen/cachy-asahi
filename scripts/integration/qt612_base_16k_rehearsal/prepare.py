# SPDX-License-Identifier: MIT
"""Verify and optionally copy the accepted offline Qt6-base rehearsal operands."""
import argparse
import io
import json
from pathlib import Path
import re
import sys
import tarfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from support import O, T, checked, entry, pair, put_json, put_text

PLAN_NAME = "plan.json"
REQUEST_KIND = "QTBASE_16K_PREPARATION_REQUEST_V1"
REQUEST_FIELDS = ("proposal", "provider", "source_map", "original")
OFFICIAL_SIGNER = "68B3537F39A313B3E574D06777193F152BDBE6A6"
OFFICIAL_KEYRING = {"archlinuxarm.gpg", "archlinuxarm-trusted", "archlinuxarm-revoked"}
MD4C = "md4c-0.5.3-1-aarch64.pkg.tar.xz"
QT_ARCHIVE = "qtbase-everywhere-src-6.12.0.tar.xz"
PACKAGE = re.compile(r"[A-Za-z0-9._+:@~-]+\.pkg\.tar\.xz")
HOOK = re.compile(r"[A-Za-z0-9_.@+-]+\.hook")
DEP = re.compile(r"[A-Za-z0-9._+@:-]+(?:[<>=]{1,2}[A-Za-z0-9._+:~-]+)?")


def read_json(ref):
    return T.decode(checked(Path(ref["path"]), pair(ref)))


def input_ref(value, limit):
    T.need(type(value) is dict and set(value) == {"path", "bytes", "sha256"} and
           type(value["path"]) is str, "Exact pinned absolute file reference required")
    path = O.absolute(value["path"])
    pin = pair(value)
    T.need(str(path) == value["path"] and 0 < pin["bytes"] <= limit, "Bounded canonical request input")
    return value


def read_request(path, digest):
    raw = T.read(path, cap=16 << 10)
    T.need(T.pin(raw)["sha256"] == digest, "Exact external request digest required")
    request = T.decode(raw)
    T.need(type(request) is dict and set(request) == {"kind", *REQUEST_FIELDS} and
           request["kind"] == REQUEST_KIND, "Exact Qtbase preparation request required")
    limits = dict(proposal=128 << 10, provider=1 << 20, source_map=128 << 10, original=16 << 20)
    return {key: input_ref(request[key], limits[key]) for key in REQUEST_FIELDS}


def inventory(rows, expected):
    text = "".join(f"{name} {version}\n" for name, version in rows)
    T.need(len(rows) == expected and rows == sorted(set(rows))
           and len({name for name, _ in rows}) == expected
           and all(re.fullmatch(r"[A-Za-z0-9._+@:-]+", name) and
                   re.fullmatch(r"[A-Za-z0-9._+:~-]+", version) for name, version in rows),
           "Exact canonical inventory")
    return text


def hook_name(path):
    path = path.removeprefix("./").lstrip("/")
    if path.startswith(("usr/share/libalpm/hooks/", "etc/pacman.d/hooks/")) and path.endswith(".hook"):
        name = Path(path).name
        T.need(HOOK.fullmatch(name), "Literal hook mask name")
        return name
    return None


def hook_masks(original, basenames, additions):
    leaves = {"evidence/bootstrap/package-audit.json", "evidence/bootstrap/rootfs-hooks.json"}
    with tarfile.open(fileobj=io.BytesIO(checked(Path(original["path"]), pair(original))), mode="r:gz") as archive:
        wanted, total = {}, 0
        for index, member in enumerate(archive, 1):
            total += member.size
            T.need(index <= 4096 and total <= 64 << 20, "Finite original public evidence archive")
            leaf = "/".join(member.name.split("/")[1:])
            if leaf in leaves:
                T.need(leaf not in wanted and member.isfile() and 0 < member.size <= 12 << 20,
                       "Unique bounded original hook-audit operands required")
                wanted[leaf] = member
        T.need(wanted.keys() == leaves, "Both original hook-audit operands required")
        reports = [T.decode(archive.extractfile(wanted["evidence/bootstrap/" + name]).read())
                   for name in ("package-audit.json", "rootfs-hooks.json")]
    audit, masks = reports
    T.need(len(audit) == len(basenames) == 256 and set(audit) == basenames and
           all(HOOK.fullmatch(name) for name in masks), "Original signed baseline hook collection")
    result = set(masks)
    for item in audit.values():
        result.update(name for path in item["installed_paths"] if (name := hook_name(path)))
    for ref in additions:
        pin = pair(ref)
        T.need(0 < pin["bytes"] <= 128 << 20, "Finite compressed Qt addition archive")
        raw = checked(Path(ref["path"]), pin)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
            total = 0
            for count, member in enumerate(archive, 1):
                total += member.size
                T.need(count <= 50000 and total <= 128 << 20, "Finite Qt addition tar")
                if name := hook_name(member.name):
                    result.add(name)
    return "".join(name + "\n" for name in sorted(result))


def select(request):
    files = {}

    def include(name, path, pin=None):
        T.need(name not in files, "Duplicate staged file")
        files[name] = entry(path, pin)

    proposal = read_json(request["proposal"])
    provider_data = read_json(request["provider"])
    source = Path(request["source_map"]["path"]).parent
    mapping = read_json(request["source_map"])
    selector = {key: request["source_map"][key] for key in ("path", "sha256")}
    T.need(proposal["source_map"] == selector and proposal["component"] == "gui_server" and
           proposal["Root_Qt_authority"] is None and proposal["ALPM_transaction"] == "NOT_RUN" and
           proposal["baseline_inventory"] == 349 and proposal["expected_inventory"] == 356 and
           proposal["scoped_archive"] == MD4C and
           proposal["SigLevel"] == proposal["LocalFileSigLevel"] == "Required TrustedOnly",
           "Exact unissued Qtbase ALPM proposal required")
    T.need(mapping["kind"] == "QT612_COMPLETE_FAMILY_SOURCE_DATA_V1" and
           mapping["input_plan_complete"] is True and mapping["Root_acceptance"] is None and
           all(value is None for value in mapping["actual"].values()),
           "Signed unissued Qt source input closure")
    T.need(provider_data["kind"] == "VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3" and
           provider_data["complete"] is True and provider_data["verified_files"] == 517 and
           not provider_data["missing_materials"] and
           all(value is None for value in provider_data["actual"].values()) and
           provider_data["signer_fingerprint"] == OFFICIAL_SIGNER and
           tuple(len(provider_data[key]) for key in ("base_materials", "supplemental_materials", "keyring_materials"))
           == (498, 16, 3), "Complete pinned ALARM bootstrap provider")
    trust = proposal["trust"]
    signer = trust["signer"]
    T.need(set(signer) == {"created", "expires", "fingerprint", "test_only"} and
           signer["test_only"] is True and re.fullmatch(r"[0-9A-F]{40}", signer["fingerprint"]) and
           signer["fingerprint"] != OFFICIAL_SIGNER and type(signer["created"]) is type(signer["expires"]) is int and
           0 < signer["expires"] - signer["created"] <= 86400, "Distinct bounded public TEST key")
    lock = read_json(provider_data["base_lock"])
    profile = read_json(provider_data["bootstrap_profile"])
    base_names = {row["filename"] for row in lock["packages"] + profile["additions"]["rows"]}
    addition_rows = proposal["expected_archives"]
    additions = [row["archive"] for row in addition_rows.values()]
    T.need(len(additions) == 7 and len(base_names) == 256 and
           all(PACKAGE.fullmatch(name) for name in base_names) and
           addition_rows["md4c"] == trust["reference"] and addition_rows["md4c"]["filename"] == MD4C,
           "256 base and seven added signed package pairs")
    verify_locks(provider_data, proposal)
    verify_qualification(trust, request["original"])
    baseline = dict(provider_data["base_materials"], **provider_data["supplemental_materials"])
    for name in sorted(base_names):
        for leaf in (name, name + ".sig"):
            ref = baseline[leaf]
            include("alpm-base/" + leaf, Path(ref["path"]), pair(ref))
    for row in addition_rows.values():
        filename = row["filename"]
        T.need(PACKAGE.fullmatch(filename), "Literal signed addition archive name")
        for field, name in (("archive", filename), ("signature", filename + ".sig")):
            ref = row[field]
            include("alpm-add/" + name, Path(ref["path"]), pair(ref))
    official = proposal["official_baseline_public_keyring_materials"]
    T.need(official.keys() == OFFICIAL_KEYRING and official == provider_data["keyring_materials"],
           "Exact official trust inputs")
    for name, ref in official.items():
        include("official/" + name, Path(ref["path"]), pair(ref))
    for name, ref in (("rootfs.tar.gz", provider_data["rootfs"]),
                      ("rootfs.tar.gz.sig", provider_data["rootfs_signature"]),
                      ("expected349.lock", provider_data["baseline_inventory"]),
                      ("expected356.lock", proposal["expected356_lock"]),
                      ("md4c-TEST-public.gpg", trust["certificate"]),
                      ("md4c-qualification.json", trust["native_qualification"]),
                      ("md4c-TEST-verification.json", trust["test_verification"])):
        include(name, Path(ref["path"]), pair(ref))

    for name, ref in sorted(mapping["files"].items()):
        recipe = "recipes/gui_server/"
        if name.startswith(recipe):
            leaf = name.removeprefix(recipe)
            T.need(re.fullmatch(r"[A-Za-z0-9._-]+", leaf) and leaf not in (".", ".."), "Literal recipe file name")
            include("recipe/" + leaf, source / name, pair(ref))
    archive = "archives/gui_server/" + QT_ARCHIVE
    include(QT_ARCHIVE, source / archive, pair(mapping["files"][archive]))
    for name in ("alpm.sh", "configure.sh"):
        include(name, HERE / name)
    generated = {
        "alpm-primary": provider_data["signer_fingerprint"] + "\n",
        "md4c-signer": signer["fingerprint"] + "\n",
        "rootfs.expected.lock": inventory(sorted((row["name"][0], row["version"][0])
                                                for row in lock["rootfs_packages"]), 165),
        "configure-dependencies.list": dependencies(source, mapping),
        "disabled-hooks.list": hook_masks(request["original"], base_names, additions),
    }
    T.need(sum(value["bytes"] for value in files.values()) < 1850 << 20, "Fixed readonly media budget")
    # Verify all source bodies before returning a usable plan or writing a copy.
    for row in files.values():
        checked(Path(row["path"]), pair(row), collect=False)
    return files, generated, signer


def verify_qualification(trust, original):
    native_ref = input_ref(trust["native_qualification"], 64 << 10)
    signed_ref = input_ref(trust["test_verification"], 64 << 10)
    native, signed = read_json(native_ref), read_json(signed_ref)
    reference = trust["reference"]
    selected = pair(reference["archive"])
    qualification = re.fullmatch(r"CLOSED_(R[1-9][0-9]*)_MD4C_HOSTED_REPRODUCIBLE_PAIR_PASS", native["status"])
    T.need(qualification is not None and native["issuer"] == "Root" and native["native_pair"] == "PASS" and
           native["comparison"] == "PASS_BYTE_IDENTICAL" and native["builds"] == 2 and
           native["attempt"] == 1 and native["host_machine"] == "aarch64" and native["host_page_size"] == 4096 and
           native["archive"] == pair(original) and native["package"] == reference["filename"] == MD4C and
           native["package_archive"] == selected and native["release"] == "CLOSE_ONLY" and
           native["expected_packages"] == 349 and native["authenticated_inputs"] == 517 and
           all(native[key] is True for key in ("original_custody_pass", "exact_host_runner_terminal",
               "independent_finisher_replay", "owned_storage_absent", "controller_empty_twice",
               "dedicated_daemon_container_image_empty_twice", "scope_cleanup_observed")),
           "Original Root-owned two-build native md4c PASS and exact archive required")
    run = qualification[1]
    signer = trust["signer"]
    T.need(signed["issuer"] == "Root" and signed["status"] == f"PASS_MD4C_{run}_EXACT_ARCHIVES_SCOPED_TEST_ONLY" and
           signed["scope"] == f"only the pinned md4c {run} build pair" and signed["purpose"] == "offline Qt build staging" and
           signed["release"] == "CLOSE_ONLY" and signed["production"] is False and signed["private_signer_removed"] is True and
           signed["native_receipt"] == native_ref and signed["signature"] == reference["signature"] and
           signed["trust"] == trust["certificate"] and signed["fingerprint"] == signer["fingerprint"] and
           signed["created_epoch"] == signer["created"] and signed["expires_epoch"] == signer["expires"],
           "Exact Root-scoped TEST verification and independently pinned package inputs required")
    observations = signed["observations"]
    T.need(type(observations) is list and len(observations) == 2 and
           observations[0]["archive"] == reference["archive"] and
           observations[0]["archive"]["path"] != observations[1]["archive"]["path"],
           "Both independently retained md4c builds required")
    for item in observations:
        archive = input_ref(item["archive"], 128 << 20)
        path = Path(archive["path"])
        fields = item["validsig"].split()
        fp = signer["fingerprint"]
        T.need(path.name == MD4C and pair(archive) == selected and type(item["exit"]) is int and item["exit"] == 0 and
               len(fields) == 12 and fields[:3] == ["[GNUPG:]", "VALIDSIG", fp] and fields[-1] == fp and
               fields[4].isascii() and fields[4].isdecimal() and signer["created"] <= int(fields[4]) < signer["expires"],
               "Exact whole md4c archive and recorded successful TEST signature observation required")
        checked(path, selected, collect=False)


def verify_locks(provider, proposal):
    before_ref = provider["baseline_inventory"]
    after_ref = proposal["expected356_lock"]
    before = T.canonical_lock(checked(Path(before_ref["path"]), pair(before_ref)), 349)
    after = T.canonical_lock(checked(Path(after_ref["path"]), pair(after_ref)), 356)
    additions = proposal["expected_archives"]
    T.need(after == before | {name: row["version"] for name, row in additions.items()} and
           not before.keys() & additions.keys(), "Exact 349 to 356 inventory and added versions required")


def dependencies(source, mapping):
    name = "reviewed/gui_server.json"
    checked(source / name, pair(mapping["files"][name]), collect=False)
    name = "recipes/gui_server/.SRCINFO"
    raw = checked(source / name, pair(mapping["files"][name])).decode()
    result = sorted({line.split(" = ", 1)[1] for line in raw.splitlines()
                     if line.strip().startswith(("depends = ", "makedepends = ", "checkdepends = "))})
    T.need(40 <= len(result) <= 64 and all(DEP.fullmatch(line) for line in result)
           and {"md4c>=0.5.3", "md4c<0.6"} <= set(result), "Exact normal Qtbase dependency contract")
    return "".join(line + "\n" for line in result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=O.absolute, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--output", type=O.absolute)
    args = parser.parse_args()
    sys.addaudithook(O.passive_fence)
    request = read_request(args.request, args.request_sha256)
    files, generated, signer = select(request)
    plan = dict(kind="QTBASE_16K_OFFLINE_OPERANDS_V1", Qt_source_map=request["source_map"]["sha256"],
                files={name: pair(row) for name, row in files.items()} |
                      {name: T.pin(raw.encode()) for name, raw in generated.items()},
                signer=signer, Root_authority=None)
    if args.output is not None:
        source = Path(request["source_map"]["path"]).parent
        inputs = [args.request, *(Path(ref["path"]) for ref in request.values()),
                  *(Path(ref["path"]) for ref in files.values())]
        T.need(not args.output.is_relative_to(source) and not args.output.is_relative_to(HERE)
               and not any(path.is_relative_to(args.output) for path in inputs),
               "Fresh disjoint staging output")
        args.output.mkdir(mode=0o700)
        for name, row in files.items():
            O.checked_copy(Path(row["path"]), args.output / name, pair(row))
        for name, raw in generated.items():
            put_text(args.output / name, raw)
        put_json(args.output / PLAN_NAME, plan)
    print(json.dumps(dict(status="PASS_EXACT_READ_ONLY_REHEARSAL_SELECTION", operands=len(plan["files"]),
                          bytes=sum(row["bytes"] for row in plan["files"].values()),
                          plan=T.pin(T.encoded(plan)), Root_authority=None, actor_entered=False),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
