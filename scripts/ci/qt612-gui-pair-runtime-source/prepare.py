# SPDX-License-Identifier: MIT
"""Construct the exact source-only Qt GUI pair runtime, without entering it."""

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qt612_runtime_source", HERE/"runtime.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

FAMILY = "scripts/ci/qt612-complete-family-native-source"
HOSTED = "scripts/ci/qt612-family-hosted"
READER = "scripts/ci/qt612-gui-pair-runtime-source/runtime.py"
ENTRY = "scripts/ci/qt612-gui-server-pair-adapter/entry.py"
PIPELINE = f"{FAMILY}/pipeline.py"
INGRESS = {f"{FAMILY}/runner_inputs.py", f"{FAMILY}/acquire_runner_inputs.py"}
SCOPED_HELPERS = {
    *(f"{FAMILY}/{name}" for name in ("common.py", "consumer.py", "consumer_worker.py", "dependency-audit.DATA.json",
                                     "family.lock.json", "lifecycle.py", "md4c_handoff.py", "pipeline.py",
                                     "proof.py", "qualify.py", "source.py")),
    *(f"{HOSTED}/{name}" for name in ("capacity.py", "evidence.py", "executor.py", "launch.py")),
    "scripts/release/offline_kit.py", "scripts/client/client.py", "scripts/release/source_delivery.py",
}
PORTABLE_MAP = "portable/source-map.json"
SELECTION = "portable/selection.DATA.json"
ROUTES = "inputs/acquisition-routes.DATA.json"
SIGNED = "inputs/md4c/md4c-0.5.3-1-aarch64.pkg.tar.xz.sig"
CERTIFICATE = "inputs/md4c/md4c-r128-TEST-public.gpg"
AUTHORITY = "inputs/md4c/Root-r128-TEST-authority.DATA.json"
R128 = {
    "ref": "refs/heads/codex/md4c053-reference-native-source-20261118-r11",
    "commit": "eed0513b957ef265b334a7762bdfba4f50afd500",
    "tree": "1b204ef98333aaf116fb1fe346b49b37a19e8ef7",
    "map": {"path": "source-map.json", "bytes": 20426,
            "sha256": "42bffdd05941787940bbc5a459cb4ce66cf26b0b01b6e5ebdb96e3d1b2e9d473"},
}
MD4C = {
    SIGNED: {"bytes": 119, "sha256": "63dda83d805e4ad8023fcbe35b6abc63e74646becd4f9e2ada339526a2fddc85"},
    CERTIFICATE: {"bytes": 265, "sha256": "4d1ea2e70ae86992f626a38acd9c61a3d9060261c5fb733bd99e91cc6ab27095"},
}
DECLARED_ROUTE = {"bytes": 513182, "sha256": "a9a4f1d15753357a211cbad1d638f6b821ec8de223943b014ad47d86a103522f"}


def externally_selected(path, sha256):
    R.need(re.fullmatch(r"[0-9a-f]{64}", sha256 or ""), "Explicit external whole input digest required")
    body = R.read(path)
    R.need(R.pin(body)["sha256"] == sha256, "Selected input digest differs")
    return body


def git(repo, *args):
    output = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "--no-replace-objects", *args], check=True, timeout=15,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
    ).stdout
    R.need(len(output) <= R.MAX_FILE, "Finite local Git readback required")
    return output


def commit(repo, selected):
    R.need(re.fullmatch(r"[0-9a-f]{40}", selected or "")
           and git(repo, "cat-file", "-t", selected) == b"commit\n", "Exact independently selected helper commit required")
    tree = git(repo, "rev-parse", selected+"^{tree}").decode("ascii").strip()
    return dict(commit=selected, tree=tree)


def git_leaf(repo, identity, name):
    selected = identity["commit"]
    name = R.leaf(name)
    raw = git(repo, "ls-tree", "-z", selected, "--", name)
    got = re.fullmatch(rb"100(?:644|755) blob ([0-9a-f]{40})\t([^\0]+)\0", raw)
    R.need(got is not None and got[2].decode() == name, "Exact ordinary Git helper leaf required")
    blob = got[1].decode("ascii")
    size = int(git(repo, "cat-file", "-s", blob))
    R.need(0 <= size <= R.MAX_FILE, "Finite Git helper leaf")
    content = git(repo, "cat-file", "blob", blob)
    R.need(len(content) == size and hashlib_git_blob(content) == blob, "Whole immutable Git helper body required")
    return content


def hashlib_git_blob(body):
    return hashlib.sha1(f"blob {len(body)}\0".encode()+body, usedforsecurity=False).hexdigest()


def descriptor(name, raw):
    return dict(path=name, **R.pin(raw))


def public_leaf(name, raw):
    R.leaf(name)
    R.need((name in MD4C or not re.search(r"(?:\.pkg\.tar[^/]*|\.tar\.(?:gz|xz|zst|bz2)|\.zip|\.bundle|\.img)$", name))
           and not re.search(rb"/(?:home/(?:gabe|runner)/|root/(?:\.gnupg|\.ssh))", raw)
           and not re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----", raw),
           "Host paths, private keys or package archive refused from runtime Source")


def portable_bodies(root, selection_sha256, map_sha256, pipeline):
    selection = R.decode(externally_selected(root/"selection.DATA.json", selection_sha256))
    raw_map = externally_selected(root/"source-map.json", map_sha256)
    mapping = R.decode(raw_map)
    R.need(selection["kind"] == "QT612_PATHLESS_RUNNER_INPUTS_DATA_V1" and selection["schema"] == 1
           and selection["Root_acceptance"] is None and selection["original_source_map"] == R.pin(raw_map)
           and mapping["kind"] == "QT612_COMPLETE_FAMILY_SOURCE_DATA_V1" and mapping["input_plan_complete"] is True
           and mapping["Root_acceptance"] is None and all(value is None for value in mapping["actual"].values())
           and len(mapping["files"]) == 250 and len(selection["public_git"]) == 30,
           "Exact complete portable-v2 Source selection required")
    archived = {name for name in mapping["files"] if name.startswith("archives/")}
    R.need(len(archived) == 5 and set(selection["public_git"]) <= mapping["files"].keys()
           and {k:mapping["files"]["family-inputs.DATA.json"][k] for k in ("bytes", "sha256")}
           == selection["original_family_inputs"], "Exact original family evidence and five archived-source declarations required")
    wanted = set(mapping["files"])-archived-set(selection["public_git"])-{"family-inputs.DATA.json"}
    names, dirs = R.scan(root)
    R.need(len(wanted) == 214 and PIPELINE in wanted
           and names == {"source-map.json", "selection.DATA.json"} | {"skeleton/"+name for name in wanted}
           and dirs == {str(p) for name in names for p in Path(name).parents if str(p) != "."},
           "Exact 214-leaf portable skeleton required")
    bodies = {}
    for name in sorted(wanted):
        desc = mapping["files"][name]
        R.need(set(desc) == {"bytes","sha256","mode"} and desc["mode"] == 0o644, "Exact portable file mode required")
        body = R.read(root/"skeleton"/name, {k:desc[k] for k in ("bytes","sha256")}, mode=0o644)
        bodies["portable/skeleton/"+name] = body
    bodies["portable/skeleton/"+PIPELINE] = pipeline
    mapping["files"][PIPELINE] = dict(R.pin(pipeline), mode=0o644)
    updated = R.canonical(mapping)
    selection["original_source_map"] = R.pin(updated)
    bodies.update({PORTABLE_MAP: updated, SELECTION: R.canonical(selection)})
    return bodies


def selected_entry(repo, path, sha256):
    if path is None:
        R.need(sha256 is None, "Entry selection and whole pin must be supplied together")
        return None, {}, None
    selection = R.decode(externally_selected(path, sha256))
    R.need(set(selection) == {"kind","commit","entry","files"}
           and selection["kind"] == "QT612_GUI_PAIR_ENTRY_SELECTION_V1", "Exact external entry selection required")
    cid = commit(repo, selection["commit"])
    files = selection["files"]
    name = selection["entry"]
    R.need(type(files) is dict and 1 <= len(files) <= 16 and name == ENTRY and name in files,
           "Finite explicit Root-selected entry closure required")
    bodies = {}
    for leaf, expected in files.items():
        R.need(re.fullmatch(r"scripts/ci/[a-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*\.py", leaf)
               and not Path(leaf).name.startswith("test_"), "Ordinary runtime entry program required")
        body = git_leaf(repo, cid, leaf)
        R.need(R.pin(body) == expected, "Externally pinned entry body differs")
        compile(body, leaf, "exec")
        bodies[leaf] = body
    return descriptor(name, bodies[name]), bodies, dict(cid, selection=R.pin(R.read(path)))


def md4c_authority(path, sha256):
    raw = externally_selected(path, sha256)
    authority = R.decode(raw)
    R.need(len(raw) <= 8192 and set(authority) == {"schema", "kind", "issuer", "approved", "status", "source",
           "run", "job", "attempt", "original_log", "original_receipt", "archive", "signature", "certificate",
           "fingerprint", "created_epoch", "expires_epoch"}
           and authority["schema"] == 1 and authority["kind"] == "ROOT_QT612_R128_MD4C_TEST_AUTHORITY_V1"
           and authority["issuer"] == "Root" and authority["approved"] is True
           and authority["status"] == "PASS_MD4C_R128_EXACT_ARCHIVES_SCOPED_TEST_ONLY"
           and authority["source"] == R128["commit"] and authority["run"] == 44241902162
           and authority["job"] == 134591565463 and authority["attempt"] == 1
           and authority["original_log"] == {"bytes": 2255414, "sha256": "ec0b1d79132cb9bcb2e5646ac2e70f675c57b8747f60cdab2737dc5bacc4d734"}
           and authority["original_receipt"] == {"bytes": 2466, "sha256": "0817066cbec53daf2ed52569340141f842caa03db3fc35d10a4db0f48e97"}
           and authority["archive"] == {"bytes": 74076, "sha256": "19149e51f05a7d93426dda7a66fd80d67bd235cab7ac4505130f7de6d40b5b95"}
           and authority["signature"] == MD4C[SIGNED] and authority["certificate"] == MD4C[CERTIFICATE]
           and authority["fingerprint"] == "D02BE98DE9C0986C1120951315A8B1E319DBEE03"
           and type(authority["created_epoch"]) is type(authority["expires_epoch"]) is int
           and (authority["created_epoch"], authority["expires_epoch"]) == (1794978886, 1795065286),
           "Exact already selected public R128 TEST authority required")
    return raw


def prepare(*, repo, helper_commit, ingress_commit, portable, portable_selection_sha256, portable_map_sha256,
            routes, routes_sha256, output, md4c_signature=None, md4c_certificate=None,
            entry_selection=None, entry_selection_sha256=None, md4c_authority_path=None, md4c_authority_sha256=None):
    repo, portable, routes = map(R.ordinary, (repo, portable, routes))
    output = R.ordinary(output, exists=False)
    R.need(not os.path.lexists(output) and output.parent.is_dir()
           and all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in (repo, portable)),
           "Fresh disjoint runtime Source output required")
    core = commit(repo, helper_commit)
    ingress = core if ingress_commit is None else commit(repo, ingress_commit)
    helpers = {name:git_leaf(repo, core, name) for name in sorted(SCOPED_HELPERS)}
    helpers.update({name:git_leaf(repo, ingress, name) for name in sorted(INGRESS)})
    lock = R.decode(helpers[f"{FAMILY}/family.lock.json"])
    parents = lock["parents"]
    for name, selected in sorted(parents.items()):
        path = R.leaf(f"{R.PARENT}/{name}")
        body = git_leaf(repo, core, path)
        R.need(R.pin(body) == selected, "Frozen family parent pin differs")
        if path in R.EXTERNAL:
            R.need(selected == R.EXTERNAL[path], "Exact independently retained historical lock required")
        else:
            helpers[path] = body
    R.need(set(R.EXTERNAL) <= {f"{R.PARENT}/{name}" for name in parents}, "Complete deferred frozen-lock selection required")
    R.need(b"PAIR_ONLY_STATUS=" in helpers[PIPELINE], "Reviewed pair-only pipeline required")
    bodies = portable_bodies(portable, portable_selection_sha256, portable_map_sha256, helpers[PIPELINE])
    route_body = externally_selected(routes, routes_sha256)
    R.need(R.pin(route_body) == DECLARED_ROUTE and R.decode(route_body)["kind"] == "Qt-Family-Transport-Public-Routes-DATA",
           "Exact previously reviewed 567-route public material plan required")
    bodies[ROUTES] = route_body
    R.need((md4c_signature is None) == (md4c_certificate is None), "Select both optional public md4c operands or neither")
    for name, path in ((SIGNED, md4c_signature), (CERTIFICATE, md4c_certificate)):
        if path is not None:
            bodies[name] = R.read(R.ordinary(path), MD4C[name])
    R.need((md4c_authority_path is None) == (md4c_authority_sha256 is None),
           "External public TEST authority and its whole pin must be supplied together")
    if md4c_authority_path is not None:
        R.need(md4c_signature is not None, "Public issuer projection must join its exact selected signature and certificate")
        bodies[AUTHORITY] = md4c_authority(md4c_authority_path, md4c_authority_sha256)
    entry, extra, entry_provenance = selected_entry(repo, entry_selection, entry_selection_sha256)
    R.need(not set(extra) & set(helpers), "Entry selection cannot replace reviewed runtime helper programs")
    bodies.update(helpers)
    bodies.update(extra)
    bodies[READER] = R.read(HERE/"runtime.py")
    input_roles = {name: descriptor(path, bodies[path]) if path in bodies else None
                   for name, path in (("portable_selection", SELECTION), ("route_plan", ROUTES),
                                      ("md4c_signature", SIGNED), ("md4c_certificate", CERTIFICATE),
                                      ("md4c_authority", AUTHORITY))}
    inputs = dict(kind="QT612_GUI_PAIR_RUNTIME_INPUTS_DATA_V1", mode="pair-only", helper=core, ingress=ingress,
                  helper_files=sorted(helpers), external_family_locks=R.EXTERNAL, r128_source=R128,
                  entry=entry, entry_provenance=entry_provenance, inputs=input_roles, Root_acceptance=None,
                  native_pair="NOT_RUN", lifecycle="NOT_RUN")
    bodies[R.INPUTS] = R.canonical(inputs)
    R.need(len(bodies) <= R.MAX_FILES and sum(map(len,bodies.values())) <= R.MAX_TOTAL,
           "Finite exact runtime Source payload required")
    for path, content in bodies.items():
        public_leaf(path, content)
    output.mkdir(mode=0o700)
    for path, content in sorted(bodies.items()):
        R.write(output, path, content)
    mapping = dict(kind=R.KIND, schema=1,
                   files={name:dict(R.pin(raw), mode=0o644) for name,raw in sorted(bodies.items())})
    raw_map = R.canonical(mapping)
    R.write(output, R.MAP, raw_map)
    R.verify(output, R.pin(raw_map)["sha256"])
    return dict(status="PREPARED_GUI_PAIR_RUNTIME_SOURCE_DATA_ONLY", files=len(bodies),
                bytes=sum(map(len,bodies.values())), map=descriptor(R.MAP, raw_map), entry=entry, inputs=input_roles,
                r128_source=R128, Root_acceptance=None, native_pair="NOT_RUN", lifecycle="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo","helper_commit","portable","portable_selection_sha256","portable_map_sha256",
                 "routes","routes_sha256","output"):
        parser.add_argument("--"+name.replace("_","-"), required=True, type=Path if name in ("repo","portable","routes","output") else str)
    for name in ("md4c_signature","md4c_certificate","entry_selection","md4c_authority_path"):
        parser.add_argument("--"+name.replace("_","-"), type=Path)
    parser.add_argument("--ingress-commit")
    parser.add_argument("--entry-selection-sha256")
    parser.add_argument("--md4c-authority-sha256")
    print(R.canonical(prepare(**vars(parser.parse_args()))).decode(), end="")


if __name__ == "__main__":
    main()
