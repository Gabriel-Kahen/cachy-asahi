# SPDX-License-Identifier: MIT
"""Prepare an unissued JBIG/TIFF extension of the retained Asahi629 guest plan."""

import argparse
from contextlib import nullcontext
from functools import partial
import json
from pathlib import Path
import re
from runpy import run_path
import shutil
import sys
import tempfile
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CONTROLLER = REPO / "scripts/install/asahi629_trial/controller.py"
BASE_CONTROLLER = {"bytes": 40879, "sha256": "9da453e78a963d21b7fd97eb6ae93e996d82823e675d613c24f7f9cd27a7cd3f"}
BASE_CODE = {
    "asahi-guest.py": {"bytes": 21854, "sha256": "19ce3dafe0b626d5a1b9fe2f4333d50a30f2c22fced4e2c7e026cca793b233a4"},
    "asahi-guest-base.py": {"bytes": 16922, "sha256": "2df92fc3d1eadea719b45a7bd4a21dbb3ae414ae2e0f32ae6845e310fe1ac78b"},
    "operands.py": {"bytes": 17512, "sha256": "b2faea755ac35c59547d5f329cb989d7babf36fe14902693321b0de63a0dead0"},
    "trial.py": {"bytes": 62735, "sha256": "6d048fb0a943c988a7cfb521d3173a7900932c2704250f0d1f20339474da9b45"},
}
BASE_INIT = {"bytes": 6290, "sha256": "ce23ab3003fa134de07b9af638c534362a7ab8d3a34ca6ed1c7de2d2936cfc36"}
CAP = 512 << 10
KIND = "ASAHI629_JBIG_TIFF_STAGE_UNISSUED_V1"
ENTRY = SimpleNamespace(**run_path(str(HERE / "guest_entry.py")))
I = SimpleNamespace(**run_path(str(HERE / "inputs.py")))
SCOPE = ENTRY.SCOPE
PLAN = "plan.json"
STAGE = "stage.UNISSUED.json"
LHEX = re.compile(r"[a-f0-9]{32}")
PREDECESSOR_NONCE = "e2167738f967156966f0e748c86ceb42"


def legacy():
    I.read(CONTROLLER, BASE_CONTROLLER)
    runner = SimpleNamespace(**run_path(str(CONTROLLER)))
    runner.T.need(runner.selection()[1] == BASE_CODE and runner.T.pin(runner.init_bytes()) == BASE_INIT,
                  "The reviewed Asahi629 guest source or PID1 has drifted")
    return runner


def replace_once(T, body, old, new):
    T.need(body.count(old) == 1, "Exact retained worker insertion point required")
    return body.replace(old, new, 1)


def extend(T, worker, operands, extras):
    checkpoint = b'''
            phase = "jbig-tiff-checkpoint"
            try:
                entry_path = "jbig-tiff/guest_entry.py"
                entry = pinned_module(GUEST_CODE / entry_path, selected["code"][entry_path])
                jbig_tiff = entry.run(T, O, sys.modules[__name__], selected)
            except Exception as error:
                jbig_tiff = dict(kind="ASAHI629_JBIG_TIFF_CHECKPOINT_V1", nonce=selected["nonce"],
                                 status="HOLD_ASAHI629_JBIG_TIFF_ENTRY", error=str(error)[:640])
            T.need(jbig_tiff["status"] == "PASS_ASAHI629_JBIG_TIFF_ROUND_TRIP",
                   "Scoped pair checkpoint held: " + jbig_tiff["status"])
'''
    seam = b'                query(stage)\n        phase = "seal"\n'
    worker = replace_once(T, worker, seam, b"                query(stage)\n" + checkpoint + b'        phase = "seal"\n')
    worker = replace_once(T, worker, b'    commands = command_plan(O, manifest)\n',
                          b'    jbig_tiff = None\n    commands = command_plan(O, manifest)\n')
    worker = replace_once(T, worker, b'O.rehash(T, O.IN, manifest, observed=observed)',
                          b'O.rehash(T, O.IN, manifest, observed=observed, extra=selected["jbig_tiff_media"])')
    output = b'    (evidence / "result.json").write_bytes(T.encoded(result))\n'
    worker = replace_once(T, worker, output, b'    result["jbig_tiff_checkpoint"] = jbig_tiff\n' + output)
    operands = replace_once(T, operands, b"def rehash(T, root, value, observed=None):",
                            b"def rehash(T, root, value, observed=None, *, extra=None):")
    extra = f'''
    if extra is not None:
        T.need(type(extra) is dict and set(extra) == set({tuple(sorted(extras))!r})
               and not files.keys() & extra.keys()
               and all(valid_pin(T, ref, 2 << 20) for ref in extra.values()),
               "Exact scoped JBIG/TIFF media files required")
        files |= extra
'''.encode("ascii")
    seam = b'    directories = {str(parent) for name in files for parent in Path(name).parents if parent != Path(".")}\n'
    operands = replace_once(T, operands, seam, extra + seam)
    compile(worker, "asahi-guest.py", "exec")
    compile(operands, "operands.py", "exec")
    return worker, operands


def source_files():
    return {name: HERE / name for name in ENTRY.SOURCES | {"guest_entry.py"} if name != "tiff-jbig-roundtrip.c"} | {
        "tiff-jbig-roundtrip.c": REPO / "scripts/build/project-libraries/tiff-jbig-roundtrip.c",
    }


def host_sources(T):
    return {name: T.read(HERE / name, cap=128 << 10, collect=False)
            for name in ("stage.py", "runner.py", "readback.py")}


def derive(L, base, review):
    T = L.T
    T.need(base.keys() == {"kind", "nonce", "code", "manifest", "media"} and base["kind"] == L.G.BOOT
           and base["code"] == BASE_CODE, "Unexpected unextended Asahi629 base plan")
    T.need(T.pin(T.encoded(base["media"])) == base["manifest"], "Original transport manifest differs")
    ENTRY.review_shape(T, review, I.PROJECT)
    pins = ENTRY.media_pins(I, review)
    paths, _ = L.selection()
    code = {name: T.read(path, BASE_CODE[name], cap=128 << 10) for name, path in paths.items()}
    code["asahi-guest.py"], code["operands.py"] = extend(T, code["asahi-guest.py"], code["operands.py"], pins)
    for leaf, path in source_files().items():
        expected = I.ROUNDTRIP_SOURCE if leaf == "tiff-jbig-roundtrip.c" else None
        code[SCOPE + leaf] = T.read(path, expected, cap=128 << 10)
    return base | {"code": {leaf: T.pin(raw) for leaf, raw in code.items()},
                   "jbig_tiff": {"test_review": review}, "jbig_tiff_media": pins}, code


def host_test(L, folder, review, *, runtime_directory=None):
    T, G = L.T, L.G
    I.require_qualified_tiff(folder / I.PROVIDERS[I.PROJECT_TIFF]["filename"])
    now = int(time.time())
    G.current_test(T, review, now, remaining=G.TIMEOUT)
    with tempfile.TemporaryDirectory(prefix="jbig-tiff-preflight-", dir=runtime_directory) as path:
        home = Path(path)
        gpg = partial(ENTRY.gpg, home, "--no-autostart")
        cert = T.read(folder / ENTRY.CERTIFICATE, review["certificate"], cap=64 << 10)
        gpg("--import", data=cert)
        listing = gpg("--with-colons", "--fingerprint", "--list-keys")
        T.need(G.key_listing(T, listing) == {review["fingerprint"]: {
            key: review[key] for key in ("not_before", "not_after")}}, "TEST certificate review differs from public input")
        G.public_only(T, gpg("--with-colons", "--list-secret-keys"))
        for name, sig in review["signatures"].items():
            archive = folder / I.PROVIDERS[name]["filename"]
            T.read(archive, I.PROVIDERS[name]["archive"], cap=2 << 20, collect=False)
            T.read(archive.with_name(archive.name + ".sig"), sig, cap=64 << 10, collect=False)
            raw = gpg("--status-fd", "1", "--verify", "--", str(archive) + ".sig", str(archive))
            G.test_signature(T, raw, review, int(time.time()))


def stage_paths(T, preview, nonce):
    T.need(LHEX.fullmatch(nonce) and nonce != PREDECESSOR_NONCE, "Fresh 32-character hexadecimal nonce required")
    raw = T.read(preview / "manifest.json", cap=CAP)
    value = T.decode(raw)
    T.need(raw == T.encoded(value), "Expected canonical retained Preview manifest")
    return value, T.pin(raw)


def put(path, body):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as file:
        file.write(body)
    path.chmod(0o400)


def prepare(L, *, preview, nonce, official_cache, project_jbig, project_tiff, test_inputs, test_review,
            test_review_sha256, output, worker=None):
    T = L.T
    I.require_qualified_tiff(project_tiff)
    media, pin = stage_paths(T, preview, nonce)
    if worker is None:
        L.O.rehash(T, preview, media)
    else:
        worker.rehash_preview(T, L.O, preview, media)
    L.O.check_current_trust(T, media, int(time.time()))
    raw = T.read(test_review, cap=64 << 10)
    review = ENTRY.review_shape(T, T.decode(raw), I.PROJECT)
    T.need(T.pin(raw)["sha256"] == test_review_sha256 and raw == T.encoded(review)
           and review["fingerprint"] not in L.O.HISTORICAL_TEST | {key["fingerprint"] for key in media["keys"].values()},
           "Exact independently reviewed fresh and distinct library TEST trust required")
    base = dict(kind=L.G.BOOT, nonce=nonce, code=BASE_CODE, manifest=pin, media=media)
    plan, code = derive(L, base, review)
    file_paths = {ENTRY.CERTIFICATE: test_inputs / ENTRY.CERTIFICATE}
    candidates = dict(zip(I.PROJECT, (project_jbig, project_tiff), strict=True))
    for name, row in I.PROVIDERS.items():
        leaf = row["filename"]
        file_paths[leaf] = official_cache / leaf if name in I.OFFICIAL else candidates[name]
        file_paths[leaf + ".sig"] = (official_cache if name in I.OFFICIAL else test_inputs) / (leaf + ".sig")
    body = {name: T.read(file_paths[name.removeprefix(SCOPE)], ref, cap=2 << 20)
            for name, ref in plan["jbig_tiff_media"].items()}
    T.need(T.ordinary(output.parent) == output.parent
           and all(not output.is_relative_to(path) for path in (REPO, preview, official_cache, test_inputs)),
           "Output staging must be disjoint from source and immutable inputs")
    output.mkdir(mode=0o700)
    try:
        for leaf, data in code.items():
            put(output / "code" / leaf, data)
        for leaf, data in body.items():
            put(output / "inputs" / leaf, data)
        signature_phase = worker.phase("library-test-signatures") if worker else nullcontext()
        with signature_phase:
            host_test(L, output / "inputs/jbig-tiff", review, runtime_directory=worker.runtime if worker else None)
        packed = T.encoded(plan)
        put(output / PLAN, packed)
        record = dict(kind=KIND, nonce=nonce, authority=None, execution="NOT RUN", plan=T.pin(packed),
                      base_plan=T.pin(T.encoded(base)), source=host_sources(T),
                      entries={"code/" + name: ref for name, ref in plan["code"].items()} |
                              {"inputs/" + name: ref for name, ref in plan["jbig_tiff_media"].items()})
        put(output / STAGE, T.encoded(record))
        return record | {"stage": str(output), "record": T.pin(T.encoded(record))}
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("preview", "official-cache", "project-jbig", "project-tiff", "test-inputs", "test-review", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("nonce", "test-review-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--worker-phase-log", type=Path, help="Record phases inside an admitted bounded systemd worker")
    args = vars(parser.parse_args())
    phase_log = args.pop("worker_phase_log")
    try:
        worker_context = nullcontext()
        if phase_log is not None:
            worker_context = run_path(str(HERE / "refresh_preflight.py"))["systemd_worker"](phase_log)
        with worker_context as worker:
            result = prepare(legacy(), worker=worker, **args)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"JBIG/TIFF stage refused: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))




if __name__ == "__main__":
    sys.exit(main())
