#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the published Current606 peer-focus correction from exact local Git."""

import argparse
import ast
import base64
import inspect
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clock606_source as clock

PARENT = "659614002fdc67f9170d4dec8db9e27dd6b6d89b"
PARENT_TREE = "aed76b7bb3bb3ca2b067cdb3bb65eed9b0cdc2cf"
CANDIDATE = "ddfe829c6ea053d4cb47f47e1652599954bfdfc0"
CANDIDATE_TREE = "dd9abb3fd1ccaef93d043284f77781cea6367173"
REF = "refs/heads/codex/current606-apps16-16k-serial-focus-20261118-r4"
COUNT = 592
PARENT_BYTES = 23960376
CANDIDATE_BYTES = 23967784
ADMISSION = "admission.py"
EXTENSION = "factory/extend_welcome8.py"
INVERSE = "fresh-test/progress576-inverse.json"
MANIFEST = clock.MANIFEST
PARENT_MANIFEST = (103447, "2b093535a663a8123f34e03813e27f868b21438f756209a1b76251e885d46ea2")
CHANGED = {
    ADMISSION: (46573, "5e747f780dd3609f57a34526167ffdf92049e978e9e8af9151505b82505f3c66"),
    EXTENSION: (6217, "6b9bf7cfedd933a0a702280b2ffd8198a14a9e62764906885fa43a22d0f361cf"),
    INVERSE: (298769, "6fbb25b800b6aec2b9d2d1374ebb5f997f445f0dd8491318d19a0764d43a7ce4"),
    MANIFEST: (103447, "326f551aeb1d356d7b65e782d6e822850a8a6d549dd542ba0e28e1b9c9b3af2b"),
}


def once(text, before, after):
    return clock.once(text.encode(), before.encode(), after.encode()).decode()


def settle_peer_focus(text):
    # Check the geometry and fresh AT-SPI focus in the same bounded settle pass.
    # GrabFocus already ran once; asynchronous state never triggers another action.
    before = '''static gboolean settled_geometry(guint pid, Geometry *value)
{
    gint64 until = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    do {
        while (g_main_context_iteration(NULL, FALSE)) {}
        if (geometry(pid, value)) return TRUE;
        g_usleep(25000);
    } while (g_get_monotonic_time() < until);
    return FALSE;
}'''
    after = '''static gboolean settled_geometry_with(guint pid, Geometry *value,
                                      gboolean (*postcondition)(void), gboolean *visible)
{
    gint64 until = g_get_monotonic_time() + 2 * G_USEC_PER_SEC;
    do {
        while (g_get_monotonic_time() < until && g_main_context_iteration(NULL, FALSE)) {}
        if (geometry(pid, value)) {
            if (visible) *visible = TRUE;
            if (!postcondition || postcondition()) return TRUE;
        }
        if (g_get_monotonic_time() >= until) break;
        g_usleep(25000);
    } while (g_get_monotonic_time() < until);
    return FALSE;
}

static gboolean settled_geometry(guint pid, Geometry *value)
{
    return settled_geometry_with(pid, value, NULL, NULL);
}

static gboolean actual_peer_focus(void)
{
    atspi_accessible_clear_cache(scroll_peer);
    AtspiStateSet *states = atspi_accessible_get_state_set(scroll_peer);
    gboolean focused = state(states, ATSPI_STATE_FOCUSED);
    if (focused) check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE),
                       "focused peer must remain enabled");
    if (states) g_object_unref(states);
    if (!focused) return FALSE;
    atspi_accessible_clear_cache(target);
    states = atspi_accessible_get_state_set(target);
    check(states && !state(states, ATSPI_STATE_ENABLED) && !state(states, ATSPI_STATE_SENSITIVE),
          "disabled target state preserved");
    g_object_unref(states);
    return TRUE;
}'''
    text = once(text, before, after)
    text = once(text, '        gboolean final_visible = settled_geometry(pid, &value);',
                '''        gboolean geometry_seen = FALSE;
        gboolean final_visible = peer_focused
            ? settled_geometry_with(pid, &value, actual_peer_focus, &geometry_seen)
            : settled_geometry(pid, &value);
        if (peer_focused && geometry_seen)
            check(final_visible, "actual peer focused state");''')
    before = '''        if (peer_focused) {
            atspi_accessible_clear_cache(scroll_peer); states = atspi_accessible_get_state_set(scroll_peer);
            check(state(states, ATSPI_STATE_FOCUSED), "actual peer focused state"); if (states) g_object_unref(states);
            atspi_accessible_clear_cache(target); states = atspi_accessible_get_state_set(target);
            check(!state(states, ATSPI_STATE_ENABLED) && !state(states, ATSPI_STATE_SENSITIVE), "disabled target state preserved");
            if (states) g_object_unref(states);
        }
'''
    return once(text, before, '')


def git(repository, *args):
    env = dict(PATH=os.defpath, LC_ALL="C", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repository), "-c", "tar.umask=0022", *args],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
    )
    clock.need(result.returncode == 0, "Exact commit objects must already be available in local Git")
    return result.stdout


def check_commit(repository, commit, tree, parent):
    raw = git(repository, "cat-file", "commit", commit)
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    clock.need(headers[0] == b"tree " + tree.encode()
               and [row for row in headers if row.startswith(b"parent ")] == [b"parent " + parent.encode()],
               "Exact Git source and sole parent required")


def committed_tree(repository, commit, tree, size):
    archive = git(repository, "archive", "--format=tar", commit)
    clock.need(size <= len(archive) <= 32 * 1024**2, "Exact bounded committed source archive required")
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        clock.need(tar.pax_headers.get("comment") == commit, "Exact Git archive commit identity required")
        for member in tar:
            if member.isdir():
                continue
            clock.need(member.isfile() and member.mode == clock.MODE and member.name not in bodies,
                       "Only unique ordinary 100644 Git leaves required")
            with tar.extractfile(member) as data:
                bodies[member.name] = data.read()
    clock.need(len(bodies) == COUNT and sum(map(len, bodies.values())) == size and clock.layout(bodies) == tree,
               "Exact Git source bytes and modes required")
    return bodies


def transform(bodies):
    raw = bodies.get(MANIFEST, b"")
    clock.need(clock.exact(raw, PARENT_MANIFEST), "Exact R3 source manifest required")
    manifest = json.loads(raw)
    pins = manifest["files"]
    clock.need(len(bodies) == COUNT and set(bodies) == pins.keys() | {MANIFEST}
               and all(clock.pin(bodies[name]) == expected for name, expected in pins.items())
               and clock.layout(bodies) == PARENT_TREE, "Exact R3 source body closure required")

    emitter = bodies[EXTENSION].decode()
    anchor = "def apply(out,selected):"
    payload = inspect.getsource(settle_peer_focus).rstrip() + "\n\n\n"
    emitter = once(emitter, anchor, payload + anchor)
    line = next(line for line in emitter.splitlines() if line.startswith(" p=out/'a11y_driver.c';"))
    clock.need(line.endswith(";p.write_text(s)"), "Exact Welcome8 driver emission required")
    emitter = once(emitter, line, line.removesuffix(";p.write_text(s)") + ";p.write_text(settle_peer_focus(s))")

    inverse = json.loads(bodies[INVERSE])
    held = json.loads(base64.b64decode(inverse["manifest"], validate=True))
    clock.need(EXTENSION not in inverse["before"] and held["files"][EXTENSION] == clock.pin(bodies[EXTENSION]),
               "Exact original Welcome8 emitter required for inversion")
    inverse["before"][EXTENSION] = base64.b64encode(bodies[EXTENSION]).decode()
    changes = {EXTENSION: emitter.encode(), INVERSE: clock.encoded(inverse)}
    admission = bodies[ADMISSION].decode()
    index = next(line for line in admission.splitlines() if line.startswith("_TEST_INGRESS_NEW="))
    pinned = ast.literal_eval(index.split("=", 1)[1])
    pinned.update({name: clock.pin(body) for name, body in changes.items()})
    admission = once(admission, index, "_TEST_INGRESS_NEW=" + repr(dict(sorted(pinned.items()))))
    old = next(line for line in admission.splitlines() if line.startswith("_TEST_INGRESS_INVERSE="))
    changes[ADMISSION] = once(admission, old, "_TEST_INGRESS_INVERSE=" + repr(clock.pin(changes[INVERSE]))).encode()
    pins.update({name: clock.pin(body) for name, body in changes.items()})
    changes[MANIFEST] = clock.encoded(manifest)

    candidate = bodies | changes
    clock.need(all(clock.exact(changes[name], expected) for name, expected in CHANGED.items())
               and sum(map(len, candidate.values())) == CANDIDATE_BYTES
               and clock.layout(candidate) == CANDIDATE_TREE, "Exact published R4 tree and four changed leaves required")
    for name in (EXTENSION, ADMISSION):
        compile(changes[name], name, "exec")
    return candidate


def emit(repository, output):
    clock.need(repository == repository.resolve(strict=True) and repository.is_dir()
               and output == output.resolve() and output.parent.is_dir()
               and not output.is_relative_to(repository) and not os.path.lexists(output),
               "Fresh canonical output disjoint from local Git required")
    check_commit(repository, PARENT, PARENT_TREE, clock.CANDIDATE)
    check_commit(repository, CANDIDATE, CANDIDATE_TREE, PARENT)
    bodies = transform(committed_tree(repository, PARENT, PARENT_TREE, PARENT_BYTES))
    with TemporaryDirectory(prefix=".current606-peer-focus-", dir=output.parent) as temporary:
        staged = Path(temporary) / "source"
        staged.mkdir(mode=0o700)
        for name, raw in bodies.items():
            leaf = staged / name
            leaf.parent.mkdir(parents=True, exist_ok=True)
            with leaf.open("xb") as stream:
                stream.write(raw)
            leaf.chmod(clock.MODE)
        verified = clock.read_tree(staged, {name: clock.pin(raw) for name, raw in bodies.items()})
        clock.need(clock.layout(verified) == CANDIDATE_TREE, "Exact staged R4 source tree required")
        output.mkdir(mode=0o700)
        try:
            staged.rename(output)
        except OSError:
            output.rmdir()
            raise
    return dict(status="PASS_CURRENT606_PEER_FOCUS_SOURCE_ONLY", source=CANDIDATE, tree=CANDIDATE_TREE,
                parent=PARENT, parent_tree=PARENT_TREE, ref=REF, files=COUNT, bytes=CANDIDATE_BYTES,
                changed=sorted(CHANGED), manifest=clock.pin(bodies[MANIFEST]), actual=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=lambda value: Path(value).absolute())
    parser.add_argument("--output", required=True, type=lambda value: Path(value).absolute())
    args = parser.parse_args()
    try:
        sys.stdout.buffer.write(clock.encoded(emit(args.repository, args.output)))
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit("Current606 peer focus source refused: " + str(error))


if __name__ == "__main__":
    main()
