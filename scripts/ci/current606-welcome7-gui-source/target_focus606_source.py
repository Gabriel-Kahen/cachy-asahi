#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the published Current606 orphan report focus correction from local Git."""

import argparse
import ast
import base64
import inspect
import json
from pathlib import Path
import subprocess
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import peer_focus606_source as peer

clock = peer.clock
PARENT, PARENT_TREE = peer.CANDIDATE, peer.CANDIDATE_TREE
PARENT_BYTES = peer.CANDIDATE_BYTES
PARENT_MANIFEST = peer.CHANGED[peer.MANIFEST]
CANDIDATE = "bde2e0fc62bdfe677a6d686b83232bbc0db6e65a"
CANDIDATE_TREE = "583943a220c868abad80acc26c06aa63e1d91e09"
CANDIDATE_BYTES = 23969731
REF = "refs/heads/codex/current606-apps16-16k-serial-focus-20261118-r5"
ADMISSION, EXTENSION, INVERSE, MANIFEST = peer.ADMISSION, peer.EXTENSION, peer.INVERSE, peer.MANIFEST
CHANGED = {
    ADMISSION: (46573, "a0d941e2c2329d5aacae5887af26bb266e242ff4baef3e574b8125cf61b9b8b6"),
    EXTENSION: (8164, "41f05ad036c5b0ec4e613de378062644c4621d621fabfb5b2fa0243da3b7d630"),
    MANIFEST: (103447, "5ba6fad112fbe965b8fddac3413adbaa1e8b54bc7bb32b96c7be1b83610ef58d"),
}

once = peer.once


def settle_target_focus(text):
    # Join the scoped orphan expander's own AT-SPI focus with complete geometry.
    # A successful GrabFocus reply requests focus and does not prove convergence.
    before = 'static void ensure_visible(guint pid)'
    after = '''static gboolean actual_orphan_report_focus(void)
{
    atspi_accessible_clear_cache(target);
    AtspiStateSet *states = atspi_accessible_get_state_set(target);
    gboolean focused = state(states, ATSPI_STATE_FOCUSED);
    if (focused) check(state(states, ATSPI_STATE_ENABLED) && state(states, ATSPI_STATE_SENSITIVE),
                       "focused orphan report must remain enabled");
    if (states) g_object_unref(states);
    return focused;
}

static void ensure_visible(guint pid)'''
    text = once(text, before, after)
    before = '''        gboolean geometry_seen = FALSE;
        gboolean final_visible = peer_focused
            ? settled_geometry_with(pid, &value, actual_peer_focus, &geometry_seen)
            : settled_geometry(pid, &value);
        if (peer_focused && geometry_seen)
            check(final_visible, "actual peer focused state");'''
    after = '''        gboolean orphan_report_focus = focus_called && wanted_scope &&
            !strcmp(wanted_scope, "Orphan assessment") && !strcmp(wanted, "View report");
        gboolean geometry_seen = FALSE;
        gboolean final_visible = peer_focused
            ? settled_geometry_with(pid, &value, actual_peer_focus, &geometry_seen)
            : orphan_report_focus
                ? settled_geometry_with(pid, &value, actual_orphan_report_focus, &geometry_seen)
                : settled_geometry(pid, &value);
        if (peer_focused && geometry_seen)
            check(final_visible, "actual peer focused state");
        if (orphan_report_focus && geometry_seen)
            check(final_visible, "actual focused control required");'''
    return once(text, before, after)


def transform(bodies):
    raw = bodies.get(MANIFEST, b"")
    clock.need(clock.exact(raw, PARENT_MANIFEST), "Exact R4 source manifest required")
    manifest = json.loads(raw)
    pins = manifest["files"]
    clock.need(set(bodies) == pins.keys() | {MANIFEST}
               and all(clock.pin(bodies[name]) == expected for name, expected in pins.items())
               and clock.layout(bodies) == PARENT_TREE, "Exact R4 source body closure required")

    anchor = "def apply(out,selected):"
    # Preserve the exact published emitter's spacing.
    payload = inspect.getsource(settle_target_focus).rstrip() + "\n" * 5
    emitter = once(bodies[EXTENSION].decode(), anchor, payload + anchor)
    emitter = once(emitter, "p.write_text(settle_peer_focus(s))",
                   "p.write_text(settle_target_focus(settle_peer_focus(s)))")

    inverse = json.loads(bodies[INVERSE])
    original = base64.b64decode(inverse["before"][EXTENSION], validate=True)
    original_manifest = json.loads(base64.b64decode(inverse["manifest"], validate=True))
    clock.need(original_manifest["files"][EXTENSION] == clock.pin(original),
               "Exact original emitter preserved by the unchanged inverse")

    admission = bodies[ADMISSION].decode()
    name = "_TEST_INGRESS_NEW"
    old = next(line for line in admission.splitlines() if line.startswith(name + "="))
    ingress = ast.literal_eval(old.split("=", 1)[1])
    clock.need(ingress[EXTENSION] == pins[EXTENSION] and ingress[INVERSE] == pins[INVERSE],
               "Exact prior extension and inverse ingress pins required")
    ingress[EXTENSION] = clock.pin(emitter.encode())
    changes = {EXTENSION: emitter.encode(),
               ADMISSION: once(admission, old, name + "=" + repr(ingress)).encode()}
    pins.update({name: clock.pin(body) for name, body in changes.items()})
    changes[MANIFEST] = clock.encoded(manifest)

    candidate = bodies | changes
    clock.need(all(clock.exact(changes[name], expected) for name, expected in CHANGED.items())
               and sum(map(len, candidate.values())) == CANDIDATE_BYTES
               and clock.layout(candidate) == CANDIDATE_TREE, "Exact published R5 tree and three changed leaves required")
    for name in (EXTENSION, ADMISSION):
        compile(changes[name], name, "exec")
    return candidate


def emit(repository, output):
    peer.check_output(repository, output)
    peer.check_commit(repository, PARENT, PARENT_TREE, peer.PARENT)
    peer.check_commit(repository, CANDIDATE, CANDIDATE_TREE, PARENT)
    bodies = transform(peer.committed_tree(repository, PARENT, PARENT_TREE, PARENT_BYTES))
    peer.write_tree(output, bodies, CANDIDATE_TREE)
    return dict(status="PASS_CURRENT606_TARGET_FOCUS_SOURCE_ONLY", source=CANDIDATE, tree=CANDIDATE_TREE,
                parent=PARENT, parent_tree=PARENT_TREE, ref=REF, files=len(bodies), bytes=CANDIDATE_BYTES,
                changed=sorted(CHANGED), manifest=clock.pin(bodies[MANIFEST]), actual=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=lambda value: Path(value).absolute())
    parser.add_argument("--output", required=True, type=lambda value: Path(value).absolute())
    args = parser.parse_args()
    try:
        sys.stdout.buffer.write(clock.encoded(emit(args.repository, args.output)))
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit("Current606 target focus source refused: " + str(error))


if __name__ == "__main__":
    main()
