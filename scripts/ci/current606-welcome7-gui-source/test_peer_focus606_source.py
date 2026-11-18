# SPDX-License-Identifier: MIT
"""Offline controls for the exact Current606 peer-focus Source and C settle predicate."""

import argparse
import ast
import inspect
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import peer_focus606_source as source

REPOSITORY = None
HARNESS = """#include <stdio.h>
#include <stdlib.h>

typedef int gboolean;
typedef unsigned int guint;
typedef long long gint64;
#define TRUE 1
#define FALSE 0
#define G_USEC_PER_SEC 1000000
typedef struct { guint count; } Geometry;
typedef struct { unsigned mask; } AtspiStateSet;
typedef int AtspiAccessible;
enum { ATSPI_STATE_ENABLED=1, ATSPI_STATE_SENSITIVE=2, ATSPI_STATE_FOCUSED=4 };

static int scenario, probes, reads, refreshes;
static gint64 now;
static AtspiAccessible peer_id, target_id;
static AtspiAccessible *target=&target_id, *scroll_peer=&peer_id;
static AtspiStateSet peer, control;
static gboolean g_main_context_iteration(void *context, gboolean block)
{ if (context || block) exit(8); return FALSE; }
static void g_usleep(unsigned long period)
{ if (period != 25000) exit(8); now += period; }
static gint64 g_get_monotonic_time(void) { return now; }
static gboolean state(AtspiStateSet *states, int bit) { return states && (states->mask & bit); }
static void check(gboolean passed, const char *reason) { if (!passed) { puts(reason); exit(2); } }
static void g_object_unref(AtspiStateSet *states) { (void)states; }
static void atspi_accessible_clear_cache(AtspiAccessible *node)
{ if (node != target && node != scroll_peer) exit(8); refreshes++; }

static AtspiStateSet *atspi_accessible_get_state_set(AtspiAccessible *node)
{
    if (node == scroll_peer) {
        reads++;
        peer.mask = 3;
        if (scenario == 7 && reads >= 3) peer.mask = 4;
        else if ((scenario != 2 && reads >= 3) || scenario == 6) peer.mask |= 4;
        return &peer;
    }
    if (node != target) exit(8);
    control.mask = scenario == 4 ? 1 : 0;
    return scenario == 5 ? NULL : &control;
}

static gboolean geometry(guint pid, Geometry *value)
{
    if (pid != 91) exit(8);
    probes++;
    if (scenario == 3) return FALSE;
    value->count = (guint)probes;
    return scenario != 6 || probes >= 3;
}
"""

PROGRAM = r"""int main(int argc, char **argv)
{
    if (argc != 2) return 8;
    scenario = atoi(argv[1]);
    Geometry value = {0};
    gboolean visible = FALSE;
    gboolean ok = scenario == 8 ? settled_geometry(91, &value)
                                : settled_geometry_with(91, &value, actual_peer_focus, &visible);
    printf("%d %d %d %d %d %u\n", ok, visible, probes, reads, refreshes, value.count);
    return now > 2 * G_USEC_PER_SEC ? 8 : 0;
}
"""


class Controls(unittest.TestCase):
    def test_missing_or_forged_parent_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Exact R3 source manifest"):
            source.transform({})
        with self.assertRaisesRegex(ValueError, "Exact R3 source manifest"):
            source.transform({source.MANIFEST: b'{"files":{}}'})

    @unittest.skipUnless(shutil.which("cc"), "C compiler required for exact peer-focus controls")
    def test_compiled_peer_focus_requires_fresh_state_and_unclipped_geometry(self):
        emitter = ast.parse(inspect.getsource(source.settle_peer_focus)).body[0]
        helper = next(ast.literal_eval(node.value) for node in emitter.body
                      if isinstance(node, ast.Assign) and node.targets[0].id == "after")
        cases = (
            (1, 0, "1 1 3 3 4 3"),              # actual focus arrives after visible geometry
            (2, 0, "0 1 80 80 80 80"),           # geometry alone never passes
            (3, 0, "0 0 80 0 0 0"),             # clipped target never passes
            (4, 2, "disabled target state preserved"),
            (5, 2, "disabled target state preserved"),
            (6, 0, "1 1 3 1 2 3"),              # the geometry can also arrive later
            (7, 2, "focused peer must remain enabled"),
            (8, 0, "1 0 1 0 0 1"),              # non-peer geometry route
        )
        with TemporaryDirectory(prefix="peer-focus606-control-") as directory:
            root = Path(directory)
            fixture, executable = root / "focus.c", root / "focus"
            fixture.write_text(HARNESS + helper + "\n" + PROGRAM)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(fixture), "-o", str(executable)],
                           check=True, capture_output=True, timeout=30)
            for case, code, expected in cases:
                with self.subTest(case=case):
                    got = subprocess.run([str(executable), str(case)], capture_output=True, text=True, timeout=5)
                    self.assertEqual((got.returncode, got.stdout.strip(), got.stderr), (code, expected, ""))

    def test_exact_public_git_replay(self):
        if REPOSITORY is None:
            self.skipTest("supply --repository containing the published R4 ancestry")
        parent = source.committed_tree(REPOSITORY, source.PARENT, source.PARENT_TREE, source.PARENT_BYTES)
        reference = source.committed_tree(REPOSITORY, source.CANDIDATE, source.CANDIDATE_TREE, source.CANDIDATE_BYTES)
        self.assertEqual({name for name in parent if parent[name] != reference[name]}, set(source.CHANGED))
        candidate = source.transform(parent)
        self.assertEqual(candidate, reference)
        self.assertEqual(candidate["fresh-test/selection.json"], parent["fresh-test/selection.json"])
        with TemporaryDirectory(prefix="peer-focus606-export-") as directory:
            output = Path(directory) / "source"
            self.assertIsNone(source.emit(REPOSITORY, output)["actual"])
            pins = {name: source.clock.pin(body) for name, body in reference.items()}
            self.assertEqual(source.clock.read_tree(output, pins), reference)
            with self.assertRaisesRegex(ValueError, "Fresh canonical output"):
                source.emit(REPOSITORY, output)
            self.assertEqual(source.clock.read_tree(output, pins), reference)

    def test_wrong_local_git_refuses_without_output(self):
        with TemporaryDirectory(prefix="peer-focus606-no-git-") as directory:
            root = Path(directory)
            nonrepo = root / "ordinary"
            nonrepo.mkdir()
            output = root / "source"
            with self.assertRaisesRegex(ValueError, "already be available in local Git"):
                source.emit(nonrepo, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repository", type=lambda value: Path(value).resolve(strict=True))
    options, rest = parser.parse_known_args()
    REPOSITORY = options.repository
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
