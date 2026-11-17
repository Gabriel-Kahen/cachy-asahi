#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only shell controls. Stubs never configure, build, or execute Qt."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


RECIPE = Path(__file__).resolve().with_name('PKGBUILD')
BASH = shutil.which('bash')
PROBE = r'''
set -euo pipefail
record() {
  local operation=$1 exported_jobs=0 exported_cmake=0
  shift
  if [[ $(declare -p MAX_JOBS 2>/dev/null) == 'declare -x '* ]]; then exported_jobs=1; fi
  if [[ $(declare -p CMAKE_BUILD_PARALLEL_LEVEL 2>/dev/null) == 'declare -x '* ]]; then exported_cmake=1; fi
  {
    printf '%s\t%s\t%s\t%s\t%s\t%s' "$operation" "${MAX_JOBS-<unset>}" \
      "${CMAKE_BUILD_PARALLEL_LEVEL-<unset>}" "$exported_jobs" "$exported_cmake" "${MAKEFLAGS-<unset>}"
    printf '\t%s' "$@"
    printf '\n'
  } >> "$PROBE_LOG"
}
cmake() { record cmake "$@"; }
python() { record python "$@"; }
install() { record install "$@"; }
timeout() { record timeout "$@"; }
source "$1"
"$2"
'''


class SingleJobShellControls(unittest.TestCase):
    def probe(self, phase, overrides):
        self.assertIsNotNone(BASH, 'bash is required for PKGBUILD shell controls')
        with tempfile.TemporaryDirectory(prefix='qt612-parallel-source-only-') as temporary:
            base = Path(temporary)
            log = base / 'operations.tsv'
            environment = {'PATH': str(base / 'no-executables'), 'LC_ALL': 'C', 'HOME': temporary,
                           'srcdir': str(base / 'src'), 'pkgdir': str(base / 'pkg'), 'PROBE_LOG': str(log)}
            environment.update(overrides)
            result = subprocess.run([BASH, '--noprofile', '--norc', '-c', PROBE,
                                     'qt612-source-only-probe', str(RECIPE), phase],
                                    env=environment, cwd=base, capture_output=True, text=True,
                                    timeout=10, check=False)
            rows = [line.split('\t') for line in log.read_text().splitlines()] if log.exists() else []
        return result, rows

    def assert_serial_operations(self, phase, overrides):
        result, rows = self.probe(phase, overrides)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(rows, 'accepted phase must reach the operation stubs')
        for row in rows:
            self.assertEqual(row[1:5], ['1', '1', '1', '1'],
                             'both job settings must equal 1 and be exported before every operation')
        builds = [row[6:] for row in rows if row[0] == 'cmake' and '--build' in row[6:]]
        self.assertEqual(len(builds), 1, f'{phase} must invoke exactly one CMake build')
        arguments = builds[0]
        self.assertEqual(arguments.count('--parallel'), 1, 'CMake build needs explicit parallel limit')
        self.assertEqual(arguments[arguments.index('--parallel') + 1], '1')
        self.assertFalse(any(arg == '-j' or arg.startswith('-j') for arg in arguments))
        return rows

    def test_defaults_and_each_literal_one_setting(self):
        for overrides in ({}, {'MAX_JOBS': '1'}, {'CMAKE_BUILD_PARALLEL_LEVEL': '1'},
                          {'MAX_JOBS': '1', 'CMAKE_BUILD_PARALLEL_LEVEL': '1'}):
            for phase in ('build', 'check'):
                with self.subTest(phase=phase, overrides=overrides):
                    self.assert_serial_operations(phase, overrides)

    def test_each_invalid_setting_refuses_before_any_operation(self):
        for variable in ('MAX_JOBS', 'CMAKE_BUILD_PARALLEL_LEVEL'):
            for value in ('0', '2', '-1', '', 'many', '01', '1 '):
                for phase in ('build', 'check'):
                    with self.subTest(phase=phase, variable=variable, value=value):
                        result, rows = self.probe(phase, {variable: value})
                        self.assertNotEqual(result.returncode, 0, 'invalid jobs setting must fail closed')
                        self.assertEqual(rows, [], 'invalid setting reached an operation before refusal')

    def test_inherited_makeflags_cannot_change_explicit_cmake_limit(self):
        for phase in ('build', 'check'):
            with self.subTest(phase=phase):
                rows = self.assert_serial_operations(phase, {'MAKEFLAGS': '-j999'})
                self.assertTrue(all(row[5] == '-j999' for row in rows), 'probe must actually inherit MAKEFLAGS')


if __name__ == '__main__':
    unittest.main()
