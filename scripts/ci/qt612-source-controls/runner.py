# SPDX-License-Identifier: MIT
"""One isolated MODEL/semantic suite, with no network or native tool execution."""
import argparse
import importlib.util
import json
from pathlib import Path
import resource
import sys
import unittest

AS_BYTES = 512 * 1024**2


def run(path, expected):
    resource.setrlimit(resource.RLIMIT_AS, (AS_BYTES, AS_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    def guard(event, args):
        # All five frozen GUI suites install their own pre-import actor fences.
        # Their deliberate audit probes must reach those fences unchanged.
        if path.parent.name == 'qt612-gui-source-reference':
            return
        if event.startswith(('socket.', 'ctypes.')) or event in (
                'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn',
                'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'):
            raise PermissionError('source controls deny network, native actors and budget changes')
        if event == 'subprocess.Popen':
            if len(args) != 4:
                raise PermissionError('invalid source subprocess audit event')
            executable, argv, _, env = args
            allowed = (path.name == 'test_parallel.py' and executable in ('/usr/bin/bash', '/bin/bash')
                       and argv[1:4] == ['--noprofile', '--norc', '-c'] and type(env) is dict
                       and Path(env.get('PATH', '')).name == 'no-executables')
            if not allowed:
                raise PermissionError('only the frozen scheduling suites may launch stubbed Bash')
    sys.addaudithook(guard)
    spec = importlib.util.spec_from_file_location('qt612_one_source_suite', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    passed = result.wasSuccessful() and result.testsRun == expected and not result.skipped
    report = {'status': 'PASS_SOURCE_CONTROLS_ONLY' if passed else 'FAIL_SOURCE_CONTROLS',
              'tests': result.testsRun, 'expected': expected, 'skips': len(result.skipped),
              'failures': len(result.failures), 'errors': len(result.errors),
              'python': '.'.join(map(str, sys.version_info[:3])), 'native_acceptance': False}
    print(json.dumps(report, sort_keys=True))
    return int(not passed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', required=True, type=Path)
    parser.add_argument('--expected', required=True, type=int)
    args = parser.parse_args()
    sys.exit(run(args.test, args.expected))
