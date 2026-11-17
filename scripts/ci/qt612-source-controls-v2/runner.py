# SPDX-License-Identifier: MIT
"""One genuine frozen DATA suite, isolated from sibling audit hooks."""
import argparse
import importlib.util
import json
from pathlib import Path
import resource
import sys
import unittest

HERE = Path(__file__).resolve().parent


def run(args):
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    policy = json.loads(args.policy.read_bytes())
    spec = importlib.util.spec_from_file_location('qt612_source_isolation', HERE / 'isolation.py')
    isolation = importlib.util.module_from_spec(spec); spec.loader.exec_module(isolation)
    seen = isolation.install(policy['workspace'], policy['scratch'], policy['allowed_files'], args.fence == 'wrapper')
    spec = importlib.util.spec_from_file_location('qt612_v2_one_suite', args.test)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    passed = result.wasSuccessful() and result.testsRun == args.expected and not result.skipped
    print(json.dumps({'status': 'PASS_ACTOR_FENCED_DATA_ONLY' if passed else 'FAIL_DATA_CONTROLS',
                      'tests': result.testsRun, 'expected': args.expected, 'skips': len(result.skipped),
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'workspace_reads': sorted(seen), 'native_acceptance': False}, sort_keys=True))
    return int(not passed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--expected', type=int, required=True)
    parser.add_argument('--fence', choices=('module', 'wrapper'), required=True)
    sys.exit(run(parser.parse_args()))
