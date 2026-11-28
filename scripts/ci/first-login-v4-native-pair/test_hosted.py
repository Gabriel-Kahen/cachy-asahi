# SPDX-License-Identifier: MIT
"""Exercise the hosted controller with a stateful, inert Docker command."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


HOSTED = Path(__file__).resolve().with_name('hosted.sh')
PINS = dict(re.findall(r'^readonly (\w+)=([0-9a-f]{40}|sha256:[0-9a-f]{64})$',
                       HOSTED.read_text(), re.M))
BASE = PINS['base_config']
COMMITTED = 'sha256:' + 'c' * 64
FOREIGN = 'f' * 64
SUPPLEMENT = b'inert input\n'


def mock_docker(args):
    case = os.environ['MOCK_CASE']
    path = Path(os.environ['MOCK_STATE'])
    state = json.loads(path.read_text())
    containers = state['containers']
    images = state['images']

    def save():
        path.write_text(json.dumps(state))

    def option(name, default=None):
        return args[args.index(name) + 1] if name in args else default

    if args[0] == 'pull' or args[0] == 'start':
        return 0
    if args[0] == 'create':
        provision = args[-1] == 'provision'
        role = 'provision' if provision else 'lane-2' if 'b' * 64 in containers else 'lane-1'
        name = option('--name', f'unreserved-{role}')
        label = option('--label', '=').split('=', 1)[1]
        container_id = {'provision': 'a', 'lane-1': 'b', 'lane-2': 'd'}[role] * 64
        if case == 'missing-create':
            return 130
        if provision and case == 'foreign-container':
            label = 'foreign'
        containers[container_id] = {'name': '/' + name, 'owner': label,
                                    'image': BASE if provision else COMMITTED}
        save()
        if provision and case == 'lost-create' or role == 'lane-2' and case == 'lost-lane-create':
            return 130
        if provision and case in ('inspect-failure', 'list-failure', 'foreign-container'):
            return 42
        print(container_id)
        return 0
    if args[0] == 'commit':
        owner = option('--change', '=').split('=', 1)[1]
        tag = args[-1] if owner and case != 'lost-untagged-commit' else None
        if case == 'missing-commit':
            return 130
        images[COMMITTED] = {'owner': owner, 'tag': tag}
        save()
        if case in ('lost-commit', 'lost-untagged-commit'):
            return 130
        print(COMMITTED)
        return 0
    if args[0] == 'cp':
        destination = Path(args[-1])
        if not destination.is_dir():
            destination.write_text('mock package inventory\n')
        return 0
    if args[0] == 'inspect':
        if '.State.ExitCode' in option('--format'):
            print(0)
        else:
            print(args[-1], containers[args[-1]]['image'], 'none false')
        return 0
    if args[:2] == ['container', 'ls']:
        if case == 'list-failure' or case == 'post-remove-list-failure' and state['removed']:
            print('Cannot connect to the Docker daemon', file=sys.stderr)
            return 1
        key, value = option('--filter').split('=', 1)
        for container_id, record in containers.items():
            if key == 'name' and re.fullmatch(value, record['name']):
                print(container_id)
            elif key == 'label' and value.split('=', 1)[1] == record['owner']:
                print(container_id)
        return 0
    if args[:2] == ['container', 'inspect']:
        if case == 'inspect-failure':
            print('Cannot connect to the Docker daemon', file=sys.stderr)
            return 1
        row = containers[args[-1]]
        print(row['name'], row['owner'])
        return 0
    if args[:2] == ['image', 'ls']:
        key, requested = option('--filter').split('=', 1)
        if key == 'reference' and case == 'foreign-image':
            images['sha256:' + FOREIGN]['tag'] = requested
            save()
        for image_id, row in images.items():
            if key == 'reference' and requested == row['tag']:
                print(image_id)
            elif key == 'label' and requested.split('=', 1)[1] == row['owner']:
                print(image_id)
        return 0
    if args[:2] == ['image', 'inspect']:
        if '.Config.Labels' in option('--format'):
            print(images[args[-1]]['owner'])
        elif '.Id' in option('--format'):
            print('linux/arm64', BASE)
        else:
            print('linux/arm64')
        return 0
    if args[:2] in (['container', 'rm'], ['image', 'rm']) or args[0] == 'rm':
        rows = images if args[0] == 'image' else containers
        if args[0] == 'image' and any(row.get('image') == args[-1] for row in containers.values()):
            return 1
        del rows[args[-1]]
        state['removed'].append(args[-1])
        save()
        return 44 if case == 'lost-remove' else 0
    raise AssertionError(args)


def run_mock(command, args):
    if command == 'docker':
        return mock_docker(args)
    if command == 'git':
        expected = {'HEAD': 'recipe_commit', 'HEAD:packages/tools/cachy-asahi-setup8-v3': 'setup_tree',
                    'HEAD:packages/tools/cachy-asahi-first-login-v4': 'first_tree'}
        print(PINS[expected[args[-1]]])
    elif command == 'uname':
        print('aarch64' if args == ['-m'] else 'mock-kernel')
    elif command == 'getconf':
        print(4096)
    elif command == 'curl':
        Path(args[args.index('--output') + 1]).write_bytes(SUPPLEMENT)
    else:
        assert command == 'python3' and args[2].endswith('/verify.py'), (command, args)
    return 0


class HostedCleanupTests(unittest.TestCase):
    def exercise(self, case, build_exit, cleanup_exit, containers=1, images=2):
        with tempfile.TemporaryDirectory(prefix='first-login-hosted-mock-') as temporary:
            root = Path(temporary)
            commands, public, inputs = (root / name for name in ('bin', 'public', 'input'))
            for path in (commands, public, inputs):
                path.mkdir()
            for command in ('docker', 'git', 'uname', 'getconf', 'python3', 'curl'):
                path = commands / command
                path.write_text(f'#!{sys.executable}\nimport runpy, sys\n'
                                f'run = runpy.run_path({str(Path(__file__).resolve())!r})["run_mock"]\n'
                                f'sys.exit(run({command!r}, sys.argv[1:]))\n')
                path.chmod(0o700)
            supplement = f'{hashlib.sha256(SUPPLEMENT).hexdigest()}  fish-4.9.3-1-aarch64.pkg.tar.xz\n'
            (inputs / 'supplement.sha256').write_text(supplement)
            supplement_sha = hashlib.sha256(supplement.encode()).hexdigest()
            (public / 'input-sha256.txt').write_text(f'{supplement_sha}  supplement.sha256\n')
            state = root / 'docker.json'
            state.write_text(json.dumps({
                'containers': {FOREIGN: {'name': '/foreign-container', 'owner': 'foreign'}},
                'images': {BASE: {'owner': '', 'tag': 'pinned-base'},
                           'sha256:' + FOREIGN: {'owner': 'foreign', 'tag': 'foreign-image'}},
                'removed': [],
            }))
            env = dict(os.environ, PATH=f'{commands}:/usr/bin:/bin', MOCK_CASE=case, MOCK_STATE=str(state),
                       GITHUB_ACTIONS='true', GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',
                       GITHUB_SHA='1' * 40, GITHUB_RUN_ID='1234', GITHUB_RUN_ATTEMPT='7', RUNNER_ARCH='ARM64')
            process = subprocess.run(['/bin/bash', HOSTED, 'build', root, root], env=env,
                                     capture_output=True, text=True, timeout=20)
            result = json.loads(state.read_text())
            self.assertEqual(process.returncode, build_exit or cleanup_exit, process.stderr)
            self.assertEqual((public / 'cleanup.txt').read_text(),
                             f'build_exit={build_exit}\ncleanup_exit={cleanup_exit}\n', f'{process.stderr}\n{result}')
            self.assertEqual(len(result['containers']), containers, result)
            self.assertEqual(len(result['images']), images, result)
            self.assertIn(FOREIGN, result['containers'])
            self.assertIn('sha256:' + FOREIGN, result['images'])
            self.assertIn(BASE, result['images'])
            return result['removed']

    def test_lost_create_reply(self):
        self.assertEqual(self.exercise('lost-create', 130, 0), ['a' * 64])

    def test_lost_second_lane_create_reply(self):
        self.assertEqual(self.exercise('lost-lane-create', 130, 0), ['d' * 64, 'b' * 64, 'a' * 64, COMMITTED])

    def test_lost_commit_reply(self):
        for case in ('lost-commit', 'lost-untagged-commit'):
            with self.subTest(case=case):
                self.assertEqual(self.exercise(case, 130, 0), ['a' * 64, COMMITTED])

    def test_interrupted_allocation_that_was_never_observed_remains_unconfirmed(self):
        self.assertEqual(self.exercise('missing-create', 130, 1), [])
        self.assertEqual(self.exercise('missing-commit', 130, 1), ['a' * 64])

    def test_failed_docker_query_is_not_absence(self):
        for case in ('list-failure', 'inspect-failure'):
            with self.subTest(case=case):
                self.assertEqual(self.exercise(case, 42, 1, containers=2), [])

    def test_reserved_name_or_tag_does_not_authorize_foreign_removal(self):
        self.assertEqual(self.exercise('foreign-container', 42, 1, containers=2), [])
        self.assertEqual(self.exercise('foreign-image', 1, 1), ['a' * 64])

    def test_lost_remove_reply_still_requires_a_successful_absence_query(self):
        order = ['d' * 64, 'b' * 64, 'a' * 64, COMMITTED]
        self.assertEqual(self.exercise('lost-remove', 0, 0), order)
        self.assertEqual(self.exercise('post-remove-list-failure', 0, 1, containers=3, images=3), ['d' * 64])


if __name__ == '__main__':
    unittest.main()
