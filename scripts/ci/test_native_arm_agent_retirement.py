"""Producer retirement regressions: source AST and disposable /bin/sh fixtures only."""
import ast
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name('native_arm.py')
KEYDIR = '/etc/pacman.d/gnupg'
ENDPOINTS = tuple('S.gpg-agent' + suffix for suffix in ('', '.browser', '.extra', '.ssh'))
TRANSACTION = 'pacman -U --noconfirm --noscriptlet /tmp/deps/*.pkg.tar.xz'
INVENTORY = 'pacman -Q | LC_ALL=C sort > /builder-packages.lock'


def render_dockerfile(tree):
    """Render only constants and the producer's two UID/GID interpolations."""
    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'dockerfile'
                           for target in node.targets)]
    if len(assignments) != 1 or not isinstance(assignments[0].value, ast.JoinedStr):
        raise AssertionError('expected one Dockerfile f-string')
    parts = []
    for value in assignments[0].value.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
            continue
        if not isinstance(value, ast.FormattedValue) or value.conversion != -1 or value.format_spec:
            raise AssertionError('unexpected Dockerfile interpolation')
        call = value.value
        if not (isinstance(call, ast.Call) and not call.args and not call.keywords
                and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                and call.func.value.id == 'os' and call.func.attr in ('getuid', 'getgid')):
            raise AssertionError('unexpected Dockerfile expression')
        parts.append(str(getattr(os, call.func.attr)()))
    return ''.join(parts)


class AgentRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_bytes())
        cls.dockerfile = render_dockerfile(cls.tree)
        runs = [line[4:] for line in cls.dockerfile.splitlines() if line.startswith('RUN ')]
        if len(runs) != 1:
            raise AssertionError('expected a single root RUN')
        cls.build_run = runs[0]
        start = cls.build_run.index(TRANSACTION)
        end = cls.build_run.index('&& ldconfig', start)
        # Execute the transaction and retirement bytes taken from production,
        # followed by its actual inventory pipeline; never execute the module.
        cls.fragment = cls.build_run[start:end]
        cls.retirement = cls.fragment[len(TRANSACTION):].strip()
        cls.inventory = cls.build_run[cls.build_run.index(INVENTORY):]

    def shell(self, root, transaction_status=0, retirement_status=0):
        home = root / 'gnupg'
        home.mkdir(exist_ok=True)
        trace, inventory = root / 'trace', root / 'inventory'
        fragment = self.fragment.replace(KEYDIR, shlex.quote(str(home)))
        inventory_command = self.inventory.replace('/builder-packages.lock', shlex.quote(str(inventory)))
        script = r'''
set -f
pacman() {
    if test "$#" = 4 && test "$1" = -U && test "$2" = --noconfirm && test "$3" = --noscriptlet && test "$4" = '/tmp/deps/*.pkg.tar.xz'; then
        printf '%s\n' transaction >> "$TRACE"
        return "$TRANSACTION_STATUS"
    fi
    test "$#" = 1 && test "$1" = -Q || return 90
    printf '%s\n' inventory >> "$TRACE"
    printf '%s\n' 'fixture-package 1-1'
}
gpgconf() {
    test "$#" = 4 && test "$1" = --homedir && test "$2" = "$FIXTURE_HOME" && test "$3" = --kill && test "$4" = gpg-agent || return 91
    printf '%s\n' retirement >> "$TRACE"
    return "$RETIREMENT_STATUS"
}
''' + fragment + '&& ' + inventory_command + '\n'
        result = subprocess.run(['/bin/sh', '-c', script], cwd=root,
                                env={'PATH': '/usr/bin:/bin', 'TRACE': str(trace),
                                     'FIXTURE_HOME': str(home),
                                     'TRANSACTION_STATUS': str(transaction_status),
                                     'RETIREMENT_STATUS': str(retirement_status)},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')
        events = trace.read_text().splitlines() if trace.exists() else []
        return result.returncode, events, inventory

    def test_exact_four_literal_gates_without_cleanup_or_bypass(self):
        expected = ['gpgconf --homedir ' + KEYDIR + ' --kill gpg-agent']
        for endpoint in ENDPOINTS:
            expected += ['test ! -e ' + KEYDIR + '/' + endpoint,
                         'test ! -L ' + KEYDIR + '/' + endpoint]
        self.assertEqual(self.retirement, '&& ' + ' && '.join(expected))
        for forbidden in ('*', 'rm ', 'unlink', 'sleep', '--kill all', '||', ';'):
            self.assertNotIn(forbidden, self.retirement)

    def test_retirement_follows_signed_transaction_before_inventory_and_user(self):
        self.assertTrue(self.dockerfile.startswith('FROM scratch\n'))
        self.assertEqual(self.build_run.count(TRANSACTION), 1)
        self.assertEqual(self.build_run.count('gpgconf '), 1)
        self.assertEqual(self.build_run.count(INVENTORY), 1)
        self.assertTrue(self.build_run[:self.build_run.index(TRANSACTION)].endswith(
            'pacman-key --init && pacman-key --populate archlinuxarm && '))
        self.assertEqual(self.inventory, INVENTORY)
        self.assertLess(self.build_run.index('gpgconf '), self.build_run.index('&& ldconfig'))
        self.assertLess(self.build_run.index('&& ldconfig'), self.build_run.index(INVENTORY))
        self.assertIn('\nUSER alarm\nWORKDIR /tmp\n', self.dockerfile)

    def test_signature_and_inventory_container_restrictions_remain_enabled(self):
        literals = [node.value for node in ast.walk(self.tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        self.assertTrue(any('SigLevel = Required\nLocalFileSigLevel = Required\n' in value
                            for value in literals))
        commands = [[item.value if isinstance(item, ast.Constant) else None for item in node.elts]
                    for node in ast.walk(self.tree) if isinstance(node, ast.List)]
        readers = [command for command in commands
                   if command[:2] == ['docker', 'run'] and '/builder-packages.lock' in command]
        self.assertEqual(len(readers), 1)
        for option in ('--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                       '--read-only', '--entrypoint=/bin/cat'):
            self.assertIn(option, readers[0])
        for value in literals:
            for forbidden in ('--privileged', '--cap-add', '--skippgpcheck', '--skipinteg',
                              'SigLevel = Never', 'SigLevel = Optional', 'TrustAll'):
                self.assertNotIn(forbidden, value)

    def test_success_orders_transaction_retirement_and_actual_inventory(self):
        with tempfile.TemporaryDirectory(prefix='agent-retirement-') as folder:
            code, events, inventory = self.shell(Path(folder))
            self.assertEqual(code, 0)
            self.assertEqual(events, ['transaction', 'retirement', 'inventory'])
            self.assertEqual(inventory.read_text(), 'fixture-package 1-1\n')

    def test_transaction_failure_prevents_retirement_and_inventory(self):
        with tempfile.TemporaryDirectory(prefix='agent-retirement-') as folder:
            code, events, inventory = self.shell(Path(folder), transaction_status=46)
            self.assertEqual(code, 46)
            self.assertEqual(events, ['transaction'])
            self.assertFalse(inventory.exists())

    def test_retirement_failure_prevents_inventory(self):
        with tempfile.TemporaryDirectory(prefix='agent-retirement-') as folder:
            code, events, inventory = self.shell(Path(folder), retirement_status=47)
            self.assertEqual(code, 47)
            self.assertEqual(events, ['transaction', 'retirement'])
            self.assertFalse(inventory.exists())

    def residue(self, kind):
        for endpoint in ENDPOINTS:
            with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory(prefix='agent-') as folder:
                root = Path(folder)
                home = root / 'gnupg'
                home.mkdir()
                path = home / endpoint
                listener = None
                try:
                    if kind == 'socket':
                        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        listener.bind(str(path))
                    elif kind == 'symlink':
                        path.symlink_to('absent-target')
                        self.assertFalse(path.exists())
                    elif kind == 'file':
                        path.write_bytes(b'preserve fixture bytes')
                    else:
                        path.mkdir()
                        (path / 'child').write_bytes(b'preserve child')
                    before = path.lstat()
                    code, events, inventory = self.shell(root)
                    self.assertNotEqual(code, 0)
                    self.assertEqual(events, ['transaction', 'retirement'])
                    self.assertFalse(inventory.exists())
                    after = path.lstat()
                    self.assertEqual((before.st_dev, before.st_ino, before.st_mode),
                                     (after.st_dev, after.st_ino, after.st_mode))
                    if kind == 'socket':
                        self.assertTrue(stat.S_ISSOCK(after.st_mode))
                    elif kind == 'symlink':
                        self.assertEqual(os.readlink(path), 'absent-target')
                    elif kind == 'file':
                        self.assertEqual(path.read_bytes(), b'preserve fixture bytes')
                    else:
                        self.assertEqual((path / 'child').read_bytes(), b'preserve child')
                finally:
                    if listener is not None:
                        listener.close()

    def test_each_residual_unix_socket_is_refused_and_untouched(self):
        self.residue('socket')

    def test_each_dangling_symlink_is_refused_and_untouched(self):
        self.residue('symlink')

    def test_each_regular_file_is_refused_and_untouched(self):
        self.residue('file')

    def test_each_directory_is_refused_and_untouched(self):
        self.residue('directory')


if __name__ == '__main__':
    unittest.main()
