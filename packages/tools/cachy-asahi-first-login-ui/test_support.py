# SPDX-License-Identifier: MIT
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


bridge = module('bridge', HERE / 'bridge.py')
setup = module('setup8', HERE / 'setup8-fixture.py')


class Interrupted(BaseException):
    pass


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='first-login-ui-')
        self.root = Path(self.temp.name)
        self.home = self.root / 'private home'; self.home.mkdir(mode=0o700)
        self.prefix = self.root / 'moved prefix'
        self.prefix.mkdir()
        subprocess.run(['bash', '-euc', 'source "$1"; srcdir="$2"; pkgdir="$3"; package',
            'stage', os.environ.get('FIRST_LOGIN_UI_RECIPE', str(HERE / 'PKGBUILD')), str(HERE), str(self.prefix)], check=True, capture_output=True)
        self.usr = self.prefix / 'usr'
        for source, target in (('first-login-entry-fixture', 'bin/cachy-asahi-first-login'),
            ('first-login-fixture.py', 'lib/cachy-asahi/first-login/first_login.py'),
            ('setup8-fixture.py', 'bin/cachy-asahi-setup')):
            path = self.usr / target; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE / source, path); path.chmod(0o755 if 'bin/' in target else 0o644)
        self.templates = self.root / 'templates'
        for component in bridge.COMPONENTS:
            path = self.templates / setup.TEMPLATES[component]
            path.parent.mkdir(parents=True); path.write_text('# private fixture ' + component + '\n')
        self.client = bridge.Bridge(self.usr, home=self.home, template_root=self.templates)

    def files(self):
        return {str(p.relative_to(self.home)): p.read_bytes() for p in self.home.rglob('*') if p.is_file()}

    def interrupted(self):
        engine = setup.Setup(self.home, self.templates)
        atomic = engine.fs.atomic
        def interrupt(path, *args, **kwargs):
            result = atomic(path, *args, **kwargs)
            if path == engine.targets['fish']:
                raise Interrupted()
            return result
        engine.fs.atomic = interrupt
        try:
            engine.run('activate', ('fish', 'zsh'), True)
        except Interrupted:
            pass
        finally:
            engine.close()

    def close(self):
        self.temp.cleanup()
