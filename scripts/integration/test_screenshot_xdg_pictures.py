#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pictures-folder fixtures only: no screenshot, compositor or fixture command runs."""
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[2] / 'packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot'
loader = importlib.machinery.SourceFileLoader('screenshot_xdg_candidate', str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
screenshot = importlib.util.module_from_spec(spec)
loader.exec_module(screenshot)


class PicturesDirectoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='screenshot-pictures-fixture-')
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name) / 'home'
        self.home.mkdir(mode=0o700)
        self.config = self.home / '.config'
        self.environment = {'HOME': str(self.home)}
        # Calling either a capture tool or its lookup is a fixture escape.
        denied = AssertionError('Pictures fixture must not launch or locate tools')
        run = mock.patch.object(screenshot.subprocess, 'run', side_effect=denied)
        which = mock.patch.object(screenshot.shutil, 'which', side_effect=denied)
        self.run, self.which = run.start(), which.start()
        self.addCleanup(run.stop)
        self.addCleanup(which.stop)

    def write_config(self, text, directory=None):
        directory = directory or self.config
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / 'user-dirs.dirs'
        path.write_bytes(text.encode() if isinstance(text, str) else text)
        path.chmod(0o640)
        return path

    def default(self, environment=None):
        return screenshot.default_directory(self.home, self.environment if environment is None else environment)

    @contextlib.contextmanager
    def cli(self, arguments):
        environment = dict(self.environment, XDG_CONFIG_HOME=str(self.config))
        with mock.patch.dict(os.environ, environment), mock.patch.object(sys, 'argv', ['cachy-asahi-screenshot', *arguments]), \
                mock.patch.object(screenshot.signal, 'signal', return_value=screenshot.signal.SIG_DFL) as handlers, \
                mock.patch.object(screenshot, 'capture') as capture, \
                contextlib.redirect_stderr(io.StringIO()) as error:
            yield capture, error
            self.assertEqual(handlers.call_args_list, [
                mock.call(screenshot.signal.SIGTERM, screenshot.cancelled),
                mock.call(screenshot.signal.SIGTERM, screenshot.signal.SIG_DFL)])

    def test_missing_config_keeps_fallback_without_creating_directories(self):
        before = sorted(self.home.iterdir())
        self.assertEqual(self.default(), self.home / 'Pictures/Screenshots')
        self.assertEqual(sorted(self.home.iterdir()), before)
        self.assertFalse(self.config.exists())

    def test_missing_pictures_key_keeps_existing_fallback(self):
        self.write_config('# User-owned settings\nXDG_DOWNLOAD_DIR="$HOME/Downloads"\n')
        self.assertEqual(self.default(), self.home / 'Pictures/Screenshots')

    def test_localized_home_relative_pictures_directory(self):
        self.write_config('XDG_PICTURES_DIR="$HOME/Meine Bilder"\n')
        self.assertEqual(self.default(), self.home / 'Meine Bilder/Screenshots')
        self.assertFalse((self.home / 'Pictures').exists())

    def test_braced_home_prefix_is_data_expansion(self):
        self.write_config('XDG_PICTURES_DIR="${HOME}/Camera Roll"\n')
        self.assertEqual(self.default(), self.home / 'Camera Roll/Screenshots')

    def test_absolute_pictures_directory(self):
        pictures = self.home.parent / 'Photos on another volume'
        self.write_config(f'XDG_PICTURES_DIR="{pictures}"\n')
        self.assertEqual(self.default(), pictures / 'Screenshots')
        self.assertFalse(pictures.exists())

    def test_explicit_config_home_and_environment_are_preserved(self):
        config = self.home / 'Settings with spaces'
        environment = dict(self.environment, XDG_CONFIG_HOME=str(config), UNRELATED='keep me')
        before = copy.deepcopy(environment)
        self.write_config('XDG_PICTURES_DIR="$HOME/Fotos"\n', config)
        self.assertEqual(self.default(environment), self.home / 'Fotos/Screenshots')
        self.assertEqual(environment, before)
        self.assertFalse(self.config.exists())

    def test_setting_home_as_pictures_does_not_create_english_pictures(self):
        self.write_config('XDG_PICTURES_DIR="$HOME"\n')
        self.assertEqual(self.default(), self.home / 'Screenshots')
        self.assertFalse((self.home / 'Pictures').exists())

    def test_quoted_literals_are_not_evaluated(self):
        self.write_config('XDG_PICTURES_DIR="$HOME/Family \\"album\\" and \\\\ literal \\$cash \\`tick\\`"\n')
        self.assertEqual(self.default(), self.home / 'Family "album" and \\ literal $cash `tick`/Screenshots')
        self.run.assert_not_called()
        self.which.assert_not_called()

    def test_config_bytes_and_permissions_survive_lookup(self):
        path = self.write_config('# personal comment\nXDG_PICTURES_DIR="$HOME/Pictures for work"\n')
        before = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(self.default(), self.home / 'Pictures for work/Screenshots')
        self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode)), before)
        self.assertFalse((self.home / 'Pictures for work').exists())

    def test_duplicate_picture_assignment_is_refused_without_writes(self):
        path = self.write_config('XDG_PICTURES_DIR="$HOME/First"\nXDG_PICTURES_DIR="$HOME/Second"\n')
        before = path.read_bytes()
        with self.assertRaises((screenshot.CaptureError, OSError)):
            self.default()
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse((self.home / 'First').exists())
        self.assertFalse((self.home / 'Second').exists())

    def test_malformed_or_dynamic_values_are_refused_as_data(self):
        sentinel = self.home / 'MUST_NOT_EXIST'
        values = ('"Pictures"', '"$OTHER/Photos"', '"$HOMEish/Photos"',
                  f'"$(touch {sentinel})"', f'"$HOME/`touch {sentinel}`"',
                  '"$HOME/Photos', 'unquoted', '"$HOME/Photos"; touch sentinel',
                  '"$HOME/Photos\\q"')
        for value in values:
            with self.subTest(value=value):
                path = self.write_config('XDG_PICTURES_DIR=' + value + '\n')
                before = path.read_bytes()
                with self.assertRaises((screenshot.CaptureError, OSError)):
                    self.default()
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse(sentinel.exists())
        self.run.assert_not_called()
        self.which.assert_not_called()

    def test_symlink_config_is_refused_and_target_is_preserved(self):
        target = self.home / 'original-settings'
        target.write_text('XDG_PICTURES_DIR="$HOME/Private Photos"\n')
        self.config.mkdir(mode=0o700)
        (self.config / 'user-dirs.dirs').symlink_to(target)
        before = target.read_bytes()
        with self.assertRaises((screenshot.CaptureError, OSError)):
            self.default()
        self.assertEqual(target.read_bytes(), before)
        self.assertTrue((self.config / 'user-dirs.dirs').is_symlink())

    def test_nonregular_config_is_refused(self):
        (self.config / 'user-dirs.dirs').mkdir(parents=True)
        with self.assertRaises((screenshot.CaptureError, OSError)):
            self.default()

    def test_oversized_config_is_refused_without_truncation(self):
        path = self.write_config(b'#' * (1024 * 1024) + b'\nXDG_PICTURES_DIR="$HOME/Photos"\n')
        before = path.read_bytes()
        with self.assertRaises((screenshot.CaptureError, OSError)):
            self.default()
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_utf8_config_is_refused(self):
        self.write_config(b'XDG_PICTURES_DIR="$HOME/\xffPhotos"\n')
        with self.assertRaises((screenshot.CaptureError, OSError)):
            self.default()

    def test_cli_default_reaches_capture_with_configured_pictures_folder(self):
        self.write_config('XDG_PICTURES_DIR="$HOME/Meine Bilder"\n')
        with self.cli(['full']) as (capture, _):
            self.assertEqual(screenshot.main(), 0)
        capture.assert_called_once_with('full', self.home / 'Meine Bilder/Screenshots')
        self.assertFalse((self.home / 'Pictures').exists())
        self.run.assert_not_called()

    def test_cli_explicit_directory_bypasses_bad_configuration(self):
        self.write_config('XDG_PICTURES_DIR="$(touch NEVER)"\n')
        output = self.home / 'Explicit output'
        with self.cli(['region', '--directory', str(output)]) as (capture, _):
            self.assertEqual(screenshot.main(), 0)
        capture.assert_called_once_with('region', output)
        self.assertFalse((self.home / 'NEVER').exists())
        self.run.assert_not_called()

    def test_cli_bad_config_refuses_before_any_capture_or_tool_lookup(self):
        path = self.write_config('XDG_PICTURES_DIR="$(touch PRIVATE_SENTINEL)"\n')
        before = path.read_bytes()
        with self.cli(['full']) as (capture, error):
            self.assertEqual(screenshot.main(), 1)
        capture.assert_not_called()
        self.run.assert_not_called()
        self.which.assert_not_called()
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn('$(touch PRIVATE_SENTINEL)', error.getvalue())


if __name__ == '__main__':
    unittest.main()
