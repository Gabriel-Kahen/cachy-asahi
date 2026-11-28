#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic ownership/profile controls; no daemon, bus or networking."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent

def module(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

p=module('nm_partition','partition.py');c=module('nm_profile','check_profile.py');source=module('nm_source','check_source.py')


class Candidate(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='nm-candidate-data-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.stage=self.root/'stage';self.stage.mkdir()
        files=['usr/bin/NetworkManager','usr/bin/nmcli','usr/bin/nmtui','usr/bin/nm-online','etc/NetworkManager/NetworkManager.conf',
               'usr/lib/systemd/system/NetworkManager.service','usr/lib/NetworkManager/conf.d/20-connectivity.conf',
               'usr/lib/libnm.so.0.1.0','usr/lib/pkgconfig/libnm.pc','usr/include/libnm/NetworkManager.h',
               'usr/lib/girepository-1.0/NM-1.0.typelib','usr/share/gir-1.0/NM-1.0.gir','usr/share/vala/vapi/libnm.vapi','usr/lib/nm-libnm-helper',
               'usr/lib/nm-cloud-setup','usr/lib/systemd/system/nm-cloud-setup.service','usr/lib/systemd/system/nm-cloud-setup.timer',
               'usr/share/gtk-doc/html/libnm/index.html',p.OVS]
        for rel in files:
            path=self.stage/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'SYNTHETIC ownership data; not a package or executable\n')
        (self.stage/'usr/lib/libnm.so').symlink_to('libnm.so.0.1.0')
        path=self.stage/'etc/NetworkManager/system-connections';path.mkdir();path.chmod(0o700)

    def test_complete_split_preserves_every_leaf_and_ovs_as_data(self):
        (self.stage/'usr/bin').chmod(0o750)
        result=p.partition(self.stage,self.root/'split')
        self.assertEqual(sum(row['kind']!='directory' for row in result['records']),20)
        self.assertEqual(set(p.verify(self.stage,self.root/'split')['split_leaves']),set(p.PACKAGES))
        directory = next(row for row in result['records'] if row['source'] == 'usr/bin')
        self.assertEqual((directory['kind'], directory['mode']), ('directory', 0o750))
        self.assertFalse((self.root/'split/networkmanager'/p.OVS).exists())
        self.assertTrue((self.root/'split/networkmanager-docs/usr/share/doc/networkmanager/NetworkManager-ovs.conf.example').is_file())
        destination = self.root/'package'
        destination.mkdir()
        p.verify(self.stage, self.root/'split', 'networkmanager', destination)
        self.assertEqual(stat.S_IMODE((destination/'usr/bin').stat().st_mode), 0o750)

    def test_relative_output_verification_resolves_symlinks(self):
        out=self.root/'split';p.partition(self.stage,out)
        relative=Path(os.path.relpath(out))
        self.assertEqual(p.verify(self.stage,relative),p.verify(self.stage,out))

    def test_split_member_tamper_and_extra_refuse(self):
        out=self.root/'split';p.partition(self.stage,out)
        path=out/'libnm/usr/lib/pkgconfig/libnm.pc';original=path.read_bytes();path.write_bytes(b'changed')
        with self.assertRaises(AssertionError):p.verify(self.stage,out)
        path.write_bytes(original);(path.parent/'unbound').write_bytes(b'extra')
        with self.assertRaises(AssertionError):p.verify(self.stage,out)

    def test_current_stage_drift_refuses_existing_split(self):
        out = self.root/'split'
        p.partition(self.stage, out)
        (self.stage/'usr/bin/nmtui').write_bytes(b'new build')
        with self.assertRaisesRegex(AssertionError, 'current staged tree'):
            p.verify(self.stage, out)

    def test_directory_modes_untracked_directories_and_fifos_refuse_before_copy(self):
        out = self.root/'split'
        p.partition(self.stage, out)
        target = self.root/'package'
        target.mkdir()
        package = out/'networkmanager'
        mode = stat.S_IMODE((package/'usr/bin').stat().st_mode)
        for path, alter, restore in (
                (package/'usr/bin', lambda path: path.chmod(mode ^ 0o020), lambda path: path.chmod(mode)),
                (package/'usr/bin/extra-dir', Path.mkdir, Path.rmdir),
                (package/'usr/bin/extra-fifo', os.mkfifo, Path.unlink)):
            with self.subTest(path=path):
                alter(path)
                try:
                    with self.assertRaises(AssertionError):
                        p.verify(self.stage, out, 'networkmanager', target)
                    self.assertEqual(list(target.iterdir()), [])
                finally:
                    restore(path)

    def recipe_fixture(self):
        self.src = self.root/'src'
        self.src.mkdir()
        for name in ('COPYING', 'COPYING.LGPL', 'COPYING.GFDL', 'LICENSE', 'NetworkManager.conf',
                     '20-connectivity.conf', 'partition.py', 'source-provenance.json'):
            shutil.copyfile(HERE/name, self.src/name)
        (self.src/'check_profile.py').write_text('raise SystemExit(0)\n')
        self.install_log = self.root/'installs'

    def package_payload(self, parent, name, *, fail_install=False):
        target = parent/name
        target.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, RECIPE=str(HERE/'PKGBUILD'), PACKAGE=name, srcdir=str(self.src),
                   pkgdir=str(target), FIXTURE_STAGE=str(self.stage), INSTALL_LOG=str(self.install_log),
                   FAIL_INSTALL=str(int(fail_install)))
        command = '''
set -euo pipefail
meson() {
  [[ $# == 6 && $1 == install && $2 == -C && $3 == "$srcdir/build" &&
    $4 == --no-rebuild && $5 == --destdir ]] || return 3
  printf '%s\n' install >> "$INSTALL_LOG"
  mkdir "$6" || return
  [[ $FAIL_INSTALL == 0 ]] || return 4
  cp -a "$FIXTURE_STAGE/." "$6/"
}
source "$RECIPE"
pkgname=$PACKAGE
"package_$PACKAGE"
'''
        result = subprocess.run(['bash', '--noprofile', '--norc', '-c', command], env=env,
                                capture_output=True, text=True, timeout=20)
        return target, result

    def test_split_functions_share_only_the_current_packaging_workspace(self):
        self.recipe_fixture()
        p.partition(self.stage, self.src/'_split')
        original = self.stage/'usr/bin/nmtui'
        original.write_bytes(b'current executable')
        first = self.root/'pkg-first'
        target, result = self.package_payload(first, 'networkmanager')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target/'usr/bin/nmtui').read_bytes(), b'current executable')
        for name, leaf in (
                ('libnm', 'usr/lib/libnm.so'),
                ('nm-cloud-setup', 'usr/lib/nm-cloud-setup'),
                ('networkmanager-docs', 'usr/share/doc/networkmanager/NetworkManager-ovs.conf.example')):
            target, result = self.package_payload(first, name)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((target/leaf).is_file())
            self.assertFalse((target/'.networkmanager-split').exists())
        self.assertTrue((first/'libnm/usr/lib/libnm.so').is_symlink())
        self.assertEqual(self.install_log.read_text().splitlines(), ['install'])

        original.write_bytes(b'repackaged executable')
        target, result = self.package_payload(self.root/'pkg-repackage', 'networkmanager')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target/'usr/bin/nmtui').read_bytes(), b'repackaged executable')
        self.assertEqual(self.install_log.read_text().splitlines(), ['install', 'install'])

    def test_failed_install_leaves_no_cache_and_can_be_retried(self):
        self.recipe_fixture()
        parent = self.root/'pkg'
        target, result = self.package_payload(parent, 'networkmanager', fail_install=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse(list(parent.glob('.networkmanager-split*')))
        target, result = self.package_payload(parent, 'networkmanager')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((target/'usr/bin/nmtui').is_file())

    def test_connections_live_dns_privileged_and_escaping_payloads_refuse(self):
        for i,(name,kind)in enumerate([('etc/resolv.conf','file'),('etc/NetworkManager/system-connections/user.nmconnection','file'),('usr/bin/escape','symlink'),('usr/bin/setuid','setuid'),('usr/bin/fifo','fifo')]):
            with self.subTest(path=name):
                path=self.stage/name;path.parent.mkdir(parents=True,exist_ok=True)
                if kind=='symlink':path.symlink_to('/etc/passwd')
                elif kind=='fifo':os.mkfifo(path)
                else:path.write_bytes(b'inert');path.chmod(0o4755 if kind=='setuid'else 0o644)
                with self.assertRaises(AssertionError):p.partition(self.stage,self.root/('bad-'+str(i)))
                path.unlink()

    def test_missing_required_payload_and_existing_output_refuse(self):
        (self.stage/'usr/bin/nmtui').unlink()
        with self.assertRaises(AssertionError):p.partition(self.stage,self.root/'missing')
        out=self.root/'existing';out.mkdir();(out/'marker').write_bytes(b'preserve')
        with self.assertRaises(AssertionError):p.partition(self.stage,out)
        self.assertEqual((out/'marker').read_bytes(),b'preserve')

    def test_feature_or_auth_relaxation_refuses(self):
        original=json.loads((HERE/'feature-options.json').read_text())
        for option,value in [('wifi',False),('nm_cloud_setup',False),('polkit_noauth_group','wheel'),('config_wifi_backend_default','iwd')]:
            data=json.loads(json.dumps(original));data['options'][option]=value;path=self.root/'profile.json';path.write_text(json.dumps(data))
            with self.assertRaises(AssertionError):c.profile(path)

    def test_exact_local_pins_and_unavailable_source_remain_distinct(self):
        self.assertIn('HOLD',source.check(HERE)['status'])
        copy=self.root/'recipe';shutil.copytree(HERE,copy,ignore=shutil.ignore_patterns('__pycache__'))
        path=copy/'COPYING';path.write_bytes(path.read_bytes()+b'changed')
        with self.assertRaises(AssertionError):source.check(copy)


if __name__=='__main__':unittest.main(verbosity=2)
