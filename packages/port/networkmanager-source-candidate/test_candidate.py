#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic ownership/profile controls; no daemon, bus or networking."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
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
        result=p.partition(self.stage,self.root/'split')
        self.assertEqual(len(result['records']),20)
        self.assertEqual(set(p.verify(self.root/'split')['split_leaves']),set(p.PACKAGES))
        self.assertFalse((self.root/'split/networkmanager'/p.OVS).exists())
        self.assertTrue((self.root/'split/networkmanager-docs/usr/share/doc/networkmanager/NetworkManager-ovs.conf.example').is_file())

    def test_relative_output_verification_resolves_symlinks(self):
        out=self.root/'split';p.partition(self.stage,out)
        relative=Path(os.path.relpath(out))
        self.assertEqual(p.verify(relative),p.verify(out))

    def test_split_member_tamper_and_extra_refuse(self):
        out=self.root/'split';p.partition(self.stage,out)
        path=out/'libnm/usr/lib/pkgconfig/libnm.pc';original=path.read_bytes();path.write_bytes(b'changed')
        with self.assertRaises(AssertionError):p.verify(out)
        path.write_bytes(original);(path.parent/'unbound').write_bytes(b'extra')
        with self.assertRaises(AssertionError):p.verify(out)

    def test_connections_live_dns_privileged_and_escaping_payloads_refuse(self):
        for i,(name,kind)in enumerate([('etc/resolv.conf','file'),('etc/NetworkManager/system-connections/user.nmconnection','file'),('usr/bin/escape','symlink'),('usr/bin/setuid','setuid')]):
            with self.subTest(path=name):
                path=self.stage/name;path.parent.mkdir(parents=True,exist_ok=True)
                if kind=='symlink':path.symlink_to('/etc/passwd')
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
