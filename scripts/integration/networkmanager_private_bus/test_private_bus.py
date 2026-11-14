#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small control tests; the opt-in run.py exercises the real daemon and bus."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('nm_private_bus_guest',HERE/'guest.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)


class Controls(unittest.TestCase):
    def test_all_caller_bus_and_loader_environment_is_discarded(self):
        caller={'DBUS_SYSTEM_BUS_ADDRESS':'unix:path=/forbidden','DBUS_SESSION_BUS_ADDRESS':'tcp:host=forbidden','DBUS_STARTER_ADDRESS':'unix:abstract=forbidden','DBUS_STARTER_BUS_TYPE':'session','G_BUS_ADDRESS':'unix:path=/forbidden','GI_TYPELIB_PATH':'/forbidden','LD_PRELOAD':'/forbidden','HOME':'/forbidden','PATH':'/forbidden'}
        saved=dict(caller);env=g.clean_env(caller);self.assertEqual(caller,saved)
        self.assertEqual(env['DBUS_SYSTEM_BUS_ADDRESS'],g.BUS)
        self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'],g.BUS)
        self.assertEqual(env['DBUS_STARTER_ADDRESS'],g.BUS)
        self.assertEqual(env['DBUS_STARTER_BUS_TYPE'],'system')
        self.assertFalse({'G_BUS_ADDRESS','GI_TYPELIB_PATH','LD_PRELOAD'}&set(env))
        self.assertNotEqual(env['HOME'],caller['HOME']);self.assertNotEqual(env['PATH'],caller['PATH'])

    def test_image_install_refuses_before_reading_contract_or_running_pacman(self):
        env=dict(os.environ);env.pop('CACHY_ASAHI_PRIVATE_BUS_IMAGE_BUILD',None)
        p=subprocess.run([sys.executable,str(HERE/'image_install.py'),'--allow-private-image-install'],env=env,capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('explicit private image build only',p.stderr)
        self.assertNotIn('contract.json',p.stderr)

    def test_guest_requires_container_before_loading_helpers(self):
        env=dict(os.environ);env.pop('CACHY_ASAHI_PRIVATE_BUS_TEST',None)
        p=subprocess.run([sys.executable,str(HERE/'guest.py'),'--allow-owned-private-system-bus'],env=env,capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('exact disposable x86 container required',p.stderr)


if __name__=='__main__':unittest.main(verbosity=2)
