# SPDX-License-Identifier: MIT
"""Finite adversarial controller guards; no Docker commands or package operations."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('python314_lifecycle_controller', Path(__file__).with_name('run.py'))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


class Guards(unittest.TestCase):
    def actor(self):
        return {'Config': {'User': ''}, 'HostConfig': {
            'NanoCpus': 2_000_000_000, 'Memory': 4 * 1024**3, 'MemorySwap': 4 * 1024**3,
            'PidsLimit': 256, 'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Init': False,
            'Privileged': False, 'Devices': [], 'Binds': None, 'CapDrop': ['ALL'],
            'CapAdd': ['CAP_CHOWN', 'CAP_SYS_CHROOT'], 'SecurityOpt': ['no-new-privileges']},
            'Mounts': [{'Destination': '/scratch', 'Type': 'volume', 'RW': True}]}

    def test_actual_docker_capability_spelling_accepted(self):
        controller.validate_actor(self.actor())
        actor = self.actor()
        del actor['HostConfig']['Init']  # Docker omits the field when no init is requested.
        controller.validate_actor(actor)

    def test_unsafe_runtime_contracts_refused(self):
        for key, value in [('NetworkMode', 'host'), ('ReadonlyRootfs', False), ('Privileged', True), ('Init', True),
                           ('Memory', 8 * 1024**3), ('PidsLimit', 0), ('Devices', ['/dev/kvm']),
                           ('Binds', ['/usr:/host']), ('CapAdd', ['CAP_SYS_ADMIN'])]:
            with self.subTest(key=key):
                actor = copy.deepcopy(self.actor())
                actor['HostConfig'][key] = value
                with self.assertRaises(ValueError):
                    controller.validate_actor(actor)

    def test_bind_mount_disguised_as_scratch_refused(self):
        actor = self.actor()
        actor['Mounts'][0]['Type'] = 'bind'
        with self.assertRaises(ValueError):
            controller.validate_actor(actor)

    def test_cleanup_missing_error_must_name_exact_owned_resource(self):
        argv = ['docker', 'volume', 'rm', 'owned-volume']
        self.assertTrue(controller.missing(argv, 'Error response from daemon: get owned-volume: no such volume\n'))
        self.assertFalse(controller.missing(argv, 'Error response from daemon: get foreign-volume: no such volume\n'))
        self.assertFalse(controller.missing(argv, 'permission denied'))


if __name__ == '__main__':
    unittest.main()
