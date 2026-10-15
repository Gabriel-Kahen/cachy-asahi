# SPDX-License-Identifier: MIT
"""Same private software profile for correctness probe and both phases."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import guest


class ShaderProfile(unittest.TestCase):
    def test_guest_profile_reaches_gbm_probe_and_both_phases_without_host_inheritance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def path(value):
                value = Path(value)
                return root / value.relative_to('/') if value.is_absolute() else value
            contract = path('/usr/local/share/virtual-proof/contract.json')
            contract.parent.mkdir(parents=True)
            contract.write_text(json.dumps({'nonce': 'a' * 32}))
            for name in ('/home/virtual-proof', '/run/virtual-proof', '/dev/dri'):
                path(name).mkdir(parents=True)
            card = path('/dev/dri/card0'); card.touch()
            with patch('guest.guest_guard'), patch('guest.Path', side_effect=path), \
                    patch.dict('guest.os.environ', {'DBUS_SESSION_BUS_ADDRESS': 'private-fixture',
                                                  'GALLIVM_PERF': 'untrusted-host-value'}, clear=True), \
                    patch('guest.command', return_value='{"status":"PASS"}') as probe, \
                    patch('guest.phase') as phases, patch('guest.emit'):
                guest.run_user()
            probe.assert_called_once()
            self.assertEqual(probe.call_args.args[0], ['/usr/local/bin/gbm-probe', str(card)])
            env = probe.call_args.args[1]
            self.assertEqual(env['GALLIVM_PERF'], 'nopt')
            self.assertEqual(env['GALLIUM_DRIVER'], 'llvmpipe')
            self.assertEqual(env['LP_NUM_THREADS'], '2')
            self.assertEqual([call.args[0] for call in phases.call_args_list], ['minimal', 'overlay'])
            self.assertTrue(all(call.args[2] is env for call in phases.call_args_list))
            self.assertNotIn('NO_AT_BRIDGE', env)
            self.assertNotIn('WAYLAND_DEBUG', env)


if __name__ == '__main__': unittest.main()
