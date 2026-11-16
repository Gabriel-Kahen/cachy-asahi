#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure plan and serial transport controls; no guest, process or package runs."""
import base64,importlib.util,json,shlex,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('no_package_plan',HERE/'plan.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)


class Controls(unittest.TestCase):
 def test_command_echo_cannot_create_frame_and_probe_bytes_survive_transport(self):
  for stage in ('after_login','before_logout'):
   command=P.guest_command(stage,'a'*32)
   self.assertEqual(command.count('\n'),1)
   self.assertNotIn('ARM16K_NO_PACKAGE_META_',command)
   args=shlex.split(command)
   self.assertEqual(args[:2],['/usr/bin/printf','%s'])
   self.assertEqual(base64.b64decode(args[2],validate=True),(HERE/'guest-metadata.sh').read_bytes())
   self.assertEqual(args[3:],['|','/usr/bin/base64','--decode','|','/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','TZ=UTC0','/bin/bash','--noprofile','--norc','-s','--',stage,'a'*32])

 def test_arbitrary_stage_and_nonce_cannot_become_shell(self):
  for stage in ('offline_before','after_login; id','before_logout\nexit','',None):
   with self.assertRaises(ValueError):P.guest_command(stage,'a'*32)
  for nonce in ('a'*31,'A'*32,'a'*32+';id','a'*31+'\n',None,True,32):
   with self.assertRaises(ValueError):P.guest_command('after_login',nonce)

 def test_draft_cannot_issue_authority_or_claim_observation(self):
  plan=json.loads(json.dumps(P.plan()))
  self.assertEqual(plan['status'],'IMPLEMENTED_CONTROL_SOURCE_NOT_EXECUTED')
  self.assertTrue(plan['decisions'])
  self.assertTrue(all(v is None for v in plan['decisions'].values()))
  self.assertEqual(plan['guest_probe']['stages'],['after_login','before_logout'])
  self.assertFalse(plan['guest_probe']['private_contents'])
  self.assertIn('same actual case14 Image/config pins and QEMU tool image; no original-kernel fallback',plan['required_fresh_Root_bindings'])

 def test_plan_does_not_substitute_perl_prepared_raw_for_original(self):
  self.assertEqual(P.plan()['original_baseline']['raw'],dict(bytes=1610612736,sha256='f69d74fbb0043793c96424d0f91ad2f6fb2d8cf3a72fb94024ea9cc40dae4cd3'))
  self.assertIn('Perl-prepared raw or package lifecycle service',P.plan()['forbidden'])
  self.assertIn('timestamp touch, absence cleanup, root/.ssh enumeration or body reads',P.plan()['forbidden'])


if __name__=='__main__':unittest.main(verbosity=2)
