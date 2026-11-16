#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Curated actual Source351 and Source355 failures remain rejection DATA."""
import importlib.util
from pathlib import Path
import sys
import unittest


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader15 actual DATA forbids actors/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader15_actual_rejection',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);S,E=R.S,R.E
PINS={'source351-public-failure.ACTUAL-r2.json':dict(bytes=8324,sha256='e7d11080d025b0fabfae1d95199613436547bf4e7f09e4962a1d1b4a6012660b'),
      'source351-mountinfo-data.ACTUAL.raw':dict(bytes=5794,sha256='c52d3185956b93870365913050bac4ebd012c3db08b5b803095822888db13460')}


class ActualFailureControls(unittest.TestCase):
 def test_exact_curated_public_bodies(self):
  for name,pin in PINS.items():self.assertEqual(S.pin((HERE/'fixtures'/name).read_bytes()),pin)
 def test_real_master_work_mount_stays_refused_before_tools(self):
  raw=(HERE/'fixtures/source351-mountinfo-data.ACTUAL.raw').read_bytes()
  self.assertIn(b' /work rw,relatime master:1 - ext4 ',raw)
  with self.assertRaisesRegex(S.Hold,'MOUNTINFO_SELECTED_PRIVATE_PROPAGATION'):E.kernel_mountinfo(raw,'work-only')
 def test_prestart_exit_zero_is_not_completed_actor(self):
  data=S.decode((HERE/'fixtures/source351-public-failure.ACTUAL-r2.json').read_bytes())
  self.assertEqual(data['run'],43928150645);self.assertEqual(data['actor'],'data')
  self.assertEqual(data['state']['ExitCode'],0)
  self.assertEqual(data['state']['FinishedAt'],'0001-01-01T00:00:00Z')
  self.assertEqual(data['state_observation'],'PRESTART_DOCKER_INSPECT_ONLY_NOT_POST_EXECUTION')
  self.assertEqual(data['actual_post_execution_state'],'NOT_RETAINED')
  self.assertEqual(data['docker_start_attach_returncode'],1)
  self.assertEqual(data['native_build'],'NOT_STARTED')
  self.assertEqual(data['Config_Env'],'OMITTED')
 def test_source351_projection_is_not_a_private_bind_or_kernel_pass(self):
  data=S.decode((HERE/'fixtures/source351-public-failure.ACTUAL-r2.json').read_bytes())
  configured=next(row for row in data['HostConfig_Mounts']if row['Target']=='/work')
  realized=next(row for row in data['Mounts']if row['Destination']=='/work')
  self.assertEqual(configured['Type'],realized['Type'])
  self.assertEqual(realized['Type'],'volume');self.assertEqual(realized['Propagation'],'')
  self.assertEqual(data['actual_kernel_private_mount'],'REFUSED')
  self.assertEqual(data['kernel_record_status'],'HOLD_KERNEL_MOUNTINFO_PREENTRY')

 def test_source355_actual_daemon_root_private_bind_refusal_is_exact(self):
  raw=(HERE/'fixtures/source355-daemon-root-bind-refusal.ACTUAL.json').read_bytes()
  self.assertEqual(S.pin(raw),dict(bytes=4701,sha256='28c650fd0e3b1979fc496342185dd43ca14d30c6658bbad2e1755a49f823d948'))
  data=S.decode(raw)
  self.assertEqual(data['source'],'79cc1238c49ec69aca21d1f35d67468f5df4391f')
  self.assertEqual(data['run'],43959643188);self.assertEqual(data['attempt'],1)
  self.assertEqual(data['phase'],'DOCKER_CREATE_DATA_ACTOR_BEFORE_START')
  self.assertEqual(data['exit'],1);self.assertEqual(data['controller_ids'],{})
  self.assertEqual(data['kernel_mount_proof'],'NOT_STARTED');self.assertEqual(data['toolchain_probes'],'NOT_STARTED')
  self.assertFalse(data['native_acceptance']);self.assertIsNone(data['Root_acceptance'])
  self.assertTrue(data['owned_resources_absent']);self.assertEqual(data['image_retirement']['status'],'PASS_RETIRED')
  self.assertEqual(S.pin(data['stderr'].encode()),data['stderr_pin'])
  self.assertIn('must use either propagation mode "rslave" or "rshared"',data['stderr'])
  self.assertIn('propagation: "rprivate"',data['stderr'])
  self.assertNotIn('Env',data);self.assertEqual(data['build'],'SKIPPED')

 def test_exact_source361_successful_finite_qualification_is_global_failure(self):
  raw=(HERE/'fixtures/source361-post-retire-guard-failure.ACTUAL.json').read_bytes()
  self.assertEqual(S.pin(raw),dict(bytes=3585,sha256='b77783095035ca5eef88176b78fcc24af71aa3321890897929e6f09587cabb67'))
  row=S.decode(raw);self.assertEqual(row['source'],'b421e5e90d0908fa972b6d20fa3a53b4a6722713');self.assertEqual(row['run'],43973692325)
  self.assertEqual(row['qualification_status'],'PASS_NATIVE_SOURCE_QUALIFICATION_ONLY');self.assertEqual(row['qualification_errors'],[])
  self.assertEqual(row['native_probe_count'],9);self.assertTrue(row['all_native_probes_natural0']);self.assertEqual(row['probe_commands'],E.PROBES)
  self.assertEqual(row['bootstrap'],'FAIL');self.assertEqual(row['build'],'SKIPPED');self.assertEqual(row['hosted_failure']['status'],'FAIL')
  self.assertEqual(row['hosted_failure']['error'],'ValueError: workspace FDs still held');self.assertFalse(row['hosted_failure']['native_acceptance'])
  self.assertIsNone(row['Root_native_acceptance']);self.assertFalse(row['release_acceptance']);self.assertEqual(row['M2'],'NOT_RUN')
 def test_actual_source361_retirement_and_kernel_descriptors_do_not_upgrade_global_outcome(self):
  row=S.decode((HERE/'fixtures/source361-post-retire-guard-failure.ACTUAL.json').read_bytes())
  self.assertEqual(set(row['kernel_mount_proof_descriptors']),{'qualification-data','qualification-probe'})
  for pair in row['kernel_mount_proof_descriptors'].values():
   for ref in pair.values():self.assertGreater(ref['bytes'],0);self.assertTrue(S.digest(ref['sha256']))
  first,last=row['workspace_lifecycle'];self.assertEqual(first['status'],'CREATED_HELD');self.assertEqual(last['status'],'RETIRED_ABSENT')
  self.assertEqual(first['nonce'],last['nonce']);self.assertEqual(first['workspace_node'],last['workspace_node']);self.assertTrue(last['fd_held_until_absence'])
  self.assertGreater(last['after_operation_count'],first['after_operation_count']);self.assertEqual(last['nodes'],553096)
  self.assertTrue(row['owned_resources_absent']);self.assertEqual(row['image_retirement']['status'],'PASS_RETIRED');self.assertEqual(row['image_retirement']['errors'],[])
  self.assertEqual(len(row['image_retirement']['images']),2);self.assertEqual(row['hosted_failure']['status'],'FAIL')


if __name__=='__main__':unittest.main()
