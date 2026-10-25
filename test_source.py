#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit finite non-actor controls; no unittest discovery/fallback."""
import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'implementation'))
import common as C,adapter,authority,source_guard
class Controls(unittest.TestCase):
 def test_closed_source_and_all_runtime_inverses(self):
  r=source_guard.verify();self.assertEqual(r['cases'],3);self.assertGreater(r['python_bodies'],200)
 def test_only_apps_delta(self):
  a,b=C.locks();self.assertEqual({n for n in a if a[n]!=b[n]},{'cachy-asahi-apps'});self.assertEqual(a['cachy-asahi-repository-runtime'],'0.1.0-1');self.assertNotIn('systemd-tests',a);driver=C.load('_source_selected_committed',C.ROOT/'cases/normal/scripts/ci/full-root-upgrade/root_upgrade.py');row=dict(status='PASS',before=a,after=b,prepared_add={'cachy-asahi-apps':'0.1.0-16'},prepared_remove={},**{k:True for k in('commit_started','packages_committed','checkpoint_changed','checkpoint_directory_synced')});driver.committed(row,a,b);row['prepared_add']['cachy-asahi-apps']='0.1.0-6'
  with self.assertRaises(ValueError):driver.committed(row,a,b)
  for case in C.CASES:
   hook=C.load('_source_quiesce_'+case,C.ROOT/'cases'/case/'scripts/ci/full-root-upgrade-caller/upgrade_hook.py')
   class ReachedOriginalGuard(Exception):pass
   def stopped(*_):raise ReachedOriginalGuard()
   hook.load=stopped
   with self.assertRaises(ReachedOriginalGuard):hook.quiesce({},a,None,None,None)
   bad=dict(a,**{'cachy-asahi-apps':'0.1.0-5'})
   with self.assertRaises(ValueError):hook.quiesce({},bad,None,None,None)
 def test_no_authority_transfer(self):
  with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound()
  p=copy.deepcopy(C.profile());p['authorities']['fresh607']={'status':'ROOT_ACCEPTED_FINITE_NATIVE_APPS16_SIX_TOOL_SOFTWARE_COMPOSITION'}
  with self.assertRaisesRegex(ValueError,'UNBOUND'):authority.require_bound(p)
 def test_typed_counter_drift(self):
  row=C.profile()['old_source_lineage']['normal']['scripts/update/full_root.py'];raw=C.read(C.ROOT/'cases/normal/scripts/update/full_root.py');old=source_guard.inverse(raw,row);self.assertEqual(old.count(b'max_packages: int = 604'),1)
  with self.assertRaisesRegex(ValueError,'counts'):adapter.transform(old.replace(b'max_packages: int = 604',b'max_packages: int = 608'),'scripts/update/full_root.py')
 def test_malformed_whole_body_inverse(self):
  row=C.profile()['old_source_lineage']['normal']['scripts/update/full_root.py'];raw=C.read(C.ROOT/'cases/normal/scripts/update/full_root.py')
  with self.assertRaises(ValueError):source_guard.inverse(raw+b'\n',row)
 def test_ordinary_clocks_and_errno(self):
  p=C.profile()
  for case in C.CASES:
   root=C.ROOT/'cases'/case;cfg=json.loads(C.read(root/'upgrade-config.json'));self.assertEqual((cfg['stage_seconds'],cfg['copy_seconds'],cfg['driver_seconds'],cfg['verify_seconds']),(1200,1200,1860 if case=='normal'else 2400,600));name='scripts/ci/full-root-upgrade-caller/container.py';raw=C.read(root/name);old=source_guard.inverse(raw,p['old_source_lineage'][case][name]);self.assertEqual(raw.count(b'3900'),old.count(b'3900'));self.assertEqual(raw.count(b'errno'),old.count(b'errno'))
 def test_honest_native_build_inventory(self):
  d=json.loads(C.read(C.HERE/'selected-input.json'));raw=d['build_evidence']['raw_pacman_Q_lock'].encode();self.assertEqual(C.pin(raw),d['build_evidence']['raw_pacman_Q_pin']);self.assertEqual(len(raw.splitlines()),575);self.assertEqual(d['build_evidence']['new607_installed_state'],'NOT_RUN_NOT_FABRICATED');self.assertEqual(len(d['payload']),8)
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls);C.need(suite.countTestCases()==7,'nonzero exact7 source groups');r=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not r.wasSuccessful())
