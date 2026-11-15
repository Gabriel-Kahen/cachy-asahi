#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced finite capability correction Source DATA controls; no Source imports."""
import argparse,ctypes,hashlib,importlib.util,json,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
PARENT=ANCESTOR=None

def load(name,path,pin=None):
 if pin and hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise ValueError('held constructor pin')
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('v4_constructor_controls',HERE/'prepare.py')
P3=load('v3_constructor_controls',HERE.parent/'successor_v3/prepare.py','7ab44efb107f77052ae1c35f3170f3db841eec5fd81b2b474b6fda297a9f58b6')
P2=load('v2_constructor_controls',HERE.parent/'successor_v2/prepare.py','ba41cc4e3ec0dc285be5909fa32331c7ce1eb5dc33ebb1d2538ae5240aa75784')
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','fcntl.lockf'):raise RuntimeError('DATA fence: '+event)
sys.addaudithook(fence)
def rebind(rows):
 m=json.loads(rows['source-map.json'][0]);m['files']=P.fs.descriptors({n:v for n,v in rows.items()if n!='source-map.json'});rows['source-map.json']=(P.encode(m),0o644);return rows
class ConstructorControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.before=P.parent(PARENT);cls.after=P.render(cls.before)
 def test_complete_exact_unpublished253_parent(self):
  self.assertEqual((len(self.before),sum(len(b)for b,_ in self.before.values())),(253,40862047));self.assertIsNone(P.PARENT['source']);self.assertIsNone(P.PARENT['ref']);self.assertEqual(P.fs.tree(self.before),P.PARENT['tree'])
 def test_exact_one_operational_predicate_and_three_archives(self):
  self.assertEqual(set(self.after)-set(self.before),{P.SAVED_VOLUME,P.SAVED_MAP,P.META});self.assertFalse(set(self.before)-set(self.after));self.assertEqual({n for n in self.before if self.before[n]!=self.after[n]},{P.VOLUME,'source-map.json'})
  raw,mode=self.before[P.VOLUME];self.assertEqual(self.after[P.VOLUME],(raw.replace(P.OLD.encode(),P.NEW.encode()),mode));self.assertEqual(raw.count(P.OLD.encode()),1)
 def test_all_actor_compiled_policy_workflow_common_other_bytes_frozen(self):
  for n,v in self.before.items():
   if n not in(P.VOLUME,'source-map.json'):self.assertEqual(self.after[n],v,n)
  self.assertEqual(self.after[P.SAVED_VOLUME],self.before[P.VOLUME]);self.assertEqual(self.after[P.SAVED_MAP],self.before['source-map.json'])
 def test_complete_selfcontained_inverse_restores253(self):
  restored=P.undo(dict(self.after));self.assertEqual(restored,self.before);self.assertEqual(P.fs.tree(restored),P.PARENT['tree'])
 def test_full256_to253_to251_to248(self):
  restored253=P.undo(dict(self.after));restored251=P3.undo(restored253);ancestor=P2.parent(ANCESTOR);restored248=P2.undo(restored251,ancestor,json.loads(restored251['successor-v2.json'][0]));self.assertEqual(restored248,ancestor)
  self.assertEqual((len(restored251),len(restored248)),(251,248))
 def test_all_new_selectors_null_outer_v2_inner_v1(self):
  for n in('source-map.json',P.META):self.assertEqual(json.loads(self.after[n][0])['actual'],P.ACTUAL)
  meta=json.loads(self.after[P.META][0]);self.assertEqual(meta['outer_operation'],P.OP);self.assertEqual(meta['inner_operation'],P.INNER)
 def test_parent_body_mode_map_extra_refused(self):
  for kind in('body','mode','map','extra'):
   rows=dict(self.before)
   if kind=='body':rows[P.VOLUME]=(rows[P.VOLUME][0]+b'\n',0o644)
   elif kind=='mode':rows['actor/entry.py']=(rows['actor/entry.py'][0],0o755)
   elif kind=='map':rows['source-map.json']=(rows['source-map.json'][0]+b' ',0o644)
   else:rows['extra.DATA']=(b'inert\n',0o644)
   with self.subTest(kind=kind),self.assertRaises(ValueError):P.render(rows)
 def test_recomputed_maps_do_not_hide_body_mode_unknown_leaf_tampering(self):
  for kind in('actor','mode','extra','volume','policy'):
   rows=dict(self.after)
   if kind=='extra':rows['extra.DATA']=(b'inert\n',0o644)
   elif kind=='mode':rows[P.VOLUME]=(rows[P.VOLUME][0],0o755)
   else:
    n={'actor':'actor/entry.py','volume':P.VOLUME,'policy':'policy.json'}[kind];rows[n]=(rows[n][0]+b'\n',rows[n][1])
   with self.subTest(kind=kind),self.assertRaises(ValueError):P.undo(rebind(rows))
 def test_archives_and_inverse_metadata_are_complete_and_immutable(self):
  for n in(P.SAVED_MAP,P.SAVED_VOLUME,P.META):
   for kind in('missing','body','mode'):
    rows=dict(self.after)
    if kind=='missing':rows.pop(n)
    elif kind=='body':rows[n]=(b'{}\n',0o644)
    else:rows[n]=(rows[n][0],0o755)
    with self.subTest(n=n,kind=kind),self.assertRaises((ValueError,KeyError)):P.undo(rebind(rows))
  for kind in('parent','scope','extra','before','after','seam'):
   rows=dict(self.after);m=json.loads(rows[P.META][0])
   if kind=='parent':m['parent']['tree']='0'*40
   elif kind=='scope':m['scope']='WAIVER'
   elif kind=='extra':m['extra']=True
   elif kind=='seam':m['changed'][P.VOLUME]['inverse']['new']="h['CapAdd']in(['CHOWN'],['CAP_CHOWN'],['SYS_ADMIN'])"
   else:m['changed'][P.VOLUME][kind]['sha256']='0'*64
   rows[P.META]=(P.encode(m),0o644)
   with self.subTest(kind=kind),self.assertRaises(ValueError):P.undo(rebind(rows))
 def test_same_count_literal_duplicate_or_wrong_old_volume_refused(self):
  with self.assertRaises(ValueError):P.corrected(self.before[P.VOLUME][0]+P.OLD.encode())
  with self.assertRaises(ValueError):P.corrected(self.after[P.VOLUME][0])
 def test_external_profile_joins_complete_code_and_expected_source(self):
  raw=(HERE/'constructor-profile.json').read_bytes();sha=hashlib.sha256(raw).hexdigest();profile=P.verify_profile(sha)
  self.assertEqual((len(self.after),sum(len(b)for b,_ in self.after.values())),(profile['expected_files'],profile['expected_bytes']));self.assertEqual(P.fs.pin(self.after['source-map.json'][0]),profile['expected_map']);self.assertEqual(P.fs.tree(self.after),profile['expected_tree'])
  with self.assertRaises(ValueError):P.verify_profile('0'*64)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--ancestor-source',type=Path,required=True);a=p.parse_args();PARENT,ANCESTOR=a.parent_source,a.ancestor_source;unittest.main(argv=[__file__],verbosity=2)
