# SPDX-License-Identifier: MIT
"""Literal ALPM byte-domain controls only, never native transaction evidence."""
import base64,copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'implementation'))
import latest_restoration as R
class Restoration(unittest.TestCase):
 def setUp(self):
  self.before=b'%NAME%\ncachy-asahi-ksmctl\n\n%VERSION%\n0.1.0-1\n\n%INSTALLDATE%\n1792296056\n\n%REASON%\n0\n\n%VALIDATION%\npgp\n\n';self.after=self.before.replace(b'1792296056',b'1792434850');self.interval=dict(authority='SOURCE_OWNED_TRANSACTION_WALLCLOCK_NOT_ROOT_OBSERVATION',start_seconds=1792434849,end_seconds=1792434851,monotonic_seconds=1.9)
 def test_only_actual_bounded_numeric_INSTALLDATE_byte_may_differ(self):
  v=R.desc(self.before,self.after,self.interval);self.assertEqual(v['original'],1792296056);self.assertEqual(v['current'],1792434850);self.assertEqual(v['all_other_desc_bytes'],'EXACT_BYTE_EQUAL')
 def test_all_other_desc_fields_framing_order_refuse(self):
  for value in(self.after.replace(b'%REASON%\n0',b'%REASON%\n1'),self.after.replace(b'pgp',b'none'),self.after+b'%FOREIGN%\n1\n\n',self.after.replace(b'%VERSION%',b'%DIFFERENT%'),self.after.replace(b'1792434850',b'FOREIGN'),self.after.replace(b'1792434850',b'01792434850'),self.after+self.after):
   with self.subTest(value=value),self.assertRaises(ValueError):R.desc(self.before,value,self.interval)
 def test_no_arbitrary_time_or_unbounded_owner_clock_authority(self):
  for value in(dict(self.interval,start_seconds=1792434851),dict(self.interval,end_seconds=1792434950),dict(self.interval,monotonic_seconds=91),dict(self.interval,authority='ROOT_OBSERVED'),dict(self.interval,start_seconds=True)):
   with self.subTest(value=value),self.assertRaises(ValueError):R.desc(self.before,self.after,value)
 def test_raw_files_mtree_andownership_all_four_held(self):
  before={};after={};times={}
  for role,name,version in R.SELECTED:
   def leaf(data):return dict(body_base64=base64.b64encode(data).decode(),mode=0o644,uid=0,gid=0,nlink=1)
   original=self.before.replace(b'cachy-asahi-ksmctl',name.encode()).replace(b'0.1.0-1',version.encode());changed=original.replace(b'1792296056',b'1792434850')
   before[name]=dict(version=version,directory=copy.deepcopy(R.DIRECTORY),leaves=dict(desc=leaf(original),files=leaf(b'%FILES%\nusr/bin/'+name.encode()+b'\n'),mtree=leaf(b'INERT_MTREE_BYTE_DOMAIN_CONTROL')));after[name]=copy.deepcopy(before[name]);after[name]['leaves']['desc']=leaf(changed);times[role]=dict(self.interval)
  self.assertEqual(R.records(before,after,times)['status'],'PASS_SELECTED_FOUR_LOGICAL_RESTORATION')
  name=R.SELECTED[0][1]
  bad=copy.deepcopy(after);bad[name]['directory']['mode']=0o700
  with self.assertRaises(ValueError):R.records(before,bad,times)
  for key,value in(('body_base64',base64.b64encode(b'FOREIGN').decode()),('uid',1),('mode',0o600),('nlink',2)):
   bad=copy.deepcopy(after);bad[name]['leaves']['files'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):R.records(before,bad,times)
if __name__=='__main__':unittest.main(verbosity=2)
