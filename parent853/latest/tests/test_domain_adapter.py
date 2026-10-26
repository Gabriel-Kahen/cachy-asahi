# SPDX-License-Identifier: MIT
import base64,copy,hashlib,importlib.util,sys,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D/'implementation'))
import latest_domain as LD,latest_restoration as R,latest_preservation_adapter as A
BASE=D.parent/'historical/boot391'
class Domain(unittest.TestCase):
 def setUp(self):LD._before=None;LD._restoration=None
 def test_native606_andouter_fullsource_inverses(self):
  raw=(BASE/'held606/scripts/ci/current606-native/tools606.py').read_bytes();old=" checkpoint('baseline604',base);install('install606');install('same-version606');remove('remove604');install('reinstall606');remove('final604')";new=" checkpoint('baseline604',base);install('install606');install('same-version606')\n import latest_component\n previous_ld,previous_aux=latest_component.exercise(g,locals())\n remove('remove604');install('reinstall606');remove('final604')";text,edits=A.native606(raw,old,new);back=text
  for before,after,count in reversed(edits):self.assertEqual(back.count(after),count);back=back.replace(after,before)
  self.assertEqual(back.encode(),raw)
  raw=(BASE/'held606/held604/scripts/ci/expanded604-apps6-public-pairs/lifecycle.py').read_bytes();text,edits=A.outer(raw);back=text
  for before,after in reversed(edits):self.assertEqual(back.count(after),1);back=back.replace(after,before)
  self.assertEqual(back.encode(),raw);self.assertIn('selected_record_domain=',text)
 def test_outerdesc_only_after_fullfour_field_proof(self):
  before={};after={};clocks={};original=b'%NAME%\ncachy-asahi-ksmctl\n\n%VERSION%\n0.1.0-1\n\n%INSTALLDATE%\n100\n\n';restored=original.replace(b'100',b'200')
  def leaf(raw):return dict(body_base64=base64.b64encode(raw).decode(),mode=0o644,uid=0,gid=0,nlink=1)
  for role,name,version in R.SELECTED:
   owned=original.replace(b'cachy-asahi-ksmctl',name.encode()).replace(b'0.1.0-1',version.encode())
   before[name]=dict(version=version,directory=copy.deepcopy(R.DIRECTORY),leaves=dict(desc=leaf(owned),files=leaf(b'INERT_FILES'),mtree=leaf(b'INERT_MTREE')));after[name]=copy.deepcopy(before[name]);after[name]['leaves']['desc']=leaf(owned.replace(b'100',b'200'));clocks[role]=dict(authority='SOURCE_OWNED_TRANSACTION_WALLCLOCK_NOT_ROOT_OBSERVATION',start_seconds=199,end_seconds=201,monotonic_seconds=2)
  path='/var/lib/pacman/local/cachy-asahi-ksmctl-0.1.0-1/desc';tree={path:dict(type='file',mode=0o644,uid=0,gid=0,size=len(original),sha256=R.pin(original)['sha256']),path.rsplit('/',1)[0]:dict(type='directory',mode=0o755,uid=0,gid=0)};changed=copy.deepcopy(tree);changed[path].update(size=len(restored),sha256=R.pin(restored)['sha256']);LD.begin_original_records({'cachy-asahi-ksmctl':tree});self.assertTrue(LD.original_record_equal('cachy-asahi-ksmctl',tree,tree))
  with self.assertRaises(ValueError):LD.original_record_equal('cachy-asahi-ksmctl',changed,tree)
  LD.bind_restoration(before,after,clocks);self.assertTrue(LD.original_record_equal('cachy-asahi-ksmctl',changed,tree));self.assertFalse(LD.original_record_equal('unselected',changed,tree));bad=copy.deepcopy(changed);bad[path]['mode']=0o600;self.assertFalse(LD.original_record_equal('cachy-asahi-ksmctl',bad,tree));bad=copy.deepcopy(changed);bad[path.rsplit('/',1)[0]]['uid']=1;self.assertFalse(LD.original_record_equal('cachy-asahi-ksmctl',bad,tree))
if __name__=='__main__':unittest.main(verbosity=2)
