"""Exact focus reply loss cannot replace required owned UI postconditions."""
import copy,unittest
from pathlib import Path
from unittest.mock import patch
import test_gui as T
C=T.C;HERE=Path(__file__).resolve().parent
class FocusReply(unittest.TestCase):
 def proof(self):
  label=T.UI['labels']['orphans'];value,window=T.scroll_proof(label)
  value.update(method='PEER_FOCUS_SCROLL',unclipped_after_scroll=False,peer_focus_reply='TIMEOUT_STATE_CONFIRMED',peer_focus_error='timeout from dbind',peer_focus=dict(pid=80,role=62,name_base64='VmlldyByZXBvcnQ=',scope='Orphan assessment',enabled=True,sensitive=True,focused=True,same_panel=True,target_enabled=False,target_sensitive=False))
  return value,window,label
 def test_timeout_must_independently_confirm_all_original_postconditions(self):
  proof,window,label=self.proof();C.visible_control(proof,80,label,window)
  for field,value in (('pid',81),('role',43),('focused',False),('enabled',False),('sensitive',False),('same_panel',False),('target_enabled',True),('target_sensitive',True)):
   bad=copy.deepcopy(proof);bad['peer_focus'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
  bad=copy.deepcopy(proof);bad['chain'][1]['rect'][3]=50
  with self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
 def test_only_exact_peer_timeout_can_have_confirmed_outcome(self):
  proof,window,label=self.proof()
  for key,value in (('peer_focus_reply','UNKNOWN'),('peer_focus_error',None),('peer_focus_error','other failure')):
   bad=copy.deepcopy(proof);bad[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
  for key in ('peer_focus_reply','peer_focus_error'):
   bad=copy.deepcopy(proof);bad.pop(key)
   with self.assertRaises(ValueError):C.visible_control(bad,80,label,window)
  ordinary,window=T.scroll_proof(label);ordinary.update(peer_focus_reply='TIMEOUT_STATE_CONFIRMED',peer_focus_error='timeout from dbind')
  with self.assertRaises(ValueError):C.visible_control(ordinary,80,label,window)
 def test_c_path_never_repeats_or_widens_deadlines_and_verifies_before_receipt(self):
  text=(HERE/'a11y_driver.c').read_text()
  self.assertIn('if (!replied && error && !strcmp(error->message, "timeout from dbind"))',text)
  self.assertEqual(text.count('atspi_component_grab_focus(peer_component, &error)'),1)
  start=text.index('peer_timed_out = peer_focus_timeout(');end=text.index('"TIMEOUT_STATE_CONFIRMED" : "REPLIED"')
  for guard in ('check(settled_geometry(pid, &value)', '"actual peer focused state"','"disabled target state preserved"'):
   self.assertLess(start,text.index(guard,start));self.assertLess(text.index(guard,start),end)
  self.assertIn('alarm(20); atspi_set_timeout(1000, 1000)',text)
if __name__=='__main__':unittest.main()
