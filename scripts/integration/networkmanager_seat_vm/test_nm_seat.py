# SPDX-License-Identifier: MIT
import copy,hashlib,importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('NM_seat_test_result',HERE/'result.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)
class NMSeat(unittest.TestCase):
 def fixture(self):
  root={'status':'PASS_X86_ROOT_OBSERVATION_ONLY','own_persisted':True,'denied_state_unchanged':True,'own_profile_cleanup':True,'user_and_original_profiles_preserved':True,'inventory_policy_PAM_unchanged':True,'initial':{'packages':'pinned','profiles':'original'},'final':{'packages':'pinned','profiles':'original'}}
  user={'status':'PASS_X86_REAL_SEAT_NM_PROFILE_LIFECYCLE_ONLY','identity':{'uid':1000,'gid':1000,'pid':600,'groups':[1000],'tty':'/dev/tty1','bus_credentials':{'UnixUserID':1000,'ProcessID':600}},'logind':{'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1','Seat':['seat0','/seat0'],'User':[1000,'/user1000']},'sd_session_get_seat':{'return':0,'seat':'seat0'},'own_authorization_no_interaction':[True,False,{}],'policy_sha256':'6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446','NM_version':'1.58.1','additional_credential_sent':False,'authentication_agent_started':False,'service_bus_identities':{'org.freedesktop.NetworkManager':{'UnixUserID':0},'org.freedesktop.PolicyKit1':{'UnixUserID':102}},'own_create':{'success':True},'own_edit':{'success':True},'own_cleanup':{'success':True},'persistence':{'passed':True},'denials':[{'name':'system-delete','success':False},{'name':'foreign-delete','success':False}],'denied_state':{'passed':True,'complete_profile_policy_package_snapshot_unchanged':True},'root_observer':root}
  return {'client':user,'root':root}
 def test_generic_seat_success_alone_or_missing_real_nm_results_is_refused(self):
  V.accept(self.fixture())
  for value in [{},{'client':{'status':'PASS_X86_REAL_SEAT_USER_PROOF_ONLY'},'root':{}},{'client':{'status':'HOLD'},'root':{}}]:
   with self.assertRaises((AssertionError,KeyError)):V.accept(value)
 def test_real_identity_seat_nochallenge_and_noextra_credential_required(self):
  for section,key,bad in [('identity','uid',0),('identity','groups',[0,1000]),('identity','tty','/dev/ttyS0'),('logind','Active',False),('sd_session_get_seat','seat',None)]:
   value=copy.deepcopy(self.fixture());value['client'][section][key]=bad
   with self.subTest(section=section,key=key),self.assertRaises(AssertionError):V.accept(value)
  for key,bad in [('additional_credential_sent',True),('authentication_agent_started',True),('own_authorization_no_interaction',[False,True,{}])]:
   value=copy.deepcopy(self.fixture());value['client'][key]=bad
   with self.assertRaises(AssertionError):V.accept(value)
 def test_actual_persistence_denials_cleanup_and_root_preservation_required(self):
  for section,key in [('own_create','success'),('own_edit','success'),('own_cleanup','success'),('persistence','passed'),('denied_state','complete_profile_policy_package_snapshot_unchanged')]:
   value=copy.deepcopy(self.fixture());value['client'][section][key]=False
   with self.assertRaises(AssertionError):V.accept(value)
  value=copy.deepcopy(self.fixture());value['client']['denials'][0]['success']=True
  with self.assertRaises(AssertionError):V.accept(value)
  value=copy.deepcopy(self.fixture());value['root']['final']={'profiles':'changed'}
  with self.assertRaises(AssertionError):V.accept(value)
 def test_retained_source_pins_and_original_controller_are_exact(self):
  references=json.loads((HERE/'references.json').read_text())
  for name,ref in references.items():self.assertEqual(hashlib.sha256((HERE.parent/name).read_bytes()).hexdigest(),ref['sha256'],name)
if __name__=='__main__':unittest.main()
