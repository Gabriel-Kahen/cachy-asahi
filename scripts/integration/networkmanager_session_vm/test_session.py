# SPDX-License-Identifier: MIT
import copy,importlib.util,json,unittest
from pathlib import Path
S=importlib.util.spec_from_file_location('session_vm_boot',Path(__file__).with_name('boot.py'));B=importlib.util.module_from_spec(S);S.loader.exec_module(B)
class Session(unittest.TestCase):
 def test_exact_nonce_unique_bounded_json_frame(self):
  data=b'NM_SESSION_BEGIN abc\r\n{"schema_version":1,"status":"HOLD"}\r\nNM_SESSION_END abc'
  self.assertEqual(B.parse_journey(data,'abc')['status'],'HOLD')
  for changed,nonce in [(data,'foreign'),(data+data,'abc'),(b'NM_SESSION_BEGIN abc\n'+b'x'*262145+b'\nNM_SESSION_END abc','abc')]:
   with self.assertRaises(AssertionError):B.parse_journey(changed,nonce)
 def test_accept_requires_real_identity_persistence_denial_and_root_preservation(self):
  value={'status':'PASS_X86_REAL_LOGIN_OWN_PROFILE_AND_DENIALS_ONLY','account':{'uid':1000,'gid':1000,'tty':'/dev/ttyS0','pid':20},'bus_identity':{'UnixUserID':1000,'ProcessID':20},'logind':{'Active':True,'Name':'builder','Type':'tty','Class':'user','Service':'login','Remote':False},'agent':{'registered':True,'same_real_login_session':True,'process_subject_pid':20},'own_create':{'success':True},'own_edit':{'success':True},'own_cleanup':{'success':True},'persistence':{'passed':True},'denials':[{'name':'system-delete','success':False},{'name':'foreign-delete','success':False}],'denied_state':{'passed':True,'complete_profile_policy_package_snapshot_unchanged':True},'root_observer':{'status':'PASS_X86_ROOT_OBSERVATION_ONLY','own_persisted':True,'denied_state_unchanged':True,'own_profile_cleanup':True,'user_and_original_profiles_preserved':True,'inventory_policy_PAM_unchanged':True,'initial':{'profile':'pin'},'final':{'profile':'pin'}},'agent_exit':-15}
  value['service_bus_identities']={service:{'credentials':{'UnixUserID':uid}}for service,uid in [('org.freedesktop.NetworkManager',0),('org.freedesktop.PolicyKit1',102),('org.freedesktop.login1',0)]};value['stock_service_states']=['active']*4
  B.accept(value)
  mutations=[('account','uid',0),('bus_identity','ProcessID',30),('logind','Active',False),('agent','same_real_login_session',False),('persistence','passed',False),('denied_state','complete_profile_policy_package_snapshot_unchanged',False),('root_observer','final',{'profile':'changed'})]
  for section,key,bad in mutations:
   changed=copy.deepcopy(value);changed[section][key]=bad
   with self.subTest(section=section,key=key),self.assertRaises(AssertionError):B.accept(changed)
  changed=copy.deepcopy(value);changed['denials'][0]['success']=True
  with self.assertRaises(AssertionError):B.accept(changed)
 def test_fixed_substrate_pin_and_policy_expectation(self):
  import hashlib
  self.assertEqual(hashlib.sha256((B.SUB/'boot.py').read_bytes()).hexdigest(),B.EXPECTED_BOOT)
  text=Path(__file__).with_name('client.py').read_text();self.assertNotIn('TEST-password',text);self.assertNotIn('pkexec',text)
if __name__=='__main__':unittest.main()
