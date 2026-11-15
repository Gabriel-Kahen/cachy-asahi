# SPDX-License-Identifier: MIT
"""Accept only actual ordinary-seat writes plus independent root preservation."""
def accept(value):
 user=value['client'];root=value['root'];assert user['status']=='PASS_X86_REAL_SEAT_NM_PROFILE_LIFECYCLE_ONLY',user.get('failure')
 identity=user['identity'];assert identity['uid']==identity['gid']==1000 and identity['tty']=='/dev/tty1'and identity['groups']==[1000]and identity['bus_credentials']['UnixUserID']==1000 and identity['bus_credentials']['ProcessID']==identity['pid']
 props=user['logind']
 for k,v in {'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1'}.items():assert props[k]==v
 assert props['Seat'][0]=='seat0'and props['User'][0]==1000 and user['sd_session_get_seat']=={'return':0,'seat':'seat0'}
 assert user['own_authorization_no_interaction'][0]is True and user['own_authorization_no_interaction'][1]is False
 assert user['policy_sha256']=='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'and user['NM_version']=='1.58.1'
 assert user['additional_credential_sent']is False and user['authentication_agent_started']is False
 for service,uid in [('org.freedesktop.NetworkManager',0),('org.freedesktop.PolicyKit1',102)]:assert user['service_bus_identities'][service]['UnixUserID']==uid
 assert user['own_create']['success']and user['own_edit']['success']and user['own_cleanup']['success']and user['persistence']['passed']
 assert len(user['denials'])==2 and {d['name']for d in user['denials']}=={'system-delete','foreign-delete'}and all(d['success']is False for d in user['denials'])
 assert user['denied_state']['passed']and user['denied_state']['complete_profile_policy_package_snapshot_unchanged']
 for observation in [root,user['root_observer']]:
  assert observation['status']=='PASS_X86_ROOT_OBSERVATION_ONLY'
  for key in ['own_persisted','denied_state_unchanged','own_profile_cleanup','user_and_original_profiles_preserved','inventory_policy_PAM_unchanged']:assert observation[key]is True
  assert observation['initial']==observation['final']
 assert root==user['root_observer'],'root snapshot result differs from user handoff'
