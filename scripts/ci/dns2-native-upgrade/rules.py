# SPDX-License-Identifier: MIT
"""Finite signed disposable575/574 lifecycle; fixture observations grant no live effect."""
import re

def need(ok,message):
 if not ok:raise ValueError(message)

def validate(value):
 need(value.get('status')=='PASS_DNS2_UPGRADE_SIGNED_PRIVATE_LIFECYCLE'and value.get('base_count')==574 and value.get('installed_count')==575 and value.get('base574_preserved')is True and value.get('user_preserved')is True and value.get('production_trust_preserved')is True and value.get('signatures')=='REQUIRED_EPHEMERAL_TEST_ONLY'and re.fullmatch('[A-F0-9]{40}',value.get('signer')or'')and value.get('architecture')=='aarch64'and type(value.get('page_size'))is int and value['page_size']>0 and value.get('hardware')=='NOT_RUN'and value.get('live_DNS')==value.get('host_sysctl_mutation')=='NOT_RUN'and value.get('release')=='NOT_ADMITTED','signed native DNS upgrade lifecycle absent')
 events=value.get('events');need(type(events)is list and len(events)==5,'five exact same-package lifecycle transitions required')
 expected=(('install-v1',575,'cachy-asahi-dns','0.1.0-1',21),('upgrade-v1-to-v2',575,'cachy-asahi-dns2','0.1.0-2',27),('remove-v2',574,None,None,None),('reinstall-v2',575,'cachy-asahi-dns2','0.1.0-2',27),('final-remove-v2',574,None,None,None))
 for row,(phase,count,role,version,controls)in zip(events,expected):
  need(row.get('phase')==phase and row.get('count')==count and row.get('base574_preserved')is True and row.get('user_preserved')is True and row.get('production_trust_preserved')is True,'exact574/user/production trust preservation absent')
  if count==575:
   need(row.get('package_name')=='cachy-asahi-dns'and row.get('version')==version and row.get('recipe_role')==role,'actual same-package version/role differs')
   observations=row.get('observations');need(type(observations)is list and len(observations)==2 and {r.get('home')for r in observations}=={'dns-upgrade-home-fresh','dns-upgrade-home-existing'},'two ordinary-user installed cases required')
   for record in observations:
    need(record.get('status')=='PASS_INSTALLED_DNS_PRIVATE_OFFLINE_FIXTURES'and record.get('recipe_role')==role and record.get('package_name')=='cachy-asahi-dns'and record.get('version')==version and record.get('controls')==controls and re.fullmatch('[a-f0-9]{64}',record.get('program_sha256')or'')and record.get('help')=='PASS'and record.get('host_NM_write')==record.get('live_DNS')=='NOT_RUN','installed exact-version21/27 fixture receipt absent')
    stream=record.get('suite',{});need(set(stream)=={'stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256','exit_code'}and type(stream['exit_code'])is int and stream['exit_code']==0,'installed suite must actually exit0')
    need(all(type(stream[k+'_bytes'])is int and 0<=stream[k+'_bytes']<=128*1024 and re.fullmatch('[a-f0-9]{64}',stream[k+'_sha256']or'')for k in('stdout','stderr'))and stream['stdout_bytes']+stream['stderr_bytes']>0,'complete bounded installed stream receipts required')
  else:need(row.get('payloads_absent')is True,'removed owned payload remains')

def frame(value,*,pid,ppid,supervisor=False):
 need(type(value)is dict and set(value)=={'Pid','PPid','CapInh','CapPrm','CapEff','CapAmb','CapBnd','NoNewPrivs'}and all(type(v)is str for v in value.values()),'exact observed process privilege frame required')
 need(value['Pid']==str(pid)and value['PPid']==str(ppid)and value['NoNewPrivs']=='1'and all(re.fullmatch('[a-f0-9]{16}',value[k])for k in('CapInh','CapPrm','CapEff','CapAmb','CapBnd')),'PID/PPID/NoNewPrivs/capability encoding differs')
 need(int(value['CapBnd'],16)==0xdb and int(value['CapEff'],16)==int(value['CapPrm'],16)==(0xdb if supervisor else 0)and int(value['CapInh'],16)==int(value['CapAmb'],16)==0,'original-six supervisor or zero E/P/I/A worker/daemon required')

def supervision(value):
 binding=value.get('supervision');need(type(binding)is dict and set(binding)=={'route','supervisor','namespaces','worker','worker_exit','worker_group_absent'}and binding['route']=='ORIGINAL_SIX_CAP_SUPERVISOR_ZERO_CAP_NM_WORKER'and type(binding['worker_exit'])is int and binding['worker_exit']==0 and binding['worker_group_absent']is True,'direct worker wait/group retirement required')
 frame(binding['supervisor'],pid=1,ppid=0,supervisor=True)
 worker=binding['worker'];need(type(worker)is dict and set(worker)=={'pid','ppid','nonce','frame','namespaces'}and type(worker['pid'])is int and worker['pid']>1 and type(worker['ppid'])is int and worker['ppid']==1 and type(worker['nonce'])is str and re.fullmatch('[a-f0-9]{32}',worker['nonce']),'exact finite supervisor worker nonce/PID binding required')
 frame(worker['frame'],pid=worker['pid'],ppid=1)
 namespaces=binding['namespaces'];need(type(namespaces)is dict and set(namespaces)=={'pid','mnt','net','user'}and all(type(v)is str and re.fullmatch(k+r':\[[1-9][0-9]*\]',v)for k,v in namespaces.items())and namespaces==worker['namespaces'],'same observed PID/mount/network/user namespaces required')
 need(value.get('worker_binding')==worker,'standalone worker/parent handshake differs')
 events=value.get('events');need(type(events)is list and len(events)==5,'complete private worker operation frame required')
 for event in events[:2]:
  need(type(event.get('pid'))is int and event['pid']>1 and event.get('pgid')==event['pid']and event.get('namespaces')==namespaces,'direct daemon group/namespace binding absent')
  frame(event.get('observed_after_exec'),pid=event['pid'],ppid=worker['pid'])
 groups=value.get('retirement',{}).get('groups',[]);need([r.get('pid')for r in groups]==[r.get('pid')for r in reversed(events[:2])],'observed daemon PIDs and actual retirement differ')

def validate_profile(value,program_sha256):
 supervision(value)
 need(value.get('status')=='PASS_REAL_PRIVATE_STORED_PROFILE_INTEGRATION'and value.get('architecture')=='aarch64'and value.get('cap_eff')=='0000000000000000'and value.get('interfaces')==['lo']and value.get('source_program_sha256')==program_sha256 and value.get('PolicyKit')=='NOT_TESTED_PRIVATE_AUTH_POLKIT_FALSE'and value.get('live_DNS')==value.get('interface_activation')==value.get('host_mutation')=='NOT_RUN','real native zero-cap private profile receipt required')
 need(value.get('stored_profiles_deleted')is True and value.get('base574_preserved')is True and value.get('base_count')==574 and value.get('network_state_preserved')is True and type(value.get('network_before'))is dict and value['network_before']and value['network_before']==value.get('network_after')and value.get('program_delivery')=='SOURCE_BYTES_EQUAL_VERIFIED_NATIVE_BUILD_A_PAYLOAD_READONLY_MOUNT','original574/private namespace preservation required')
 for name in('base_manifest_sha256','native_archive_sha256'):need(type(value.get(name))is str and re.fullmatch('[a-f0-9]{64}',value[name]),'exact source-enforced original byte identity')
 retirement=value.get('retirement',{});groups=retirement.get('groups')
 need(retirement.get('status')=='PASS_DAEMONS_REAPED_OWN_STATE_REMOVED'and retirement.get('private_work_removed')is True and retirement.get('resolver_preserved')is True and type(groups)is list and len(groups)==2 and [row.get('role')for row in groups]==['NetworkManager','dbus']and all(type(row.get('pid'))is int and row['pid']>1 and type(row.get('returncode'))is int and row['returncode']==0 and row.get('group_absent')is True for row in groups),'both daemon groups naturally retired before maps')
 events=value.get('events');need(type(events)is list and len(events)==5 and [r.get('kind')for r in events]==['daemon-start','daemon-start','stored-profile-roundtrip','stored-profile-roundtrip','foreign-edit-refused'],'complete bounded real private profile operations required')
 before={'ipv4.dns':['192.0.2.53'],'ipv4.ignore-auto-dns':'no','ipv6.dns':['2001:db8::53'],'ipv6.ignore-auto-dns':'no'}
 for row,label,ipv4,ipv6 in zip(events[2:4],('nonempty','empty'),(['1.1.1.1','9.9.9.9'],[]),(['2001:4860:4860::8888'],[])):
  need(row.get('status')=='PASS'and row.get('case')==label and row.get('before')==before and row.get('applied')=={'ipv4.dns':ipv4,'ipv4.ignore-auto-dns':'yes','ipv6.dns':ipv6,'ipv6.ignore-auto-dns':'yes'}and re.fullmatch('[a-f0-9]{64}',row.get('receipt_sha256')or''),'real both-family/empty-list stored profile roundtrip required')
 need(events[2]['restored_raw_sha256']==events[3]['restored_raw_sha256']and re.fullmatch('[a-f0-9]{64}',events[2]['restored_raw_sha256'])and events[-1].get('status')=='PASS'and re.fullmatch('[a-f0-9]{64}',events[-1].get('preserved_raw_sha256')or''),'restored baseline/foreign-edit refusal identities required')
 # This projection is only synthetic fixture metadata, never a host profile capture.
 grammar=value.get('discovery_grammar');names=('ordinary profile','colon:name','back\\slash','Café 東京','line\nbreak','tab\there','escape\x1b[31m')
 need(type(grammar)is list and len(grammar)==len(names),'all real private NM discovery cases required')
 for row,name in zip(grammar,names):
  need(row.get('name')==name and row.get('stored_fields_preserved')is True and type(row.get('terse'))is str and type(row.get('detail'))is str,'exact genuine grammar/preservation receipt required')
  uuid='5f7d4f36-a20e-4bd8-9f15-4e6e68731410';escaped=name.replace('\\','\\\\').replace(':','\\:')
  need(row['terse']==uuid+':802-3-ethernet:'+escaped+'\n'and row['detail']==uuid+'\n802-3-ethernet\n'+name+'\n','exact native NM raw escaped metadata projection differs')
  result=row.get('installed_discovery')
  if '\n'in name:need(result=='REFUSED_AMBIGUOUS_MULTILINE','real multiline name must refuse')
  else:need(type(result)is dict and set(result)=={'status','profiles','live_dns'}and result.get('live_dns')=='NOT_REAPPLIED_STORED_PROFILE_ONLY'and result.get('status')=='STORED_CONNECTION_PROFILES'and result.get('profiles')==[dict(uuid='5f7d4f36-a20e-4bd8-9f15-4e6e68731410',type='802-3-ethernet',name=name)],'actual native discovery must return exact stored synthetic metadata')
