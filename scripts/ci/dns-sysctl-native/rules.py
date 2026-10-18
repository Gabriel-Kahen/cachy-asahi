# SPDX-License-Identifier: MIT
"""Finite signed disposable576/574 lifecycle; fixture observations grant no live effect."""
import re

def need(ok,message):
 if not ok:raise ValueError(message)

def validate(value):
 need(value.get('status')=='PASS_DNS_SYSCTL_SIGNED_PRIVATE_LIFECYCLE'and value.get('base_count')==574 and value.get('installed_count')==576 and value.get('base574_preserved')is True and value.get('user_preserved')is True and value.get('signatures')=='REQUIRED_EPHEMERAL_TEST_ONLY'and re.fullmatch('[A-F0-9]{40}',value.get('signer')or'')and value.get('architecture')=='aarch64'and type(value.get('page_size'))is int and value['page_size']>0 and value.get('hardware')=='NOT_RUN'and value.get('live_DNS')=='NOT_RUN'and value.get('host_sysctl_mutation')=='NOT_RUN'and value.get('release')=='NOT_ADMITTED','signed native fixture lifecycle absent')
 events=value.get('events');need(type(events)is list and len(events)==5,'five exact lifecycle transitions required')
 for row,(phase,count)in zip(events,(('install',576),('same-version-reinstall',576),('remove',574),('reinstall-after-removal',576),('final-remove',574))):
  need(row.get('phase')==phase and row.get('count')==count and row.get('base574_preserved')is True and row.get('user_preserved')is True,'exact574/user preservation absent')
  if count==576:
   observations=row.get('observations');need(type(observations)is list and len(observations)==2 and {r.get('home')for r in observations}=={'dns-sysctl-home-fresh','dns-sysctl-home-existing'},'two ordinary-user installed cases required')
   for record in observations:
    need(record.get('dns')=='PASS_INSTALLED_21_PRIVATE_AND_OFFLINE_CONTROLS'and record.get('sysctl')=='PASS_INSTALLED_PRIVATE_MODEL_CONTROLS'and record.get('help')==['cachy-asahi-dns','cachy-asahi-sysctl']and record.get('sysctl_keys')=='PASS_READONLY_FIXED_KEYS'and record.get('host_NM_write')=='NOT_RUN'and record.get('host_sysctl_write')=='NOT_RUN','installed source-joined fixture checks absent')
  else:need(row.get('payloads_absent')is True,'removed owned payload remains')

def validate_profile(value,program_sha256):
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
