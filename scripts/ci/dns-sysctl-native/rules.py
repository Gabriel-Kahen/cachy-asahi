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
