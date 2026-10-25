# SPDX-License-Identifier: MIT
"""Invoke only source-closed tests through actual installed script/helper locations."""
import json

def observe(home,session,phase,work,user,L):
 result={}
 for mode,key,count in (('apps','apps16_installed_controls',15),('client','client_v2_installed_controls',2),('apps-stage','apps16_stage_controls',4)):
  value=json.loads(user(home,session,['/usr/bin/python3','-I','-B','/runner/fixture_checks.py',mode]))
  L.need(value.get('status')=='PASS_INSTALLED_CONTROLS'and value.get('tests')==count and value.get('installed_source')is True,'actual installed source controls failed: '+mode)
  result[key]=value
 return result
