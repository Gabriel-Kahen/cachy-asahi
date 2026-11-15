# SPDX-License-Identifier: MIT
"""Match actual event leaf to stock seat-tagged input parent, without mutation."""
import re
from pathlib import PurePosixPath
RULE_SHA256='b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3'
def properties(text):
 result={}
 for line in text.splitlines():
  if not line:continue
  key,value=line.split('=',1)
  if key in result:raise ValueError('duplicate udev property')
  result[key]=value
 return result
def is_seat_keyboard(record):
 try:
  if record['name']!='AT Translated Set 2 keyboard':return False
  leaf=PurePosixPath(record['sysfs_path']);parent=PurePosixPath(record['parent_sysfs_path'])
  if '..'in leaf.parts or '..'in parent.parts or leaf.parent!=parent:return False
  if not re.fullmatch(r'event[0-9]+',leaf.name)or not re.fullmatch(r'input[0-9]+',parent.name):return False
  if not str(parent).startswith('/sys/devices/')or'i8042'not in parent.parts:return False
  event=properties(record['properties']);device=properties(record['parent_properties'])
  if event.get('DEVPATH')!=str(leaf)[4:]or event.get('DEVNAME')!='/dev/input/'+leaf.name:return False
  if event.get('ID_INPUT_KEYBOARD')!='1'or event.get('ID_BUS')!='i8042':return False
  if device.get('DEVPATH')!=str(parent)[4:]or device.get('SUBSYSTEM')!='input':return False
  if 'seat'not in device.get('TAGS','').split(':')or device.get('ID_SEAT','seat0')!='seat0':return False
  tag=device.get('ID_PATH_TAG','')
  return bool(re.fullmatch('[A-Za-z0-9_-]+',tag))and device.get('ID_FOR_SEAT')=='input-'+tag
 except (KeyError,TypeError,ValueError):return False
