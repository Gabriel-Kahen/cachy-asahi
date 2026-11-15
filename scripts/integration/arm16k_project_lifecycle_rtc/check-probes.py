#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Validate installed CLI outputs only; never touch sysfs or change policy."""
import json,sys
from pathlib import Path


def validate(directory,status,report):
 for name,code in (('status',status),('report',report)):
  if code not in (0,3):raise ValueError('unexpected diagnostic status')
  if code==3:
   if 'unavailable'not in(directory/(name+'.stderr')).read_text():raise ValueError('missing unavailable diagnostic')
   continue
  value=json.loads((directory/(name+'.json')).read_text())
  if value.get('tool')!='cachy-asahi-ksmctl'or value.get('version')!='0.1.0'or value.get('mode')!='read-only'or value.get('management_available')is not False:raise ValueError('diagnostic identity differs')
  if name=='report'and value.get('page_size_bytes')!=16384:raise ValueError('runtime CLI page size differs')
 return {'diagnostic':'read-only output/refusal only','KSM_kernel_functionality':'NOT QUALIFIED'}


if __name__=='__main__':validate(Path(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]))
