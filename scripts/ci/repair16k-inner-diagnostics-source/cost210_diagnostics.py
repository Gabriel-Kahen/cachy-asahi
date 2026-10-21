# SPDX-License-Identifier: MIT
"""Bounded scalar copied-root cost DATA; never an acceptance or clock grant."""
import json,os,resource,time
COST_STAGES=('TREE_OBSERVE','SELECTED_LINKS','AUX_CHECKPOINT','SOURCE_BEFORE','CAPACITY_AND_DESTINATION_OPEN','DIRECTORIES','REGULAR_FILES','SYMLINKS','DIRECTORY_METADATA','DESTINATION_OBSERVE','SOURCE_AFTER','FINAL_ROOT_CHECKS','COMPLETE')
COST_EVENTS=('BEGIN','END','FAIL','POINT')
COST_COLUMNS=('monotonic_ns','process_cpu_ns','user_us','system_us','maxrss_kib','rchar','wchar','syscr','syscw','read_bytes','write_bytes','cancelled_write_bytes')
_cost_sequence=0;_cost_origin=None

def cost(stage,event):
 """One bounded procIO/rusage read; failure cannot alter original authority."""
 global _cost_sequence,_cost_origin
 try:
  if stage not in COST_STAGES or event not in COST_EVENTS or _cost_sequence>=64:return
  start=time.monotonic_ns();usage=resource.getrusage(resource.RUSAGE_SELF);cpu=time.process_time_ns()
  fd=os.open('/proc/self/io',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
  try:raw=os.read(fd,1025)
  finally:os.close(fd)
  if len(raw)>1024:return
  rows={}
  for line in raw.decode('ascii').splitlines():
   name,value=line.split(': ',1)
   if name in rows:return
   rows[name]=int(value)
  names=COST_COLUMNS[5:]
  if set(rows)!=set(names)or any(type(v)is not int or not -2**63<v<2**63 for v in rows.values()):return
  values=[start,cpu,int(usage.ru_utime*10**6),int(usage.ru_stime*10**6),usage.ru_maxrss,*[rows[n]for n in names]]
  if _cost_origin is None:_cost_origin=values[:]
  # Process-relative counters only: no paths, payload, PIDs, credentials or maps.
  delta=[v-b for v,b in zip(values,_cost_origin)];_cost_sequence+=1
  record=[1,_cost_sequence,COST_STAGES.index(stage),COST_EVENTS.index(event),*delta,time.monotonic_ns()-start]
  data=b'APPS574_COST '+json.dumps(record,separators=(',',':')).encode('ascii')+b'\n'
  if len(data)<=384:os.write(2,data)
 except BaseException:pass # Preserve original cancellation, refusal and cleanup.
