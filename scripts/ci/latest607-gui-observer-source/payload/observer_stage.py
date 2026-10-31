# SPDX-License-Identifier: MIT
"""At most2KiB fixed observer boundary DATA; no paths, user bytes or authority."""
import json,os,time
STAGES=('inventory_begin','inventory_end','metadata_begin','metadata_end','payload_begin','payload_end','recheck_begin','recheck_end')
CAP=2048
class Stages:
 def __init__(self):self.start=time.monotonic_ns();self.last=-1;self.bytes=0
 def mark(self,stage):
  try:
   if type(stage)is not str or stage not in STAGES:return False
   ordinal=STAGES.index(stage)
   if ordinal<=self.last:return False
   raw=('INSTALLED607_OBSERVER_STAGE_DATA '+json.dumps(dict(schema=1,role='EXACT_INSTALLED607_VERIFY',stage=stage,ordinal=ordinal+1,elapsed_ns=min(max(time.monotonic_ns()-self.start,0),605000000000),status='BOUNDARY_DATA_ONLY_NOT_ACCEPTANCE'),sort_keys=True,separators=(',',':'))+'\n').encode()
   if self.bytes+len(raw)>CAP:return False
   self.last=ordinal;self.bytes+=len(raw);return os.write(2,raw)==len(raw)
  except Exception:return False
