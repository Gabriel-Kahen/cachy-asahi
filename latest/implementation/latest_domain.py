# SPDX-License-Identifier: MIT
"""One owned PID1 record-domain state, no filesystem cache or old digest claim."""
import base64,copy,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'latest'))
import latest_restoration as R
_before=None
_restoration=None

def begin_original_records(records):
 global _before
 R.plan.need(_before is None and type(records)is dict,'one original587 raw DB before-domain')
 chosen={name:copy.deepcopy(records[name])for _,name,_ in R.SELECTED if name in records}
 R.plan.need(set(chosen)=={'cachy-asahi-ksmctl'},'exact selected KSM1 already in original587; other selected tools are later additions')
 _before=chosen

def bind_restoration(before,after,transactions):
 global _restoration
 R.plan.need(_before is not None and _restoration is None,'one complete selected-four restoration proof')
 proof=R.records(before,after,transactions)
 _restoration=dict(before=copy.deepcopy(before),after=copy.deepcopy(after),proof=copy.deepcopy(proof))
 return proof

def original_record_equal(name,current,before):
 if current==before:return True
 if name!='cachy-asahi-ksmctl':return False
 R.plan.need(_before is not None and _restoration is not None and before==_before[name],'complete original/current selected record proof before normalization')
 a=_restoration['before'][name];b=_restoration['after'][name];version=a['version'];root='/var/lib/pacman/local/'+name+'-'+version
 # Original outer observer retains whole tree hashes/modes/owners. Rebind only
 # the one desc byte count/hash AFTER complete full-byte INSTALLDATE proof.
 original=base64.b64decode(a['leaves']['desc']['body_base64'],validate=True);restored=base64.b64decode(b['leaves']['desc']['body_base64'],validate=True);path=root+'/desc';old=before.get(path)
 R.plan.need(type(old)is dict and old.get('type')=='file'and old.get('size')==len(original)and old.get('sha256')==R.pin(original)['sha256']and all(old.get(k)==a['leaves']['desc'][k]for k in('mode','uid','gid')),'outer original KSM1 desc matches complete native606 before bytes')
 expected=copy.deepcopy(before);expected[path]=dict(old,size=len(restored),sha256=R.pin(restored)['sha256'])
 return current==expected
