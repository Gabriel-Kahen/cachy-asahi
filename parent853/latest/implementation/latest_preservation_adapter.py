# SPDX-License-Identifier: MIT
"""Finite selected-four logical scope over complete genuine native606 source."""
import ast,hashlib
import latest_plan as plan

def one(text,before,after):
 plan.need(text.count(before)==1,'one exact native preservation-domain seam');return text.replace(before,after,1)
TOOLS_EDITS=(
 ("base_digest=I.preserve_base(L,state)","base_digest=I.preserve_base(L,LR.unselected_base(state))"),
 ("I.preserve_base(L,state)==base_digest,'all604 original payload/inode/rawDB preserved'","I.preserve_base(L,LR.unselected_base(state))==base_digest,'all599 nonselected original payload/inode/rawDB physically preserved'"),
 ("all604_preserved=True","other599_physical_preservation=True,selected_five_domain='EXACT_TYPED_ALPM_NO_SELECTED_INODE_RESTORATION'"),
 ("base604_state_sha256=base_digest","unselected599_state_sha256=base_digest,selected_five_logical_restoration='REQUIRES_LATEST_COMPONENT_COMPLETE_PROOF'"),
)
OUTER_ANCHOR="C.need(all(records.get(n)==r for n,r in baseline_records.items() if n not in C.UPGRADES),\n                   'original585 non-upgrade database changed')"
OUTER_REPLACEMENT="C.need(all(LD.original_record_equal(n,records.get(n),r) for n,r in baseline_records.items() if n not in C.UPGRADES),\n                   'original non-upgrade database except exact source-proven INSTALLDATE domain changed')"

def native606(raw,old_insertion,new_insertion):
 text=raw.decode();edits=[('import hashlib,json,os,pwd,sys',"import hashlib,json,os,pwd,sys\nsys.path.insert(0,'/runner/latest')\nimport latest_restoration as LR"),*TOOLS_EDITS,(old_insertion,new_insertion)]
 # The two per-event branches deliberately carry the same old literal. All
 # occurrences are counted and recovered; none of their other fields change.
 counted=[]
 for before,after in edits:
  count=2 if before=='all604_preserved=True'else 1;plan.need(text.count(before)==count,'exact counted native606 selected-domain seam');text=text.replace(before,after);counted.append((before,after,count))
 restored=text
 for before,after,count in reversed(counted):plan.need(restored.count(after)==count,'whole native606 inverse count');restored=restored.replace(after,before)
 plan.need(restored.encode()==raw,'entire original native606 body outside typed selected-four domain');compile(text,'<native606-latest-tools-typed-domain>','exec');return text,counted

def outer(raw):
 text=raw.decode();edits=[('import sys\nsys.path.insert(0,str(Path(__file__).resolve().parent))','import sys\nsys.path.insert(0,str(Path(__file__).resolve().parent))\nimport latest_domain as LD'),("        baseline_db,baseline_records=database()","        baseline_db,baseline_records=database()\n        LD.begin_original_records(baseline_records)"),(OUTER_ANCHOR,OUTER_REPLACEMENT),("originals_preserved=True,user_config_preserved=True","originals_preserved=True,user_config_preserved=True,selected_record_domain='EXACT_SOURCE_PROVEN_INSTALLDATE_ONLY'")]
 for before,after in edits:text=one(text,before,after)
 restored=text
 for before,after in reversed(edits):restored=one(restored,after,before)
 plan.need(restored.encode()==raw,'whole original587/604 source outside one exact typed rawDB field domain');compile(text,'<native604-latest-tools-typed-record-domain>','exec');return text,edits
