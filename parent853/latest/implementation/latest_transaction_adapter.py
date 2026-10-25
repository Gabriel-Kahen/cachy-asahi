# SPDX-License-Identifier: MIT
"""Finite five-product native operands; original ALPM/noexec/security body held."""
import hashlib
import latest_plan as plan
HELD=dict(bytes=6105,sha256='c4efe235fd0a7ebe4ee65da5e139cfe272308b5c6c11ffa7a3bdf48600f1a087')
def derive(raw,role):
 plan.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==HELD,'whole original signed ALPM step source');_,name,old,new=plan.product(role);text=raw.decode()
 edits=[("NAME='cachy-asahi-apps'",'NAME='+repr(name)),(" C.need(Path(root)==Path('/work/main/root')and Path(keys)==Path('/work/test-verification')and Path(log).parent==Path('/out'),'fixed owned copy/ephemeral TEST verification scope')"," C.native_scope(root,keys,log)"),(" C.need(len(before)in(605,606)and len(after)in(605,606)and {k:v for k,v in before.items()if k!=NAME}=={k:v for k,v in after.items()if k!=NAME}and len({k:v for k,v in before.items()if k!=NAME})==605,'exact other605 versions held')"," C.need(len(before)in(606,607)and len(after)in(606,607)and {k:v for k,v in before.items()if k!=NAME}=={k:v for k,v in after.items()if k!=NAME}and len({k:v for k,v in before.items()if k!=NAME})in(605,606)and before.get('cachy-asahi-repository-runtime')==after.get('cachy-asahi-repository-runtime')=='0.1.0-1','exact all nonacted versions and protected Runtime1 held')"),(" C.need(before.get(NAME)in(None,'0.1.0-6','0.1.0-7')and after.get(NAME)in(None,'0.1.0-6','0.1.0-7'),'only Welcome4/5 selection')"," C.need(before.get(NAME)in"+repr(tuple(dict.fromkeys((None,old,new))))+"and after.get(NAME)in"+repr(tuple(dict.fromkeys((None,old,new))))+",'only fixed original/latest tool selection')"),("path.parent==Path('/runner/inputs/archives')","path.parent==Path('/tools606/latest/archives')"),("status='COMMITTED_SELECTED_APPS_REQUIRES_FULL_READBACK'","product=NAME,status='COMMITTED_SELECTED_LATEST_TOOL_REQUIRES_FULL_NATIVE_READBACK'")]
 for before,after in edits:plan.need(text.count(before)==1,'one exact native tool transaction seam');text=text.replace(before,after,1)
 restored=text
 for before,after in reversed(edits):plan.need(restored.count(after)==1,'one exact signed-step inverse seam');restored=restored.replace(after,before,1)
 plan.need(restored.encode()==raw,'complete original signed load/prepare/noexec/commit/inventory/expiry/retirement body inverse');compile(text,'<native-latest-tool-signed-step>','exec');return text,edits
