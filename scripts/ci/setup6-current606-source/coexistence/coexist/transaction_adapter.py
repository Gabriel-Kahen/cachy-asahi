# SPDX-License-Identifier: MIT
"""Full original Setup ALPM/signature/noexec primitive; native root/path only."""
import hashlib
import latest_plan as P
EDITS=((" C.need(Path(root)==Path('/work/main/root')and Path(keys)==Path('/work/test-verification')and Path(log).parent==Path('/out'),'fixed owned copy/ephemeral TEST verification scope')"," C.native_scope(root,keys,log)"),("path.parent==Path('/runner/inputs/archives')","path.parent==Path('/tools606/setup6/archives')"),("status='COMMITTED_SELECTED_SETUP6_REQUIRES_FULL_READBACK'","status='COMMITTED_NATIVE_SETUP6_REQUIRES_FULL_READBACK'"))
def derive(raw,wanted,role):
 P.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==wanted,'whole exact signed Setup primitive');_,name,old,new=P.product(role);edits=list(EDITS);edits[1]=(edits[1][0],"path.parent==Path('/tools606/"+('apps7'if role=='apps'else'setup6')+"/archives')");edits[2]=(edits[2][0],"status='COMMITTED_NATIVE_APPS7_SETUP6_REQUIRES_FULL_READBACK'");edits.extend([("NAME='cachy-asahi-setup'","NAME="+repr(name))]if role=='apps'else[]);edits.extend([("(None,'0.1.0-5','0.1.0-6')","(None,'0.1.0-6','0.1.0-7')")]if role=='apps'else[]);text=raw.decode()
 for old,new in edits:P.need(text.count(old)==(2 if old.startswith("(None,")else 1),'one native Setup transaction seam');text=text.replace(old,new)
 inverse=text
 for old,new in reversed(edits):P.need(inverse.count(new)==(2 if old.startswith("(None,")else 1),'one whole Setup transaction inverse');inverse=inverse.replace(new,old)
 P.need(inverse.encode()==raw,'all signature/dependency/lock/noexec/expiry/clock bodies held');return text
