# SPDX-License-Identifier: MIT
"""Full original Setup ALPM/signature/noexec primitive; native root/path only."""
import hashlib
import latest_plan as P
EDITS=((" C.need(Path(root)==Path('/work/main/root')and Path(keys)==Path('/work/test-verification')and Path(log).parent==Path('/out'),'fixed owned copy/ephemeral TEST verification scope')"," C.native_scope(root,keys,log)"),("path.parent==Path('/runner/inputs/archives')","path.parent==Path('/tools606/setup6/archives')"),("status='COMMITTED_SELECTED_SETUP6_REQUIRES_FULL_READBACK'","status='COMMITTED_NATIVE_SETUP6_REQUIRES_FULL_READBACK'"))
def derive(raw,wanted):
 P.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==wanted,'whole exact signed Setup primitive');text=raw.decode()
 for old,new in EDITS:P.need(text.count(old)==1,'one native Setup transaction seam');text=text.replace(old,new,1)
 inverse=text
 for old,new in reversed(EDITS):P.need(inverse.count(new)==1,'one whole Setup transaction inverse');inverse=inverse.replace(new,old,1)
 P.need(inverse.encode()==raw,'all signature/dependency/lock/noexec/expiry/clock bodies held');return text
