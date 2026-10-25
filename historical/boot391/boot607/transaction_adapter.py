# SPDX-License-Identifier: MIT
"""Finite native Boot selection adapter to the whole original ALPM primitive."""
import hashlib

ORIGINAL = 'copyworker/scripts/ci/current606-apps7-copy/alpm_step.py'
ORIGINAL_SHA256 = 'c4efe235fd0a7ebe4ee65da5e139cfe272308b5c6c11ffa7a3bdf48600f1a087'
EDITS = (
 ("NAME='cachy-asahi-apps'", "NAME='cachy-asahi-boot-report'"),
 (" C.need(Path(root)==Path('/work/main/root')and Path(keys)==Path('/work/test-verification')and Path(log).parent==Path('/out'),'fixed owned copy/ephemeral TEST verification scope')", " C.native_scope(root,keys,log)"),
 (" C.need(len(before)in(605,606)and len(after)in(605,606)and {k:v for k,v in before.items()if k!=NAME}=={k:v for k,v in after.items()if k!=NAME}and len({k:v for k,v in before.items()if k!=NAME})==605,'exact other605 versions held')", " C.need(len(before)in(606,607)and len(after)in(606,607)and {k:v for k,v in before.items()if k!=NAME}=={k:v for k,v in after.items()if k!=NAME}and len({k:v for k,v in before.items()if k!=NAME})==606,'exact other606 versions held')"),
 (" C.need(before.get(NAME)in(None,'0.1.0-6','0.1.0-7')and after.get(NAME)in(None,'0.1.0-6','0.1.0-7'),'only Welcome4/5 selection')", " C.need(before.get(NAME)in(None,'0.1.0-1')and after.get(NAME)in(None,'0.1.0-1'),'only accepted Boot0.1.0-1 selection')"),
 ("path.parent==Path('/runner/inputs/archives')", "path.parent==Path('/tools606/boot607')"),
 ("status='COMMITTED_SELECTED_APPS_REQUIRES_FULL_READBACK'", "status='COMMITTED_SELECTED_BOOT_REQUIRES_FULL_NATIVE_READBACK'"),
)

def one(raw,before,after):
    if raw.count(before) != 1:
        raise ValueError('one exact native Boot transaction seam')
    return raw.replace(before,after)

def derive(raw):
    if hashlib.sha256(raw.encode()).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('whole original signed ALPM source drift')
    result = raw
    for before,after in EDITS:
        result = one(result,before,after)
    restored = result
    for before,after in reversed(EDITS):
        restored = one(restored,after,before)
    if restored != raw:
        raise ValueError('full original transaction inverse differs')
    compile(result,'<boot607-native-signed-step>','exec')
    return result
