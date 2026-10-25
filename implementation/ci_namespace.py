# SPDX-License-Identifier: MIT
"""Whole1176 byte inverse; only presecret source-controller authority is changed."""
import json
import common as C
PARENT=dict(bytes=218144,sha256='c59ddeebb11e975ebdf815de831bd28f765c11ff1cee32abcd58c79a526df173')
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
ROOT_LINE=" C.need(os.getuid()==os.geteuid()==0,'presecret source-control controller requires root authority; no internal user namespace fallback')\n"
OLD_UNSHARE="['unshare','--user','--map-root-user','--mount','--net','--'"
NEW_UNSHARE="['unshare','--mount','--net','--'"
OLD_CALL='python3 -I -B "$GITHUB_WORKSPACE/fresh607-code/implementation/source_controls.py"'
NEW_CALL='sudo -n -- '+OLD_CALL
GUARD_LINE=" __import__('ci_namespace').verify()\n"
CHANGED={'README.md','implementation/source_controls.py','implementation/workflow.py','implementation/workflow-template.yml','implementation/source_guard.py','source-manifest.json',*ALIASES}
def one(raw,before,after):
 C.need(raw.count(before.encode())==1,'one exact source namespace seam '+before[:55]);return raw.replace(before.encode(),after.encode(),1)
def old_body(name,raw):
 if name=='README.md':return one(raw,'under a presecret root-authority controller in a child mount/network namespace backed by','in a child user/mount/network namespace backed by')
 if name=='implementation/source_controls.py':return one(one(raw,ROOT_LINE,''),NEW_UNSHARE,OLD_UNSHARE)
 if name in('implementation/workflow.py','implementation/workflow-template.yml'):return one(raw,NEW_CALL,OLD_CALL)
 if name=='implementation/source_guard.py':return one(raw,GUARD_LINE,'')
 return raw

def verify():
 before=json.loads(C.checked(C.HERE/'parent1176.json',PARENT));C.need(len(before)==1176 and CHANGED<=set(before),'whole original1176 source map and closed eight inverse seams');old={};changed=set()
 for name,w in before.items():
  if name in(*ALIASES,'source-manifest.json'):continue
  raw=C.read(C.ROOT/name);b=old_body(name,raw);C.need(C.pin(b)==w,'whole original1176 body '+name);old[name]=b
  if b!=raw:changed.add(name)
 manifest=json.loads(C.read(C.ROOT/'source-manifest.json'));manifest['files']={n:w for n,w in before.items()if n not in(*ALIASES,'source-manifest.json')};old_manifest=C.enc(manifest);C.need(C.pin(old_manifest)==before['source-manifest.json'],'complete original1176 manifest inverse');changed.add('source-manifest.json');template=old['implementation/workflow-template.yml'];C.need(template.count(b'@FRESH607_MANIFEST@')==1,'one original manifest workflow seal');expected=template.replace(b'@FRESH607_MANIFEST@',before['source-manifest.json']['sha256'].encode())
 for name in ALIASES:C.need(C.pin(expected)==before[name],'entire original1176 workflow inverse');changed.add(name)
 C.need(changed==CHANGED,'only declared eight source/controller/workflow guard seams; all runtime held');return dict(status='PASS_WHOLE1176_SOURCE_CONTROLLER_AUTHORITY_INVERSE',held=1168,changed=8,added=2,source_controls='NOT_RUN',fresh607='NOT_RUN',runtime='UNCHANGED_NOT_RUN')
