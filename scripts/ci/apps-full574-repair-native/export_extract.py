# SPDX-License-Identifier: MIT
"""Apps-only pinned export extractor; retain security.capability, refuse other attrs."""
import hashlib,types
from pathlib import Path

ORIGINAL='scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py'
ORIGINAL_SHA256='9738acb125ce6d468d5359ecfbd5540454826567fd4ac4481576ec31da37190c'
ANCHOR="set(member.pax_headers)<={'path','linkpath','mtime','atime','ctime'}"
XATTR='SCHILY.xattr.security.capability'
PLAIN={'path','linkpath','mtime','atime','ctime'}

def isolated(source,capabilities,read):
 path=Path(source)/ORIGINAL;raw=read(path)
 if hashlib.sha256(raw).hexdigest()!=ORIGINAL_SHA256 or raw.count(ANCHOR.encode())!=1:raise ValueError('exact original extractor source/anchor required')
 adapted=raw.replace(ANCHOR.encode(),b'apps_pax_allowed(member)');module=types.ModuleType('_apps574_capability_export');module.__file__=str(path)
 def allowed(member):
  if not set(member.pax_headers)<=PLAIN|{XATTR}:return False
  if XATTR in member.pax_headers:
   if not member.isfile():return False
   capabilities.pax_value(member.pax_headers[XATTR])
  return True
 module.apps_pax_allowed=allowed
 exec(compile(adapted,str(path),'exec'),module.__dict__)
 original_records=module.records;original_extract=module.extract
 def records(archive):
  result,total,excluded=original_records(archive);mapping={}
  for name,member in result.items():
   if XATTR in member.pax_headers:mapping[name]=capabilities.pax_value(member.pax_headers[XATTR]).hex()
  for name,member in result.items():
   if member.islnk() and module.name(member.linkname) in mapping:mapping[name]=mapping[module.name(member.linkname)]
  module.apps_capabilities=dict(sorted(mapping.items()))
  return result,total,excluded
 module.apps_adapted_source_sha256=hashlib.sha256(adapted).hexdigest()
 module.apps_original_records=original_records
 module.records=records
 def extract(archive,target,expected_sha=None):
  value=original_extract(archive,target,expected_sha)
  value.update(metadata='uid/gid/mode/mtime/symlink/internal-hardlink preserved; only validated security.capability PAX accepted; other unknown PAX/xattrs refused',
   original_extractor_sha256=ORIGINAL_SHA256,adapted_extractor_sha256=hashlib.sha256(adapted).hexdigest(),
   security_capabilities=module.apps_capabilities,capability_restoration='PENDING_RESTORE_AND_COMPLETE_NODE_VERIFICATION')
  return value
 module.extract=extract
 return module
