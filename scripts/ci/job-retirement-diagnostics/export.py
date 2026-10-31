#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Export only a verified diagnostic sidecar; never original cleanup authority."""
import argparse,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import retain as D
NAMES=['scripts/ci/job-retirement-diagnostics/export.py','scripts/ci/job-retirement-diagnostics/retain.py','scripts/ci/orphans-full574-native/supervise.py','scripts/ci/apps-full574-repair-native/supervise.py']
def export(source,proof,diagnostic,output):
 value=D.verify(D.decode(D.read(diagnostic,32768,private=True)));identity=value['identity'];raw=D.read(proof,65536);original=D.decode(raw)
 D.need(identity['source_sha']==original['source_sha']==os.environ.get('SOURCE_SHA')==os.environ.get('GITHUB_SHA')==os.environ.get('GITHUB_WORKFLOW_SHA') and identity['proof_sha256']==D.pin(raw)['sha256'] and identity['consumer_token']==original['consumer_token'] and identity['producer_token']==original['job_token'] and identity['trial']=='full574-signed-repair' and identity.get('case')==original.get('case')==os.environ.get('REPAIR_CASE'),'original proof and workflow diagnostic joins')
 D.need(value['sources']==D.sources(source,source/'scripts/ci/apps-full574-repair-native/source-manifest.json',NAMES),'exact source joins before separate export')
 # A separate fresh directory leaves the original closed lifecycle retainer intact.
 directory,name=D.parent(output)
 try:D.need(os.fstat(directory).st_uid==os.getuid(),'owned fresh export parent');os.mkdir(name,mode=0o700,dir_fd=directory)
 finally:os.close(directory)
 D.save_diagnostic(output/'outer-handoff-diagnostic.json',value);return value
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','proof','diagnostic','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();export(a.source,a.proof,a.diagnostic,a.output)
