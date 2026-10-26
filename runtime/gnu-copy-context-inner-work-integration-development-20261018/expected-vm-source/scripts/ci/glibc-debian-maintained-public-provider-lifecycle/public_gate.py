# SPDX-License-Identifier: MIT
"""Native compile-input phase ONLY. No private16K or ALPM acceptance is generated."""
import hashlib,json
INDEX=dict(bytes=5662,sha256='a8e3317cabb3fe914a6b3898b2bfbc900905c3823495f15166c419564f7e4956')
SOURCE='78dfd3bbd85a61a84dda2dfc601796ee89edfd5f';RUN=38994309021
ARCHIVE='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def validate(C,root,value,candidate=None):
 G=C.load('public_compile_identity',C.HERE/'candidate_gate.py')
 if 'public_input_index' in value:
  raw=C.read(C.ref(root,value['public_input_index']))
 else:raw=C.read(root/'packet.json')
 C.need(pin(raw)==INDEX,'exact already public compile-input index');index=json.loads(raw)
 if 'public_input_index' not in value:C.need(index==value,'exact public packet data')
 G.identity(index.get('candidate'));files=index['files'];C.need(index['status']=='ROOT_ACCEPTED_PROVIDER_STAGED16K_INPUTS' and len(files)==21 and not {'private16k','private16k_archive_sha256'}&index.keys(),'public compile-input phase only; no invented private16K')
 for name,row in files.items():C.ref(root,dict(path=name,**row),256*1024**2)
 C.need(sum(r['bytes'] for r in files.values())==47420206,'exact public21 payload byte closure')
 def receipt(key):return json.loads(C.read(C.ref(root,index[key])))
 pair=receipt('provider_pair');normal=receipt('probe_receipt');authority=receipt('source_authority')
 for row in (pair,normal):G.identity(row['candidate']);C.need(row['source_sha']==SOURCE and row['run_id']==RUN,'actual accepted compile pair source/run')
 C.need(pair['status']=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and pair['hardware']=='NOT_RUN' and pair['archive_sha256']==ARCHIVE==index['archives']['a']['sha256']==index['archives']['b']['sha256'] and pair['provider_pkgbuild_sha256']==index['provider_pkgbuild_sha256']==G.EXPECTED['pkgbuild_sha256'],'exact compile archive/recipe identity')
 C.need(normal['status']=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and normal['files']==index['probes'] and set(normal['compile_receipts'])=={'a','b'},'actual normal compiler probes; not executed installed runtime')
 C.need(index['source_authority']['bytes']==15506 and index['source_authority']['sha256']==G.EXPECTED['authority_sha256'] and authority['status']=='ROOT_ACCEPTED_DEBIAN_MAINTAINED_SOURCE_AUTHORITY' and authority['release']=='NOT_ADMITTED','exact source-only authority')
 if candidate is None:candidate=C.archive(C.ref(root,index['archives']['a']))
 G.payload(candidate,pair)
 return dict(candidate=G.EXPECTED,native_source=SOURCE,native_run=RUN,payload=pair['payload'],phase='NATIVE_COMPILE_INPUTS_ONLY_NO_INSTALLATION_OR16K_ACCEPTANCE')
