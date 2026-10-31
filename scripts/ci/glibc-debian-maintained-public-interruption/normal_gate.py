# SPDX-License-Identifier: MIT
"""Exact existing caa3 native-normal prerequisite; never interruption authority."""
import hashlib,json,stat
from pathlib import Path
DECISION=dict(ref='b07ecd0070859bd6c2b5740778ea7dabda8fe338',path='payload/native-lifecycle.json',bytes=3270,sha256='f2e83638dba69df86159694319a9498c4f93c1846328cbd4c28d0928e73437b1')
SOURCE='9aef8b7429fb8dd9f9d8412f4e878c5e0324c58d'
ARCHIVE='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9'
def need(ok,why):
 if not ok:raise ValueError(why)
def descriptor(value):
 need(type(value)is dict and value==DECISION,'UNBOUND exact caa3 native-normal Root descriptor required');return value

def read(path):
 path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary native-normal decision path')
 info=path.stat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size==DECISION['bytes'],'bounded single-link native-normal decision')
 raw=path.read_bytes();need(len(raw)==info.st_size,'native-normal decision changed');return raw

def fields(value):
 need(value['status']=='ROOT_ACCEPTED_CAA3_PUBLIC_COMPILE_INPUT_NATIVE_LIFECYCLE'and value['source_sha']==SOURCE and value['run_id']==39054408035 and value['attempt']==1,'same actual caa3 native-normal source/run/status')
 need(value['input_phase']=='NATIVE_COMPILE_INPUTS'and value['ALPM_installation']=='PASS'and value['ordered_cleanup']=='PASS'and value['page_size']==4096 and value['hardware']=='NOT_RUN'and value['release']=='NOT_ADMITTED','actual native-normal ALPM and ordered cleanup only')
 need(value['provider_archive_sha256']==ARCHIVE and value['provider_archive_bytes']==18598440 and value['native_pair']['archive_sha256']==ARCHIVE,'same maintained provider pair only')
 candidate=value['candidate'];need(candidate['version']=='2.43.caa3-1'and candidate['package']=='cachy-asahi-glibc-gnu-provider'and candidate['pkgbuild_sha256']=='9d6d5e688c95febe85321abc69fbfe1b7781a02e318771ae43851d8c29f68bb8'and candidate['authority_sha256']==value['source_authority_sha256']=='88643eabd61a39df63ecaeb50bb20041d17cf4fd3adee55d82d43d3c1ca08707','same maintained source/recipe identity')
 need(value['cases']==['modified','pristine']and value['committed_transactions']==6 and value['zero_commit_refusals']==2 and value['complete574_maps']==16 and value['normal_runtime_observations']==8 and value['source_nodes']==123056,'complete two-case native-normal retained scope')
 need(value['workflow_conclusion']=='failure'and value['workflow_failure']['category']=='POST_RUNTIME_DIAGNOSTIC_HELPER_MISSING','retain original failed-workflow qualification')
 return value

def validate(raw):
 need(type(raw)is bytes and len(raw)==DECISION['bytes']and hashlib.sha256(raw).hexdigest()==DECISION['sha256'],'exact published native-normal decision bytes')
 def pairs(rows):
  result={}
  for key,value in rows:need(key not in result,'duplicate native-normal field');result[key]=value
  return result
 value=json.loads(raw,object_pairs_hook=pairs);return fields(value)
def check_file(path):return validate(read(path))
