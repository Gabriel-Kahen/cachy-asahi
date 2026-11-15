#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Finite v3 Source DATA constructor/inverse; no image, compiler, XS or network."""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[4]
HELPER=Path(os.environ.get('CACHY_XS_V3_ATOMIC_HELPER',REPO/'scripts/ci/native-build-namespace-preflight/prepare.py'))
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':raise ValueError('held atomic DATA helper differs')
spec=importlib.util.spec_from_file_location('xs_v3_atomic',HELPER);atomic=importlib.util.module_from_spec(spec);spec.loader.exec_module(atomic)
atomic.MAX_FILES=384;atomic.MAX_TOTAL=96*1024**2
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))
PARENT='102281ee1f584fcc7e1e612f7b8def3248cac3de';PARENT_MAP='9255e7853758069a4ed23eb89872a162fdb116b6a86fc7e3c03914a8df9c0c03';PARENT_TREE='38e123007884b0c237c16479574145f433939e6a'
OPERATION='perl5423-native-xs-v3';OLD_ALIAS='.github/workflows/native-arm-perl5423-xs-v2.yml';NEW_ALIAS='.github/workflows/native-arm-perl5423-xs-v3.yml'
ARCHIVE_MAP={'xs/entry.py':'previous-v2/entry.py','xs/prepare_inputs.py':'previous-v2/prepare_inputs.py','.github/workflows/native-arm-build.yml':'previous-v2/workflow.yml','xs-provenance.json':'previous-v2/provenance.json','source-map.json':'previous-v2/source-map.json'}
NEW_FILES={'xs/compiler_image.py','accepted/compiler-inputs.json'}
MODE_PIN=dict(bytes=349767,sha256='7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2');PACKAGE_PIN=dict(bytes=22071176,sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22')
def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def previous(path):
 files=atomic.snapshot(path);atomic.need(len(files)==298 and sum(len(b)for b,_ in files.values())==87360147 and atomic.tree(files)==PARENT_TREE and atomic.pin(files['source-map.json'][0])['sha256']==PARENT_MAP,'exact closed full298 v2 Source bodies/modes/tree required')
 m=atomic.decode(files['source-map.json'][0]);atomic.need(m['actual']==ACTUAL and m['files']==atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'})and files[OLD_ALIAS]==files['.github/workflows/native-arm-build.yml'],'complete v2 namespace and aliases')
 return files

def workflow(raw,old_sha,new_sha):
 text=raw.decode()
 for old,new in [('native-arm-perl5423-xs-v2','native-arm-perl5423-xs-v3'),('perl5423-native-xs-v2',OPERATION),(old_sha,new_sha)]:atomic.need(old in text,'exact v2 workflow seam');text=text.replace(old,new)
 needle='            ${{ runner.temp }}/perl-hosted/preparation*.json\n';atomic.need(text.count(needle)==1,'one exact diagnostic export seam');text=text.replace(needle,needle+'            ${{ runner.temp }}/perl-hosted/compiler-image*.json\n',1)
 atomic.need('group: native-arm-build\n  cancel-in-progress: false\n  queue: max'in text,'unchanged serialized native lane required');return text.encode()

def inverse(files):
 before=dict(files)
 for name,saved in ARCHIVE_MAP.items():atomic.need(saved in before,'complete explicit v2 inverse');before[name]=before.pop(saved)
 for name in NEW_FILES:atomic.need(name in before,'complete fixed v3 additions');del before[name]
 del before[NEW_ALIAS];before[OLD_ALIAS]=before['.github/workflows/native-arm-build.yml']
 atomic.need(len(before)==298 and atomic.tree(before)==PARENT_TREE and atomic.pin(before['source-map.json'][0])['sha256']==PARENT_MAP,'inverse must restore exact298 v2 bytes/modes/tree');return before

def render(parent,profile_sha):
 raw,_=atomic.read(HERE/'profile.json');atomic.need(atomic.pin(raw)['sha256']==profile_sha,'whole external v3 profile pin');profile=atomic.decode(raw)
 atomic.need(profile['schema']==1 and profile['actual']==ACTUAL and profile['operation']==OPERATION and profile['delegated_consumer_operation']=='perl5423-native-xs-v1'and profile['parent_source']==PARENT and profile['runtime_manifest']==MODE_PIN and profile['accepted_archive']==PACKAGE_PIN,'new separate v3 Source, no closed-run replay')
 before=previous(parent);files=dict(before)
 for name,saved in ARCHIVE_MAP.items():files[saved]=before[name]
 for name,row in profile['payload'].items():
  atomic.need(name in ['xs/entry.py','xs/prepare_inputs.py','xs/compiler_image.py'],'finite v3 replacement set');body,mode=atomic.read(HERE/'payload'/name);atomic.need(dict(**atomic.pin(body),mode=mode)==row,'exact reviewed v3 payload: '+name);files[name]=(body,mode)
 atomic.need(set(profile['payload'])=={'xs/entry.py','xs/prepare_inputs.py','xs/compiler_image.py'},'all three exact payloads required')
 body,mode=atomic.read(HERE/'compiler-inputs.json');atomic.need(atomic.pin(body)==profile['compiler_manifest']and mode==0o644,'exact compiler archive/alias/helper DATA pins');files['accepted/compiler-inputs.json']=(body,mode)
 text=workflow(before[OLD_ALIAS][0],atomic.pin(before['xs/entry.py'][0])['sha256'],atomic.pin(files['xs/entry.py'][0])['sha256']);del files[OLD_ALIAS];files[NEW_ALIAS]=files['.github/workflows/native-arm-build.yml']=(text,0o644)
 files['xs-provenance.json']=(encode(dict(schema=1,actual=ACTUAL,operation=OPERATION,delegated_consumer_operation='perl5423-native-xs-v1',parent_source=PARENT,parent_map_sha256=PARENT_MAP,parent_tree=PARENT_TREE,closed_failed_run='43711176509',closed_failed_job='132802844378',closed_failed_artifact='14160304074',closed_failure='FROZEN_SINGLE_LINK_GCC_INPUT_GUARD_BEFORE_XS',original_runtime_inode_link_count='NOT_RETAINED; exact package hardlink group observed as DATA',runtime_manifest=profile['runtime_manifest'],compiler_manifest=profile['compiler_manifest'],accepted_archive=profile['accepted_archive'],constructor_profile_sha256=profile_sha,correction='ONE_EXACT_SINGLE_LINK_DRIVER_IN_DISTINCT_QUALIFIED_OWNED_IMAGE_NO_CONSUMER_WAIVER',image_seal_resources=dict(cpus=2,memory_bytes=512*1024**2,swap_bytes=0,pids=64,seconds=120,max_image_delta_bytes=8*1024**2),native_acceptance=False,XS_acceptance=False)),0o644)
 preserved={n:r for n,r in before.items()if n.startswith(('held/','consumer/','accepted/'))or n=='LICENSE'};atomic.need(all(files[n]==r for n,r in preserved.items()),'all original held272/consumer/runtime/accepted bytes and modes preserved')
 files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,scope='PROPOSED_SEPARATE_NATIVE_XS_V3_PRIVATE_SINGLE_LINK_COMPILER_IMAGE',files=atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'}))),0o644)
 atomic.need(len(files)==305 and sum(len(b)for b,_ in files.values())<=96*1024**2,'finite305 v3 Source');atomic.need(inverse(files)==before,'whole298 exact inverse relation');return files

def construct(parent,profile_sha,output):
 parent,output=map(atomic.absolute,(parent,output));atomic.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in [REPO,parent]),'fresh disjoint Source DATA output')
 files=render(parent,profile_sha);atomic.publish(files,output);return dict(status='CONSTRUCTED_XS_V3_SOURCE_DATA_ONLY',actual=ACTUAL,files=len(files),bytes=sum(len(b)for b,_ in files.values()),map=atomic.pin(files['source-map.json'][0]),prospective_tree=atomic.tree(files),parent_source=PARENT,native_acceptance=False,XS_acceptance=False)
if __name__=='__main__':
 atomic.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Source DATA constructor');p=argparse.ArgumentParser(description=__doc__)
 for name in ['previous-xs-source','profile-sha256','output']:p.add_argument('--'+name,required=True)
 a=p.parse_args();print(json.dumps(construct(Path(a.previous_xs_source),a.profile_sha256,Path(a.output)),sort_keys=True))
