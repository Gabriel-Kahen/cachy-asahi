#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Finite v4 Source DATA constructor/inverse; no image, compiler, XS or network."""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[4]
HELPER=Path(os.environ.get('CACHY_XS_V4_ATOMIC_HELPER',REPO/'scripts/ci/native-build-namespace-preflight/prepare.py'))
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7':raise ValueError('held atomic DATA helper differs')
spec=importlib.util.spec_from_file_location('xs_v4_atomic',HELPER);atomic=importlib.util.module_from_spec(spec);spec.loader.exec_module(atomic)
atomic.MAX_FILES=384;atomic.MAX_TOTAL=96*1024**2
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))
PARENT='5261eb22032b986cd77796a808f99779c100cfe8';PARENT_MAP='22ecc198c9ca8187c08093860a3c4513c8a2d0c7b44a7542e9aa8504fadaa185';PARENT_TREE='4efb18d7e2ce796bb4feb48a700908da20bd95ac'
OPERATION='perl5423-native-xs-v4';OLD_ALIAS='.github/workflows/native-arm-perl5423-xs-v3.yml';NEW_ALIAS='.github/workflows/native-arm-perl5423-xs-v4.yml'
ARCHIVE_MAP={'xs/entry.py':'previous-v3/entry.py','xs/prepare_inputs.py':'previous-v3/prepare_inputs.py','.github/workflows/native-arm-build.yml':'previous-v3/workflow.yml','xs-provenance.json':'previous-v3/provenance.json','source-map.json':'previous-v3/source-map.json','xs/compiler_image.py':'previous-v3/compiler_image.py'}
NEW_FILES=set()
MODE_PIN=dict(bytes=349767,sha256='7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2');PACKAGE_PIN=dict(bytes=22071176,sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22')
def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def previous(path):
 files=atomic.snapshot(path);atomic.need(len(files)==305 and sum(len(b)for b,_ in files.values())==87508922 and atomic.tree(files)==PARENT_TREE and atomic.pin(files['source-map.json'][0])['sha256']==PARENT_MAP,'exact closed full305 v3 Source bodies/modes/tree required')
 m=atomic.decode(files['source-map.json'][0]);atomic.need(m['actual']==ACTUAL and m['files']==atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'})and files[OLD_ALIAS]==files['.github/workflows/native-arm-build.yml'],'complete v3 namespace and aliases')
 return files

def workflow(raw,old_sha,new_sha):
 text=raw.decode()
 for old,new in [('native-arm-perl5423-xs-v3','native-arm-perl5423-xs-v4'),('perl5423-native-xs-v3',OPERATION),(old_sha,new_sha)]:atomic.need(old in text,'exact v3 workflow seam');text=text.replace(old,new)
 needle='            ${{ runner.temp }}/perl-hosted/preparation*.json\n';atomic.need(text.count(needle)==1,'one exact diagnostic export seam');atomic.need(text.count('            ${{ runner.temp }}/perl-hosted/compiler-image*.json\n')==1,'existing compiler evidence export retained')
 atomic.need('group: native-arm-build\n  cancel-in-progress: false\n  queue: max'in text,'unchanged serialized native lane required');return text.encode()

def inverse(files):
 before=dict(files)
 for name,saved in ARCHIVE_MAP.items():atomic.need(saved in before,'complete explicit v3 inverse');before[name]=before.pop(saved)
 for name in NEW_FILES:atomic.need(name in before,'complete fixed v3 additions');del before[name]
 del before[NEW_ALIAS];before[OLD_ALIAS]=before['.github/workflows/native-arm-build.yml']
 atomic.need(len(before)==305 and atomic.tree(before)==PARENT_TREE and atomic.pin(before['source-map.json'][0])['sha256']==PARENT_MAP,'inverse must restore exact305 v3 bytes/modes/tree');return before

def render(parent,profile_sha):
 raw,_=atomic.read(HERE/'profile.json');atomic.need(atomic.pin(raw)['sha256']==profile_sha,'whole external v4 profile pin');profile=atomic.decode(raw)
 atomic.need(profile['schema']==1 and profile['actual']==ACTUAL and profile['operation']==OPERATION and profile['delegated_consumer_operation']=='perl5423-native-xs-v1'and profile['parent_source']==PARENT and profile['runtime_manifest']==MODE_PIN and profile['accepted_archive']==PACKAGE_PIN and profile['derived_default_argv']==dict(Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false'])and profile['captured_config_fields']==['AttachStderr','AttachStdout','Hostname','Image'],'new separate v4 Source, no closed-run replay')
 before=previous(parent);files=dict(before)
 for name,saved in ARCHIVE_MAP.items():files[saved]=before[name]
 for name,row in profile['payload'].items():
  atomic.need(name in ['xs/entry.py','xs/prepare_inputs.py','xs/compiler_image.py'],'finite v4 replacement set');body,mode=atomic.read(HERE/'payload'/name);atomic.need(dict(**atomic.pin(body),mode=mode)==row,'exact reviewed v4 payload: '+name);files[name]=(body,mode)
 atomic.need(set(profile['payload'])=={'xs/entry.py','xs/prepare_inputs.py','xs/compiler_image.py'},'all three exact payloads required')
 body,mode=atomic.read(HERE/'compiler-inputs.json');atomic.need(atomic.pin(body)==profile['compiler_manifest']and mode==0o644,'exact compiler archive/alias/helper DATA pins');atomic.need(before['accepted/compiler-inputs.json']==(body,mode),'original compiler descriptor unchanged')
 text=workflow(before[OLD_ALIAS][0],atomic.pin(before['xs/entry.py'][0])['sha256'],atomic.pin(files['xs/entry.py'][0])['sha256']);del files[OLD_ALIAS];files[NEW_ALIAS]=files['.github/workflows/native-arm-build.yml']=(text,0o644)
 files['xs-provenance.json']=(encode(dict(schema=1,actual=ACTUAL,operation=OPERATION,delegated_consumer_operation='perl5423-native-xs-v1',parent_source=PARENT,parent_map_sha256=PARENT_MAP,parent_tree=PARENT_TREE,closed_failed_run='43718658756',closed_failed_job='132825604072',closed_failed_artifact='14163084922',closed_failure='POST_COMMIT_DERIVED_CONFIG_DEFAULTS_AND_CONTAINER_METADATA_GUARD',original_runtime_inode_link_count='OBSERVED_V3: exact GCC group nlink3; copied driver nlink1',runtime_manifest=profile['runtime_manifest'],compiler_manifest=profile['compiler_manifest'],accepted_archive=profile['accepted_archive'],constructor_profile_sha256=profile_sha,correction='EXPLICIT_NONEMPTY_FALSE_DEFAULTS_AND_EXACT_SEALING_CONFIG_METADATA_NO_IGNORED_FIELDS',derived_default_argv=dict(Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false']),captured_config_fields=['AttachStderr','AttachStdout','Hostname','Image'],image_seal_resources=dict(cpus=2,memory_bytes=512*1024**2,swap_bytes=0,pids=64,seconds=120,max_image_delta_bytes=8*1024**2),native_acceptance=False,XS_acceptance=False)),0o644)
 preserved={n:r for n,r in before.items()if n.startswith(('held/','consumer/','accepted/'))or n=='LICENSE'};atomic.need(all(files[n]==r for n,r in preserved.items()),'all original held272/consumer/runtime/accepted bytes and modes preserved')
 files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,scope='PROPOSED_SEPARATE_NATIVE_XS_V4_FAIL_CLOSED_DERIVED_DEFAULTS',files=atomic.descriptors({n:r for n,r in files.items()if n!='source-map.json'}))),0o644)
 atomic.need(len(files)==311 and sum(len(b)for b,_ in files.values())<=96*1024**2,'finite311 v4 Source');atomic.need(inverse(files)==before,'whole305 exact inverse relation');return files

def construct(parent,profile_sha,output):
 parent,output=map(atomic.absolute,(parent,output));atomic.need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in [REPO,parent]),'fresh disjoint Source DATA output')
 files=render(parent,profile_sha);atomic.publish(files,output);return dict(status='CONSTRUCTED_XS_V4_SOURCE_DATA_ONLY',actual=ACTUAL,files=len(files),bytes=sum(len(b)for b,_ in files.values()),map=atomic.pin(files['source-map.json'][0]),prospective_tree=atomic.tree(files),parent_source=PARENT,native_acceptance=False,XS_acceptance=False)
if __name__=='__main__':
 atomic.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Source DATA constructor');p=argparse.ArgumentParser(description=__doc__)
 for name in ['previous-xs-source','profile-sha256','output']:p.add_argument('--'+name,required=True)
 a=p.parse_args();print(json.dumps(construct(Path(a.previous_xs_source),a.profile_sha256,Path(a.output)),sort_keys=True))
