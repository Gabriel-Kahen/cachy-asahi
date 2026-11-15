#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent passive v4 DATA checks; Root authentication and acceptance external."""
import argparse,importlib.util,json,stat,sys,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v4_passive_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);d=B.d
SOURCE='c23a24a0cff3ce102e2f3240cc86a890b2ad4b0b';REF='refs/heads/codex/native-arm-perl5423-xs-v4-20261115';MAP='ed4b624d6a32359b481b6361930b0e99c3085ccf71fe493f6fa586bbfa54edec';TREE='7c7308369ab757cadc6b250ad4692314ab850475';OUTER='perl5423-native-xs-v4';INNER='perl5423-native-xs-v1'
PARENT=B.parent.SOURCE;PARENT_MAP=B.parent.MAP;PARENT_TREE=B.parent.TREE
PROFILE=dict(bytes=1564,sha256='d048993fbff26dc316771104216416c77f48e899b3829cd826cbfaf6e09a022c');ACTUAL=B.parent.ACTUAL
ARCHIVE_MAP={'xs/entry.py':'previous-v3/entry.py','xs/prepare_inputs.py':'previous-v3/prepare_inputs.py','.github/workflows/native-arm-build.yml':'previous-v3/workflow.yml','xs-provenance.json':'previous-v3/provenance.json','source-map.json':'previous-v3/source-map.json','xs/compiler_image.py':'previous-v3/compiler_image.py'}
def binding(value):
 d.need(type(value)is dict and set(value)=={'schema','binding','artifact'},'exact Root Reader envelope')
 b=value['binding'];d.need(type(b)is dict and b.get('source')==SOURCE and d.sha(b.get('source'),40)and b.get('ref')==REF and b.get('source_map_sha256')==MAP and b.get('operation')==OUTER,'actual new v4 Root Source/ref/map/operation required; NULL refuses')
 B.previous.binding(dict(value,binding=dict(b,source_map_sha256=B.previous.MAP,operation='perl5423-native-xs-v2')));return b,value['artifact']

def inverse305(leaves):
 old=dict(leaves)
 for name,saved in ARCHIVE_MAP.items():d.need(saved in old,'all six exact v3 inverse bodies');old[name]=old.pop(saved)
 del old['.github/workflows/native-arm-perl5423-xs-v4.yml'];old['.github/workflows/native-arm-perl5423-xs-v3.yml']=old['.github/workflows/native-arm-build.yml']
 d.need(len(old)==305 and B.previous.git_tree(old)==PARENT_TREE and d.pin(old['source-map.json'][0])==dict(bytes=59704,sha256=PARENT_MAP),'exact whole311→305 inverse')
 return old

def inverse298(leaves):
 old=dict(leaves)
 for name,saved in {'xs/entry.py':'previous-v2/entry.py','xs/prepare_inputs.py':'previous-v2/prepare_inputs.py','.github/workflows/native-arm-build.yml':'previous-v2/workflow.yml','xs-provenance.json':'previous-v2/provenance.json','source-map.json':'previous-v2/source-map.json'}.items():old[name]=old.pop(saved)
 for n in ['xs/compiler_image.py','accepted/compiler-inputs.json','.github/workflows/native-arm-perl5423-xs-v3.yml']:del old[n]
 old['.github/workflows/native-arm-perl5423-xs-v2.yml']=old['.github/workflows/native-arm-build.yml'];return old

def source(root,b):
 d.need(b['ref']==REF and b['source_map_sha256']==MAP and b['operation']==OUTER and b['source']==SOURCE,'new externally authenticated v4 tuple')
 raw=d.read(root,'source-map.json',d.MIB);d.need(d.pin(raw)==dict(bytes=60699,sha256=MAP),'whole311 Source map');m=d.decode(raw);d.need(m['actual']==ACTUAL and len(m['files'])==310,'311 NULL-declared Source')
 names=d.inventory(root,311,96*d.MIB);d.need(names==set(m['files'])|{'source-map.json'},'complete311 physical namespace')
 leaves={}
 for name in sorted(names):
  body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode);d.need(mode in(0o644,0o755),'ordinary Source mode')
  if name!='source-map.json':d.need(dict(**d.pin(body),mode=mode)==m['files'][name],'whole311 Source body/mode: '+name)
  leaves[name]=(body,mode)
 d.need(sum(len(v[0])for v in leaves.values())==87648917 and B.previous.git_tree(leaves)==TREE,'whole311 body/mode/tree')
 old=inverse305(leaves);predicate,_=B.source_projection(3);predicate(old,dict(b,source=PARENT,ref=B.parent.REF,source_map_sha256=PARENT_MAP,operation='perl5423-native-xs-v3'))
 prior=inverse298(old);predicate,_=B.source_projection(2);predicate(prior,dict(b,source=B.parent.PARENT,ref='refs/heads/codex/native-arm-perl5423-xs-v2-20261115',source_map_sha256=B.previous.MAP,operation='perl5423-native-xs-v2'))
 for n,v in old.items():
  if n.startswith(('held/','consumer/','accepted/'))or n=='LICENSE':d.need(leaves[n]==v,'unchanged held272/consumer/accepted/helper/notices')
 d.need(leaves['.github/workflows/native-arm-build.yml']==leaves['.github/workflows/native-arm-perl5423-xs-v4.yml'],'exact v4 aliases')
 v=d.decode(leaves['xs-provenance.json'][0]);d.need(v['operation']==OUTER and v['delegated_consumer_operation']==INNER and v['parent_source']==PARENT and v['parent_map_sha256']==PARENT_MAP and v['parent_tree']==PARENT_TREE and v['constructor_profile_sha256']==PROFILE['sha256']and v['actual']==ACTUAL and v['closed_failed_run']=='43718658756'and v['closed_failed_job']=='132825604072'and v['closed_failed_artifact']=='14163084922'and v['runtime_manifest']==B.parent.MODE_PIN and v['compiler_manifest']==B.parent.COMPILER_PIN and v['derived_default_argv']==dict(Entrypoint=['/usr/bin/false'],Cmd=['/usr/bin/false'])and v['captured_config_fields']==['AttachStderr','AttachStdout','Hostname','Image']and v['image_seal_resources']==dict(cpus=2,memory_bytes=536870912,swap_bytes=0,pids=64,seconds=120,max_image_delta_bytes=8388608)and v['accepted_archive']==dict(bytes=22071176,sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22')and v['native_acceptance']is v['XS_acceptance']is False,'new v4 lineage, retained failed-v3 proof and explicit refusal defaults')
 return m

def validate(args):
 d.start();d.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info>=(3,14),'isolated unoptimized Python3.14+ passive zstd Reader')
 p=d.absolute(args.binding);raw=d.read(p.parent,p.name,2*d.MIB);d.need(d.sha(args.binding_sha256)and d.pin(raw)['sha256']==args.binding_sha256,'external Root whole binding pin');b,a=binding(d.decode(raw));root,evidence=d.absolute(args.source_root),d.absolute(args.evidence);m=source(root,b)
 meta=d.absolute(args.artifact_metadata);origin=B.original(args.original_artifact,evidence,a,d.read(meta.parent,meta.name,2*d.MIB),b)
 def get(name,cap=16*d.MIB):d.need(name in d._evidence_names,'missing Original evidence leaf: '+name);return d.read(evidence,name,cap)
 spec=importlib.util.spec_from_file_location('xs_v4_passive_adapters',HERE/'adapters.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A);context=A.bootstrap(get,root,b,m,d);result=A.consumer(get,root,b,context,d);d.tick()
 return dict(schema=1,status='PASS_SCOPED_XS_V4_ORIGINAL_DATA_CHECKS',binding=b,original=origin,source_files=311,prior_source_files=[305,298],held_files=272,outer_operation=OUTER,frozen_inner_operation=INNER,compiler_image=context['compiler_image'],consumer=result,Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',install_lifecycle='NOT_QUALIFIED',native16K='NOT_QUALIFIED',M2='NOT_QUALIFIED',performance='NOT_MEASURED',release='NOT_QUALIFIED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ['binding','binding-sha256','source-root','original-artifact','artifact-metadata','evidence']:p.add_argument('--'+n,required=True)
 a=p.parse_args()
 try:print(json.dumps(validate(a),sort_keys=True,indent=2,allow_nan=False))
 except(ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile,RuntimeError)as error:print(json.dumps(dict(status='REFUSED_XS_V4_DATA',reason=type(error).__name__+': '+str(error),Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False)));sys.exit(2)
