#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Independent passive v3 Original joins. Root authentication/acceptance external."""
import argparse,hashlib,importlib.util,json,stat,sys,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v3_passive_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);d=B.d
SOURCE='5261eb22032b986cd77796a808f99779c100cfe8';REF='refs/heads/codex/native-arm-perl5423-xs-v3-20261115';MAP='22ecc198c9ca8187c08093860a3c4513c8a2d0c7b44a7542e9aa8504fadaa185';TREE='4efb18d7e2ce796bb4feb48a700908da20bd95ac'
PARENT='102281ee1f584fcc7e1e612f7b8def3248cac3de';PARENT_MAP='9255e7853758069a4ed23eb89872a162fdb116b6a86fc7e3c03914a8df9c0c03';PARENT_TREE='38e123007884b0c237c16479574145f433939e6a';OUTER='perl5423-native-xs-v3';INNER='perl5423-native-xs-v1'
MODE_PIN=dict(bytes=349767,sha256='7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2');COMPILER_PIN=dict(bytes=11025,sha256='fa613490865d94362d4d9efe6c5860904158c09733439a9f6c5709168f88d23c');PROFILE=dict(bytes=1336,sha256='8b36e55a438b851b29717481e814d51b4c67094546fd01382f1acd60d4efcc1d')
ACTUAL=dict.fromkeys(['source','ref','run','job','reader','authority','approval','artifact','image'])
def binding(value):
 # Project only the admitted outer-operation literal into the immutable v2
 # envelope predicate, then additionally require the exact Root-published Source.
 d.need(type(value)is dict and set(value)=={'schema','binding','artifact'},'exact Root Reader envelope')
 b=value['binding'];d.need(type(b)is dict and b.get('source')==SOURCE and b.get('ref')==REF and b.get('source_map_sha256')==MAP and b.get('operation')==OUTER,'actual v3 Root Source/ref/map/operation required; NULL refuses')
 projected=dict(value,binding=dict(b,source_map_sha256=B.previous.MAP,operation='perl5423-native-xs-v2'));B.previous.binding(projected);return b,value['artifact']

def source(root,b):
 d.need(b['source']==SOURCE and b['ref']==REF and b['source_map_sha256']==MAP,'exact published v3 Source')
 raw=d.read(root,'source-map.json',d.MIB);d.need(d.pin(raw)==dict(bytes=59704,sha256=MAP),'whole305 Source map');m=d.decode(raw);d.need(m['actual']==ACTUAL and len(m['files'])==304,'305 NULL-declared Source')
 names=d.inventory(root,305,96*d.MIB,ignore_git=True);d.need(names==set(m['files'])|{'source-map.json'},'complete305 namespace')
 leaves={}
 for name in sorted(names):
  body=d.read(root,name,64*d.MIB);mode=stat.S_IMODE((Path(root)/name).stat().st_mode);d.need(mode in(0o644,0o755),'ordinary Source mode')
  if name!='source-map.json':d.need(dict(**d.pin(body),mode=mode)==m['files'][name],'whole Source body/mode: '+name)
  leaves[name]=(body,mode)
 d.need(sum(len(v[0])for v in leaves.values())==87508922 and B.previous.git_tree(leaves)==TREE,'whole305 body/mode/tree')
 held={n[5:]:r for n,r in leaves.items()if n.startswith('held/')};d.need(len(held)==272 and B.previous.git_tree(held)==B.previous.HELD_TREE and d.pin(held['source-map.json'][0])['sha256']==B.previous.HELD_MAP,'complete held272 identity')
 old=dict(leaves);inverse={'xs/entry.py':'previous-v2/entry.py','xs/prepare_inputs.py':'previous-v2/prepare_inputs.py','.github/workflows/native-arm-build.yml':'previous-v2/workflow.yml','xs-provenance.json':'previous-v2/provenance.json','source-map.json':'previous-v2/source-map.json'}
 for name,saved in inverse.items():old[name]=old.pop(saved)
 for n in ['xs/compiler_image.py','accepted/compiler-inputs.json','.github/workflows/native-arm-perl5423-xs-v3.yml']:del old[n]
 old['.github/workflows/native-arm-perl5423-xs-v2.yml']=old['.github/workflows/native-arm-build.yml'];prior=d.decode(old['source-map.json'][0]);d.need(len(old)==298 and sum(len(v[0])for v in old.values())==87360147 and B.previous.git_tree(old)==PARENT_TREE and d.pin(old['source-map.json'][0])==dict(bytes=58527,sha256=PARENT_MAP),'complete prior298 inverse')
 d.need(prior['actual']==ACTUAL and prior['files']=={n:dict(**d.pin(v[0]),mode=v[1])for n,v in old.items()if n!='source-map.json'},'prior298 complete declared namespace')
 for n,v in old.items():
  if n.startswith(('held/','consumer/','accepted/')):d.need(leaves[n]==v,'unchanged original runtime/consumer/accepted body/mode')
 d.need(leaves['.github/workflows/native-arm-build.yml']==leaves['.github/workflows/native-arm-perl5423-xs-v3.yml'],'v3 aliases identical')
 v=d.decode(leaves['xs-provenance.json'][0]);d.need(v['operation']==OUTER and v['delegated_consumer_operation']==INNER and v['parent_source']==PARENT and v['parent_map_sha256']==PARENT_MAP and v['parent_tree']==PARENT_TREE and v['runtime_manifest']==MODE_PIN and v['compiler_manifest']==COMPILER_PIN and v['constructor_profile_sha256']==PROFILE['sha256']and v['closed_failed_run']=='43711176509'and v['closed_failed_job']=='132802844378'and v['actual']==ACTUAL and v['native_acceptance']is v['XS_acceptance']is False,'new outer v3 lineage/closed v2 failure/inner v1')
 oldv=d.decode(old['xs-provenance.json'][0]);d.need(oldv['closed_failed_run']=='43705018149'and oldv['parent_source']=='0885f89ab7a4301bbdf9c4b180620fb447d9a41a','closed v1 failure preserved')
 d.need(d.pin(leaves['accepted/runtime-files.json'][0])==MODE_PIN and d.pin(leaves['accepted/compiler-inputs.json'][0])==COMPILER_PIN,'exact runtime and compiler descriptor pins');return m

def validate(args):
 d.start();d.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info>=(3,14),'isolated unoptimized Python3.14+ passive zstd Reader')
 p=d.absolute(args.binding);raw=d.read(p.parent,p.name,2*d.MIB);d.need(d.sha(args.binding_sha256)and d.pin(raw)['sha256']==args.binding_sha256,'external Root whole admission pin');b,a=binding(d.decode(raw));root,evidence=d.absolute(args.source_root),d.absolute(args.evidence);m=source(root,b)
 meta=d.absolute(args.artifact_metadata);origin=B.original(args.original_artifact,evidence,a,d.read(meta.parent,meta.name,2*d.MIB),b)
 def get(name,cap=16*d.MIB):d.need(name in d._evidence_names,'missing Original evidence leaf: '+name);return d.read(evidence,name,cap)
 spec=importlib.util.spec_from_file_location('xs_v3_passive_adapters',HERE/'adapters.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A);context=A.bootstrap(get,root,b,m,d);result=A.consumer(get,root,b,context,d);d.tick()
 return dict(schema=1,status='PASS_SCOPED_XS_V3_ORIGINAL_DATA_CHECKS',binding=b,original=origin,source_files=305,prior_source_files=298,held_files=272,outer_operation=OUTER,frozen_inner_operation=INNER,compiler_image=context['compiler_image'],consumer=result,Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',install_lifecycle='NOT_QUALIFIED',native16K='NOT_QUALIFIED',M2='NOT_QUALIFIED',performance='NOT_MEASURED',release='NOT_QUALIFIED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ['binding','binding-sha256','source-root','original-artifact','artifact-metadata','evidence']:p.add_argument('--'+n,required=True)
 a=p.parse_args()
 try:print(json.dumps(validate(a),sort_keys=True,indent=2,allow_nan=False))
 except(ValueError,KeyError,TypeError,OSError,zipfile.BadZipFile,RuntimeError)as error:print(json.dumps(dict(status='REFUSED_XS_V3_DATA',reason=type(error).__name__+': '+str(error),Root_authentication=False,Root_acceptance=None,native_acceptance=False,XS_acceptance=False)));sys.exit(2)
