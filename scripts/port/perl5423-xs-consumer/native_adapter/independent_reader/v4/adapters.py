# SPDX-License-Identifier: MIT
"""Narrow v4 outer/v1 inner projections with an independent image-seal segment."""
import ast,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v4_adapter_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
spec=importlib.util.spec_from_file_location('xs_v4_compiler_predicates',HERE/'compiler.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
OUTER='perl5423-native-xs-v4';INNER='perl5423-native-xs-v1'
def inner_binding(b,op,io):io.need(b['operation']==OUTER and op['operation']==INNER,'only explicit outer v4/inner v1 projection');return dict(b,operation=INNER)
def extra_budget(raw):
 tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='boot_operations'];count=0
 for n in ast.walk(nodes[0]):
  if isinstance(n,ast.Constant)and type(n.value)is int and n.value==5340:n.value=5520;count+=1
 if len(nodes)!=1 or count!=1:raise ValueError('one exact aggregate budget projection for120s+60s new stage')
 return ast.unparse(ast.fix_missing_locations(tree)).encode()
def consumer_bundle(raw):
 old=b"'preparation.json':io.pin(preparation_raw)})";new=b"'preparation.json':io.pin(preparation_raw),'compiler-image-qualification.json':io.pin(get('compiler-image-qualification.json'))})"
 if raw.count(old)!=1:raise ValueError('one exact new finite bundle qualification leaf')
 return raw.replace(old,new)
def bootstrap(get,root,b,m,io):
 io.need(b['operation']==OUTER,'actual external v4 outer operation')
 outer=B.load('bootstrap.py','outer',extra_budget);inner=B.load('bootstrap.py','inner');outer.OPERATION=OUTER
 h=io.decode(get('hosted-xs.json'));io.need(h['schema']==1 and h['status']=='XS_SMOKE_EXPORTED_PENDING_ROOT_READER'and h['binding']==b and h['native_acceptance']is h['XS_acceptance']is False and h['qualification']=='NOT_GRANTED'and type(h['producer_exit'])is int and h['producer_exit']==0 and not any(k in h for k in ['error','daemon_build_retirement']),'actual complete v4 hosted result, no acceptance')
 source=outer.source_job(get,root,b,m,h,io);helper=B.daemon_classifier(root,m,io);raw=get('daemon.json');io.need(io.pin(raw)['sha256']==h['daemon_identity_sha256'],'whole actual daemon identity');daemon=io.decode(raw);helper.daemon_data(daemon)
 seq=outer.boot_operations(get,h,io);parent,work,token,home=outer.signed_bootstrap(get,root,m,b,h,seq,daemon,source,helper,io)
 q,parent_data,derived=C.stage(get,root,b,h,parent,work,source,seq,io)
 original=outer.image_data
 def image_data(raw,image,t,binding,data):
  if image==parent:return original(raw,image,t,binding,data)
  data.need(image==q['image'],'only the exact separately qualified derived image');rows=data.decode(raw);data.need(len(rows)==1,'one derived image inspection');return C.qualified(parent_data,rows[0],q,data)
 outer.image_data=inner.image_data=image_data
 prep=outer.preparation(get,root,m,b,h,q['image'],work,source,seq,io);op,report,result,observation=inner.producer(get,q['image'],work,h,b,daemon,io)
 class Cleanup:
  inserted=False
  def take(self,argv,**kwargs):
   if argv==C.DOCKER+['image','inspect',parent]and not self.inserted:C.retire(seq,q,h,parent_data,io);self.inserted=True
   return seq.take(argv,**kwargs)
  def end(self):io.need(self.inserted,'mandatory derived image retirement before original-parent cleanup');seq.end()
 outer.bootstrap_cleanup(Cleanup(),h,parent,token,home,prep,b,io)
 mode=B.load('v2/adapters.py','runtime_modes');modes=mode.mode_map(get,root,io)
 return dict(image=q['image'],operation=op,producer_report=report,actor_result=result,runtime_observation=observation,compiler_image=dict(status='SCOPED_DERIVED_IMAGE_DATA_CHECKS_ONLY',qualification=q,derived_image_absent=True,parent_image_absent=True,owned_sealing_container_absent=True),reviewed_runtime_modes=modes)
def consumer(get,root,b,context,io):
 projected=inner_binding(b,context['operation'],io);a=io.decode(get('bundle/xs-admission.json'));manifest=io.decode(io.read(root,'accepted/compiler-inputs.json',io.MIB));driver=manifest['payload'][manifest['driver_source']];make=manifest['payload']['/usr/bin/make'];expected=dict(cc=dict(path='/usr/bin/cachy-asahi-xs-gcc',**{k:driver[k]for k in ['bytes','sha256']}),ld=dict(path='/usr/bin/cachy-asahi-xs-gcc',**{k:driver[k]for k in ['bytes','sha256']}),make=dict(path='/usr/bin/make',**{k:make[k]for k in ['bytes','sha256']}));io.need(a['toolchain']==expected,'exact single-link sealed compiler and unchanged native make operands')
 module=B.load('consumer.py','consumer',consumer_bundle);result=module.validate(get,root,projected,context,io);result.update(outer_operation=OUTER,frozen_inner_operation=INNER,reviewed_runtime_modes=context['reviewed_runtime_modes']);return result
