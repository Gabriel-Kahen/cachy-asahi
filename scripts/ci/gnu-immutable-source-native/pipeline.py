"""Actual current574 producer/owner/consumer entry and ordered teardown seam."""
import argparse,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D

def seed_archive(root,cache,producer):
 h=D.load('_immutable_source_archive32',root/D.LANE/'archive32.py');v=h.policy(root/D.LANE/'archive32-policy.json',root/D.VM/'scripts/ci/maintained-desktop574-inputs.json');return h.seed_exact(cache,producer/'context/deps',v)
def seed_archive20(root,cache,producer):
 h=D.load('_immutable_source_archive20',root/D.LANE/'archive20.py');v=h.policy(root/D.LANE/'archive20-policy.json',root/D.VM/'scripts/ci/maintained-desktop574-inputs.json');return h.seed_exact(cache,producer/'context/deps',v)
def seed_archive8(root,cache,producer):
 h=D.load('_immutable_source_archive8',root/D.LANE/'archive8.py');v=h.policy(root/D.LANE/'archive8-policy.json',root/D.VM/'scripts/ci/maintained-desktop574-inputs.json');return h.seed_exact(cache,producer/'context/deps',v)
def owner(root):return D.load('_immutable_current_original_owner',root/D.VM/D.OWNER/'job.py')
def native_writer_retirement(root,path):
 O=owner(root);v=O.read(path/'owner.json');D.need(v['status']=='PASS_LIFECYCLE_PENDING_ORDERED_PRODUCER_CLEANUP'and len(v['actors'])>0 and len(v['commands'])>0 and all(r['status']=='PASS_ABSENCE_VERIFIED'for r in v['actors'])and all(r['group_absence_verified']is True for r in v['commands']),'fresh native source writers retired before readonly image preparation');inner=O.read(path/'inner/owner.json');D.need(inner['status']=='PASS_GENERIC_ARM_INSTALLED_PROVIDER_AND_TEARDOWN','same fresh native full574 lifecycle and teardown');return dict(status='SOURCE_ENFORCED_CURRENT_NATIVE_WRITERS_RETIRED',source=v['source_sha'],token=v['token'],owner_report=D.pin(D.read(path/'owner.json')),inner_report=D.pin(D.read(path/'inner/owner.json')),prior_Root_decision='INPUT_AUTHORITY_ONLY_NOT_CURRENT_NATIVE_ACCEPTANCE')
def consume(a):
 root=a.source.absolute();D.source(root);witness=native_writer_retirement(root,a.owner);selected=a.binding/'selected-runtime';private=a.binding/'private-inputs';sys.path.insert(0,str(selected/'immutable'));C=D.load('_immutable_selected_native_controller',selected/'immutable/native_controller.py');value=D.obj(D.read(private/'policy.json'));D.need(witness['source']==value['actual_source'],'fresh writer source equals actual deployment');value['bootstrap']['producer_retirement']=witness
 # Only runtime-private selection changes after actual original actor retirement.
 for p in(private/'policy.json',selected/'immutable/policy.json'):p.write_bytes(D.encoded(value))
 manifest=D.obj(D.read(selected/'runtime-source.json',2*1024**2));manifest['files']['immutable/policy.json']=D.pin(D.encoded(value));(selected/'runtime-source.json').write_bytes(D.encoded(manifest));args=argparse.Namespace(workspace=root/D.VM,acceptances=root/D.VM/D.INST/'prerequisites',owner=a.owner,base=a.base,kernel_work=a.kernel,kernel_receipt=a.kernel/'Root-artifact-replay.json',output=a.output,runtime_bundle=selected,runtime_inputs=private);return C.execute(args,value)
def cleanup(a):
 # Original cleanup is reachable only after exact consumer absence. A failed
 # or partial consumer with unknown state cannot trigger producer destruction.
 root=a.source.absolute();D.source(root)
 if a.output.exists():
  value=D.obj(D.read(a.output/'owner.json',4*1024**2));D.need(value.get('consumer_cleanup')=='PASS_ALL_ACTORS_GROUPS_AND_DISKS_REMOVED','unknown new consumer: retain producer and source')
 O=owner(root);return O.cleanup(argparse.Namespace(workspace=root/D.VM,proof=a.proof,base=a.base,output=a.owner,receipt=a.receipt))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('seed-archive','seed-archive20','seed-archive8','consume','cleanup'));p.add_argument('--source',type=Path,default=D.ROOT)
 for n in('cache','base','owner','binding','kernel','output','proof','receipt'):p.add_argument('--'+n,type=Path)
 a=p.parse_args()
 if a.action=='seed-archive':print(D.encoded(seed_archive(a.source,a.cache,a.base)).decode(),end='');return 0
 if a.action=='seed-archive20':print(D.encoded(seed_archive20(a.source,a.cache,a.base)).decode(),end='');return 0
 if a.action=='seed-archive8':print(D.encoded(seed_archive8(a.source,a.cache,a.base)).decode(),end='');return 0
 if a.action=='consume':return consume(a)
 print(D.encoded(cleanup(a)).decode(),end='');return 0
if __name__=='__main__':raise SystemExit(main())
