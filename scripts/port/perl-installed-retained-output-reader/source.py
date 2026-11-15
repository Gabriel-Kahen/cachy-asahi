# SPDX-License-Identifier: MIT
"""Independent whole252 and deterministic241/232 capsule inverses, as DATA."""
import io,tarfile,importlib.util
from pathlib import Path
s=importlib.util.spec_from_file_location('retained_reader_DATA',Path(__file__).parent/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
MAP='2bbf2c808562d13a158d654f7e7d3adb71c7e577444e82ea05a0aad5cf0f3c97';TREE='f8bbb62a4adbe9157b98c13bb8d5b9148bfc12f0'
PARENTS=[(241,81151225,'2267627b5dd03ac09e71ce8819e76bce160faf65','34d0b92316fd3c3aac69fb947b3b31ef14474d0128d10f7a0b1684495cc14175'),(232,80960040,'119da3d2e86d305ba517a7f567c98333aeb9f872','951e947e2d717f5b97e159bf8640adcd69d8884f982a4d22377fbeadf04e0c58')]
RETENTION=dict(parent='/cachy-asahi-perl-lifecycle',path='/cachy-asahi-perl-lifecycle/result',uid=0,gid=0,mode=0o700,storage='OWNED_CONTAINER_WRITABLE_LAYER',parent_absent_before_entry=True,same_filesystem_as_parent_root=True)

def capsule(raw,descriptor):
 D.need(D.pin(raw)=={k:descriptor[k]for k in('bytes','sha256')},'whole Source capsule');out={};total=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as t:
  for item in t:
   D.need(item.isfile()and not item.sparse and item.name.startswith('capsule/'),'only regular Source capsule DATA');n=D.relative(item.name[8:]);D.need(n in descriptor['members']and n not in out and item.uid==item.gid==0 and item.mtime==1791748800 and item.mode==0o444 and 0<item.size<=32*D.MIB,'exact protected Source capsule metadata');b=t.extractfile(item).read(item.size+1);total+=len(b);D.need(total<=48*D.MIB and dict(**D.pin(b),mode=item.mode)==descriptor['members'][n],'Source capsule member hash/mode');out[n]=(b,item.mode)
 D.need(len(out)==20 and set(out)==set(descriptor['members']),'complete20 Source capsule');D.need(D.decode(out['source-map.json'][0])['files']=={n:D.pin(b)for n,(b,m)in out.items()if n!='source-map.json'},'inner Source map');return out

def pack(files):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:',format=tarfile.PAX_FORMAT)as t:
  for n,(b,m)in sorted(files.items()):
   item=tarfile.TarInfo('capsule/'+D.relative(n));item.uid=item.gid=0;item.mtime=1791748800;item.mode=m;item.size=len(b);t.addfile(item,io.BytesIO(b))
 return out.getvalue()

def inverse(files,version):
 record=D.decode(files[f'v{version}-inverse.json'][0]);previous='previous-v'+str(version-1)
 replace={'lifecycle-code/producer.py':previous+'/lifecycle-code-producer.py','lifecycle-code-map.json':previous+'/lifecycle-code-map.json','hosted/common.py':previous+'/hosted-common.py','.github/workflows/native-arm-build.yml':previous+'/workflow.yml','.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml':previous+'/workflow.yml','contract.json':previous+'/contract.json','inverse.json':previous+'/inverse.json','source-map.json':previous+'/source-map.json'}
 if version==3:replace['lifecycle-code/actor.py']=previous+'/lifecycle-code-actor.py'
 D.need(record['replacements']==replace and all(v is None for v in record['actual'].values()),'finite exact archived inverse operands');wanted=record['parent_files'];result={n:files[replace.get(n,n)]for n in wanted if n!='lifecycle-capsule.tar'}
 current=capsule(files['lifecycle-capsule.tar'][0],D.decode(files['contract.json'][0])['capsule'])
 for name in (('actor.py','producer.py')if version==3 else('producer.py',)):current[name]=(files[previous+'/lifecycle-code-'+name][0],0o444)
 current['source-map.json']=(files[previous+'/capsule-source-map.json'][0],0o444);result['lifecycle-capsule.tar']=(pack(current),wanted['lifecycle-capsule.tar']['mode'])
 count,total,tree,map_sha=PARENTS[3-version]
 D.need(len(result)==count and sum(len(b)for b,m in result.values())==total and D.descriptors(result)==wanted and D.tree(result)==tree and D.pin(result['source-map.json'][0])['sha256']==map_sha,'whole exact parent inverse including deterministic capsule');return result

def review(root):
 files=D.snapshot(root);D.need(len(files)==252 and sum(len(b)for b,m in files.values())==81364853 and D.tree(files)==TREE and D.pin(files['source-map.json'][0])['sha256']==MAP,'whole exact252 Source body/mode/map/tree');m=D.decode(files['source-map.json'][0]);D.need(all(v is None for v in m['actual'].values())and m['files']==D.descriptors({n:r for n,r in files.items()if n!='source-map.json'}),'closed252 map/NULL Source selectors')
 parent=inverse(files,3);old=inverse(parent,2);D.need(D.decode(old['source-map.json'][0])['files']==D.descriptors({n:r for n,r in old.items()if n!='source-map.json'}),'closed232 parent map')
 original={n[9:]:r for n,r in files.items()if n.startswith('original/')};D.need(len(original)==200 and D.tree(original)=='f1757dbedeed1591cdb8538f6c91e493cd451966'and D.tree({n:r for n,r in files.items()if n.startswith('original/')})=='83ae6693a6d43465f249eb843eae3ada9c855e5a','whole unchanged original200');contract=D.decode(files['contract.json'][0]);inner=capsule(files['lifecycle-capsule.tar'][0],contract['capsule'])
 for n in ('hosted/reader.py','hosted/capsule.py','lifecycle-code/read_result.py','lifecycle-code/common.py','policy.json','input-review.json','lifecycle-code/domain.json'):D.need(files[n]==parent[n],'unchanged passive Reader/trust/resources: '+n)
 D.need(files['lifecycle-code/actor.py'][0]==inner['actor.py'][0]and files['lifecycle-code/producer.py'][0]==inner['producer.py'][0],'same revised actor/producer core and capsule')
 D.need(contract['adapter_revision']['kind']=='PERL_INSTALLED_RETAINED_RESULT_LAYER_V3'and contract['adapter_revision']['revised_core_files']==['actor.py','producer.py']and contract['adapter_revision']['unchanged_parent_core_files']==10 and contract['adapter_revision']['runtime_grant']is False,'explicit new actor/producer scope')
 return files,contract,inner
