# SPDX-License-Identifier: MIT
"""Real held-source derivation and kernel DATA controls; no actors or GPG."""
import argparse,ast,contextlib,json,os,shutil,sys,tempfile,time,types,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter,media,controller

class Sources(unittest.TestCase):
 def test_whole_media_inverse(self):
  raw=C.read(VM/'runtime'/media.DONOR,256*1024).decode();derived,held=media.derive(VM/'runtime');ast.parse(derived)
  old=ast.parse(raw);new=ast.parse(derived)
  old_functions={n.name:ast.dump(n,include_attributes=False)for n in old.body if isinstance(n,ast.FunctionDef)};new_functions={n.name:ast.dump(n,include_attributes=False)for n in new.body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(set(old_functions),set(new_functions))
  for name in set(old_functions)-{'prepare'}:self.assertEqual(old_functions[name],new_functions[name])
  self.assertIn('umount /dev',held);self.assertNotIn('umount /dev',derived);self.assertIn('BOOT.apply',derived)
  parsed=media.module(VM/'runtime');self.assertTrue(callable(parsed.formatter_recovery_directory));self.assertTrue(callable(parsed.prepare))
 def test_entire_owner_inverse_and_real_binding(self):
  # Compile actual whole accepted function with one consumer and one new-clock
  # replacement; this is the exact implementation path used by execute().
  raw=C.read(CORE/'scripts/ci/core-native-lifecycle/owner.py',256*1024).decode();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='execute');body='\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno])+'\n';self.assertEqual(body.count(controller.TAIL),1);self.assertEqual(body.count('deadline=time.monotonic()+4800'),1)
  api=adapter.core(CORE);self.assertEqual(len(api.C.states()[0]),574);self.assertEqual(len(api.C.states()[2]),589);self.assertEqual(len(api.C.NAMES),7)
 def test_whole_execute_inert_actor_boundary(self):
  # Execute the entire source-derived owner(), substituting only the external
  # actor interfaces. This never calls Docker, GPG, pacman, QEMU or systemctl.
  core=adapter.core(CORE);route=[]
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);base=root/'base';base.mkdir();inputs=root/'carrier7';inputs.mkdir();deps=root/'carrier64';deps.mkdir();workspace=CORE/'runtime/runtime-vm';proof=root/'proof.json';output=root/'owner';image='sha256:'+'a'*64
   lock=''.join(n+' '+v+'\n'for n,v in sorted(core.C.states()[0].items())).encode();(base/'installed-packages.lock').write_bytes(lock);(base/'probe-cid').write_text('e'*64)
   proof.write_bytes(C.encoded(dict(producer_token='a'*16,consumer_token='b'*32,source_sha='c'*40)))
   (base/'report.json').write_bytes(C.encoded(dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',packages=574,ownership=dict(token='a'*16,before_images=[]),image=image)))
   args=types.SimpleNamespace(workspace=workspace,base=base,core7=inputs,core64=deps,output=output,proof=proof)
   def load(name,path):
    if name=='core_original574_owner':return types.SimpleNamespace(inspect_image=lambda *a:dict(Id=image,Size=1))
    return types.SimpleNamespace(load=lambda *a:route.append('apparmor')or dict(status='INERT_SOURCE_CONTROL'))
   def boundary(label):
    def call(*args):route.append(label)
    return call
   def consumer(a,report,command,index,deadline):
    route.append('two-boot-consumer');self.assertGreater(deadline-time.monotonic(),14390);self.assertLessEqual(deadline-time.monotonic(),14400)
   namespace=dict(need=C.need,os=types.SimpleNamespace(environ={}),shutil=types.SimpleNamespace(disk_usage=lambda p:types.SimpleNamespace(free=100*1024**3)),time=time,read=lambda p,cap=None:C.decode(C.read(p)),sha=lambda p:C.pin(C.read(p))['sha256'],LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac',load=load,producer_lease=lambda *a:contextlib.nullcontext(),lease=lambda *a:contextlib.nullcontext(),command_api=lambda *a:lambda *a,**kw:None,save=lambda p,v:p.write_bytes(C.encoded(v)),snapshot_source=boundary('full-original-source-snapshot'),assembly=boundary('whole-original-auth-and-sign'),binding=lambda *a:route.append('original-input-binding')or{},NEW_VM=consumer,retire=boundary('original-actor-retirement'),LABEL='original',failure_data=boundary('failure-data'))
   exec(compile(controller.derive_owner(CORE),'actual-whole-owner-inert-boundaries','exec'),namespace)
   self.assertEqual(namespace['execute'](args),0,C.decode(C.read(output/'owner.json')));self.assertEqual(route,['apparmor','full-original-source-snapshot','whole-original-auth-and-sign','original-input-binding','two-boot-consumer','original-actor-retirement']);self.assertFalse(C.decode(C.read(output/'owner.json'))['release_admission'])
 def test_actual_actor_argv_and_retirement_with_inert_daemon(self):
  import unittest.mock as M
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);base=root/'base';base.mkdir();out=root/'owner';out.mkdir();work=out/'vm-work';work.mkdir();media=out/'media';media.mkdir();nonce='a'*32;image='sha256:'+'b'*64;report=dict(commands=[])
   (base/'report.json').write_bytes(C.encoded(dict(image=image,ownership=dict(token='c'*16))))
   args=types.SimpleNamespace(selected=dict(nonce=nonce),base=base,output=out,core_source=CORE,vm_source=VM,kernel_inputs=root/'kernel-inputs',_owner_report=report);state=dict(exists=False,created=None)
   def command(argv,required=True,seconds=30):
    report['commands'].append(dict(argv=argv,time_limit=seconds));out=b'';err=b'';code=0
    if argv[1:3]==['image','inspect']:out=C.encoded([dict(Id=image,Architecture='arm64',Os='linux',Config=dict(Labels={'org.cachy-asahi.bootstrap574.job':'c'*16}))])
    elif argv[1:3]==['container','inspect']:
     name=argv[-1]
     if not state['exists']:code=1;err=('No such object: '+name).encode()
     else:out=C.encoded([dict(Id='d'*64,Name='/'+name,Image=image,Config=dict(Labels={'org.cachy-asahi.core7-systemd-vm':nonce}),HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,CapDrop=['ALL'],CapAdd=['CAP_CHOWN','CAP_DAC_OVERRIDE','CAP_FOWNER','CAP_FSETID','CAP_SETFCAP'],SecurityOpt=['no-new-privileges']),State=dict(Running=False,Pid=0,ExitCode=0))])
    elif argv[1]=='run':state.update(exists=True,created=argv);self.assertEqual(seconds,1900)
    elif argv[1]=='rm':self.assertEqual(argv[-1],'d'*64);state['exists']=False
    else:self.fail('unexpected actor boundary')
    return dict(code=code,out=out,err=err)
   result=controller.actor(args,command,work,media,'prepare');self.assertTrue(result['actor_absent']);self.assertFalse(state['exists']);argv=state['created'];self.assertIn('--network=none',argv);self.assertIn('--read-only',argv);self.assertNotIn('--privileged',argv);self.assertEqual([a for a in argv if a.startswith('--cap-add=')],['--cap-add='+n for n in('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP')]);self.assertEqual(argv[-4:],['-I','-B','/workspace/media.py','prepare']);self.assertIn('type=bind,src='+str(media)+',dst=/measurement',argv)
 def test_actual_work_registry_matches_original_media_copy_contract(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);work=root/'vm-work';work.mkdir();out=root/'owner';out.mkdir();profile=C.decode(C.read(C.HERE/'profile.json',4*1024**2));selected=dict(nonce='a'*32,source_profiles={n:profile['source_profiles'][n]for n in('core800','ksm637','core7_carrier')})
   args=types.SimpleNamespace(selected=selected,output=out,core_source=CORE,vm_source=VM)
   value=controller.prepare_work(args,work);manifest=C.decode(C.read(work/'runner/runner-files.json',4*1024**2));self.assertEqual(value['runner_files'],manifest)
   self.assertEqual(C.decode(C.read(work/'runner/media-selection.json')),value);self.assertEqual(C.decode(C.read(work/'runner/selection.json')),selected)
   for n,pin in manifest.items():self.assertEqual(C.pin(C.read(work/'runner'/n,32*1024**2)),pin)
   self.assertNotIn('runner-files.json',manifest);self.assertNotIn('selection.json',manifest);self.assertEqual(C.decode(C.read(out/'vm-work-map.json',4*1024**2)),adapter.source_rows(work))
 def test_whole_kernel_import_real_inputs(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);(root/'kernel').mkdir();profile=C.decode(C.read(C.HERE/'profile.json',4*1024**2));rows=profile['source_profiles']['kernel_carrier']['files'];adapter.verify(KERNEL,profile['source_profiles']['kernel_carrier'])
   for n,pin in rows.items():
    raw=C.read(KERNEL/n,256*1024**2);self.assertEqual(C.pin(raw),pin);(root/'kernel'/Path(n).name).write_bytes(raw)
   sys.path.insert(0,str(VM/'runtime'));C.load('contract',VM/'runtime/contract.py');K=C.load('_test_whole_original_kernel',VM/'runtime/kernel_input.py');value,receipt,image,config=K.imported(profile['kernel'],root,VM/'runtime');self.assertEqual(value,profile['kernel']['profile']);self.assertEqual(C.pin(C.read(image,256*1024**2)),value['Image']);self.assertEqual(receipt['status'],'IMPORTED_BUILD_DATA_NOT_SAME_JOB_RECEIPT')
   bad=dict(profile['kernel'],kernel_source='0'*40)
   with self.assertRaisesRegex(ValueError,'source-owned kernel'):K.imported(bad,root,VM/'runtime')
class GraphAPI(unittest.TestCase):
 def bindings(self):
  import graph_api
  core=adapter.core(CORE)
  query=C.load('_core_fresh_graph_query_control',CORE/'runtime/runtime-vm/scripts/ci/expanded600-installer-vm/observer600.py')
  return graph_api,core,query
 def test_private_graph_relative_all_bytes_unicode_and_refusal_parity(self):
  import itertools
  Q,core,query=self.bindings();old=core.api['roots'].installer.relative;new=Q.relative(old)
  values=['a'+chr(i)+'b'for i in range(256)]+['漢字/é','a\\b','a//b','a/./b','a/../b','/a','a/','.', '..','',None,1,Path('a'),'a/\udc80','a/\ud800']
  values+=['/'.join(parts)for parts in itertools.product(('','a','.','..','漢字','a\\b'),repeat=3)]
  for value in values:
   results=[]
   for f in(old,new):
    try:results.append(('ok',f(value)))
    except BaseException as e:results.append(('error',type(e).__name__,str(e)))
   self.assertEqual(results[0],results[1],repr(value))
 def test_whole_fresh_statx_no_result_cache_fallback_and_deadline(self):
  import ctypes,errno
  from unittest.mock import patch
  Q,core,query=self.bindings();calls=[];fallback=[];mode=['success']
  class Call:
   def __call__(self,fd,path,flags,mask,result):
    calls.append(fd);self.assertions=(path,flags,mask)
    if mode[0]!='success':ctypes.set_errno(errno.ENOSYS if mode[0]=='fallback'else errno.EIO);return -1
    result._obj.mask=0x1000;result._obj.mnt_id=100+len(calls);return 0
  call=Call();lib=types.SimpleNamespace(statx=call)
  def original(fd,limits):fallback.append(fd);return 101
  class Limits:
   def tick(self):pass
  with patch.object(ctypes,'CDLL',return_value=lib):fresh=query._mount600(original)
  self.assertEqual(fresh(71,Limits()),101);self.assertEqual(fresh(71,Limits()),102);self.assertEqual(calls,[71,71]);self.assertEqual(fallback,[71]);self.assertEqual(call.assertions,(b'',0x1000,0x1000))
  mode[0]='fallback';calls.clear();fallback.clear()
  with patch.object(ctypes,'CDLL',return_value=lib):fresh=query._mount600(original)
  self.assertEqual(fresh(72,Limits()),101);self.assertEqual(fresh(73,Limits()),101);self.assertEqual(calls,[72]);self.assertEqual(fallback,[72,73])
  mode[0]='error'
  with patch.object(ctypes,'CDLL',return_value=lib):fresh=query._mount600(original)
  with self.assertRaises(OSError):fresh(74,Limits())
  class Expired:
   def tick(self):raise ValueError('root observation deadline')
  with self.assertRaisesRegex(ValueError,'root observation deadline'):fresh(74,Expired())
 def test_entire_actual_guest_graph_private_descriptor_and_caps_route(self):
  import guest,graph_api,gzip
  from unittest.mock import patch
  Q,core,query=self.bindings();scope=VM/'runtime/media-source/scripts/ci/full-root-upgrade-caller/persistent_scope.py';cap=VM/'runtime/media-source/scripts/ci/current604-public-pair-updater16k/cap_scope.py';caps=VM/'runtime/media-source/scripts/apps/file_capabilities.py'
  oldroots=core.api['roots'];oldmount=oldroots._mount_id;oldrelative=oldroots.installer.relative;before=core.T.END;core.T.END=time.monotonic()+3300
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'root';root.mkdir();out=Path(td)/'out';out.mkdir();(root/'payload').write_bytes(b'whole real source-shaped graph\n');os.link(root/'payload',root/'alias');(root/'literal').symlink_to('/literal-not-followed')
   real_load=C.load;real_read=C.read;records=[]
   def load(name,path):
    mapped=scope if str(path)=='/persistent_scope.py'else cap if str(path)=='/source/media-source/scripts/ci/current604-public-pair-updater16k/cap_scope.py'else path
    module=real_load(name,mapped)
    if mapped==scope:
     # The development host has unrelated stacked duplicate mounts. Supply the
     # exact live fixture/root mount rows only, as an explicit test DATA boundary.
     ids=set()
     for endpoint in(root,Path('/')):
      fd=oldroots._open_root(endpoint)
      try:ids.add(oldmount(fd,core.T.budget(core.api,600)))
      finally:os.close(fd)
     raw=module._mount_table();selected='\n'.join(line for line in raw.splitlines()if int(line.split()[0])in ids)+'\n';module._mount_table=lambda:selected
    return module
   def read(path,*args):return real_read(caps if str(path)=='/source/media-source/scripts/apps/file_capabilities.py'else path,*args)
   original=Q.roots
   def selected(roots,q):
    value=original(roots,q);records.append(value);return value
   try:
    with patch.object(guest,'ROOT',root),patch.object(guest,'OUT',out),patch.object(C,'load',side_effect=load),patch.object(C,'read',side_effect=read),patch.object(Q,'roots',side_effect=selected):
     report={};v=guest.graph(core,'private-test',report)
    self.assertEqual(len(records),1);self.assertIsNot(records[0],oldroots);self.assertIs(oldroots._mount_id,oldmount);self.assertIs(oldroots.installer.relative,oldrelative);self.assertEqual(v['nodes']['alias']['hardlink_group'],'alias');self.assertEqual(v['nodes']['literal']['target'],'/literal-not-followed');self.assertEqual(v['security_capabilities'],{})
    raw=C.encoded(v);self.assertEqual(C.inflate((out/'private-test-root.json.gz').read_bytes()),raw);self.assertEqual(report['graphs']['private-test']['raw'],C.pin(raw));self.assertIn('scope.source_manifest',__import__('inspect').getsource(guest.graph));self.assertEqual(core.T.budget(core.api,600).max_nodes,500000)
   finally:core.T.END=before
 def test_graph_api_source_drift_and_unknown_caps_refuse(self):
  import graph_api
  from unittest.mock import patch
  Q,core,query=self.bindings()
  with patch.object(Q,'PINS',dict(Q.PINS,roots=dict(bytes=1,sha256='0'*64))),self.assertRaisesRegex(ValueError,'whole original graph API'):Q.roots(core.api['roots'],query)
  caps=VM/'runtime/media-source/scripts/apps/file_capabilities.py';helper=C.load('_core_graph_caps_source_test',VM/'runtime/media-source/scripts/ci/current604-public-pair-updater16k/cap_scope.py');raw=C.read(caps);observer=helper.derive(raw,set())
  with self.assertRaisesRegex(ValueError,'whole original capability'):Q.capabilities(observer,query,raw+b'\n')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core-source',type=Path,required=True);p.add_argument('--vm-source',type=Path,required=True);p.add_argument('--kernel-carrier',type=Path,required=True);a,rest=p.parse_known_args();CORE=a.core_source.absolute();VM=a.vm_source.absolute();KERNEL=a.kernel_carrier.absolute();unittest.main(argv=[sys.argv[0],*rest])
