# SPDX-License-Identifier: MIT
"""Four-boot source-shaped inert actor controls; no boot/install/GPG authority."""
import argparse,ast,base64,copy,importlib.util,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,rollback as R,guest as G,guest_guard as GG,host,adapter
p=argparse.ArgumentParser();p.add_argument('--core-source',type=Path,required=True);a,rest=p.parse_known_args()

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.original=adapter.core(a.core_source.absolute())
 def selected(self):
  profile=C.decode(C.read(C.HERE/'profile.json',4*1024**2));return dict(schema=1,scope=profile['purpose'],actual=dict(source='a'*40,ref='codex/source-shaped-rollback',run=1,attempt=1),nonce='b'*32,kernel=profile['kernel'],source_profiles={n:profile['source_profiles'][n]for n in('core800','ksm637','core7_carrier')},budgets=C.BUDGET)
 def test_real_source_declared_full_inventories_and_exact_two_boundaries(self):
  base,middle,installed,remove=R.states(self.original);self.assertEqual([len(v)for v in(base,middle,installed,remove)],[574,589,589,15]);self.assertEqual({n:v for n,v in middle.items()if n not in remove},base);self.assertEqual(set(remove),self.original.C.NAMES-self.original.C.REPLACED|set(self.original.C.profile()['support']))
 def test_all_four_boots_same_full_nonce_media_and_expected_live_pid1(self):
  s=self.selected();C.selection(s);values=[host.qemu('/kernel','/boot','/data',s['nonce'],n,1792659524)for n in range(1,5)]
  for phase,argv in enumerate(values,1):
   self.assertEqual(GG.kernel_fields('caa_core_vm='+s['nonce']+' caa_core_phase='+str(phase))['caa_core_phase'],str(phase));self.assertIn('caa_core_phase='+str(phase),argv[argv.index('-append')+1]);self.assertEqual([v for v in argv if v.startswith('virtio-blk-pci,')],[v for v in values[0]if v.startswith('virtio-blk-pci,')]);self.assertIn('none',argv);self.assertNotIn('-virtfs',argv)
  self.assertEqual([R.expected(s,n)['package_version']for n in range(1,5)],['systemd 262-1.2\n']*2+['systemd 262-1\n']*2);self.assertEqual([R.expected(s,n,True)['package_version']for n in range(1,5)],['systemd 262-1\n','systemd 262-1.2\n','systemd 262-1.2\n','systemd 262-1\n'])
  for raw in('caa_core_vm='+s['nonce']+' caa_core_phase=5','caa_core_vm='+s['nonce']+' caa_core_phase=3 caa_core_phase=4'):
   with self.assertRaises(ValueError):GG.kernel_fields(raw)
 def test_actual_source_worker_executes_both_rollback_boundaries_and_fourth_boot(self):
  core=self.original;base,middle,installed,remove=R.states(core);state={'inventory':installed,'phase':3};s=self.selected();root_identity=dict(device=258,inode=2,serial=C.disk_serial(s['nonce'],'boot'),machine_id=s['nonce']);calls=[]
  with tempfile.TemporaryDirectory()as td:
   temporary=Path(td);out=temporary/'out';out.mkdir();fs=temporary/'fixture';fs.mkdir()
   for name in('inputs','etc','run','proc'):(fs/name).mkdir()
   (fs/'proc/cmdline').write_text('source-only readback delegated to exact kernel_epoch boundary');(fs/'inputs/lifecycle-input.json').write_bytes(b'{}\n');(fs/'etc/shells').write_bytes(b'/bin/bash\n')
   def path(value):
    value=Path(value)
    return fs/value.relative_to('/')if str(value)in('/inputs','/etc','/run','/proc')or str(value).startswith(('/inputs/','/etc/','/run/','/proc/'))else value
   old_read=C.read
   def read(value,cap=2*1024**2):return old_read(path(value),cap)
   def node(raw):return dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(raw))
   original_nodes={'protected':node(b'full-other-source-shaped'),'etc/pacman.conf':node(b'owned-user'),'etc/systemd/system.conf':node(b'owned-user')}
   original_nodes.update({'usr/lib/source-shaped-'+n:node(('original:'+n).encode())for n in core.C.REPLACED})
   def graph_value():
    nodes=dict(original_nodes)
    if len(state['inventory'])==589:
     for n in set(installed)-set(base):nodes['usr/lib/source-shaped-'+n]=node(n.encode())
     if state['inventory']==installed:
      for n in core.C.REPLACED:nodes['usr/lib/source-shaped-'+n]=node(('candidate:'+n).encode())
    return dict(complete=True,nodes=nodes,security_capabilities={})
   import gzip
   def save_graph(name,report):
    value=graph_value();raw=C.encoded(value);compressed=gzip.compress(raw,mtime=0);name+='-root.json.gz';(out/name).write_bytes(compressed);report['graphs'][name.removesuffix('-root.json.gz')]=dict(file=name,raw=C.pin(raw),compressed=C.pin(compressed));return value
   initial=graph_value();raw=C.encoded(initial);(out/'phase1-installed-root.json.gz').write_bytes(gzip.compress(raw,mtime=0));(out/'phase1-before-root.json.gz').write_bytes(gzip.compress(C.encoded(dict(nodes=original_nodes,security_capabilities={})),mtime=0));previous=dict(status='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION',root=root_identity);(out/'phase2-custody.json').write_bytes(C.encoded(previous))
   packages={}
   for n in core.C.NAMES|set(core.C.profile()['support']):
    key=n if n in core.C.NAMES else n+'-original';version=installed[n];data=('candidate:'+n).encode()if n in core.C.REPLACED else n.encode();packages[key]=dict(observed=dict(metadata=dict(pkgname=[n],pkgver=[version],backup=[]),nodes={'usr/lib/source-shaped-'+n:node(data)}),transaction=dict(name=n,version=version,archive=Path('/inputs/packages')/(n+'.pkg.tar.xz')))
   for n in core.C.REPLACED:packages[n+'-original']=dict(observed=dict(metadata=dict(pkgname=[n],pkgver=[base[n]],backup=[]),nodes={'usr/lib/source-shaped-'+n:node(('original:'+n).encode())}),transaction=dict(name=n,version=base[n],archive=Path('/inputs/packages')/(n+'-original.pkg.tar.xz')))
   accounts={n:dict(file=C.pin(n.encode()),data=base64.b64encode(n.encode()).decode())for n in __import__('effects').ACCOUNTS}
   class Commands:
    def __init__(self,api,report):self.report=report
    def call(self,argv,seconds=90):
     if argv[0]=='/usr/bin/pacman':
      calls.append(argv);expected_request=json.loads((fs/'run/core-hook-expected.json').read_bytes());(fs/'run/core-hook-witness.json').write_bytes(C.encoded(expected_request));(fs/'run/core-pacman.log').write_bytes(b"running '20-systemd-sysusers.hook'\nrunning '21-systemd-tmpfiles.hook'\n")
      state['inventory']=middle if '-U'in argv else base
     number=len(self.report['commands']);raw=b'';row=dict(argv=argv,exit_code=0,group_absence_verified=True,time_limit=seconds,seconds=.001,output_limit=1024**2,stdout_bytes=0,stderr_bytes=0,stdout_sha256=C.pin(raw)['sha256'],stderr_sha256=C.pin(raw)['sha256']);self.report['commands'].append(row)
     for suffix in('stdout','stderr'):(out/('phase%d-command-%03d.%s'%(state['phase'],number,suffix))).write_bytes(raw)
     return raw
   def pid1(*_):
    e=R.expected(s,state['phase'],True);mask=(1<<41)-1
    return dict(architecture='aarch64',page_size=16384,kernel=e['kernel'],capabilities=dict(CapEff=mask,CapPrm=mask,CapBnd=mask,CapInh=0,CapAmb=0,NoNewPrivs=0,Seccomp=0,last=40),pid=1,exe_link='/usr/lib/systemd/systemd',exe=e['exe'],version=e['version'],package_version=e['package_version'],manager=dict(Version=e['manager_version'],Virtualization='qemu',SystemState='initializing'),root=root_identity,boot_id='a'*8+'-'+'b'*27)
   def reference(name):
    raw=C.read(out/name);return dict(file=name,compressed=C.pin(raw),raw=C.pin(C.inflate(raw)))
   first=dict(status='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION',root=root_identity,accounts=dict(after=accounts),graphs={'phase1-installed':reference('phase1-installed-root.json.gz'),'phase1-before':reference('phase1-before-root.json.gz')});(out/'phase1-custody.json').write_bytes(C.encoded(first));(temporary/'inputs/packages').mkdir(parents=True)
   products={key:dict(file=key+'.pkg.tar.xz',name=row['transaction']['name'],version=row['transaction']['version'])for key,row in packages.items()};(temporary/'inputs/catalog.json').write_bytes(C.encoded(dict(products=products)))
   def keys(*_):
    home=temporary/'keys';home.mkdir();return home,packages
   T=types.SimpleNamespace(END=None,INPUTS=None,public_keys=keys,budget=lambda *_:None,payload=lambda *args:calls.append('whole-payload'),configuration=lambda *args:calls.append(('whole-user-config',args[-1])))
   F=types.SimpleNamespace(accounts=lambda *_:copy.deepcopy(accounts),capture=lambda *_:dict(complete='source-shaped-boundary'),read_aux=lambda *_:b'aux');bound=types.SimpleNamespace(C=types.SimpleNamespace(**{n:getattr(core.C,n)for n in('states','REPLACED','NAMES','FIXTURES','profile')},P=types.SimpleNamespace(archive=lambda path:packages[Path(path).name.removesuffix('.pkg.tar.xz')]['observed']),configuration=lambda *_:(dict(token=s['nonce'],source_capabilities={}),)),T=T,F=F,api={})
   fake=types.SimpleNamespace(OUT=out,ROOT=fs,END=None,sources=lambda *_:bound,Commands=Commands,pid1=pid1,graph=lambda _,label,report:save_graph(label,report),inventory=lambda _:dict(state['inventory']),generated=lambda *args:dict(source_only=True),save=lambda name,value:(out/name).write_bytes(C.encoded(value)))
   with patch.object(R,'Path',path),patch.object(C,'read',read),patch.object(R.W.time,'time_ns',return_value=1792659524*10**9),patch.object(R.W,'kernel_epoch',return_value=1792659524),patch.object(R,'changes',lambda *args:dict(source_only='whole-function-inert-effects-boundary')):
    for phase in(3,4):(out/('phase%d-wallclock.json'%phase)).write_bytes(C.encoded(dict(schema=1,source='CURRENT_NATIVE_HOST_CLOCK_REALTIME',nonce=s['nonce'],phase=phase,epoch_seconds=1792659524,previous_realtime_ns=1790293564*10**9,initialized_realtime_ns=1792659524*10**9,monotonic_before_ns=10,monotonic_after_ns=11)))
    third=R.worker(fake,s,3,root_identity);self.assertEqual(state['inventory'],base);self.assertEqual(set(third['graphs']),{'phase3-before','phase3-downgraded','phase3-restored'});self.assertEqual(third['inventories'],dict(before=installed,downgraded=middle,restored=base));self.assertTrue(third['public_home_retired']);state['phase']=4;fourth=R.worker(fake,s,4,root_identity);self.assertEqual(set(fourth['graphs']),{'phase4-before'});self.assertEqual(fourth['previous'],C.pin(C.encoded(third)))
   # Whole new passive tail executes against the same full source-shaped worker
   # output, with only archive/actor/effects boundaries inert in this route test.
   def frame(phase,row):
    state['phase']=phase;value=pid1();e=R.expected(s,phase);value.update(exe=e['exe'],version=e['version'],package_version=e['package_version']);value['manager'].update(Version=e['manager_version'],SystemState='running');return dict(phase=phase,qemu=dict(exit_code=0,group_absence_verified=True,time_limit=3600,seconds=.1,output_limit=1024**2,stdout_bytes=0,stderr_bytes=0),result=dict(pid1=value,custody=row,previous=row['previous'],observer_commands=[]))
   boots=[{}, {},frame(3,third),frame(4,fourth)]
   def read_graph(directory,ref):return C.decode(C.inflate(C.read(directory/ref['file'])))
   with patch.object(R,'changes',lambda *args:dict(source_only='whole-function-inert-effects-boundary')):
    self.assertEqual(R.validate_tail(out,bound,s,boots,read_graph)['original_packages'],574)
    bad=copy.deepcopy(third);bad['inventories']['restored'].pop('systemd');(out/'phase3-custody.json').write_bytes(C.encoded(bad));broken=copy.deepcopy(boots);broken[2]['result']['custody']=bad
    with self.assertRaisesRegex(ValueError,'inventory equality'):R.validate_tail(out,bound,s,broken,read_graph)
   transactions=[v for v in calls if isinstance(v,list)];self.assertEqual(len(transactions),2);self.assertEqual(transactions[0][5],'-U');self.assertEqual(transactions[1][5],'-R');self.assertEqual(transactions[1][6:],sorted(remove));self.assertNotIn('--noscriptlet',str(transactions));self.assertNotIn('--nodeps',str(transactions));self.assertEqual(calls.count('whole-payload'),4);self.assertEqual(calls.count(('whole-user-config',False)),4)
 def test_whole_existing_hook_body_exact_needs_targets_and_prewrite_refusals(self):
  import io
  raw=C.read(C.HERE/'hook.py').decode();body=raw[raw.index("s=C.decode"):];selected=self.selected();request=dict(nonce=selected['nonce'],label='rollback-downgrade',targets=sorted(self.original.C.REPLACED))
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   def path(value):return root/Path(value).name
   (root/'selection.json').write_bytes(C.encoded(selected));(root/'core-hook-expected.json').write_bytes(C.encoded(request));oldread=C.read
   def read(value,cap=2*1024**2):return oldread(path(value),cap)
   for payload,okay in((('\n'.join(request['targets'])+'\n').encode(),True),(b'systemd\n',False),(b'systemd\nsystemd\n',False),(b'systemd',False)):
    target=root/'core-hook-witness.json'
    if target.exists():target.unlink()
    namespace=dict(C=C,G=types.SimpleNamespace(guard=lambda s,role:self.assertEqual(role,'hook')),Path=path,sys=types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(payload))))
    with patch.object(C,'read',read):
     if okay:exec(compile(body,'whole-existing-libALPM-witness-body','exec'),namespace);self.assertEqual(C.decode(oldread(target)),request)
     else:
      with self.assertRaises(ValueError):exec(compile(body,'whole-existing-libALPM-witness-body','exec'),namespace)
      self.assertFalse(target.exists())
 def test_whole_original_graph_body_refuses_unrelated_changes(self):
  core=self.original;before={'etc/user-owned':dict(type='file',mode=0o644,uid=1000,gid=1000,**C.pin(b'held'))};after=copy.deepcopy(before);after['etc/user-owned']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'unrelated/protected'):core.C.changes(before,after,[],[])
  self.assertTrue(core.C.changes(before,before,[],[])['unrelated_complete_nodes_preserved'])
 def test_additional_boot_protocol_requires_original_pid1_and_natural_retirement(self):
  import test_protocol as fixture
  selected,_,value=fixture.fixture();selected['scope']=self.selected()['scope'];selected['budgets']=C.BUDGET;value['phase']=3;value['custody']['phase']=3;value['custody']['wallclock']['phase']=3
  e=dict(R.expected(selected,3),host_clock=dict(schema=1,source='CURRENT_NATIVE_HOST_CLOCK_REALTIME',nonce=selected['nonce'],phase=3,epoch_seconds=1792659524,host_monotonic_ns=100));value['pid1'].update(exe=e['exe'],version=e['version'],package_version=e['package_version']);value['pid1']['manager']['Version']=e['manager_version']
  raw=fixture.frames(value);self.assertEqual(C.protocol(raw,selected,3,e)['phase'],3)
  bad=copy.deepcopy(value);candidate=R.expected(selected,2);bad['pid1'].update(exe=candidate['exe'],version=candidate['version'],package_version=candidate['package_version'])
  with self.assertRaises(ValueError):C.protocol(fixture.frames(bad),selected,3,e)
  with self.assertRaises(ValueError):C.protocol(raw.split(C.RETIRED)[0],selected,3,e)
 def test_complete_held_effects_body_original_config_cache_account_and_graph_guards(self):
  import struct,effects
  core=self.original;nodes={'protected':dict(type='file',mode=0o644,uid=1000,gid=1000,**C.pin(b'user'))};accounts={}
  for name in effects.ACCOUNTS:
   stem=Path(name).name.removesuffix('-');raw=(b'root:x:0:0:root:/root:/bin/bash\n'if stem=='passwd'else b'root:x:0:\n'if stem=='group'else b'root:!:::\n');accounts[name]=dict(file=C.pin(raw),data=base64.b64encode(raw).decode(),records={'root':C.pin(raw)});nodes[name]=dict(type='file',mode=0o600 if 'shadow'in name else 0o644,uid=0,gid=0,**C.pin(raw))
  raw=core.F.A.MAGIC+struct.pack('<II',1,1)+core.F.A.ENTRY.pack(1,2,3,4,0,0,0)+b'\0'*4+b'\0';node=dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(b'abc'));nodes['usr/lib/source-shaped.so']=node;nodes['usr/bin/ldconfig']=dict(type='file',mode=0o755,uid=0,gid=0,bytes=865664,sha256=core.F.A.HELPER_SHA256);nodes[effects.AUX]=dict(type='file',mode=0o600,uid=0,gid=0,**C.pin(raw));cache=dict(raw=C.pin(raw),data=base64.b64encode(raw).decode(),libraries=[dict(key=[1,2,3,4],files=[dict(path='usr/lib/source-shaped.so',node=node,identity=[4,1,0o100644,1,0,0,3,1,2000000000])])]);shell=b'/bin/bash\n';nodes['etc/shells']=dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(shell));generated={}
  for name,argv in effects.GENERATED.items():
   node=dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(b'generated'));nodes[name]=node;command=dict(argv=list(argv),exit_code=0,group_absence_verified=True,time_limit=90,seconds=.1,output_limit=1024**2,stdout_bytes=0,stderr_bytes=0);generated[name]=dict(before=node,first=node,second=node,command=command)
  branches=[]
  def configuration(*args):branches.append(args[-1]);return core.T.configuration(*args)
  bound=types.SimpleNamespace(C=core.C,F=core.F,T=types.SimpleNamespace(configuration=configuration));args=[nodes,copy.deepcopy(nodes),[],[],dict(before=accounts,after=accounts),cache,generated,dict(data='',pin=C.pin(b'')),dict(before=base64.b64encode(shell).decode(),after=base64.b64encode(shell).decode())]
  self.assertTrue(R.changes(bound,*args)['no_prefix_exemptions']);self.assertEqual(branches,[False])
  bad=copy.deepcopy(args);bad[1]['protected']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'unrelated/protected'):R.changes(bound,*bad)
  bad=copy.deepcopy(args);bad[5]['libraries'][0]['key'][0]=99
  with self.assertRaises(ValueError):R.changes(bound,*bad)
  bad=copy.deepcopy(args);bad[4]['after']['etc/passwd']['records']['root']=C.pin(b'changed')
  with self.assertRaises(ValueError):R.changes(bound,*bad)
 def test_whole_host_four_boot_sequence_identity_custody_and_forced_retirement_refusal(self):
  import test_protocol as fixture
  selected=self.selected()
  for failure in(None,'forced','reused-boot-id'):
   with self.subTest(failure=failure),tempfile.TemporaryDirectory()as td:
    root=Path(td);media=root/'media';media.mkdir();out=root/'boots';identities={}
    for name,size in(('boot.raw',16*1024**3),('data.raw',24*1024**3)):
     (media/name).write_bytes(b'source-shaped-disk-actor-boundary');st=(media/name).stat();identities[name]=dict(identity=[st.st_dev,st.st_ino,st.st_uid,size],bytes=size,sha256=C.pin(name.encode())['sha256'])
    (media/'core-media.json').write_bytes(C.encoded(dict(status='PREPARED_CORE7_REAL_SYSTEMD_MEDIA_NOT_BOOTED',nonce=selected['nonce'],budgets=C.BUDGET,files={n:{k:v[k]for k in('bytes','sha256')}for n,v in identities.items()})))
    previous=[];calls=[]
    def execute(argv,output,env,seconds,limit):
     phase=len(calls)+1;calls.append(argv);_,_,value=fixture.fixture();e=R.expected(selected,phase);value.update(nonce=selected['nonce'],phase=phase);utc=int(next(x.split('=',1)[1]for x in argv[argv.index('-append')+1].split()if x.startswith('caa_core_realtime=')));value['custody'].update(phase=phase,wallclock=dict(schema=1,source='CURRENT_NATIVE_HOST_CLOCK_REALTIME',nonce=selected['nonce'],phase=phase,epoch_seconds=utc,previous_realtime_ns=1790293564*10**9,initialized_realtime_ns=utc*10**9,monotonic_before_ns=10,monotonic_after_ns=11));value['pid1'].update(exe=e['exe'],version=e['version'],package_version=e['package_version']);value['pid1']['manager']['Version']=e['manager_version'];value['pid1']['root'].update(serial=e['serial'],machine_id=selected['nonce']);value['pid1']['boot_id']=('00000000-0000-0000-0000-%012d'%(1 if failure=='reused-boot-id'else phase));value['previous']=None if not previous else C.pin(C.encoded(previous[-1]));previous.append(value['custody']);raw=fixture.frames(value)
     row=dict(argv=argv,exit_code=0,group_absence_verified=failure!='forced',time_limit=seconds,seconds=.001,output_limit=limit,stdout_bytes=len(raw),stderr_bytes=0,stdout_sha256=C.pin(raw)['sha256'],stderr_sha256=C.pin(b'')['sha256']);return row,raw,b'',None
    with patch.object(host,'disk',lambda path,size:copy.deepcopy(identities[Path(path).name])):
     if failure:
      with self.assertRaises(ValueError):host.two_boots(selected,media,'/exact-kernel',out,types.SimpleNamespace(run_command=execute),None)
     else:
      result=host.two_boots(selected,media,'/exact-kernel',out,types.SimpleNamespace(run_command=execute),None);self.assertEqual(len(result['boots']),4);self.assertEqual([r['phase']for r in result['boots']],[1,2,3,4]);self.assertTrue(all((out/('boot-%d.json'%n)).is_file()for n in range(1,5)));self.assertEqual([C.decode(C.read(out/('launch-%d.json'%n)))for n in range(1,5)],[r['host_clock']for r in result['boots']])
    import fcntl
    for name in identities:
     with (media/name).open('rb')as stream:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
 def test_no_native_authority_and_original_stage_caps_preserved(self):
  self.assertEqual(C.BUDGET,dict(owner=21600,producer=2300,assembly=1070,media=1900,vm_shared=14400,boot=3600,transaction=90,cleanup=60));self.assertIsNone(C.decode(C.read(C.HERE/'profile.json',4*1024**2))['actual']);s=self.selected();s['actual']=None
  with self.assertRaises(ValueError):C.selection(s)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
