"""Genuine Source transforms and MODEL boundaries; no actor, raw or authority."""
import ast,base64,copy,hashlib,importlib.util,json,stat,subprocess,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
HERE=Path(__file__).parent
LEGACY=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-warm-baseline-inputs-r1/constructed-source/arm16k_perl5423_vm')
INITIALIZED=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-initialized-qualification-20261117/scripts/integration/arm16k_perl_initialized_vm')
def module(n,root=HERE):
 s=importlib.util.spec_from_file_location('lifecycle_test_'+n,root/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=module('constructor');Q=module('qualification',INITIALIZED);P=module('policy',INITIALIZED);E=module('ssh_empty',INITIALIZED);ET=module('test_ssh_empty',INITIALIZED)
def scan():
 proof=E.aggregate(ET.Reader(),17,4);nodes={}
 def row(n,kind='directory',mode=0o755):return dict(inode=n,links=2,type=kind,mode=mode,uid=0,gid=0,size=4096,xattrs={},mtime=100,mtime_ns=0)
 for n,(path,kind,mode)in enumerate(P.PUBLIC,100):
  r=row(n,kind,mode)
  if kind=='file':r['sha256']='a'*64
  if kind=='symlink':r['target_b64']=base64.b64encode(b'../usr/lib/os-release').decode()
  nodes[path]=r
 for n,path in enumerate(P.PARENTS,1):nodes[path]=row(4 if path=='root'else n,mode=0o700 if path=='root'else 0o755)
 nodes['root/.ssh']=dict(proof['inode_metadata'],xattrs={})
 return dict(nodes=nodes,records={},root_ssh_empty_proof=proof)
T=SimpleNamespace(scan=scan,P=P)
class Controls(unittest.TestCase):
 def original(self):return {p.relative_to(LEGACY).as_posix():(p.read_bytes(),stat.S_IMODE(p.stat().st_mode))for p in LEGACY.rglob('*')if p.is_file()and p.name!='source.lock.json'}
 def test_genuine_source_transforms_compile_and_only_declared_operational_seams_change(self):
  original=self.original();new=C.transform(original)
  changed={n for n in new if n not in original or new[n]!=original[n]}
  self.assertEqual(changed,{'adapter.py','actor.py','controller.py','image.py','preboot.py','root_ssh.py','guest/root.sh','guest/root-ssh.sh','guest/initialized-state.sh','initialized_integration.py'})
  for name,(body,mode)in new.items():
   if name.endswith('.py'):compile(body,name,'exec')
   if name.endswith('.sh'):self.assertEqual(subprocess.run(['/usr/bin/bash','-n'],input=body,capture_output=True).returncode,0,name)
  for name in('contracts.py','runtime.py','budget.py','protocol.py','proof.py','retention.py','expected_payload.py','restoration.py','guest/probe.sh','guest/case.sh','guest/official-trust.sh','guest/installed-metadata.sh'):self.assertEqual(original[name],new[name])
  actor=new['actor.py'][0].decode();self.assertIn("module('root_ssh').preserve(K,scan,after)",actor);self.assertIn("module('root_ssh').preserve(K,before,after)",actor)
  guest=new['guest/root.sh'][0].decode();self.assertNotIn('preboot_parent_fd',guest);self.assertNotIn('rmdir /var/cache/ldconfig',guest);self.assertNotIn('cp -a -- "$S/$name.saved"',guest)
  self.assertIn('cache_snapshot > "$S/after.cache"',guest);self.assertIn("module('initialized_integration').verify_packet",new['controller.py'][0].decode())
 def test_changed_predecessor_seam_fails_closed(self):
  files=self.original();raw,mode=files['actor.py'];files['actor.py']=(raw.replace(b'descriptor_path=W/',b'UNKNOWN_path=W/'),mode)
  with self.assertRaises(ValueError):C.transform(files)
 def test_whole_constructor_has_full_predecessor_body_mode_inverse(self):
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp)/'Source';r=C.construct(LEGACY,INITIALIZED,out);A=module('adapter',out);self.assertEqual(A.source(r['source_lock']['sha256']),r['source_lock'])
   for p in LEGACY.rglob('*'):
    if p.is_file():q=out/'_legacy'/p.relative_to(LEGACY);self.assertEqual(p.read_bytes(),q.read_bytes());self.assertEqual(stat.S_IMODE(p.stat().st_mode),stat.S_IMODE(q.stat().st_mode))
   self.assertEqual(module('qualification',out/'_initialized').source(C.INITIALIZED),C.INITIALIZED)
   manifest=json.loads((out/'initialized-construction.DATA.json').read_bytes());self.assertIsNone(manifest['actual']['Root_qualification']);self.assertEqual(r['status'],'CONSTRUCTED_SOURCE_NOT_QUALIFIED_OR_EXECUTED')
 def test_old_cold_descriptor_refuses_initialized_present_nodes(self):
  L=Q.legacy(LEGACY);scan=T.scan();case=dict(Source_lock={'bytes':1,'sha256':'a'*64},nonce='a'*32,case={'bytes':1,'sha256':'a'*64});cert=dict(baseline_certificate=dict(raw=Q.RAW,prepared=Q.PREPARED),runtime_certificate=dict(baseline_namespace_pin=L.contracts.json_pin({p:L.image.stable(r)for p,r in scan['nodes'].items()})))
  context=L.preboot.context(L.contracts,cert,case['Source_lock'],case['nonce'],case['case'])
  with self.assertRaises(ValueError):L.preboot.descriptor(L.contracts,L.image,case,cert,scan,L.contracts.canonical(context))
 def test_new_descriptor_authenticates_initialized_snapshot_without_cold_policy(self):
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp)/'Source';C.construct(LEGACY,INITIALIZED,out);P=module('preboot',out);L=Q.legacy(LEGACY);scan=T.scan();cert=dict(_initialized_state=T.P.snapshot(scan),baseline_certificate=dict(raw=Q.RAW,prepared=Q.PREPARED),runtime_certificate=dict(baseline_namespace_pin=L.contracts.json_pin({p:L.image.stable(r)for p,r in scan['nodes'].items()})));packet=dict(Source_lock={'bytes':1,'sha256':'a'*64},nonce='b'*32,case={'bytes':1,'sha256':'c'*64})
   ctx=P.context(L.contracts,cert,packet['Source_lock'],packet['nonce'],packet['case']);raw=P.descriptor(L.contracts,L.image,packet,cert,scan,L.contracts.canonical(ctx));self.assertEqual(len(raw.splitlines()),15);self.assertNotIn('absence_policy',ctx);self.assertFalse(ctx['cold_cleanup']);self.assertNotIn(b'\nA ',raw)
   bad=copy.deepcopy(scan);bad['nodes']['etc/.updated']['inode']+=1
   with self.assertRaises(ValueError):P.descriptor(L.contracts,L.image,packet,cert,bad,L.contracts.canonical(ctx))
 def reader_model(self,nonempty):
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp)/'Source';C.construct(LEGACY,INITIALIZED,out);J=module('initialized_integration',out)
   bodies={2:ET.block([(2,b'.',2),(2,b'..',2),(4,b'root',2)]),4:ET.block([(4,b'.',2),(2,b'..',2),(17,b'.ssh',2)]),17:ET.block([(17,b'.',2),(4,b'..',2)]+([(99,b'PRIVATE_MODEL_NAME',1)]if nonempty else []))};calls=[]
   class Base:
    def __init__(self):self.data=copy.deepcopy(bodies)
    def inode(self,n):
     if n not in(2,4,17):raise AssertionError('private child inode visited')
     calls.append(('inode',n));r=dict(ET.Reader().row,inode=n,mode=0o700 if n in(4,17)else 0o755);r['xattrs']=self.xattrs(b'',0);return r,b'INODE'
    def xattrs(self,*args):calls.append(('xattr',17));return {}
    def chunks(self,r,raw):calls.append(('chunks',r['inode']));yield self.data[r['inode']]
    def inventory(self):
     r,raw=self.inode(17);self.data[17]=ET.block([(17,b'.',2),(4,b'..',2),(99,b'PRIVATE_MODEL_NAME',1)]);return b''.join(self.chunks(r,raw))
   body=(out/'image.py').read_bytes();node=next(n for n in ast.walk(ast.parse(body))if isinstance(n,ast.ClassDef)and n.name=='Reader');K=SimpleNamespace(need=C.need,load=lambda p:{'root_ssh_emptiness':E.aggregate(ET.Reader(),17,4)})
   env=dict(F=SimpleNamespace(Ext4Reader=Base),K=K,module=lambda n:J,time=SimpleNamespace(monotonic=lambda:0),deadline=100,guard=lambda:None)
   exec(compile(ast.Module(body=[node],type_ignores=[]),'constructed_image_reader_MODEL','exec'),env);r=env['Reader']()
   if nonempty:
    with self.assertRaises(ValueError):r.inventory()
    self.assertFalse(any(c[0]=='xattr'for c in calls))
   else:self.assertNotIn(b'PRIVATE_MODEL_NAME',r.inventory());self.assertEqual(sum(c==('chunks',17)for c in calls),1)
   self.assertNotIn(('inode',99),calls)
 def test_constructed_inventory_refuses_nonempty_before_xattrs_or_child_reads(self):self.reader_model(True)
 def test_constructed_inventory_uses_only_verified_empty_blocks_on_race(self):self.reader_model(False)
 def test_new_lifecycle_profile_needs_new_source_and_identical_bounds(self):
  J=module('integration');L=Q.legacy(LEGACY);source=dict(bytes=500,sha256='c'*64)
  oldq=dict(source_lock=C.INITIALIZED,outputs={'prepare':'old-p','boot':'old-b'},created_utc=1,expires_utc=2,method='MODEL_FIXED_METHOD')
  resource=dict(Q.FIXED_RESOURCES,baseline_allocated_bytes=634167296,physical_free_bytes=1,host_MemAvailable_bytes=2,quota_guard=oldq)
  prior={n:{'MODEL':n}for n in J.EVIDENCE};prior['resource_certificate']=resource
  cert=copy.deepcopy(prior);cert['resource_certificate']['quota_guard'].update(source_lock=source,outputs={'prepare':'new-p','boot':'new-b'},created_utc=3,expires_utc=4)
  cert['resource_certificate']['physical_free_bytes']=3;case={'package':'MODEL_UNCHANGED','evidence':{'resource':'MODEL_NEW'}};oldcase=dict(case,evidence={'resource':'MODEL_OLD'})
  J.lifecycle_join(L.contracts,Q,case,cert,oldcase,prior,source)
  bad=copy.deepcopy(cert);bad['resource_certificate']['quota_guard']['source_lock']=C.INITIALIZED
  with self.assertRaises(ValueError):J.lifecycle_join(L.contracts,Q,case,bad,oldcase,prior,source)
  bad=copy.deepcopy(cert);bad['resource_certificate']['boot_seconds']+=1
  with self.assertRaises(ValueError):J.lifecycle_join(L.contracts,Q,case,bad,oldcase,prior,source)
  bad=copy.deepcopy(cert);bad['runtime_certificate']={'MODEL':'CHANGED_PROVIDER'}
  with self.assertRaises(ValueError):J.lifecycle_join(L.contracts,Q,case,bad,oldcase,prior,source)
 def test_unissued_qualification_still_refuses_before_fixture(self):
  with self.assertRaises(ValueError):Q.qualify(json.loads((INITIALIZED/'qualification.TEMPLATE.json').read_bytes()),{}, {}, {}, {}, {}, {}, {})
if __name__=='__main__':unittest.main(verbosity=2)
