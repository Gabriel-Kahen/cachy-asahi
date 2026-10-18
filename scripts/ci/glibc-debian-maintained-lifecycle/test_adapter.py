"""Finite metadata/source controls. No native packages, signing or actors."""
import ast,copy,hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
A=load('caa3_adapter',HERE/'adapter.py');G=load('caa3_gate',HERE/'candidate_gate.py')
def functions(raw):
 result={}
 for n in ast.parse(raw).body:
  if isinstance(n,ast.FunctionDef) and n.name not in result:result[n.name]=n
 return result
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix='caa3-lifecycle-source-');cls.output=Path(cls.temp.name)/'emitted'
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):cls.receipt=A.emit(ROOT,cls.output)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def setUp(self):
  guard=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));guard.start();self.addCleanup(guard.stop)
 def test_all_case_runtime_caps_mount_profile_and_cleanup_bodies_unchanged(self):
  for role in ('lifecycle','interruption'):
   old=ROOT/(A.OLD+role);new=self.output/(A.NEW+role)
   for name in ('container.py','run.py','scrub.py')+(('interruption.py',) if role=='interruption' else ()):
    self.assertEqual((old/name).read_bytes(),(new/name).read_bytes())
   before=functions((old/'common.py').read_bytes());after=functions((new/'common.py').read_bytes())
   for name,node in before.items():self.assertEqual(ast.dump(node,include_attributes=False),ast.dump(after[name],include_attributes=False),name)
 def test_outer_owner_changes_only_exact_identity_and_extra_binding_operands(self):
  for role in ('lifecycle','interruption'):
   before=functions((ROOT/(A.OLD+role+'-owner/job.py')).read_bytes());after=functions((self.output/(A.NEW+role+'-owner/job.py')).read_bytes())
   for name,node in before.items():
    actual=copy.deepcopy(after[name])
    if name=='materialize':
     calls=[n for n in ast.walk(actual) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='dict' and any(k.arg=='version' for k in n.keywords)];self.assertEqual(len(calls),1)
     call=calls[0];self.assertEqual({k.arg for k in call.keywords}-{k.arg for n in ast.walk(node) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='dict' for k in n.keywords},{'candidate','source_authority'})
     call.keywords=[k for k in call.keywords if k.arg not in ('candidate','source_authority')]
     next(k.value for k in call.keywords if k.arg=='version').value='2.43.caa1-1'
    self.assertEqual(ast.dump(node,include_attributes=False),ast.dump(actual,include_attributes=False),name)
 def test_unbound_refuses_before_input_output_or_actor(self):
  for role in ('lifecycle','interruption'):
   folder=self.output/(A.NEW+role);c=load('inner_'+role,folder/'common.py');owner=load('owner_'+role,self.output/(A.NEW+role+'-owner/job.py'))
   with self.assertRaisesRegex(ValueError,'UNBOUND'):c.configuration(self.output/'NO_INPUT','0'*64)
   proof=self.output/('NO_PROOF_'+role)
   with self.assertRaisesRegex(ValueError,'UNBOUND'):owner.proof(NS(workspace=self.output,proof=proof))
   self.assertFalse(proof.exists());self.assertFalse((self.output/'NO_INPUT').exists())
 def test_old_caa1_caa2_and_source_only_carrier_cannot_be_native_identity(self):
  self.assertEqual(G.identity(dict(G.EXPECTED)),G.EXPECTED)
  for bad in ({},dict(status='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR'),dict(G.EXPECTED,version='2.43.caa1-1'),dict(G.EXPECTED,version='2.43.caa2-1'),dict(G.EXPECTED,authority_sha256='0'*64),dict(G.EXPECTED,source_packet_ref='0'*40)):
   with self.subTest(bad=bad),self.assertRaises(ValueError):G.identity(bad)
 def test_payload_uses_full_new_measured_nodes_not_old_magic_count(self):
  nodes={'usr':dict(type='directory',mode=493,uid=0,gid=0),'usr/item':dict(type='file',mode=420,uid=0,gid=0,bytes=1,sha256='a'*64)}
  payload=dict(node_count=2,node_manifest_sha256=hashlib.sha256(G.encoded(nodes)).hexdigest());self.assertEqual(G.payload(dict(nodes=nodes),dict(payload=payload)),payload)
  for wrong in (dict(payload,node_count=1066),dict(payload,node_count=True),dict(payload,node_manifest_sha256='0'*64)):
   with self.assertRaises(ValueError):G.payload(dict(nodes=nodes),dict(payload=wrong))
  changed=copy.deepcopy(nodes);changed['usr/item']['mode']=493
  with self.assertRaises(ValueError):G.payload(dict(nodes=changed),dict(payload=payload))
 def test_closed_generated_manifests_and_current_app_armor_pin_present(self):
  self.assertEqual(self.receipt['status'],'EMITTED_SOURCE_ONLY_CAA3_PAIR_PACKET_UNBOUND')
  for role in ('lifecycle','interruption'):
   for suffix,filename in (('','source-manifest.json'),('-owner','integration-manifest.json')):
    folder=self.output/(A.NEW+role+suffix);m=json.loads((folder/filename).read_bytes())
    for name,row in m['files'].items():
     p=folder/name if not suffix else self.output/name
     if not p.exists():p=ROOT/name
     self.assertEqual(A.pin(p.read_bytes()),row,name)
    if suffix:self.assertIn('scripts/ci/glibc-gnu-trial-apparmor/profile.py',m['files'])
 def test_current_created_export_exception_remains_exact_and_nonruntime(self):
  for role in ('lifecycle','interruption'):
   job=load('created_export_'+role,self.output/(A.NEW+role+'-owner/job.py'))
   token='a'*32;name=('caa-gnu-provider-owner-' if role=='lifecycle' else 'caa-gnu-provider-interruption-owner-')+token+'-export'
   value=dict(Name='/'+name,Image='sha256:'+'b'*64,Id='c'*64,Config=dict(Labels={job.LABEL:token},Entrypoint=['/usr/bin/false']),
    AppArmorProfile='',RestartCount=0,State=dict(Status='created',ExitCode=0,Error='',Running=False,Pid=0,StartedAt='0001-01-01T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z',Paused=False,Restarting=False,OOMKilled=False,Dead=False),
    HostConfig=dict(ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=None,NetworkMode='none',SecurityOpt=['no-new-privileges']))
   self.assertEqual(job.verify_actor(value,name,value['Image'],job.LABEL,token,'c'*64),'c'*64)
   for suffix in ('extract','source-cleanup','inner-scrub'):
    bad=copy.deepcopy(value);bad['Name']='/'+name.removesuffix('export')+suffix
    with self.subTest(role=role,suffix=suffix),self.assertRaises(ValueError):job.verify_actor(bad,bad['Name'][1:],bad['Image'],job.LABEL,token)
   for section,key,replacement in (('State','StartedAt','2026-10-17T01:00:00Z'),('State','Running',True),('HostConfig','ReadonlyRootfs',False),('HostConfig','CapAdd',['SYS_ADMIN']),('HostConfig','NetworkMode','host'),('Config','Entrypoint',['/usr/bin/sleep'])):
    bad=copy.deepcopy(value);bad[section][key]=replacement
    with self.subTest(role=role,section=section,key=key),self.assertRaises(ValueError):job.verify_actor(bad,name,bad['Image'],job.LABEL,token)
 def test_source_drift_refuses_before_any_output(self):
  with tempfile.TemporaryDirectory(prefix='caa3-source-negative-') as d:
   root=Path(d);out=root/'not-created'
   # The first missing exact source file refuses before mkdir; no fallback source.
   with self.assertRaises((ValueError,OSError)):A.emit(root,out)
   self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(verbosity=2)
