"""Finite source/inert-transport controls; no accepting VM or fabricated boot."""
import argparse,copy,io,json,os,shutil,subprocess,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D,binding,kernel_input as K,runtime_adapter,entry
ROOT=D.ROOT
class Tests(unittest.TestCase):
 def test_actual_current_owner_preparer_and_lifecycle_compose(self):
  v=entry.source(ROOT);self.assertEqual(v['current_provider'],'a8e9_CAA3');self.assertEqual(v['native_owner_seams'],10);self.assertIn('transaction',v['original_lifecycle_bodies_held'])
 def test_default_boot_refuses_before_output_API_or_environment(self):
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   out=Path(td)/'out'
   # Exactly invert the explicitly selected boot DATA operands for this one
   # original NULL-default assertion; all source/custody assertions stay live.
   original=D.obj(D.read(ROOT/D.LANE/'input-policy.json'))
   if original['boot_decision']is None:
    with self.assertRaisesRegex(ValueError,'NULL'):binding.build(ROOT,out,{})
   else:
    with self.assertRaisesRegex(ValueError,'genuine first native'):binding.build(ROOT,out,{})
    null=dict(original,boot_decision=None,boot_projection=None)
    def read(path,*args):
     if Path(path)==ROOT/D.LANE/'input-policy.json':return D.encoded(null)
     return before(path,*args)
    before=D.read
    with patch.object(D,'read',side_effect=read):
     with self.assertRaisesRegex(ValueError,'NULL'):binding.boot(ROOT)
   self.assertFalse(out.exists())
 def test_real_Root_kernel20_provenance_and_whole_reader_source(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   k,v=K.known();self.assertEqual(len(k['members']),30);self.assertEqual(v['configuration'],dict(active_changes=14,delta=dict(bytes=1582,sha256='8e074cfb3bab7a59e876b2b80d73fbcd7d1832949f60fb4e10e933aaa828087d'),inactive_domain=189))
   with K.reader()as R:self.assertEqual(R.SOURCE,k['source']);self.assertEqual(R.RUN,k['run'])
 def test_selected_boot_exact_identity_and_no_mapping_credit(self):
  p=D.obj(D.read(ROOT/D.LANE/'input-policy.json'))
  if p['boot_decision']is None:
   with self.assertRaises(ValueError):binding.boot(ROOT)
  else:
   raw,projected=binding.boot(ROOT);v=D.obj(projected)
   self.assertEqual([v[n]for n in('verity_mapping','integrity','lifecycle')],['NOT_QUALIFIED']*3)
   import boot_binding
   k,_=K.known();result=D.read(ROOT/D.LANE/'Root-boot-strict.json')
   for data in(raw+b' ',D.encoded(dict(D.obj(raw),source='0'*40))):
    with self.assertRaises(ValueError):boot_binding.projection(data,result,k)
 def test_bootstrap_requires_fresh_writer_witness_not_prior_Root_literal(self):
  I=binding.runtime(ROOT);module=D.load('_immutable_writer_refusal',ROOT/'runtime/immutable/bootstrap_loader.py')
  for v in(None,dict(status='ROOT_VERIFIED_SOURCE_PRODUCERS_RETIRED',source='7d7ccbcb7b5a170999716ed640285806b7cab9bb'),{}):
   with self.assertRaises(ValueError):module.writer_retired(v)
  raw=D.read(ROOT/'runtime/immutable/bootstrap_loader.py');self.assertIn(b'data.replace(old,new)',raw);self.assertIn(b'writer_retired=writer_retired',raw)
 def test_fresh_writer_guard_requires_nonempty_actual_retired_reports(self):
  import pipeline,types
  v=dict(status='PASS_LIFECYCLE_PENDING_ORDERED_PRODUCER_CLEANUP',actors=[],commands=[])
  with patch.object(pipeline,'owner',return_value=types.SimpleNamespace(read=lambda p:v)):
   with self.assertRaisesRegex(ValueError,'writers retired'):pipeline.native_writer_retirement(ROOT,Path('/INERT'))
 def test_one_acquisition_intent_failure_no_retry_or_partial_reuse(self):
  with tempfile.TemporaryDirectory()as td:
   parent=Path(td);parent.chmod(0o700);out=parent/'acquire';calls=[]
   def fail(*a):calls.append(a[0]);raise OSError('INERT_NO_NETWORK')
   with self.assertRaises(OSError):K.acquire(out,fetch=fail,token='INERT')
   self.assertEqual(len(calls),1);self.assertTrue((out/'acquisition-failure.json').is_file());self.assertFalse((out/'artifact.zip').exists())
   with self.assertRaises(ValueError):K.acquire(out,fetch=lambda *a:self.fail('retry'),token='INERT')
 def test_foreign_read_endpoint_refuses_before_subprocess(self):
  with patch.object(subprocess,'run',side_effect=AssertionError('NO_API')):
   for endpoint in('https://foreign.invalid/data','repos/foreign/repo/actions/runs/39156901928','repos/Gabriel-Kahen/cachy-asahi/actions/artifacts/12147995918/zip'):
    with self.assertRaises(ValueError):K.get(endpoint,Path('/tmp/never-created'),1,1,'INERT')
 def test_partial_changed_fresh_API_never_reaches_artifact_download(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'acquire';calls=[]
   def bad(endpoint,path,*args):calls.append(endpoint);path.write_bytes(b'{}')
   with self.assertRaises((ValueError,KeyError)):K.acquire(out,fetch=bad,token='INERT')
   self.assertEqual(len(calls),2);self.assertFalse((out/'artifact.zip').exists())
 def test_missing_or_foreign_artifact_members_rejected_data_only(self):
  with K.reader()as R:
   for name in('Image','../Image','unapproved.py'):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w')as z:z.writestr(name,b'INERT_NOT_A_KERNEL')
    with self.assertRaises(ValueError):R.archive_files(b.getvalue())
 def test_typed_runtime_derivative_inverse_and_full_roles_held(self):
  p=D.obj(D.read(ROOT/D.LANE/'runtime-derivation.json'));basis=D.obj(D.read(ROOT/D.LANE/'runtime-basis.json',2*1024**2));self.assertEqual(p['basis_files'],667)
  for n,row in p['changed'].items():
   raw=D.read(ROOT/'runtime'/n,4*1024**2);self.assertEqual(D.pin(raw),row['after'])
   if type(row['inverse'])is list:
    for e in reversed(row['inverse']):self.assertEqual(raw.decode().count(e['new']),e['count']);raw=raw.replace(e['new'].encode(),e['old'].encode())
    self.assertEqual(D.pin(raw),row['before'])
  for n,v in basis.items():
   if n not in p['changed']:self.assertEqual(D.pin(D.read(ROOT/'runtime'/n,16*1024**2)),v)
 def test_closed_source_allows_only_topGit_metadata(self):
  with tempfile.TemporaryDirectory()as td:
   def top_metadata(folder,names):return {'.git'}if Path(folder)==ROOT else set()
   self.assertEqual(top_metadata(ROOT/'runtime',['.git']),set())
   root=Path(td)/'source';shutil.copytree(ROOT,root,ignore=top_metadata);(root/'.git').mkdir();(root/'.git/config').write_text('INERT_METADATA');D.source(root)
   (root/'.git/config').unlink();(root/'.git').rmdir();(root/'.git').write_text('gitdir: INERT_NOT_FOLLOWED');D.source(root)
   for extra in(root/'.git-shadow',root/'runtime/.git'):
    # A canonical runtime carrier clone already has registered nested Git metadata.
    if extra.is_dir():extra=extra/'INERT_UNEXPECTED'
    self.assertFalse(extra.exists())
    extra.write_text('INERT_UNEXPECTED')
    with self.assertRaises(ValueError):D.source(root)
    extra.unlink()
   (root/'extra').write_text('INERT')
   with self.assertRaises(ValueError):D.source(root)
   (root/'extra').unlink();(root/'alias').symlink_to(root/'runtime',target_is_directory=True)
   with self.assertRaises(ValueError):D.source(root)
 def test_exact_archive32_original_lock_profile(self):
  A=D.load('_immutable_archive32_test',ROOT/D.LANE/'archive32.py');v=A.policy(ROOT/D.LANE/'archive32-policy.json',ROOT/D.VM/'scripts/ci/maintained-desktop574-inputs.json');self.assertEqual(len(v['files']),32);self.assertEqual(sum(r['bytes']for r in v['files'].values()),209001064)
 def test_generated_workflow_source_gate_acquisition_and_seed_order(self):
  w=D.read(ROOT/'.github/workflows/native-arm-build.yml').decode();self.assertIn('  actions: read\n',w);self.assertIn('timeout-minutes: 360',w)
  names=('Whole source and maintained phase','Genuine independent boot','Acquire exact existing kernel20','Seed the six existing','Seed exact32 verified','Reuse unchanged owned574','Snapshot original574','Actual new-purpose immutable','Retire all new and native')
  positions=[w.index(n)for n in names];self.assertEqual(positions,sorted(positions));self.assertNotIn('rust6',w.lower());self.assertIn('2300s',w);self.assertIn('timeout-minutes: 220',w)
 def test_unknown_consumer_state_keeps_original_producer(self):
  import pipeline
  with tempfile.TemporaryDirectory()as td:
   out=Path(td);(out/'owner.json').write_text('{"consumer_cleanup":"UNKNOWN"}')
   a=argparse.Namespace(source=ROOT,output=out,proof=None,base=None,owner=None,receipt=None)
   with patch.object(pipeline,'owner',side_effect=AssertionError('NO_PRODUCER_CLEANUP')):
    with self.assertRaisesRegex(ValueError,'unknown new consumer'):pipeline.cleanup(a)

 def test_generated_checkout_source_is_separate_and_all_source_routes_match(self):
  import re
  w=D.read(ROOT/'.github/workflows/native-arm-build.yml').decode()
  self.assertIn('working-directory: immutable-source/runtime/runtime-vm',w)
  self.assertIn('ref: ${{ inputs.source_sha }}\n          path: immutable-source\n          persist-credentials: false',w)
  self.assertEqual(re.findall(r'--source "([^"\n]+)"',w),['$GITHUB_WORKSPACE/immutable-source']*9)
  for name in('SLICE','BUNDLE','DEPLOY'):
   line=next(v for v in w.splitlines()if v.strip().startswith(name+':'))
   self.assertIn('${{ github.workspace }}/immutable-source/',line)
  self.assertIn('"$GITHUB_WORKSPACE/immutable-source/runtime/immutable/test_controls.py"',w)
  self.assertIn('path: lifecycle-packet',w);self.assertIn('path: retained-public-inputs',w)
  self.assertIn('--packet-root "$GITHUB_WORKSPACE/lifecycle-packet"',w)
  self.assertIn('"$GITHUB_WORKSPACE/retained-public-inputs/seed.py"',w)
  cleanup=w[w.index('      - name: Retire all new'):w.index('      - name: Retain only closed')]
  self.assertIn('pipeline.py" cleanup --source "$GITHUB_WORKSPACE/immutable-source"',cleanup)
 def test_real_source_closure_after_both_sibling_checkouts_and_unknown_refusal(self):
  expected_files=D.source(ROOT)['files']
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   workspace=Path(td);root=workspace/'immutable-source'
   shutil.copytree(ROOT,root,ignore=lambda directory,names:{'.git'}if Path(directory)==ROOT else set())
   for name in('lifecycle-packet','retained-public-inputs'):
    sibling=workspace/name;sibling.mkdir();(sibling/'index.json').write_text('{"INERT":"NOT_A_PACKET"}');(sibling/'.git').mkdir();(sibling/'.git/config').write_text('INERT')
   legacy=workspace/'old-layout';shutil.copytree(ROOT,legacy,ignore=lambda directory,names:{'.git'}if Path(directory)==ROOT else set())
   for name in('lifecycle-packet','retained-public-inputs'):
    (legacy/name).mkdir();(legacy/name/'index.json').write_text('INERT_UNEXPECTED_CHECKOUT')
   with self.assertRaisesRegex(ValueError,'exact source closure'):D.source(legacy)
   self.assertEqual(D.source(root)['files'],expected_files)
   for name in('extra','lifecycle-packet'):
    (root/name).write_text('INERT_UNEXPECTED')
    with self.assertRaisesRegex(ValueError,'exact source closure'):D.source(root)
    (root/name).unlink()
   self.assertEqual(D.source(root)['files'],expected_files)
class MediaPreparationControls(unittest.TestCase):
 def modules(self):
  binding.runtime(ROOT)
  return D.load('_stage_callback_controls',ROOT/'runtime/immutable/stage.py'),D.load('_prepare_handoff_controls',ROOT/'runtime/immutable/native_prepare.py')
 def test_actual_recovery_function_sees_patched_command_and_original_guards(self):
  import types
  stage,prepare=self.modules();images=stage.original_images();recovery=images.prepare.__globals__['recovery'];self.assertIsInstance(recovery,types.ModuleType)
  dot=b'/2/040755/0/0/.//\n/2/040755/0/0/..//\n';lost=b'/11/040700/0/0/lost+found//\n';children=b'/11/040700/0/0/.//\n/2/040755/0/0/..//\n';calls=[];removed=False
  def command(argv,seconds):
   nonlocal removed
   self.assertEqual(seconds,60);calls.append([str(x)for x in argv])
   request=argv[-2]
   if request=='ls -p /':return dot if removed else dot+lost
   if request=='ls -p /lost+found':return children
   self.assertEqual(request,'rmdir /lost+found');removed=True;return b''
  with tempfile.TemporaryDirectory()as td:
   parent=Path(td);image=parent/'source.raw';image.write_bytes(b'INERT_ORDINARY_IMAGE_DATA');image.chmod(0o600)
   # Reproduce copied-namespace defect without any tool/image actor.
   copied=types.SimpleNamespace(**vars(recovery))
   with patch.object(copied,'command',command):
    with self.assertRaises(TypeError):copied.formatter_recovery_directory(image,{},parent)
   with patch.object(recovery,'command',command):recovery.formatter_recovery_directory(image,{},parent)
   self.assertEqual(len(calls),4);self.assertEqual(image.read_bytes(),b'INERT_ORDINARY_IMAGE_DATA');self.assertIsNone(recovery.command)
   with patch.object(recovery,'command',side_effect=AssertionError('no unsafe command')):
    with self.assertRaises(ValueError):recovery.formatter_recovery_directory(image,{'lost+found/foreign':{}},parent)
 def test_actual_owner_allocation_satisfies_unchanged_strict_media_handoff(self):
  import ast,types
  stage,prepare=self.modules()
  controller=D.load('_private_media_owner_allocation',ROOT/'runtime/immutable/native_controller.py')
  original=ROOT/'runtime/runtime-vm/scripts/ci/glibc-debian-maintained-installed16k/run.py'
  raw=D.read(original);derived,proof=controller.derive(raw);self.assertEqual(proof['seams'],10)
  def allocation(text,output):
   function=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='execute')
   start=next(i for i,n in enumerate(function.body)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and ast.unparse(n.value.func)=='args.output.mkdir')
   statements=function.body[start:start+6]
   self.assertEqual([ast.unparse(n)for n in statements[1::2]],["out = args.output", "disks.mkdir()"if text==raw.decode()else "disks.mkdir(mode=448)", "public.mkdir()"])
   scope=dict(args=types.SimpleNamespace(output=output));exec(compile(ast.Module(body=statements,type_ignores=[]),'<actual-owner-output-allocation>','exec'),scope);return scope['disks']
  for mask in(0o022,0o002,0o077):
   with self.subTest(umask=oct(mask)),tempfile.TemporaryDirectory()as td:
    parent=Path(td);previous=os.umask(mask)
    try:
     before=allocation(raw.decode(),parent/'before');after=allocation(derived,parent/'after')
    finally:os.umask(previous)
    self.assertEqual(after.stat().st_mode&0o777,0o700);self.assertEqual((after.stat().st_uid,after.stat().st_gid),(os.getuid(),os.getgid()))
    for directory in(before,after):
     media=directory/'immutable-media';media.mkdir(mode=0o700);drive=media/'source.hash';drive.write_bytes(b'PRIVATE_HASH_BYTES');drive.chmod(0o600)
    if mask!=0o077:
     self.assertNotEqual(before.stat().st_mode&0o777,0o700)
     with self.assertRaisesRegex(ValueError,'exact original private output owner'):prepare.media_handoff(before,os.getuid(),os.getgid())
    prepare.media_handoff(after,os.getuid(),os.getgid());self.assertEqual((after/'immutable-media/source.hash').read_bytes(),b'PRIVATE_HASH_BYTES');self.assertEqual((after/'immutable-media/source.hash').stat().st_mode&0o777,0o600)
 def test_real_private_media_handoff_keeps_child_contents_and_metadata(self):
  stage,prepare=self.modules()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);root.chmod(0o700);media=root/'immutable-media';media.mkdir(mode=0o700);p=media/'source.raw';p.write_bytes(b'PRIVATE_PARTIAL');p.chmod(0o600);before=p.stat();data=p.read_bytes()
   prepare.media_handoff(root,os.getuid(),os.getgid());after=p.stat()
   self.assertEqual(data,p.read_bytes());self.assertEqual((before.st_dev,before.st_ino,before.st_mode,before.st_nlink,before.st_size,before.st_mtime_ns),(after.st_dev,after.st_ino,after.st_mode,after.st_nlink,after.st_size,after.st_mtime_ns));self.assertEqual(media.stat().st_uid,root.stat().st_uid)
 def test_handoff_uses_exact_drive_fds_preserving0600_hash_and_JSON(self):
  stage,prepare=self.modules()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);root.chmod(0o700);media=root/'immutable-media';media.mkdir(mode=0o700)
   for name in ('source.raw','source.hash','source-image.json'):
    p=media/name;p.write_bytes(name.encode());p.chmod(0o600 if name=='source.hash'else 0o644)
   metadata=(media/'source-image.json').stat();calls=[];original=os.fchown
   def chown(fd,uid,gid):calls.append(os.fstat(fd).st_ino);return original(fd,uid,gid)
   with patch.object(os,'fchown',side_effect=chown):prepare.media_handoff(root,os.getuid(),os.getgid())
   self.assertEqual(calls,[(media/'source.raw').stat().st_ino,(media/'source.hash').stat().st_ino,media.stat().st_ino]);self.assertEqual((media/'source.hash').stat().st_mode&0o777,0o600);self.assertEqual((media/'source-image.json').stat(),metadata)
 def test_media_alias_hardlink_extras_and_wrong_owner_refuse(self):
  stage,prepare=self.modules()
  for kind in ('alias','hardlink','extra','directory','parent-alias','wrong-owner'):
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);root.chmod(0o700);media=root/'immutable-media';media.mkdir(mode=0o700);p=media/'source.raw';p.write_bytes(b'PRIVATE');p.chmod(0o600);uid=os.getuid();gid=os.getgid();target=root
    if kind=='alias':p.unlink();p.symlink_to(root/'other')
    if kind=='hardlink':os.link(p,root/'other')
    if kind=='extra':(media/'foreign').write_bytes(b'REFUSE')
    if kind=='directory':(media/'nested').mkdir()
    if kind=='parent-alias':target=root/'alias';target.symlink_to(root,target_is_directory=True)
    if kind=='wrong-owner':uid+=1
    with patch.object(os,'fchown',side_effect=AssertionError('must refuse before ownership mutation')):
     with self.assertRaises((ValueError,OSError)):prepare.media_handoff(target,uid,gid)
 def test_real_media_name_replacement_refuses_before_chown(self):
  stage,prepare=self.modules()
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);root.chmod(0o700);media=root/'immutable-media';media.mkdir(mode=0o700);p=media/'source.raw';p.write_bytes(b'PRIVATE');p.chmod(0o600);original=os.listdir;count=0
   def replace(fd):
    nonlocal count
    count+=1
    if count==2:media.rename(root/'replaced');media.mkdir(mode=0o700)
    return original(fd)
   with patch.object(os,'listdir',side_effect=replace),patch.object(os,'fchown',side_effect=AssertionError('wrong anchored name')):
    with self.assertRaises(ValueError):prepare.media_handoff(root,os.getuid(),os.getgid())
 def test_prepare_failure_handoff_preserves_error_and_NULL_refuses_first(self):
  stage,prepare=self.modules();policy=json.loads((ROOT/'runtime/immutable/policy.json').read_bytes());calls=[]
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):
   with self.assertRaisesRegex(ValueError,'NULL'):prepare.execute(policy)
  def fail():raise RuntimeError('INERT_PREPARE_FAILURE')
  with patch.object(prepare.runtime_policy,'gate'),patch.object(prepare,'load',return_value={'prepare':fail}),patch.object(prepare,'media_handoff',side_effect=lambda *a:calls.append(a)),patch.dict(os.environ,OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid())):
   with self.assertRaisesRegex(RuntimeError,'INERT_PREPARE_FAILURE'):prepare.execute(policy)
  self.assertEqual(calls,[(Path('/out'),os.getuid(),os.getgid())])


class Archive20ProducerControls(unittest.TestCase):
 def test_exact20_source_helpers_and_original32_held(self):
  self.assertEqual(D.pin(D.read(ROOT/D.LANE/'archive20.py')),dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'));self.assertEqual(D.pin(D.read(ROOT/D.LANE/'archive20-policy.json')),dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'))
  self.assertEqual(D.pin(D.read(ROOT/D.LANE/'archive32.py')),dict(bytes=11102,sha256='b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418'))
 def test_full20_prefetch_and_seed_before_unchanged_producer(self):
  import pipeline
  w=D.read(ROOT/D.LANE/'workflow.yml.in').decode();self.assertLess(w.index('Prefetch exact20'),w.index('Seed the six existing private'));self.assertLess(w.index('Seed exact20 verified'),w.index('Reuse unchanged owned574 native producer'))
  self.assertIn('"$DEPLOY/archive20.py" --policy "$DEPLOY/archive20-policy.json"',w);self.assertIn('--cache "$RUNNER_TEMP/immutable-archive20"',w);self.assertIn('seed-archive20 --source "$GITHUB_WORKSPACE/immutable-source"',w)
  import inspect
  source=inspect.getsource(pipeline.seed_archive20);self.assertIn("producer/'context/deps'",source);self.assertIn('h.seed_exact(cache',source)


class Archive8ProducerControls(unittest.TestCase):
 def test_exact8_source_helpers_and_prior20_held(self):
  self.assertEqual(D.pin(D.read(ROOT/D.LANE/'archive8.py')),dict(bytes=11040,sha256='5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565'));self.assertEqual(D.pin(D.read(ROOT/D.LANE/'archive8-policy.json')),dict(bytes=2589,sha256='2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20'))
  self.assertEqual(D.pin(D.read(ROOT/D.LANE/'archive20.py')),dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'))
 def test_full8_prefetch_seed_after20_before_original_producer(self):
  import pipeline
  w=D.read(ROOT/D.LANE/'workflow.yml.in').decode();self.assertLess(w.index('Prefetch exact20'),w.index('Prefetch exact8'));self.assertLess(w.index('Prefetch exact8'),w.index('Seed the six existing private'));self.assertLess(w.index('Seed exact20 verified'),w.index('Seed exact8 verified'));self.assertLess(w.index('Seed exact8 verified'),w.index('Reuse unchanged owned574 native producer'))
  self.assertIn('"$DEPLOY/archive8.py" --policy "$DEPLOY/archive8-policy.json"',w);self.assertIn('--cache "$RUNNER_TEMP/immutable-archive8"',w);self.assertIn('seed-archive8 --source "$GITHUB_WORKSPACE/immutable-source"',w)
  import inspect
  source=inspect.getsource(pipeline.seed_archive8);self.assertIn("producer/'context/deps'",source);self.assertIn('h.seed_exact(cache',source)


class DMLookupControls(unittest.TestCase):
 """Inert ioctl-structure controls only; no kernel DM, mount, block or VM actor."""
 def api(self):
  import ast,ctypes,fcntl,stat,types
  I=binding.runtime(ROOT);R=I.broker()[1].reader();path=ROOT/'runtime/gnu-verity-bootstrap-development-20261018/dm.py';raw=path.read_bytes();space=dict(__name__='_inert_dm_structure',__file__=str(path),need=D.need,Header=R.Header,Target=R.Target,validate_table=R.validate_table,kernel_table=lambda *a:self.fail('NO_ACTUAL_DM_TABLE'))
  for anchor in(b'from common import need\n',b'from borrowed.reader import Header,Target,validate_table,kernel_table\n'):self.assertEqual(raw.count(anchor),1);raw=raw.replace(anchor,b'')
  M=types.ModuleType('_inert_dm_structure');vars(M).update(space);exec(compile(raw,str(path),'exec'),vars(M));obj=M.Device.__new__(M.Device);obj.name=M.NAME;obj.uuid='CAA-GNU-VERITY-'+'a'*32;obj.dev=None;obj.created=False;return M,obj,R
 def invoke(self,M,obj,cmd,*,foreign=None,bad=None):
  import ctypes,errno,stat,types
  events=[];closed=[];gates=[];dev=os.makedev(253,7);mapping=dict(name=obj.name,uuid=obj.uuid,dev=dev)
  if foreign:mapping.update(foreign)
  def kernel(fd,op,raw,mutate):
   self.assertEqual((fd,mutate),(73,True));h=M.Header.from_buffer(raw);number=op&255;events.append(dict(cmd=number,name=bytes(h.name),uuid=bytes(h.uuid),dev=h.dev))
   # Linux v6.18.20 validate_params and __find_device_hash_cell semantics:
   # CREATE accepts name+UUID; every lookup accepts exactly one identifier.
   if number==3:
    if not bytes(h.name):raise OSError(errno.EINVAL,'inert kernel CREATE name required')
    h.dev=dev
   else:
    if sum(bool(v)for v in(bytes(h.name),bytes(h.uuid),h.dev))!=1:raise OSError(errno.EINVAL,'inert kernel exclusive lookup identifier')
    if h.dev!=mapping['dev']:raise OSError(errno.ENXIO,'inert kernel no mapping')
    h.name=mapping['name'].encode();h.uuid=mapping['uuid'].encode()
   if bad=='version':h.version[0]=5
   if bad=='buffer':h.flags|=M.BUFFER_FULL
   if bad=='device':h.dev=dev+1
  info=types.SimpleNamespace(st_mode=stat.S_IFCHR|0o600,st_rdev=os.makedev(10,236)if bad!='control'else 0)
  def opening(path,flags):self.assertEqual(path,'/dev/mapper/control');return 73
  with patch.object(M,'pid1',side_effect=lambda:gates.append(True)),patch.object(M.os,'open',side_effect=opening),patch.object(M.os,'fstat',return_value=info),patch.object(M.os,'close',side_effect=lambda fd:closed.append(fd)),patch.object(M.fcntl,'ioctl',side_effect=kernel):
   try:result=obj.request(cmd)
   except BaseException as e:e.inert_events=events;raise
  self.assertEqual(closed,[73]*len(events));self.assertGreaterEqual(len(gates),len(events));return result,events
 def test_create_metadata_then_exclusive_device_lookup_for_all_commands(self):
  M,obj,R=self.api();dev,events=self.invoke(M,obj,3);self.assertEqual(events,[dict(cmd=3,name=obj.name.encode(),uuid=obj.uuid.encode(),dev=0)]);obj.dev=dev;obj.created=True
  for cmd in(4,6,7,9,12):
   result,events=self.invoke(M,obj,cmd);self.assertEqual(result,dev);self.assertEqual([r['cmd']for r in events],[7,cmd]if cmd in(4,6,9)else[cmd]);self.assertTrue(all(r['name']==r['uuid']==b''and r['dev']==dev for r in events))
 def test_foreign_mapping_refused_before_any_mutating_ioctl(self):
  for field,bad in(('name','FOREIGN'),('uuid','FOREIGN')):
   for cmd in(4,6,9):
    M,obj,R=self.api();obj.dev=os.makedev(253,7);obj.created=True
    with self.assertRaisesRegex(ValueError,'foreign mapping')as caught:self.invoke(M,obj,cmd,foreign={field:bad})
    self.assertEqual([r['cmd']for r in caught.exception.inert_events],[7])
 def test_bad_control_response_version_capacity_and_device_refuse(self):
  for bad in('control','version','buffer','device'):
   M,obj,R=self.api();obj.dev=os.makedev(253,7);obj.created=True
   with self.assertRaises(ValueError):self.invoke(M,obj,9,bad=bad)
 def test_uncreated_or_invalid_command_refuses_before_control_open(self):
  M,obj,R=self.api()
  with patch.object(M,'pid1'),patch.object(M.os,'open',side_effect=AssertionError('NO_DM_OPEN')):
   for cmd in(4,6,7,9,12):
    with self.assertRaises(ValueError):obj.request(cmd)
   for cmd in(0,1,5,8,13):
    with self.assertRaises(ValueError):obj.request(cmd)
 def test_original_pid1_16k_and_verity_backing_checks_remain(self):
  M,obj,R=self.api();text=(ROOT/'runtime/gnu-verity-bootstrap-development-20261018/dm.py').read_text();tree=__import__('ast').parse(text)
  f=lambda name:__import__('ast').get_source_segment(text,next(n for n in __import__('ast').walk(tree)if isinstance(n,__import__('ast').FunctionDef)and n.name==name))
  self.assertIn("os.getpid()==1",f('pid1'));self.assertIn("os.sysconf('SC_PAGE_SIZE')==16384",f('pid1'));self.assertIn("'exact selected backing devices, not foreign target'",f('create'));self.assertIn('kernel_table(self.dev)',f('create'));self.assertIn("need(self.created,'only owned created mapping removed')",f('remove'))
 def test_closed_fail_without_nonce_still_refuses_with_genuine_error(self):
  import ast,types
  path=ROOT/'runtime/immutable/native_controller.py';text=path.read_text();f=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='protocol');space=dict(P=types.SimpleNamespace(need=D.need,decode=D.obj),json=json);exec(compile(ast.get_source_segment(text,f),str(path),'exec'),space)
  failure=dict(cleanup='NOT_ACCEPTED_UNKNOWN_STATE_RETAIN_BACKING_FILES',error='[Errno 22] Invalid argument',error_type='OSError',purpose='GNU_IMMUTABLE_RUNTIME_V1',status='FAIL')
  with self.assertRaisesRegex(ValueError,'guest FAIL DATA only.*OSError'):space['protocol']((json.dumps(failure)+'\n').encode(),{})
  for bad in(dict(failure,nonce='a'*32),dict(failure,error='x'*4097),dict(failure,cleanup='PASS')):
   with self.assertRaises(ValueError):space['protocol']((json.dumps(bad)+'\n').encode(),{})



# Fixed diagnostic DATA only; these controls grant no native authority.
import ast,types
PHASE_LABELS=(b'OBSERVE_BEGIN', b'OBSERVE_END', b'OBSERVE_FAIL', b'CAPABILITIES_BEGIN', b'CAPABILITIES_END', b'CAPABILITIES_FAIL', b'SELECTED_LINKS_BEGIN', b'SELECTED_LINKS_END', b'SELECTED_LINKS_FAIL', b'AUXILIARY_1_BEGIN', b'AUXILIARY_1_END', b'AUXILIARY_1_FAIL', b'AUXILIARY_2_BEGIN', b'AUXILIARY_2_END', b'AUXILIARY_2_FAIL', b'LIFECYCLE_BEGIN', b'LIFECYCLE_END', b'LIFECYCLE_FAIL', b'READBACK_BEGIN', b'READBACK_END', b'READBACK_FAIL', b'CLEANUP_BEGIN', b'CLEANUP_END', b'CLEANUP_FAIL')
def marker(node):
 return isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and len(node.value.args)in(1,2) and isinstance(node.value.args[0],ast.Constant)and node.value.args[0].value in PHASE_LABELS and (isinstance(node.value.func,ast.Name)and node.value.func.id=='_phase'or isinstance(node.value.func,ast.Subscript)and isinstance(node.value.func.value,ast.Name)and node.value.func.value.id=='api'and isinstance(node.value.func.slice,ast.Constant)and node.value.func.slice.value=='_phase')
def strip(tree):
 class Strip(ast.NodeTransformer):
  def visit_Module(self,node):
   node.body=[n for n in node.body if not(isinstance(n,ast.Import)and any(a.asname=='_phase_os'for a in n.names))and not(isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in('_PHASE_LABELS','_PHASE_ROOT_TYPE')for t in n.targets))and not(isinstance(n,ast.FunctionDef)and n.name=='_phase')];return self.generic_visit(node)
  def visit_Expr(self,node):return None if marker(node)else self.generic_visit(node)
  def visit_Try(self,node):
   if len(node.handlers)==1 and len(node.handlers[0].body)==2 and isinstance(node.handlers[0].body[0],ast.Try)and marker(node.handlers[0].body[0].body[0])and isinstance(node.handlers[0].body[1],ast.Raise):
    return [self.visit(n)for n in node.body]
   return self.generic_visit(node)
 return Strip().visit(copy.deepcopy(tree))
def module(raw):
 tree=ast.parse(raw);body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('raw_maps','observe','_phase')or isinstance(n,ast.Import)and any(a.asname=='_phase_os'for a in n.names)or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in('_PHASE_LABELS','_PHASE_ROOT_TYPE')for t in n.targets)];namespace=dict(__name__='_gnu_broker_original_snapshot',C=types.SimpleNamespace(need=D.need),Path=Path);exec(compile(ast.Module(body=body,type_ignores=[]),'<trusted-source-diagnostic-unit-only>','exec'),namespace);return namespace
class PhaseDiagnosticControls(unittest.TestCase):
 def test_whole_action_guard_budget_AST_strip_only(self):
  self.assertEqual(len(runtime_adapter.PHASE_RULES),3)
  for row in runtime_adapter.PHASE_RULES.values():self.assertEqual(ast.dump(strip(ast.parse(row["after"]))),ast.dump(ast.parse(row["before"])))
 def operation(self,raw,failure=None,write=None,root=Path('/held')):
   namespace=module(raw);actions=[];observation=dict(complete=True,nodes={});limits=object()
   def observe(*args,**kw):actions.append(('full_observe',args[0],kw));return observation
   def caps(*args):actions.append(('fresh_capabilities',args));return ({},{})
   def links(*args):actions.append(('selected_links',args))
   def aux(*args):actions.append(('fresh_auxiliary',args))
   methods=dict(full_root=types.SimpleNamespace(observe=observe),file_capabilities=types.SimpleNamespace(_scan=caps),root_link_selection=types.SimpleNamespace(check=links),aux_checkpoint=types.SimpleNamespace(checkpoint=aux))
   if failure:
    def bad(*a,**kw):raise failure
    methods['file_capabilities']._scan=bad
   with patch.object(os,'write',side_effect=write or(lambda fd,data:len(data))):return namespace['observe'](methods,root,limits),actions
 def test_original_actions_and_return_unchanged(self):
   old=runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['before'].encode();new=runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['after'].encode();a,actions=self.operation(old);writes=[];b,other=self.operation(new,write=lambda fd,data:writes.append((fd,data))or len(data));self.assertEqual(a,b);self.assertEqual([x[0]for x in actions],[x[0]for x in other]);self.assertEqual([data for fd,data in writes],[b'GNU_PHASE_DATA '+(p+'_'+s).encode()+b'\n'for p in('OBSERVE','CAPABILITIES','SELECTED_LINKS','AUXILIARY_1')for s in('BEGIN','END')]);self.assertTrue(all(fd==2 for fd,_ in writes))
 def test_action_exception_and_cancellation_objects_reraised(self):
   raw=runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['after'].encode()
   for error in(ValueError('original-action-error'),KeyboardInterrupt('original-cancel'),SystemExit(8)):
    with self.subTest(error=type(error).__name__),self.assertRaises(type(error))as caught:self.operation(raw,failure=error)
    self.assertIs(caught.exception,error)
 def test_failure_marker_never_replaces_existing_exception(self):
   raw=runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['after'].encode();error=ValueError('ORIGINAL')
   def write(fd,data):
    if data.endswith(b'CAPABILITIES_FAIL\n'):raise KeyboardInterrupt('diagnostic-only-failure')
    return len(data)
   with self.assertRaises(ValueError)as caught:self.operation(raw,failure=error,write=write)
   self.assertIs(caught.exception,error)
 def test_write_oserror_has_no_action_effect_or_retry(self):
   raw=runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['after'].encode();attempts=[]
   def write(fd,data):attempts.append(data);raise OSError('DIAGNOSTIC_LOSS')
   result,actions=self.operation(raw,write=write);self.assertTrue(result['observation']['complete']);self.assertEqual(len(attempts),8);self.assertEqual(len(actions),4)
 def test_finite_payloads_no_identity_path_time_or_per_node_counter(self):
   raw=runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['after'].encode();namespace=module(raw);writes=[]
   with patch.object(os,'write',side_effect=lambda fd,b:writes.append(b)or len(b)):
    for value in PHASE_LABELS:namespace['_phase'](value)
    namespace['_phase'](b'UNKNOWN');namespace['_phase'](b'/private/path')
   for value in PHASE_LABELS:namespace['_phase'](value,Path('/work/private-fixture'))
   class Foreign:
    def __str__(self):raise AssertionError('NO_USER_DEFINED_CONVERSION')
    def __eq__(self,other):raise AssertionError('NO_USER_DEFINED_EQUALITY')
   for value in PHASE_LABELS:namespace['_phase'](value,Foreign())
   self.assertEqual(len(writes),24);self.assertTrue(all(len(b)<=64 and b.startswith(b'GNU_PHASE_DATA ')and not b.startswith(b'{')for b in writes));self.assertLessEqual(sum(map(len,writes)),1536)
   quiet=[];result,actions=self.operation(raw,root=Path('/work/private-fixture'),write=lambda fd,b:quiet.append(b)or len(b));self.assertEqual(quiet,[]);self.assertTrue(result['observation']['complete']);self.assertEqual(len(actions),4)

# Explicit1200 TEST validation profile; unchanged original phase controls above.
class ColdValidationProfileControls(unittest.TestCase):
 def test_two_exact_profile_derivatives_and_entire_inverse(self):
  names=('immutable/owner.py','immutable/native_controller.py')
  before={names[0]:runtime_adapter.PHASE_RULES[names[0]]['after'].encode(),names[1]:(ROOT/'runtime'/names[1]).read_bytes()}
  # Native-controller source is already derived; recover only this new guard.
  marker=" P.need(v.get('cold_validation')=="+repr(runtime_adapter.COLD_VALIDATION_PROFILE)+",'exact explicit1200 cold-validation TEST profile; no600-fit claim')\n"
  before[names[1]]=before[names[1]].replace(marker.encode(),b'')
  for name in names:
   raw=before[name];new,edits=runtime_adapter.cold_profile_derivative(raw,name);restored=new.decode()
   for edit in reversed(edits):self.assertEqual(restored.count(edit['new']),1);restored=restored.replace(edit['new'],edit['old'])
   self.assertEqual(restored.encode(),raw)
   with self.assertRaises(ValueError):runtime_adapter.cold_profile_derivative(new,name)
 def test_explicit_profile_real_clock_arithmetic_shared_outer_ceilings(self):
  import time
  text=(ROOT/'runtime/immutable/owner.py').read_text();tree=ast.parse(text);profile=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='COLD_VALIDATION_PROFILE'for t in n.targets));self.assertEqual(profile,runtime_adapter.COLD_VALIDATION_PROFILE)
  self.assertEqual(profile,dict(name='GNU_GENERIC16K_COLD_VALIDATION_1200_V1',seconds=1200,shared_owner_ceiling=10500,qemu_ceiling=10800,fit_600='NOT_ESTABLISHED'))
  call=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Limits');expr=next(k.value for k in call.keywords if k.arg=='deadline');code=compile(ast.Expression(expr),'<exact-source-cold-deadline>','eval')
  for remaining in(-1,30,10500):
   started=time.monotonic();outer=started+remaining;result=eval(code,dict(deadline=outer,time=time,COLD_VALIDATION_PROFILE=profile));after=time.monotonic();self.assertLessEqual(result,outer);self.assertTrue(result==outer or started+1200<=result<=after+1200)
  self.assertIn('deadline = started + 10500',text);self.assertIn('seconds = int(deadline - time.monotonic())',text);self.assertIn('0 < seconds <= 10500',text)
 def test_all_fresh_validation_and_both_auxiliary_calls_byte_held(self):
  snapshot=(ROOT/'runtime/gnu-verity-bootstrap-development-20261018/source_snapshot.py').read_bytes();self.assertEqual(snapshot,runtime_adapter.PHASE_RULES['gnu-verity-bootstrap-development-20261018/source_snapshot.py']['after'].encode())
  context=(ROOT/'runtime/gnu-immutable-source-broker-development-20261018/context.py').read_bytes();self.assertEqual(context,runtime_adapter.PHASE_RULES['gnu-immutable-source-broker-development-20261018/context.py']['after'].encode())
  self.assertEqual(snapshot.count(b"modules['aux_checkpoint'].checkpoint("),1);self.assertEqual(context.count(b"modules['aux_checkpoint'].checkpoint("),1)
 def test_old_or_missing_profile_never_enters_positive_protocol(self):
  import types
  raw=(ROOT/'runtime/immutable/native_controller.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='protocol');space=dict(P=types.SimpleNamespace(need=D.need,decode=D.obj),json=json);exec(compile(ast.get_source_segment(raw,node),'<trusted-source-protocol-refusal-only>','exec'),space)
  for value in({},dict(cold_validation=dict(runtime_adapter.COLD_VALIDATION_PROFILE,seconds=600))):
   with self.assertRaisesRegex(ValueError,'explicit1200'):space['protocol']((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode(),{})

# Complete real graph regression; these owned files carry no VM/native authority.
class GraphDiagnostics(unittest.TestCase):
 def test_real_reverse_creation_full_projection_not_sorted_sample(self):
  saved=dict(sys.modules);paths=list(sys.path)
  try:
   for name in('inputs','map_join','protocol','context','client','broker'):sys.modules.pop(name,None)
   sys.path.insert(0,str(ROOT/'runtime/immutable'))
   import inputs,map_join,time,types
   api,modules=inputs.broker()[1].source_api();F=modules['full_root']
   def snapshot(root):
    value=api['raw_maps'](modules,root,F.Limits(deadline=time.monotonic()+30,max_nodes=1000,max_bytes=1024**2,max_file_bytes=65536));value['auxiliary']={n:{}for n in('helper','configs','aliases','scan','targets','caches')};value['auxiliary'].update(main_bytes=b'INERT_NOT574',aux_bytes=b'INERT_AUX_NOT574',closure=(),scan_directories=());return value
   with tempfile.TemporaryDirectory()as td:
    roots=[Path(td)/n for n in('a','b')]
    for root,order in zip(roots,(range(90),reversed(range(90)))):
     root.mkdir()
     for n in order:(root/('absolute%03d'%n)).symlink_to('/INERT_NOT574')
     (root/'relative').symlink_to('absolute000');(root/'cycle').symlink_to('cycle');(root/'escape').symlink_to('../escape')
     for p in(*root.iterdir(),root):os.utime(p,ns=(1000000000,1000000000),follow_symlinks=False)
    # ext4 hash directories need not preserve creation order. Only this unit
    # control orders REAL DirEntry objects; production observe is untouched.
    import contextlib
    real_scandir=F.os.scandir
    @contextlib.contextmanager
    def ordered(directory,reverse):
     with real_scandir(directory)as entries:
      yield iter(sorted(entries,key=lambda entry:entry.name,reverse=reverse))
    with patch.object(F.os,'scandir',side_effect=lambda directory:ordered(directory,False)):a=snapshot(roots[0])
    with patch.object(F.os,'scandir',side_effect=lambda directory:ordered(directory,True)):b=snapshot(roots[1])
    self.assertEqual(a['nodes'],b['nodes']);self.assertNotEqual(a['observation']['unsupported'],b['observation']['unsupported']);before=copy.deepcopy((a,b));self.assertEqual(map_join.join(a,b)['nodes'],93);self.assertEqual((a,b),before);self.assertEqual(len(map_join.diagnostics(a)),93)
    raw=(ROOT/'runtime/immutable/map_join.py').read_text();old=raw.replace(runtime_adapter.GRAPH_REPLACEMENT,runtime_adapter.GRAPH_ANCHOR,1).replace(runtime_adapter.GRAPH_DIAGNOSTICS,'',1);self.assertEqual(D.pin(old.encode()),dict(bytes=6281,sha256='d918ed1faef7a9b31b0085eae464eeca7d2481bed13fcc0f977b30c7aa4a83b3'));prior=types.ModuleType('_graph_original');exec(compile(old,'<whole-pinned-original-map-join>','exec'),vars(prior))
    with self.assertRaisesRegex(ValueError,'complete original observation field unsupported'):prior.join(a,b)
    P=inputs.broker()[0];wire=P.unpack(P.decode(P.encode(P.pack(a))));self.assertEqual(map_join.join(wire,b)['nodes'],93)
    for change in(lambda v:v['observation']['unsupported'][0].__setitem__('path','FOREIGN'),lambda v:v['observation']['unsupported'].pop(),lambda v:v['observation']['unsupported_counts'].__setitem__('absolute-symlink',90),lambda v:v['observation'].__setitem__('eligible',True)):
     value=copy.deepcopy(b);change(value)
     with self.assertRaises(ValueError):map_join.join(a,value)
  finally:
   sys.path[:]=paths
   for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
   sys.modules.update(saved)


class WorkerValidationControls(unittest.TestCase):
 def helpers(self):
  import dataclasses,time
  text=(ROOT/'runtime/immutable/worker_api.py').read_text();tree=ast.parse(text);names={'WORKER_VALIDATION_PROFILE','_VALIDATION_LABELS','_validation_writes','validation_failure','validation_limits','install_validation'}
  nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in names for t in n.targets)]
  space=dict(P=types.SimpleNamespace(need=D.need),Path=Path,os=os,types=types);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<whole-source-worker-profile>','exec'),space)
  guest_path=ROOT/D.VM/'scripts/ci/glibc-debian-maintained-installed16k/guest.py';raw=guest_path.read_text();function=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='_copy_context_limits');old={};exec(compile(ast.get_source_segment(raw,function),str(guest_path),'exec'),old)
  @dataclasses.dataclass
  class Limits:
   deadline:float
   max_nodes:int=500000
   def tick(self):
    if time.monotonic()>=self.deadline:raise ValueError('root observation deadline')
  return space,types.SimpleNamespace(__file__=str(guest_path),_copy_context_limits=old['_copy_context_limits']),Limits
 def test_real_source_profile_arithmetic_and_original600_refusal(self):
  import time
  s,g,Limits=self.helpers()
  with patch.object(time,'monotonic',return_value=100):
   with self.assertRaisesRegex(ValueError,'fresh bounded'):g._copy_context_limits(Limits(1300))
   value=s['validation_limits'](g,Limits(1300));self.assertEqual(value.deadline,4900);self.assertEqual(value.max_nodes,500000)
  with patch.object(time,'monotonic',return_value=4900),self.assertRaisesRegex(ValueError,'root observation deadline'):value.tick()
 def test_real_source_window1200_and_same_exception(self):
  import time
  s,g,Limits=self.helpers();now=[100.0]
  with patch.object(time,'monotonic',side_effect=lambda:now[0]),patch.object(os,'write',return_value=1):
   value=s['validation_limits'](g,Limits(1300));error=KeyboardInterrupt('original')
   def original(**kw):now[0]=1299;value.tick();raise error
   with self.assertRaises(KeyboardInterrupt)as caught:value._copy_observe(original,limits=value)
   self.assertIs(caught.exception,error)
   now[0]=100
   def deadline(**kw):now[0]=1300;value.tick()
   with self.assertRaisesRegex(ValueError,'root observation deadline'):value._copy_observe(deadline,limits=value)
 def test_original_snapshot_function_operands_and_explicit_product_limit(self):
  s,_,_=self.helpers();calls=[];error=ValueError('original')
  def snapshot(*a):calls.append(a);raise error
  m=types.SimpleNamespace(limits=lambda api,seconds=600:seconds,snapshot=snapshot);s['install_validation'](m);self.assertEqual(m.limits(None),1200);self.assertEqual(m.limits(None,120),120)
  with patch.object(os,'write',side_effect=OSError('lost')),self.assertRaises(ValueError)as caught:m.snapshot('api','root','pristine-clone')
  self.assertIs(caught.exception,error);self.assertEqual(calls,[('api','root','pristine-clone')])
 def test_failure_relay_finite_literals_cap_partial_and_write_failure(self):
  raw=(ROOT/'runtime/immutable/owner.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='relay_worker_failure');space=dict(os=os);exec(compile(ast.get_source_segment(raw,node),'<source-owned-failure-relay>','exec'),space);writes=[];valid=b'GNU_WORKER_FAILURE_DATA COPY_COPY_DATA\n'
  with patch.object(os,'write',side_effect=lambda fd,b:writes.append(b)or len(b)):
   space['relay_worker_failure'](valid*100);space['relay_worker_failure'](b'GNU_WORKER_FAILURE_DATA /private/path\n');space['relay_worker_failure'](valid[:-1]);space['relay_worker_failure'](valid*(512*1024//len(valid)+1))
  self.assertEqual(writes,[valid]*8)
  with patch.object(os,'write',side_effect=KeyboardInterrupt('lost')):space['relay_worker_failure'](valid)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=D.ROOT);a,rest=p.parse_known_args();ROOT=a.source.absolute();unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
