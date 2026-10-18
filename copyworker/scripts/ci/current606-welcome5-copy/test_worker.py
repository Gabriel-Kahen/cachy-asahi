# SPDX-License-Identifier: MIT
import copy,hashlib,os,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path[:0]=[str(HERE),str(ROOT/'held-copy/scripts/update'),str(ROOT/'held-copy/scripts/apps')]
import contract as C,guard as G,rooted_fixture as F
import full_root as R,aux_copy,disposable_copy,file_capabilities as caps,full574_copy as scope

class Controls(unittest.TestCase):
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)
 def test_default_refuses_before_any_actor_or_copy(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'UNSUPPLIED'):C.authority(C.decode(C.ordinary(HERE/'input-policy.json')),'copy-worker8','0'*32)
 def test_real_complete_private_copy_hardlinks_caps_and_disposal(self):
  with tempfile.TemporaryDirectory()as d:
   source=Path(d)/'source';source.mkdir();(source/'dir').mkdir();(source/'dir/a').write_bytes(b'real private fixture\n');os.link(source/'dir/a',source/'dir/b');(source/'alias').symlink_to('dir/a')
   before=R.observe(source,limits=self.budget(),hardlinks='generic-development-internal');original=caps.observe(source,before['nodes'],self.budget())
   with disposable_copy.copied_root(source,Path(d)/'owned',limits=self.budget())as(target,report):
    after=R.observe(target,limits=self.budget(),hardlinks='generic-development-internal')
    self.assertEqual(after['nodes'],before['nodes']);self.assertEqual((target/'dir/a').stat().st_ino,(target/'dir/b').stat().st_ino)
    self.assertEqual(caps.restore(target,after['nodes'],original,self.budget()),original)
   self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed');self.assertFalse((Path(d)/'owned').exists());G.same_source(before,R.observe(source,limits=self.budget(),hardlinks='generic-development-internal'))
 def test_real_failure_disposes_private_copy_preserves_source(self):
  with tempfile.TemporaryDirectory()as d:
   source=Path(d)/'source';source.mkdir();(source/'data').write_bytes(b'held')
   with self.assertRaisesRegex(RuntimeError,'fixture failure'):
    with disposable_copy.copied_root(source,Path(d)/'owned',limits=self.budget())as(target,report):
     (target/'data').write_bytes(b'changed');raise RuntimeError('fixture failure')
   self.assertEqual((source/'data').read_bytes(),b'held');self.assertFalse((Path(d)/'owned').exists());self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed')
 def test_unknown_xattr_refuses_before_restore(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'file').write_bytes(b'held');before=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal')
   os.setxattr(root/'file','user.unrecognized',b'not accepted')
   with self.assertRaisesRegex(ValueError,'unknown xattr'):caps.observe(root,before['nodes'],self.budget())
   self.assertEqual(os.getxattr(root/'file','user.unrecognized'),b'not accepted')
 def test_real_source_metadata_and_content_refusals(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'file').write_bytes(b'held');a=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');(root/'file').write_bytes(b'edit')
   with self.assertRaisesRegex(ValueError,'source graph'):G.same_source(a,R.observe(root,limits=self.budget(),hardlinks='generic-development-internal'))
 def test_selected_real_route_refuses_inert_fixture(self):
  with tempfile.TemporaryDirectory()as d:
   source=Path(d)/'source';source.mkdir();(source/'file').write_bytes(b'inert')
   with self.assertRaisesRegex(ValueError,'selected-literal-link-drift'):
    with aux_copy.copied_root(source,Path(d)/'owned',limits=self.budget()):pass
   self.assertFalse((Path(d)/'owned').exists())
 def test_dynamic_capacity_only_two_counters(self):
  a=dict(complete=True,nodes={},unsupported=[],unsupported_counts={},footprint=dict(filesystem_free_bytes=1,filesystem_free_inodes=2,bytes=0));b=copy.deepcopy(a);b['footprint'].update(filesystem_free_bytes=100,filesystem_free_inodes=20);G.same_source(a,b)
  b['footprint']['bytes']=1
  with self.assertRaises(ValueError):G.same_source(a,b)
 def test_selected_inventory_is_exact_other605(self):
  base={f'p{i}':'1'for i in range(605)}|{G.NAME:'0.1.0-4'};G.inventory(base|{G.NAME:'0.1.0-5'},base,'0.1.0-5');G.inventory({k:v for k,v in base.items()if k!=G.NAME},base,None)
  with self.assertRaises(ValueError):G.inventory(base|{'p4':'2',G.NAME:'0.1.0-5'},base,'0.1.0-5')
 def test_selected_target_preserves_every_other_row_and_raw_db(self):
  node=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='0'*64)
  before=dict(complete=True,unsupported_counts={},nodes={'usr/bin/welcome':node,'var/lib/pacman/local/other-1/desc':node,'home/alarm/.config/user':node},hardlink_groups={})
  after=copy.deepcopy(before);after['nodes']['usr/bin/welcome']=dict(node,sha256='1'*64)
  args=dict(old_paths=['usr/bin/welcome'],new_paths=['usr/bin/welcome'],old_database='var/lib/pacman/local/cachy-asahi-welcome-0.1.0-4',new_database='var/lib/pacman/local/cachy-asahi-welcome-0.1.0-5')
  G.target(before,after,**args)
  after['nodes']['var/lib/pacman/local/other-1/desc']=dict(node,sha256='2'*64)
  with self.assertRaises(ValueError):G.target(before,after,**args)
 def test_selected_cross_hardlink_refused(self):
  v=dict(complete=True,unsupported_counts={},nodes={},hardlink_groups={'usr/bin/welcome':dict(members=['usr/bin/welcome','usr/bin/protected'])})
  with self.assertRaisesRegex(ValueError,'cross hardlink'):G.target(v,v,old_paths=['usr/bin/welcome'],new_paths=['usr/bin/welcome'],old_database=None,new_database=None)
 def test_exact_new_cap_profile_and_zero_ordinary(self):
  v=dict(CapEff=C.WORKER_MASK,CapPrm=C.WORKER_MASK,CapBnd=C.WORKER_MASK,CapInh=0,CapAmb=0,NoNewPrivs=1,uid=0,gid=0);C.capability_profile(v)
  for mask in(0xdb,0x400db,0xffffffffffffffff):
   with self.assertRaises(ValueError):C.capability_profile(dict(v,CapEff=mask))
  C.capability_profile(dict(v,CapEff=0,CapPrm=0,uid=1000,gid=1000),ordinary_child=True)
 def test_fixture_derivative_preserves_assertions_ast(self):
  import ast
  original=(ROOT/'held-welcome/scripts/ci/welcome5-native-upgrade/fixture_checks.py').read_bytes();derived=F.derive(original)
  restored=derived
  for before,after in reversed(F.ROUTES):restored=restored.replace(after,before)
  self.assertEqual(restored,original);self.assertEqual(ast.dump(ast.parse(restored)),ast.dump(ast.parse(original)))
  self.assertIn(b"'Ran 5 tests'",derived);self.assertIn(b"count=8 if role",derived);self.assertIn(b"else 12",derived);self.assertIn(b"ok 1 /management/root-guard",derived)
  with self.assertRaises(ValueError):F.derive(original+b'\n')
 def test_fixed_map_paths_bounds_and_duplicate_json_refuse(self):
  refs={name:dict(path='/bridge-proof/'+name.replace('_','-')+'.json',bytes=1,sha256='0'*64)for name in C.MAPS};G.fixed_maprefs(refs)
  refs['packages']['path']='/tmp/packages.json'
  with self.assertRaises(ValueError):G.fixed_maprefs(refs)
  with self.assertRaises(ValueError):C.decode(b'{"x":1,"x":2}')
 def test_nofollow_and_hardlinked_inputs_refuse(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'source').write_bytes(b'{}');(root/'alias').symlink_to('source')
   with self.assertRaises(OSError):C.ordinary(root/'alias')
   os.link(root/'source',root/'linked')
   with self.assertRaises(ValueError):C.ordinary(root/'source')
 def test_mount_scope_refuses_missing_actual_bind_mounts(self):
  with self.assertRaises(ValueError):scope._rows(b'1 2 0:1 / / rw - tmpfs tmpfs rw\n',3,4,(0,1))

class RuntimeControls(unittest.TestCase):
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)
 # These are small component fixtures, never a synthetic positive native606.
 def test_real_protected_inode_replacement_refused(self):
  import physical
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'protected').write_bytes(b'held');a=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');ids=physical.capture(root,a['nodes'],self.budget());(root/'replacement').write_bytes(b'held');os.replace(root/'replacement',root/'protected');b=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');after=physical.capture(root,b['nodes'],self.budget())
   self.assertEqual(a['nodes'],b['nodes'])
   with self.assertRaisesRegex(ValueError,'inode metadata'):physical.protected(ids,after,a['nodes'],b['nodes'],lambda _:False)
 def test_real_selected_db_full_fields_and_current_date(self):
  import driver
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);db=root/'var/lib/pacman/local/cachy-asahi-welcome-0.1.0-5';db.mkdir(parents=True)
   fields={'NAME':['cachy-asahi-welcome'],'VERSION':['0.1.0-5'],'ARCH':['aarch64'],'INSTALLDATE':['123'],'DESC':['inert component fixture'],'REASON':['0']}
   raw=''.join('%'+k+'%\n'+'\n'.join(v)+'\n\n'for k,v in fields.items()).encode();(db/'desc').write_bytes(raw);(db/'files').write_bytes(b'%FILES%\nusr/bin/cachy-asahi-welcome\n\n');(db/'mtree').write_bytes(b'inert mtree bytes');db.chmod(0o755)
   for p in db.iterdir():p.chmod(0o644)
   value=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');product=dict(version='0.1.0-5',payload={'usr/bin/cachy-asahi-welcome':{}},database_fields=fields,mtree=C.pin((db/'mtree').read_bytes()));rows=[dict(name='cachy-asahi-welcome',version='0.1.0-5',files=['usr/bin/cachy-asahi-welcome'])]
   if os.getuid()!=0:
    with self.assertRaisesRegex(ValueError,'metadata'):driver.selected_database(root,rows,value['nodes'],product,window=(120,125))
   else:self.assertTrue(driver.selected_database(root,rows,value['nodes'],product,window=(120,125)))
   parsed=driver.database_api().fields(raw);self.assertTrue(driver.validate_fields(parsed,fields,(120,125)))
   with self.assertRaisesRegex(ValueError,'INSTALLDATE'):driver.validate_fields(parsed,fields,(124,125))
   changed=copy.deepcopy(fields);changed['DESC']=['different']
   with self.assertRaisesRegex(ValueError,'metadata'):driver.validate_fields(parsed,changed,(120,125))
 def test_real_zero_cap_NNP_child_and_retirement(self):
  import supervised
  code="import sys,json,os;sys.path.insert(0,"+repr(str(HERE))+");import rooted_fixture as F;fd=os.open('/proc/self/status',os.O_RDONLY);F.zero_caps();print(json.dumps(F.status(fd)));os.close(fd)"
  r=supervised.run([sys.executable,'-I','-B','-c',code],env={'PATH':'/usr/bin:/bin'},cwd='/',timeout=3,output_limit=4096)
  self.assertEqual(r['returncode'],0);self.assertTrue(r['direct_child_reaped']);self.assertTrue(r['group_retired']);status=C.decode(r['stdout'])
  for name in('CapEff','CapPrm','CapInh','CapAmb'):self.assertEqual(status[name],0)
  self.assertEqual(status['NoNewPrivs'],1)
 def test_actual_original_restore_not_fresh_sameversion(self):
  import lifecycle
  original=dict(version='0.1.0-4',sha256='0'*64,payload={n:{}for n in C.WELCOME_FILES});row=dict(original,source_record=original)
  new=dict(version='0.1.0-5',sha256='1'*64,payload=original['payload']);lifecycle.operands(row,new,original604_manifest={G.NAME:original})
  fresh=dict(row,sha256='2'*64)
  with self.assertRaisesRegex(ValueError,'original4'):lifecycle.operands(fresh,new,original604_manifest={G.NAME:original})
 def test_exact_five_bind_contract(self):
  rows=[dict(source='/owned/'+str(i),target=t,readonly=r)for i,(t,r)in enumerate((('/runner',True),('/seed',True),('/bridge-proof',True),('/work',False),('/out',False)))];C.bindings(rows)
  rows[0]['readonly']=False
  with self.assertRaises(ValueError):C.bindings(rows)
 def test_verification_key_refusal_before_process_or_work_write(self):
  import verification
  row=dict(path='/tmp/not-a-key',bytes=1,sha256='0'*64,signer='A'*40)
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'fixed readonly'):verification.prepare([row],signers={'A'*40},budget=self.budget())
 def test_archive_db_constructor_calibrates_every_source_field(self):
  import plan
  info=dict(pkgname=['cachy-asahi-welcome'],pkgver=['0.1.0-4'],arch=['aarch64'],size=['1'],builddate=['100'],packager=['inert component fixture'],pkgbase=['cachy-asahi-welcome'],xdata=['pkgtype=pkg'],makedepend=['gcc'])
  source={plan.FIELDS[k]:v for k,v in info.items()if k in plan.FIELDS}|{'INSTALLDATE':['123'],'REASON':['0'],'VALIDATION':['pgp']}
  self.assertEqual(plan.fields(info,source),source)
  candidate=dict(info,pkgver=['0.1.0-5']);self.assertEqual(plan.fields(candidate,source)['VERSION'],['0.1.0-5'])
  with self.assertRaises(ValueError):plan.fields(dict(info,unknown=['unsupported']),source)
  with self.assertRaises(ValueError):plan.fields(info,dict(source,UNKNOWN=['must not discard']))
 def test_lock_parent_projection_needs_exact_actual_witness(self):
  import physical
  a={'var/lib/pacman':[1,2,0o40755,0,0,3,4096,1,1]};b={'var/lib/pacman':[1,2,0o40755,0,0,3,8192,2,2]};nodes={'var/lib/pacman':dict(type='directory')}
  with self.assertRaises(ValueError):physical.protected(a,b,nodes,nodes,lambda _:False)
  proof=dict(path='var/lib/pacman',lock_created=True,lock_removed=True,before=a['var/lib/pacman'],after=b['var/lib/pacman'])
  physical.protected(a,b,nodes,nodes,lambda _:False,lock_witness=proof)
  with self.assertRaises(ValueError):physical.protected(a,b,nodes,nodes,lambda _:False,lock_witness=dict(proof,lock_removed=False))
 def test_all_emitted_worker_programs_compile(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   for p in HERE.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')
 def test_generated_worker_main_is_full_lifecycle_not_copy_credit(self):
  import ast
  source=(HERE/'worker.py').read_text();tree=ast.parse(source);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');calls=[ast.unparse(n.func)for n in ast.walk(main)if isinstance(n,ast.Call)]
  self.assertIn('driver.run',calls);self.assertIn('copy_verified',calls);self.assertIn('C.actor_guard',calls);self.assertIn('C.authority',calls)
  self.assertNotIn('VERIFIED_606_COPY_ONLY_NO_TRANSACTION_CREDIT',source)

class SerializedSourceView(unittest.TestCase):
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)
 def observe(self,p):return R.observe(p,limits=self.budget(),hardlinks='generic-development-internal',absolute_paths=True)
 def tree(self,p):
  (p/'etc').mkdir();(p/'etc/aux').write_bytes(b'original auxiliary');(p/'file').write_bytes(b'original bytes');os.link(p/'file',p/'alias');(p/'link').symlink_to('file')
 def serialized(self,value):return C.decode(C.encoded(value))
 def test_real_finalizer_json_roundtrip_keeps_entire_worker_source_view(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td);self.tree(p);before=self.observe(p);loaded=self.serialized(before);after=self.observe(p)
   self.assertIs(type(before['hardlink_groups']['alias']['members']),tuple);self.assertIs(type(loaded['hardlink_groups']['alias']['members']),list)
   self.assertEqual(loaded['nodes'],after['nodes']);G.same_source(loaded,after)
   self.assertEqual(loaded['hardlink_groups']['alias']['members'],['alias','file'])
   self.assertEqual(set(G.observation(loaded)),set(loaded));self.assertEqual(set(G.observation(loaded)['hardlink_groups']['alias']),set(loaded['hardlink_groups']['alias']))
 def test_actual_copy_verified_route_passes_json_join_then_refuses_non606_fixture(self):
  import worker as W
  with tempfile.TemporaryDirectory()as td:
   p=Path(td);self.tree(p);loaded=self.serialized(self.observe(p));data=dict(ordinary_observation=loaded,packages=[])
   # This inert filesystem lacks real606 selected links/aux. Observe all real
   # nodes here, then require the actual next complete606 guard to refuse.
   with patch.object(W,'observe',side_effect=lambda path,budget:self.observe(p))as observed,patch.object(G,'same_source',wraps=G.same_source)as joined:
    with self.assertRaisesRegex(ValueError,'complete original606 database rows'):
     with W.copy_verified(data,self.budget()):self.fail('inert fixture copied')
   self.assertEqual(observed.call_count,1);self.assertEqual(joined.call_count,1)
 def test_real_content_mode_aux_and_hardlink_break_still_refuse(self):
  for change in ('content','mode','aux','hardlink'):
   with self.subTest(change=change),tempfile.TemporaryDirectory()as td:
    p=Path(td);self.tree(p);loaded=self.serialized(self.observe(p))
    if change=='content':(p/'file').write_bytes(b'changed content')
    elif change=='mode':(p/'file').chmod(0o600)
    elif change=='aux':(p/'etc/aux').write_bytes(b'changed auxiliary')
    else:(p/'alias').unlink();(p/'alias').write_bytes(b'original bytes')
    with self.assertRaisesRegex(ValueError,'source graph'):G.same_source(loaded,self.observe(p))
 def test_uid_and_all_nonmember_fields_remain_compared(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td);self.tree(p);before=self.serialized(self.observe(p));live=self.observe(p)
   for field in ('uid','gid','mode','sha256','bytes'):
    after=copy.deepcopy(live);after['nodes']['file'][field]=('0'*64 if field=='sha256'else after['nodes']['file'][field]+1)
    with self.assertRaisesRegex(ValueError,'source graph'):G.same_source(before,after)
   for field in ('nlink','sha256','bytes','uid','gid','mode'):
    after=copy.deepcopy(live);after['hardlink_groups']['alias'][field]=('0'*64 if field=='sha256'else after['hardlink_groups']['alias'][field]+1)
    with self.assertRaises(ValueError):G.same_source(before,after)
   after=copy.deepcopy(live);after['unsupported']=tuple(after['unsupported'])
   with self.assertRaises(ValueError):G.same_source(before,after)
 def test_malformed_unsorted_duplicate_or_foreign_members_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td);self.tree(p);before=self.serialized(self.observe(p));live=self.observe(p)
   for members in (['file','alias'],['alias','alias'],['alias',False],['alias'],['alias','foreign'],'alias'):
    after=copy.deepcopy(before);after['hardlink_groups']['alias']['members']=members
    with self.assertRaises(ValueError):G.same_source(after,live)
   for nlink in (True,1,3,'2'):
    after=copy.deepcopy(before);after['hardlink_groups']['alias']['nlink']=nlink
    with self.assertRaises(ValueError):G.same_source(after,live)
   after=copy.deepcopy(before);after['hardlink_groups']['foreign']=after['hardlink_groups'].pop('alias')
   with self.assertRaises(ValueError):G.same_source(after,live)

class CopyHardlinkProjection(unittest.TestCase):
 """Private real trees plus a declared tiny TEST selector, never a606 acceptance fixture."""
 def budget(self):return R.Limits(deadline=time.monotonic()+10,max_nodes=1000,max_bytes=1024**2,max_file_bytes=1024**2)
 def tree(self,root):
  for n in('etc','usr/bin','usr/lib'):(root/n).mkdir(parents=True,exist_ok=True)
  (root/'usr/lib/a').write_bytes(b'PRIVATE_REAL_HARDLINK_PAYLOAD');os.link(root/'usr/lib/a',root/'usr/lib/b')
  (root/'usr/bin/ldconfig').write_bytes(b'INERT_NOT_EXECUTED_NOT_PRODUCTION_HELPER');(root/'usr/bin/ldconfig').chmod(0o755)
  (root/'usr/sbin').symlink_to('bin');(root/'sbin').symlink_to('usr/bin');(root/'absolute').symlink_to('/usr/lib/a');(root/'etc/mtab').symlink_to('/proc/self/mounts')
 def observe(self,root):return R.observe(root,limits=self.budget(),hardlinks='generic-development-internal',absolute_paths=True)
 def selection(self,before):
  # Only test EXPECTED DATA uses the real ordinary fixture's metadata. Original
  # checker/projector code is unchanged; production87 constants remain whole.
  import contextlib,root_link_selection as links
  @contextlib.contextmanager
  def selected():
   rows={n:dict(before['nodes'][n])for n in('absolute','etc/mtab')}
   with patch.object(links,'LINK_NODES',rows),patch.object(links,'CHAIN_PATHS',tuple(sorted(rows))),patch.object(links,'RESOLVED_ENDPOINTS',{'absolute':'usr/lib/a'}),patch.object(links,'DATA_ONLY_ENDPOINTS',{'etc/mtab':'proc/self/mounts'}):yield
  return selected()
 def guard(self,before,copied,*,old=False,graph_only=False):
  import ast,root_link_selection as links
  tree=ast.parse((HERE/'worker.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='copy_verified')
  block=next(n for n in ast.walk(fn)if isinstance(n,ast.With)and isinstance(n.items[0].context_expr,ast.Call)and isinstance(n.items[0].context_expr.func,ast.Name)and n.items[0].context_expr.func.id=='copier')
  code=copy.deepcopy(block.body[1:3]);self.assertEqual(ast.unparse(code[0].value.func),'C.need');self.assertEqual(ast.unparse(code[1].value.func),'roots.check_hardlink_preservation')
  self.assertEqual([ast.unparse(v)for v in code[1].value.args],['root_link_selection.view(before, budget)','root_link_selection.view(copied, budget)'])
  if old:code[1].value.args=[ast.Name(id='before',ctx=ast.Load()),ast.Name(id='copied',ctx=ast.Load())]
  if graph_only:code=code[1:]
  exec(compile(ast.fix_missing_locations(ast.Module(body=code,type_ignores=[])),'<actual-source-copy-guards>','exec'),dict(C=C,roots=R,root_link_selection=links,before=before,copied=copied,budget=self.budget()))
 def test_real_absolute_alias_ldconfig_route_old_refuses_new_preserves_raw_maps(self):
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);a=base/'source';b=base/'copy';a.mkdir();b.mkdir();self.tree(a);self.tree(b);before,copied=self.observe(a),self.observe(b)
   self.assertEqual(before['nodes'],copied['nodes']);self.assertFalse(before['eligible']);self.assertEqual(before['unsupported_counts'],{'absolute-symlink':2,'auxiliary-present':3})
   raw=(C.encoded(before),C.encoded(copied))
   with self.selection(before):
    with self.assertRaisesRegex(ValueError,'unsupported or incomplete root observation'):self.guard(before,copied,old=True)
    self.guard(before,copied)
   self.assertEqual((C.encoded(before),C.encoded(copied)),raw);self.assertFalse(before['eligible']);self.assertFalse(copied['eligible'])
   self.assertEqual((a/'usr/lib/a').stat().st_ino,(a/'usr/lib/b').stat().st_ino);self.assertNotEqual((a/'usr/lib/a').stat().st_ino,(b/'usr/lib/a').stat().st_ino)
 def test_real_unknown_absolute_escape_and_fifo_still_refuse(self):
  for kind in('absolute','escape','fifo'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    a=Path(td)/'source';b=Path(td)/'copy';a.mkdir();b.mkdir();self.tree(a);self.tree(b);selected=self.observe(a)
    for root in(a,b):
     if kind=='absolute':(root/'unselected').symlink_to('/usr/lib/a')
     elif kind=='escape':(root/'unselected').symlink_to('../outside')
     else:os.mkfifo(root/'unselected',0o600)
    before,copied=self.observe(a),self.observe(b)
    with self.selection(selected),self.assertRaises(ValueError):self.guard(before,copied)
 def test_real_group_break_content_mode_and_aux_hardlink_refuse(self):
  for kind in('break','content','mode','helper-hardlink'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    a=Path(td)/'source';b=Path(td)/'copy';a.mkdir();b.mkdir();self.tree(a);self.tree(b)
    if kind=='helper-hardlink':
     for root in(a,b):os.link(root/'usr/bin/ldconfig',root/'usr/lib/helper-alias')
    before=self.observe(a)
    if kind=='break':(b/'usr/lib/b').unlink();(b/'usr/lib/b').write_bytes(b'PRIVATE_REAL_HARDLINK_PAYLOAD')
    elif kind=='content':(b/'usr/lib/a').write_bytes(b'CHANGED')
    elif kind=='mode':(b/'usr/lib/a').chmod(0o600)
    copied=self.observe(b)
    with self.selection(before),self.assertRaises(ValueError):self.guard(before,copied,graph_only=True)
 def test_original_full87_policy_tables_and_actual_worker_observe_guards_held(self):
  import ast,root_link_selection as links
  self.assertEqual((len(links.LINK_NODES),len(links.CHAIN_PATHS),len(links.RESOLVED_ENDPOINTS),len(links.DATA_ONLY_ENDPOINTS)),(87,87,45,42))
  self.assertEqual(hashlib.sha256(('\n'.join(links.CHAIN_PATHS)+'\n').encode()).hexdigest(),'29e3696affcb565286672dffa03e5f1dfc7549be2bb2ec23ffc9c057c853bbf2')
  nodes={}
  def parents(name):
   for i in range(1,len(name.split('/'))):nodes.setdefault('/'.join(name.split('/')[:i]),dict(type='directory',mode=0o755,uid=0,gid=0))
  for n,row in links.LINK_NODES.items():parents(n);nodes[n]=dict(row)
  for n in links.RESOLVED_ENDPOINTS.values():
   parents(n);nodes.setdefault(n,dict(type='directory',mode=0o755,uid=0,gid=0)if n in('usr/share/xkeyboard-config-2','usr/share/licenses/qt6-base')else dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='a'*64))
  nodes['usr/lib/libkeyutils.so.1']=dict(type='symlink',mode=0o777,uid=0,gid=0,target='libkeyutils.so.1.10')
  value=dict(complete=True,eligible=False,nodes=nodes,unsupported_counts={'absolute-symlink':87,'auxiliary-present':3},hardlink_groups={})
  links.check(value,self.budget());value['nodes']['etc/mtab']['target']='/proc/1/mounts'
  with self.assertRaises(ValueError):links.view(value,self.budget())
  fn=next(n for n in ast.parse((HERE/'worker.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='observe');calls=[ast.unparse(n.func)for n in ast.walk(fn)if isinstance(n,ast.Call)]
  self.assertEqual(calls,['roots.observe','root_link_selection.check','aux_checkpoint.checkpoint']);self.assertIn('return value',ast.unparse(fn))

class ExplicitReasonEncoding(unittest.TestCase):
 # Pure schema controls, never an accepting signed/native606 fixture.
 def operands(self):
  import plan
  apps='apps7'in str(HERE)
  info=dict(pkgname=['cachy-asahi-apps'if apps else'cachy-asahi-welcome'],pkgver=['0.1.0-6'if apps else'0.1.0-4'],arch=['any'if apps else'aarch64'],size=['1'],builddate=['100'],packager=['inert schema fixture'],xdata=['pkgtype=pkg'])
  source={plan.FIELDS[k]:list(v)for k,v in info.items()}|{'INSTALLDATE':['123'],'VALIDATION':['pgp']}
  return plan,info,source
 def test_raw_reason_omission_is_preserved(self):
  plan,info,source=self.operands();self.assertEqual(plan.fields(info,source),source);self.assertNotIn('REASON',plan.fields(info,source))
  apps='apps7'in str(HERE);oldkey,newkey=('original6','new7')if apps else('original4','new5')
  old=dict(pkginfo=info);new=dict(pkginfo=dict(info,pkgver=['0.1.0-7'if apps else'0.1.0-5']))
  value={oldkey:old,newkey:new,'verification_keys':[]}
  if apps:value.update(runtime={},original606_manifest={})
  else:value.update(original604_manifest={},fixture_policy={},fixture_products={'cachy-asahi-welcome':old,'cachy-asahi-welcome5':new})
  completed=plan.complete(value,source)
  for key in(oldkey,newkey):self.assertNotIn('REASON',completed[key]['database_fields'])
  changed=dict(source,XDATA=['different from actual archive'])
  with self.assertRaises(ValueError):plan.complete(value,changed)
 def test_explicit_zero_present_is_preserved(self):
  plan,info,source=self.operands();source['REASON']=['0'];self.assertEqual(plan.fields(info,source),source)
 def test_foreign_and_malformed_reason_refuse(self):
  import contextlib,io
  plan,info,source=self.operands()
  for reason in (['1'],[],['0','0'],['00'],[''],0,None):
   with self.subTest(reason=reason),contextlib.redirect_stderr(io.StringIO()):
    with self.assertRaises(ValueError):plan.fields(info,dict(source,REASON=reason))
 def test_missing_required_unknown_and_unsigned_refuse(self):
  import contextlib,io
  plan,info,source=self.operands()
  for value in ({k:v for k,v in source.items()if k!='INSTALLDATE'},{k:v for k,v in source.items()if k!='VALIDATION'},dict(source,UNKNOWN_PRIVATE=['secret']),dict(source,VALIDATION=['none'])):
   with self.subTest(keys=sorted(value)),contextlib.redirect_stderr(io.StringIO()):
    with self.assertRaises(ValueError):plan.fields(info,value)
 def test_failure_diagnostic_is_bounded_pinned_and_redacted(self):
  import contextlib,io,json
  plan,info,source=self.operands();source['PRIVATE_FIELD_NAME']=['private-value-never-export'];out=io.StringIO()
  with contextlib.redirect_stderr(out):
   with self.assertRaises(ValueError):plan.fields(info,source)
  raw=out.getvalue();self.assertLessEqual(len(raw.encode()),2049);row=json.loads(raw)
  self.assertEqual(row['source_fields'],C.pin(C.encoded(source)));self.assertEqual(row['unknown_count'],1)
  self.assertEqual(row['unknown_labels_sha256'],hashlib.sha256(C.encoded(['PRIVATE_FIELD_NAME'])).hexdigest())
  self.assertNotIn('PRIVATE_FIELD_NAME',raw);self.assertNotIn('private-value',raw);self.assertEqual(row['status'],'DIAGNOSTIC_ONLY')
 def test_reporting_failure_cannot_replace_original_guard(self):
  import contextlib,io
  plan,info,source=self.operands()
  with patch.object(plan.sys,'stderr',None):
   with self.assertRaises(ValueError):plan.fields(info,dict(source,VALIDATION=['none']))
 def test_all_current_metadata_keys_remain_exact(self):
  import driver
  plan,info,source=self.operands();self.assertTrue(driver.validate_fields(source,source,(120,125)))
  for changed in(dict(source,REASON=['0']),dict(source,XDATA=['changed']),{k:v for k,v in source.items()if k!='XDATA'}):
   with self.assertRaises(ValueError):driver.validate_fields(changed,source,(120,125))
 def test_success_has_no_diagnostic_output(self):
  import contextlib,io
  plan,info,source=self.operands();out=io.StringIO()
  with contextlib.redirect_stderr(out):plan.fields(info,source)
  self.assertEqual(out.getvalue(),'')


class FixtureFailureControls(unittest.TestCase):
 def state(self):
  import supervised as S
  return ((0,0,0),(0,0,0),(0,),dict(CapEff=C.WORKER_MASK,CapPrm=C.WORKER_MASK,CapBnd=C.WORKER_MASK,CapInh=0,CapAmb=0,NoNewPrivs=1,uid=0,gid=0))
 def test_signal_credential_call_sequence_restores_on_success_and_exception(self):
  # Call-sequence control only. Real credential permission proof is the
  # separately Root-executed exact8-cap private OCI probe, never this model.
  import signal,supervised as S
  for error in(None,PermissionError(1,'INERT_PERMISSION_FAILURE')):
   state={'uid':0};calls=[]
   def setuid(v):calls.append(('seteuid',v));state['uid']=v
   def kill(group,sig):
    calls.append(('killpg',group,sig,state['uid']))
    if error:raise error
   with patch.object(S,'_credentials',return_value=self.state()),patch.object(S.os,'seteuid',side_effect=setuid),patch.object(S.os,'geteuid',side_effect=lambda:state['uid']),patch.object(S.os,'killpg',side_effect=kill):
    helper=S._SignalOS(1000)
    if error:
     with self.assertRaises(PermissionError):helper.killpg(12345,signal.SIGTERM)
    else:helper.killpg(12345,signal.SIGTERM)
   self.assertEqual(state['uid'],0);self.assertEqual(calls,[('seteuid',1000),('killpg',12345,signal.SIGTERM,1000),('seteuid',0)])
 def test_signal_uid_group_kind_and_root_credentials_refuse(self):
  import signal,supervised as S
  for uid in(True,-1,2**31,'1000'):
   with self.assertRaises(ValueError):S._SignalOS(uid)
  with patch.object(S,'_credentials',return_value=self.state()):
   helper=S._SignalOS(0)
   for group,sig in((1,signal.SIGTERM),(12345,signal.SIGCONT)):
    with self.assertRaises(ValueError):helper.killpg(group,sig)
  bad=list(self.state());bad[0]=(1000,1000,1000)
  with patch.object(S,'_credentials',return_value=tuple(bad)):
   with self.assertRaises(ValueError):S._SignalOS(1000)
 def test_no_added_capability_original_caps_and_guard_line_held(self):
  import inspect,supervised as S
  self.assertEqual(C.WORKER_MASK,0x800400db);self.assertNotIn('KILL',C.WORKER_CAPS)
  text=inspect.getsource(F.run)
  self.assertIn("signal_uid=spec['uid']",text)
  self.assertIn("C.need(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is True and value['group_retired']is True,'rooted Welcome fixture failed; retained disposal required')",text)
  self.assertIn('output_limit=128*1024,grace=1',text)
 def value(self):
  return dict(returncode=1,termination=None,direct_child_reaped=True,group_kill_sent=True,group_retired=True,descendants_reaped=0,stdout=b'INERT_PRIVATE_OUT'*300,stderr=b'INERT_PRIVATE_ERROR'*300)
 def spec(self):return dict(role='INERT_NOT_ACTUAL_FIXTURE',kind='ordinary',uid=1000,gid=1000)
 def test_failure_only_original_stream_pins_tails_and_cap(self):
  import base64,contextlib,io,json
  out=io.StringIO();v=self.value();s=self.spec()
  with contextlib.redirect_stderr(out):F._failure_data(v,s)
  raw=out.getvalue();self.assertTrue(raw.startswith('CURRENT606_ROOTED_FIXTURE_FAILURE '));data=raw.split(' ',1)[1];self.assertLessEqual(len(data.encode()),8192);r=json.loads(data)
  self.assertEqual(r['status'],'ROOTED_FIXTURE_FAILURE_DATA_NOT_ACCEPTANCE');self.assertEqual(r['spec_sha256'],C.pin(C.encoded(s))['sha256'])
  for n in('stdout','stderr'):
   p=r['streams'][n];self.assertEqual({k:p[k]for k in('bytes','sha256')},C.pin(v[n]));self.assertEqual(base64.b64decode(p['tail_base64'],validate=True),v[n][-2048:]);self.assertEqual(p['omitted_bytes'],len(v[n])-2048);self.assertTrue(p['truncated'])
 def test_unavailable_failure_projection_does_not_suppress_original_refusal(self):
  import contextlib,io
  with patch.object(F.sys,'stderr',None):F._failure_data(self.value(),self.spec())
  out=io.StringIO();v=self.value();v['stderr']=b'X'*(128*1024+1)
  with contextlib.redirect_stderr(out):F._failure_data(v,self.spec())
  self.assertEqual(out.getvalue(),'')
  with self.assertRaisesRegex(ValueError,'original refusal'):C.need(False,'original refusal')

class ProcSelfSetup(unittest.TestCase):
 def test_whole_two_C_sources_and_all_original_bodies_are_reversible(self):
  for role in('cachy-asahi-welcome','cachy-asahi-welcome5'):
   raw=(ROOT.parent/'heldwelcome/packages/tools'/role/'test_management.c').read_bytes();derived=F.derive_management_fixture(raw);restored=derived
   for before,after in reversed(F.MANAGEMENT_SETUP_ROUTES):
    self.assertEqual(restored.count(after),1);restored=restored.replace(after,before)
   self.assertEqual(restored,raw);self.assertIn(b'g_assert_nonnull(self);',derived);self.assertIn(b'G_FILE_ERROR_NOENT',derived);self.assertIn(b'getauxval(AT_EXECFN)',derived);self.assertEqual(derived.count(b'g_test_skip('),raw.count(b'g_test_skip('))
   with self.assertRaises(ValueError):F.derive_management_fixture(raw+b'\n')
 def test_actual_generated_Python_uses_same_C_derivation_and_only_compile_setup_route(self):
  original=(ROOT/'held-welcome/scripts/ci/welcome5-native-upgrade/fixture_checks.py').read_bytes();derived=F.derive(original);ns={'__name__':'owned_source_fixture_control'};exec(compile(derived,'source-owned-fixture','exec'),ns)
  for role in('cachy-asahi-welcome','cachy-asahi-welcome5'):
   raw=(ROOT.parent/'heldwelcome/packages/tools'/role/'test_management.c').read_bytes();self.assertEqual(ns['derive_management_fixture'](raw),F.derive_management_fixture(raw))
  self.assertIn(b"command([str(program),'-p','/management/root-guard'])",derived);self.assertIn(b"'# SKIP'not in text",derived);self.assertIn(b"'-DMANAGEMENT_TEST','-iquote',str(root)",derived)
 def test_generated_fixture_source_create_once_noalias_and_exact_bytes(self):
  ns={'__name__':'owned_source_fixture_control'};original=(ROOT/'held-welcome/scripts/ci/welcome5-native-upgrade/fixture_checks.py').read_bytes();exec(compile(F.derive(original),'source-owned-fixture','exec'),ns)
  source=ROOT.parent/'heldwelcome/packages/tools/cachy-asahi-welcome'
  with tempfile.TemporaryDirectory()as d:
   work=Path(d);path=ns['proc_self_fixture'](source,work);self.assertEqual(path.read_bytes(),F.derive_management_fixture((source/'test_management.c').read_bytes()));self.assertEqual(path.stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):ns['proc_self_fixture'](source,work)
   path.unlink();path.symlink_to(work/'must-not-exist')
   with self.assertRaises(FileExistsError):ns['proc_self_fixture'](source,work)
   self.assertFalse((work/'must-not-exist').exists())

if __name__=='__main__':unittest.main()
