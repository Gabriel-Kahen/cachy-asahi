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
  base={f'p{i}':'1'for i in range(605)}|{G.NAME:'0.1.0-1'};G.inventory(base|{G.NAME:'0.2.0-1'},base,'0.2.0-1');G.inventory({k:v for k,v in base.items()if k!=G.NAME},base,None)
  with self.assertRaises(ValueError):G.inventory(base|{'p4':'2',G.NAME:'0.2.0-1'},base,'0.2.0-1')
 def test_selected_target_preserves_every_other_row_and_raw_db(self):
  node=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='0'*64)
  before=dict(complete=True,unsupported_counts={},nodes={'usr/bin/welcome':node,'var/lib/pacman/local/other-1/desc':node,'home/alarm/.config/user':node},hardlink_groups={})
  after=copy.deepcopy(before);after['nodes']['usr/bin/welcome']=dict(node,sha256='1'*64)
  args=dict(old_paths=['usr/bin/welcome'],new_paths=['usr/bin/welcome'],old_database='var/lib/pacman/local/cachy-asahi-doctor-0.1.0-1',new_database='var/lib/pacman/local/cachy-asahi-doctor-0.2.0-1')
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
   root=Path(d);db=root/'var/lib/pacman/local/cachy-asahi-doctor-0.2.0-1';db.mkdir(parents=True)
   fields={'NAME':['cachy-asahi-doctor'],'VERSION':['0.2.0-1'],'ARCH':['aarch64'],'INSTALLDATE':['123'],'DESC':['inert component fixture'],'REASON':['0']}
   raw=''.join('%'+k+'%\n'+'\n'.join(v)+'\n\n'for k,v in fields.items()).encode();(db/'desc').write_bytes(raw);(db/'files').write_bytes(b'%FILES%\nusr/bin/cachy-asahi-doctor\n\n');(db/'mtree').write_bytes(b'inert mtree bytes');db.chmod(0o755)
   for p in db.iterdir():p.chmod(0o644)
   value=R.observe(root,limits=self.budget(),hardlinks='generic-development-internal');product=dict(version='0.2.0-1',payload={'usr/bin/cachy-asahi-doctor':{}},database_fields=fields,mtree=C.pin((db/'mtree').read_bytes()));rows=[dict(name='cachy-asahi-doctor',version='0.2.0-1',files=['usr/bin/cachy-asahi-doctor'])]
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
  original=dict(version='0.1.0-1',signer='DA8AD638E79414E661656E4C23132CAA1000DA38',sha256='06898669fdd6c9e5bdcc9909e6b0e75e958bdbd57520a7082c0e9f5f7fac7482',payload={n:{}for n in C.DOCTOR_FILES});row=dict(original,source_record=original)
  new=dict(version='0.2.0-1',sha256='5d27ef618bfc571c0238cfbbbcf382d0e4c689df509d1f62123ad5fe53245ee7',signer='DA8AD638E79414E661656E4C23132CAA1000DA38',payload=original['payload']);lifecycle.operands(row,new,original606_manifest={G.NAME:original})
  fresh=dict(row,sha256='2'*64)
  with self.assertRaisesRegex(ValueError,'original1'):lifecycle.operands(fresh,new,original606_manifest={G.NAME:original})
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
  info=dict(pkgname=['cachy-asahi-doctor'],pkgver=['0.1.0-1'],arch=['any'],size=['1'],builddate=['100'],packager=['inert component fixture'],pkgbase=['cachy-asahi-doctor'],xdata=['pkgtype=pkg'],makedepend=['gcc'])
  source={plan.FIELDS[k]:v for k,v in info.items()if k in plan.FIELDS}|{'INSTALLDATE':['123'],'REASON':['0'],'VALIDATION':['pgp']}
  self.assertEqual(plan.fields(info,source),source)
  candidate=dict(info,pkgver=['0.2.0-1']);self.assertEqual(plan.fields(candidate,source)['VERSION'],['0.2.0-1'])
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
  apps='doctor2'in str(HERE)
  info=dict(pkgname=['cachy-asahi-doctor'if apps else'cachy-asahi-welcome'],pkgver=['0.1.0-1'if apps else'0.1.0-4'],arch=['any'if apps else'aarch64'],size=['1'],builddate=['100'],packager=['inert schema fixture'],xdata=['pkgtype=pkg'])
  source={plan.FIELDS[k]:list(v)for k,v in info.items()}|{'INSTALLDATE':['123'],'VALIDATION':['pgp']}
  return plan,info,source
 def test_raw_reason_omission_is_preserved(self):
  plan,info,source=self.operands();self.assertEqual(plan.fields(info,source),source);self.assertNotIn('REASON',plan.fields(info,source))
  apps='doctor2'in str(HERE);oldkey,newkey=('original1','new2')if apps else('original4','new5')
  old=dict(pkginfo=info);new=dict(pkginfo=dict(info,pkgver=['0.2.0-1'if apps else'0.1.0-5']))
  value={oldkey:old,newkey:new,'verification_keys':[]}
  if apps:value.update(runtime={},original606_manifest={})
  else:value.update(original104_manifest={},fixture_policy={},fixture_products={'cachy-asahi-welcome':old,'cachy-asahi-welcome5':new})
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


class DoctorFixtureContracts(unittest.TestCase):
 def entry(self):
  import importlib.util
  p=HERE/'fixture_entry.py';s=importlib.util.spec_from_file_location('_doctor_source_fixture',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 def test_actual_installed_path_and_no_dev_or_query_fabrication(self):
  import ast
  raw=(HERE/'fixture_entry.py').read_text();tree=ast.parse(raw)
  self.assertIn("PROGRAM=Path('/usr/bin/cachy-asahi-doctor')",raw);self.assertIn("not Path('/dev/null').exists()",raw);self.assertIn('SOURCE_OWNED_FIXED_PACMAN_Q_NOT_DOCTOR_QUERY',raw)
  calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='call'and n.args and isinstance(n.args[0],ast.List)]
  inventory=[n for n in calls if isinstance(n.args[0].elts[0],ast.Constant)and ast.literal_eval(n.args[0].elts[0])=='/usr/bin/pacman']
  self.assertEqual(len(inventory),1);self.assertEqual(ast.literal_eval(inventory[0].args[0]),['/usr/bin/pacman','-Q'])
  self.assertNotIn('os.mknod',raw);self.assertNotIn('mount(',raw);self.assertIn('stdin=0',raw)
 def test_real_cli_entry_refuses_host_before_any_query(self):
  m=self.entry()
  with patch.object(m.subprocess,'run',side_effect=AssertionError('NO_HOST_QUERY')),patch.object(m.sys,'argv',['fixture']),self.assertRaisesRegex(ValueError,'ordinary native'):m.main()
 def test_private_source_controls_bind_actual_program_and_all24(self):
  raw=(HERE/'fixture_entry.py').read_text();self.assertIn('raw==(CONTEXT/\'doctor/cachy-asahi-doctor\').read_bytes()',raw);self.assertIn('result.testsRun==24',raw);self.assertIn('not result.skipped',raw);self.assertIn('setattr(module,key,actual)',raw);self.assertIn("RealIPC=dict(tests=3,reason='NOT_RUN_COPIED_ROOT_NO_DEV_NULL'",raw)
 def test_unknown_never_becomes_installed_or_healthy(self):
  m=self.entry();platform=dict(check='platform',value=dict(architecture='aarch64',kernel=os.uname().release,page_size_bytes=os.sysconf('SC_PAGE_SIZE')))
  value=dict(schema_version=1,tool='cachy-asahi-doctor',scope='local observations only',version='0.2.0',checks=[platform,dict(check='audio/default-output',state='unavailable',value=None),dict(check='package/cachy-asahi-doctor',state='unavailable',value=dict(presence='unknown',version=None))])
  self.assertIs(m.report(value,'doctor2'),value)
  for changed in(dict(check='audio/default-output',state='checked',value=dict(volume=1)),dict(check='package/cachy-asahi-doctor',state='checked',value=dict(presence='present',version='0.2.0-1'))):
   bad=__import__('copy').deepcopy(value);bad['checks'].append(changed)
   with self.assertRaises(ValueError):m.report(bad,'doctor2')


class SignedTransactionLimits(unittest.TestCase):
 def test_actual_pinned_constructor_missing_limits_refuses_before_ALPM(self):
  with patch.object(R.installer.Alpm,'__init__',side_effect=AssertionError('NO_NATIVE_ALPM')):
   with self.assertRaisesRegex(TypeError,'limits'):R.Alpm(Path('/INERT'),Path('/INERT'),Path('/INERT'),'aarch64')
 def test_real_apply_passes_exact_single_bounded_limits_before_native_ALPM(self):
  import alpm_step as S
  class StopBeforeNative(Exception):pass
  captured=[]
  def stop(handle,*args,**kwargs):
   captured.append(handle.limits);raise StopBeforeNative()
  before={f'held-{i}':'1-1'for i in range(605)};before['cachy-asahi-doctor']='0.1.0-1';after={k:v for k,v in before.items()if k!='cachy-asahi-doctor'}
  with tempfile.TemporaryDirectory()as td:
   info=os.stat(td)
   with patch.object(R.installer.Alpm,'__init__',new=stop),patch.object(S.Path,'stat',return_value=info),patch.object(S.os,'listdir',return_value=[]),patch.object(S.time,'monotonic',return_value=100.):
    with self.assertRaises(StopBeforeNative):S.apply('/work/main/root',before=before,after=after,archive=None,keys='/work/test-verification',log='/out/remove2-alpm.log')
  self.assertEqual(len(captured),1);limits=captured[0];self.assertIsInstance(limits,R.Limits);self.assertEqual(limits.deadline,190.)
  for name,value in C.BOUNDS.items():self.assertEqual(getattr(limits,name),value)
 def test_both_handles_share_one_original90s606_limits_and_guard(self):
  import ast,inspect,alpm_step as S,driver
  tree=ast.parse(inspect.getsource(S.apply));calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Alpm']
  self.assertEqual(len(calls),2)
  for call in calls:
   self.assertEqual([(v.arg,ast.unparse(v.value))for v in call.keywords],[('limits','limits')])
  limits=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='Limits'];self.assertEqual(len(limits),1)
  self.assertEqual(ast.unparse(limits[0]),'roots.Limits(deadline=time.monotonic() + 90, **C.BOUNDS)')
  raw=inspect.getsource(driver.run);self.assertIn('timeout=min(90,budget.deadline-time.monotonic())',raw);self.assertIn('output_limit=128*1024,grace=1',raw)
  self.assertIn("C.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired'],'signed transaction child failed or group not retired')",raw)
  self.assertIn('limit_seconds',inspect.getsource(driver._transaction_failure_data))
 def value(self):return dict(returncode=1,termination=None,direct_child_reaped=True,group_kill_sent=False,group_retired=True,descendants_reaped=0,owned_group_id=12345,stdout=b'INERT_OUTPUT'*300,stderr=b'INERT_TRACEBACK'*300)
 def test_failure_data_retains_exact_exit_budget_group_and_bounded_streams(self):
  import base64,contextlib,io,json,driver
  output=io.StringIO();value=self.value()
  with contextlib.redirect_stderr(output):driver._transaction_failure_data(value,'upgrade2',{'INERT':'NOT_A_PLAN'},89.5)
  raw=output.getvalue();self.assertTrue(raw.startswith('CURRENT606_TRANSACTION_FAILURE '));row=json.loads(raw.split(' ',1)[1]);self.assertLessEqual(len(raw.encode()),4096+40)
  self.assertEqual(row['limit_seconds'],89.5);self.assertEqual(row['output_limit'],128*1024);self.assertEqual(row['acceptance'],'NOT_GRANTED')
  self.assertEqual(row['spec_sha256'],C.pin(C.encoded({'INERT':'NOT_A_PLAN'}))['sha256'])
  for name,stream in row['streams'].items():
   self.assertEqual({k:stream[k]for k in('bytes','sha256')},C.pin(value[name]));self.assertEqual(base64.b64decode(stream['tail_base64'],validate=True),value[name][-1024:]);self.assertEqual(stream['omitted_bytes'],len(value[name])-1024)
  self.assertEqual(row['outcome'],{k:value[k]for k in row['outcome']})
 def test_success_invalid_budget_oversize_and_diagnostic_loss_grant_nothing(self):
  import contextlib,io,driver
  for value,timeout in((dict(self.value(),returncode=0),90),(self.value(),91),(dict(self.value(),stderr=b'X'*(128*1024+1)),90)):
   output=io.StringIO()
   with contextlib.redirect_stderr(output):driver._transaction_failure_data(value,'upgrade2',{},timeout)
   self.assertEqual(output.getvalue(),'')
  with patch.object(driver.C,'pin',side_effect=OSError('INERT_DIAGNOSTIC_LOSS')):driver._transaction_failure_data(self.value(),'upgrade2',{},90)
  with self.assertRaisesRegex(ValueError,'original refusal'):C.need(False,'original refusal')


class TargetFailureData(unittest.TestCase):
 def private(self,root):
  for n,raw in{'usr/bin/cachy-asahi-doctor':b'original-selected','var/lib/pacman/local/protected-1/desc':b'PRIVATE_RAW_DB','home/alarm/data':b'PRIVATE_USER_CONTENT','etc/trust':b'PRIVATE_TRUST_CONTENT'}.items():
   p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
  os.link(root/'home/alarm/data',root/'home/alarm/alias')
 def observed(self,root):return R.observe(root,limits=R.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2),hardlinks='generic-development-internal',absolute_paths=True)
 def target(self,before,after):return G.target(before,after,old_paths=['usr/bin/cachy-asahi-doctor'],new_paths=['usr/bin/cachy-asahi-doctor'],old_database='var/lib/pacman/local/cachy-asahi-doctor-0.1.0-1',new_database='var/lib/pacman/local/cachy-asahi-doctor-0.2.0-1')
 def test_real_selected_payload_only_passes_no_failure_DATA(self):
  import contextlib,io
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.private(root);before=self.observed(root);(root/'usr/bin/cachy-asahi-doctor').write_bytes(b'new-selected');after=self.observed(root);out=io.StringIO()
   with contextlib.redirect_stderr(out):self.assertTrue(self.target(before,after))
   self.assertEqual(out.getvalue(),'');self.assertEqual((root/'home/alarm/data').read_bytes(),b'PRIVATE_USER_CONTENT')
 def test_real_protected_rawDB_content_and_user_mode_diff_sorted_first(self):
  import contextlib,io,json
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.private(root);before=self.observed(root);(root/'var/lib/pacman/local/protected-1/desc').write_bytes(b'changed private DB');(root/'home/alarm/data').chmod(0o600);after=self.observed(root);out=io.StringIO()
   with contextlib.redirect_stderr(out),self.assertRaisesRegex(ValueError,'protected605/unowned node or raw DB changed'):self.target(before,after)
   raw=out.getvalue();row=json.loads(raw.split(' ',1)[1]);self.assertEqual(row['first_key'],'home/alarm/alias');self.assertEqual(row['fields'],['mode']);self.assertEqual(row['categories'],{'PROTECTED_RAW_DB':1,'PROTECTED_PAYLOAD_OR_UNOWNED':2});self.assertFalse(row['acceptance_authority']);self.assertFalse(row['cleanup_authority']);self.assertNotIn('PRIVATE_',raw);self.assertLessEqual(len(raw.encode()),4096+40)
 def test_real_protected_extra_missing_and_rawDB_category(self):
  import contextlib,io,json
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);self.private(root);before=self.observed(root);(root/'var/lib/pacman/local/protected-1/extra').write_bytes(b'PRIVATE_EXTRA');after=self.observed(root);out=io.StringIO()
   with contextlib.redirect_stderr(out),self.assertRaises(ValueError):self.target(before,after)
   row=json.loads(out.getvalue().split(' ',1)[1]);self.assertEqual(row['kind'],'EXTRA');self.assertEqual(row['first_category'],'PROTECTED_RAW_DB');self.assertIsNone(row['before'])
   out=io.StringIO()
   with contextlib.redirect_stderr(out),self.assertRaises(ValueError):self.target(after,before)
   self.assertEqual(json.loads(out.getvalue().split(' ',1)[1])['kind'],'MISSING')
 def test_actual_guard_bare_reraise_and_diagnostic_loss_does_not_pass(self):
  import contextlib,io
  before=dict(nodes={'etc/protected':dict(type='file',mode=420)},complete=True,unsupported_counts={});after=copy.deepcopy(before);after['nodes']['etc/protected']['mode']=384
  with patch.object(G.C,'encoded',side_effect=AssertionError('unused')):
   with contextlib.redirect_stderr(io.StringIO()),self.assertRaisesRegex(ValueError,'protected605/unowned node or raw DB changed'):self.target(before,after)
  original=G.target_failure
  # The actual diagnostic catches projection loss; the caller still raises.
  import json
  with patch.object(json,'dumps',side_effect=OSError('INERT_DATA_LOSS')),contextlib.redirect_stderr(io.StringIO()),self.assertRaisesRegex(ValueError,'protected605/unowned node or raw DB changed'):self.target(before,after)
 def test_whole_target_inverse_and_caps_limits_transaction_held(self):
  import inspect
  raw=inspect.getsource(G.target);wrapped="  try:C.need(left==right,'protected605/unowned node or raw DB changed')\n  except ValueError:\n   target_failure(a,b,selected_node)\n   raise";self.assertEqual(raw.count(wrapped),1)
  before=raw.replace(wrapped,"  C.need(left==right,'protected605/unowned node or raw DB changed')");self.assertNotIn('target_failure(',before)
  import alpm_step as A
  self.assertIn('limits=roots.Limits(deadline=time.monotonic()+90,**C.BOUNDS)',inspect.getsource(A.apply));self.assertEqual(inspect.getsource(A.apply).count(',limits=limits)'),2)

if __name__=='__main__':unittest.main()
