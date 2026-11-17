# SPDX-License-Identifier: MIT
"""Passive source/real synthetic ext4 metadata controls; no actual image/actor."""
import ast,copy,hashlib,importlib.util,json,struct,sys,tempfile,time,types,unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','os.kill','os.killpg','fcntl.flock','resource.setrlimit'):raise AssertionError('no actor/process/socket/syscall/lease in passive controls')
 if event=='open'and args and isinstance(args[0],(str,bytes)):
  name=str(args[0])
  if name.endswith(('.raw','credentials.canonical.private.json','collection.lock'))or 'private-keys-v1.d'in name:raise AssertionError('no actual Raw/private/credential/lease read')
sys.addaudithook(fence)
def module(name):
 s=importlib.util.spec_from_file_location('restored_test_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
R=module('recovery');M=module('inode_metadata');D=module('derive')
OLD={n:(HERE/'predecessor'/n).read_bytes()for n in D.PINS};NEW=D.apply(OLD)
def frame(row):
 stamp=datetime.fromtimestamp(row['mtime'],timezone.utc).strftime('%a %b %e %H:%M:%S %Y');kind='directory'if row['type']=='directory'else'regular';extra=row['mtime_ns']<<2
 return (f'debugfs 1.47.4 (29-Mar-2025)\nInode: {row["inode"]}   Type: {kind}    Mode:  {row["mode"]:04o}   Flags: 0x0\nUser: {row["uid"]}   Group: {row["gid"]}    Size: {row["size"]}\nLinks: {row["links"]}   Blockcount: 8\n atime: 0x{row["mtime"]:08x}:{extra:08x} -- {stamp}\n mtime: 0x{row["mtime"]:08x}:{extra:08x} -- {stamp}\n').encode()
def synthetic(xattr=False,external=False):
 body=bytearray(8*4096);u16=lambda at,v:struct.pack_into('<H',body,at,v);u32=lambda at,v:struct.pack_into('<I',body,at,v)
 for at,v in((1024,8),(1028,8),(1048,2),(1056,8),(1064,8),(1120,0x40)):u32(at,v)
 u16(1080,0xef53);u16(1112,256);u32(4096+8,2)
 rows={}
 for number,(path,kind,mode,size)in enumerate(zip(R.PATHS,('file','directory','file'),(0o644,0o700,0o600),(4,4096,6)),1):
  at=8192+(number-1)*256;u16(at,(0o100000 if kind=='file'else 0o40000)|mode);u32(at+4,size);u16(at+26,1 if kind=='file'else 2);u16(at+128,32)
  for offset in(8,12,16,144):u32(at+offset,100)
  rows[path]=dict(type=kind,mode=mode,uid=0,gid=0,inode=number,links=1 if kind=='file'else 2,size=size,mtime=100,mtime_ns=0,atime=100,atime_ns=0)
 if xattr:
  if external:
   u32(8192+104,3);u32(12288,0xea020000);u32(12296,1);at=12320;base=12288;voff=4000
  else:u32(8192+160,0xea020000);at=8192+164;base=at;voff=60
  struct.pack_into('<BBHIII',body,at,1,1,voff,0,6,0);body[at+16]=ord('x');body[base+voff:base+voff+6]=b'SECRET'
 return body,rows
class Controls(unittest.TestCase):
 def test_NULL_request_refuses_and_three_exact_paths_only(self):
  value=json.loads((HERE/'request.TEMPLATE.json').read_bytes());R.declared(value)
  with self.assertRaisesRegex(ValueError,'fresh explicit Root'):R.plan(value)
  rows=R.fixed_plan();self.assertEqual(len(rows),18);self.assertEqual({r['path']for r in rows if'path'in r},set(R.PATHS));self.assertFalse(any('-w'in r['argv']or r['argv'][0]=='/usr/bin/qemu-system-aarch64'for r in rows))
 def test_other_paths_or_input_graph_resources_refuse(self):
  for path in('root/.ssh','etc/shadow','etc','var/cache/ldconfig/child'):
   with self.assertRaises(ValueError):R.S.request(path)
  value=json.loads((HERE/'request.TEMPLATE.json').read_bytes())
  for field in('Source_lock','baseline','backing','resources'):
   v=copy.deepcopy(value)
   if field=='Source_lock':v[field]['sha256']='a'*64
   elif field=='resources':v[field]['cpus']=2
   else:v[field]['path']='/OTHER'
   with self.subTest(field=field),self.assertRaises(ValueError):R.declared(v)
 def test_stat_realistic_three_types_absence_duplicates_private_frames(self):
  _,rows=synthetic()
  for path,row in rows.items():
   self.assertEqual(R.S.parse_stat(frame(row),path),row)
   missing=b'debugfs 1.47.4 (29-Mar-2025)\n/'+path.encode()+b': File not found by ext2_lookup\n';self.assertIsNone(R.S.parse_stat(missing,path))
   for raw in(frame(row)+b'PRIVATE\n',frame(row)+b'Extended attributes:\n  user.secret = "SECRET"\n',frame(row)+frame(row)):
    with self.assertRaises(ValueError):R.S.parse_stat(raw,path)
  path=R.PATHS[0];raw=frame(rows[path])+b'Extended attributes:\n  user.x (6) = "SECRET"\n'
  self.assertEqual(R.S.parse_stat(raw,path),rows[path]);self.assertEqual(R.S.printed_xattr_count(raw,path),1);self.assertNotIn('SECRET',json.dumps(R.S.parse_stat(raw,path)))
 def test_real_synthetic_ext4_selected_inodes_empty_xattrs(self):
  body,rows=synthetic()
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'inert.img';p.write_bytes(body);result=M.observe(p,rows,time.monotonic()+5)
  self.assertEqual(set(result),set(R.PATHS));self.assertTrue(all(r['xattrs']==dict(count=0,entries=[])for r in result.values()))
 def test_inline_and_external_xattrs_are_hashes_not_names_or_values(self):
  for external in(False,True):
   body,rows=synthetic(True,external)
   with tempfile.TemporaryDirectory()as tmp:
    p=Path(tmp)/'inert.img';p.write_bytes(body);result=M.observe(p,rows,time.monotonic()+5)
   value=result[R.PATHS[0]]['xattrs'];self.assertEqual(value['count'],1);self.assertEqual(value['entries'][0]['value_sha256'],hashlib.sha256(b'SECRET').hexdigest());self.assertNotIn('SECRET',json.dumps(result));self.assertNotIn('user.x',json.dumps(result))
 def test_real_inode_mismatch_alias_deadline_and_corrupt_xattrs_refuse(self):
  body,rows=synthetic(True)
  with tempfile.TemporaryDirectory()as tmp:
   p=Path(tmp)/'inert.img';p.write_bytes(body)
   bad=copy.deepcopy(rows);bad[R.PATHS[0]]['uid']=1
   with self.assertRaisesRegex(ValueError,'typed fields'):M.observe(p,bad,time.monotonic()+5)
   bad=copy.deepcopy(rows);bad[R.PATHS[2]]['inode']=1
   with self.assertRaisesRegex(ValueError,'aliases'):M.observe(p,bad,time.monotonic()+5)
   with self.assertRaisesRegex(ValueError,'budget'):M.observe(p,rows,time.monotonic()-1)
   struct.pack_into('<I',body,8192+164+4,1);p.write_bytes(body)
   with self.assertRaisesRegex(ValueError,'external xattr value inode'):M.observe(p,rows,time.monotonic()+5)
 def test_inode_reader_has_no_inventory_or_payload_call(self):
  tree=ast.parse((HERE/'inode_metadata.py').read_bytes())
  self.assertFalse(any(isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr in('chunks','inventory')for n in ast.walk(tree)))
  with self.assertRaisesRegex(ValueError,'three exact'):M.observe(Path('/NEVER'),{},time.monotonic()+5)
 def test_exact_r90_graph_parser_and_mutation_refusals(self):
  raw=(HERE/'graph_predecessor.py').read_bytes();self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),(8849,'8c7a60ea1261ffe5274067db21d8dd94f9f48f8e93054d4c7e70066483c1022b'))
  rows=json.loads((HERE/'actual-r89-chain.DATA.json').read_bytes());eof=rows[0]['children'][0]['info']['virtual-size'];self.assertEqual(R.G.chain(json.dumps(rows).encode(),eof)['status'],'EXACT_TWO_NODE_CHAIN_METADATA_ONLY')
  for changed in('filename','children','eof','format'):
   value=copy.deepcopy(rows)
   if changed=='filename':value[0]['children'][0]['info']['filename']='/OTHER'
   elif changed=='children':value[0]['children'][0]['info']['children']=[{}]
   elif changed=='eof':value[0]['children'][0]['info']['virtual-size']+=1
   else:value[0]['children'][0]['info']['format']='http'
   with self.subTest(changed=changed),self.assertRaises(ValueError):R.G.chain(json.dumps(value).encode(),eof)
 def test_canonical_summary_closed_outputs_counts_and_no_cause_claim(self):
  baseline=json.loads((HERE/'baseline-public.DATA.json').read_bytes());views={view:{path:dict(row,xattrs=dict(count=0,entries=[]))for path,row in baseline['nodes'].items()}for view in('baseline','restored')}
  comparison=R.compare(views,baseline);self.assertEqual(comparison['restoration_cause'],'UNPROVEN');self.assertIsNone(comparison['Root_acceptance'])
  def summary(views):
   files={name:dict(bytes=1,sha256='a'*64)for name in R.artifact_names(views)}
   for view in views:
    for key,path in(('main',R.FILES[0]),('aux',R.FILES[1])):
     row=views[view][path]
     if row is not None:files[f'{view}-{key}.bin']=dict(bytes=row['size'],sha256=row['sha256'])
   return dict(kind='OBSERVED_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_V2',status='PUBLIC_CACHE_FACTS_ONLY_CAUSE_UNPROVEN',Source_lock=R.SOURCE,request=dict(bytes=1,sha256='b'*64),files=files,cache_observation=R.compare(views,baseline),tools_reverified=True,commands=14+sum(views[v][p]is not None for v in views for p in R.FILES),planned_commands=18,all_tools_naturally_reaped=True,temporary_raw_removed=True,**dict.fromkeys(('Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')))
  v=summary(views);R.validate_summary(v,v['request'],R.SOURCE)
  for change in('raw','cause','body','xattr','count','cap','acceptance'):
   x=copy.deepcopy(v)
   if change=='raw':x['files']['observation.raw']=dict(bytes=1,sha256='a'*64)
   elif change=='cause':x['cache_observation']['restoration_cause']='PROVEN'
   elif change=='body':x['files']['baseline-aux.bin']['sha256']='a'*64
   elif change=='xattr':x['cache_observation']['views']['restored'][R.PATHS[0]]['xattrs']={'count':1,'entries':[{'name':'SECRET'}]}
   elif change=='count':x['commands']=17
   elif change=='cap':x['files']['commands.DATA.json']['bytes']=65537
   else:x['lifecycle_acceptance']=True
   with self.subTest(change=change),self.assertRaises(ValueError):R.validate_summary(x,x['request'],R.SOURCE)
  views['restored'][R.FILES[1]]=None;x=summary(views);self.assertEqual(x['commands'],17);self.assertNotIn('restored-aux.bin',x['files']);R.validate_summary(x,x['request'],R.SOURCE)
  views['baseline'][R.FILES[1]]['sha256']='c'*64;x=summary(views);self.assertIn('sha256',x['cache_observation']['baseline_r76_reference_changed_fields'][R.FILES[1]]);R.validate_summary(x,x['request'],R.SOURCE)
 def test_exact_r2_derivative_core_equalities_and_seven_mounts(self):
  self.assertEqual(D.inverse(OLD,NEW),OLD);a=D.functions(OLD['run_metadata.py'].decode());b=D.functions(NEW['run_metadata.py'].decode())
  for name in D.CORE:self.assertEqual(a[name],b[name],name)
  self.assertEqual(OLD['exec_limiter.py'],NEW['exec_limiter.py'])
  m=types.ModuleType('virtual_observer');m.__file__=str(HERE/'virtual/run_metadata.py');exec(compile(NEW['run_metadata.py'],m.__file__,'exec'),m.__dict__)
  c=dict(nonce='a'*32,qualification_authority=dict(path='/MODEL/request.json',sha256='b'*64));f=dict(input_raw=dict(path='/MODEL/backing'),input_prepared=dict(path='/MODEL/overlay'),input_baseline=dict(path='/MODEL/baseline'),prior_packet=dict(path='/MODEL/code/packet.json'),image=R.IMAGE)
  argv=m.create_argv(c,f,Path('/MODEL/output'),'c'*64,1000);mounts=[argv[i+1]for i,v in enumerate(argv)if v=='--mount'];self.assertEqual(len(mounts),7);self.assertEqual(sum(',readonly'not in v for v in mounts),1)
 def test_corrupt_predecessor_or_new_code_refuses(self):
  value=dict(OLD);value['run_metadata.py']+=b'\n'
  with self.assertRaises(ValueError):D.apply(value)
  value=dict(NEW);value['run_metadata.py']+=b'\n'
  with self.assertRaises(ValueError):D.inverse(OLD,value)
 def test_no_raw_publication_no_alarm_reset_no_semantic_claim(self):
  text=(HERE/'observe_initialized.py').read_text();self.assertIn("p.unlink();need(not p.exists()",text);self.assertNotIn('setitimer(',text);self.assertIn('R.validate_summary',text)
  self.assertLess(text.index("put(scan/(label+'.retirement.json')"),text.index("need(result['passed']"));self.assertIn('PRIOR_LITERAL_STAT_ABSENT',text)
 def test_owned_temporary_conversion_removed_on_natural_refusal(self):
  E=module('observe_initialized')
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp)
   def refused(*args):
    p=root/'inert.img';p.write_bytes(b'INERT');p.rename(root/'observation.raw');raise ValueError('MODEL_REFUSAL')
   with patch.object(E,'OUT',root),patch.object(E,'_execute',side_effect=refused):
    with self.assertRaisesRegex(ValueError,'MODEL_REFUSAL'):E.execute('/NEVER','0'*64)
   self.assertFalse((root/'observation.raw').exists())
if __name__=='__main__':unittest.main(verbosity=2)
