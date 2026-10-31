# SPDX-License-Identifier: MIT
"""Account and raw-cache refusal controls; no package/native actors."""
import base64,copy,importlib.util,json,os,struct,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C,fixture as F,audio_aux as A

def cache(rows):
 strings=bytearray(b'\0');records=[]
 for key,flags,name,isa in rows:
  offset=0 if name is None else len(strings)
  if name is not None:strings.extend(name+b'\0')
  records.append(A.ENTRY.pack(*key,flags,offset,isa)+b'\0'*4)
 return A.MAGIC+struct.pack('<II',len(records),len(strings))+b''.join(records)+bytes(strings)
def record(raw):
 key=A.parse(raw)[0][0];info=[key[3],key[0],0o100755,0,0,1,key[2],1,key[1]*10**9];node=dict(type='file',mode=0o755,uid=0,gid=0,bytes=key[2],sha256='a'*64);return dict(raw=C.pin(raw),data=base64.b64encode(raw).decode(),libraries=[dict(key=list(key),files=[dict(path='usr/lib/libtest.so',identity=info,node=node)])])
def graph(r):return{'usr/bin/ldconfig':dict(type='file',mode=0o755,uid=0,gid=0,bytes=865664,sha256=A.HELPER_SHA256),F.AUX:dict(type='file',mode=0o600,uid=0,gid=0,**r['raw']),'usr/lib/libtest.so':r['libraries'][0]['files'][0]['node'],'etc/passwd':dict(type='file',mode=0o644,uid=0,gid=0,bytes=3,sha256='b'*64),'boot/Image':dict(type='file',sha256='c'*64)}
class Controls(unittest.TestCase):
 def test_cache_all_named_bytes_and_current_live_keys_required(self):
  raw=cache([((5,7,9,11),771,b'libtest.so',0)]);r=record(raw);nodes=graph(r);self.assertEqual(F.check_record(r,nodes),raw);self.assertEqual(F.cache_pair(r,r,nodes),dict(kind='RAW_EQUAL'))
  for edit in(lambda v:v['libraries'].clear(),lambda v:v['libraries'][0]['files'][0]['identity'].__setitem__(8,99),lambda v:v['libraries'][0]['files'][0]['node'].update(sha256='f'*64),lambda v:v['libraries'][0]['files'][0].update(path='etc/passwd')):
   v=copy.deepcopy(r);edit(v)
   with self.assertRaises(ValueError):F.check_record(v,nodes)
  changed=record(cache([((5,7,9,11),771,b'other.so',0)]))
  with self.assertRaises(ValueError):F.cache_pair(r,changed,graph(changed))
 def test_only_proved_cache_can_change_accounts_and_protected_nodes_stay_exact(self):
  r=record(cache([((5,7,9,11),771,b'libtest.so',0)]));after=graph(r);before=copy.deepcopy(after);before[F.AUX]['sha256']='d'*64
  with self.assertRaisesRegex(ValueError,'protected'):C.changes(before,after,[],[])
  self.assertTrue(F.changes(before,after,[],[],(),r)['unrelated_complete_nodes_preserved'])
  for name in('etc/passwd','boot/Image'):
   bad=copy.deepcopy(after);bad[name]['sha256']='e'*64
   with self.assertRaisesRegex(ValueError,'protected'):F.changes(before,bad,[],[],(),r)
 def test_raw_account_line_preservation_and_exact_backup(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);(root/'etc').mkdir()
   for name in F.ACCOUNTS:(root/name).write_bytes(b'root:x:0:0:root:/root:/bin/bash\n')
   before=F.accounts(root)
   for n in('passwd','shadow','group','gshadow'):
    (root/('etc/'+n+'-')).write_bytes((root/('etc/'+n)).read_bytes());(root/('etc/'+n)).write_bytes((root/('etc/'+n)).read_bytes()+b'polkitd:!:102:102:service:/:/usr/bin/nologin\n')
   after=F.accounts(root);self.assertEqual(F.initialized_accounts(before,after)['added']['etc/passwd'],['polkitd'])
   for edit in(lambda v:v['etc/passwd']['records'].update(root=C.pin(b'changed')),lambda v:v['etc/passwd-'].update(file=C.pin(b'changed')),lambda v:v['etc/passwd'].update(data=base64.b64encode(b'foreign:!:1\n').decode())):
    bad=copy.deepcopy(after);edit(bad)
    with self.assertRaises(ValueError):F.initialized_accounts(before,bad)
 def test_exact_127_commands_original_signature_and_stage_commands_held(self):
  # Test source-only shape with inert index; no command is executed.
  index=dict(test_signer='A'*40);rows=C.expected_commands(index);self.assertEqual(len(rows),127);self.assertEqual(sum(r[-1]=='/usr/bin/ldconfig'for r in rows),10);self.assertEqual(sum(F.BASE_SHELL in r for r in rows),4);self.assertTrue(all('262-1'==r[-1]==r[-2]for r in rows if F.BASE_SHELL in r));self.assertEqual(rows[0][0],'/usr/bin/gpg');self.assertEqual(rows[-1],['/usr/bin/gpgconf','--homedir','/tmp/core-public-gpg','--kill','all'])
 def test_whole_baseline_driver_uses_original_scriptlet_body_and_retires_lease(self):
  spec=importlib.util.spec_from_file_location('_new_container',Path(__file__).with_name('container.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);(root/'tmp').mkdir();calls=[];raw=b'ORIGINAL_SOURCE_ONLY_NOT_EXECUTED'
   def call(argv):self.assertEqual((root/'tmp/core-systemd.install').read_bytes(),raw);calls.append(argv)
   with patch.object(F,'SCRIPT_PIN',C.pin(raw)):m.baseline_step(types.SimpleNamespace(call=call),root,{'systemd-original':dict(observed=dict(data={'.INSTALL':raw}))},'262-1');self.assertEqual(calls,[F.baseline_argv(root,'262-1')]);self.assertFalse((root/'tmp/core-systemd.install').exists())
   with self.assertRaises(RuntimeError),patch.object(F,'SCRIPT_PIN',C.pin(raw)):m.baseline_step(types.SimpleNamespace(call=lambda _:(_ for _ in()).throw(RuntimeError())),root,{'systemd-original':dict(observed=dict(data={'.INSTALL':raw}))},'262-1')
   self.assertFalse((root/'tmp/core-systemd.install').exists())
if __name__=='__main__':unittest.main(verbosity=2)
