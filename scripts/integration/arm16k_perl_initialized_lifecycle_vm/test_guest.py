# SPDX-License-Identifier: MIT
"""Real ordinary temporary-tree controls; no guest, raw input or actors."""
import base64,hashlib,os,shlex,stat,subprocess,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
PATHS=('etc/.pwd.lock','etc/.updated','etc/audisp','etc/audit/plugins.d','etc/audit/rules.d','etc/ld.so.cache','etc/os-release','etc/udev/hwdb.bin','etc/vconsole.conf','etc','etc/audit','etc/udev','root','root/.ssh')
KINDS=('f','f','d','d','d','f','l','f','f','d','d','d','d','d')
MODES=(0o600,0o644,0o755,0o750,0o755,0o644,0o777,0o444,0o644,0o755,0o755,0o755,0o700,0o700)
NONCE='a'*32

def descriptor(prefix):
 rows=[]
 for p,kind in zip(PATHS,KINDS):
  q=prefix/p;s=q.lstat();payload='-'
  if kind=='f':payload=hashlib.sha256(q.read_bytes()).hexdigest()
  if kind=='l':payload=base64.b64encode(os.readlink(q).encode()).decode()
  rows.append(f'N {p} {s.st_ino} {s.st_nlink} {kind} {stat.S_IMODE(s.st_mode):o} {s.st_uid} {s.st_gid} {s.st_size} {s.st_mtime_ns//10**9}.{s.st_mtime_ns%10**9:09d} {payload}\n')
 return ''.join(rows)

class Guest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.d=self.root/'case';self.d.mkdir()
  for p,kind,mode in sorted(zip(PATHS,KINDS,MODES),key=lambda r:len(Path(r[0]).parts)):
   q=self.root/p;q.parent.mkdir(exist_ok=True,parents=True)
   if kind=='d':q.mkdir(exist_ok=True);q.chmod(mode)
   elif kind=='l':q.symlink_to('../usr/lib/os-release')
   else:q.write_bytes(('original '+p+'\n').encode());q.chmod(mode)
  self.context=self.d/'preboot-context.json';self.context.write_bytes(b'{"kind":"TEST_ONLY"}\n');self.context.chmod(0o644)
  self.desc=self.d/'initialized-state.tsv';self.desc.write_text('PERL5423_INITIALIZED_STATE_V1 '+NONCE+' '+hashlib.sha256(self.context.read_bytes()).hexdigest()+'\n'+descriptor(self.root));self.desc.chmod(0o600)
  self.sha=hashlib.sha256(self.desc.read_bytes()).hexdigest()
 def run_shell(self,body):
  prefix='set -euo pipefail\nsource '+shlex.quote(str(HERE/'guest/initialized-state.sh'))+'\nD='+shlex.quote(str(self.d))+'\nnonce='+NONCE+'\n'
  return subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',prefix+body],capture_output=True,text=True)
 def capture(self):return '_initialized_capture '+shlex.quote(str(self.root))+' '+str(os.getuid())+' '+self.sha+'\n'
 def test_preserves_existing_nodes_and_repeated_capture_cannot_reset(self):
  before=descriptor(self.root);r=self.run_shell(self.capture()+'_initialized_capture "$initialized_prefix" '+str(os.getuid())+' '+self.sha+'\n_initialized_guard\n')
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(before,descriptor(self.root))
 def test_changed_public_bytes_refuse_without_repair(self):
  path=self.root/'etc/ld.so.cache';r=self.run_shell(self.capture()+'printf changed > '+shlex.quote(str(path))+'\n_initialized_guard\n')
  self.assertNotEqual(r.returncode,0);self.assertEqual(path.read_bytes(),b'changed')
 def test_changed_parent_mtime_refuses(self):
  r=self.run_shell(self.capture()+'touch -m --date=@1000 '+shlex.quote(str(self.root/'etc'))+'\n_initialized_guard\n');self.assertNotEqual(r.returncode,0)
 def test_same_bytes_new_inode_refuses(self):
  path=self.root/'etc/.updated';r=self.run_shell(self.capture()+'cp -- '+shlex.quote(str(path))+' '+shlex.quote(str(self.d/'replacement'))+'\nmv -- '+shlex.quote(str(self.d/'replacement'))+' '+shlex.quote(str(path))+'\n_initialized_guard\n');self.assertNotEqual(r.returncode,0)
 def test_nonempty_ssh_refuses_before_xattrs_without_name_or_body(self):
  secret='NEVER_EMIT_PRIVATE_CHILD';(self.root/'root/.ssh'/secret).write_text('NEVER_READ_PRIVATE_BODY')
  r=self.run_shell('_initialized_attrs() { printf XATTR_WAS_VISITED >&2;return 2; }\n'+self.capture())
  self.assertNotEqual(r.returncode,0);self.assertNotIn(secret,r.stdout+r.stderr);self.assertNotIn('NEVER_READ_PRIVATE_BODY',r.stdout+r.stderr);self.assertNotIn('XATTR_WAS_VISITED',r.stderr)
 def test_guest_public_entry_rejects_test_prefix(self):
  r=self.run_shell('initialized_capture '+shlex.quote(str(self.root))+'\n');self.assertNotEqual(r.returncode,0)
 def test_cold_descriptor_cannot_authorize(self):
  self.desc.write_text('PERL5423_PREBOOT_ETC_V2 '+NONCE+'\n');self.sha=hashlib.sha256(self.desc.read_bytes()).hexdigest();r=self.run_shell(self.capture());self.assertNotEqual(r.returncode,0)
 def test_mutating_xattr_refuses(self):
  try:os.setxattr(self.root/'etc/.updated','user.test',b'first')
  except OSError as e:self.skipTest(str(e))
  # Refresh only test fixture descriptor after the pre-capture xattr setup.
  r=self.run_shell(self.capture()+'setfattr -n user.test -v second '+shlex.quote(str(self.root/'etc/.updated'))+'\n_initialized_guard\n');self.assertNotEqual(r.returncode,0)

if __name__=='__main__':unittest.main()
