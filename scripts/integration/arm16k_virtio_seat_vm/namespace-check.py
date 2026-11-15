#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed guest-only actual namespace ownership/bytes proof after ordinary ALPM."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
D=Path('/var/lib/arm16k-virtio-seat')
def main():
 assert __debug__ and sys.flags.isolated and os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and Path('/proc/1/comm').read_text().strip()=='systemd' and not Path('/.dockerenv').exists()
 expected={'usr/bin/python3','usr/bin/pkaction','usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy','usr/lib/python3.14/site-packages/gi/__init__.py','usr/lib/girepository-1.0/Gio-2.0.typelib','usr/lib/girepository-1.0/GLib-2.0.typelib'}
 source=D/'required-namespace.json';assert source.is_file() and not source.is_symlink() and source.stat().st_size<=65536
 rows=json.loads(source.read_text());assert set(rows)==expected
 for name,row in rows.items():
  p=Path('/')/name;r=row['payload'];info=p.lstat();assert (stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)==(r['mode'],r['uid'],r['gid'])
  owner=subprocess.run(['/usr/bin/pacman','-Qoq','--',str(p)],capture_output=True,timeout=5);assert owner.returncode==0 and owner.stdout.decode().strip()==row['owner'] and len(owner.stdout)<=1024
  if r['type']=='0':
   assert stat.S_ISREG(info.st_mode) and info.st_size==r['bytes'] and info.st_size<=16*1024**2
   with p.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==r['sha256']
  else:assert r['type']=='2' and stat.S_ISLNK(info.st_mode) and os.readlink(p)==r['link']
 print(json.dumps({'status':'PASS_FIXED_GUEST_NAMESPACE_ONLY','files':len(rows)}))
if __name__=='__main__':main()
