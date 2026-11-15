#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain actual archive BUILDINFO and real signature results; no source claims."""
import hashlib,json,subprocess,sys,tarfile
from pathlib import Path
cache=Path(sys.argv[1]);refs=json.loads(Path('/opt/package-refs.json').read_text());facts=[]
for ref in refs:
 p=cache/ref['filename'];assert p.stat().st_size==ref['bytes']
 with p.open('rb')as f:assert hashlib.file_digest(f,'sha256').hexdigest()==ref['sha256']
 result=subprocess.run(['gpg','--batch','--no-options','--homedir','/etc/pacman.d/gnupg','--no-auto-key-retrieve','--status-fd','1','--verify',str(p)+'.sig',str(p)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=20)
 valid=[line for line in result.stdout.decode().splitlines()if line.startswith('[GNUPG:] VALIDSIG ')];assert len(valid)==1
 with tarfile.open(p)as t:
  build=t.extractfile('.BUILDINFO').read(1024**2).decode();info=t.extractfile('.PKGINFO').read(1024**2).decode()
  values={line.split(' = ',1)[0]:line.split(' = ',1)[1]for line in info.splitlines()if' = 'in line}
  assert values['pkgname']==ref['name']and values['pkgver']==ref['version']
 facts.append({**ref,'VALIDSIG':valid[0],'BUILDINFO':build,'PKGINFO':info,'source_recipe_correspondence':'BUILDINFO recipe digest retained; source recipe/reproduction acceptance not established'})
Path('/opt/tool-provenance.json').write_text(json.dumps({'packages':facts,'keyring_sha256':hashlib.sha256(Path('/usr/share/pacman/keyrings/archlinux.gpg').read_bytes()).hexdigest(),'scope':'mathematical signatures under retained official-image keyring, not production freshness/source/legal/native acceptance'},indent=2)+'\n')
