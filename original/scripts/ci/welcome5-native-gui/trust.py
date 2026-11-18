# SPDX-License-Identifier: MIT
"""Only disposable TEST trust for the explicitly pinned GUI input packages."""
import json,re,subprocess
from pathlib import Path

ROOT=Path('/tmp/products');HOME=Path('/tmp/management-trust')
def need(ok,message):
    if not ok:raise ValueError(message)
def install():
    need(not HOME.exists(),'fresh disposable TEST trust required');HOME.mkdir(mode=0o700)
    rows=json.loads((ROOT/'trust.json').read_text());need(type(rows)is list and 1<=len(rows)<=3,'finite TEST key roles required')
    gpg=['/usr/bin/gpg','--batch','--no-options','--no-auto-key-retrieve','--homedir',str(HOME)]
    def run(args,data=None):
        p=subprocess.run(args,input=data,capture_output=True,timeout=20);need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=65536,'TEST trust command refused');return p.stdout
    for row in rows:
        need(set(row)=={'key','signer'}and re.fullmatch('[A-Z0-9._-]{1,80}\\.asc',row['key'],re.I)and re.fullmatch('[0-9A-F]{40}',row['signer']),'explicit TEST key/fingerprint required')
        key=ROOT/row['key'];raw=run(gpg+['--with-colons','--import-options','show-only','--import',str(key)]).decode()
        need(row['signer']in [line.split(':')[9]for line in raw.splitlines()if line.startswith('fpr:')],'TEST key fingerprint differs')
        run(gpg+['--import',str(key)]);run(gpg+['--import-ownertrust'],(row['signer']+':6:\n').encode())
    Path('/tmp/management.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(HOME)+'\n')
if __name__=='__main__':install()
