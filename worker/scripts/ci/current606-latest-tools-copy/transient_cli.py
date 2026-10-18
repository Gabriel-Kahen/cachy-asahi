# SPDX-License-Identifier: MIT
"""Real Apps7 CLI on transient605; no original606-domain fixture15 credit."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
CONTEXT=Path('/var/tmp/caa-latest605-cli')
def need(ok,why):
 if not ok:raise ValueError(why)
def call(argv,seconds):
 r=subprocess.run(argv,stdin=0,capture_output=True,timeout=seconds);need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=128*1024,'actual Apps605 readonly command');return r
def main():
 need(len(sys.argv)==3 and os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64'and sys.argv[2]=='apps7','ordinary native Apps7 transient605 only')
 work=Path(sys.argv[1]);need(work.is_relative_to(CONTEXT/'outputs'),'owned fixed output');r=call(['/usr/bin/cachy-asahi-apps','--help'],15);need(b'inventory'in r.stdout,'actual help inventory route')
 p=work/'actual-inventory.json';r=call(['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(p)],40);receipt=json.loads(r.stdout);raw=p.read_bytes();s=p.lstat()
 need(0<len(raw)<=16*1024**2 and receipt['applied']=='NOT_APPLIED'and receipt['sha256']==hashlib.sha256(raw).hexdigest()and s.st_uid==os.geteuid()and s.st_nlink==1 and stat.S_ISREG(s.st_mode),'own actual inventory snapshot')
 rows=json.loads(raw)['packages'];inventory={r['name']:r['version']for r in rows};need(len(rows)==len(inventory)==605 and inventory['cachy-asahi-apps']=='0.1.0-7'and 'cachy-asahi-welcome'not in inventory and inventory['cachy-asahi-repository-runtime']=='0.1.0-1','actual transient605 Apps7 inventory')
 need(p.lstat()==s,'snapshot identity drift');p.unlink()
 print(json.dumps(dict(status='PASS_ACTUAL_APPS605_READONLY_CLI_ONLY',recipe_role='apps7',CLI=2,inventory_count=605,inventory_sha256=hashlib.sha256(raw).hexdigest(),inventory_versions_sha256=hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode()).hexdigest(),installed_controls='NOT_RUN_ORIGINAL15_REQUIRES606_DOMAIN',applied='NOT_APPLIED'),sort_keys=True))
if __name__=='__main__':main()
