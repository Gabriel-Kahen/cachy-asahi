# SPDX-License-Identifier: MIT
"""Create source-owned TEST journal DATA using only explicitly synthetic inputs."""
import hashlib,json,re,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ENV=dict(PATH='/usr/bin:/bin',LC_ALL='C',SYSTEMD_LOG_TARGET='console',SYSTEMD_JOURNAL_REMOTE_CONFIG_FILE='/dev/null')
IMPORTER=Path('/usr/lib/systemd/systemd-journal-remote');CTL=Path('/usr/bin/journalctl')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def generate():
 out=HERE/'fixture';out.mkdir(mode=0o700)
 authored=[]
 for i,boot in enumerate(('1'*32,'2'*32)):
  for transport in ('kernel','stdout'):
   authored.append({'__REALTIME_TIMESTAMP':str(1700000000000000+i),'__MONOTONIC_TIMESTAMP':str(i+1),'_BOOT_ID':boot,'_MACHINE_ID':'a'*32,'_HOSTNAME':'synthetic-boot-fixture','_UID':'65534','_TRANSPORT':transport,'PRIORITY':'3','MESSAGE':f'SYNTHETIC TEST ONLY {boot} {transport}'})
 export=''.join(''.join(k+'='+v+'\n'for k,v in row.items())+'\n'for row in authored).encode();(out/'journal.export').write_bytes(export)
 argv=[str(IMPORTER),'--output='+str(out/'system.journal'),'--split-mode=none','--compress=no','--seal=no','-']
 p=subprocess.run(argv,input=export,capture_output=True,env=ENV,timeout=10);assert p.returncode==0,p.stderr
 q=subprocess.run([str(CTL),'--directory='+str(out),'--system','--output=json','--all','--no-pager','--quiet'],capture_output=True,env=ENV,timeout=10);assert q.returncode==0,q.stderr
 rows=[json.loads(line)for line in q.stdout.splitlines()];assert len(rows)==4
 for sequence,(actual,expected) in enumerate(zip(rows,authored),1):
  assert set(actual)==set(expected)|{'__CURSOR','__SEQNUM','__SEQNUM_ID'},actual
  assert {k:v for k,v in actual.items()if not k.startswith('__SEQNUM')and k!='__CURSOR'}==expected,actual
  assert type(actual['__CURSOR'])is str and len(actual['__CURSOR'])<=256
  assert actual['__SEQNUM']==str(sequence) and re.fullmatch('[0-9a-f]{32}',actual['__SEQNUM_ID']) and actual['__SEQNUM_ID']==rows[0]['__SEQNUM_ID']
 save(out/'authored-records.json',authored);save(out/'decoded-records.json',rows)
 versions={}
 for name,tool in [('importer',IMPORTER),('journalctl',CTL)]:
  r=subprocess.run([str(tool),'--version'],capture_output=True,env=ENV,timeout=10);assert r.returncode==0;versions[name]=dict(path=str(tool),binary=pin(tool.read_bytes()),version_stdout=r.stdout.decode(),version_stderr=r.stderr.decode())
 save(out/'generation.json',dict(scope='SYNTHETIC_PRIVATE_JOURNAL_FIXTURE_DATA_ONLY_NEVER_REAL_BOOT_CRASH_AUTHORITY',input=pin(export),generator=pin(Path(__file__).read_bytes()),tools=versions,argv=argv,environment=ENV,stdout=pin(p.stdout),stderr=p.stderr.decode(),journal=pin((out/'system.journal').read_bytes()),decoded=pin(q.stdout),decoded_fields='EXACT_AUTHORED_FIELDS_PLUS_ONLY_GENERATED_CURSOR_AND_SEQUENCE_METADATA',records=4,host_history_read=False,network=False))
 print(json.dumps(dict(status='PASS_EXACT_SYNTHETIC_DECODED_RECORDS',journal=pin((out/'system.journal').read_bytes()))))
if __name__=='__main__':generate()
