#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Single private TEST account provisioning or UID1000 secret handoff via stdin."""
import hashlib,json,os,pwd,subprocess,sys
from pathlib import Path
if not(__debug__ and os.environ.get('CACHY_ASAHI_PAM_ACTOR')=='1'and Path('/.dockerenv').is_file()):raise RuntimeError('owned credential fixture only')
secret=sys.stdin.buffer.read(129);assert 32<=len(secret)<=128 and all(32<x<127 for x in secret)
if os.geteuid()==0:
 p=Path('/run/auth-credentials/shadow');old=p.read_text().splitlines();newhash=subprocess.run(['/usr/bin/openssl','passwd','-6','-stdin'],input=secret,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=5).stdout.decode().strip();assert newhash.startswith('$6$')
 changed=[];new=[]
 for line in old:
  row=line.split(':')
  if row[0]=='builder':
   assert pwd.getpwnam('builder').pw_uid==1000;row[1]=newhash;changed.append('builder')
  new.append(':'.join(row))
 assert changed==['builder'];p.write_text('\n'.join(new)+'\n');p.chmod(0o600);Path('/run/CREDENTIAL_READY').touch()
 files=[p for d in ['/etc/pam.d','/usr/lib/pam.d']for p in Path(d).glob('*')if p.is_file()]
 print(json.dumps({'private_TEST_account_uid':1000,'changed_only_password_field_for':'builder','PAM_policy_pins':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in files},'password_and_hash_exported':False}))
elif os.geteuid()==os.getegid()==1000:
 p=Path('/home/UID1000/TEST-password');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(secret)
 print('{"private_TEST_credential_stored":true,"exported":false}')
else:raise RuntimeError('unexpected credential role')
