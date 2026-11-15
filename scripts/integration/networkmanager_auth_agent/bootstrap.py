#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private TEST shadow storage; no PAM/rule modification or extra capabilities."""
import importlib.util,json,os,shutil,socket,time
from pathlib import Path
I=Path('/opt/nm-private-bus')
if not(__debug__ and os.geteuid()==0 and os.environ.get('CACHY_ASAHI_PAM_ACTOR')=='1'and Path('/.dockerenv').is_file()):raise RuntimeError('owned PAM actor only')
rows=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
assert all(int(rows[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and rows['NoNewPrivs'].strip()=='1'
assert {x[1]for x in socket.if_nameindex()}=={'lo'}
assert any(l.split(' - ')[0].split()[4]=='/'and 'ro'in l.split(' - ')[0].split()[5].split(',')for l in Path('/proc/self/mountinfo').read_text().splitlines())
p=Path('/run/auth-credentials');p.mkdir(mode=0o700);shutil.copyfile('/opt/TEST-original-shadow',p/'shadow');(p/'shadow').chmod(0o600)
Path('/run/NEED_CREDENTIAL').touch();until=time.monotonic()+30
while not Path('/run/CREDENTIAL_READY').exists()and time.monotonic()<until:time.sleep(.05)
assert Path('/run/CREDENTIAL_READY').exists(),'private credential provisioning deadline'
s=importlib.util.spec_from_file_location('pam_actor_fixture',I/'fixture.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
raise SystemExit(m.main())
