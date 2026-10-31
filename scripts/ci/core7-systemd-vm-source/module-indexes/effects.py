# SPDX-License-Identifier: MIT
"""Exact original tmpfiles nodes and regenerated caches, never prefix exemptions."""
import base64,re,shlex,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,initramfs as J
GENERATED={J.ARTIFACT:J.GENERATE,'usr/lib/udev/hwdb.bin':('/usr/bin/systemd-hwdb','--usr','update'),'var/lib/systemd/catalog/database':('/usr/bin/journalctl','--update-catalog')}
ACCOUNTS=tuple('etc/'+n+s for n in('passwd','shadow','group','gshadow')for s in('','-'))
AUX='var/cache/ldconfig/aux-cache'

def account_ids(raw,group=False):
 rows={}
 for line in raw.decode().splitlines():
  fields=line.split(':');C.need(len(fields)==(4 if group else 7)and fields[0]and fields[2].isdigit(),'complete fixed passwd/group records');C.need(fields[0]not in rows,'unique account name');rows[fields[0]]=int(fields[2])
 return rows

def tmpfiles_rules(raw,users,groups):
 """Only literal source-listed nodes qualify. Recursive/glob/dynamic rules grant nothing."""
 C.need(type(raw)is bytes and len(raw)<=1024**2,'bounded complete actual --cat-config output');result={}
 for line in raw.decode().splitlines():
  if not line.strip()or line.lstrip().startswith('#'):continue
  fields=shlex.split(line,comments=True);C.need(len(fields)>=2,'typed tmpfiles source row');kind,path=fields[:2]
  # Nonliteral and recursive rules remain in source DATA, but cannot authorize
  # any changed full-graph node. Unexpected effects therefore refuse.
  if not path.startswith('/')or any(c in path for c in('%','*','?','[','\\')):continue
  name=path[1:].rstrip('/');
  if not name:continue
  C.need(name and all(x not in('','.','..')for x in name.split('/')),'literal tmpfiles path')
  if name.split('/')[0]in('run','tmp','proc','sys','dev'):continue
  fields+=['-']*(7-len(fields));kind=kind.rstrip('!+-=~^$');mode,user,group=fields[2:5];create_only=any(v.startswith(':')for v in(mode,user,group));mode,user,group=(v.removeprefix(':')for v in(mode,user,group))
  if kind not in('d','D','v','q','Q','f','F','L','L?')or mode=='-'and kind not in('L','L?'):continue
  if kind in('L','L?'):
   if len(fields)<7 or fields[6]=='-'or '%'in fields[6]:continue
   node=dict(type='symlink',mode=0o777,uid=0,gid=0,target=fields[6])
  else:
   if not re.fullmatch('[0-7]{3,4}',mode):continue
   def uid(value,table):
    if value=='-':return 0
    if value.isdigit():return int(value)
    C.need(value in table,'source tmpfiles named account exists');return table[value]
   node=dict(type='directory'if kind in('d','D','v','q','Q')else'file',mode=int(mode,8),uid=uid(user,users),gid=uid(group,groups))
   if node['type']=='file':
    if fields[6]not in('-',''):continue
    node.update(C.pin(b''))
  if create_only:node=dict(node,create_only=True)
  C.need(name not in result or result[name]==node,'unambiguous exact tmpfiles node');result[name]=node
 return result

def changes(core,before,after,packages,versions,accounts,cache,generated,tmpfiles,shells):
 """Every allowed nonpackage node is joined to a complete typed proof first."""
 core.F.initialized_accounts(accounts['before'],accounts['after'])
 for name in ACCOUNTS:
  for label,nodes in(('before',before),('after',after)):
   row=accounts[label][name];C.need(nodes.get(name)==dict(type='file',mode=0o600 if 'shadow'in name else 0o644,uid=0,gid=0,**row['file']),'complete account graph/raw join '+name)
 core.F.check_record(cache,after)
 old=[p for p in packages if p['metadata']['pkgname'][0]in core.C.REPLACED and p['metadata']['pkgver'][0]==core.C.states()[0][p['metadata']['pkgname'][0]]];new=[p for p in packages if p['metadata']['pkgname'][0]in core.C.NAMES and p['metadata']['pkgver'][0]==core.C.profile()['packages'][p['metadata']['pkgname'][0]]['version']];core.T.configuration(after,before,old,new,True)
 allowed=set(ACCOUNTS)|{AUX}|{n+s for p in packages for n in p['metadata'].get('backup',[])for s in('.pacnew','.pacsave')};required={}
 C.need(set(generated)==set(GENERATED),'all three exact source-defined generated artifact/cache receipts')
 for name,proof in generated.items():
  C.need(set(proof)=={'before','first','second','command'}and proof['command']['argv']==list(GENERATED[name]),'exact generated data command role')
  C.command(proof['command']);C.need(proof['first']==proof['second']==after.get(name)and proof['first']['type']=='file'and proof['first']['uid']==proof['first']['gid']==0,'whole regenerated cache idempotence and graph join');allowed.add(name)
 users=account_ids(base64.b64decode(accounts['after']['etc/passwd']['data'],validate=True));groups=account_ids(base64.b64decode(accounts['after']['etc/group']['data'],validate=True),True)
 rules=tmpfiles_rules(base64.b64decode(tmpfiles['data'],validate=True),users,groups);C.need(C.pin(base64.b64decode(tmpfiles['data'],validate=True))==tmpfiles['pin'],'whole source-listed tmpfiles policy')
 for name in set(before)|set(after):
  if before.get(name)==after.get(name)or name not in rules:continue
  rule=dict(rules[name]);create_only=rule.pop('create_only',False);C.need(not create_only or name not in before,'create-only tmpfiles rule cannot authorize modifying an existing node '+name)
  C.need(after.get(name)==rule,'literal tmpfiles effect exact mode/owner/content '+name);allowed.add(name);required[name]=rule
 old=base64.b64decode(shells['before'],validate=True);new=base64.b64decode(shells['after'],validate=True);line=b'/usr/bin/systemd-home-fallback-shell\n'
 C.need(new==old or line not in old.splitlines(keepends=True)and new==old+line,'only exact authenticated scriptlet shells append')
 C.need(before.get('etc/shells')==dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(old))and after.get('etc/shells')==dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(new)),'whole original user shell configuration');allowed.add('etc/shells')
 result=core.C.changes(before,after,packages,versions,allowed)
 return dict(status='PASS_EXACT_PACKAGE_ACCOUNT_GENERATED_CACHE_AND_LITERAL_TMPFILES_EFFECTS',whole_graph=result,literal_tmpfiles=required,no_prefix_exemptions=True,configuration='WHOLE_ORIGINAL_ACTIVE_USER_AND_KNOWN_SIDECAR_BODY')
