#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite real-TTY own-action credential gate and terminal HOLD short circuit."""
import json,re,socket,time
OWN='org.freedesktop.NetworkManager.settings.modify.own'
ADMIN='org.freedesktop.NetworkManager.settings.modify.system'
class JourneyHold(RuntimeError):pass
class RefusedPrompt(RuntimeError):pass
def plain(data):
 text=data.decode(errors='replace').replace('\r','')
 text=re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)','',text)
 return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
class Gate:
 def __init__(self,nonce,agent_sha):self.nonce=nonce;self.agent_sha=agent_sha;self.responded=set();self.seen_prompts=set();self.events=[];self.identity=None;self.journey=None
 def observe(self,data):
  text=plain(data);begin='NM_SESSION_BEGIN '+self.nonce+'\n';end='\nNM_SESSION_END '+self.nonce
  if begin in text and end in text:
   assert text.count(begin)==1 and text.count(end)==1
   body=text.split(begin,1)[1].split(end,1)[0];assert len(body)<256*1024
   self.journey=json.loads(body)
   if self.journey.get('status')!='PASS_X86_REAL_LOGIN_OWN_PROFILE_AND_DENIALS_ONLY':raise JourneyHold('complete NM HOLD frame: '+str(self.journey.get('failure',{}))[:1024])
  ready=list(re.finditer(r'(?m)^NM_AUTH_READY '+self.nonce+r' (\{[^\n]*\})\n',text))
  assert len(ready)<=1,'duplicate credential identity boundary'
  if not ready:return [] # Initial serial PAM login remains the completed driver's job.
  identity=json.loads(ready[0].group(1));assert identity['uid']==identity['gid']==1000 and identity['tty']=='/dev/ttyS0'
  assert identity['pid']==identity['bus_pid']and type(identity['pid'])is int and identity['pid']>1
  assert identity['agent_pid']!=identity['pid']and identity['agent_pid']>1 and identity['start_time']>0 and identity['agent_registered']is True and identity['session_active']is True
  assert identity['agent_sha256']==self.agent_sha and re.fullmatch('[A-Za-z0-9_-]{1,64}',identity['session_id'])
  self.identity=identity;tail=text[ready[0].end():];answers=[]
  operations=list(re.finditer(r'(?m)^NM_AUTH_OPERATION '+self.nonce+r' ([a-z-]+)\n',tail))
  for index,prompt in enumerate(re.finditer(r'(?m)^Password:[ \t]*',tail)):
   if index in self.seen_prompts:continue
   self.seen_prompts.add(index)
   prior=[m for m in operations if m.end()<=prompt.start()]
   if not prior:raise RefusedPrompt('password prompt outside a fixed operation')
   operation=prior[-1].group(1);chunk=tail[prior[-1].end():prompt.start()]
   headers=re.findall(r'(?m)^==== AUTHENTICATING FOR ([A-Za-z0-9_.-]+) ====\n',chunk)
   names=re.findall(r'(?m)^Authenticating as: ([^\n]+)\n',chunk)
   if len(headers)!=1 or len(names)!=1:raise RefusedPrompt('non-exact authentication header/identity')
   action=headers[0];name=names[0]
   event={'operation':operation,'action':action,'identity':name,'password_sent':False}
   if operation in {'foreign-delete','system-delete'}and action==ADMIN:
    self.events.append(event);continue # Guest normally cancels the real admin request.
   if operation not in {'own-create','own-edit','own-cleanup'}or action!=OWN or name!='NM session TEST user (builder)':raise RefusedPrompt('credential refused for non-own action/identity')
   if operation in self.responded or len(self.responded)>=3:raise RefusedPrompt('no repeated password attempts for a fixed own operation')
   self.responded.add(operation);event['password_sent']=True;self.events.append(event);answers.append(operation)
  return answers
 def report(self):return {'scope':'additional real own-action TTY responses only; initial PAM login separate','identity':self.identity,'events':self.events,'responses':len(self.responded),'admin_or_unknown_credentials_sent':False}
def extension(base,nonce,secret,agent_sha,instances):
 class ChallengeSerial(base):
  def __init__(self,stream,deadline):super().__init__(stream,deadline);self.gate=Gate(nonce,agent_sha);instances.append(self)
  def until(self,pattern):
   regex=re.compile(pattern)
   while True:
    for operation in self.gate.observe(bytes(self.data)):self.send(secret+b'\n')
    match=regex.search(bytes(self.data),self.offset)
    if match:self.offset=match.end();return match
    remaining=self.deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('bounded NM session serial deadline')
    self.stream.settimeout(min(.5,remaining))
    try:chunk=self.stream.recv(65536)
    except socket.timeout:continue
    if not chunk:raise EOFError('NM reference serial closed before expected frame')
    self.data.extend(chunk)
    if len(self.data)>1024**2:raise ValueError('NM reference serial byte limit')
 return ChallengeSerial
