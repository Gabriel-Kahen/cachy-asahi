# SPDX-License-Identifier: MIT
"""Passive x86 evdev release counting and read-only password readiness."""
import errno,os,struct,termios
EVENT=struct.Struct('@llHHi')
class Releases:
 def __init__(self):self.pending=b'';self.count=0
 def consume(self,data):
  if len(data)>65536:raise ValueError('input observation byte bound')
  data=self.pending+data;complete=len(data)//EVENT.size*EVENT.size;counts=[]
  for offset in range(0,complete,EVENT.size):
   _seconds,_micros,kind,_ignored_code,value=EVENT.unpack_from(data,offset)
   if kind==1 and value==0:
    self.count+=1
    if self.count>46:raise ValueError('unexpected extra keyboard release; no authentication retry')
    counts.append(self.count)
  self.pending=data[complete:];return counts
 def report(self):return {'release_count':self.count,'raw_events_or_keycodes_exported':False,'event_grab':False}
def tty_attributes(path='/dev/tty1'):
 fd=None
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOCTTY|os.O_NONBLOCK|os.O_CLOEXEC);return termios.tcgetattr(fd),None
 except (OSError,termios.error)as error:
  number=getattr(error,'errno',None)or error.args[0]
  if number in {errno.EIO,errno.ENXIO}:return None,number
  raise
 finally:
  if fd is not None:os.close(fd)
def password_ready(text,attributes,count):
 return attributes is not None and count==8 and 'login: builder'in text and 'Password:'in text and not(attributes[3]&termios.ECHO)
def key_events(code):
 if code not in list('abcdefghijklmnopqrstuvwxyz0123456789')+['ret','ctrl','alt','f1']:raise ValueError('fixed QMP key alphabet required')
 return [{'type':'key','data':{'down':down,'key':{'type':'qcode','data':code}}}for down in [True,False]]
