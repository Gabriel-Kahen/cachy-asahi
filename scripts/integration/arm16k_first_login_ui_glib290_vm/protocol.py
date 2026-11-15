# SPDX-License-Identifier: MIT
"""Unchanged ARM PAM/keyboard journey plus a mandatory independent UI frame."""
import hashlib,importlib.util,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
CONSOLE_UNITS=('Owned ARM16K trusted UI lifecycle after package bootstrap','Owned ARM16K UI result observer')
CONSOLE_SGR=(b'\x1b[0;31m',b'\x1b[0;1;31m',b'\x1b[0m')

def systemd_status_line(line):
 if not 0<len(line)<=256:return False
 if line.startswith(b'\x1bM\r\x1b[K'):line=line[6:]
 elif line.startswith(b'\x1bM\x1b[K'):line=line[5:]
 for sgr in CONSOLE_SGR:line=line.replace(sgr,b'')
 try:text=line.decode('utf-8','strict')
 except UnicodeDecodeError:return False
 match=re.fullmatch(r'\[([* ]{6})\] \(([12]) of ([12])\) A start job is running for(.+) \((?:[0-9]min )?[0-5]?[0-9]s / (?:[0-9]min )?[0-5]?[0-9]s\)',text)
 if not match or not 1<=match[1].count('*')<=3 or int(match[2])>int(match[3]):return False
 unit=match[4]
 return any(unit==' '+name or(unit.startswith('…')and 8<=len(unit[1:])<=len(name)and name.endswith(unit[1:]))for name in CONSOLE_UNITS)

def frame_bytes(data,nonce,label):
 assert isinstance(data,bytes)and len(data)<=1024**2 and re.fullmatch('[0-9a-f]{32}',nonce)and label in ['SEAT_SESSION','UI_SESSION']
 lines=[line.rstrip(b'\r')for line in data.split(b'\n')];markers={};expected=nonce.encode()
 for index,line in enumerate(lines):
  if line.startswith((b'SEAT_SESSION_BEGIN ',b'SEAT_SESSION_END ',b'UI_SESSION_BEGIN ',b'UI_SESSION_END ')):
   match=re.fullmatch(rb'(SEAT_SESSION|UI_SESSION)_(BEGIN|END) ([0-9a-f]{32})',line);assert match and match[3]==expected,'foreign or malformed nonce frame marker';markers.setdefault((match[1],match[2]),[]).append(index)
 assert all(len(rows)==1 for rows in markers.values()),'duplicate nonce frame marker'
 spans=[]
 for family in [b'SEAT_SESSION',b'UI_SESSION']:
  left=markers.get((family,b'BEGIN'),[]);right=markers.get((family,b'END'),[])
  if left:spans.append((left[0],right[0]if right else len(lines)))
 for index,line in enumerate(lines):
  if any(left<index<right for left,right in spans):continue
  if line.lstrip().startswith(b'{'):raise ValueError('unframed trailing JSON object')
  if line.lstrip().startswith(b'['):
   try:outside=json.loads(line.decode('utf-8','strict'))
   except (ValueError,UnicodeDecodeError):continue
   if isinstance(outside,list):raise ValueError('unframed trailing JSON array')
 begin=(label+'_BEGIN '+nonce).encode();end=(label+'_END '+nonce).encode();starts=markers.get((label.encode(),b'BEGIN'),[]);ends=markers.get((label.encode(),b'END'),[]);assert len(starts)==len(ends)==1 and starts[0]<ends[0],'missing or reversed nonce frame'
 body=lines[starts[0]+1:ends[0]];assert sum(len(line)+1 for line in body)<128*1024,'bounded nonce frame body required'
 payload=None;statuses=0
 for line in body:
  if not line.strip():continue
  if line.lstrip().startswith(b'{'):
   assert payload is None,'extra JSON in nonce frame';value=json.loads(line.decode('utf-8','strict'));assert isinstance(value,dict);payload=line
  elif systemd_status_line(line):statuses+=1;assert statuses<=16,'bounded console status interleaving required'
  else:raise ValueError('unrecognized '+label+' frame line bytes='+str(len(line))+' sha256='+hashlib.sha256(line).hexdigest())
 assert payload is not None,'one complete JSON object required'
 return begin+b'\n'+payload+b'\n'+end+b'\n'

def parse_ui(data,nonce):
 return json.loads(frame_bytes(data,nonce,'UI_SESSION').split(b'\n')[1].decode('utf-8','strict'))
def guard_pattern(nonce,pattern):
 assert re.fullmatch('[0-9a-f]{32}',nonce);return rb'(?m:^UI_HOLD '+nonce.encode()+rb' \{[^\r\n]{0,4096}\}\r?\n)|(?:'+pattern+b')'
def bind(arm):
 original=load('UI_original_ARM_protocol',arm/'frozen/arm16k_virtio_seat/protocol.py');original.INPUT=load('UI_corrected_modern_input',arm/'input_seat.py');result=load('UI_upper_result',HERE/'result.py')
 frozen_parse=original.parse
 # The unchanged lower validator receives the exact JSON bytes in a strict frame.
 original.parse=lambda data,nonce:frozen_parse(frame_bytes(data,nonce,'SEAT_SESSION'),nonce)
 class Serial(original.Serial):
  def until(self,pattern):
   match=super().until(guard_pattern(self.nonce,pattern))
   if match.group(0).startswith(b'UI_HOLD '):raise original.SeatHold('ARM UI observer/root stage held; sanitized frame retained')
   return match
 class Adapter:
  pass
 def journey(serial,rpc,password):
  proof=original.journey(serial,rpc,password);ui=parse_ui(bytes(serial.data),serial.nonce);combined=result.join(proof['seat'],ui,serial.nonce);return {**proof,'ui_journey':ui,'ui_status':combined['status']}
 Adapter.Serial=Serial;Adapter.journey=staticmethod(journey);Adapter.redact_serial=original.redact_serial;return Adapter
