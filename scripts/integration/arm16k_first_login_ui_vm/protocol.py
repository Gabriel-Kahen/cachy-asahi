# SPDX-License-Identifier: MIT
"""Unchanged ARM PAM/keyboard journey plus a mandatory independent UI frame."""
import importlib.util,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def parse_ui(data,nonce):
 assert re.fullmatch('[0-9a-f]{32}',nonce)and len(data)<=1024**2;text=data.decode(errors='replace').replace('\r','');begin='UI_SESSION_BEGIN '+nonce+'\n';end='UI_SESSION_END '+nonce;assert text.count(begin)==text.count(end)==1
 body=text.split(begin,1)[1].split(end,1)[0].strip();assert len(body)<128*1024;return json.loads(body)
def guard_pattern(nonce,pattern):
 assert re.fullmatch('[0-9a-f]{32}',nonce);return rb'(?m:^UI_HOLD '+nonce.encode()+rb' \{[^\r\n]{0,4096}\}\r?\n)|(?:'+pattern+b')'
def bind(arm):
 original=load('UI_original_ARM_protocol',arm/'frozen/arm16k_virtio_seat/protocol.py');result=load('UI_upper_result',HERE/'result.py')
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
