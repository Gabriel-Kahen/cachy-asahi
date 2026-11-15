# SPDX-License-Identifier: MIT
import re,socket,time
MAX_SERIAL=1024**2
class Serial:
 def __init__(self,stream,deadline):self.stream=stream;self.deadline=deadline;self.data=bytearray();self.offset=0
 def until(self,pattern):
  regex=re.compile(pattern)
  while True:
   match=regex.search(bytes(self.data),self.offset)
   if match:self.offset=match.end();return match
   remaining=self.deadline-time.monotonic()
   if remaining<=0:raise TimeoutError('bounded reference serial deadline')
   self.stream.settimeout(min(.5,remaining))
   try:chunk=self.stream.recv(65536)
   except socket.timeout:continue
   if not chunk:raise EOFError('reference serial closed before expected frame')
   self.data.extend(chunk)
   if len(self.data)>MAX_SERIAL:raise ValueError('reference serial byte limit')
 def send(self,data):self.stream.sendall(data)
