# SPDX-License-Identifier: MIT
"""Bounded live busctl observer; captures real messages without replacing notify-send."""
import base64,hashlib,os,selectors,signal,subprocess,time
import observation as O


class Monitor:
    def __init__(self,env):
        self.argv=['/usr/bin/busctl','--user','--auto-start=no','--json=short','monitor','org.freedesktop.Notifications']
        self.process=subprocess.Popen(self.argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        self.selector=selectors.DefaultSelector();self.parts=[bytearray(),bytearray()];self.closed=False
        try:
            for i,pipe in enumerate((self.process.stdout,self.process.stderr)):
                os.set_blocking(pipe.fileno(),False);self.selector.register(pipe,selectors.EVENT_READ,i)
        except BaseException:
            self.close();raise

    def pump(self):
        for key,_ in self.selector.select(.02):
            raw=os.read(key.fd,4096)
            if not raw:self.selector.unregister(key.fileobj);continue
            self.parts[key.data].extend(raw);O.need(sum(map(len,self.parts))<=262144,'real D-Bus monitor output cap')

    def rows(self):
        O.need(self.process.poll() is None,'D-Bus monitor exited prematurely');self.pump()
        raw=bytes(self.parts[0]);return O.messages(raw[:raw.rfind(b'\n')+1])

    def finish(self):
        O.need(self.process.poll() is None,'monitor not live at owned stop')
        os.killpg(self.process.pid,signal.SIGINT);until=time.monotonic()+5
        while self.process.poll() is None or self.selector.get_map():
            O.need(time.monotonic()<until,'monitor owned stop/drain deadline');self.pump()
        code=self.process.wait(timeout=1);O.need(code in (0,-signal.SIGINT),'unexpected D-Bus monitor stop')
        raw=bytes(self.parts[0]);O.messages(raw)
        return dict(pid=self.process.pid,argv=self.argv,exit=code,stop_signal='SIGINT',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),raw_base64=base64.b64encode(raw).decode(),stderr=bytes(self.parts[1]).decode('utf-8','replace'))

    def close(self):
        if self.closed:return
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid,signal.SIGTERM)
                try:self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=2)
            try:os.killpg(self.process.pid,0)
            except ProcessLookupError:pass
            else:raise ValueError('owned D-Bus monitor group remains')
        finally:
            self.selector.close();self.process.stdout.close();self.process.stderr.close();self.closed=True
