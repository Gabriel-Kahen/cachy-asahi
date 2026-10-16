# SPDX-License-Identifier: MIT
"""Real interactive Fish on an owned PTY, using the inherited managed bus."""
import errno,fcntl,hashlib,os,pty,re,resource,select,signal,subprocess,termios,time
from pathlib import Path

COMMANDS={0:'command sleep 5.25',7:"command sh -c 'sleep 5.25; exit 7'"}
INIT='''set -g fish_history ''
set -g __fdm_prompt 0
source /usr/share/cachy-asahi/fish-done/opt-in.fish
functions --query __done_ended __done_notify caa_done_watch caa_done_disable; or exit 91
test (command --search notify-send) = /usr/bin/notify-send; or exit 92
function fish_prompt
    set -l outcome $status
    set -g __fdm_prompt (math $__fdm_prompt + 1)
    printf '\\nFDM_PROMPT_%s_%s\\n' $__fdm_prompt $outcome
end
function __fdm_continue
    printf '\\nFDM_CONT_%s\\n' $argv[1]
end
'''


def need(ok,why):
    if not ok:raise ValueError(why)


class Terminal:
    def __init__(self,env):
        need(os.geteuid()==23001 and env.get('PATH')=='/usr/bin' and
             env.get('DBUS_SESSION_BUS_ADDRESS')=='unix:path=/run/user/23001/bus', 'real managed Fish environment required')
        self.master,slave=pty.openpty();self.output=bytearray();self.closed=False
        def child():
            os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            resource.setrlimit(resource.RLIMIT_CPU,(10,10))
            resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
        try:
            self.process=subprocess.Popen(['/usr/bin/fish','--no-config','--private','--interactive','--init-command',INIT],
                stdin=slave,stdout=slave,stderr=slave,env=dict(env,TERM='xterm'),cwd=env['HOME'],preexec_fn=child)
        except BaseException:
            os.close(self.master);self.closed=True;raise
        finally:os.close(slave)
        try:self.wait(b'FDM_PROMPT_1_',15)
        except BaseException:
            self.close();raise

    def send(self,text):
        raw=text.encode();need(len(raw)<=4096 and os.write(self.master,raw)==len(raw),'bounded Fish PTY write required')

    def pump(self):
        if select.select([self.master],[],[],.02)[0]:
            try:raw=os.read(self.master,4096)
            except OSError as error:
                if error.errno!=errno.EIO:raise
                raw=b''
            self.output.extend(raw);need(len(self.output)<=65536,'Fish PTY output cap')
            if b'\x1b[0c' in raw:self.send('\x1b[?1;2c')
            if b'\x1b[6n' in raw:self.send('\x1b[1;1R')

    def wait(self,marker,seconds):
        until=time.monotonic()+seconds
        while marker not in self.output:
            need(self.process.poll() is None,'interactive Fish exited before continuation')
            need(time.monotonic()<until,'Fish interactive continuation deadline');self.pump()

    def start(self,outcome):
        need(outcome in COMMANDS,'fixed foreground case required');self.send(COMMANDS[outcome]+'\n')

    def continuation(self,outcome):
        self.wait(('FDM_PROMPT_2_'+str(outcome)).encode(),15)
        self.send('__fdm_continue $status\n');self.wait(('FDM_CONT_'+str(outcome)).encode(),5)
        self.wait(b'FDM_PROMPT_3_',5)
        return dict(pid=self.process.pid,command=COMMANDS[outcome],outcome=outcome,prompt_status=outcome,caller_continuation=outcome)

    def finish(self):
        self.send('exit 0\n');until=time.monotonic()+5
        while self.process.poll() is None:
            need(time.monotonic()<until,'normal Fish exit deadline');self.pump()
        need(self.process.wait(timeout=1)==0,'normal owned Fish exit required')
        raw=bytes(self.output);return dict(exit=0,pty_bytes=len(raw),pty_sha256=hashlib.sha256(raw).hexdigest(),pty_base64=__import__('base64').b64encode(raw).decode())

    def close(self):
        if self.closed:return
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid,signal.SIGTERM)
                try:self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=2)
            try:os.killpg(self.process.pid,0)
            except ProcessLookupError:pass
            else:raise ValueError('owned Fish process group remains')
        finally:os.close(self.master);self.closed=True
