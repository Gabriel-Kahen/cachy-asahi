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


# The product's original watch function owns its PROCESS_EXIT handler and Notify.
# These commands only launch/register a real child and observe caller/retirement.
BACKGROUND_COMMAND=("command sleep 8 &; set -g __fdm_job $last_pid; caa_done_watch $__fdm_job; "
    "set -g __fdm_watch_status $status; test $__fdm_watch_status -eq 0; or exit 93; "
    "functions --query __done_job_$__fdm_job; or exit 94; "
    "printf '\\nFDM_WATCH_%s_%s\\n' $__fdm_job $__fdm_watch_status")
RETIRE_COMMAND=("not functions --query __done_job_$__fdm_job; or exit 95; "
    "test -d /proc/$__fdm_job; and exit 96; "
    "printf '\\nFDM_BG_RETIRED_%s\\n' $__fdm_job")


def watched_pid(raw):
    rows=re.findall(rb'(?:^|[\r\n])FDM_WATCH_([1-9][0-9]{0,9})_0(?=[\r\n]|$)',raw)
    need(len(rows)==1,'one successful real watch registration required');return int(rows[0])


def retired_pid(raw):
    rows=re.findall(rb'(?:^|[\r\n])FDM_BG_RETIRED_([1-9][0-9]{0,9})(?=[\r\n]|$)',raw)
    need(len(rows)==1,'one exact watched job retirement marker required');return int(rows[0])


def child_identity(pid,parent):
    path=Path('/proc')/str(pid)
    raw=(path/'stat').read_bytes();need(len(raw)<=4096,'bounded child identity required')
    fields=raw[raw.rfind(b')')+2:].split()
    args=(path/'cmdline').read_bytes();need(len(args)<=4096,'bounded child arguments required')
    exe=os.readlink(path/'exe')
    need(int(fields[1])==parent and int(fields[2])==pid and exe=='/usr/bin/sleep' and
         args.split(b'\0') in ([b'sleep',b'8',b''],[b'/usr/bin/sleep',b'8',b'']),
         'actual single-process owned sleep job required')
    return dict(pid=pid,parent_pid=parent,process_group=pid,start_ticks=int(fields[19]),executable=exe,argv=['sleep','8'])


def verify_background(watch,fish_pid,raw,retired):
    need(type(watch) is dict and type(watch.get('registration_status')) is int and watch['registration_status']==0 and watch.get('handler_registered') is True and watch.get('caller_before_completion') is True,
         'actual watched handler registration required')
    child=watch.get('child');need(type(child) is dict and type(child.get('pid')) is int and child['pid']>0 and
         child['pid']!=fish_pid and child.get('parent_pid')==fish_pid and child.get('process_group')==child['pid'] and
         type(child.get('start_ticks')) is int and child['start_ticks']>0 and child.get('executable')=='/usr/bin/sleep' and
         child.get('argv')==['sleep','8'],'actual owned watched job identity required')
    need(watched_pid(raw)==child['pid'] and retired_pid(raw)==child['pid'],
         'actual watch registration/retirement bytes required')
    markers=[('FDM_WATCH_'+str(child['pid'])+'_0').encode(),b'FDM_PROMPT_2_0',b'FDM_CONT_0',('FDM_BG_RETIRED_'+str(child['pid'])).encode()]
    need(all(m in raw for m in markers) and [raw.index(m) for m in markers]==sorted(raw.index(m) for m in markers),
         'watch, prompt, independent caller and retirement order differs')
    need(type(retired) is dict and retired.get('child')==child and retired.get('handler_absent') is True and
         retired.get('pid_absent') is True and retired.get('process_group_absent') is True,
         'owned watched handler/job retirement required')


class BackgroundTerminal(Terminal):
    def __init__(self,env):
        self.job=None;self.retired=None;super().__init__(env)

    def start(self,outcome):
        need(outcome==0,'one positive background case only')
        self.send(BACKGROUND_COMMAND+'\n');self.wait(b'FDM_PROMPT_2_0',15)
        pid=watched_pid(bytes(self.output));self.job=child_identity(pid,self.process.pid)
        self._caller=super().continuation(outcome)
        need(child_identity(pid,self.process.pid)==self.job,'job completed before independent Fish continuation')
        self.watch=dict(child=self.job,registration_status=0,handler_registered=True,caller_before_completion=True)
        self._caller.update(command=BACKGROUND_COMMAND,watch=self.watch)

    def continuation(self,outcome):
        need(outcome==0,'one positive background continuation only');return self._caller

    def finish(self):
        self.send(RETIRE_COMMAND+'\n');self.wait(('FDM_BG_RETIRED_'+str(self.job['pid'])).encode(),5)
        need(not (Path('/proc')/str(self.job['pid'])).exists(),'watched job PID remained')
        try:os.killpg(self.job['process_group'],0)
        except ProcessLookupError:pass
        else:raise ValueError('watched job process group remained')
        self.retired=dict(child=self.job,handler_absent=True,pid_absent=True,process_group_absent=True)
        result=super().finish();result['watch_retirement']=self.retired;return result

    def close(self):
        if self.closed:return
        first=None
        try:
            # Registration may fail before its marker is read. Discover only this
            # Fish's one exact sleep8 child while the parent is still owned/live.
            if self.job is None and self.process.poll() is None:
                children=Path('/proc')/str(self.process.pid)/'task'/str(self.process.pid)/'children'
                raw=children.read_bytes();need(len(raw)<=4096,'bounded owned-child discovery required')
                found=[]
                for token in raw.split():
                    try:found.append(child_identity(int(token),self.process.pid))
                    except (ValueError,FileNotFoundError,ProcessLookupError):pass
                need(len(found)<=1,'ambiguous owned sleep child');self.job=found[0] if found else None
            if self.job and (Path('/proc')/str(self.job['pid'])).exists():
                need(child_identity(self.job['pid'],self.process.pid)==self.job,'owned background PID reused')
                os.kill(self.job['pid'],signal.SIGTERM)
                until=time.monotonic()+2
                while (Path('/proc')/str(self.job['pid'])).exists() and time.monotonic()<until:self.pump()
                if (Path('/proc')/str(self.job['pid'])).exists():os.kill(self.job['pid'],signal.SIGKILL)
        except BaseException as error:first=error
        try:super().close()
        except BaseException as error:
            if first is None:first=error
        if self.job:
            until=time.monotonic()+2
            while (Path('/proc')/str(self.job['pid'])).exists() and time.monotonic()<until:time.sleep(.02)
            if (Path('/proc')/str(self.job['pid'])).exists() and first is None:first=ValueError('owned watched job survived Fish cleanup')
        if first is not None:raise first
