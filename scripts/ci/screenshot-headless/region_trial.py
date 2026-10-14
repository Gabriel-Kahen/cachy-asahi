# SPDX-License-Identifier: MIT
"""Actual region follow-up inside the registered contained runtime only."""
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import secrets
import signal
import socket
import stat
import struct
import subprocess
import resource
import time
from PIL import Image

SOURCE=Path('/source');EVIDENCE=Path('/evidence');HOME=Path('/tmp/screenshot-home')
CODE=SOURCE/'scripts/ci/screenshot-headless'
HELPER=SOURCE/'packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot'
X,Y,W,H=31,47,73,59
RGB=(18,52,86)

def need(ok,reason):
    if not ok:raise ValueError(reason)

def packet_read(conn,deadline):
    def exact(n):
        out=bytearray()
        while len(out)<n:
            left=deadline-time.monotonic();need(left>0,'custody read deadline');conn.settimeout(left)
            chunk=conn.recv(n-len(out));need(chunk,'custody channel EOF');out.extend(chunk)
        return bytes(out)
    size=struct.unpack('!I',exact(4))[0];need(0<size<=2048,'custody packet bound')
    return json.loads(exact(size))

def packet_send(conn,data):
    raw=json.dumps(data,sort_keys=True,separators=(',',':')).encode()
    need(0<len(raw)<=2048,'custody packet bound');conn.sendall(struct.pack('!I',len(raw))+raw)

class Custody:
    """Single helper/wrapper rendezvous; actual slurp is a direct runner child."""
    def __init__(self,end):
        self.path=Path('/tmp/screenshot-runtime/region-custody.sock');self.end=min(end,time.monotonic()+20)
        self.token=secrets.token_hex(16);self.conn=None;self.node=None;self.used=False;self.listener=None
        root=self.path.parent.lstat()
        need(stat.S_ISDIR(root.st_mode) and stat.S_IMODE(root.st_mode)==0o700 and root.st_uid==os.getuid(),'private custody runtime')
        need(not self.path.exists(),'fresh custody path')
        try:
            self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.listener.bind(str(self.path));self.node=self.path.lstat();self.path.chmod(0o600);self.listener.listen(1)
        except BaseException:self.close();raise
    def left(self):
        n=self.end-time.monotonic();need(n>0,'custody deadline');return min(n,3)
    def accept(self,helper):
        need(not self.used,'single-use custody handshake');self.used=True
        self.listener.settimeout(self.left());self.conn,_=self.listener.accept();self.listener.close()
        self.conn.settimeout(self.left())
        pid,uid,gid=struct.unpack('=iii',self.conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        hello=packet_read(self.conn,min(self.end,time.monotonic()+3))
        need(type(hello) is dict and set(hello)=={'schema','token','pid','ppid','args'},'custody exact hello schema')
        need(type(hello['schema']) is int and hello['schema']==1 and hello['token']==self.token,'owned custody nonce')
        need(type(hello['pid']) is type(hello['ppid']) is int and hello['pid']==pid and hello['ppid']==helper.pid and uid==os.getuid() and gid==os.getgid(),'actual wrapper/helper custody credentials')
        need(hello['args']==['-f','%x,%y %wx%h'] and helper.poll() is None,'held helper slurp args/lifetime')
        self.wrapper_pid=pid;self.uid=uid;self.gid=gid
    def alive(self):
        need(self.conn is not None,'custody handshake required')
        timeout=self.conn.gettimeout();self.conn.setblocking(False)
        try:
            try:data=self.conn.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)
            except BlockingIOError:return
        finally:self.conn.settimeout(timeout)
        need(False,'custody wrapper EOF' if data==b'' else 'unsolicited custody packet')
    def finish(self,code,body):
        need(type(code) is int and len(body)<=128,'real slurp return bound')
        self.alive();self.conn.settimeout(self.left())
        packet_send(self.conn,{'schema':1,'code':code,'stdout_hex':body.hex()})
    def close(self):
        if self.conn is not None:self.conn.close()
        if self.listener is not None:self.listener.close()
        if self.node is not None:
            now=self.path.lstat()
            need(stat.S_ISSOCK(now.st_mode) and now.st_uid==os.getuid() and (now.st_dev,now.st_ino)==(self.node.st_dev,self.node.st_ino),'exact owned custody socket retirement')
            self.path.unlink();self.node=None

def reaped_child(process):
    need(process.returncode is not None,'direct slurp has not exited')
    try:os.waitpid(process.pid,os.WNOHANG)
    except ChildProcessError:
        return {'pid':process.pid,'owner_pid':os.getpid(),'returncode':process.returncode,'direct_child_waited':True,'absent_from_parent_child_table':True}
    raise ValueError('slurp direct child still waitable; retirement not proven')

def start_slurp(client,owned):
    need(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,'default SIGCHLD needed for direct reaping evidence')
    old_mask=None
    def limits():
        signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
        resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,2*1024**2))
    trace=os.open(EVIDENCE/'slurp-protocol.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        geometry=os.open(EVIDENCE/'slurp-geometry.stdout',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGHUP})
            try:
                process=subprocess.Popen(['/usr/bin/slurp','-f','%x,%y %wx%h'],env={**client,'PATH':'/usr/bin:/bin','WAYLAND_DEBUG':'client'},stdin=subprocess.DEVNULL,stdout=geometry,stderr=trace,start_new_session=True,preexec_fn=limits)
                owned.append(('region-slurp',process))
            finally:signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
            return process
        finally:os.close(geometry)
    finally:os.close(trace)

def stimulus():
    """Displayed test input only. The desired solid patch occurs exactly once."""
    image=Image.new('RGB',(320,240),(101,67,33))
    image.paste(RGB,(X,Y,X+W,Y+H))
    image.paste((211,7,19),(3,9,19,26));image.paste((9,37,223),(287,199,311,221))
    return image

class Watch:
    def __init__(self,path,parser,guard=None):self.path=path;self.parser=parser;self.offset=0;self.pending=b'';self.guard=guard
    def update(self):
        if not self.path.exists():return
        node=self.path.lstat()
        need(stat.S_ISREG(node.st_mode) and node.st_uid==os.getuid() and stat.S_IMODE(node.st_mode)==0o600 and self.offset<=node.st_size<=2*1024**2,'private bounded trace file')
        with self.path.open('rb') as f:f.seek(self.offset);chunk=f.read(2*1024**2-self.offset)
        self.offset+=len(chunk);self.pending+=chunk
        lines=self.pending.split(b'\n');self.pending=lines.pop();need(len(self.pending)<=4096,'bounded partial trace line')
        for line in lines:self.parser.line(line.decode('ascii'))
    def until(self,condition,process,deadline):
        deadline=min(deadline,time.monotonic()+5)
        while time.monotonic()<deadline:
            if self.guard is not None:self.guard()
            self.update()
            if condition():return
            need(process.poll() is None,'owned protocol actor exited before evidence')
            time.sleep(.01)
        raise ValueError('bounded real protocol readiness timeout')

def exercise(sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record):
    Pointer=runpy.run_path(str(CODE/'region_pointer.py'))['Pointer']
    Trace=runpy.run_path(str(CODE/'region_trace.py'))['Trace']
    pointer=None;background=None;helper=None;slurp=None;custody=None;first=None;result={};wire_trace=[]
    held={str(p):file_record(p) for p in shots.iterdir()}
    def preserved():
        for name,record in held.items():need(file_record(Path(name))==record,'all previous actual PNGs preserved')
    def captured(response):
        need(response.returncode==0 and response.stderr==b'','actual test-input full capture')
        names=response.stdout.decode().splitlines();need(len(names)==1,'one actual full PNG path')
        path=Path(names[0]);need(path.parent==shots and path.is_absolute() and str(path) not in held,'one new private direct child capture')
        record=file_record(path);need(record['mode']==0o600 and record['uid']==os.getuid() and record['bytes']<=8*1024**2,'actual PNG private bounds')
        preserved();held[str(path)]=record;previous[str(path)]=record;return path,record
    try:
        expected=stimulus();path=HOME/'region-stimulus-NOT-CAPTURE.png'
        with path.open('xb') as f:expected.save(f,format='PNG')
        path.chmod(0o600)
        result['displayed_test_input']={'path':str(path),'role':'STIMULUS_NOT_CAPTURE','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'unique_patch':[X,Y,W,H],'rgb':list(RGB)}
        background=spawn(['/usr/bin/swaybg','-o',output,'-i',str(path),'-m','stretch'],{**client,'WAYLAND_DEBUG':'client'},'region-background')
        (EVIDENCE/'region-background.log').chmod(0o600)
        bg_trace=Trace('wallpaper',0);bg_watch=Watch(EVIDENCE/'region-background.log',bg_trace)
        bg_watch.until(lambda:bg_trace.committed,background,end)
        response=call(['/usr/bin/python3','-I','-B',str(HELPER),'full','--directory',str(shots)],client)
        full,full_record=captured(response)
        data=full.read_bytes();checker=runpy.run_path(str(CODE/'validate_png.py'))
        need(checker['chunks'](data,320,240)=='RGB','strict captured full pattern PNG structure')
        with Image.open(io.BytesIO(data)) as image:image.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load();need(image.mode=='RGB' and image.size==(320,240) and image.tobytes()==expected.tobytes(),'every actual full stimulus pixel/origin')
        result['full_pattern_capture']={'path':str(full),**full_record,'pixels_checked':320*240}
        pointer=Pointer(client['WAYLAND_DISPLAY'],min(end,time.monotonic()+20),sway.pid,wire_trace)
        pointer.position(X,Y)
        custody=Custody(end)
        env={**client,'PATH':str(CODE/'region-tools')+':/usr/bin:/bin','REGION_CUSTODY_TOKEN':custody.token,'REGION_CUSTODY_PARENT_PID':str(os.getpid())}
        helper=spawn(['/usr/bin/python3','-I','-B',str(HELPER),'region','--directory',str(shots)],env,'region-helper')
        custody.accept(helper);slurp=start_slurp(client,owned)
        result['slurp_custody']={'owner_pid':os.getpid(),'direct_slurp_pid':slurp.pid,'wrapper_pid':custody.wrapper_pid,'helper_pid':helper.pid,'peer_uid':custody.uid,'peer_gid':custody.gid,'single_use':True,'actual_args':['/usr/bin/slurp','-f','%x,%y %wx%h']}
        def guard():
            custody.alive();need(helper.poll() is None,'held helper lost during selection');need(slurp.poll() is None,'direct actual slurp lost during selection')
        trace=Trace('selection',3);watch=Watch(EVIDENCE/'slurp-protocol.log',trace,guard)
        watch.until(lambda:trace.committed,helper,end)
        pointer.position(X,Y)
        watch.until(lambda:trace.ready(X,Y),helper,end)
        entered=trace.enter
        pointer.button(1);watch.until(lambda:trace.buttons==[1],helper,end)
        pointer.position(X+W-1,Y+H-1)
        endpoint=(Decimal(X+W-1)+Decimal('.5'),Decimal(Y+H-1)+Decimal('.5'))
        watch.until(lambda:endpoint in trace.motions,helper,end)
        pointer.button(0)
        until=min(end,custody.end,time.monotonic()+8)
        while slurp.poll() is None:
            custody.alive();need(helper.poll() is None,'helper lost before real slurp exit')
            need(time.monotonic()<until,'bounded direct slurp exit');time.sleep(.01)
        need(slurp.wait(timeout=1)==0,'actual direct slurp failed')
        result['slurp_reaping']=reaped_child(slurp)
        watch.update()
        need(trace.buttons==[1,0] and endpoint in trace.motions,'actual press/motion/release sequence completed')
        need(trace.retired,'actual selection overlay retirement sync')
        result['selection_retirement']={'layer_surface':trace.layer_id,'surface':trace.surface,'sync_callback':trace.retirement_callback,'acknowledged':trace.retirement_ack,'trace_bytes':watch.offset}
        geometry=(EVIDENCE/'slurp-geometry.stdout').read_bytes()
        need(geometry==f'{X},{Y} {W}x{H}'.encode(),'real slurp inclusive endpoint geometry')
        pointer.close();result['pointer_retired_before_capture']=pointer.capabilities
        custody.finish(slurp.returncode,geometry)
        helper.wait(timeout=max(.01,min(8,end-time.monotonic())));watch.update()
        need(helper.returncode==0 and trace.buttons==[1,0] and endpoint in trace.motions,'actual press/motion/release sequence completed')
        names=(EVIDENCE/'region-helper.log').read_text().splitlines();need(len(names)==1,'one actual region helper stdout path')
        crop=Path(names[0]);need(crop.parent==shots and crop.is_absolute() and str(crop) not in held,'new direct region PNG')
        record=file_record(crop);need(record['mode']==0o600 and record['uid']==os.getuid(),'private actual region capture')
        checked=call(['/usr/bin/python3','-I','-B',str(CODE/'validate_png.py'),str(crop),'--root',str(shots),'--width',str(W),'--height',str(H),'--rgb',*map(str,RGB)],client,8)
        need(checked.returncode==0,'unchanged strict validator every region pixel')
        preserved();held[str(crop)]=record;previous[str(crop)]=record
        need({str(p) for p in shots.iterdir()}==set(held),'no unexpected capture/partial entries')
        result['region_capture']=json.loads(checked.stdout);result['actual_slurp_geometry']=geometry.decode().strip()
        result['slurp_protocol_evidence']={'overlay_surface':trace.surface,'layer_surface':trace.layer_id,'configure_serial':trace.configure,'actual_enter':[str(v) for v in entered],'enter_callback_observed_before_press':True,'buttons':trace.buttons,'endpoint':[str(v) for v in endpoint],'trace_bytes':watch.offset}
        result['seat_capabilities']={'before':pointer.before,'with_virtual_pointer':pointer.capabilities}
    except BaseException as error:first=error
    finally:
        if slurp is None:
            tracked=[p for name,p in owned if name=='region-slurp']
            if len(tracked)==1:slurp=tracked[0]
            elif tracked:
                if first is None:first=ValueError('ambiguous direct slurp custody')
        if slurp is not None:
            try:
                retire('region-slurp',slurp);result['slurp_reaping']=reaped_child(slurp);owned.remove(('region-slurp',slurp))
            except BaseException as error:
                if first is None:first=error
                else:result['slurp_cleanup_failure']=str(error)
        if custody is not None:
            try:custody.close();result['custody_socket_retired']=True
            except BaseException as error:
                if first is None:first=error
                else:result['custody_channel_cleanup_failure']=str(error)
        if pointer is not None:
            try:
                pointer.close();result['pointer_retired_capabilities']=pointer.capabilities
            except BaseException as error:
                if first is None:first=error
                else:result['pointer_cleanup_failure']=str(error)
        (EVIDENCE/'virtual-pointer-wire.json').write_text(json.dumps(wire_trace,sort_keys=True,indent=2)+'\n')
        for name,p in [('region-helper',helper),('region-background',background)]:
            if p is None:continue
            try:retire(name,p);owned.remove((name,p))
            except BaseException as error:
                if first is None:first=error
                else:result['process_cleanup_failure']=str(error)
        result['status']='REAL_REGION_PIXEL_ORIGIN_PASS' if first is None else 'REAL_REGION_PIXEL_ORIGIN_FAIL'
        result['first_failure']=None if first is None else {'type':type(first).__name__,'message':str(first)}
        (EVIDENCE/'region-result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    if first is not None:raise first
    return result
