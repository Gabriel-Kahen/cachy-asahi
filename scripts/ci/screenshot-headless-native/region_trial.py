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
import sys
import resource
import time
from PIL import Image

SOURCE=Path('/source');EVIDENCE=Path('/evidence');HOME=Path('/tmp/screenshot-home')
CODE=SOURCE/'scripts/ci/screenshot-headless-native'
HELPER=SOURCE/'packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot'
X,Y,W,H=31,47,73,59
RGB=(18,52,86)

def need(ok,reason):
    if not ok:raise ValueError(reason)

def cleanup_uncertain(error,reason):
    try:
        labels=getattr(error,'region_cleanup_uncertainty',[])
        if type(labels) is not list:labels=[]
        error.region_cleanup_uncertainty=list(dict.fromkeys([x for x in labels if type(x) is str][:8]+[reason]))[:9]
    except BaseException:pass

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
        except BaseException as error:
            try:self.close()
            except BaseException:cleanup_uncertain(error,'custody-constructor-cleanup')
            raise
    def left(self):
        n=self.end-time.monotonic();need(n>0,'custody deadline');return min(n,3)
    def accept(self,helper):
        need(not self.used,'single-use custody handshake');self.used=True
        self.listener.settimeout(self.left());self.conn,_=self.listener.accept();self.listener.close()
        self.conn.settimeout(self.left())
        pid,uid,gid=struct.unpack('=iII',self.conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
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
        first=None
        for name in ('conn','listener'):
            handle=getattr(self,name);setattr(self,name,None)
            if handle is not None:
                try:handle.close()
                except BaseException as error:
                    if first is None:first=error
                    cleanup_uncertain(first,'custody-'+name+'-close')
        if self.node is not None:
            try:
                now=self.path.lstat()
                need(stat.S_ISSOCK(now.st_mode) and now.st_uid==os.getuid() and (now.st_dev,now.st_ino)==(self.node.st_dev,self.node.st_ino),'exact owned custody socket retirement')
                self.path.unlink();self.node=None
            except BaseException as error:
                if first is None:first=error
                cleanup_uncertain(first,'custody-socket-retirement')
        if first is not None:raise first

def reaped_child(process):
    need(process.returncode is not None,'direct slurp has not exited')
    try:os.waitpid(process.pid,os.WNOHANG)
    except ChildProcessError:
        return {'pid':process.pid,'owner_pid':os.getpid(),'returncode':process.returncode,'direct_child_waited':True,'absent_from_parent_child_table':True}
    raise ValueError('slurp direct child still waitable; retirement not proven')

def start_slurp(client,owned,case):
    need(case in ('positive','cancel'),'closed slurp evidence case')
    need(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,'default SIGCHLD needed for direct reaping evidence')
    old_mask=None
    def limits():
        signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
        resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,2*1024**2))
    trace=os.open(EVIDENCE/('region-'+case+'-slurp-protocol.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    geometry=None;first=None
    try:
        geometry=os.open(EVIDENCE/('region-'+case+'-slurp.stdout'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGHUP})
        try:
            process=subprocess.Popen(['/usr/bin/slurp','-f','%x,%y %wx%h'],env={**client,'PATH':'/usr/bin:/bin','WAYLAND_DEBUG':'client'},stdin=subprocess.DEVNULL,stdout=geometry,stderr=trace,start_new_session=True,preexec_fn=limits)
            owned.append(('region-'+case+'-slurp',process))
        except BaseException as error:first=error;raise
        finally:
            try:signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
            except BaseException as error:
                if first is None:first=error
                cleanup_uncertain(first,'selector-mask-restore')
            if first is not None and not sys.exc_info()[0]:raise first
        return process
    except BaseException as error:first=error;raise
    finally:
        for fd in (geometry,trace):
            if fd is not None:
                try:os.close(fd)
                except BaseException as error:
                    if first is None:first=error
                    cleanup_uncertain(first,'selector-fd-close')
        if first is not None and not sys.exc_info()[0]:raise first

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

def private_bytes(path,maximum):
    node=path.lstat()
    need(stat.S_ISREG(node.st_mode) and node.st_uid==os.getuid() and stat.S_IMODE(node.st_mode)==0o600 and node.st_size<=maximum,'private bounded case evidence')
    return path.read_bytes()

def json_record(name,result):
    with (EVIDENCE/name).open('x') as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(result,stream,sort_keys=True,indent=2);stream.write('\n')

def remaining(end,cap):
    left=end-time.monotonic();need(left>0,'region case deadline');return min(left,cap)

def exercise(sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record):
    return exercise_case(False,sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record)

def exercise_cancel(sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record):
    return exercise_case(True,sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record)

def exercise_case(cancel,sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record):
    Pointer=runpy.run_path(str(CODE/'region_pointer.py'))['Pointer']
    Trace=runpy.run_path(str(CODE/'region_trace.py'))['Trace']
    case='cancel' if cancel else 'positive';prefix='region-'+case
    helper_name=prefix+'-helper';slurp_name=prefix+'-slurp'
    pointer=background=helper=slurp=custody=None
    first=None;result={'case':case};wire_trace=[];sentinel=sentinel_record=None
    held={str(path):file_record(path) for path in shots.iterdir()}
    need(len(held)==(5 if cancel else 3) and held==previous,'expected complete prior capture records')
    result['capture_files_before']=len(held);result['preserved_capture_records']=dict(held)
    def preserved():
        need({str(path):file_record(path) for path in shots.iterdir()}==held,'all expected PNGs preserved without new entries')
        if sentinel is not None:need(file_record(sentinel)==sentinel_record,'private external sentinel preserved')
    def captured(path):
        need(path.parent==shots and path.is_absolute() and str(path) not in held,'new direct child capture')
        record=file_record(path)
        need(record['mode']==0o600 and record['uid']==os.getuid() and record['bytes']<=8*1024**2,'actual PNG private bounds')
        need({str(p) for p in shots.iterdir()}==set(held)|{str(path)},'one new capture without partials')
        for name,old in held.items():need(file_record(Path(name))==old,'prior PNG identity preserved')
        held[str(path)]=record;previous[str(path)]=record;return record
    try:
        remaining(end,1)
        if cancel:
            home=HOME.lstat()
            need(stat.S_ISDIR(home.st_mode) and home.st_uid==os.getuid() and stat.S_IMODE(home.st_mode)==0o700,'private external sentinel parent')
            sentinel=HOME/'region-cancel-external-sentinel'
            need(not sentinel.is_relative_to(shots),'sentinel outside capture directory')
            with sentinel.open('xb') as stream:
                os.fchmod(stream.fileno(),0o600);stream.write(b'native-region-cancel-preserve\n')
            sentinel_record=file_record(sentinel)
            result['external_sentinel']={'path':str(sentinel),'before':sentinel_record}
        else:
            expected=stimulus();path=HOME/'region-stimulus-NOT-CAPTURE.png'
            with path.open('xb') as stream:expected.save(stream,format='PNG')
            path.chmod(0o600)
            result['displayed_test_input']={'path':str(path),'role':'STIMULUS_NOT_CAPTURE','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'unique_patch':[X,Y,W,H],'rgb':list(RGB)}
            background=spawn(['/usr/bin/swaybg','-o',output,'-i',str(path),'-m','stretch'],{**client,'WAYLAND_DEBUG':'client'},'region-background')
            bg_trace=Trace('wallpaper',0);bg_watch=Watch(EVIDENCE/'region-background.log',bg_trace)
            bg_watch.until(lambda:bg_trace.committed,background,end)
            response=call(['/usr/bin/python3','-I','-B',str(HELPER),'full','--directory',str(shots)],client)
            need(response.returncode==0 and response.stderr==b'','actual full pattern capture')
            names=response.stdout.decode().splitlines();need(len(names)==1,'one full pattern path')
            full=Path(names[0]);record=captured(full);data=full.read_bytes()
            checker=runpy.run_path(str(CODE/'validate_png.py'))
            need(checker['chunks'](data,320,240)=='RGB','strict full pattern PNG structure')
            with Image.open(io.BytesIO(data)) as image:image.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.load();need(image.mode=='RGB' and image.size==(320,240) and image.tobytes()==expected.tobytes(),'every full pattern pixel/origin')
            result['full_pattern_capture']={'path':str(full),**record,'pixels_checked':320*240}
        pointer=Pointer(client['WAYLAND_DISPLAY'],min(end,time.monotonic()+20),sway.pid,wire_trace)
        pointer.position(X,Y)
        custody=Custody(end)
        env={**client,'PATH':str(CODE/'region-tools')+':/usr/bin:/bin','REGION_CUSTODY_TOKEN':custody.token,'REGION_CUSTODY_PARENT_PID':str(os.getpid())}
        helper=spawn(['/usr/bin/python3','-I','-B',str(HELPER),'region','--directory',str(shots)],env,helper_name,split=True)
        custody.accept(helper);slurp=start_slurp(client,owned,case)
        result['slurp_custody']={'owner_pid':os.getpid(),'direct_slurp_pid':slurp.pid,'wrapper_pid':custody.wrapper_pid,'helper_pid':helper.pid,'peer_uid':custody.uid,'peer_gid':custody.gid,'single_use':True,'actual_args':['/usr/bin/slurp','-f','%x,%y %wx%h']}
        def guard():
            custody.alive();need(helper.poll() is None and slurp.poll() is None,'held live helper and direct selector')
        trace=Trace('selection',3);watch=Watch(EVIDENCE/(prefix+'-slurp-protocol.log'),trace,guard)
        watch.until(lambda:trace.committed,helper,min(end,custody.end))
        pointer.position(X,Y)
        watch.until(lambda:trace.ready(X,Y),helper,min(end,custody.end))
        entered=trace.enter;motions_before=len(trace.motions)
        pointer.button(1);watch.until(lambda:trace.buttons==[1],helper,min(end,custody.end))
        if not cancel:
            pointer.position(X+W-1,Y+H-1)
            endpoint=(Decimal(X+W-1)+Decimal('.5'),Decimal(Y+H-1)+Decimal('.5'))
            watch.until(lambda:endpoint in trace.motions,helper,min(end,custody.end))
        pointer.button(0)
        until=min(end,custody.end,time.monotonic()+8)
        while slurp.poll() is None:
            custody.alive();need(helper.poll() is None,'helper held until real selector result')
            remaining(until,1);time.sleep(.01)
        need(slurp.wait(timeout=remaining(until,1))==(1 if cancel else 0),'actual direct selector result')
        result['slurp_reaping']=reaped_child(slurp);watch.update()
        need(trace.buttons==[1,0] and trace.retired,'actual buttons and overlay retirement acknowledged')
        if cancel:
            need(len(trace.motions)==motions_before,'stationary cancellation has no intervening motion')
        else:need(endpoint in trace.motions,'actual positive endpoint motion')
        result['selection_retirement']={'layer_surface':trace.layer_id,'surface':trace.surface,'sync_callback':trace.retirement_callback,'acknowledged':trace.retirement_ack,'trace_bytes':watch.offset}
        geometry=private_bytes(EVIDENCE/(prefix+'-slurp.stdout'),128)
        if cancel:
            raw=private_bytes(EVIDENCE/(prefix+'-slurp-protocol.log'),2*1024**2)
            count=raw.splitlines(keepends=True).count(b'selection cancelled\n')
            need(geometry==b'' and count==1,'real cancelled selector empty stdout/exact diagnostic line')
            result['slurp_result']={'returncode':slurp.returncode,'stdout_bytes':len(geometry),'cancel_diagnostic_lines':count}
            result['motion_count_before']=motions_before;result['motion_count_after']=len(trace.motions)
        else:need(geometry==f'{X},{Y} {W}x{H}'.encode(),'real slurp inclusive endpoint geometry')
        active=pointer.capabilities;need(pointer.before==0 and active==1,'active POINTER-only capability')
        pointer.close();result['pointer_retired_before_capture']=pointer.capabilities
        custody.finish(slurp.returncode,geometry)
        helper.wait(timeout=remaining(min(end,custody.end),8));watch.update()
        stdout=private_bytes(EVIDENCE/(helper_name+'.stdout'),8192)
        stderr=private_bytes(EVIDENCE/(helper_name+'.stderr'),8192)
        if cancel:
            expected_error=b'No region captured: selection cancelled or slurp failed. No full-screen fallback.\n'
            need(helper.returncode==1 and stdout==b'' and stderr==expected_error,'actual helper cancellation without fallback')
            need(len(trace.motions)==motions_before and trace.buttons==[1,0],'stationary cancellation trace held through helper exit')
            preserved();result['helper_result']={'returncode':helper.returncode,'stdout_bytes':len(stdout),'stderr':stderr.decode()}
            result['no_output_delta']=True;result['external_sentinel_preserved']=True
            result['external_sentinel']['after']=file_record(sentinel)
        else:
            need(helper.returncode==0 and stderr==b'','actual positive region helper result')
            names=stdout.decode().splitlines();need(len(names)==1,'one actual region path')
            crop=Path(names[0]);captured(crop)
            checked=call(['/usr/bin/python3','-I','-B',str(CODE/'validate_png.py'),str(crop),'--root',str(shots),'--width',str(W),'--height',str(H),'--rgb',*map(str,RGB)],client,8)
            need(checked.returncode==0,'strict every region pixel validation')
            result['region_capture']=json.loads(checked.stdout);result['actual_slurp_geometry']=geometry.decode()
        preserved();remaining(end,1)
        result['capture_files_after']=len(held)
        result['slurp_protocol_evidence']={'overlay_surface':trace.surface,'layer_surface':trace.layer_id,'configure_serial':trace.configure,'actual_enter':[str(v) for v in entered],'enter_callback_observed_before_press':True,'buttons':trace.buttons,'trace_bytes':watch.offset}
        if not cancel:result['slurp_protocol_evidence']['endpoint']=[str(v) for v in endpoint]
        result['seat_capabilities']={'before':pointer.before,'with_virtual_pointer':active}
    except BaseException as error:first=error
    finally:
        def recover(name,process):
            nonlocal first
            if process is not None:return process
            tracked=[actor for role,actor in owned if role==name]
            if len(tracked)==1:return tracked[0]
            if tracked and first is None:first=ValueError('ambiguous registered case actor')
            return None
        slurp=recover(slurp_name,slurp);helper=recover(helper_name,helper)
        if not cancel:background=recover('region-background',background)
        def cleanup(action,key):
            nonlocal first
            try:action()
            except BaseException as error:
                if first is None:first=error
                else:result[key]=type(error).__name__
                cleanup_uncertain(first,key)
        if slurp is not None:
            def retire_slurp():
                retire(slurp_name,slurp);result['slurp_reaping']=reaped_child(slurp);owned.remove((slurp_name,slurp))
            cleanup(retire_slurp,'slurp_cleanup_failure')
        if custody is not None:
            def close_custody():custody.close();result['custody_socket_retired']=True
            cleanup(close_custody,'custody_channel_cleanup_failure')
        if pointer is not None:
            def close_pointer():pointer.close();result['pointer_retired_capabilities']=pointer.capabilities
            cleanup(close_pointer,'pointer_cleanup_failure')
        cleanup(lambda:json_record(prefix+'-pointer-wire.json',wire_trace),'wire_evidence_failure')
        for name,process in ((helper_name,helper),('region-background',background)):
            if process is not None:
                def retire_process(name=name,process=process):retire(name,process);owned.remove((name,process))
                cleanup(retire_process,'process_cleanup_failure')
        if first is None:cleanup(lambda:remaining(end,1),'global_deadline_failure')
        result['status']=('REAL_LIVE_SELECTION_CANCEL_PASS' if cancel else 'REAL_REGION_PIXEL_ORIGIN_PASS') if first is None else ('REAL_LIVE_SELECTION_CANCEL_FAIL' if cancel else 'REAL_REGION_PIXEL_ORIGIN_FAIL')
        result['first_failure']=None if first is None else {'type':type(first).__name__,'message':str(first)}
        if first is not None:
            labels=getattr(first,'region_cleanup_uncertainty',None)
            if type(labels) is list:result['first_failure']['cleanup_uncertainty']=labels
        cleanup(lambda:json_record(prefix+'-result.json',result),'result_evidence_failure')
    if first is not None:raise first
    return result
