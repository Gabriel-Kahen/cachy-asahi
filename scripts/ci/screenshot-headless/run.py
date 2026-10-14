#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Finite actual Sway/pixman screenshot-helper behavior trial, inside CI only."""
import hashlib
import json
import os
import resource
import runpy
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

SOURCE=Path('/source')
EVIDENCE=Path('/evidence')
RUNTIME=Path('/tmp/screenshot-runtime')
HOME=Path('/tmp/screenshot-home')
HELPER=SOURCE/'packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot'
VALIDATOR=SOURCE/'scripts/ci/screenshot-headless/validate_png.py'
HELPER_SHA='5a920a5dd7a40463417a9b15e64a6620acfe7b2328960bf7014c9f587c4b69a8'
LIMIT=180

def need(ok,message):
    if not ok:raise ValueError(message)

def file_record(p):
    s=p.lstat();need(stat.S_ISREG(s.st_mode) and not p.is_symlink(),'regular file required')
    b=p.read_bytes();return {'bytes':len(b),'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'inode':[s.st_dev,s.st_ino],'sha256':hashlib.sha256(b).hexdigest()}

def private(p):
    p.mkdir(mode=0o700);s=p.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'private directory')

def main():
    start=time.monotonic();end=start+LIMIT
    records=[];owned=[];logs=[];first=None;cleanup=[];success=False
    result={'scope':'x86_64 standalone Sway headless pixman helper behavior only','positive_capture':'NOT_RUN','ARM_archive_Hyprland_M2_acceptance':False}
    def left(cap):
        n=end-time.monotonic();need(n>0,'trial deadline');return min(n,cap)
    def call(args,env,cap=40):
        prefix='command-'+str(len(records))
        def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
        with (EVIDENCE/(prefix+'.stdout')).open('xb') as out,(EVIDENCE/(prefix+'.stderr')).open('xb') as err:
            r=subprocess.run(args,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=left(cap),check=False,preexec_fn=output_limit)
        r.stdout=(EVIDENCE/(prefix+'.stdout')).read_bytes();r.stderr=(EVIDENCE/(prefix+'.stderr')).read_bytes()
        need(len(r.stdout)<1024**2 and len(r.stderr)<1024**2,'bounded command output')
        records.append({'argv':args,'code':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')})
        return r
    def log_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,2*1024**2))
    def spawn(args,env,name):
        f=open(EVIDENCE/(name+'.log'),'xb');logs.append(f)
        p=subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=log_limit)
        owned.append((name,p));return p
    def socket_node(p):
        s=p.lstat();need(stat.S_ISSOCK(s.st_mode) and s.st_uid==os.getuid() and p.parent==RUNTIME,'private owned socket');return [s.st_dev,s.st_ino]
    def ipc(kind,payload=''):
        path=RUNTIME/'sway.sock';socket_node(path)
        raw=payload.encode();need(len(raw)<=4096,'IPC request cap')
        deadline=min(end,time.monotonic()+3)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            def budget():
                remaining=deadline-time.monotonic();need(remaining>0,'IPC deadline');s.settimeout(remaining)
            budget();s.connect(str(path));budget();s.sendall(b'i3-ipc'+struct.pack('<II',len(raw),kind)+raw)
            def exact(count):
                out=bytearray()
                while len(out)<count:
                    budget();chunk=s.recv(count-len(out));need(chunk,'IPC EOF');out.extend(chunk)
                return bytes(out)
            header=exact(14);need(header[:6]==b'i3-ipc','IPC magic')
            size,response=struct.unpack('<II',header[6:]);need(response==kind and size<=1024**2,'IPC response cap/type')
            return json.loads(exact(size))
    def retire(name,p):
        if p.poll() is None:p.terminate()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill();p.wait(timeout=5)
            cleanup.append({'name':name,'forced':True,'code':p.returncode})
            raise ValueError('owned process required force kill')
        cleanup.append({'name':name,'forced':False,'code':p.returncode})
    try:
        need(os.getuid()!=0,'unprivileged trial required')
        need(not Path('/dev/dri').exists() and not Path('/dev/input').exists(),'no DRM/input devices')
        need(not os.isatty(0) and not os.isatty(1) and not os.isatty(2),'no physical tty')
        need(EVIDENCE.is_dir() and stat.S_IMODE(EVIDENCE.stat().st_mode)==0o700 and EVIDENCE.stat().st_uid==os.getuid(),'owned evidence root')
        need(file_record(HELPER)['sha256']==HELPER_SHA,'exact helper Source')
        private(RUNTIME);private(HOME)
        for n in ('config','cache','data','state'):private(HOME/n)
        shots=EVIDENCE/'shots';private(shots)
        config=HOME/'config/sway.conf'
        config.write_text('xwayland disable\noutput * mode 320x240 position 0,0 scale 1\n')
        config.chmod(0o600)
        env={'PATH':'/usr/bin:/bin','HOME':str(HOME),'XDG_CONFIG_HOME':str(HOME/'config'),'XDG_CACHE_HOME':str(HOME/'cache'),'XDG_DATA_HOME':str(HOME/'data'),'XDG_STATE_HOME':str(HOME/'state'),'XDG_RUNTIME_DIR':str(RUNTIME),'SWAYSOCK':str(RUNTIME/'sway.sock'),'WLR_BACKENDS':'headless','WLR_RENDERER':'pixman','WLR_HEADLESS_OUTPUTS':'1','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1'}
        result['environment']=env;result['helper']=file_record(HELPER)
        lock=json.loads((SOURCE/'scripts/ci/screenshot-headless/runtime.lock.json').read_bytes())
        query=call(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\n'],env,8)
        need(query.returncode==0,'runtime inventory query')
        actual=sorted(tuple(line.split('\t')) for line in query.stdout.decode().splitlines())
        expected=sorted((p['name'],p['version'],p['architecture']) for p in lock['packages'])
        need(actual==expected,'exact complete installed runtime inventory')
        result['runtime_packages']=actual
        need(not (RUNTIME/'sway.sock').exists(),'fresh IPC path')
        sway=spawn(['/usr/bin/sway','-d','-c',str(config)],env,'sway')
        ready_end=time.monotonic()+min(15,left(15));display=None
        while time.monotonic()<ready_end:
            need(sway.poll() is None,'compositor exited before readiness')
            candidates=[p for p in RUNTIME.glob('wayland-*') if stat.S_ISSOCK(p.lstat().st_mode)]
            if (RUNTIME/'sway.sock').exists() and len(candidates)==1:
                socket_node(candidates[0]);display=candidates[0];break
            time.sleep(0.05)
        need(display is not None,'bounded private socket readiness')
        client={**env,'WAYLAND_DISPLAY':str(display)}
        outputs=ipc(3);active=[o for o in outputs if o.get('active')]
        need(len(active)==1 and active[0]['current_mode']['width']==320 and active[0]['current_mode']['height']==240 and active[0]['scale']==1,'one exact virtual output')
        output=active[0]['name'];need(output.startswith('HEADLESS-'),'headless output name')
        result['outputs']=outputs;result['version']=ipc(7)
        previous={};captures=[]
        def capture(color,env_for=client):
            need(sway.poll() is None and bg.poll() is None,'owned compositor/background alive')
            before={p.name for p in shots.iterdir()}
            r=call(['/usr/bin/python3','-I','-B',str(HELPER),'full','--directory',str(shots)],env_for)
            need(r.returncode==0 and r.stderr==b'','actual full capture')
            lines=r.stdout.decode().splitlines();need(len(lines)==1,'one printed path')
            path=Path(lines[0]);need(path.is_absolute() and path.parent==shots and path.name not in before,'fresh direct child path')
            rgb=[str(int(color[i:i+2],16)) for i in (1,3,5)]
            checked=call(['/usr/bin/python3','-I','-B',str(VALIDATOR),str(path),'--root',str(shots),'--width','320','--height','240','--rgb',*rgb],client,8)
            need(checked.returncode==0,'independent full PNG/pixel validation')
            summary=json.loads(checked.stdout);captures.append(summary)
            need({p.name for p in shots.iterdir()}==before|{path.name},'one new PNG, no partial')
            for old,record in previous.items():need(file_record(Path(old))==record,'prior capture preserved')
            previous[str(path)]=file_record(path)
            return path
        bg=spawn(['/usr/bin/swaybg','-o',output,'-c','#123456'],client,'background-A')
        # A protocol round-trip plus finite frame interval precedes the first
        # measured capture. Incorrect/not-ready pixels fail; no fake image fallback.
        ipc(3);time.sleep(min(0.25,left(0.25)))
        capture('#123456');capture('#123456')
        retire('background-A',bg);owned.remove(('background-A',bg))
        bg=spawn(['/usr/bin/swaybg','-o',output,'-c','#654321'],client,'background-B')
        ipc(3);time.sleep(min(0.25,left(0.25)));capture('#654321')
        result['captures']=captures;result['positive_capture']='THREE_REAL_COLOR_CHECKED_CAPTURES'
        result['region']=runpy.run_path(str(SOURCE/'scripts/ci/screenshot-headless/region_trial.py'))['exercise'](sway,output,client,shots,end,owned,previous,call,spawn,retire,file_record)
        offline=Path('/tmp/screenshot-offline');private(offline)
        absent={**client,'XDG_RUNTIME_DIR':str(offline),'WAYLAND_DISPLAY':str(offline/'absent')}
        before={str(p):file_record(p) for p in shots.iterdir()}
        for mode in ('full','full','region'):
            r=call(['/usr/bin/python3','-I','-B',str(HELPER),mode,'--directory',str(shots)],absent,10)
            need(r.returncode==1 and r.stdout==b'','actual offline refusal')
            expected=b'grim failed; no screenshot was published.' if mode=='full' else b'No region captured: selection cancelled or slurp failed. No full-screen fallback.'
            need(r.stderr.strip()==expected,'offline diagnostic')
            need({str(p):file_record(p) for p in shots.iterdir()}==before and not list(offline.iterdir()),'offline preserves PNGs/no partials')
        shared=EVIDENCE/'insecure-output';private(shared);shared.chmod(0o755)
        sentinel=shared/'preserved.txt';sentinel.write_bytes(b'preserve me\n');sentinel.chmod(0o600);held=file_record(sentinel)
        r=call(['/usr/bin/python3','-I','-B',str(HELPER),'full','--directory',str(shared)],client,10)
        need(r.returncode==1 and r.stdout==b'' and b'Existing permissions were preserved.' in r.stderr,'insecure directory refusal')
        need(stat.S_IMODE(shared.stat().st_mode)==0o755 and file_record(sentinel)==held and {p.name for p in shared.iterdir()}=={'preserved.txt'},'sentinel/mode preserved')
        need(sway.poll() is None and bg.poll() is None,'owned compositor/background remained alive')
        text=(EVIDENCE/'sway.log').read_text(errors='replace')
        markers=['Starting headless backend','Creating pixman renderer','Created shm allocator']
        need(all(marker in text for marker in markers),'observed headless/pixman/SHM log markers')
        result['software_path_log_markers']=markers
        success=True
    except BaseException as error:
        first={'type':type(error).__name__,'message':str(error)}
    finally:
        for name,p in reversed(owned):
            try:retire(name,p)
            except BaseException as error:
                if first is None:first={'type':type(error).__name__,'message':str(error)}
                else:cleanup.append({'name':name,'fault':str(error)})
        for f in logs:f.close()
        remaining=[p.name for p in RUNTIME.iterdir()] if RUNTIME.exists() else []
        if remaining:
            success=False
            if first is None:first={'type':'ValueError','message':'runtime entries remain after owned compositor retirement'}
        result.update(status='SOFTWARE_SCREENSHOT_PASS' if success and first is None else 'SOFTWARE_SCREENSHOT_FAIL',first_failure=first,commands=records,owned_cleanup=cleanup,runtime_remaining=remaining,elapsed_seconds=time.monotonic()-start)
        (EVIDENCE/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return 0 if result['status']=='SOFTWARE_SCREENSHOT_PASS' else 1

if __name__=='__main__':raise SystemExit(main())
