# SPDX-License-Identifier: MIT
"""One private native-GPU session, three unchanged real Done notification cases."""
import base64,hashlib,json,os,platform,resource,signal,struct,subprocess,sys,time
from pathlib import Path
P=Path('/inputs');W=Path('/work')
sys.path.insert(0,str(P))
import observation as O,monitor,fish_terminal as F,capture
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
actors=[];cases=[];cleanup=[];errors=[];sequence=0;term=observer=None
E=dict(os.environ,LD_LIBRARY_PATH='/work/libs')
E.pop('AQ_NO_KMS_REQUIREMENT',None)
assert str(os.geteuid())==E['CACHY_NATIVE_UID'] and not Path('/run/user').exists() and not Path('/dev/input').exists()
assert not any(Path('/dev/dri').glob('card*')) and Path(E['CACHY_RENDER_NODE']).is_char_device()
assert not any(E.get(k) for k in ('DISPLAY','WAYLAND_DISPLAY','DBUS_SESSION_BUS_ADDRESS','HYPRLAND_INSTANCE_SIGNATURE','WAYLAND_DEBUG','G_DBUS_DEBUG'))

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(a,env=None,timeout=5):
 global sequence
 sequence+=1;p=subprocess.Popen(a,env=E if env is None else env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:out,err=p.communicate(timeout=timeout)
 except BaseException:
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  p.communicate(timeout=2);raise
 try:os.killpg(p.pid,0)
 except ProcessLookupError:absent=True
 else:absent=False
 O.need(len(out)+len(err)<=65536,'bounded command output')
 (W/f'command-{sequence}.json').write_text(json.dumps({'argv':a,'pid':p.pid,'exit':p.returncode,'group_absent':absent,'stdout':out.decode('utf8','replace'),'stderr':err.decode('utf8','replace')},indent=2)+'\n')
 O.need(p.returncode==0 and absent,'command failed or group remains '+a[0]);return out

def actor(name,a,env=None):
 out=(W/(name+'.stdout')).open('xb');err=(W/(name+'.stderr')).open('xb')
 try:p=subprocess.Popen(a,env=E if env is None else env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
 finally:out.close();err.close()
 actors.append((name,p,a));return p

def healthy():
 for name,p,a in actors:
  O.need(p.poll() is None,'owned actor exited '+name)
  O.need(sum((W/(name+'.'+x)).stat().st_size for x in ('stdout','stderr'))<=262144,'actor output cap')
 if observer is not None:observer.rows()
 if term is not None:O.need(term.process.poll() is None,'Fish exited');term.pump()

def until(probe,seconds,why):
 end=time.monotonic()+seconds
 while True:
  healthy();v=probe()
  if v:return v
  O.need(time.monotonic()<end,why);time.sleep(.01)

def monitor_ready(observer,probe,healthy,*,clock=time.monotonic,sleep=time.sleep):
 """Synchronize subscription before Fish; only benign pretrigger probes repeat."""
 deadline=clock()+5;attempts=0
 while True:
  remaining=deadline-clock();O.need(remaining>0 and attempts<51,'monitor readiness')
  probe(min(2,remaining));attempts+=1
  rows=observer.rows()
  observed=any(row.get('type')=='method_call' and row.get('member')=='GetCapabilities' and
               row.get('path')=='/org/freedesktop/Notifications' and
               row.get('interface')=='org.freedesktop.Notifications' for row in rows)
  O.need(clock()<=deadline,'monitor readiness')
  if observed:return {'attempts':attempts,'budget_seconds':5,'observed_method_call':True}
  healthy();remaining=deadline-clock();O.need(remaining>0,'monitor readiness')
  sleep(min(.1,remaining))


def stop(name,p,normal=False):
 if p.poll() is None:
  os.killpg(p.pid,signal.SIGTERM)
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=2)
 try:os.killpg(p.pid,0)
 except ProcessLookupError:absent=True
 else:absent=False
 row={'name':name,'pid':p.pid,'exit':p.returncode,'group_absent':absent};cleanup.append(row)
 O.need(absent and (not normal or p.returncode==0),'normal owned actor retirement '+name)

def dbus(method,*args):
 return command(['/usr/bin/busctl','--user','--auto-start=no','--timeout=2s','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',method,*args]).decode().strip()

def listing():return json.loads(command([str(W/'tools/makoctl'),'list','-j']))
def image_roi(path):
 import re
 raw=path.read_bytes();header=re.match(rb'P6\s+1024\s+768\s+255\s',raw)
 O.need(header is not None and len(raw)==header.end()+1024*768*3,'original native PPM shape')
 rgb=raw[header.end():];points=[];color=capture.COLORS['border']
 for i in range(0,len(rgb),3):
  if all(abs(rgb[i+c]-color[c])<=6 for c in range(3)):points.append((i//3%1024,i//3//1024))
 if not points:return {'status':'FAIL_NOTIFICATION_PIXELS_ABSENT','frame_sha256':digest(path),'roi_basis':'No border pixels in original first image'}
 x=min(q[0] for q in points);y=min(q[1] for q in points)
 box={'x':x,'y':y,'w':max(q[0] for q in points)-x+1,'h':max(q[1] for q in points)-y+1}
 value=capture.notification_pixels(path,box)
 value['roi_basis']='Image-derived bounding rectangle of shipped border color on this private empty output; NOT original Hyprland geometry proof'
 return value

configs={name:digest(W/name) for name in ('sway.conf','mako.conf')}
payload={str(q.relative_to(W/'done')):digest(q) for q in (W/'done').rglob('*') if q.is_file()}
bindings=json.loads((W/'bindings.json').read_bytes())
native_arch=bindings['native_arch'];O.need(platform.machine()==native_arch['name'] and {'x86_64':62,'aarch64':183}.get(native_arch['name'])==native_arch['elf_machine'],'actual native architecture differs')
label='X86' if native_arch['name']=='x86_64' else 'AARCH64'
def verify_native(path,expected):
 raw=Path(path).read_bytes();O.need(hashlib.sha256(raw).hexdigest()==expected,'staged/system input drift')
 O.need(raw[:6]==b'\x7fELF\x02\x01' and len(raw)>=64 and struct.unpack_from('<H',raw,18)[0]==native_arch['elf_machine'],'staged/system native architecture differs')
for name,entry in bindings['inside_tools'].items():
 verify_native(entry['path'],entry['sha256'])
O.need(str(Path('/usr/bin/sh').resolve())==bindings['inside_tools']['shell']['path'],'sh runtime alias drift')
aliases=bindings['fish_aliases']
if aliases:
 held=Path('/usr/bin/fish').stat();O.need(len(aliases)==held.st_nlink==3,'complete Fish multicall count')
 for alias in aliases:
  other=Path(alias).lstat();O.need((other.st_dev,other.st_ino,other.st_nlink)==(held.st_dev,held.st_ino,3),'Fish multicall alias drift')
for name,entry in bindings['libraries'].items():verify_native(W/'libs'/name,entry['sha256'])
try:
 E.update(WLR_BACKENDS='headless',WLR_HEADLESS_OUTPUTS='1',WLR_RENDERER='gles2',WLR_RENDER_DRM_DEVICE=E['CACHY_RENDER_NODE'])
 parent=actor('sway',[str(W/'tools/sway'),'--config','/work/sway.conf'])
 socket=until(lambda:next((p for p in (W/'runtime').glob('wayland-*') if p.is_socket()),None),15,'private parent socket')
 E['WAYLAND_DISPLAY']=socket.name
 # Direct private Sway replaces Hyprland. No Hyprland geometry/protocol credit.
 ipc=until(lambda:next((p for p in (W/'runtime').glob('sway-ipc*.sock') if p.is_socket()),None),5,'owned Sway IPC')
 E['SWAYSOCK']=str(ipc)
 monitors=json.loads(command([str(W/'tools/swaymsg'),'-s',str(ipc),'-r','-t','get_outputs']))
 O.need(len(monitors)==1 and monitors[0]['rect']['width']==1024 and monitors[0]['rect']['height']==768 and monitors[0]['scale']==1,'fixed private output')
 output=monitors[0]['name']
 bus=actor('bus',['/usr/bin/dbus-daemon','--session','--nofork','--nopidfile','--nosyslog','--address=unix:path=/work/runtime/bus'])
 until(lambda:(W/'runtime/bus').is_socket(),5,'owned bus socket');E['DBUS_SESSION_BUS_ADDRESS']='unix:path=/work/runtime/bus'
 O.need(dbus('NameHasOwner','s','org.freedesktop.Notifications')=='b false','fresh private notification bus')
 mako=actor('mako',[str(W/'tools/mako'),'--config','/work/mako.conf'])
 until(lambda:dbus('NameHasOwner','s','org.freedesktop.Notifications')=='b true',5,'normal Mako registration')
 owner=json.loads(dbus('GetNameOwner','s','org.freedesktop.Notifications')[2:]);pid=int(dbus('GetConnectionUnixProcessID','s','org.freedesktop.Notifications').split()[1])
 O.need(pid==mako.pid,'exact owned recipient');O.need(listing()==[],'no initial notifications')
 for stage,(kind,outcome) in O.CASES.items():
  row={'stage':stage,'case':kind,'outcome':outcome,'recipient':owner,'mako_pid':mako.pid,'notification_timeout_ms':3000};cases.append(row)
  observer=monitor.Monitor(E)
  # Non-notification D-Bus method proves the observer is live before the real Fish trigger.
  row['monitor_readiness']=monitor_ready(observer,lambda remaining:command(['/usr/bin/busctl','--user','--auto-start=no','call','org.freedesktop.Notifications','/org/freedesktop/Notifications','org.freedesktop.Notifications','GetCapabilities'],timeout=remaining),healthy)
  term=(F.BackgroundTerminal if stage=='background' else F.Terminal)(E)
  term.start(outcome)
  wire=until(lambda:O.notify(observer.rows(),owner,outcome,'Watched job' if stage=='background' else 'Foreground command'),15,'original Done delivery15s')
  row['wire']=wire;row['request_timing']=O.capture_timing_facts(wire,time.time_ns()//1000,time.monotonic_ns())
  O.capture_timing(wire,row['request_timing']['request_realtime_us'],row['request_timing']['request_monotonic_ns'])
  def visible():
   notice=O.listing(listing(),wire)
   return {'notification':notice,'scope':'Mako listing only; Sway has no original Hyprland live-layer geometry witness'} if notice else None
  row['visibility']=until(visible,2,'original natural-expiry readiness2s')
  target=W/(stage+'.ppm');O.need(not target.exists(),'one fresh first frame')
  started=time.monotonic_ns();started_us=time.time_ns()//1000
  command(['/usr/bin/grim','-t','ppm','-o',output,str(target)],timeout=2)
  finished_us=time.time_ns()//1000
  row['capture']={'first':True,'started_us':started_us,'finished_us':finished_us,'elapsed_ms':(time.monotonic_ns()-started)//1000000,'notify_to_started_us':started_us-wire['call']['timestamp-realtime'],'notify_to_finished_us':finished_us-wire['call']['timestamp-realtime'],'bytes':target.stat().st_size,'sha256':digest(target)}
  O.need(0<=row['capture']['notify_to_finished_us']<=2000000,'first capture within original pre-expiry2s')
  row['pixels']=image_roi(target)
  if row['pixels']['status']!='PASS_PIXEL_PRESENCE_PENDING_READABILITY':errors.append(stage+':first notification pixels absent')
  row['caller']=term.continuation(outcome)
  end=time.monotonic()+3.5
  while time.monotonic()<end:healthy();time.sleep(.02)
  row['fish']=term.finish();term.close();term=None
  row['monitor']=observer.finish();observer.close();observer=None
  row['closed']=O.closure_facts(base64.b64decode(row['monitor']['raw_base64']),wire)
  closed=row['closed']['matching_closed_signals'];O.need(len(closed)==1 and closed[0]['signal']['payload']['data']==[wire['id'],1],'actual natural expiry reason1')
  O.need(listing()==[],'no notice after natural expiry');row['status']='PASS_TRANSPORT_CALLER_EXPIRY_WITH_ORIGINAL_FIRST_FRAME'
 O.need({name:digest(W/name) for name in configs}==configs,'private configs preserved')
 O.need({str(q.relative_to(W/'done')):digest(q) for q in (W/'done').rglob('*') if q.is_file()}==payload,'Done payload preserved')
 stop('mako',mako,True);actors.remove(next(x for x in actors if x[0]=='mako'))
 O.need(dbus('NameHasOwner','s','org.freedesktop.Notifications')=='b false','owned notification service absent')
 stop('bus',bus,True);actors.remove(next(x for x in actors if x[0]=='bus'))
 stop('sway',parent,True);actors.remove(next(x for x in actors if x[0]=='sway'))
except BaseException as ex:
 errors.append(type(ex).__name__+': '+str(ex))
 if term is not None:(W/'failure-fish-pty').write_bytes(bytes(term.output))
 if observer is not None:
  (W/'failure-bus-stdout').write_bytes(bytes(observer.parts[0]));(W/'failure-bus-stderr').write_bytes(bytes(observer.parts[1]))
finally:
 for item,name in ((term,'fish'),(observer,'monitor')):
  if item is not None:
   try:item.close();cleanup.append({'name':name,'owned_cleanup':'PASS'})
   except BaseException as ex:errors.append('cleanup '+name+': '+str(ex))
 for name,p,a in reversed(actors):
  try:stop(name,p)
  except BaseException as ex:errors.append('cleanup '+name+': '+str(ex))
 result={'native_arch':native_arch,'status':'PASS_NATIVE_'+label+'_GPU_DONE_FUNCTIONAL_PENDING_VISUAL_REVIEW' if not errors and len(cases)==3 else 'FAIL_OR_BLOCKED_NATIVE_'+label+'_FIXTURE','scope':bindings['scope'],'errors':errors,'cases':cases,'cleanup':cleanup,'configs':configs,'payload':payload,'device_nodes':sorted(str(p) for p in Path('/dev').rglob('*')),'visual_review':'NOT_RUN','source_to_original_arm_mako_binary_attestation':'NOT_ESTABLISHED','bindings':bindings,'renderer_qualification':'Selected render-node/GLES and source guards; no live GL vendor/model readback or hardware-performance claim'}
 (W/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':result['status'],'errors':errors,'cases':len(cases)}))
