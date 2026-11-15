# SPDX-License-Identifier: MIT
"""Case-local operational gates and live bounds. Imports perform no operation."""
import hashlib,importlib.util,json,math,os,re,shutil,socket,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
_cache={}
def load(name):
 if name not in _cache:
  path=HERE/('frozen/independent_readback.py'if name=='independent_readback'else name+'.py')
  s=importlib.util.spec_from_file_location('llvm23_ops_'+name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);_cache[name]=m
 return _cache[name]
def modules():return load('contracts'),load('runtime'),load('contracts').helper('reference_controller.py'),load('ownership'),load('image')
def receipt(path,cap=8*1024**2):
 K=load('contracts');p=K.ordinary(path);pin=K.pin(p,cap);raw=p.read_bytes();K.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==pin,'stable bounded runtime receipt')
 def unique(rows):
  out={}
  for key,value in rows:K.need(key not in out,'duplicate runtime JSON key');out[key]=value
  return out
 def invalid(value):raise ValueError('nonfinite runtime JSON')
 value=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
 def finite(v):
  if isinstance(v,float):K.need(math.isfinite(v),'finite runtime observation')
  elif isinstance(v,dict):
   for x in v.values():finite(x)
  elif isinstance(v,list):
   for x in v:finite(x)
 finite(value);K.need(type(value)is dict,'runtime JSON object');return value

def arguments(p):
 for n in('case','materials','packet','kernel-bundle','tool-metadata','authority','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--base','--baseline',dest='base',type=Path,required=True)
 p.add_argument('--baseline-report','--base-first-boot-report',dest='baseline_report',type=Path,required=True)
 p.add_argument('--baseline-ownership',type=Path,required=True)
 for n in('case-sha256','source-lock-sha256','authority-sha256'):p.add_argument('--'+n,required=True)

def packet(directory,pin,case,lock):
 K=load('contracts');root=K.ordinary(directory);meta=K.load(root/'case-packet.json');K.need(K.pin(root/'case-packet.json')==pin,'Root-selected case packet')
 K.need(meta['status']=='PREPARED_CASE_PACKET_NOT_INSTALLED_OR_BOOTED'and meta['operation']==K.OP and meta['Source_lock']==lock and re.fullmatch('[0-9a-f]{32}',meta['nonce']),'exact prepared case packet lineage')
 K.need(meta['files']['case-inputs.json']['sha256']==K.json_pin(case)['sha256'],'packet/native case bytes')
 found=set()
 for current,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:K.need(not(Path(current)/name).is_symlink(),'packet directory alias')
  for name in files:found.add((Path(current)/name).relative_to(root).as_posix())
 K.need(found==set(meta['files'])|{'case-packet.json'},'closed packet membership')
 for n,row in meta['files'].items():K.need(K.pin(root/n)=={k:row[k]for k in('bytes','sha256')}and stat.S_IMODE((root/n).stat().st_mode)==row['mode'],'whole packet file/mode')
 return meta

def kernel(directory,expected):
 K=load('contracts');root=K.ordinary(directory);K.need({p.name for p in root.iterdir()}=={'bundle.json','Image','config'},'closed selected kernel bundle')
 K.need(K.pin(root/'bundle.json')==expected,'Root-selected built kernel bundle');value=receipt(root/'bundle.json');H=K.helper('rtc_contract.py');H.header(root/'Image');cfg=H.values((root/'config').read_bytes())
 for n in('ARM64_16K_PAGES','RTC_CLASS','RTC_DRV_PL031','RTC_HCTOSYS','RTC_INTF_SYSFS','EXT4_FS','VIRTIO_BLK','VIRTIO_MMIO','SERIAL_AMBA_PL011_CONSOLE'):K.need(cfg.get('CONFIG_'+n)=='y','required fixed16K/RTC platform option '+n)
 for n in('Image','config'):K.need(K.pin(root/n)==value['files'][n],'actual selected kernel bytes')
 return value

def preflight(a,phase):
 K=load('contracts');A=load('adapter');started=time.monotonic();K.need(phase in('prepare','boot')and os.getuid()==os.geteuid()!=0,'explicit ordinary Root-controller phase')
 authority=K.load(a.authority);K.need(K.pin(a.authority)['sha256']==a.authority_sha256,'external Root authority digest')
 K.need(authority.get('kind')=='ROOT_ARM16K_LLVM23_VM_AUTHORITY_V1'and authority.get('issued_by')=='Root'and authority.get('operation')==K.OP and authority.get('allow_'+phase)is True,'fresh explicit Root phase authority')
 K.need(K.positive(authority['phase_seconds'])and authority['phase_seconds']<=999999999,'finite Root controller envelope')
 K.END=A.K.END=started+authority['phase_seconds']
 case,certs,observed,lock=A.preflight(a.case,a.case_sha256,a.materials,a.source_lock_sha256,a.base,a.baseline_report,a.baseline_ownership)
 limits=certs['resource_certificate'];K.need(authority['source_lock']==lock and authority['case']==K.pin(a.case)and authority['phase_seconds']==limits['prepare_seconds'if phase=='prepare'else'boot_seconds'],'exact code/case/phase authority')
 K.need(1<=limits['image_scan_passes']<=16 and 1610612736<=limits['prepared_raw_bytes']<=4*1024**3 and limits['prepared_raw_bytes']%4096==0 and limits['guest_memory_bytes']%1024**2==0 and 0<limits['overlay_cap_bytes']<=1024**3 and limits['cleanup_seconds']>3,'reviewed scanner/QEMU/retirement bounds')
 baseline=K.load(HERE/'data/baseline111.json');base=receipt(a.base/'prepared.json');report=receipt(a.baseline_report)
 K.need(K.pin(a.base/'prepared.json')==baseline['prepared']and K.pin(a.baseline_report)==baseline['first_boot_report'],'exact immutable Source111 baseline/report')
 for n,row in baseline['files'].items():K.need(K.pin(a.base/n,row['bytes'])==row,'immutable Source111 file '+n)
 K.need(K.pin(a.base/'arm16k-first-boot-attempt.json')==baseline['original_marker']and base['nonce']==baseline['base_nonce']and base['base_packages']==baseline['base_packages'],'original consumed111 marker/nonce/inventory preserved')
 K.need(report['status']==baseline['first_boot_status']and report['normal_PAM_logout_observed']is report['owned_container_absence_verified']is True and not report.get('cleanup_errors'),'accepted actual Source111 PAM/retirement')
 K.need(certs['baseline_certificate']['inventory']=={r['name']:r['version']for r in baseline['base_packages']},'Source111 only; never relabel accepted155')
 tool=receipt(a.tool_metadata);K.need(K.pin(a.tool_metadata)==K.pin(HERE/'data/tool-metadata.json')and authority['tool_metadata']==K.pin(a.tool_metadata),'exact qualified tool metadata')
 K.need(tool['image_id']==authority['tool_image_id']and tool['qemu_path']=='/usr/bin/qemu-system-aarch64'and'virtio-blk-device'in tool['devices'],'qualified software-only QEMU declaration')
 built=kernel(a.kernel_bundle,authority['kernel_bundle']);m=packet(a.packet,authority['packet'],case,lock)
 K.need(authority['nonce']==m['nonce']and m['nonce']!=base['nonce'],'distinct Root-bound case nonce')
 credentials=K.ordinary(a.base/'credentials.json');K.need(K.pin(credentials)==authority['credentials']and stat.S_IMODE(credentials.stat().st_mode)==0o600,'exact private original PAM credentials')
 out=K.ordinary(a.output);K.need(not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh ordinary owned output')
 inputs=[HERE,K.ordinary(a.base),K.ordinary(a.materials),K.ordinary(a.packet),K.ordinary(a.kernel_bundle)]
 K.need(all(out!=p and p not in out.parents and out not in p.parents for p in inputs),'disjoint controller output')
 K.need(limits['host_uid']==os.getuid()and limits['output_device']==out.parent.stat().st_dev,'actual own UID/output filesystem')
 K.endpoint(authority);K.docker_cli(authority)
 policy=authority['postboot_policy'];K.keys(policy,('mutable_unowned_paths','new_unowned_paths'),'finite Root postboot policy')
 for group in policy.values():
  K.need(type(group)is list and len(group)<=256 and len(set(group))==len(group),'finite unique postboot paths')
  for path in group:
   K.need(type(path)is str and re.fullmatch('[A-Za-z0-9._+/@:~-]+',path)and not path.startswith('/')and all(x not in('','..','.')for x in path.split('/')),'exact relative postboot path')
   K.need(not any(path==n or path.startswith(n+'/')for n in('etc','usr','opt','home','root','var/lib/pacman')),'postboot policy cannot waive software/PAM/users/package state')
 final=int(started+authority['phase_seconds']);deadline=final-limits['cleanup_seconds'];K.need(time.monotonic()<deadline,'preflight inside finite work budget')
 ctx=dict(case=case,certs=certs,limits=limits,source_lock=lock,authority=authority,authority_pin=K.pin(a.authority),base=base,baseline=baseline,tool=tool,kernel=built,nonce=m['nonce'],deadline=deadline,active_deadline=deadline,final_deadline=final,phase=phase,host_gid=os.getgid(),paths=dict(base=str(K.ordinary(a.base)),materials=str(K.ordinary(a.materials)),packet=str(K.ordinary(a.packet)),kernel_bundle=str(K.ordinary(a.kernel_bundle)),output=str(out),case=str(K.ordinary(a.case)),baseline_report=str(K.ordinary(a.baseline_report)),baseline_ownership=str(K.ordinary(a.baseline_ownership)),authority=str(K.ordinary(a.authority)),tool_metadata=str(K.ordinary(a.tool_metadata))))
 guard(ctx,out)();return ctx

def actor_context(inputs,work,phase='boot'):
 K=load('contracts');inputs=Path(inputs);work=Path(work);manifest=K.load(inputs/'input-manifest.json');ctx=manifest['ctx']
 K.need(manifest['phase']==ctx['phase']==phase and manifest['deadline']==ctx['deadline']and time.monotonic()<ctx['deadline'],'fixed finite actor phase')
 K.need(os.getuid()==os.geteuid()==0 and Path('/.dockerenv').is_file(),'explicit rootless-mapped actor UID0')
 status=dict(x.split(':',1)for x in Path('/proc/self/status').read_text().splitlines()if':'in x)
 K.need(all(int(status[n].strip(),16)==0 for n in('CapEff','CapPrm','CapBnd','CapInh','CapAmb'))and status['NoNewPrivs'].strip()=='1'and {n for _,n in socket.if_nameindex()}=={'lo'}and not Path('/dev/kvm').exists(),'actual cap0/NNP/no-network/noKVM actor')
 uidmap=[list(map(int,x.split()))for x in Path('/proc/self/uid_map').read_text().splitlines()];K.need([0,ctx['limits']['host_uid'],1]in uidmap,'actor writes accounted to exact host own UID')
 load('adapter').source(ctx['source_lock']['sha256']);K.need(K.json_pin(ctx['authority'])==ctx['authority_pin']and ctx['authority']['allow_'+phase]is True,'unchanged Root actor authority')
 observed={**{n:ctx['case']['package'][n]for n in K.MATERIALS},**ctx['case']['evidence']};K.validate(ctx['case'],observed,**ctx['certs'])
 K.need(K.pin(Path('/usr/bin/qemu-system-aarch64'),ctx['tool']['actual_tool_pin']['bytes'])==ctx['tool']['actual_tool_pin'],'actual qualified actor QEMU bytes')
 ctx['actor']=True;ctx['paths'].update(base='/base',materials='/materials',packet='/packet',kernel_bundle='/kernel',output=str(work));return ctx

class Guard:
 def __init__(self,ctx,out,quota_reader=None):self.ctx=ctx;self.out=Path(out);self.initial=True;self.read_quota=quota_reader or load('quota').read
 def __call__(self):
  K=load('contracts');R=load('runtime');c=self.ctx;l=c['limits'];K.need(time.monotonic()<c.get('active_deadline',c['deadline']),'finite original controller deadline')
  root=self.out if self.out.exists()else self.out.parent;free=shutil.disk_usage(root).free
  cap=sum(l[n]for n in('clone_allocated_cap_bytes','overlay_cap_bytes','readback_allocated_cap_bytes','logs_cap_bytes'))
  allocated=R.allocated(self.out,c.get('active_deadline',c['deadline']))if self.out.exists()else 0
  K.need(allocated<=cap and free>=l['reserve_bytes']and(not self.initial or free>=cap+l['reserve_bytes']),'actual sparse allocated blocks/live physical reserve')
  if not c.get('actor'):
   K.need(root.stat().st_dev==l['output_device']and os.getuid()==l['host_uid'],'own-UID quota filesystem identity')
   q=self.read_quota(root,l['host_uid']);head=load('quota').headroom(q,l['host_uid'],l['output_device'])
   K.need(head>=(l['quota_initial_headroom_bytes']if self.initial else l['quota_live_reserve_bytes']),'actual live own-UID quota reserve')
   mem={a:int(b.split()[0])*1024 for a,b in(x.split(':',1)for x in Path('/proc/meminfo').read_text().splitlines())};K.need(mem['MemAvailable']>=l['owner_memory_bytes']+l['host_reserve_bytes'],'live host memory reserve')
  self.initial=False;return dict(allocated_bytes=allocated,physical_free_bytes=free)
def guard(ctx,out):return Guard(ctx,out)

def recheck(ctx):
 K=load('contracts');p=ctx['paths'];load('adapter').source(ctx['source_lock']['sha256'])
 K.need(K.pin(Path(p['authority']))==ctx['authority_pin'],'authority unchanged')
 K.endpoint(ctx['authority']);K.docker_cli(ctx['authority'])
 for n,row in ctx['baseline']['files'].items():K.need(K.pin(Path(p['base'])/n,row['bytes'])==row,'immutable original baseline after actor')
 K.need(K.pin(Path(p['base'])/'prepared.json')==ctx['baseline']['prepared']and K.pin(Path(p['baseline_report']))==ctx['baseline']['first_boot_report']and K.pin(Path(p['base'])/'arm16k-first-boot-attempt.json')==ctx['baseline']['original_marker'],'original prepared/PAM report/consumed marker unchanged')
 for n,path in load('adapter').NAMES.items():
  expected=ctx['case']['package'][n]if n in K.MATERIALS else ctx['case']['evidence'][n]
  K.need(K.pin(Path(p['materials'])/path,expected['bytes'])==expected,'retained actual candidate/certificate bytes unchanged')
 kernel(Path(p['kernel_bundle']),ctx['authority']['kernel_bundle']);packet(Path(p['packet']),ctx['authority']['packet'],ctx['case'],ctx['source_lock'])
 return True

def namespace_delta(now,old,policy):
 K=load('contracts')
 mutable=set(policy['mutable_unowned_paths']);new=set(policy['new_unowned_paths'])
 K.need(not mutable&set(old['owned'])and not mutable&set(old['protected']),'Root policy cannot waive owned/protected baseline')
 K.need(all(now.get(n)==row for n,row in old['old_namespace'].items()if n not in mutable),'original namespace preserved outside finite Root unowned policy')
 additions=set(now)-set(old['old_namespace'])-set(old['staged_namespace']);casepath='var/lib/arm16k-llvm23-vm'
 known={'home/builder/.arm16k-llvm23-sentinel','root/.arm16k-llvm23-sentinel'}
 K.need(all(n==casepath or n.startswith(casepath+'/')or n in known or n in new for n in additions),'no unexpected unowned postboot namespace additions')
 K.need(not any(n==casepath+'/trust'or n.startswith(casepath+'/trust/')for n in now),'private TEST trust absent after normal lifecycle')
 return True

def postboot(ctx,out,overlay,check):
 K,R,B,O,D=modules();out=Path(out);raw=out/'verification.raw';K.need(not raw.exists(),'fresh postboot verification copy')
 def command(label,argv,seconds=None):
  check();value=R.command(argv,out,label,seconds or max(4,ctx['deadline']-time.monotonic()),ctx['deadline'],watched_tree=(out,sum(ctx['limits'][n]for n in('overlay_cap_bytes','readback_allocated_cap_bytes','logs_cap_bytes')),ctx['limits']['reserve_bytes']),check=False,completed=True);check();return value
 value=command('postboot-convert',['qemu-img','convert','-f','qcow2','-O','raw','-S','4k',str(overlay),str(raw)]);K.need(value.returncode==0,'natural owned verification conversion')
 K.need(raw.stat().st_size==ctx['limits']['prepared_raw_bytes'],'actual prepared raw geometry')
 value=command('postboot-journal',['e2fsck','-p','-E','journal_only',str(raw)]);K.need(value.returncode in(0,1),'verification-copy-only journal replay')
 K.need(command('postboot-readonly',['e2fsck','-fn',str(raw)]).returncode==0,'readonly ext4 after natural VM retirement')
 old=K.load(Path('/inputs/ownership.json'),64*1024**2)
 maxfile=max(ctx['case']['package']['archive']['bytes'],ctx['limits']['guest_output_cap_bytes'],max(r.get('bytes',0)for r in ctx['certs']['runtime_certificate']['candidate_namespace'].values()),max(r.get('bytes',0)for r in old['old_namespace'].values()))
 scan=D.scan(raw,ctx['deadline'],check,max_file_bytes=maxfile,max_read_bytes=ctx['limits']['prepared_raw_bytes']*ctx['limits']['image_scan_passes']);now=scan['nodes'];prepared=K.load(Path('/inputs/prepared.json'))
 K.need(O.all_owned_records(scan['records'],old['packages'],now)==old['owned'],'all111 owned payload bytes/modes restored')
 namespace_delta(now,old,ctx['authority']['postboot_policy'])
 K.need(all(now.get(n)==row for n,row in old['protected'].items()),'original PAM/boot protected paths')
 prefix=K.PREFIX.lstrip('/');K.need(not any(n==prefix or n.startswith(prefix+'/')for n in now),'package private prefix absent after normal removal')
 for n,row in old['staged_namespace'].items():
  if n.endswith('/trust'):continue
  K.need(now.get(n)==row,'immutable case fixture/service delta differs: '+n)
 dest=out/'guest-results';K.need(not dest.exists(),'fresh durable guest results extraction');dest.mkdir(mode=0o700)
 frozen=load('independent_readback');base='var/lib/arm16k-llvm23-vm/results/'
 with frozen.Ext4Reader(raw,max_nodes=150000,max_file_bytes=maxfile)as reader:
  reader.read_budget=ctx['limits']['prepared_raw_bytes']*ctx['limits']['image_scan_passes'];inventory=reader.inventory()['nodes']
  for n in('smoke','unwind','outputs.sha256','summary.env'):
   row=inventory[base+n];K.need(row['type']=='file'and row['size']<=ctx['limits']['guest_output_cap_bytes'],'bounded actual durable result inode')
   fields,data=reader.inode(row['inode']);p=dest/n
   with p.open('xb')as stream:
    for block in reader.chunks(fields,data):check();stream.write(block)
   p.chmod(0o600)
 raw.unlink();check()
 return dict(status='PASS_COMPLETE_LLVM23_POSTBOOT_PRESERVATION',nonce=ctx['nonce'],source_lock=ctx['source_lock'],ownership=prepared['ownership'],all111_unchanged=True,PAM_boot_unchanged=True,fixture_unchanged=True,prefix_absent=True)
