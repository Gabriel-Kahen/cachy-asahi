# SPDX-License-Identifier: MIT
"""All seven accepted core packages in two complete owned574 copies; never host PID1."""
import argparse,base64,gzip,hashlib,importlib.util,json,os,platform,shutil,signal,sys,tarfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C,transaction as T,fixture as F
SOURCE=Path('/source');INPUTS=Path('/inputs');HELD=Path('/held');WORK=Path('/work');OUT=Path('/out');END=None;REPORT=None;START=None

def checkpoint():
 if REPORT is None:return
 raw=C.encoded(REPORT);C.need(len(raw)<=2*1024**2,'bounded complete lifecycle progress receipt');temporary=OUT/'.result.partial';C.need(not os.path.lexists(temporary),'fresh owned progress write')
 with temporary.open('xb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 temporary.replace(OUT/'result.json')


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def budget(api,seconds=600):return api['roots'].Limits(deadline=min(END,time.monotonic()+seconds),max_packages=589,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)

def snapshot(api,root,label,index,report):
 b=budget(api);v=api['roots'].observe(root,limits=b,hardlinks='generic-development-internal');C.need(v['complete']is True and set(v['unsupported_counts'])<={'absolute-symlink','auxiliary-present'},'complete bounded graph including every absolute link and auxiliary')
 caps=api['caps'].observe(root,v['nodes'],b);C.need(caps==index['source_capabilities'],'whole source capability map unchanged');v['security_capabilities']=caps
 raw=json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode();compressed=gzip.compress(raw,mtime=0);C.need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'original complete graph export caps');C.need(sum(p.stat().st_size for p in OUT.iterdir()if p.is_file())+len(compressed)<=512*1024**2,'original aggregate complete evidence cap');path=OUT/(label+'-root.json.gz');path.write_bytes(compressed)
 report.setdefault('snapshots',{})[label]=dict(file=path.name,raw=C.pin(raw),compressed=C.pin(compressed),capabilities=C.pin(C.encoded(caps)));checkpoint();return v

def database(api,root):return api['db'].database(root,max_packages=589,max_files=100000,max_nodes=500000)
def inventory(api,root):return {r['name']:r['version']for r in database(api,root)}

class Commands:
 def __init__(self,api,report):self.api=api;self.report=report
 def call(self,argv,seconds=90,expect=0,cleanup=False):
  C.need((cleanup and argv==['/usr/bin/gpgconf','--homedir','/tmp/core-public-gpg','--kill','all']and seconds==15)or time.monotonic()<END,'original3600 lifecycle clock; only original15s key cleanup after expiry');row,out,err,error=self.api['runtime'].run_command(argv,WORK,dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1'),seconds if cleanup else min(seconds,max(.001,END-time.monotonic())),1024**2);n=len(self.report['commands']);C.need(n<128,'original128 command cap');self.report['commands'].append(row);(OUT/('command-%03d.stdout'%n)).write_bytes(out);(OUT/('command-%03d.stderr'%n)).write_bytes(err);checkpoint()
  if error:raise error
  C.need(row['exit_code']==expect and row['group_absence_verified'],'actual foreground exit/group absence');return out
 def inside(self,root,argv):return self.call(['/usr/bin/chroot',str(root),*argv])

def public_keys(commands,index):
 keys=Path('/tmp/core-public-gpg');C.need(not keys.exists(),'fresh public-only consumer key home');keys.mkdir(mode=0o700);(keys/'gpg.conf').write_text('no-auto-key-retrieve\nauto-key-locate clear\nno-autostart\n');gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(keys),'--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart']
 commands.call(gpg+['--import',str(C.HERE/'keyring/archlinuxarm.gpg'),str(INPUTS/'TEST-public.asc')]);C.need(not commands.call(gpg+['--with-colons','--list-secret-keys']),'no secret key in consumer')
 trust=keys/'ownertrust';trust.write_text(''.join(n+':6:\n'for n in(index['test_signer'],'68B3537F39A313B3E574D06777193F152BDBE6A6')));commands.call(gpg+['--import-ownertrust',str(trust)])
 sys.path.insert(0,str(C.HERE/'core-tools'));import native_arm
 def verify(path,signature,signer):
  status=commands.call(gpg+['--status-fd','1','--verify',str(signature),str(path)]).decode();native_arm.valid_signature(status,signer);C.need(not any('[GNUPG:] '+n in status for n in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR')),'current signer/expiry/revocation complete statuses')
 verify(INPUTS/'catalog.json',INPUTS/'catalog.json.sig',index['test_signer']);verify(INPUTS/'core7-test.db.tar.gz',INPUTS/'core7-test.db.tar.gz.sig',index['test_signer'])
 with tarfile.open(INPUTS/'core7-test.db.tar.gz','r:gz')as repo:
  entries={}
  for member in repo:
   C.need(member.isdir()or member.isfile(),'ordinary signed test repository nodes');C.need(not member.name.startswith('/')and'..'not in Path(member.name).parts,'bounded test repository path')
   if member.isfile():
    C.need(member.name.endswith('/desc')and member.size<=1024**2,'only complete repository desc');raw=repo.extractfile(member).read();fields={};key=None
    for line in raw.decode().splitlines():
     if line.startswith('%')and line.endswith('%'):key=line[1:-1];C.need(key not in fields,'unique repo field');fields[key]=[]
     elif line:C.need(key is not None,'typed repo value');fields[key].append(line)
    name=fields['NAME'][0];C.need(name not in entries and name in C.NAMES,'exact seven repo names');row=C.profile()['packages'][name];C.need(fields['VERSION']==[row['version']]and fields['FILENAME']==[row['filename']]and fields['SHA256SUM']==[row['sha256']]and fields['CSIZE']==[str(row['bytes'])]and base64.b64decode(fields['PGPSIG'][0],validate=True)==C.read(INPUTS/'packages'/(row['filename']+'.sig')),'whole repository metadata/package/signature join');entries[name]=fields
  C.need(set(entries)==C.NAMES,'complete signed Core7 repo set')
 catalog=json.loads(C.read(INPUTS/'catalog.json'));C.need(catalog['before']==C.states()[0]and catalog['after']==C.states()[2]and catalog['native_origin']==C.profile()['accepted_build']and catalog['signer_roles']==dict(ephemeral_TEST=index['test_signer'],upstream_ALARM='68B3537F39A313B3E574D06777193F152BDBE6A6'),'complete signed fixed Core7 TEST catalog')
 packages={};wanted={}
 for key,row in catalog['products'].items():
  path=INPUTS/'packages'/row['file'];sig=Path(str(path)+'.sig');C.need(C.pin(C.read(path,128*1024**2))==row['archive']and C.pin(C.read(sig))==row['signature'],'whole signed local input bytes');verify(path,sig,row['signer']);a=C.P.archive(path);C.need(a['metadata']['pkgname']==[row['name']]and a['metadata']['pkgver']==[row['version']],'signed archive identity')
  role='CORE7'if key in C.NAMES else('SUPPORT'if row['name']in C.profile()['support']else'ROLLBACK');C.need(row['kind']==role and row['signer']==(index['test_signer']if role=='CORE7'else catalog['signer_roles']['upstream_ALARM']),'exact original-vs-TEST signer role separation')
  if role=='CORE7':expected=C.profile()['packages'][key];C.need(row['archive']=={k:expected[k]for k in('bytes','sha256')}and a['metadata']==expected['fields'],'same accepted native seven bytes/full PKGINFO')
  else:
   original=C.closure()['support'][row['name']]if role=='SUPPORT'else index['rollback_rows'][row['name']];C.need(row['archive']==dict(bytes=original['size'],sha256=original['sha256'])and row['signature']==dict(bytes=original['signature_size'],sha256=original['signature_sha256']),'exact original support/rollback archive and signature')
  packages[key]=dict(observed=a,transaction=dict(name=row['name'],version=row['version'],archive=path,signature=sig,signer=row['signer']));wanted[row['file']]=row['archive'];wanted[row['file']+'.sig']=row['signature']
 C.need(set(packages)==C.NAMES|{n+'-original'for n in C.REPLACED|set(C.profile()['support'])}and set(p.name for p in(INPUTS/'packages').iterdir())==set(wanted),'closed exact25 archive/signature inputs only');return keys,packages

def payload(nodes,packages,backups=()):
 for package in packages:
  for name,row in package['nodes'].items():
   if row['type']=='directory'or name in backups:continue
   C.need(name in nodes and all(nodes[name].get(k)==v for k,v in row.items()),'complete installed payload identity '+name)
  groups={}
  for name,row in package['nodes'].items():
   if'hardlink_group'in row:groups.setdefault(row['hardlink_group'],set()).add(name)
  for key,names in groups.items():C.need({n for n,row in nodes.items()if row.get('hardlink_group')==key}==names,'entire package hardlink group equality')

def smoke(commands,api,root,expected,label,report):
 C.need(inventory(api,root)==expected,'complete installed589/held574 inventory before execution');rows={}
 for key,argv in(('pacman-version',['/usr/bin/pacman','--version']),('systemd-version',['/usr/lib/systemd/systemd','--version']),('udev-version',['/usr/bin/udevadm','--version']),('pacman-db',['/usr/bin/pacman','-Dk'])):rows[key]=C.pin(commands.inside(root,argv))
 actual=commands.inside(root,['/usr/bin/pacman','-Q']).decode();C.need(dict(line.split(' ',1)for line in actual.splitlines())==expected,'installed pacman actual complete DB readback');rows['pacman-inventory']=C.pin(actual.encode());report[label]=rows

def scriptlet(commands,root,packages,new_version,old_version,report,label):
 script=packages['systemd']['observed']['data']['.INSTALL']if new_version=='262-1.2'else packages['systemd-original']['observed']['data']['.INSTALL'];path=root/'tmp/core-systemd.install';C.need(not path.exists(),'fresh exact scriptlet lease');path.write_bytes(script)
 try:
  C.need(not(root/'run/systemd/system').exists()and not(root/'run/systemd/system').is_symlink(),'never a booted host/target service manager');out=commands.inside(root,['/usr/bin/bash','--noprofile','--norc','-e','-x','-c','cd /; source /tmp/core-systemd.install; post_upgrade "$1" "$2"','original-complete-systemd-post-upgrade',new_version,old_version]);report[label]=dict(script=C.pin(script),stdout=C.pin(out),automatic_hooks='ORIGINAL_DISABLED',live_PID1_bus_boot='NOT_RUN')
 finally:path.unlink()

def baseline_step(commands,root,packages,version):
 script=packages['systemd-original']['observed']['data']['.INSTALL'];path=root/'tmp/core-systemd.install';C.need(C.pin(script)==F.SCRIPT_PIN,'exact original authenticated baseline INSTALL');C.need(not path.exists(),'fresh signed ORIGINAL baseline scriptlet lease');path.write_bytes(script)
 try:
  C.need(not(root/'run/systemd/system').exists()and not(root/'run/systemd/system').is_symlink(),'never booted fixture service manager');commands.call(F.baseline_argv(root,version))
 finally:path.unlink()

def configuration(nodes,initial,old,new,installed):
 defaults_old={n:r for p in old for n,r in p['nodes'].items()if n in p['metadata'].get('backup',[])};defaults_new={n:r for p in new for n,r in p['nodes'].items()if n in p['metadata'].get('backup',[])}
 for n,row in(defaults_new if installed else defaults_old).items():
  previous=initial.get(n);old_default=defaults_old.get(n);modified=previous is not None and(old_default is None or previous.get('sha256')!=old_default.get('sha256'));expected=previous if modified else row
  C.need(n in nodes and all(nodes[n].get(k)==v for k,v in expected.items()),'complete active config expected standard ALPM preservation/default '+n)
  known=[r for r in(previous,defaults_old.get(n),defaults_new.get(n))if r is not None]
  for suffix in('.pacnew','.pacsave'):
   if n+suffix in nodes:C.need(any(all(nodes[n+suffix].get(k)==v for k,v in r.items())for r in known),'sidecar is exact initial/held/candidate bytes and metadata '+n)


def run_case(api,commands,index,packages,case,report):
 base,_,installed=C.states();report['status']='FAIL';source=snapshot(api,HELD,case+'-source-before',index,report);C.need(inventory(api,HELD)==base,'exact source574');old=[packages[n+'-original']['observed']for n in C.REPLACED];support=[packages[n+'-original']['observed']for n in C.profile()['support']];new=[packages[n]['observed']for n in C.NAMES];all_packages=old+support+new;versions=[(n,v)for n,v in installed.items()if n in C.NAMES|set(C.profile()['support'])]+[(n,base[n])for n in C.REPLACED];backups={n for p in all_packages for n in p['metadata'].get('backup',[])};sidecars={n+s for n in backups for s in('.pacnew','.pacsave')};evidence={}
 try:
  with api['capabilities'].copied_root(api,HELD,WORK/case,index,evidence=evidence,limits=budget(api),cleanup_seconds=120)as(root,lifetime):
   C.need(lifetime['copy']['copy_byte_identical_before_initialization']is True,'whole clone byte identity');C.need(inventory(api,root)==base,'complete clone DB');report['copy_evidence']=evidence
   for n in C.FIXTURES:
    original=next(p['data'][n]for p in old if n in p['data']);path=root/n;path.write_bytes(original+(b'\n# Core7 owned modified configuration\n'if case=='modified'else b''))
   before_accounts=F.accounts(root);baseline_step(commands,root,packages,base['systemd']);first=snapshot(api,root,case+'-fixture-first',index,report);first_cache=F.capture(api,root,first,budget(api),F.read_aux(root));after_accounts=F.accounts(root);baseline_step(commands,root,packages,base['systemd'])
   initial=snapshot(api,root,case+'-initial',index,report);second_cache=F.capture(api,root,initial,budget(api),F.read_aux(root));proof=dict(before_accounts=before_accounts,after_accounts=after_accounts,second_accounts=F.accounts(root),account_transition=F.initialized_accounts(before_accounts,after_accounts),first_cache=first_cache,second_cache=second_cache,cache_idempotence=F.cache_pair(first_cache,second_cache,initial['nodes']),script=C.pin(packages['systemd-original']['observed']['data']['.INSTALL']));F.initialization(source['nodes'],first['nodes'],initial['nodes'],proof,C.FIXTURES);report['baseline_initialization']=dict(proof,first_cache=F.save_record(OUT,case+'-fixture-first',first_cache),second_cache=F.save_record(OUT,case+'-initial',second_cache));report['cache_transitions']={};checkpoint();before_config={n:initial['nodes'][n]for n in C.FIXTURES};add=[packages[n]['transaction']for n in sorted(C.NAMES)]+[packages[n+'-original']['transaction']for n in C.profile()['support']];rollback=[packages[n+'-original']['transaction']for n in sorted(C.REPLACED)];remove={n:installed[n]for n in set(installed)-set(base)};keys=Path('/tmp/core-public-gpg');report['transactions']={}
   report['transactions']['precommit-refused']=T.apply(api,root,keys,OUT/(case+'-precommit.log'),add,{},base,installed,END,prepare_only=True);pre=snapshot(api,root,case+'-precommit-refused',index,report);C.need(pre['nodes']==initial['nodes']and pre.get('hardlink_groups')==initial.get('hardlink_groups'),'complete precommit refusal leaves graph unchanged')
   for stage in C.STAGES[1:]:
    install=stage in('install','repeat-install');reinstall=stage=='reinstall';before=base if install else installed;after=installed if install or reinstall else base;rows=add if install else([packages[n]['transaction']for n in sorted(C.NAMES)]if reinstall else rollback);report['latest_phase']=stage;checkpoint();report['transactions'][stage]=T.apply(api,root,keys,OUT/(case+'-'+stage+'.log'),rows,{}if install or reinstall else remove,before,after,END)
    with api['proc_probe'].runtime_mounts(root,report):
     if not reinstall:scriptlet(commands,root,packages,'262-1.2'if install else base['systemd'],base['systemd']if install else'262-1.2',report,stage+'-scriptlet')
     smoke(commands,api,root,after,stage,report)
     if after==installed:
      for name in('systemd-tests','systemd-ukify'):
       row=packages[name]['observed'];C.need(row['metadata']['pkgver']==['262-1.2'],'both optional split packages actually installed')
      commands.inside(root,['/usr/bin/ukify','--version'])
      for program in('test-id128','test-prioq','test-list'):commands.inside(root,['/usr/lib/systemd/tests/unit-tests/'+program])
    raw=F.read_aux(root);before_aux=dict(raw=C.pin(raw),data=base64.b64encode(raw).decode());commands.inside(root,['/usr/bin/ldconfig']);observed=snapshot(api,root,case+'-'+stage,index,report);cache=F.capture(api,root,observed,budget(api),F.read_aux(root));report['cache_transitions'][stage]=dict(before=before_aux,after=F.save_record(OUT,case+'-'+stage,cache),idempotence=F.cache_pair(before_aux,cache,observed['nodes']));checkpoint();C.need(inventory(api,root)==after,'actual exact after transaction');payload(observed['nodes'],new+support if after==installed else old,backups);F.changes(initial['nodes'],observed['nodes'],all_packages,versions,sidecars,cache);configuration(observed['nodes'],initial['nodes'],old,new,after==installed)
    if case=='modified':C.need(all(observed['nodes'].get(n)==r for n,r in before_config.items()),'active user configuration exact bytes/mode/owner preserved')
   final=snapshot(api,root,case+'-final',index,report);C.need(inventory(api,root)==base,'original574 restored after repeat');report['final_preservation']=F.changes(initial['nodes'],final['nodes'],all_packages,versions,sidecars,F.load_record(OUT,report['cache_transitions']['repeat-rollback']['after']));report['status']='PENDING_COPY_AND_SOURCE_CLEANUP';report['copy_lifetime']=lifetime
 finally:
  after=snapshot(api,HELD,case+'-source-after',index,report);C.need(source['nodes']==after['nodes']and source.get('hardlink_groups')==after.get('hardlink_groups')and source['security_capabilities']==after['security_capabilities'],'complete readonly original source graph/capabilities preserved');C.need(not(WORK/case).exists()and evidence.get('lifetime',{}).get('cleanup')=='PASS-owned-workspace-removed','owned copied-root disposal complete')
 report['status']='PASS_CORE7_INSTALLED_REINSTALLED_ROLLED_BACK_AND_REPEATED';checkpoint()

def main():
 argparse.ArgumentParser(description=__doc__).parse_args()
 global END,REPORT,START
 C.need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_GNU_PROVIDER_LIFECYCLE')=='1'and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline native container only');os.chown(WORK,0,0);WORK.chmod(0o700);START=time.monotonic();END=START+3600;index=json.loads(C.read(INPUTS/'lifecycle-input.json'));C.need(index['scope']=='DISPOSABLE_CORE7_NATIVE_LIFECYCLE'and index['source_capabilities_sha256']==C.pin(C.encoded(index['source_capabilities']))['sha256'],'fixed original source map binding');common=load('held_complete574_common',SOURCE/'scripts/ci/glibc-gnu-provider-lifecycle/common.py');api=common.helpers(SOURCE);api['capability_index']=index;report=dict(status='FAIL',commands=[],cases={},hardware='NOT_RUN',Asahi='NOT_RUN',old_target261='UNCHANGED_UNACCEPTED',live_service_manager_boot='NOT_RUN',release='NOT_ADMITTED');commands=Commands(api,report);REPORT=report;keys=None;checkpoint()
 try:
  apparmor=load('held_core_inside_apparmor',SOURCE/'scripts/ci/glibc-gnu-trial-apparmor/profile.py');report['apparmor']=apparmor.inside(index['token'],'lifecycle');report['proc_preflight']=api['proc_probe'].check(commands,WORK);keys,packages=public_keys(commands,index)
  for case in C.CASES:report['latest_case']=case;report['cases'][case]={};checkpoint();run_case(api,commands,index,packages,case,report['cases'][case])
  C.need(not any(WORK.iterdir())and time.monotonic()<END,'no private copy remains; original3600 clock held');report['status']='PASS_DISPOSABLE_CORE7_NATIVE_LIFECYCLE'
 except BaseException as error:report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:512])
 finally:
  if keys is not None:
   try:
    commands.call(['/usr/bin/gpgconf','--homedir',str(keys),'--kill','all'],seconds=15,cleanup=True);C.need(not any(os.path.lexists(keys/n)for n in('S.gpg-agent','S.gpg-agent.extra','S.gpg-agent.browser','S.gpg-agent.ssh')),'public verifier agent absence');shutil.rmtree(keys);report['public_home_cleanup']='PASS'
   except BaseException as error:report.update(status='FAIL',public_home_cleanup='FAIL_OR_UNESTABLISHED',key_cleanup_error=str(error)[:512])
  report.update(seconds=time.monotonic()-START,lifecycle_seconds_limit=3600);(OUT/'result.json').write_bytes(C.encoded(report));uid,gid=int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID'])
  for p in OUT.iterdir():C.need(p.is_file()and not p.is_symlink(),'closed ordinary public evidence');os.chown(p,uid,gid)
  os.chown(WORK,uid,gid)
 return int(report['status']!='PASS_DISPOSABLE_CORE7_NATIVE_LIFECYCLE')
if __name__=='__main__':
 def cancelled(*_):raise KeyboardInterrupt()
 for number in(signal.SIGTERM,signal.SIGINT):signal.signal(number,cancelled)
 raise SystemExit(main())
