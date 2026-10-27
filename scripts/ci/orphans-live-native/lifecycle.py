#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real installed0.3 explicit-target removal, only inside an isolated ARM container."""
import ctypes,hashlib,importlib.util,json,os,re,signal,stat,subprocess,time
from pathlib import Path

PREFIX='caa-orphans3-'
ROLES=('leaf-a','leaf-b','explicit','required','hard-user','optional','optional-user','protected')
FIXTURES={PREFIX+n for n in ROLES}
PRODUCT='cachy-asahi-orphans';VERSION='0.3.0-2';CLI='/usr/bin/'+PRODUCT
SOURCE=Path('/source');INPUTS=Path('/inputs');OUT=Path('/out');WORK=Path('/work')
MAX_MAP=128*1024**2
STATUS='PASS_ORPHANS03_REAL_NATIVE_EXPLICIT_TARGET_REMOVAL'
SCOPE='PRIVATE_EXPLICIT_LIVE_CLI_FIXTURE_ONLY'
EVENT_CASES=('missing-authorization','target-mismatch','policy-hash','different-selection','duplicate-selection','same-bytes-assessment','same-bytes-policy','foreign-lock','positive','stale-after-removal','helper-alias','unsafe-payload','matching-hook')
UNCHANGED_CASES=tuple(n for n in EVENT_CASES if n!='positive')+tuple('protected-needed-'+n for n in ('protected','explicit','required','optional'))
PACKAGE_PHASES=('install','repeat','remove','reinstall','final-remove')
FLAGS=(1<<7)|(1<<10)



def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def guard():
    need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file()
         and os.environ.get('CACHY_ASAHI_ORPHANS03_NATIVE')=='lifecycle','dedicated native root container PID1 required')
    interfaces={line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    need(interfaces=={'lo'},'network-isolated native consumer required')
    need(not WORK.exists() and OUT.is_dir() and INPUTS.is_dir() and SOURCE.is_dir(),'closed source/inputs/output and fresh private work required')


def archives(control,inputs=INPUTS):
    need(type(control) is dict and set(control)=={'signer','candidate','fixtures'} and re.fullmatch('[0-9A-F]{40}',control['signer']), 'exact TEST control schema')
    need(type(control['fixtures']) is dict and set(control['fixtures'])==FIXTURES,'exact eight inert fixtures required')
    rows={PRODUCT:control['candidate'],**control['fixtures']};paths={}
    for name,row in rows.items():
        need(type(row) is dict and set(row)=={'archive','sha256'} and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact archive hash row')
        version=VERSION if name==PRODUCT else '1-1';need(row['archive'] in {name+'-'+version+'-any.pkg.tar.'+s for s in ('xz','zst')},'fixed native archive basename')
        p=inputs/row['archive'];s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=16*1024**2 and sha(p)==row['sha256'],'ordinary exact archive bytes')
        signature=p.with_name(p.name+'.sig');s=signature.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16384,'detached signature required');paths[name]=p
    actual={p.name for p in inputs.iterdir() if '.pkg.tar.' in p.name and not p.name.endswith('.sig')}
    need(actual=={p.name for p in paths.values()},'no additional native archives allowed');return paths


def node(path):
    s=path.lstat();result=dict(dev=s.st_dev,ino=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,
      links=s.st_nlink,bytes=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
    if stat.S_ISDIR(s.st_mode):result['kind']='directory'
    elif stat.S_ISLNK(s.st_mode):result.update(kind='symlink',target=os.readlink(path))
    else:
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=128*1024**2,'bounded ordinary map node')
        result['kind']='file'
        # Real ALPM lock is mode000; its complete inode metadata is retained.
        if path.name!='db.lck':result['sha256']=sha(path)
    after=path.lstat();need(all(getattr(s,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'map node changed during read');return result


def snapshot(root):
    rows={'.':node(root)};spent=0
    for parent,dirs,names in os.walk(root,followlinks=False):
        for name in sorted(dirs+names):
            path=Path(parent)/name;relative=str(path.relative_to(root));row=node(path);rows[relative]=row
            need(len(rows)<=32768,'finite inert target map');spent+=row['bytes'] if row['kind']=='file' else 0;need(spent<=MAX_MAP,'finite inert target bytes')
    return rows


def preservation(before,after,removed=()):
    """Exact non-directory identity/bytes; only declared removals and parent stats."""
    allowed=set(removed)
    need(set(after)<=set(before),'unexpected target entries appeared')
    need(set(before)-set(after)<=allowed,'undeclared target entry removed')
    for path,current in after.items():
        old=before[path]
        if old['kind']=='directory':need(all(current.get(k)==old[k] for k in ('kind','dev','ino','mode','uid','gid')),'target directory replaced or permissions changed: '+path)
        else:need(current==old,'unselected payload/database identity or bytes changed: '+path)
    return True


def positive_removed(before):
    leaf=PREFIX+'leaf-a';prefixes=('var/lib/pacman/local/'+leaf+'-1-1','usr/share/licenses/'+leaf)
    return {name for name in before if name=='usr/share/orphans3-fixture/'+leaf+'.txt' or any(name==p or name.startswith(p+'/') for p in prefixes)}

def validate_lifecycle(value):
    """Pure result gate. File/hash/map replay is performed by the matching reader."""
    pin=lambda v:type(v) is str and re.fullmatch('[0-9a-f]{64}',v)
    need(type(value) is dict and value.get('status')==STATUS and value.get('version')==VERSION and value.get('scope')==SCOPE and value.get('real_backend') is True,'exact0.3 real explicit-target lifecycle required')
    need(value.get('architecture')=='aarch64' and type(value.get('page_size')) is int and value['page_size']>0 and value.get('hardware')=='NOT_RUN' and value.get('release')=='NOT_ADMITTED','native fixture evidence grants no hardware/release authority')
    before={n:'1-1' for n in FIXTURES};after={n:v for n,v in before.items() if n!=PREFIX+'leaf-a'}
    need(value.get('before')==before and value.get('after')==after and value.get('before_count')==8 and value.get('after_count')==7 and value.get('base574_preserved') is True and value.get('configuration_preserved') is True and value.get('final_lock')=='ABSENT','exact8to7/base574/configuration preservation required')
    commands=value.get('commands');need(type(commands) is list and bool(commands),'complete actual command records required');by_index={}
    for index,row in enumerate(commands,1):
        need(type(row) is dict and type(row.get('index')) is int and row['index']==index and type(row.get('argv')) is list and row['argv'] and all(type(a) is str for a in row['argv']) and type(row.get('exitcode')) is int and type(row.get('expected_exit')) is int and row['exitcode']==row['expected_exit'] and type(row.get('stdout')) is str and type(row.get('stderr')) is str and 'error_type' not in row,'actual command exit/stdout/stderr must be complete')
        by_index[index]=row
    backend=value.get('installed_backend',{});need(backend.get('path')=='/usr/lib/cachy-asahi-orphans3/live.py' and backend.get('class_name')=='LiveTransaction' and backend.get('module')=='orphans03_installed_actual_backend' and pin(backend.get('sha256')),'actual installed0.3 backend identity required')
    policy=value.get('policy_contract',{});need(policy.get('path')=='reports/live-policy.json' and pin(policy.get('sha256')),'retained reviewed policy required')
    expected=dict(schema_version=1,profile='private-fixture',root=str(WORK/'root'),dbpath=str(WORK/'root/var/lib/pacman'),supported_base={PREFIX+n:'1-1' for n in ('explicit','hard-user','optional-user')},platform={PREFIX+'protected':'1-1'},transaction_flags=FLAGS,hooks='refuse-matching',scriptlets='refuse',configuration='refuse-selected',ldconfig=dict(mode='forbid'))
    need(policy.get('value')==expected and hashlib.sha256(encoded(expected)).hexdigest()==policy['sha256'],'exact helper-free explicit fixture policy required')
    events=value.get('events');need(type(events) is list and all(type(e) is dict for e in events) and [e.get('case') for e in events]==list(EVENT_CASES),'complete ordered0.3 event set required');seen=set()
    for event in events:
        case=event['case'];index=event.get('command_index');row=by_index.get(index)
        need(type(index) is int and index not in seen and row is not None and row['argv'][:3]==[CLI,'live','remove'],'event must link a distinct actual installed live CLI remove command');seen.add(index);argv=row['argv']
        for flag in ('--target-root','--target-dbpath','--policy','--policy-sha256','--plan-sha256','--result'):
            need(argv.count(flag)==1 and argv.index(flag)+1<len(argv),'every target/policy/plan/output argument must be explicit')
        argument=lambda flag:argv[argv.index(flag)+1]
        root,db=('/','/var/lib/pacman') if case=='target-mismatch' else (str(WORK/'root'),str(WORK/'root/var/lib/pacman'))
        need(argument('--target-root')==root and argument('--target-dbpath')==db and argument('--policy')==str(OUT/'reports/live-policy.json') and argument('--policy-sha256')==('0'*64 if case=='policy-hash' else policy['sha256']) and pin(argument('--plan-sha256')) and argument('--result')==str(OUT/'reports'/case/'result.json'),'explicit event target/policy/plan/output binding differs')
        selected=[argv[n+1] for n,arg in enumerate(argv) if arg=='--select' and n+1<len(argv)]
        leaf='leaf-b' if case in ('different-selection','helper-alias','unsafe-payload','matching-hook') else 'leaf-a'
        need(selected==[PREFIX+leaf]*(2 if case=='duplicate-selection' else 1),'actual event selection differs')
        need(argv.count('--authorize-live-removal')==(0 if case=='missing-authorization' else 1),'operator authorization command binding differs')
        actual=event.get('result')
        if case=='missing-authorization':
            need(actual is None and event.get('durable_result') is None and event.get('refusal_stage')=='ARGPARSE' and row['exitcode']==2 and not row['stdout'].strip() and '--authorize-live-removal' in row['stderr'],'missing authorization must be an observed parse refusal, without fabricated product result')
            continue
        need(type(actual) is dict and event.get('refusal_stage')=='PRODUCT' and actual.get('scope')=='EXPLICIT_LIVE_ORPHAN_TARGET_V1','actual0.3 JSON product result required')
        need(json.loads(row['stdout'])==actual,'event result differs from actual command stdout')
        if case=='positive':
            need(actual.get('root')==str(WORK/'root') and actual.get('dbpath')==str(WORK/'root/var/lib/pacman') and actual.get('selected')=={PREFIX+'leaf-a':'1-1'} and actual.get('target',{}).get('profile')=='private-fixture' and actual.get('effects',{}).get('ldconfig',{}).get('mode')=='forbid','positive receipt must bind the explicit helper-free private fixture')
            worker=actual.get('worker',{})
            need(row['exitcode']==0 and actual.get('status')=='APPLIED' and actual.get('commit_started') is True and actual.get('packages_committed') is True and actual.get('transaction_flags')==FLAGS and actual.get('prepared_add')=={} and actual.get('prepared_remove')=={PREFIX+'leaf-a':'1-1'} and actual.get('transaction_released') is True and actual.get('handle_released') is True and actual.get('lock_state')=='ABSENT' and actual.get('cleanup_errors')==[] and worker.get('reaped') is True and worker.get('exitcode')==0 and worker.get('ownership')=='REAPED' and worker.get('session_registered') is True and worker.get('descendant_exit')=='UNKNOWN_NOT_DIRECTLY_REAPED' and event.get('durable_result')=='reports/positive/result.json','exact actual0.3 commit/session/cleanup receipt required')
        else:need(row['exitcode']==1 and actual.get('status')=='REFUSED' and actual.get('commit_started') is False and actual.get('packages_committed') is False,'actual negative product result must establish no commit')
        durable=event.get('durable_result');need(durable is None or durable=='reports/'+case+'/result.json','fixed result receipt path required')
    phases=value.get('package_lifecycle');need(type(phases) is list and all(type(p) is dict for p in phases) and [r.get('phase') for r in phases]==list(PACKAGE_PHASES),'complete installed package lifecycle required');last=0
    for phase in phases:
        installed=phase['phase'] in ('install','repeat','reinstall');row=by_index.get(phase.get('command_index'));query=by_index.get(phase.get('identity_command'))
        need(phase.get('installed') is installed and phase.get('version')==VERSION and row is not None and query is not None and row['index']>last and query['index']==row['index']+1 and query['argv']==['/usr/bin/pacman','-Q',PRODUCT],'package phase must link actual mutation and identity query');last=query['index']
        need(row['argv'][0]=='/usr/bin/pacman' and ('-U' in row['argv']) is installed and ('-R' in row['argv']) is (not installed) and ('--noscriptlet' in row['argv']) is installed,'operation-specific pacman flags required')
        need(query['exitcode']==(0 if installed else 1) and query['stdout']==(PRODUCT+' '+VERSION+'\n' if installed else ''),'actual installed/removal identity evidence differs')
    cleanup=value.get('cleanup',{});need(cleanup.get('outer_candidate')=='REMOVED' and cleanup.get('foreign_lock')=='RELEASED_BY_OWN_HANDLE' and cleanup.get('TEST_agents')=='STOPPED' and cleanup.get('outer_container')=='PARENT_MUST_VERIFY_ABSENCE_AFTER_ACTOR_EXIT','complete owned inner cleanup required')
    maps=value.get('maps',{});required={'positive-before','positive-after','final-target'}|{case+'-'+side for case in UNCHANGED_CASES for side in ('before','after')}
    need(type(maps) is dict and set(maps)==required,'complete actual preservation maps required')
    for name,row in maps.items():need(type(row) is dict and row.get('path')=='maps/'+name+'.json' and pin(row.get('sha256')) and type(row.get('nodes')) is int and row['nodes']>0,'bounded actual map reference required')
    for key,path in (('base_before','base-before.json'),('base_after','base-after.json')):
        row=value.get(key,{});need(row.get('path')==path and pin(row.get('sha256')) and type(row.get('nodes')) is int and row['nodes']>0,'complete original574 base reference required')
    need(pin(value.get('base_preservation_sha256')),'original574 preservation digest required')
    configured=value.get('configuration_before',{});need(configured.get('kind')=='file' and configured.get('mode')==0o640 and pin(configured.get('sha256')),'actual authored configuration identity required')
    ownership=value.get('selected_ownership',{});need(ownership.get('package')==PREFIX+'leaf-a' and ownership.get('version')=='1-1' and type(ownership.get('paths')) is list and ownership['paths'] and len(set(ownership['paths']))==len(ownership['paths']),'actual selected installed file ownership required')
    regular={'usr/share/orphans3-fixture/'+PREFIX+'leaf-a.txt','usr/share/licenses/'+PREFIX+'leaf-a/LICENSE'}
    allowed=regular|{str(p) for name in regular for p in Path(name).parents if str(p)!='.'}
    need(regular<=set(ownership['paths']) and all(type(n) is str and n.rstrip('/') in allowed for n in ownership['paths']),'fixed inert selected ownership paths required')
    release=value.get('foreign_lock_release',{});need(release.get('transaction_released') is True and release.get('handle_released') is True and release.get('cleanup_errors')==[],'actual foreign holder release required')
    need(value.get('ownership_query_cleanup',{}).get('handle_released') is True,'actual ownership query handle release required')
    return value


class Trial:
    def __init__(self):
        self.report=dict(status='FAIL',version=VERSION,real_backend=True,architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),
            hardware='NOT_RUN',release='NOT_ADMITTED',scope=SCOPE,commands=[],events=[],fixture_edits=[],maps={},package_lifecycle=[],cleanup={'target':'NOT_CREATED','outer_candidate':'NOT_INSTALLED','foreign_lock':'NOT_HELD'})
        self.until=time.monotonic()+600;self.count=0;self.holder=None;self.trust=None
    def save(self):
        raw=encoded(self.report);need(len(raw)<=16*1024**2,'finite lifecycle report');p=OUT/'lifecycle.pending';p.write_bytes(raw);os.replace(p,OUT/'lifecycle.json')
    def command(self,argv,expected=0,timeout=60,stdin=None):
        need(time.monotonic()<self.until,'native actor deadline exhausted');self.count+=1
        row=dict(index=self.count,argv=list(map(str,argv)),expected_exit=expected)
        if stdin is not None:row['stdin']=stdin.decode()
        self.report['commands'].append(row);self.save()
        try:
            result=subprocess.run(row['argv'],**({'input':stdin} if stdin is not None else {'stdin':subprocess.DEVNULL}),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=min(timeout,max(0.01,self.until-time.monotonic())),env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',HOME='/root',TZ='UTC',PYTHONDONTWRITEBYTECODE='1'))
            need(len(result.stdout)+len(result.stderr)<=4*1024**2,'native command output bound')
            row.update(exitcode=result.returncode,stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace'))
            self.save();need(result.returncode==expected,'native command unexpected exit: '+row['argv'][0]);return row['stdout']
        except BaseException as error:
            row.update(error_type=type(error).__name__,error=str(error)[:500],exitcode=row.get('exitcode','UNKNOWN'));self.save();raise
    def map(self,name,root):
        rows=snapshot(root);p=OUT/'maps'/(name+'.json');p.parent.mkdir(exist_ok=True);p.write_bytes(encoded(rows));self.report['maps'][name]=dict(path='maps/'+p.name,sha256=sha(p),nodes=len(rows));self.save();return rows
    def inventory(self,pacman):
        lines=self.command(pacman+['-Q']).splitlines();result=dict(line.split() for line in lines);need(len(result)==len(lines),'unique real installed identities');return result
    def signed_pacman(self,signer):
        hooks=Path('/tmp/orphans-hooks');hooks.mkdir();masked=set()
        for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
            for path in Path(parent).glob('*.hook'):
                if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
        self.trust='/tmp/orphans-trust';Path(self.trust).mkdir(mode=0o700)
        gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',self.trust,'--no-auto-key-retrieve']
        shown=self.command(gpg+['--with-colons','--import-options','show-only','--import',INPUTS/'TEST-public.asc'])
        need(signer in [line.split(':')[9] for line in shown.splitlines() if line.startswith('fpr:')],'exact TEST verification signer')
        self.command(gpg+['--import',INPUTS/'TEST-public.asc']);self.command(gpg+['--import-ownertrust'],stdin=(signer+':6:\n').encode())
        config=Path('/tmp/orphans-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = '+str(hooks)+'\nGPGDir = '+self.trust+'\n')
        return ['/usr/bin/pacman','--config',str(config),'--noconfirm']
    def live_args(self,*,target=None,policy_pin=None):
        root,db=target if target is not None else (self.root,self.db)
        return ['--target-root',str(root),'--target-dbpath',str(db),'--policy',str(self.policy),'--policy-sha256',policy_pin or self.policy_sha]
    def prepare(self,label,select='leaf-a'):
        d=OUT/'reports'/label;d.mkdir(parents=True,mode=0o700);assessment=d/'assessment.json';plan=d/'plan.json'
        self.command([CLI,'live','assess',*self.live_args(),'--output',assessment])
        actual=json.loads(assessment.read_bytes());expected=[PREFIX+'leaf-a',PREFIX+'leaf-b'] if len(actual['installed']['packages'])==8 else [PREFIX+'leaf-b']
        need(actual['eligible_candidates']==expected,'exact current actual live candidate set')
        self.command([CLI,'live','plan',assessment,*self.live_args(),'--select',PREFIX+select,'--output',plan])
        reviewed=json.loads(plan.read_bytes());need(reviewed['operation']=='EXPLICIT_LIVE_ORPHAN_REMOVAL_PLAN' and reviewed['root']==str(self.root) and set(reviewed['selected'])=={PREFIX+select} and reviewed['transaction_flags']==FLAGS,'actual exact explicit-target plan required')
        return assessment,plan
    def remove(self,label,plan,names,expected=1,*,authorize=True,target=None,policy_pin=None):
        d=OUT/'reports'/label;d.mkdir(parents=True,mode=0o700);output=d/'result.json'
        argv=[CLI,'live','remove',plan,*self.live_args(target=target,policy_pin=policy_pin),'--plan-sha256',sha(plan)]
        for name in names:argv+=['--select',PREFIX+name]
        if authorize:argv+=['--authorize-live-removal']
        argv+=['--result',output,'--timeout-seconds','60'];raw=self.command(argv,expected=expected)
        value=json.loads(raw) if raw.strip() else None
        if output.exists():need(value is not None and json.loads(output.read_bytes())==value,'durable/stdout live result differs')
        need(value is not None or expected==2 and not authorize and not output.exists(),'empty result is only an observed authorization parse refusal')
        self.report['events'].append(dict(case=label,command_index=self.count,result=value,durable_result=str(output.relative_to(OUT)) if output.exists() else None,refusal_stage='ARGPARSE' if value is None else 'PRODUCT'))
        self.save();return value
    def unchanged(self,label,operation):
        before=self.map(label+'-before',self.root);value=operation();after=self.map(label+'-after',self.root);preservation(before,after)
        need(not (self.db/'db.lck').exists(),'refusal left an uncertain native lock');return value
    def package_phase(self,outer,path,phase,installed):
        operation=['--noscriptlet','-U',path] if installed else ['-R',PRODUCT]
        self.command(outer+operation);mutation=self.count
        self.report['cleanup']['outer_candidate']='INSTALLED' if installed else 'REMOVED';self.save()
        actual=self.command(['/usr/bin/pacman','-Q',PRODUCT],expected=0 if installed else 1)
        if installed:need(actual==PRODUCT+' '+VERSION+'\n','installed candidate package version')
        else:need(actual=='','removed candidate must not remain in installed inventory')
        self.report['package_lifecycle'].append(dict(phase=phase,command_index=mutation,identity_command=self.count,installed=installed,version=VERSION));self.save()
    def run(self):
        control=json.loads((INPUTS/'control.json').read_bytes());paths=archives(control)
        L=load('orphans3_existing_welcome',SOURCE/'scripts/ci/welcome-native/lifecycle.py');I=load('orphans3_existing_installed',SOURCE/'scripts/ci/orphans-native/installed.py');driver=load('orphans3_existing_database',SOURCE/'scripts/ci/full-root-upgrade/root_upgrade.py')
        L.command=self.command;held=I.base_state(L,driver);need(len(held['packages'])==574,'complete original574 base required')
        base_map=OUT/'base-before.json';base_map.write_bytes(encoded(held));need(base_map.stat().st_size<=MAX_MAP,'original574 retention bound')
        self.report['base_before']=dict(path=base_map.name,sha256=sha(base_map),nodes=len(held['nodes']));self.save()
        outer=self.signed_pacman(control['signer'])
        gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',self.trust,'--no-auto-key-retrieve']
        for path in paths.values():
            status=self.command(gpg+['--status-fd','1','--verify',str(path)+'.sig',path]);valid=[line.split()[2:] for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            need(len(valid)==1 and len(valid[0])==10 and valid[0][-1]==control['signer'] and valid[0][7] in ('8','9','10','11') and not re.search(r'\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY)',status),'exact current TEST signature required')
        self.package_phase(outer,paths[PRODUCT],'install',True);self.package_phase(outer,paths[PRODUCT],'repeat',True)
        need(self.command([CLI,'--version'])=='cachy-asahi-orphans 0.3.0\n','installed0.3 identity')
        installed_path=Path('/usr/lib/cachy-asahi-orphans3/live.py');module=load('orphans03_installed_actual_backend',installed_path)
        need(module.LiveTransaction.__module__=='orphans03_installed_actual_backend','real packaged ctypes live backend required')
        self.report['installed_backend']=dict(path=str(installed_path),sha256=sha(installed_path),class_name='LiveTransaction',module=module.LiveTransaction.__module__)
        self.root=WORK/'root';self.root.mkdir(mode=0o700);self.db=self.root/'var/lib/pacman';(self.db/'local').mkdir(parents=True);(self.db/'local/ALPM_DB_VERSION').write_text('9\n')
        config=WORK/'fixture-pacman.conf';config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+self.trust+'\nHookDir = /tmp/orphans-hooks\n')
        cache=WORK/'cache';cache.mkdir();pm=['/usr/bin/pacman','--config',str(config),'--root',str(self.root),'--dbpath',str(self.db),'--gpgdir',self.trust,'--cachedir',str(cache),'--logfile',str(OUT/'fixture-pacman.log'),'--noconfirm']
        self.command(pm+['--noscriptlet','-U','--asdeps',*(paths[n] for n in sorted(FIXTURES))]);self.command(pm+['-D','--asexplicit',*(PREFIX+n for n in ('explicit','hard-user','optional-user'))])
        before=self.inventory(pm);need(before=={n:'1-1' for n in FIXTURES},'real eight-package initial inventory');self.report['before_count']=8;self.report['before']=before;self.report['cleanup']['target']='PRESERVED_OWNED_UNTIL_OUTER_DISPOSAL';self.save()
        authored=self.root/'etc/operator-owned.conf';authored.parent.mkdir();authored.write_text('retained authored configuration\n');authored.chmod(0o640);self.report['configuration_before']=node(authored)
        policy=dict(schema_version=1,profile='private-fixture',root=str(self.root),dbpath=str(self.db),supported_base={PREFIX+n:'1-1' for n in ('explicit','hard-user','optional-user')},platform={PREFIX+'protected':'1-1'},transaction_flags=FLAGS,hooks='refuse-matching',scriptlets='refuse',configuration='refuse-selected',ldconfig=dict(mode='forbid'))
        (OUT/'reports').mkdir(mode=0o700);self.policy=OUT/'reports/live-policy.json';self.policy.write_bytes(encoded(policy));self.policy.chmod(0o600);self.policy_sha=sha(self.policy)
        self.report['policy_contract']=dict(path='reports/live-policy.json',sha256=self.policy_sha,value=policy);self.save()
        assessment,plan=self.prepare('initial');facts=json.loads(assessment.read_bytes())['installed']
        for n in ('leaf-a','leaf-b','required','optional','protected'):need(facts['packages'][PREFIX+n]['reason']=='dependency','real dependency reason required')
        need(facts['packages'][PREFIX+'required']['required_by']==[PREFIX+'hard-user'] and facts['packages'][PREFIX+'optional']['optional_required_by']==[PREFIX+'optional-user'] and facts['packages'][PREFIX+'protected']['protected'] is True,'actual dependency/protection facts')
        self.unchanged('missing-authorization',lambda:self.remove('missing-authorization',plan,['leaf-a'],expected=2,authorize=False))
        self.unchanged('target-mismatch',lambda:self.remove('target-mismatch',plan,['leaf-a'],target=(Path('/'),Path('/var/lib/pacman'))))
        self.unchanged('policy-hash',lambda:self.remove('policy-hash',plan,['leaf-a'],policy_pin='0'*64))
        self.unchanged('different-selection',lambda:self.remove('different-selection',plan,['leaf-b']))
        self.unchanged('duplicate-selection',lambda:self.remove('duplicate-selection',plan,['leaf-a','leaf-a']))
        for name in ('protected','explicit','required','optional'):
            def reject(name=name):return self.command([CLI,'live','plan',assessment,*self.live_args(),'--select',PREFIX+name,'--output',OUT/'reports'/('refused-'+name+'.json')],expected=1)
            self.unchanged('protected-needed-'+name,reject)
        old=assessment.read_bytes();old_identity=node(assessment);replacement=assessment.with_suffix('.replacement');replacement.write_bytes(old);replacement.chmod(0o600);replacement.replace(assessment)
        self.report['fixture_edits'].append(dict(case='same-bytes-assessment',path=str(assessment.relative_to(OUT)),before=old_identity,after=node(assessment)));self.save()
        self.unchanged('same-bytes-assessment',lambda:self.remove('same-bytes-assessment',plan,['leaf-a']))
        _,plan=self.prepare('before-policy-change');old_identity=node(self.policy);replacement=self.policy.with_suffix('.replacement');replacement.write_bytes(self.policy.read_bytes());replacement.chmod(0o600);replacement.replace(self.policy)
        self.report['fixture_edits'].append(dict(case='same-bytes-policy',path='reports/live-policy.json',before=old_identity,after=node(self.policy)));self.save()
        self.unchanged('same-bytes-policy',lambda:self.remove('same-bytes-policy',plan,['leaf-a']))
        _,plan=self.prepare('before-foreign-lock');self.holder=module.LiveTransaction(self.root,self.db);self.holder.begin();self.report['cleanup']['foreign_lock']='HELD_REAL_ALPM_TRANSACTION';self.save()
        lock_before=self.map('foreign-lock-before',self.root);value=self.remove('foreign-lock',plan,['leaf-a']);lock_after=self.map('foreign-lock-after',self.root);preservation(lock_before,lock_after);need(value['commit_started'] is False,'foreign lock must prevent commit')
        cleanup=module.initial_result();self.holder.cleanup(cleanup);self.report['foreign_lock_release']=cleanup;need(cleanup['transaction_released'] is True and cleanup['handle_released'] is True and not (self.db/'db.lck').exists(),'actual holder cleanup');self.holder=None;self.report['cleanup']['foreign_lock']='RELEASED_BY_OWN_HANDLE';self.save()
        _,plan=self.prepare('fresh-after-lock');before_map=self.map('positive-before',self.root)
        selected=PREFIX+'leaf-a';ownership=module.LiveTransaction(self.root,self.db);ownership_cleanup=module.initial_result()
        try:owned=ownership.files(selected,'1-1')
        finally:ownership.cleanup(ownership_cleanup)
        need(ownership_cleanup['handle_released'] is True,'actual ownership query handle release');self.report['ownership_query_cleanup']=ownership_cleanup
        self.report['selected_ownership']=dict(package=selected,version='1-1',paths=owned)
        value=self.remove('positive',plan,['leaf-a'],expected=0)
        need(value['status']=='APPLIED' and value['commit_started'] is True and value['packages_committed'] is True and value['prepared_add']=={} and value['prepared_remove']=={selected:'1-1'} and value['transaction_released'] is True and value['handle_released'] is True and value['lock_state']=='ABSENT' and value['worker']['reaped'] is True and value['worker']['session_registered'] is True,'real exact explicit-target commit/cleanup required')
        after_map=self.map('positive-after',self.root);preservation(before_map,after_map,positive_removed(before_map))
        after=self.inventory(pm);need(after=={n:v for n,v in before.items() if n!=selected} and PREFIX+'leaf-b' in after,'exact removal with second leaf retained');self.report.update(after_count=7,after=after)
        self.unchanged('stale-after-removal',lambda:self.remove('stale-after-removal',plan,['leaf-a']))
        _,fresh=self.prepare('helper-plan','leaf-b');helper=self.root/'usr/bin/ldconfig';created_bin=not helper.parent.exists();helper.parent.mkdir(exist_ok=True);helper.symlink_to('/nonexistent')
        edit=dict(case='helper-alias',path='usr/bin/ldconfig',before='ABSENT',injected=node(helper));self.report['fixture_edits'].append(edit);self.save()
        value=self.unchanged('helper-alias',lambda:self.remove('helper-alias',fresh,['leaf-b']));need(value['commit_started'] is False,'actual helper alias guard');helper.unlink()
        if created_bin:helper.parent.rmdir()
        edit['restored']='ABSENT';self.save()
        _,fresh=self.prepare('unsafe-plan','leaf-b');payload=self.root/'usr/share/orphans3-fixture'/(PREFIX+'leaf-b.txt');held_payload=payload.read_bytes();payload.unlink();payload.symlink_to('/nonexistent')
        edit=dict(case='unsafe-payload',path=str(payload.relative_to(self.root)),injected=node(payload),restore_sha256=hashlib.sha256(held_payload).hexdigest());self.report['fixture_edits'].append(edit);self.save()
        value=self.unchanged('unsafe-payload',lambda:self.remove('unsafe-payload',fresh,['leaf-b']));need(value['commit_started'] is False,'actual payload alias guard');payload.unlink();payload.write_bytes(held_payload);payload.chmod(0o644);edit['restored']=node(payload);self.save()
        _,fresh=self.prepare('hook-plan','leaf-b');hook=self.root/'usr/share/libalpm/hooks/native-refusal.hook';need(not hook.parent.parent.exists(),'fresh controlled hook hierarchy required');hook.parent.mkdir(parents=True)
        hook.write_text('[Trigger]\nOperation = Remove\nType = Package\nTarget = '+PREFIX+'leaf-b\n\n[Action]\nWhen = PostTransaction\nExec = /must-not-run-native-fixture\n')
        edit=dict(case='matching-hook',path=str(hook.relative_to(self.root)),injected=node(hook));self.report['fixture_edits'].append(edit);self.save()
        self.unchanged('matching-hook',lambda:self.remove('matching-hook',fresh,['leaf-b']));hook.unlink();hook.parent.rmdir();hook.parent.parent.rmdir();edit['restored']='ABSENT';self.save()
        need(node(authored)==self.report['configuration_before'],'unselected authored configuration changed');self.report['configuration_preserved']=True
        self.package_phase(outer,paths[PRODUCT],'remove',False)
        need(I.base_state(L,driver)==held,'base574 changed after first candidate removal')
        self.package_phase(outer,paths[PRODUCT],'reinstall',True)
        need(self.command([CLI,'--version'])=='cachy-asahi-orphans 0.3.0\n','reinstalled0.3 identity')
        self.package_phase(outer,paths[PRODUCT],'final-remove',False)
        base_digest=I.preserve_base(L,held);need(len(L.inventory())==574,'original574 restored')
        actual_after=I.base_state(L,driver);need(actual_after==held,'complete actual original574 after map differs')
        base_after=OUT/'base-after.json';base_after.write_bytes(encoded(actual_after));need(base_after.stat().st_size<=MAX_MAP,'original574 after retention bound')
        self.report['base_after']=dict(path=base_after.name,sha256=sha(base_after),nodes=len(actual_after['nodes']))
        self.map('final-target',self.root);self.report.update(base574_preserved=True,base_preservation_sha256=base_digest,status=STATUS,final_lock='ABSENT');self.save()
    def finish(self):
        if self.holder is not None:
            cleanup=dict(transaction_released=False,handle_released=False);self.holder.cleanup(cleanup);self.report['foreign_lock_final_cleanup']=cleanup;self.holder=None
        if self.trust is not None:
            try:self.command(['/usr/bin/gpgconf','--homedir',self.trust,'--kill','all'],timeout=20);self.report['cleanup']['TEST_agents']='STOPPED'
            except BaseException as error:self.report['cleanup']['TEST_agents']='UNCERTAIN';self.report['cleanup_error']=str(error)[:500];self.report['status']='FAIL'
        if hasattr(self,'db'):self.report['final_lock']='PRESENT_OR_UNCERTAIN' if os.path.lexists(self.db/'db.lck') else 'ABSENT'
        self.report['cleanup']['outer_container']='PARENT_MUST_VERIFY_ABSENCE_AFTER_ACTOR_EXIT';self.save()
        # Private CLI reports are mode0600/root-owned during operations. Publish
        # their content only after every product process has exited, so the
        # ordinary outer collector can read complete success/failure evidence.
        for path in OUT.rglob('*'):
            info=path.lstat();need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink==1,'ordinary exported evidence only')
            path.chmod(0o755 if stat.S_ISDIR(info.st_mode) else 0o644)


def main():
    guard();WORK.mkdir(mode=0o700);trial=Trial();trial.save()
    try:trial.run()
    except BaseException as error:trial.report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:1000])
    finally:trial.finish()
    print(json.dumps({k:v for k,v in trial.report.items() if k not in ('commands','maps')},sort_keys=True));return int(trial.report['status']!=STATUS)

if __name__=='__main__':raise SystemExit(main())
