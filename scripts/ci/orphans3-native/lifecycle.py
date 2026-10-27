#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real signed inert-package removal, only inside an owned offline ARM container."""
import ctypes,hashlib,importlib.util,json,os,re,signal,stat,subprocess,time
from pathlib import Path

PREFIX='caa-orphans3-'
ROLES=('leaf-a','leaf-b','explicit','required','hard-user','optional','optional-user','protected')
FIXTURES={PREFIX+n for n in ROLES}
PRODUCT='cachy-asahi-orphans';VERSION='0.2.0-1';CLI='/usr/bin/'+PRODUCT
SOURCE=Path('/source');INPUTS=Path('/inputs');OUT=Path('/out');WORK=Path('/work')
MAX_MAP=128*1024**2


def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def guard():
    need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file()
         and os.environ.get('CACHY_ASAHI_ORPHANS3_NATIVE')=='lifecycle','dedicated native root container PID1 required')
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


class Trial:
    def __init__(self):
        self.report=dict(status='FAIL',version=VERSION,real_backend=True,architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),
            hardware='NOT_RUN',release='NOT_ADMITTED',scope='PRIVATE_OFFLINE_SYNTHETIC_TARGET_ONLY',commands=[],events=[],fixture_edits=[],maps={},cleanup={'target':'NOT_CREATED','outer_candidate':'NOT_INSTALLED','foreign_lock':'NOT_HELD'})
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
        return ['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
    def prepare(self,label,select='leaf-a'):
        d=OUT/'reports'/label;d.mkdir(parents=True,mode=0o700);assessment=d/'assessment.json';plan=d/'plan.json'
        self.command([CLI,'assess','--root',self.root,'--dbpath',self.db,'--protect',PREFIX+'protected','--output',assessment])
        actual=json.loads(assessment.read_bytes());need(actual['candidates']==[PREFIX+'leaf-a',PREFIX+'leaf-b'] if len(actual['packages'])==8 else actual['candidates']==[PREFIX+'leaf-b'],'exact current real candidate set')
        self.command([CLI,'plan',assessment,'--select',PREFIX+select,'--output',plan]);self.command([CLI,'verify',plan]);return assessment,plan
    def remove(self,label,plan,names,expected=1):
        d=OUT/'reports'/label;d.mkdir(parents=True,mode=0o700);output=d/'result.json';argv=[CLI,'remove',plan,'--plan-sha256',sha(plan)]
        for name in names:argv+=['--select',PREFIX+name]
        argv+=['--result',output,'--timeout-seconds','60'];raw=self.command(argv,expected=expected);value=json.loads(raw)
        if output.exists():need(json.loads(output.read_bytes())==value,'durable/stdout removal result differs')
        self.report['events'].append(dict(case=label,result=value,durable_result=str(output.relative_to(OUT)) if output.exists() else None));self.save();return value
    def unchanged(self,label,operation):
        before=self.map(label+'-before',self.root);value=operation();after=self.map(label+'-after',self.root);preservation(before,after)
        need(not (self.db/'db.lck').exists(),'refusal left an uncertain native lock');return value
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
        self.command(outer+['-U',paths[PRODUCT]]);self.report['cleanup']['outer_candidate']='INSTALLED';self.save()
        need(self.command(['/usr/bin/pacman','-Q',PRODUCT])==PRODUCT+' '+VERSION+'\n','installed candidate package version')
        need(self.command([CLI,'--version'])=='cachy-asahi-orphans 0.2.0\n','installed successor identity')
        module=load('orphans3_installed_actual_backend',Path('/usr/lib/cachy-asahi-orphans3/remove.py'))
        need(module.Transaction.__module__=='orphans3_installed_actual_backend','real packaged ctypes backend required')
        self.root=WORK/'root';self.root.mkdir(mode=0o700);self.db=self.root/'var/lib/pacman';(self.db/'local').mkdir(parents=True);(self.db/'local/ALPM_DB_VERSION').write_text('9\n')
        config=WORK/'fixture-pacman.conf';config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+self.trust+'\nHookDir = /tmp/orphans-hooks\n')
        cache=WORK/'cache';cache.mkdir();pm=['/usr/bin/pacman','--config',str(config),'--root',str(self.root),'--dbpath',str(self.db),'--gpgdir',self.trust,'--cachedir',str(cache),'--logfile',str(OUT/'fixture-pacman.log'),'--noconfirm']
        self.command(pm+['--noscriptlet','-U','--asdeps',*(paths[n] for n in sorted(FIXTURES))]);self.command(pm+['-D','--asexplicit',*(PREFIX+n for n in ('explicit','hard-user','optional-user'))])
        before=self.inventory(pm);need(before=={n:'1-1' for n in FIXTURES},'real eight-package initial inventory');self.report['before_count']=8;self.report['before']=before;self.report['cleanup']['target']='PRESERVED_OWNED_UNTIL_OUTER_DISPOSAL';self.save()
        assessment,plan=self.prepare('initial');facts=json.loads(assessment.read_bytes())
        for n in ('leaf-a','leaf-b','required','optional','protected'):need(facts['packages'][PREFIX+n]['reason']=='dependency','real dependency reason required')
        need(facts['packages'][PREFIX+'required']['required_by']==[PREFIX+'hard-user'] and facts['packages'][PREFIX+'optional']['optional_required_by']==[PREFIX+'optional-user'] and facts['packages'][PREFIX+'protected']['protected'] is True,'actual dependency/protection facts')
        self.unchanged('different-selection',lambda:self.remove('different-selection',plan,['leaf-b']))
        self.unchanged('duplicate-selection',lambda:self.remove('duplicate-selection',plan,['leaf-a','leaf-a']))
        for name in ('protected','explicit','required','optional'):
            def reject(name=name):return self.command([CLI,'plan',assessment,'--select',PREFIX+name,'--output',OUT/'reports'/('refused-'+name+'.json')],expected=1)
            self.unchanged('protected-needed-'+name,reject)
        old=assessment.read_bytes();old_identity=node(assessment);replacement=assessment.with_suffix('.replacement');replacement.write_bytes(old);replacement.chmod(0o600);replacement.replace(assessment)
        self.report['fixture_edits'].append(dict(case='same-bytes-assessment',path=str(assessment.relative_to(OUT)),before=old_identity,after=node(assessment)));self.save()
        self.unchanged('same-bytes-assessment',lambda:self.remove('same-bytes-assessment',plan,['leaf-a']))
        _,plan=self.prepare('before-foreign-lock');self.holder=module.Transaction(self.root,self.db);self.holder.begin();self.report['cleanup']['foreign_lock']='HELD_REAL_ALPM_TRANSACTION';self.save()
        lock_before=self.map('foreign-lock-before',self.root);value=self.remove('foreign-lock',plan,['leaf-a']);lock_after=self.map('foreign-lock-after',self.root);preservation(lock_before,lock_after);need(value['commit_started'] is False,'foreign lock must prevent commit')
        cleanup=module.initial_result();self.holder.cleanup(cleanup);self.report['foreign_lock_release']=cleanup;need(cleanup['transaction_released'] is True and cleanup['handle_released'] is True and not (self.db/'db.lck').exists(),'actual holder cleanup');self.holder=None;self.report['cleanup']['foreign_lock']='RELEASED_BY_OWN_HANDLE';self.save()
        _,plan=self.prepare('fresh-after-lock');before_map=self.map('positive-before',self.root)
        selected=PREFIX+'leaf-a';ownership=module.Transaction(self.root,self.db);ownership_cleanup=module.initial_result()
        try:owned=ownership.files(selected,'1-1')
        finally:ownership.cleanup(ownership_cleanup)
        need(ownership_cleanup['handle_released'] is True,'actual ownership query handle release');self.report['ownership_query_cleanup']=ownership_cleanup
        removed={p.rstrip('/') for p in owned};local='var/lib/pacman/local/'+selected+'-1-1';removed|={p for p in before_map if p==local or p.startswith(local+'/')}
        value=self.remove('positive',plan,['leaf-a'],expected=0)
        need(value['status']=='APPLIED' and value['commit_started'] is True and value['packages_committed'] is True and value['prepared_add']=={} and value['prepared_remove']=={selected:'1-1'} and value['transaction_released'] is True and value['handle_released'] is True and value['lock_state']=='ABSENT' and value['worker']['reaped'] is True,'real exact commit/cleanup required')
        after_map=self.map('positive-after',self.root);preservation(before_map,after_map,removed)
        after=self.inventory(pm);need(after=={n:v for n,v in before.items() if n!=selected} and PREFIX+'leaf-b' in after,'exact removal with second leaf retained');self.report.update(after_count=7,after=after)
        self.unchanged('stale-after-removal',lambda:self.remove('stale-after-removal',plan,['leaf-a']))
        _,fresh=self.prepare('helper-plan','leaf-b');helper=self.root/'usr/bin/ldconfig';helper.parent.mkdir(exist_ok=True);helper.symlink_to('/nonexistent')
        edit=dict(case='helper-alias',path='usr/bin/ldconfig',before='ABSENT',injected=node(helper));self.report['fixture_edits'].append(edit);self.save()
        value=self.unchanged('helper-alias',lambda:self.remove('helper-alias',fresh,['leaf-b']));need('ldconfig' in value['reason'] and value['commit_started'] is False,'actual helper guard');helper.unlink();edit['restored']='ABSENT';self.save()
        _,fresh=self.prepare('unsafe-plan','leaf-b');payload=self.root/'usr/share/orphans3-fixture'/(PREFIX+'leaf-b.txt');held_payload=payload.read_bytes();payload.unlink();payload.symlink_to('/nonexistent')
        edit=dict(case='unsafe-payload',path=str(payload.relative_to(self.root)),injected=node(payload),restore_sha256=hashlib.sha256(held_payload).hexdigest());self.report['fixture_edits'].append(edit);self.save()
        value=self.unchanged('unsafe-payload',lambda:self.remove('unsafe-payload',fresh,['leaf-b']));need(value['commit_started'] is False and value['transaction_released'] is True,'actual payload guard');payload.unlink();payload.write_bytes(held_payload);payload.chmod(0o644);edit['restored']=node(payload);self.save()
        self.command(outer+['-R',PRODUCT]);self.report['cleanup']['outer_candidate']='REMOVED';base_digest=I.preserve_base(L,held);need(len(L.inventory())==574,'original574 restored')
        actual_after=I.base_state(L,driver);need(actual_after==held,'complete actual original574 after map differs')
        base_after=OUT/'base-after.json';base_after.write_bytes(encoded(actual_after));need(base_after.stat().st_size<=MAX_MAP,'original574 after retention bound')
        self.report['base_after']=dict(path=base_after.name,sha256=sha(base_after),nodes=len(actual_after['nodes']))
        self.map('final-target',self.root);self.report.update(base574_preserved=True,base_preservation_sha256=base_digest,status='PASS_ORPHANS3_REAL_NATIVE_OFFLINE_REMOVAL',final_lock='ABSENT');self.save()
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
    print(json.dumps({k:v for k,v in trial.report.items() if k not in ('commands','maps')},sort_keys=True));return int(trial.report['status']!='PASS_ORPHANS3_REAL_NATIVE_OFFLINE_REMOVAL')

if __name__=='__main__':raise SystemExit(main())
