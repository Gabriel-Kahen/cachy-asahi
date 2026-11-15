#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Normal trusted ALPM lifecycle INSIDE the private, offline full-system guest."""
import hashlib, importlib.util, json, os, socket, stat, subprocess, sys, time
from pathlib import Path
I=Path('/opt/ui-session'); R=Path('/run/ui-session'); H=Path('/home/builder')
POLICY=['etc/pam.d/login','etc/pam.d/system-login','usr/lib/pam.d/polkit-1','usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy','usr/share/polkit-1/rules.d/50-default.rules','usr/share/polkit-1/rules.d/empower.rules','usr/lib/udev/rules.d/71-seat.rules']
def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
class FixtureFailure(Exception):pass

def main():
    assert __debug__ and sys.flags.isolated and os.geteuid()==0 and not Path('/.dockerenv').exists()
    assert Path('/proc/1/comm').read_text().strip()=='systemd' and {v for _,v in socket.if_nameindex()}=={'lo'}
    assert not R.exists();R.mkdir(mode=0o755); report={'status':'HOLD','scope':'owned offline x86 guest ALPM; not host/ARM/M2/release'}
    spec=importlib.util.spec_from_file_location('ui_receipts','/usr/local/libexec/ui-receipts.py');receipts=importlib.util.module_from_spec(spec);spec.loader.exec_module(receipts)
    ospec=importlib.util.spec_from_file_location('ui_ownership','/usr/local/libexec/ui-ownership.py');ownership=importlib.util.module_from_spec(ospec);ospec.loader.exec_module(ownership)
    nonce=Path('/etc/tcg-reference-nonce').read_text().strip();writer=None;ownership_index=None
    report['filesystem_sync']={}
    def publish(name,value):
        # Disk receipt is already fsynced before this runtime signal is exposed.
        assert name in {'installed.json','removed.json','failure.json'}
        temporary=R/('.'+name+'.pending');fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644);os.fchmod(fd,0o644)
        try:
            raw=(json.dumps(value,sort_keys=True)+'\n').encode();assert len(raw)<=128*1024
            with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
        os.replace(temporary,R/name);directory=os.open(R,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    def sync(label):
        if writer is not None:writer.command('sync-'+label,'started')
        try:ownership.sync_filesystem()
        except OSError:
            if writer is not None:writer.command('sync-'+label,'failed',error='syncfs-refusal')
            raise FixtureFailure('syncfs-refusal')from None
        if writer is not None:writer.command('sync-'+label,'passed',0)
        report['filesystem_sync'][label]=True
    def call(label,args,timeout=90):
        writer.command(label,'started')
        try:
            result=subprocess.run(args,capture_output=True,timeout=timeout,env={**os.environ,'LC_ALL':'C'})
            if len(result.stdout)+len(result.stderr)>1024**2:
                writer.command(label,'failed',error='output-bound-refusal');raise FixtureFailure('output-bound-refusal')
            if label=='installed-ownership':
                # Preserve the actual exit before interpreting warning metadata.
                writer.command(label,'failed'if result.returncode else'passed',result.returncode,'ownership-refusal'if result.returncode else None)
                diagnostic=ownership.analyze(result.stdout,result.stderr,result.returncode,ownership_index)
                ownership.persist(writer,diagnostic)
                if diagnostic['HOLD']:raise FixtureFailure('ownership-refusal')
                return result.stdout
            if result.returncode:
                text=result.stderr.decode(errors='replace').lower()
                error=('signature-refusal'if any(t in text for t in ['signature','unknown public key'])else 'dependency-refusal'if 'dependenc'in text else 'permission-refusal'if 'permission denied'in text else 'command-failed')
                writer.command(label,'failed',result.returncode,error);raise FixtureFailure(error)
            writer.command(label,'passed',result.returncode);return result.stdout
        except subprocess.TimeoutExpired:
            writer.command(label,'failed',error='command-timeout');raise FixtureFailure('command-timeout')from None
        except FileNotFoundError:
            writer.command(label,'failed',error='command-not-found');raise FixtureFailure('command-not-found')from None
    try:
        writer=receipts.Writer(receipts.DIRECTORY,nonce);writer.phase('baseline-check')
        contract=json.loads((I/'inputs.json').read_text()); rows=contract['archives']; assert len(rows)==128
        before=call('baseline',['pacman','-Q']).decode(); baseline={l.split()[0]:l.split()[1] for l in before.splitlines()}; assert len(baseline)==164 and baseline==contract['baseline_versions']
        policy={p:sha(Path('/')/p) for p in POLICY}; sentinel=H/'user-config.txt';sentinel_pin=sha(sentinel)
        accounts={p:Path(p).read_text() for p in ['/etc/passwd','/etc/group','/etc/shadow','/etc/gshadow'] if Path(p).exists()}
        writer.phase('public-trust')
        gpg=R/'gnupg';gpg.mkdir(mode=0o700)
        assert sha(I/'official-keyring.gpg')==contract['official_keyring_sha256'] and sha(I/'TEST-public.asc')==contract['TEST_certificate_sha256']
        common=['gpg','--no-options','--homedir',str(gpg),'--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
        call('public-import',common+['--import',str(I/'official-keyring.gpg'),str(I/'TEST-public.asc')])
        # Explicit TEST-context ultimate ownertrust of exact retained identities;
        # no private key, local certification, fetched key or production trust claim.
        owners=sorted(set(contract['official_primary_signers']+[contract['TEST_fingerprint']]))
        trust=R/'TEST-ownertrust';trust.write_text(''.join(p+':6:\n' for p in owners));call('TEST-public-ownertrust',common+['--import-ownertrust',str(trust)])
        assert not call('no-secret-keys',common+['--with-colons','--list-secret-keys']).strip()
        conf=R/'pacman.conf';conf.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = '+str(gpg)+'\n')
        report['trust']={'configuration':conf.read_text(),'explicit_TEST_primary_ownertrust':owners,'private_keys':False,'freshness_or_production_acceptance':False}
        writer.phase('archive-input-check')
        archives=[]
        for row in rows:
            p=I/'packages'/row['filename'];s=p.with_name(p.name+'.sig')
            assert p.is_file() and p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
            assert s.is_file() and s.stat().st_size==row['signature_bytes'] and sha(s)==row['signature_sha256']
            assert row['name'] not in baseline
            archives.append(str(p))
        ownership_index=ownership.load_index(I/'ownership',contract['ownership_metadata'],{r['name']for r in rows})
        pacman=['pacman','--config',str(conf),'--noconfirm','--noprogressbar']
        writer.phase('trusted-install')
        call('trusted-install',pacman+['-U',*archives],150);sync('post-install')
        writer.phase('installed-check')
        after=call('installed-inventory',['pacman','-Q']).decode(); actual={l.split()[0]:l.split()[1] for l in after.splitlines()}
        assert actual=={**baseline,**{r['name']:r['version'] for r in rows}},'exact installed inventory mismatch'
        call('installed-dependencies',['pacman','-Dk']);call('installed-ownership',pacman+['-Qkk',*[r['name'] for r in rows]])
        owned=[]
        for row in rows:
            for raw in call('package-files',['pacman','-Qlq',row['name']]).decode().splitlines():
                p=Path(raw)
                if p.is_symlink() or p.is_file(): owned.append(str(p))
        for rel,pin in contract['project_payloads'].items(): assert sha(Path('/')/rel)==pin
        assert policy=={p:sha(Path('/')/p) for p in POLICY} and sha(sentinel)==sentinel_pin
        installed={'status':'INSTALLED_EXACT_128_TRUSTED_PACKAGES','baseline_count':164,'installed_count':292,'dependency_and_ownership_checks':True}
        receipt={'schema_version':1,'nonce':nonce,'stage':'installed','inputs_sha256':sha(I/'inputs.json'),'inventory_sha256':receipts.inventory_sha256(actual),'baseline_count':164,'installed_count':292,'archive_count':128,'project_file_count':len(contract['project_payloads']),'trusted_ALPM_completed':True,'exact_inventory':True,'dependencies':True,'ownership':True,'project_hashes':True,'original_policy':True,'unrelated_user_file':True,'filesystem_synced':True}
        writer.write('installed.json',receipt);writer.phase('installed');report['installation_receipt']=receipt
        publish('installed.json',receipt);writer.phase('waiting-user')
        until=time.monotonic()+110
        while not(H/'UI_READY_FOR_REMOVAL.json').exists():
            client=H/'UI_CLIENT_REPORT.json'
            if client.exists(): raise RuntimeError('ordinary UI client ended before removal gate')
            if time.monotonic()>until: raise TimeoutError('ordinary real GTK action deadline')
            time.sleep(.1)
        writer.phase('session-check')
        ready=H/'UI_READY_FOR_REMOVAL.json'; assert ready.is_file() and not ready.is_symlink() and ready.stat().st_uid==1000 and ready.stat().st_size<=128*1024
        user=json.loads(ready.read_text()); assert user['gui']['status']=='PASS_REAL_INSTALLED_GTK_CONTROLS'
        import gi
        from gi.repository import Gio,GLib
        bus=Gio.bus_get_sync(Gio.BusType.SYSTEM,None)
        def rpc(path,interface,method,args,out):return bus.call_sync('org.freedesktop.login1',path,interface,method,args,GLib.VariantType(out),Gio.DBusCallFlags.NONE,5000,None).unpack()
        session=rpc('/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSessionByPID',GLib.Variant('(u)',(user['pid'],)),'(o)')[0]
        props=rpc(session,'org.freedesktop.DBus.Properties','GetAll',GLib.Variant('(s)',('org.freedesktop.login1.Session',)),'(a{sv})')[0]
        assert props['User'][0]==1000 and props['Active']is True and props['Seat'][0]=='seat0' and props['TTY']=='tty1' and props['Service']=='login' and props['Remote']is False
        status=dict(line.split(':',1)for line in Path('/proc/'+str(user['pid'])+'/status').read_text().splitlines()if ':'in line)
        assert {int(v)for v in status['Uid'].split()}=={1000} and {int(v)for v in status['Gid'].split()}=={1000}
        assert os.getsid(user['pid'])==user['process_session']
        report['client_session_corroboration']={'pid':user['pid'],'process_session':user['process_session'],'login1':{k:props[k]for k in ['Id','Name','User','Active','Class','Type','Remote','Service','TTY','Seat','Leader']}}
        userfiles=user['gui']['user_files'];home=H/'UI-profile'
        observed=lambda:{str(p.relative_to(home)):sha(p) for p in home.rglob('*') if p.is_file()}
        assert observed()==userfiles
        writer.phase('trusted-remove')
        call('trusted-remove',pacman+['-R',*[r['name'] for r in rows]],90);sync('post-remove')
        writer.phase('restored-check')
        final=call('restored-inventory',['pacman','-Q']).decode();assert final==before,'164 package baseline not restored'
        call('restored-dependencies',['pacman','-Dk'])
        remaining=[p for p in owned if Path(p).exists() or Path(p).is_symlink()];assert not remaining,('package-owned non-directory paths remain',remaining[:12])
        assert policy=={p:sha(Path('/')/p) for p in POLICY} and sha(sentinel)==sentinel_pin and observed()==userfiles
        # Retain normal sysusers/cache effects honestly; these are not erased to
        # manufacture full-filesystem restoration. Inventory/owned paths are exact.
        account_changes={p:{'before_sha256':hashlib.sha256(v.encode()).hexdigest(),'after_sha256':sha(Path(p))} for p,v in accounts.items() if Path(p).read_text()!=v}
        report.update(status='PASS_UI_GUEST_ALPM_LIFECYCLE',installed=installed,baseline_inventory_restored=True,package_owned_nondirectory_paths_absent=True,package_owned_paths_checked=len(set(owned)),original_PAM_policy_preserved=True,unrelated_user_file_preserved=True,user_files_preserved=userfiles,normal_hook_account_file_changes=account_changes,full_filesystem_restoration='NOT CLAIMED; normal sysusers/cache effects are recorded',trust=report['trust'])
        writer.write('restored.json',{'schema_version':1,'nonce':nonce,'stage':'restored','baseline_count':164,'inventory_restored':True,'dependencies':True,'package_owned_paths_absent':True,'original_policy':True,'user_files_preserved':True});writer.phase('restored')
        ownership.signal_after_sync(lambda:sync('terminal-pass'),lambda:publish('removed.json',report))
        return 0
    except BaseException as e:
        label=str(e)if isinstance(e,FixtureFailure)else 'state-refusal'if isinstance(e,(AssertionError,ValueError))else 'unexpected-error'
        assert label in receipts.ERRORS
        failure=writer.failure(label)if writer is not None else {'schema_version':1,'nonce':nonce,'stage':'starting','error_label':label,'status':'HOLD'}
        try:sync('terminal-hold')
        except FixtureFailure:
            failure=writer.failure('syncfs-refusal')if writer is not None else {**failure,'error_label':'syncfs-refusal'}
        publish('failure.json',failure);return 1
if __name__=='__main__':raise SystemExit(main())
