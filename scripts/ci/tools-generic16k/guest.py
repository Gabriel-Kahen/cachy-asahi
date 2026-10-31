# SPDX-License-Identifier: MIT
"""Runs only inside the marked diskless generic 16 KiB guest, without a GUI."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,cap=262144):
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=cap,'bounded regular guest file')
    data=path.read_bytes();need(len(data)<=cap,'guest file byte bound');return data


def snapshot(root):
    result={}
    for path in sorted(root.rglob('*')):
        need(len(result)<128,'configuration count bound');info=path.lstat()
        need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),'configuration node type')
        result[str(path.relative_to(root))]=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,
            sha256=sha(read(path)) if path.is_file() else None)
    return result


class CommandFailure(ValueError):
    def __init__(self,reason,row,stdout,stderr):
        super().__init__(reason)
        self.row,self.stdout,self.stderr=row,stdout,stderr


def command(argv,env,expected=0,seconds=30):
    process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    poll=selectors.DefaultSelector();parts=[bytearray(),bytearray()];start=time.monotonic()
    try:
        for n,pipe in enumerate((process.stdout,process.stderr)):
            os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,n)
        while poll.get_map() or os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            need(time.monotonic()-start<seconds,'guest command deadline')
            for key,_ in poll.select(.05):
                data=os.read(key.fd,8192)
                if not data:poll.unregister(key.fileobj);continue
                need(sum(map(len,parts))+len(data)<=131072,'guest command output bound');parts[key.data].extend(data)
    finally:
        # Keep the leader unreaped until group signals, so its PID cannot be reused.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(process.pid,sig)
            except ProcessLookupError:pass
        code=process.wait(timeout=5);poll.close();process.stdout.close();process.stderr.close()
    try:os.killpg(process.pid,0)
    except ProcessLookupError:absent=True
    else:absent=False
    out,err=map(bytes,parts)
    row=dict(argv=argv,exit=code,group_absent=absent,seconds=round(time.monotonic()-start,6),
             stdout_bytes=len(out),stdout_sha256=sha(out),stderr_bytes=len(err),stderr_sha256=sha(err))
    if code!=expected or not absent:
        row.update(expected_exit=expected,natural_exit=True,pid=process.pid,pgid=process.pid)
        raise CommandFailure('guest command exit/group differs: '+str(code),row,out,err)
    return row,out


SUBSTRING_CASES=('noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private','coexist')
SUBSTRING_IDENTITIES=('guest.py','fixtures/substring.py','fixtures/substring_observer.py','usr/bin/zsh',
    'usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh',
    'usr/share/cachy-asahi/zsh-history-substring-search/zsh-history-substring-search.zsh',
    'usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh')


def sample(raw,limit,tail=False):
    data=raw[-limit:] if tail else raw[:limit]
    return dict(bytes=len(raw),sha256=sha(raw),sample_sha256=sha(data),sample_base64=base64.b64encode(data).decode(),
        sample_offset=len(raw)-len(data) if tail else 0,sample_complete=len(data)==len(raw))


def diagnostic_file(path,limit,tail=False,cap=65536):
    try:
        need(not any(p.is_symlink() for p in (path,*path.parents)),'diagnostic alias refused')
        info=path.lstat()
        need(info.st_uid==os.getuid() and info.st_nlink==1,'private diagnostic ownership/link differs')
        raw=read(path,cap)
        return dict(status='FILE',uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),**sample(raw,limit,tail))
    except FileNotFoundError:return dict(status='ABSENT')
    except (OSError,ValueError) as error:return dict(status='UNAVAILABLE',error_type=type(error).__name__)


def substring_diagnostic(error,work,nonce,release,manifest_raw,argv):
    # Read only fixed leaves from the original private fixture, never histories or setup scripts.
    manifest=json.loads(manifest_raw);cases={}
    for name in SUBSTRING_CASES:
        case=work/name;files={leaf:diagnostic_file(case/leaf,limit,tail) for leaf,limit,tail in
            (('terminal.log',1536,True),('ready',64,False),('prompt-sequence',64,False))}
        files['terminal-exit.json']=diagnostic_file(case/'terminal-exit.json',3072,cap=3072)
        present=[i for i in range(1,11) if (case/('snapshot-'+str(i))).exists()]
        latest=present[-1] if present else None
        if latest is not None:files['latest_snapshot']=diagnostic_file(case/('snapshot-'+str(latest)),4096)
        cases[name]=dict(snapshot_numbers_present=present,latest_snapshot=latest,files=files)
    value=dict(schema_version=1,status='SUBSTRING_FAILURE_DIAGNOSTIC_ONLY',acceptance_credit=False,
        nonce=nonce,kernel=release,architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),
        uid=list(os.getresuid()),gid=list(os.getresgid()),groups=os.getgroups(),source_commit=manifest['source_commit'],
        payload_manifest_sha256=sha(manifest_raw),identities={n:manifest['files'][n] for n in SUBSTRING_IDENTITIES},
        argv=argv,error_type=type(error).__name__,reason=str(error)[:256],
        original_receipt=diagnostic_file(work/'receipt.json',16384,cap=16384),cases=cases,
        product_change='NONE',rerun='NOT_RUN')
    if isinstance(error,CommandFailure):
        value.update(command=error.row,stdout=sample(error.stdout,1024),stderr=sample(error.stderr,1024))
    raw=json.dumps(value,sort_keys=True,separators=(',',':'))
    # Receipt and case names survive even if all raw terminal/snapshot samples hit the cap.
    if len(raw.encode())>65536:
        for case in value['cases'].values():case['files']={k:v for k,v in case['files'].items() if k!='latest_snapshot'}
        value['snapshot_samples_omitted_for_total_cap']=True
        raw=json.dumps(value,sort_keys=True,separators=(',',':'))
    if len(raw.encode())>65536:
        for case in value['cases'].values():
            row=case['files']['terminal.log']
            if row.get('status')!='FILE':continue
            data=base64.b64decode(row['sample_base64'],validate=True);tail=data[-512:]
            row.update(sample_base64=base64.b64encode(tail).decode(),sample_sha256=sha(tail),
                sample_offset=row['sample_offset']+len(data)-len(tail),
                sample_complete=row['sample_complete'] and len(tail)==len(data))
        value['terminal_tails_reduced_for_total_cap']=True
        raw=json.dumps(value,sort_keys=True,separators=(',',':'))
    need(len(raw.encode())<=65536,'substring diagnostic total bound')
    return raw


def run_substring(call,work,nonce,release,manifest_raw):
    argv=['/usr/bin/python3','-I','-B','/fixtures/substring_observer.py','--module-dir',
        '/usr/share/cachy-asahi/zsh-history-substring-search','--work',str(work),
        '--highlight-wrapper','/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh']
    try:
        call(argv,seconds=180)
        value=json.loads(read(work/'receipt.json'))
        need(value['status']=='PASS_HOST_ZSH_PTY_CONTROLS' and len(value['tests'])==6 and
             all(r['status']=='PASS' and r['exit']==0 for r in value['tests']),'complete substring fixtures failed')
        return value
    except BaseException as error:
        try:print('TOOLS16K_DIAGNOSTIC '+substring_diagnostic(error,work,nonce,release,manifest_raw,argv),flush=True)
        except Exception as diagnostic_error:
            print('TOOLS16K_DIAGNOSTIC_UNAVAILABLE '+type(diagnostic_error).__name__,flush=True)
        raise


def payload_identity(manifest):
    for name,row in manifest['files'].items():
        path=Path('/')/name;raw=read(path,64*1024**2)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and
             stat.S_IMODE(path.stat().st_mode)==row['mode'],'guest payload identity differs')


def owned_absent():
    others=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:
            fields=(path/'status').read_text().splitlines()
            uid=next(line.split()[1:] for line in fields if line.startswith('Uid:'))
        except FileNotFoundError:continue
        if '23001' in uid:others.append(int(path.name))
    need(not others,'owned fixture process remains: '+str(others[:16]))
    return True



def progress(nonce,phase):
    need(len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce),'progress nonce differs')
    print('TOOLS16K_PROGRESS '+nonce+' '+phase,flush=True)


def exercise(nonce,release):
    need(os.geteuid()==0 and os.uname().machine=='aarch64' and os.uname().release==release and
         os.sysconf('SC_PAGE_SIZE')==16384 and 'tools16k=1' in Path('/proc/cmdline').read_text().split(),
         'marked generic16K guest required')
    progress(nonce,'PYTHON_ENTER');progress(nonce,'PAYLOAD_BEGIN')
    manifest_raw=read(Path('/payload.json'),1024**2);manifest=json.loads(manifest_raw);payload_identity(manifest)
    progress(nonce,'PAYLOAD_READY')
    root=Path('/tmp/tools16k');root.mkdir(mode=0o700);os.chown(root,23001,23001)
    os.setgroups([]);os.setgid(23001);os.setuid(23001)
    need(os.getuid()==os.geteuid()==os.getgid()==23001,'private unprivileged guest identity')
    progress(nonce,'UID_READY')
    owned_absent()
    home=root/'user';home.mkdir(mode=0o700)
    for name in ('config','cache','data','state','runtime'):
        directory=home/name;directory.mkdir(mode=0o700);(directory/'sentinel').write_bytes(b'preserve user settings\n')
    temporary=root/'temporary';temporary.mkdir(mode=0o700);protected=snapshot(home)
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME=str(home),TMPDIR=str(temporary),
        PYTHONDONTWRITEBYTECODE='1',DISPLAY='',WAYLAND_DISPLAY='',DBUS_SESSION_BUS_ADDRESS='unix:path=/no-session',
        XDG_CONFIG_HOME=str(home/'config'),XDG_CACHE_HOME=str(home/'cache'),XDG_DATA_HOME=str(home/'data'),
        XDG_STATE_HOME=str(home/'state'),XDG_RUNTIME_DIR=str(home/'runtime'))
    commands=[]
    def call(argv,expected=0,seconds=30):
        row,out=command(argv,env,expected,seconds);row['owned_processes_absent']=owned_absent();commands.append(row);return out
    fixtures={}
    progress(nonce,'HIGHLIGHTING_BEGIN')
    highlight=root/'highlighting';highlight.mkdir(mode=0o700)
    fixtures['highlighting']=json.loads(call(['/usr/bin/python3','-I','-B','/fixtures/highlighting.py',str(highlight)],seconds=180))
    need(fixtures['highlighting']['status']=='PASS_INSTALLED_ZLE' and fixtures['highlighting']['natural_exit']==0 and
         len(fixtures['highlighting']['snapshots'])==2,'real mapped highlighting fixture failed')
    progress(nonce,'HIGHLIGHTING_READY')
    progress(nonce,'SUBSTRING_BEGIN')
    substring=root/'substring';substring.mkdir(mode=0o700)
    fixtures['substring']=run_substring(call,substring,nonce,release,manifest_raw)
    progress(nonce,'SUBSTRING_READY')
    progress(nonce,'AUTOPAIR_BEGIN')
    autopair=root/'autopair'
    call(['/usr/bin/python3','-I','-B','/fixtures/autopair.py','--source',
          '/usr/share/cachy-asahi/fish-autopair','--output',str(autopair)],seconds=180)
    fixtures['autopair']=json.loads(read(autopair/'receipt.json'))
    cases=fixtures['autopair']['cases']
    need(fixtures['autopair']['status']=='PASS' and len(cases)==14 and all(r['exit']==0 for r in cases.values()) and
         sum(len(r.get('snapshots',[])) for r in cases.values())==57,'complete real Fish pair editing failed')
    progress(nonce,'AUTOPAIR_READY')
    progress(nonce,'MIRRORS_BEGIN')
    mirror=root/'mirrors';mirror.mkdir(mode=0o700)
    catalog=mirror/'catalog.json';candidate=mirror/'candidate';target=mirror/'mirrorlist';state=mirror/'journal.json'
    config=dict(schema_version=1,architecture='aarch64',base='asahi-alarm',repository='core',
        database=dict(bytes=1,sha256=sha(b'x')),mirrors=[dict(id='private',server='https://example.invalid/$arch/$repo')])
    catalog.write_text(json.dumps(config,sort_keys=True)+'\n');catalog_sha=sha(read(catalog))
    raw=('# Separate candidate; selected repository: core\n# Exact catalog SHA256: '+catalog_sha+
         '\nServer = https://example.invalid/$arch/$repo\n').encode()
    candidate.write_bytes(raw);candidate.chmod(0o600)
    original=b'# preserve caller mirror bytes\nServer = https://original.invalid/$arch/$repo\n'
    target.write_bytes(original);target.chmod(0o640);prior=target.stat()
    def mirror_call(*argv,expected=0):return json.loads(call(['/usr/bin/cachy-asahi-mirrors',*map(str,argv)],expected))
    need(call(['/usr/bin/cachy-asahi-mirrors','--version'])==b'cachy-asahi-mirrors 0.2.0\n','mirror version differs')
    need(mirror_call('check',catalog)['status']=='PASS_CATALOG_SYNTAX','mirror catalog check failed')
    def activate(journal):return mirror_call('activate',catalog,'--candidate',candidate,'--repository','core','--target',target,'--state',journal)
    def restore(journal,expected=0):return mirror_call('restore','--repository','core','--target',target,'--state',journal,expected=expected)
    need(activate(state)['status']=='PASS_ACTIVATED' and read(target)==raw,'mirror activation differs')
    journal_raw=read(state);journal=json.loads(journal_raw)
    need(base64.b64decode(journal['before']['data'])==original and stat.S_IMODE(state.stat().st_mode)==0o600,
         'private durable original journal differs')
    need(activate(state)['status']=='PASS_ACTIVATED' and read(state)==journal_raw,'activation retry changed journal')
    need(restore(state)['status']=='PASS_RESTORED' and read(target)==original,'mirror restoration differs')
    info=target.stat()
    need(all(getattr(info,k)==getattr(prior,k) for k in ('st_uid','st_gid','st_mode')),'mirror metadata differs')
    need(restore(state)['status']=='PASS_RESTORED','restore retry failed')
    conflict=mirror/'conflict.json';need(activate(conflict)['status']=='PASS_ACTIVATED','second explicit activation failed')
    edited=b'preserve this deliberate caller edit\n';target.write_bytes(edited);changed=target.stat()
    need(restore(conflict,expected=1)['status']=='FAIL' and read(target)==edited and target.stat().st_ino==changed.st_ino and
         json.loads(read(conflict))['phase']=='ACTIVE','mirror edited target was overwritten or journal intent lost')
    need(snapshot(home)==protected,'caller configuration changed');payload_identity(manifest);owned_absent()
    need(len(commands)==11,'complete finite tool command set required')
    progress(nonce,'MIRRORS_READY')
    return dict(status='PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY',nonce=nonce,architecture='aarch64',page_size=16384,
        kernel=release,uid=os.getuid(),commands=commands,fixtures=fixtures,
        mirrors=dict(version='0.2.0',catalog_sha256=catalog_sha,candidate_sha256=sha(raw),original_sha256=sha(original),
            restored_bytes_mode_uid_gid=True,retry_preserved=True,edited_target_preserved=True,conflict_journal_phase='ACTIVE',network='NOT_USED'),
        config_preserved=True,payload_preserved=True,owned_processes_absent=True,payload_manifest_sha256=sha(manifest_raw),
        package_registration='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY',GUI='NOT_RUN',hardware='NOT_RUN',
        performance='NOT_RUN',release_admission=False)


if __name__=='__main__':
    try:
        need(len(sys.argv)==3 and len(sys.argv[1])==32,'guest arguments')
        value=exercise(sys.argv[1],sys.argv[2]);raw=json.dumps(value,sort_keys=True,separators=(',',':'))
        need(len(raw.encode())<=65536,'guest report byte bound');print('TOOLS16K_REPORT '+raw,flush=True)
    except BaseException as error:
        print('TOOLS16K_ERROR '+type(error).__name__+': '+str(error)[:160],flush=True);raise
