# SPDX-License-Identifier: MIT
"""Owned no-network NM fixture on the existing VM bus; never replaces that bus."""
import hashlib,json,os,resource,signal,stat,subprocess,time
from pathlib import Path
import dns_contract as D

WORK=Path('/tmp/welcome5-dns-fixture')
STATE_ROOTS=(Path('/run/NetworkManager'),Path('/var/lib/NetworkManager'))
CAP=1024**2
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/dbus/system_bus_socket')

def command(argv,expected=0):
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,start_new_session=True)
    try:
        out,err=process.communicate(timeout=15)
        D.need(len(out)+len(err)<=65536 and process.returncode==expected,'bounded fixture read command failed: '+argv[0]);return out.decode()
    finally:
        if process.poll()is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
        process.stdout.close();process.stderr.close()

def bus(method,*args):
    return json.loads(command(['/usr/bin/busctl','--system','--json=short','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus',method,*args]))
def bus_owner():
    value=bus('NameHasOwner','s','org.freedesktop.NetworkManager')
    D.need(value.get('type')=='b' and type(value.get('data'))is list and len(value['data'])==1 and type(value['data'][0])is bool,'typed NM bus ownership required');return value['data'][0]
def nm(*args):return command(['/usr/bin/nmcli','--wait','10','--colors','no',*args])
def pin(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):
    s=path.lstat();return (s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode),stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid,None if stat.S_ISDIR(s.st_mode)else s.st_nlink)
def tree(root):
    if not os.path.lexists(root):return {}
    result={}
    for p in (root,*sorted(root.rglob('*'))):
        D.need(len(result)<128 and not p.is_symlink(),'bounded nonsymlink daemon state tree required')
        info=p.lstat();D.need(stat.S_ISDIR(info.st_mode)or stat.S_ISREG(info.st_mode)or stat.S_ISSOCK(info.st_mode),'ordinary owned daemon state required')
        D.need(not stat.S_ISREG(info.st_mode)or info.st_size<=CAP,'NM state file bound')
        result[str(p)]=dict(identity=identity(p),sha256=pin(p.read_bytes())if p.is_file()else None)
    return result

def remove_new(root,before):
    after=tree(root)
    for name,row in before.items():D.need(after.get(name)==row,'preexisting NM state changed; preservation refused')
    for name in sorted(set(after)-set(before),key=lambda n:len(Path(n).parts),reverse=True):
        p=Path(name);D.need(tree(root).get(name)==after[name],'NM state changed during retirement')
        p.rmdir()if p.is_dir()else p.unlink()
    D.need(tree(root)==before,'NM state not restored')

def network():
    D.need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'held -nic none GUI VM required')
    paths=('/sys/class/net/lo/flags','/sys/class/net/lo/mtu','/proc/net/if_inet6')
    value={p:Path(p).read_text()for p in paths}
    value['v4']=[r[:4]+r[6:]for r in (l.split()for l in Path('/proc/net/route').read_text().splitlines()[1:])]
    value['v6']=[r[:6]+r[8:]for r in (l.split()for l in Path('/proc/net/ipv6_route').read_text().splitlines())]
    return pin(D.encoded(value))

def resolver():
    p=Path('/etc/resolv.conf');s=p.lstat()
    D.need(p.is_file()and s.st_size<=65536,'bounded existing resolver required')
    return pin(D.encoded(dict(identity=identity(p),link=os.readlink(p)if p.is_symlink()else None,bytes=pin(p.read_bytes()))))

def configuration(work):
    D.need(work==WORK,'fixed owned fixture path required')
    return '[main]\nplugins=keyfile\nauth-polkit=false\ndns=none\nrc-manager=unmanaged\nno-auto-default=*\n[connectivity]\nenabled=false\n[keyfile]\npath='+str(work/'profiles')+'\nunmanaged-devices=*\n[device-all]\nmatch-device=*\nmanaged=0\n'
def keyfile():
    return ('[connection]\nid='+D.NAME+'\nuuid='+D.UUID+'\ntype=ethernet\ninterface-name=owned-dns0\nautoconnect=false\n[ethernet]\n[ipv4]\nmethod=disabled\n[ipv6]\nmethod=disabled\n').encode()
def daemon_argv():
    return ['/usr/bin/setpriv','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','--','/usr/bin/NetworkManager','--no-daemon','--debug',
        '--config='+str(WORK/'NetworkManager.conf'),'--config-dir='+str(WORK/'conf'),'--system-config-dir='+str(WORK/'conf'),
        '--intern-config='+str(WORK/'state/intern.conf'),'--state-file='+str(WORK/'state/NetworkManager.state'),'--pid-file='+str(WORK/'state/NetworkManager.pid')]

def daemon_identity(pid):
    root=Path('/proc')/str(pid);fields=(root/'stat').read_text().rsplit(')',1)[1].split()
    status=dict(l.split(':',1)for l in (root/'status').read_text().splitlines()if':'in l)
    return dict(pid=pid,pgid=int(fields[2]),starttime=int(fields[19]),uid=list(map(int,status['Uid'].split())),exe=os.readlink(root/'exe'),
        **{k:status[k].strip()for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd','NoNewPrivs')})

class Fixture:
    def __init__(self,guard,metadata):
        guard(True)
        D.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and
               'cachy_asahi_welcome5_dns=1'in Path('/proc/cmdline').read_text().split(),'new owned ARM GUI fixture only')
        D.need(not os.path.lexists(WORK)and Path('/run/dbus/system_bus_socket').is_socket()and not bus_owner(),'fresh fixture and existing unowned system bus required')
        self.metadata=metadata;self.process=None;self.log=None;self.closed=False;self.record=None
        self.original={r:tree(r)for r in STATE_ROOTS};self.before=dict(resolver=resolver(),network=network(),metadata=pin(D.encoded(metadata())))
        WORK.mkdir(mode=0o700);self.work_id=identity(WORK)
        for n in ('profiles','conf','state'):(WORK/n).mkdir(mode=0o700)
        self.profile=WORK/'profiles/owned.nmconnection';self.profile.write_bytes(keyfile());self.profile.chmod(0o600)
        self.profile_id=identity(self.profile);self.before['profile']=pin(self.profile.read_bytes())
        config=WORK/'NetworkManager.conf';config.write_text(configuration(WORK));config.chmod(0o600)
        try:
            self.log=(WORK/'NetworkManager.log').open('xb')
            def limit():resource.setrlimit(resource.RLIMIT_FSIZE,(CAP,CAP))
            self.process=subprocess.Popen(daemon_argv(),stdin=subprocess.DEVNULL,stdout=self.log,stderr=subprocess.STDOUT,env=ENV,start_new_session=True,preexec_fn=limit)
            until=time.monotonic()+8
            while True:
                D.need(self.process.poll()is None and time.monotonic()<until,'owned capability-free NM startup failed')
                try:
                    row=daemon_identity(self.process.pid)
                    if row['exe']=='/usr/bin/NetworkManager'and bus_owner():
                        owner=bus('GetConnectionUnixProcessID','s','org.freedesktop.NetworkManager')
                        D.need(owner==dict(type='u',data=[self.process.pid]),'foreign NM acquired bus name')
                        D.need(row['uid']==[0]*4 and row['pgid']==row['pid']and row['NoNewPrivs']=='1'and
                            all(row[k]=='0000000000000000'for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')),'NM privilege reduction failed')
                        self.record=row;break
                except FileNotFoundError:pass
                time.sleep(.02)
            self.check()
        except BaseException:
            self.close();raise
    def check(self):
        D.need(not self.closed and self.process.poll()is None and daemon_identity(self.process.pid)==self.record,'owned daemon changed')
        D.need(identity(self.profile)==self.profile_id and pin(self.profile.read_bytes())==self.before['profile'],'stored profile bytes/identity changed')
        D.need(nm('--get-values','UUID','connection','show').strip()==D.UUID and
               nm('--get-values','UUID','connection','show','--active').strip()=='','exact one stored profile and no active connection required')
        after=dict(profile=pin(self.profile.read_bytes()),resolver=resolver(),network=network(),metadata=pin(D.encoded(self.metadata())))
        D.need(after==self.before,'DNS discovery changed profile/resolver/network/metadata');return after
    def close(self):
        D.need(not self.closed,'fixture already retired');failure=None;after=None
        try:
            if self.record is not None:after=self.check()
        except BaseException as error:failure=error
        finally:
            if self.process is not None:
                if self.process.poll()is None:
                    os.killpg(self.process.pid,signal.SIGTERM)
                    try:self.process.wait(timeout=3)
                    except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=2)
                try:os.killpg(self.process.pid,0);absent=False
                except ProcessLookupError:absent=True
                D.need(absent,'owned daemon group remains')
            if self.log is not None:self.log.close()
            D.need(not bus_owner(),'NM bus owner remains')
            for root in reversed(STATE_ROOTS):remove_new(root,self.original[root])
            D.need(resolver()==self.before['resolver']and network()==self.before['network']and pin(D.encoded(self.metadata()))==self.before['metadata'],'retiring NM changed resolver/network/metadata')
            D.need(identity(WORK)==self.work_id,'owned work root identity changed')
            rows=tree(WORK)
            for name in sorted(rows,key=lambda n:len(Path(n).parts),reverse=True):
                p=Path(name);D.need(tree(WORK).get(name)==rows[name],'fixture work changed during retirement');p.rmdir()if p.is_dir()else p.unlink()
            self.closed=True
        if failure is not None:raise failure
        D.need(after==self.before and self.record is not None,'startup/readonly observation incomplete')
        return dict(status='PASS_OWNED_STORED_DNS_FIXTURE',profile=D.PROFILE,daemon=self.record,before=self.before,after=after,
            profile_bytes_preserved=True,resolver_preserved=True,network_preserved=True,no_active_connection=True,metadata_preserved=True,
            daemon_reaped=True,daemon_group_absent=True,system_bus_owner_absent=True,owned_state_removed=True)
