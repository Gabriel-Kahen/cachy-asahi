# SPDX-License-Identifier: MIT
"""One failure-only public TEST signature observation; never alter verification/time."""
import base64,hashlib,json,os,stat,time
from pathlib import Path
MAX_PUBLIC=16384;MAX_RECORD=65536;MAX_SAMPLE=8192
def need(ok,why):
    if not ok:raise ValueError(why)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
encoded=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def packets(raw):
    """Bounded binary packet framing for the fixture's v4 metadata only."""
    need(type(raw) is bytes and 0<len(raw)<=MAX_PUBLIC,'public packet bound')
    pos=0;rows=[]
    while pos<len(raw):
        need(len(rows)<16,'packet count');header=raw[pos];pos+=1;need(header&128,'packet header')
        if header&64:
            tag=header&63;need(pos<len(raw),'packet length');size=raw[pos];pos+=1
            if 192<=size<224:
                need(pos<len(raw),'packet length');size=(size-192)*256+raw[pos]+192;pos+=1
            elif size==255:
                need(pos+4<=len(raw),'packet length');size=int.from_bytes(raw[pos:pos+4],'big');pos+=4
            else:need(size<192,'partial packet unsupported')
        else:
            tag=(header>>2)&15;n=(1,2,4,0)[header&3];need(n and pos+n<=len(raw),'indeterminate packet unsupported');size=int.from_bytes(raw[pos:pos+n],'big');pos+=n
        need(size>0 and pos+size<=len(raw),'truncated packet');rows.append((tag,raw[pos:pos+size]));pos+=size
    return rows

def signature_clock(body):
    need(len(body)>=8 and body[0]==4,'v4 signature required');length=int.from_bytes(body[4:6],'big');need(6+length+2<=len(body),'signature hashed bound')
    data=body[6:6+length];pos=0;known={}
    while pos<len(data):
        size=data[pos];pos+=1
        if 192<=size<255:
            need(pos<len(data),'subpacket length');size=(size-192)*256+data[pos]+192;pos+=1
        elif size==255:
            need(pos+4<=len(data),'subpacket length');size=int.from_bytes(data[pos:pos+4],'big');pos+=4
        need(size>0 and pos+size<=len(data),'subpacket bound');kind=data[pos]&127;value=data[pos+1:pos+size];pos+=size
        if kind in (2,3,9):
            need(len(value)==4 and kind not in known,'clock subpacket');known[kind]=int.from_bytes(value,'big')
    need(2 in known,'signature creation absent')
    return dict(version=4,signature_type=body[1],public_algorithm=body[2],hash_algorithm=body[3],created_epoch=known[2],signature_lifetime_seconds=known.get(3,0),key_lifetime_seconds=known.get(9,0))

def clocks(key,signature):
    public=packets(key);primary=[body for tag,body in public if tag==6];detached=packets(signature)
    need(len(primary)==1 and len(primary[0])>=6 and primary[0][0]==4 and len(detached)==1 and detached[0][0]==2,'one v4 public primary/detached signature required')
    body=primary[0];fingerprint=hashlib.sha1(b'\x99'+len(body).to_bytes(2,'big')+body).hexdigest().upper()
    return dict(status='PARSED_PACKET_METADATA_NOT_CRYPTOGRAPHIC_VERIFICATION',primary_fingerprint=fingerprint,key_created_epoch=int.from_bytes(body[1:5],'big'),public_algorithm=body[5],
        public_key_signature_packets=[signature_clock(b) for tag,b in public if tag==2],detached=signature_clock(detached[0][1]))

def sample(raw):
    value=raw[:MAX_SAMPLE]
    return dict(bytes=len(raw),sha256=sha(raw),sample_base64=base64.b64encode(value).decode(),sample_sha256=sha(value),sample_complete=len(value)==len(raw))

def public_read(path):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'public fixture alias');s=path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and s.st_size<=MAX_PUBLIC,'public fixture metadata')
    with path.open('rb') as stream:raw=stream.read(MAX_PUBLIC+1)
    need(len(raw)==s.st_size<=MAX_PUBLIC,'public fixture read bound');return raw

def gpg_argv(directory):
    return ['/usr/bin/gpg','--batch','--no-tty','--no-options','--homedir',str(directory/'gpg-home'),'--no-default-keyring','--keyring',str(directory/'external-public.gpg'),
        '--no-auto-key-retrieve','--no-auto-key-import','--auto-key-locate','clear','--disable-dirmngr','--no-autostart','--no-auto-check-trustdb','--status-fd','1','--verify',str(directory/'signature-1'),str(directory/'signed-release.json')]

def observe(original,work,env,error):
    """Only after original Apps install-plan FAIL; direct GPG is diagnostic credit0."""
    public=work/'apps/public';start=dict(wall_time_ns=time.time_ns(),monotonic_ns=time.monotonic_ns())
    value=dict(schema_version=1,scope='FAILURE_ONLY_PUBLIC_TEST_SIGNATURE_NO_ACCEPTANCE',original_command_sha256=sha(encoded(error.row)),clock_before=start,commands=[],acceptance_credit=False)
    names=('public.gpg','bundle/release.json','bundle/release.json.sig','catalog.json','catalog.json.sig')
    blobs={name:public_read(public/name) for name in names};need(sum(map(len,blobs.values()))<=MAX_PUBLIC,'aggregate public fixture bound')
    value['public_files']={n:dict(bytes=len(raw),sha256=sha(raw),base64=base64.b64encode(raw).decode()) for n,raw in blobs.items()}
    try:value['packet_clocks']=clocks(blobs['public.gpg'],blobs['bundle/release.json.sig'])
    except Exception as failure:value['packet_clocks']=dict(status='UNSUPPORTED_METADATA',error_type=type(failure).__name__,reason=str(failure)[:160])
    directory=work/'signature-diagnostic';directory.mkdir(mode=0o700);home=directory/'gpg-home';home.mkdir(mode=0o700);keyring=directory/'external-public.gpg';keyring.write_bytes(blobs['public.gpg']);keyring.chmod(0o600)
    signature=directory/'signature-1';signature.write_bytes(blobs['bundle/release.json.sig']);signature.chmod(0o600)
    data=directory/'signed-release.json';data.write_bytes(blobs['bundle/release.json']);data.chmod(0o600)
    # Same client.Verifier.verify flags/environment and original30-second helper.
    argv=gpg_argv(directory)
    child_env=dict(PATH=env['PATH'],HOME=str(home),GNUPGHOME=str(home),LC_ALL='C')
    try:
        try:
            # No process exit can equal -256. Existing CommandFailure preserves
            # BOTH pipes for every result; this observation grants no PASS.
            original.command(argv,child_env,-256,30);raise AssertionError('impossible diagnostic expected exit')
        except original.CommandFailure as failed:row,out,err=failed.row,failed.stdout,failed.stderr
        value['commands'].append(dict(command=row,stdout=sample(out),stderr=sample(err)))
    except BaseException as failed:value['command_error']=dict(error_type=type(failed).__name__,reason=str(failed)[:160])
    value['clock_after']=dict(wall_time_ns=time.time_ns(),monotonic_ns=time.monotonic_ns());value['owned_processes_absent']=original.owned_absent()
    need(all(public_read(public/n)==raw for n,raw in blobs.items()),'public diagnostic input changed')
    need(len(encoded(value))<=MAX_RECORD,'signature diagnostic record bound');return value


def validate(value):
    """Retained diagnostic consistency only; cannot grant a successful case."""
    need(value['schema_version']==1 and value['scope']=='FAILURE_ONLY_PUBLIC_TEST_SIGNATURE_NO_ACCEPTANCE' and value['acceptance_credit'] is False and len(encoded(value))<=MAX_RECORD,'diagnostic scope/bound')
    need(set(value['public_files'])=={'public.gpg','bundle/release.json','bundle/release.json.sig','catalog.json','catalog.json.sig'} and len(value['commands'])<=1 and value['clock_after']['monotonic_ns']>=value['clock_before']['monotonic_ns'],'diagnostic sequence/clock')
    total=0
    for name,row in value['public_files'].items():
        need(name in ('public.gpg','bundle/release.json','bundle/release.json.sig','catalog.json','catalog.json.sig'),'public diagnostic name')
        raw=base64.b64decode(row['base64'],validate=True);total+=len(raw);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and total<=MAX_PUBLIC,'public diagnostic hash/bound')
    for record in value['commands']:
        command=record['command'];argv=command['argv']
        need(len(argv)>5 and argv==gpg_argv(Path(argv[5]).parent) and Path(argv[5]).name=='gpg-home' and Path(argv[5]).parent.name=='signature-diagnostic' and
            command['expected_exit']==-256 and command['natural_exit'] is True and command['pid']==command['pgid']>1 and command['group_absent'] is True and
            type(command['exit']) is int and -64<=command['exit']<=255 and command['stdout_bytes']+command['stderr_bytes']<=131072 and 0<=command['seconds']<=35,'direct diagnostic GPG/group differs')
        for field in ('stdout','stderr'):
            row=record[field];raw=base64.b64decode(row['sample_base64'],validate=True)
            need(row['bytes']==command[field+'_bytes'] and row['sha256']==command[field+'_sha256'] and len(raw)<=MAX_SAMPLE and len(raw)<=row['bytes'] and sha(raw)==row['sample_sha256'],'diagnostic sample join')
            if row['sample_complete']:need(pin(raw)==dict(bytes=row['bytes'],sha256=row['sha256']),'diagnostic complete raw hash')
    return value

def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
