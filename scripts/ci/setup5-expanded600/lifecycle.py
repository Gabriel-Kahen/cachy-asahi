#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate signed600 Setup3→5→3 consumer; original eight-checkpoint consumer is isolated."""
import hashlib
import os
from pathlib import Path
import pwd
import sys
import time
import types
sys.path.insert(0,str(Path(__file__).resolve().parent))
import policy as P

L=None


def adapted_source(raw):
    anchor="        install();checkpoint('install600',after,rows)\n"
    P.need(raw.count(anchor)==1,'exact original install600 bootstrap anchor required')
    return raw.replace(anchor,anchor+"        report.update(_setup5_trial(locals()),ldconfig=ld_receipts)\n        return 0\n")


def desc_fields(raw):
    fields={};key=None
    for line in raw.decode('utf-8').splitlines():
        if not line:key=None
        elif line.startswith('%') and line.endswith('%'):
            key=line[1:-1];P.need(key not in fields,'duplicate installed Setup3 metadata');fields[key]=[]
        else:P.need(key is not None,'installed Setup3 metadata shape');fields[key].append(line)
    return fields


def restored_desc(before,after,earliest,latest):
    a,b=desc_fields(before),desc_fields(after)
    P.need(a.get('NAME')==b.get('NAME')==[P.SETUP] and a.get('VERSION')==b.get('VERSION')==['0.1.0-3'],
        'actual Setup3 database identity required')
    P.need({k:v for k,v in a.items() if k!='INSTALLDATE'}=={k:v for k,v in b.items() if k!='INSTALLDATE'},
        'Setup3 rollback metadata changed beyond normal ALPM INSTALLDATE')
    dates=b.get('INSTALLDATE',[])
    P.need(len(dates)==1 and dates[0].isdigit() and earliest<=int(dates[0])<=latest,
        'rollback INSTALLDATE outside actual transaction interval')


def other599(before_db,before_records,after_db,after_records):
    P.need(len(before_db)==len(after_db)==600 and
        {n:r for n,r in after_db.items() if n!=P.SETUP}=={n:r for n,r in before_db.items() if n!=P.SETUP} and
        all(after_records.get(n)==r for n,r in before_records.items() if n!=P.SETUP),
        'other599 ALPM records changed')


SETUP5_ADDED=frozenset({'usr/bin/cachy-asahi-repository',
                        'usr/share/doc/cachy-asahi-setup/repository-enrollment.md'})


def payload_transition(full,product):
    paths={p for p in full['ownership'][P.SETUP] if full['nodes'][p]['type']!='directory'}
    P.need(len(paths)==4 and not paths&SETUP5_ADDED and
        set(product['payload'])==paths|SETUP5_ADDED,
        'exact four Setup3 paths plus two accepted Setup5 additions required')
    P.need(not SETUP5_ADDED&set(full['nodes']),
        'Setup5 added paths collide with signed full600 payload')
    return paths,SETUP5_ADDED


def added_absent(paths,phase):
    P.need(all(L.node(Path('/')/p)==dict(type='absent') for p in paths),
        'Setup5 added payload must be absent '+phase)


def expected_other599(full,baseline,incoming):
    # The unchanged native600 guard preserves the established signed587 image,
    # including its configured package-owned files, and checks incoming bytes.
    paths={p for name,owned in full['ownership'].items() if name!=P.SETUP for p in owned
           if full['nodes'][p]['type']!='directory'}
    expected={p:row for p,row in baseline.items() if p in paths}
    for package in incoming:
        name=package['name']
        P.need(name!=P.SETUP and full['packages'].get(name)==package['version'],
            'incoming600 package identity differs')
        owned={p for p in full['ownership'][name] if full['nodes'][p]['type']!='directory'}
        P.need(set(package['payload'])==owned,'incoming600 signed ownership differs')
        for path,member in package['payload'].items():
            row=L.expected_node(member)
            P.need(path not in expected and row==L.expected_node(full['nodes'][path]),
                'incoming600 signed payload/baseline overlap differs: '+path)
            expected[path]=row
    P.need(set(expected)==paths,'complete exact other599 installed payload basis required')
    return expected


def same_payload(expected,actual,why):
    if expected==actual:return
    path=next(p for p in sorted(set(expected)|set(actual)) if expected.get(p)!=actual.get(p))
    def operand(row):
        result=dict(row)
        if len(result.get('link','').encode())>96:
            raw=result['link'].encode();result['link']=dict(prefix=raw[:96].decode('utf-8','replace'),
                bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        return result
    detail=dict(path=path.encode()[:96].decode('utf-8','replace'),path_sha256=hashlib.sha256(path.encode()).hexdigest(),
        expected=operand(expected.get(path,dict(type='absent'))),actual=operand(actual.get(path,dict(type='absent'))))
    raise ValueError(why+': '+P.encoded(detail).decode().strip())


def ordinary_absent(uid):
    entries=list(Path('/proc').iterdir());P.need(len(entries)<512,'bounded owned process namespace required')
    for path in entries:
        if not path.name.isdigit():continue
        try:raw=(path/'status').read_text()
        except FileNotFoundError:continue
        uids=[line.split()[1:] for line in raw.splitlines() if line.startswith('Uid:')]
        P.need(len(uids)==1 and len(uids[0])==4 and str(uid) not in uids[0],'ordinary generated-RC fixture process remains')


def trial(context):
    global L
    P.need(L is not None,'explicit inherited bootstrap namespace required')
    after,plan,rows,pacman=context['after'],context['plan'],context['rows'],context['pacman']
    P.expected(after,'0.1.0-3');native_root=Path('/real-source')
    native=P.load('expanded_setup5_native_gate',native_root/'scripts/ci/setup5-native-real-modules/contract.py')
    native.verify_source(native_root)
    extra=P.read(Path('/plan/setup5-integration.json'));product=extra['product']
    P.need(extra['baseline600_sha256']==P.AFTER and extra['pair_source']==P.PAIR and extra['probe_source']==P.PROBE and
        product['name']==P.SETUP and product['version']=='0.1.0-5' and product['sha256']==P.ARCHIVE and
        product['signer']==plan['test_signer'] and extra['original_consumer_modified'] is False,
        'exact separately signed accepted Setup5 trial plan required')
    archive=Path('/addons')/product['archive'];signature=Path('/addons')/product['signature']['path']
    P.need(P.sha(archive)==P.ARCHIVE and P.sha(signature)==product['signature']['sha256'] and
        signature.stat().st_size==product['signature']['bytes'] and L.metadata(archive)==product['metadata'],
        'actual Setup5 archive/signature/metadata join differs')
    original=context['original'];old=next(r for r in original['packages'] if r['name']==P.SETUP)
    P.need(old['version']=='0.1.0-3' and len([r for r in original['packages'] if r['name']==P.SETUP])==1,
        'original signed587 Setup3 rollback archive required')
    rollback=Path('/original')/old['archive']
    full=P.read(Path('/plan/full600-payload.json'),64*1024**2)
    P.need(full['packages']==after,'exact signed complete600 payload map required')
    setup_paths,added_paths=payload_transition(full,product)
    added_absent(added_paths,'before upgrade')
    before_db,before_records=L.database();P.need({n:r['version'] for n,r in before_db.items()}==after,'real600 database required')
    expected=expected_other599(full,context['held'],rows)
    held={p:L.node(Path('/')/p) for p in expected}
    same_payload(expected,held,'actual other599 signed payload differs')
    dbparent={p:L.node(Path(p)) for p in ('/var/lib/pacman','/var/lib/pacman/local')}
    setup_dir=Path('/var/lib/pacman/local')/(P.SETUP+'-0.1.0-3');desc_before=(setup_dir/'desc').read_bytes()
    P.need(len(desc_before)<=16384,'bounded Setup3 metadata required');Path('/out/setup3-before.desc').write_bytes(desc_before)
    existing_configs=context['configs'];existing_users=context['users'];events=[]
    user_parent=None;user_state=None;workspace=None

    def preserved(phase,version):
        desired=P.expected(after,version);P.need(L.inventory()==desired,'exact600 inventory/version lock differs')
        db,records=L.database();other599(before_db,before_records,db,records)
        same_payload(held,{p:L.node(Path('/')/p) for p in held},'other599 installed payload changed')
        P.need({p:L.node(Path(p)) for p in dbparent}==dbparent,'database parent modes/owners changed')
        P.need({k:v for k,v in L.tree(Path('/etc')).items() if k!='/etc/ld.so.cache'}==existing_configs and
            L.tree(Path('/home'))|L.tree(Path('/root'))==existing_users,'existing configurations/defaults changed')
        selected=product if version=='0.1.0-5' else dict(name=P.SETUP,version='0.1.0-3',
            payload={p:full['nodes'][p] for p in setup_paths})
        L.check_incoming([selected],desired,db)
        if version=='0.1.0-3':added_absent(added_paths,'after Setup3 rollback')
        L.run(pacman+['-Dk']);L.run(pacman+['-T',*sorted({d for r in db.values() for d in r['depend']})])
        if user_state is not None:P.need(workspace()==user_state,'complete generated/edited user workspace changed')
        context['ld_checkpoint'](phase)
        events.append(dict(phase=phase,count=600,status='PASS',other599_versions=True,other599_database=True,
            other599_payload=True,configuration_preserved=True,database_check=True,
            inventory_sha256=hashlib.sha256(L.C.inventory_bytes(desired)).hexdigest()))

    printed=L.run(pacman+['--noconfirm','-U','--print','--print-format','%n %v',archive])
    P.need(printed.strip()==P.SETUP+' 0.1.0-5','sole Setup5 upgrade preflight required')
    L.run(pacman+['--noconfirm','--noscriptlet','-U',archive]);preserved(P.PHASES[0],'0.1.0-5')
    account=pwd.getpwnam('alarm');user_parent=Path('/tmp/setup5-expanded-real-user');user_parent.mkdir(mode=0o700)
    os.chown(user_parent,account.pw_uid,account.pw_gid);ordinary_absent(account.pw_uid)
    env=dict(PATH='/usr/bin:/bin',HOME=str(user_parent),LANG='C.UTF-8',LC_ALL='C.UTF-8',
        PYTHONDONTWRITEBYTECODE='1',CACHY_SETUP5_REAL_USER='1')
    command=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in env.items()),
        '/usr/bin/python3','-I','-B','/real-source/scripts/ci/setup5-native-real-modules/installed.py',
        '--source','/real-source','--output',str(user_parent/'work')]
    # Preserve raw probe bytes before validation or later ALPM operations.
    output=L.subprocess.run(command,capture_output=True,text=True,timeout=240)
    P.need(len(output.stdout.encode())+len(output.stderr.encode())<=128*1024,'accepted real probe output bound')
    Path('/out/real-modules.json').write_text(output.stdout)
    P.need(output.returncode==0,'real generated-RC probe failed: '+output.stderr[-1024:])
    real=P.read(Path('/out/real-modules.json'),128*1024);native.validate_real(real);ordinary_absent(account.pw_uid)
    snapshot=P.load('setup5_complete_workspace',native_root/'scripts/ci/setup5-native-real-modules/lifecycle.py')
    snapshot.C=native
    io=P.load('setup5_workspace_entry',native_root/'scripts/ci/welcome-native/lifecycle.py')
    homes=P.load('setup5_bounded_homes',native_root/'scripts/ci/setup5-real-modules/run.py')
    workspace=lambda:snapshot.workspace_snapshot(user_parent,real,io,homes)
    user_state=workspace();preserved(P.PHASES[1],'0.1.0-5')
    L.run(pacman+['--noconfirm','--noscriptlet','-U',archive]);preserved(P.PHASES[2],'0.1.0-5')
    earliest=int(time.time());L.run(pacman+['--noconfirm','--noscriptlet','-U',rollback]);latest=int(time.time())
    preserved(P.PHASES[3],'0.1.0-3')
    after_db,after_records=L.database();P.need(after_db[P.SETUP]==before_db[P.SETUP],'Setup3 logical ownership/dependency record not restored')
    desc_after=(setup_dir/'desc').read_bytes();P.need(len(desc_after)<=16384,'bounded rollback metadata required')
    Path('/out/setup3-after.desc').write_bytes(desc_after);restored_desc(desc_before,desc_after,earliest,latest)
    before=before_records[P.SETUP];restored=after_records[P.SETUP]
    P.need(set(before)==set(restored) and all(restored[p]==row for p,row in before.items() if p!=str(setup_dir/'desc')),
        'Setup3 database files changed beyond normal INSTALLDATE record')
    ordinary_absent(account.pw_uid);P.need(workspace()==user_state,'complete workspace changed after Setup3 rollback')
    return dict(status='PASS_SETUP5_EXPANDED600_INTEGRATION',scope='SEPARATE_OWNED_FULL600_SETUP5_CONSUMER',
        package_count=600,restored_count=600,baseline600_sha256=P.AFTER,setup3_version='0.1.0-3',setup5_version='0.1.0-5',
        setup5_archive_sha256=P.ARCHIVE,setup5_events=events,real_modules=real,original_consumer_modified=False,
        complete_user_workspace_preserved=True,ordinary_user_processes_absent=True,setup3_payload_restored=True,
        setup3_database_semantics_restored=True,other_setup3_db_files_identical=True,
        setup3_database_install_date=dict(before=desc_fields(desc_before)['INSTALLDATE'],after=desc_fields(desc_after)['INSTALLDATE'],interval=[earliest,latest],
            policy='NORMAL_ALPM_ROLLBACK_ONLY; ORIGINAL_EIGHT_CHECKPOINT_CONSUMER_IS_ISOLATED'),
        hardware='NOT_RUN',release='NOT_ADMITTED')


def main():
    global L
    P.policy()
    P.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file(),
        'dedicated owned native ARM root PID1 required')
    folder=Path('/code/scripts/ci/expanded-development-composition');sys.path.insert(0,str(folder))
    C=P.load('contract',folder/'contract.py');C.source(Path('/code'));C.verify_self(Path('/code'))
    source=adapted_source((folder/'lifecycle.py').read_text())
    L=types.ModuleType('unchanged_full600_bootstrap_for_setup5');L.__file__=str(folder/'lifecycle.py')
    L.__dict__['_setup5_trial']=trial;exec(compile(source,L.__file__,'exec'),L.__dict__)
    code=L.main()
    native=P.load('setup5_expanded_final_validator',Path('/real-source/scripts/ci/setup5-native-real-modules/contract.py'))
    P.validate(P.read(Path('/out/lifecycle.json')),native);return code


if __name__=='__main__':raise SystemExit(main())
