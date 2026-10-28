#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact587 ->600 ->587 lifecycle, only inside the explicitly owned ARM container."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

CODE=Path('/code')
OUT=Path('/out')


def run(argv,data=None):
    result=subprocess.run(list(map(str,argv)),input=data,text=True,capture_output=True,timeout=180)
    C.need(len(result.stdout)+len(result.stderr)<=4*1024**2,'transaction output cap')
    if result.returncode:raise ValueError('command failed '+str(argv[:5])+': '+result.stderr[-4096:])
    return result.stdout


def ld_adapter():
    return type('Adapter',(),dict(
        pin=staticmethod(lambda p,d,s:C.need(p.stat().st_size==s and C.sha(p)==d,'helper pin differs')),
        run=staticmethod(run)))


def inventory():
    raw=run(['pacman','-Q']).encode();return C.lock(raw,len(raw.splitlines()))


def node(path):
    try:info=path.lstat()
    except FileNotFoundError:return dict(type='absent')
    row=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
    if stat.S_ISREG(info.st_mode):
        C.need(info.st_size<=1024**3,'observed regular file byte limit')
        row.update(type='file',size=info.st_size,sha256=C.sha(path))
    elif stat.S_ISDIR(info.st_mode):row['type']='directory'
    elif stat.S_ISLNK(info.st_mode):row.update(type='symlink',link=os.readlink(path))
    else:raise ValueError('observed special node: '+str(path))
    return row


def tree(root):
    result={};spent=0
    if not root.exists():return result
    result[str(root)]=node(root)
    for path in sorted(root.rglob('*')):
        C.need(len(result)<50000,'configuration node limit');row=node(path)
        spent+=row.get('size',0);C.need(spent<=128*1024**2,'configuration byte limit')
        result[str(path)]=row
    return result


def database():
    helper=C.load('expanded_root_database',CODE/'scripts/ci/full-root-upgrade/root_upgrade.py')
    rows=helper.database(Path('/'),max_packages=600)
    C.need(len(rows) in (587,600),'actual database count differs')
    snapshots={row['name']:tree(Path('/var/lib/pacman/local')/(row['name']+'-'+row['version'])) for row in rows}
    return {row['name']:row for row in rows},snapshots


def expected_node(member):
    base={k:member[k] for k in ('mode','uid','gid')}
    if member['type']=='file':base.update(type='file',size=member['bytes'],sha256=member['sha256'])
    elif member['type']=='symlink':base.update(type='symlink',link=member['target'])
    elif member['type']=='0':base.update(type='file',size=member['size'],sha256=member['sha256'])
    elif member['type']=='2':base.update(type='symlink',link=member['link'])
    else:raise ValueError('unexpected incoming node type')
    return base


def check_incoming(rows,installed,db):
    for row in rows:
        C.need(db[row['name']]['version']==row['version'] and set(db[row['name']]['files'])==set(row['payload']),
               'installed addon ownership differs: '+row['name'])
        for path,member in row['payload'].items():
            C.need(node(Path('/')/path)==expected_node(member),'installed addon bytes/mode/owner differ: '+path)
    owners={}
    for name,row in db.items():
        for path in row['files']:
            C.need(path not in owners,'installed ownership overlap: '+path);owners[path]=name
    C.need({n:r['version'] for n,r in db.items()}==installed,'actual database inventory differs')


def trust(work,plan,original):
    home=work/'trust';home.mkdir(mode=0o700)
    gpg=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve']
    keys=[Path('/original')/row['path'] for row in original['keyrings']]+[Path('/addons/TEST-public.asc')]
    run(gpg+['--import',*keys])
    signers=set(row['signer'] for row in original['packages'])|{plan['test_signer']}
    C.need(len(signers)==3 and all(re.fullmatch('[0-9A-F]{40}',s) for s in signers),'three exact signer roles required')
    run(gpg+['--import-ownertrust'],''.join(s+':6:\n' for s in sorted(signers)))
    hooks=work/'hooks';hooks.mkdir();names=set()
    for directory in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks'):
        names.update(p.name for p in Path(directory).glob('*.hook'))
    for row in original['packages']+plan['incoming']:
        source=('/original/'+row['archive']) if row in original['packages'] else '/addons/'+row['archive']
        listing=run(['pacman','-Qqlp',source]).splitlines()
        names.update(Path(p).name for p in listing if p.startswith(('/usr/share/libalpm/hooks/','/etc/pacman.d/hooks/')) and p.endswith('.hook'))
    for name in names:
        C.need(re.fullmatch('[A-Za-z0-9_.@+-]+\\.hook',name),'unsafe incoming hook');(hooks/name).symlink_to('/dev/null')
    conf=work/'pacman.conf'
    conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(home)+'\nHookDir = '+str(hooks)+'\n')
    return ['pacman','--config',str(conf)],home


def metadata(path):
    result={}
    for line in run(['bsdtar','-xOf',path,'.PKGINFO']).splitlines():
        if line and not line.startswith('#'):
            key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
    return result


def main():
    report=dict(status='FAIL',events=[],subtransactions=[],services='NOT_RUN',audio_execution='NOT_RUN',
                hardware='NOT_RUN',notification_delivery='NOT_RUN',defaults_enabled=False)
    work=None;home=None
    try:
        C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.geteuid()==0 and
               Path('/.dockerenv').is_file() and re.fullmatch('[0-9a-f]{32}',os.environ.get('CACHY_ASAHI_EXPANDED600','')) and
               not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(),'owned offline native container required')
        plan=C.read(Path('/plan/plan.json'),32*1024**2);original=C.read(Path('/original/manifest.json'))
        before=plan['before'];after=plan['after'];rows=plan['incoming']
        C.need(C.selected(before,{r['name']:r['version'] for r in rows if r['name'] in C.AUDIO},
                              {r['name']:r['version'] for r in rows if r['name'] in C.SCRIPTS|{C.UPGRADE}})==after,
               'exact600 plan differs')
        base=C.lock(Path('/original/builder-packages.lock').read_bytes(),574)
        C.need(inventory()==base,'actual fresh574 container inventory differs')
        projects={r['name'] for r in original['projects']};extras={'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
        initial=[r for r in original['packages'] if r['name'] in projects|extras]
        C.need(len(initial)==14 and len(projects)==10 and before=={k:v for k,v in base.items() if k!='libfdk-aac'}|
               {r['name']:r['version'] for r in initial},'bootstrap must preserve exact initial587')
        work=Path(tempfile.mkdtemp(prefix='expanded600-',dir='/tmp'));pacman,home=trust(work,plan,original)
        initial_paths=['/original/'+r['archive'] for r in initial]
        metas={r['name']:metadata('/original/'+r['archive']) for r in initial}
        conflicts={(name,d) for name,m in metas.items() for d in m.get('conflict',[]) if re.split('[<>=]',d)[0] in set(base)|projects|extras}
        C.need(conflicts=={('cachy-asahi-fdk-aac','libfdk-aac')},'bootstrap sole FDK replacement differs')
        run(pacman+['--noconfirm','--noscriptlet','--ask','4','-U',*initial_paths])
        C.need(inventory()==before,'exact signed original587 not established')
        sample=Path('/home/composition-user/.config');sample.mkdir(parents=True)
        for path in ('fish/config.fish','zsh/.zshrc','systemd/user/unchanged.fixture'):
            destination=sample/path;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text('# retained user configuration\n')
        original_payload=C.read(Path('/plan/original-payload.json'),64*1024**2)
        owned_paths=original_payload['ownership'];bang_paths=set(owned_paths[C.UPGRADE])
        held={p:node(Path('/')/p) for p in original_payload['nodes'] if p not in bang_paths}
        held={p:n for p,n in held.items() if n['type']!='directory'}
        baseline_db,baseline_records=database()
        database_parents={p:node(Path(p)) for p in ('/var/lib/pacman','/var/lib/pacman/local')}
        check_incoming(C.read(Path('/plan/initial14-payload.json'),16*1024**2),before,baseline_db)
        configs={k:v for k,v in tree(Path('/etc')).items() if k!='/etc/ld.so.cache'}
        users=tree(Path('/home'))|tree(Path('/root'))
        old=next(r for r in original['packages'] if r['name']==C.UPGRADE)
        old_path='/original/'+old['archive']
        old_payload=C.read(Path('/plan/bang1-payload.json'))
        old_row=dict(name=C.UPGRADE,version=C.OLD,payload=old_payload)
        addon_paths=['/addons/'+r['archive'] for r in rows]
        additions=sorted(C.AUDIO|C.SCRIPTS)
        C.need(len(rows)==14 and len(additions)==13,'incoming selection count differs')
        for row,path in zip(rows,addon_paths):
            C.need(metadata(path)==row['metadata'],'actual incoming metadata differs')
            C.need(not any(row['metadata'].get(k) for k in ('conflict','replaces','backup')),'incoming replacement/config refused')
            for name in row['payload']:
                if row['name']!=C.UPGRADE:C.need(node(Path('/')/name)['type']=='absent','incoming path already exists: '+name)
        audio=C.load('expanded_ld_state',CODE/'scripts/ci/full-development-composition/audio.py')
        adapter=ld_adapter()
        audio_rows=[r for r in C.read(CODE/'scripts/ci/full-development-composition/audio-inputs.json')]
        previous_ld=None;previous_aux=None
        ld_receipts=[]

        def ld_checkpoint(label):
            nonlocal previous_ld,previous_aux
            state=audio.ld_state(adapter,audio_rows);data,_,_=audio.ld_aux_read(state)
            transition={'kind':'BASELINE'} if previous_aux is None else audio.aux_order.compare(previous_aux,data)
            if previous_ld is not None:
                for field in ('helper','configs','aliases','scan','targets','mapping','generator','caches'):
                    left,right=previous_ld[field],state[field]
                    if field=='caches':
                        left={p:{k:v for k,v in n.items() if k!='sha256'} for p,n in left.items()}
                        right={p:{k:v for k,v in n.items() if k!='sha256'} for p,n in right.items()}
                    C.need(left==right,'ldconfig recorded state changed: '+field)
            (OUT/('ld-'+label+'.json')).write_bytes(C.encoded(state))
            (OUT/('aux-'+label+'.bin')).write_bytes(data)
            ld_receipts.append(dict(phase=label,state_sha256=hashlib.sha256(C.encoded(state)).hexdigest(),
                                    aux_sha256=hashlib.sha256(data).hexdigest(),transition=transition,helper_exit='NOT_OBSERVED'))
            previous_ld,previous_aux=state,data

        def preservation(expected,selected_rows,final=False):
            actual=inventory();C.need(actual==expected,'actual transaction inventory differs')
            db,records=database();check_incoming(selected_rows,expected,db)
            C.need({p:node(Path(p)) for p in database_parents}==database_parents,'database parent metadata changed')
            C.need({p:node(Path('/')/p) for p in held}==held,'original non-bang payload changed')
            C.need(all(records.get(n)==r for n,r in baseline_records.items() if n!=C.UPGRADE),
                   'original non-bang database changed')
            C.need({k:v for k,v in tree(Path('/etc')).items() if k!='/etc/ld.so.cache'}==configs and
                   tree(Path('/home'))|tree(Path('/root'))==users,'existing configuration changed or defaults enabled')
            if final:
                C.need(db[C.UPGRADE]==baseline_db[C.UPGRADE],'bang1 ownership/metadata not restored')
                for r in rows:
                    if r['name']!=C.UPGRADE:
                        C.need(all(node(Path('/')/p)['type']=='absent' for p in r['payload']),'removed addon payload remains')
            run(pacman+['-Dk'])
            depends=sorted({d for r in db.values() for d in r['depend']})
            run(pacman+['-T',*depends])

        def checkpoint(phase,expected,selected_rows,final=False):
            preservation(expected,selected_rows,final);ld_checkpoint(phase)
            report['events'].append(dict(phase=phase,count=len(expected),bang_bang=expected[C.UPGRADE],status='PASS',
                signatures=True,dependencies=True,payload=True,ownership=True,originals_preserved=True,user_config_preserved=True))

        def install():
            printed=run(pacman+['--noconfirm','-U','--print','--print-format','%n %v',*addon_paths])
            C.need(dict(line.split() for line in printed.splitlines())=={r['name']:r['version'] for r in rows},
                   'normal incoming dependency/conflict preflight differs')
            run(pacman+['--noconfirm','--noscriptlet','-U',*addon_paths])

        def restore(phase):
            run(pacman+['--noconfirm','--noscriptlet','-R',*additions])
            interim=before|{C.UPGRADE:C.NEW};preservation(interim,[r for r in rows if r['name']==C.UPGRADE]);ld_checkpoint(phase+'-bang2')
            report['subtransactions'].append(dict(phase=phase+'-bang2',count=587,bang_bang=C.NEW,status='PASS'))
            run(pacman+['--noconfirm','--noscriptlet','-U',old_path])
            checkpoint(phase,before,[old_row],final=True)

        checkpoint('baseline587',before,[old_row])
        install();checkpoint('install600',after,rows)
        driver=plan['combined'];entry=Path('/combined')/C.relative(driver['entry'])
        for name,ref in driver['files'].items():C.checked(Path('/combined'),ref)
        userwork=Path('/tmp')/('expanded600-shell-'+os.urandom(16).hex())
        arguments=[a.replace('{work}',str(userwork)) for a in driver['arguments']]
        run(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','LC_ALL=C.UTF-8',
             '/usr/bin/python3','-I','-B','/runner/installed_shells.py',*arguments])
        receipt=userwork/'receipt.json';raw=receipt.read_bytes();C.need(len(raw)<=1024**2,'combined receipt byte cap')
        combined=json.loads(raw)
        C.validate_combined(combined)
        C.need(combined['source_inputs']=={p:r['sha256'] for p,r in driver['files'].items() if p.startswith('packages/')},
               'combined fixture source closure differs')
        shutil.copyfile(receipt,OUT/'combined-shell.json')
        report['combined_shell']=dict(path='combined-shell.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        preservation(after,rows)
        install();checkpoint('same-version600',after,rows)
        restore('remove-to587')
        install();checkpoint('restore600',after,rows)
        restore('final587')
        report.update(status='PASS_EXPANDED600_METADATA_LIFECYCLE',baseline_sha256=C.BASE_SHA,
                      package_count=600,restored_count=587,ldconfig=ld_receipts)
        C.validate_result(report)
    except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        if home:
            try:run(['gpgconf','--homedir',home,'--kill','all'])
            except BaseException as error:report.update(status='FAIL',cleanup_error=str(error)[:512])
        (OUT/'lifecycle.json').write_bytes(C.encoded(report))
    return int(report['status']!='PASS_EXPANDED600_METADATA_LIFECYCLE')


if __name__=='__main__':raise SystemExit(main())
