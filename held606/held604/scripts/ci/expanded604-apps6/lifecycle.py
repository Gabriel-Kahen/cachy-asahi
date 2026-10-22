#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact587 ->604 ->587 lifecycle, only inside the explicitly owned ARM container."""
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
    helper=C.load('expanded604_root_database',CODE/'scripts/ci/full-root-upgrade/root_upgrade.py')
    rows=helper.database(Path('/'),max_packages=604)
    C.need(len(rows) in (587,604),'actual604 database count differs')
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


def input_paths(root,rows):
    return [C.checked(root,dict(path=r['archive'],bytes=r['size'],sha256=r['sha256']),256*1024**2) for r in rows]


def verify_signature(gpg,archive,signature,expected):
    output=run(gpg+['--status-fd','1','--verify',signature,archive])
    states=[line.removeprefix('[GNUPG:] ').split() for line in output.splitlines() if line.startswith('[GNUPG:] ')]
    rejected={'BADSIG','ERRSIG','EXPSIG','EXPKEYSIG','KEYEXPIRED','SIGEXPIRED','REVKEYSIG','KEYREVOKED','NO_PUBKEY','FAILURE'}
    C.need(not any(s and s[0] in rejected for s in states),'invalid/expired/revoked signature')
    valid=[s for s in states if s and s[0]=='VALIDSIG']
    C.need(len(valid)==1 and len(valid[0]) in (10,11) and (valid[0][10] if len(valid[0])==11 else valid[0][1])==expected,'exact primary signer required')


def trust(work,plan,original):
    home=work/'trust';home.mkdir(mode=0o700)
    gpg=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve']
    keys=[C.checked(Path('/original'),dict(path=r['path'],bytes=r['size'],sha256=r['sha256']),1024**2) for r in original['keyrings']]
    C.need(len(keys)==2,'two original public keyrings required')
    run(gpg+['--import',*keys])
    signers={row['signer'] for row in original['packages']}
    roles=original['preparation']['signer_roles']
    C.need(set(roles)=={'upstream_ALARM','ephemeral_TEST'} and set(roles.values())==signers and len(signers)==2 and
           all(re.fullmatch('[0-9A-F]{40}',s) for s in signers),'exact two original signer roles required')
    run(gpg+['--import-ownertrust'],''.join(s+':6:\n' for s in sorted(signers)))
    for root,rows in ((Path('/original'),original['packages']),(Path('/target'),plan['incoming'])):
        for row,path in zip(rows,input_paths(root,rows)):
            signature=C.checked(root,dict(path=row['signature'],bytes=row['signature_size'],sha256=row['signature_sha256']),1024**2)
            C.need(row['signature']==row['archive']+'.sig' and row['signer'] in signers,'closed signature reference required')
            if root==Path('/target'):
                role='upstream_ALARM' if row['name']=='lsp-plugins-lv2' else 'ephemeral_TEST'
                C.need(row['signer']==roles[role],'incoming signer role differs')
            verify_signature(gpg,path,signature,row['signer'])
    hooks=work/'hooks';hooks.mkdir();names=set()
    for directory in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks'):
        names.update(p.name for p in Path(directory).glob('*.hook'))
    for root,rows in ((Path('/original'),original['packages']),(Path('/target'),plan['incoming'])):
        for row in rows:
            listing=run(['pacman','-Qqlp',root/row['archive']]).splitlines()
            names.update(Path(p).name for p in listing if p.startswith(('/usr/share/libalpm/hooks/','/etc/pacman.d/hooks/')) and p.endswith('.hook'))
    for name in names:
        C.need(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',name),'unsafe incoming hook');(hooks/name).symlink_to('/dev/null')
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
                hardware='NOT_RUN',notification_delivery='NOT_RUN',defaults_enabled=False,
                apps_plan='NOT_APPLIED',cache_removal='NOT_APPLIED')
    work=None;home=None
    try:
        C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.geteuid()==0 and
               Path('/.dockerenv').is_file() and re.fullmatch('[0-9a-f]{32}',os.environ.get('CACHY_ASAHI_EXPANDED604','')) and
               not Path('/dev/snd').exists() and not Path('/run/systemd/system').exists(),'owned offline604 native container required')
        plan=C.read(Path('/plan/plan.json'),32*1024**2)
        profile=C.load('expanded604_original_profile',CODE/'scripts/ci/full-composition-installer-vm/profile.py')
        original,_,before=profile.manifest(Path('/original'))
        rows=plan['incoming'];after=plan['after']
        C.need(plan['before']==before and len(rows)==19 and len({r['name'] for r in rows})==19 and
               C.selected(before,{r['name']:r['version'] for r in rows})==after,'exact604 plan differs')
        driver=plan['combined'];C.relative(driver['entry'])
        C.need(driver['arguments']==['--source','/combined','--output','{work}'],'fixed combined driver arguments required')
        for name,ref in driver['files'].items():C.checked(Path('/combined'),ref)
        base=C.lock(Path('/original/builder-packages.lock').read_bytes(),574)
        C.need(inventory()==base,'actual fresh574 container inventory differs')
        projects={r['name'] for r in original['projects']};extras={'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
        initial=[r for r in original['packages'] if r['name'] in projects|extras]
        C.need(len(initial)==14 and len(projects)==10 and before=={k:v for k,v in base.items() if k!='libfdk-aac'}|
               {r['name']:r['version'] for r in initial},'bootstrap must preserve exact initial587')
        work=Path(tempfile.mkdtemp(prefix='expanded604-',dir='/tmp'))
        # Record the verification home before trust(), so failures still retire its agent.
        home=work/'trust';pacman,home=trust(work,plan,original)
        initial_paths=['/original/'+r['archive'] for r in initial]
        metas={r['name']:metadata('/original/'+r['archive']) for r in initial}
        conflicts={(name,d) for name,m in metas.items() for d in m.get('conflict',[]) if re.split('[<>=]',d)[0] in set(base)|projects|extras}
        C.need(conflicts=={('cachy-asahi-fdk-aac','libfdk-aac')},'bootstrap sole FDK replacement differs')
        addon_paths=[str(p) for p in input_paths(Path('/target'),rows)]
        for row,path in zip(rows,addon_paths):
            C.need(metadata(path)==row['metadata'],'actual incoming metadata differs')
            C.need(not any(row['metadata'].get(k) for k in ('conflict','replaces','backup')),'incoming replacement/config refused')
        original_payload=C.read(Path('/plan/original-payload.json'),64*1024**2)
        initial_payload=C.read(Path('/plan/initial14-payload.json'),16*1024**2)
        predecessors=C.read(Path('/plan/predecessor-payload.json'),16*1024**2)
        C.need(set(predecessors)==set(C.UPGRADES),'both exact original predecessors required')
        run(pacman+['--noconfirm','--noscriptlet','--ask','4','-U',*initial_paths])
        C.need(inventory()==before,'exact signed original587 not established')
        sample=Path('/home/composition-user/.config');sample.mkdir(parents=True)
        for path in ('fish/config.fish','zsh/.zshrc','systemd/user/unchanged.fixture'):
            destination=sample/path;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text('# retained user configuration\n')
        upgrade_paths=set().union(*(set(original_payload['ownership'][name]) for name in C.UPGRADES))
        held={p:node(Path('/')/p) for p in original_payload['nodes'] if p not in upgrade_paths}
        held={p:n for p,n in held.items() if n['type']!='directory'}
        baseline_db,baseline_records=database()
        C.need(set(baseline_records)-C.UPGRADES.keys()==set(before)-C.UPGRADES.keys(),'exact585 preserved original DB required')
        database_parents={p:node(Path(p)) for p in ('/var/lib/pacman','/var/lib/pacman/local')}
        check_incoming(initial_payload,before,baseline_db)
        configs={k:v for k,v in tree(Path('/etc')).items() if k!='/etc/ld.so.cache'}
        users=tree(Path('/home'))|tree(Path('/root'))
        old_rows=[dict(name=n,version=v['before'],payload=predecessors[n]) for n,v in C.UPGRADES.items()]
        old_paths=['/original/'+next(r['archive'] for r in original['packages'] if r['name']==n) for n in C.UPGRADES]
        additions=sorted(C.ADDITIONS)
        C.need(len(additions)==17 and set(rows[i]['name'] for i in range(len(rows)))==C.ADDITIONS|C.UPGRADES.keys(),
               'exact seventeen additions/two upgrades required')
        for row in rows:
            for name in row['payload']:
                if row['name'] in C.ADDITIONS:C.need(node(Path('/')/name)['type']=='absent','incoming path already exists: '+name)
        audio=C.load('expanded604_ld_state',CODE/'scripts/ci/full-development-composition/audio.py')
        adapter=ld_adapter();audio_rows=C.read(CODE/'scripts/ci/full-development-composition/audio-inputs.json')
        previous_ld=None;previous_aux=None;ld_receipts=[]

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
            C.need(inventory()==expected,'actual transaction inventory differs')
            db,records=database();check_incoming(selected_rows,expected,db)
            C.need({p:node(Path(p)) for p in database_parents}==database_parents,'database parent metadata changed')
            C.need({p:node(Path('/')/p) for p in held}==held,'original non-upgrade payload changed')
            C.need(all(records.get(n)==r for n,r in baseline_records.items() if n not in C.UPGRADES),
                   'original585 non-upgrade database changed')
            C.need({k:v for k,v in tree(Path('/etc')).items() if k!='/etc/ld.so.cache'}==configs and
                   tree(Path('/home'))|tree(Path('/root'))==users,'existing configuration changed or defaults enabled')
            if final:
                C.need(all(db[n]==baseline_db[n] for n in C.UPGRADES),'both original predecessor ownership/metadata required')
                C.need(all(all(node(Path('/')/p)['type']=='absent' for p in r['payload'])
                           for r in rows if r['name'] in C.ADDITIONS),'removed addon payload remains')
                C.need(all(all(node(Path('/')/p)['type']=='absent' for p in r['payload'] if p not in predecessors[r['name']])
                           for r in rows if r['name'] in C.UPGRADES),'successor-only predecessor payload remains')
            run(pacman+['-Dk']);depends=sorted({d for r in db.values() for d in r['depend']})
            run(pacman+['-T',*depends])

        def versions(expected):return {n:expected[n] for n in C.UPGRADES}

        def checkpoint(phase,expected,selected_rows,final=False):
            preservation(expected,selected_rows,final);ld_checkpoint(phase)
            report['events'].append(dict(phase=phase,count=len(expected),upgrades=versions(expected),status='PASS',
                signatures=True,dependencies=True,payload=True,ownership=True,originals_preserved=True,user_config_preserved=True))

        def install():
            printed=run(pacman+['--noconfirm','-U','--print','--print-format','%n %v',*addon_paths])
            C.need(dict(line.split() for line in printed.splitlines())=={r['name']:r['version'] for r in rows},
                   'normal incoming dependency/conflict preflight differs')
            run(pacman+['--noconfirm','--noscriptlet','-U',*addon_paths])

        def restore(phase):
            run(pacman+['--noconfirm','--noscriptlet','-R',*additions])
            interim=before|{n:v['after'] for n,v in C.UPGRADES.items()}
            preservation(interim,[r for r in rows if r['name'] in C.UPGRADES]);ld_checkpoint(phase+'-upgraded')
            report['subtransactions'].append(dict(phase=phase+'-upgraded',count=587,upgrades=versions(interim),status='PASS'))
            run(pacman+['--noconfirm','--noscriptlet','-U',*old_paths])
            checkpoint(phase,before,old_rows,final=True)

        checkpoint('baseline587',before,old_rows)
        install();checkpoint('install604',after,rows)
        userwork=Path('/tmp')/('expanded604-shell-'+os.urandom(16).hex())
        arguments=[a.replace('{work}',str(userwork)) for a in driver['arguments']]
        run(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','LC_ALL=C.UTF-8',
             '/usr/bin/python3','-I','-B','/runner/installed_shells.py',*arguments])
        receipt=userwork/'receipt.json';raw=receipt.read_bytes();C.need(len(raw)<=1024**2,'combined receipt byte cap')
        combined=json.loads(raw);C.validate_combined(combined)
        C.need(combined['source_inputs']=={p:r['sha256'] for p,r in driver['files'].items() if p.startswith('packages/')},
               'combined fixture source closure differs')
        shutil.copyfile(receipt,OUT/'combined-shell.json')
        report['combined_shell']=dict(path='combined-shell.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        preservation(after,rows)
        install();checkpoint('same-version604',after,rows)
        restore('remove-to587')
        install();checkpoint('restore604',after,rows)
        restore('final587')
        report.update(status='PASS_APPS6_CURRENT604_METADATA_LIFECYCLE',baseline_sha256=C.BASE_SHA,target_sha256=C.TARGET_SHA,
                      package_count=604,restored_count=587,ldconfig=ld_receipts)
        C.validate_result(report)
    except BaseException as error:report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        if home:
            try:run(['gpgconf','--homedir',home,'--kill','all'])
            except BaseException as error:report.update(status='FAIL',cleanup_error=str(error)[:512])
        (OUT/'lifecycle.json').write_bytes(C.encoded(report))
    return int(report['status']!='PASS_APPS6_CURRENT604_METADATA_LIFECYCLE')


if __name__=='__main__':raise SystemExit(main())
