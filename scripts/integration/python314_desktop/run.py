#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Candidate Python plus unchanged installed FirstLogin GTK: one host-only lane."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
UI_COMMIT = '1bff639be5582559c81a012320f6b3752f259433'
UI_REL = 'scripts/integration/first_login_ui_candidate'
UI_SHA = '869fb4f1dcf7fc26ff87594398eba8d15d4a8051e6feaf96d4b8fe457ccb4ea4'
PY_SHA = '8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e'
MIN_FREE = 8 * 1024**3


def require(ok, message):
    if not ok: raise ValueError(message)


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def capacity(path):
    free = shutil.disk_usage(path).free
    require(free >= MIN_FREE, 'HOLD workspace capacity below8GiB; do not provision')
    return {'free_bytes': free, 'minimum_bytes': MIN_FREE, 'device': path.stat().st_dev,
            'plan': 'reuse built UI; one provision and two derived images; no copied full root or new UI build'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def prepare_inputs(ui, source, retained, candidate, archive, target):
    profile = json.loads((source / 'inputs.json').read_text())
    reader = ui.load('desktop_archive_reader', source.parents[2] / 'scripts/update/archive_stream.py',
                     '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838')
    target.mkdir()
    (target / 'materials').mkdir()
    (target / 'templates').mkdir()
    rows = {}
    for name, expected in profile['archives'].items():
        path = retained / 'materials' / expected['name']
        require(ui.pin(path) == {k: expected[k] for k in ('bytes', 'sha256')}, 'retained UI backend/template input differs')
        shutil.copyfile(path, target / 'materials' / path.name)
        nodes = reader.archive_payload(path, reader.Limits(1024**2, 1024**2, 8*1024**2, 200,
                                        2*1024**2, 128*1024**2, time.monotonic()+15))
        rows[name] = {p: row for p, row in nodes.items() if row['type'] == 'file'}
        with tarfile.open(path) as stream:
            controls = {m.name.removeprefix('./') for m in stream if m.name.removeprefix('./').startswith('.')}
        require(controls <= {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'unexpected backend control/script')
        if name in ('fish', 'zsh'):
            member = 'usr/share/cachy-asahi/' + name + '/config.' + name
            with tarfile.open(path) as stream:
                with stream.extractfile(member) as file: data = file.read(2*1024**2 + 1)
            require(hashlib.sha256(data).hexdigest() == rows[name][member]['sha256'], 'template differs')
            folder = target / 'templates' / name
            folder.mkdir()
            (folder / ('config.' + name)).write_bytes(data)
    require(len(rows['first_login']) == 6 and len(rows['setup']) == 10, 'backend payload count')
    for package, path, fixture in [('first_login','usr/lib/cachy-asahi/first-login/first_login.py','first-login-fixture.py'),
                                   ('setup','usr/bin/cachy-asahi-setup','setup8-fixture.py')]:
        require(rows[package][path]['sha256'] == profile['recipe_files'][fixture]['sha256'], 'backend source binding')
    ui_rows = {path: {'sha256': profile['recipe_files'][name]['sha256'],
                      'mode': 0o755 if path.startswith('usr/bin/') else 0o644} for path,name in ui.UI_FILES.items()}
    nodes = reader.archive_payload(archive, reader.Limits(1024**2,1024**2,8*1024**2,200,
                                   2*1024**2,128*1024**2,time.monotonic()+15))
    actual = {p: {'sha256':r['sha256'],'mode':r['mode']} for p,r in nodes.items() if r['type']=='file'}
    require(actual == ui_rows, 'exact UI archive/source payload join')
    for path in (candidate, archive): shutil.copyfile(path, target / 'materials' / path.name)
    (target / 'inputs.json').write_text(json.dumps(profile, sort_keys=True))
    (target / 'payloads.json').write_text(json.dumps({'first_login': rows['first_login'], 'setup': rows['setup'], 'ui':ui_rows}, sort_keys=True))
    for path in target.rglob('*'):
        if path.is_file(): path.chmod(0o444)
    return profile


def main():
    require(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized Python required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ui-worktree', type=Path, required=True)
    parser.add_argument('--retained-inputs', type=Path, required=True)
    parser.add_argument('--ui-archive', type=Path, required=True)
    parser.add_argument('--python-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    space = capacity(args.output.absolute().parent)
    source = args.ui_worktree / UI_REL
    borrowed = ('run.py','owner.py','user_journey.py','installed_gui.py','provision.sh','inputs.json')
    source_pins = {}
    for name in borrowed:
        committed = subprocess.check_output(['git','-C',str(args.ui_worktree),'show',UI_COMMIT+':'+UI_REL+'/'+name], timeout=10)
        require((source/name).read_bytes() == committed, 'borrowed UI source differs from exact commit')
        source_pins[name] = hashlib.sha256(committed).hexdigest()
    require(args.ui_archive.stat().st_size == 16905 and sha(args.ui_archive)==UI_SHA, 'exact retained UI archive required')
    require(sha(args.python_archive)==PY_SHA, 'exact full-Tk Python archive required')
    ui = load('completed_ui_controller', source/'run.py')
    runtime = ui.load('desktop_process_runtime', ROOT/'scripts/port/fdk-native-stage/runtime.py',
                      '253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a')
    out = args.output.absolute()
    require(not out.exists() and not any(p.is_symlink() for p in (out,*out.parents)), 'fresh private output required')
    out.mkdir(mode=0o700)
    driver = out/'driver';driver.mkdir();(driver/'borrowed').mkdir()
    for name in borrowed: shutil.copyfile(source/name,driver/'borrowed'/name)
    for name in ('provision.sh','owner.py','user_probe.py','checks.py'): shutil.copyfile(HERE/name,driver/name)
    profile = prepare_inputs(ui, source, args.retained_inputs, args.python_archive, args.ui_archive, out/'inputs')
    token=uuid.uuid4().hex[:16]
    names={k:'python314-desktop-'+k+'-'+token for k in ('provision','backend','lifecycle','work','secret')}
    images={k:'cachy-asahi-python314-desktop-'+k+':'+token for k in ('deps','backends')}
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','XDG_RUNTIME_DIR','DOCKER_HOST','DOCKER_CONTEXT')}
    runner=runtime.Runner(2100,env,out/'logs')
    report={'schema_version':1,'status':'HOLD','capacity_preflight':space,'base':ui.BASE,'UI_commit':UI_COMMIT,
            'borrowed_source_sha256':source_pins,'input_profile':profile,'UI_archive_sha256':UI_SHA,'python_archive_sha256':PY_SHA,
            'controller_sha256':sha(HERE/'run.py'),'extension_sha256':{p.name:sha(p) for p in HERE.iterdir() if p.is_file()},
            'operations':[],'cleanup':[],'holds':['x86_64 cross-component only; nativeARM/16K/M2 NOT RUN',
            'source/legal/production trust/full-system/release gates unchanged']}
    def command(argv, seconds=60, check=True):
        p=runner.run(list(map(str,argv)),timeout=seconds,log=f'{len(report["operations"]):02d}.txt')
        report['operations'].append({'argv':list(map(str,argv)),'exit':p.returncode})
        require(not check or p.returncode==0,'operation failed:'+str(len(report['operations'])-1))
        return p
    def mount(src,dst,kind='bind',readonly=True):
        return ['--mount',f'type={kind},src={src},dst={dst}'+(',readonly' if readonly else '')]
    common=['--init',*ui.LIMITS,'--security-opt=no-new-privileges']
    def inspect(name, expected):
        value=json.loads(command(['docker','inspect',names[name]]).stdout)[0]
        report[name+'_resources']=ui.resources(value,False,'0:0')
        require({m['Destination']:(m['Type'],m['RW']) for m in value['Mounts']}==expected,'unexpected mount/source access')
    error=None
    try:
        with runtime.cancellation_handlers():
            command(['docker','image','inspect',ui.BASE])
            report['capacity_before_provision']=capacity(out)
            command(['docker','create','--name',names['provision'],*common,'--network=host',*mount(driver,'/driver'),
                     '--entrypoint=/usr/bin/bash',ui.BASE,'/driver/provision.sh'])
            command(['docker','start','--attach',names['provision']],900)
            command(['docker','commit',names['provision'],images['deps']],120)
            for name in ('work','secret'): command(['docker','volume','create',names[name]])
            shared=[*mount(driver,'/driver'),*mount(names['work'],'/work','volume',False),*mount(names['secret'],'/signing','volume',False)]
            command(['docker','create','--name',names['backend'],*common,'--network=none','--cap-drop=ALL','--user=0:0',
                     *shared,*mount(out/'inputs','/inputs'),'--entrypoint=/usr/bin/python3',images['deps'],'-I','-B','/driver/owner.py','backend'])
            inspect('backend',{'/driver':('bind',False),'/work':('volume',True),'/signing':('volume',True),'/inputs':('bind',False)})
            command(['docker','start','--attach',names['backend']],240)
            command(['docker','commit',names['backend'],images['backends']],120)
            command(['docker','create','--name',names['lifecycle'],*common,'--network=none','--cap-drop=ALL','--user=0:0',
                     *shared,'--entrypoint=/usr/bin/sleep',images['backends'],'900'])
            inspect('lifecycle',{'/driver':('bind',False),'/work':('volume',True),'/signing':('volume',True)})
            command(['docker','start',names['lifecycle']])
            for user,script,operation,extra,seconds in [
                ('0:0','owner.py','prepare',[],180),('0:0','owner.py','candidate',[],180),
                ('1000:1000','user_probe.py','launch',['3.14.8'],150),('0:0','owner.py','restore',[],180),
                ('1000:1000','user_probe.py','verify',[],30),('1000:1000','user_probe.py','launch',['3.14.9'],150),
                ('0:0','owner.py','remove',[],90),('1000:1000','user_probe.py','verify',[],30)]:
                command(['docker','exec','--user='+user,names['lifecycle'],'/usr/bin/python3','-I','-B','/driver/'+script,operation,*extra],seconds)
            command(['docker','cp',names['lifecycle']+':/work/python-desktop/user',str(out/'user')],60)
            command(['docker','cp',names['lifecycle']+':/work/public',str(out/'public')],60)
            for version in ('3.14.8','3.14.9'):
                value=json.loads((out/'user'/('result-'+version+'.json')).read_text())
                require(value['python'].startswith(version+' '),'actual UI interpreter mismatch')
                require(json.loads((out/'user'/('gui-'+version+'.stdout')).read_text())['count']==4,'installed GUI count differs')
            require(json.loads((out/'user/homes-preserved.json').read_text())['homes']==2,'caller home preservation missing')
            require(sha(args.ui_archive)==UI_SHA and sha(args.python_archive)==PY_SHA,'original archives changed')
            report['status']='PASS candidate Python actual installed GTK/Preview/Apply and exact provider/inventory/home restoration'
    except BaseException as exc:
        error=exc;report.update(status='FAIL cross-component run',failure=type(exc).__name__+': '+str(exc))
    finally:
        cleanup=runtime.Runner(180,env,out/'logs')
        with runtime.defer_signals():
            for target,path in [('user','/work/python-desktop/user'),('public','/work/public')]:
                if not (out/target).exists():
                    try: cleanup.run(['docker','cp',names['lifecycle']+':'+path,str(out/target)],timeout=20)
                    except BaseException: pass
            actions=[['docker','rm','-f',names[n]] for n in ('lifecycle','backend','provision')]
            actions += [['docker','volume','rm',names[n]] for n in ('work','secret')]
            actions += [['docker','image','rm',images[n]] for n in ('backends','deps')]
            for argv in actions:
                try:
                    p=cleanup.run(argv,timeout=15);text=p.stdout.decode(errors='replace')
                    report['cleanup'].append({'argv':argv,'exit':p.returncode,'already_absent':ui.absent(argv,text),'output':text[-1024:]})
                except BaseException as exc:report['cleanup'].append({'argv':argv,'error':str(exc)})
        if any(c.get('exit')!=0 and not c.get('already_absent') for c in report['cleanup']):report['status']='HOLD cleanup incomplete'
        report['export_sha256']={str(p.relative_to(out)):sha(p) for name in ('user','public') for p in sorted((out/name).rglob('*')) if p.is_file()}
        (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    if error:raise error
    print(json.dumps({'status':report['status'],'report':str(out/'report.json')}))
    return 0 if report['status'].startswith('PASS') else 2


if __name__=='__main__':raise SystemExit(main())
