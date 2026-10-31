# SPDX-License-Identifier: MIT
"""Fresh TEST authority entirely inside the owned native capture actor."""
import importlib.util,io,json,os,shutil,subprocess,tarfile,time
from pathlib import Path


def need(ok,why):
    if not ok:raise ValueError(why)

def create(source,files):
    # This bounded fixture layout is not a Git checkout; it holds exactly the
    # unchanged release test plus three already archive-verified runtime helpers.
    work=Path('/tmp/management16k-signing');work.mkdir(mode=0o700)
    layout=work/'fixture-api/scripts/release';layout.mkdir(parents=True)
    fixture=layout/'test_release.py';fixture.write_bytes((source/'scripts/release/test_release.py').read_bytes())
    prefix='usr/share/cachy-asahi/repository-runtime/'
    for name,(mode,raw) in files.items():
        if name.startswith(prefix):
            target=work/'fixture-api'/name[len(prefix):];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    spec=importlib.util.spec_from_file_location('management16k_test_release',fixture);api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
    case=None;cls=api.ReleaseTests
    try:
        cls.setUpClass();case=cls('test_signed_stage_and_verify');case.setUp();case.stage();api.r.verify_release(case.directory,case.key,case.env)
        public=work/'public';public.mkdir();shutil.copytree(case.directory,public/'bundle',symlinks=True)
        value=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256=api.r.sha(public/'bundle/release.json'),
            repository='fixture',applications=[dict(id='fixture',title='Synthetic Fixture',description='Isolated TEST catalog; never applied',packages=['fixture'])])
        catalog=public/'catalog.json';catalog.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');api.r.sign(catalog,case.key,case.env)
        (public/'public.gpg').write_bytes(api.r.run(['gpg','--batch','--export',case.key],env=case.env))
        control=dict(signer=case.key,release_sha256=value['release_sha256'],catalog_sha256=api.r.sha(catalog),synthetic=True,production_trust='NOT_ESTABLISHED')
        (public/'control.json').write_text(json.dumps(control,sort_keys=True)+'\n')
        output=io.BytesIO();count=0;total=0
        with tarfile.open(fileobj=output,mode='w:') as archive:
            for path in sorted(public.rglob('*')):
                count+=1;name=path.relative_to(public).as_posix();need(count<=128,'public fixture count bound')
                member=tarfile.TarInfo(name);member.uid=member.gid=member.mtime=0
                if path.is_symlink():
                    link=os.readlink(path);need('/' not in link and link not in ('.','..'),'public fixture symlink differs');member.type=tarfile.SYMTYPE;member.linkname=link;member.mode=0o777;archive.addfile(member)
                elif path.is_dir():member.type=tarfile.DIRTYPE;member.mode=0o755;archive.addfile(member)
                else:
                    raw=path.read_bytes();total+=len(raw);need(total<=1024**2 and len(raw)<=262144,'public fixture byte bound')
                    member.size=len(raw);member.mode=0o644;archive.addfile(member,io.BytesIO(raw))
        raw=output.getvalue();need(len(raw)<=2*1024**2,'public fixture archive bound')
    finally:
        if case is not None:case.doCleanups()
        cls.tearDownClass();shutil.rmtree(work)
    # GPG agents are the only possible daemon. Explicitly retire/reap them before
    # any public capture is published; never export a private key/home/socket.
    end=time.monotonic()+5
    while True:
        try:
            while os.waitpid(-1,os.WNOHANG)[0]:pass
        except ChildProcessError:pass
        others=[]
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal() or int(path.name)==os.getpid():continue
            try:uid=next(line.split()[1:] for line in (path/'status').read_text().splitlines() if line.startswith('Uid:'))
            except FileNotFoundError:continue
            if str(os.getuid()) in uid:others.append(int(path.name))
        if not others:break
        need(time.monotonic()<end,'TEST signing actor remains');time.sleep(.02)
    return raw,dict(**control,private_authority_removed=True,signing_processes_absent=True,source='UNCHANGED_PROJECT_SYNTHETIC_RELEASE_FIXTURE',native_installation='NOT_RUN')
