#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the exact, separate Overlay583 installed onboarding source and test inputs."""
import argparse
from base64 import b64encode
from hashlib import file_digest, sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE_SHA='113a28f6925162d9933c93c569536cb5eafe1c31e46a46cd31b22b2753c50d02'
ROOT_ENTRY='a0d61f0cefae8bb5b1ab9fabd63016ace46451bc01eb432d895eeee42ca1d245'
RUNTIME_WRAPPER_SHA='87a494064ebc6ec4e17d9a00f4cf3c6e3ffed2560e32b8ce558c008a98166bce'
BASE_SOURCE='3a415e51ad5380ff20cde6455fc9c51255d268ff'
EXAMPLE_SOURCE='868f7f4aca866605c69ae911508c4767d2b18280'
SCOPE='cachy-overlay583-development-onboarding-r1.scope'
PREFIX='caa-overlay583-development-onboarding-r1-'
TRIAL='scripts/install/overlay583_trial/trial.py'
OWNER='scripts/virtual/owned_process.py'
EXAMPLE='examples/development/'
BASE_ROLE='OVERLAY583_OWNED_GUEST_PLAN_V1'
TOOLS={
 'bash': ('usr/bin/bash',),
 'binutils': ('usr/bin/as','usr/bin/ld','usr/bin/readelf'),
 'gcc': ('usr/bin/cc','usr/bin/gcc','usr/bin/aarch64-unknown-linux-gnu-gcc',
         'usr/lib/gcc/aarch64-unknown-linux-gnu/16.1.1/cc1'),
 'gcc-libs': (), 'libgcc': (),
 'git': ('usr/bin/git','usr/bin/git-upload-pack','usr/lib/git-core/git-upload-pack'),
 'glibc': ('usr/lib/ld-linux-aarch64.so.1',),
 'nano': ('usr/bin/nano',),
 'python': ('usr/bin/python3','usr/bin/python3.14'),
}


def require(ok,why):
    if not ok:
        raise ValueError(why)


def ref(raw):
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest())


def body(path,expected,cap=2**20):
    require(path.resolve(strict=True)==path and path.is_file() and path.stat().st_size<=cap,'bounded ordinary selected input')
    raw=path.read_bytes()
    require(ref(raw)['sha256']==expected,'exact selected bytes '+path.name)
    return raw


def checked_archive(path,pin):
    require(path.resolve(strict=True)==path and path.stat().st_size==pin['bytes'],'exact signed archive size')
    with path.open('rb') as stream:
        require(file_digest(stream,'sha256').hexdigest()==pin['sha256'],'exact archived compiler member provenance')


def invoke(repo,*words,stamp=False):
    env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC',HOME='/nonexistent',GIT_CONFIG_NOSYSTEM='1',
             GIT_CONFIG_GLOBAL='/dev/null',GIT_OPTIONAL_LOCKS='0',GIT_ALLOW_PROTOCOL='file')
    if stamp:
        env.update(GIT_AUTHOR_NAME='Onboarding Fixture',GIT_AUTHOR_EMAIL='onboarding@example.invalid',
                   GIT_COMMITTER_NAME='Onboarding Fixture',GIT_COMMITTER_EMAIL='onboarding@example.invalid',
                   GIT_AUTHOR_DATE='2026-11-18T00:00:00Z',GIT_COMMITTER_DATE='2026-11-18T00:00:00Z')
    argv=['/usr/bin/git','--no-replace-objects','-C',str(repo),'-c','core.hooksPath=/dev/null','-c','gc.auto=0',*words]
    return subprocess.run(argv,env=env,check=True,stdin=subprocess.DEVNULL,capture_output=True,timeout=35).stdout


def fixture(path):
    return bundle_fixture(path,lambda name:invoke(ROOT,'show',EXAMPLE_SOURCE+':'+name))


def bundle_fixture(path,read_source):
    wanted=(EXAMPLE+'hello.c',EXAMPLE+'onboarding.py',EXAMPLE+'README.md','LICENSE')
    paths={name:read_source(name) for name in wanted}
    require(ref(paths[EXAMPLE+'hello.c'])['sha256']=='fc4d365017395544876cf526639d8dfa1b4f6784d7f92887ee35c40146f749b5' and
            ref(paths[EXAMPLE+'onboarding.py'])['sha256']=='7a46c6df2546120f7aa0e6ce77b75b86a3d12ca851f898a3cf085a781952fa9f',
            'exact #583/#587 maintained input bytes')
    with tempfile.TemporaryDirectory(prefix='onboarding-git-') as temporary:
        root=Path(temporary)
        invoke(root,'init','-q','-b','onboarding','--object-format=sha1')
        for name,raw in paths.items():
            p=root/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(raw)
        invoke(root,'add','--',*wanted)
        invoke(root,'commit','-qm','Exact onboarding example fixture',stamp=True)
        sha=invoke(root,'rev-parse','HEAD').decode().strip()
        invoke(root,'bundle','create',str(path),'refs/heads/onboarding')
    program=paths[EXAMPLE+'onboarding.py']
    example=paths[EXAMPLE+'hello.c']
    edited=example.replace(b'Hello from cachy-asahi',b'Hello from my installed terminal')
    raw=path.read_bytes()
    return dict(fixture_commit=sha,upstream_commit=EXAMPLE_SOURCE,example_sha256=ref(example)['sha256'],
                edit_sha256=ref(edited)['sha256'],program=b64encode(program).decode('ascii'),
                program_sha256=ref(program)['sha256'],bundle=b64encode(raw).decode('ascii'),bundle_sha256=ref(raw)['sha256'])


def selected_tools(staging,packet):
    versions, leaves, operand_pins={},{},{}
    for name,roles in TOOLS.items():
        versions[name]=version=packet['packages'][name]['version']
        relative=f'base-repository/repo/{name}-{version}-aarch64.pkg.tar.xz'
        archive=staging/relative
        for operand in (relative,relative+'.sig'):
            expected=packet['files'][operand]
            checked_archive(staging/operand,expected)
            operand_pins[operand]=expected
        if not roles:
            continue
        with tarfile.open(archive) as tar:
            members={entry.name:entry for entry in tar.getmembers()}
            for role in roles:
                entry=members[role]
                if entry.issym():
                    leaves[role]=dict(link=entry.linkname)
                    continue
                kept=entry if entry.isfile() else members[entry.linkname]
                require(kept.isfile() and kept.size<=128*2**20 and kept.mode & 0o111,'exact executable tool archive member')
                with tar.extractfile(kept) as stream:
                    leaves[role]=dict(bytes=kept.size,sha256=file_digest(stream,'sha256').hexdigest(),mode=kept.mode)
    return versions,leaves,operand_pins


def once(text,old,new):
    require(text.count(old)==1,'one exact reviewed overlay seam')
    return text.replace(old,new,1)


def project_worker(original, selected, probe):
    prefix='''

# Dedicated installed-onboarding witness. Base plan, tool trust and controller stay exact.
def _onboarding_selected(plan):
    need(plan.get('kind') == 'OVERLAY583_OWNED_GUEST_PLAN_V1' and not plan.get('lifecycle')
         and not plan.get('signature_recovery'), 'dedicated unchanged Overlay583 base plan required')

'''
    source=original.decode()
    source=once(source,'if __name__ == "__main__":',prefix+f'_ONBOARDING = {selected!r}\n'+
        f'import types as _onboarding_types\n_onboarding = _onboarding_types.ModuleType("owned_installed_onboarding")\n'
        f'exec(compile({probe!r}, "guest-onboarding.py", "exec"), vars(_onboarding))\n\nif __name__ == "__main__":')
    source=once(source,'    snapshots = {"installed.lock", "result.json", "pacman.log"}',
                '    _onboarding_selected(plan)\n    snapshots = {"installed.lock", "result.json", "pacman.log", "installed-onboarding.json"}')
    source=once(source,'        phase = "seal"\n        unchanged(observed)',
                '        _onboarding_selected(plan)\n        onboarding = _onboarding.exercise(sys.modules[__name__],plan,lock,env,deadline,_ONBOARDING)\n'
                '        (OUTPUT/"installed-onboarding.json").write_bytes(encoded(onboarding))\n        phase = "seal"\n        unchanged(observed)')
    source=once(source,'    return dict(status="MATCHED_DISPOSABLE_OVERLAY583_TRANSACTION_EVIDENCE",\n',
                '    _onboarding_selected(plan)\n    onboarding = decode(read(output/"installed-onboarding.json",files["installed-onboarding.json"],cap=2<<20))\n'
                '    _onboarding.validate(onboarding,_ONBOARDING,target,plan["nonce"])\n'
                '    summary = {k:onboarding.get(k) for k in ("status","failure","fixture_commit","upstream_commit",\n'
                '              "verified","final_lock","workspace_removed","origin_namespace_absent")}\n'
                '    return dict(status="MATCHED_DISPOSABLE_OVERLAY583_TRANSACTION_EVIDENCE", onboarding=summary,\n')
    raw=source.encode()
    require(len(raw)<=128*1024,'held worker size cap')
    compile(raw,'projected-overlay-worker.py','exec')
    return raw


def project_shell(raw, handoff):
    source=raw.decode()
    for old,new in ((BASE_SHA,handoff),('cachy-overlay583-first-login-r2.scope',SCOPE),
                    ('caa-overlay583-first-login-r2-',PREFIX),('Overlay583 FirstLogin attempt','Overlay583 onboarding attempt'),
                    ('supplement=65dfcb0264024da05b39df03f5f505367a8be257f61bbb332575ee14261c3334\n',''),
                    ('  --mount "type=bind,source=$run_data/first-login,target=/inputs/first-login,readonly"\n',''),
                    ('   --first-login /inputs/first-login --first-login-sha256 "$supplement"','')):
        source=once(source,old,new)
    require(source.count('overlay583-first-login')==2,'exact retained output path seams')
    return source.replace('overlay583-first-login','overlay583-development-onboarding').encode()


def runtime_entry(path, runner, runtime_wrapper):
    source=body(runtime_wrapper,RUNTIME_WRAPPER_SHA).decode()
    replacements=(
        ('First Login R5 guest','installed onboarding guest'),
        ('Exact First Login operand changed','Exact onboarding operand changed'),
        ('cachy-overlay583-native-first-login-v3-r5.scope',SCOPE),
        ('ENTRY = CACHE / "first-login-r5-overlay583-actor-DATA.vov1kYtd/root-entry.sh"','ENTRY = HERE / "root-entry.sh"'),
        ('713eecc881e68a99d012426d1443460b34120af040730730405b6496d1ace1f9',runner),
        ('DATA = CACHE / "first-login-r5-overlay583-DATA.mQVMCq2e/signed-rehearsal"\nREVIEW = GUARD.parent / "once/signature-review.DATA.json"',
         'DATA = HERE'),
        ('    cli.add_argument("--signature-review-sha256")\n',''),
        ('a.handoff_sha256, a.signature_review_sha256','a.handoff_sha256'),
        ('    checked(REVIEW, a.signature_review_sha256)\n',''),
        ('Require whole Runtime44 profile, guest handoff and original signature review pins','Require whole Runtime44 and guest handoff pins'),
        ('PASS_HELD_R5_RUNTIME44_CODE_ONLY','PASS_INSTALLED_ONBOARDING_RUNTIME44_CODE_ONLY'),
    )
    for old,new in replacements:
        if 'a.handoff_sha256, a.signature_review_sha256'==old:
            require(source.count(old)==3,'exact removed unrelated review argv')
            source=source.replace(old,new)
        else:
            source=once(source,old,new)
    path.write_bytes(source.encode())


def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(output, held, runtime_wrapper):
    require(output.is_absolute() and output.resolve()==output and not output.exists() and output.parent.stat().st_uid==os.getuid(),
            'fresh private onboarding capsule')
    old=json.loads(body(held/'HANDOFF.DATA.json',BASE_SHA))
    original=json.loads(body(held/'plan-template.DATA.json',old['plan_template']['sha256']))
    packet=original['packet']
    require(old['source_revision']==BASE_SOURCE and packet['target']['sha256']=='12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba',
            'exact unchanged installed Overlay583 selection')
    versions,tools,operands=selected_tools(Path(old['staging']),packet)
    output.mkdir(mode=0o700)
    selected=fixture(output/'onboarding.bundle')
    selected.update(tool_versions=versions,tools=tools,owned_process=invoke(ROOT,'show',BASE_SOURCE+':'+OWNER).decode())
    work={name:body(held/'source'/name,pin['sha256']) for name,pin in old['source'].items()
          if name.startswith(('scripts/install/overlay583_trial/','scripts/integration/arm16k_perl5423_vm/'))}
    require(len(work)==9 and ref(work[TRIAL])==old['source'][TRIAL] and ref(selected['owned_process'].encode())==old['source'][OWNER],
            'entire exact held base runtime and compiler child supervisor')
    work[TRIAL]=project_worker(work[TRIAL],selected,(HERE/'guest.py').read_text())
    for name,raw in work.items():
        path=output/'source'/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
    trial=module(output/'source'/TRIAL,'read_only_onboarding_trial')
    plan=trial.guest_plan(packet,original['nonce'])
    require(plan['kind']==BASE_ROLE and plan=={**{k:v for k,v in original.items() if k!='first_login'},'kind':BASE_ROLE},
            'base plan byte-match without unrelated addon')
    raw=trial.encoded(plan)
    (output/'plan-template.DATA.json').write_bytes(raw)
    result=dict(kind='OVERLAY583_DEVELOPMENT_ONBOARDING_ROOT_OPERANDS_ONLY_V1',root_scope=SCOPE,
        source={name:ref(raw) for name,raw in work.items()},base_source=BASE_SOURCE,staging=old['staging'],
        docker=old['docker'],actor_image=old['actor_image'],references=old['references'],tools=old['tools'],
        preflight=old['preflight'],plan_template=dict(nonce=plan['nonce'],**ref(raw)),
        selection={k:v for k,v in selected.items() if k not in ('bundle','program','owned_process')},
        archive_operands=operands,local_compilation='NOT RUN',Root_authority=None,native_M2=None)
    raw=trial.encoded(result)
    (output/'HANDOFF.DATA.json').write_bytes(raw)
    runner=project_shell(body(held/'root-entry.sh',ROOT_ENTRY),ref(raw)['sha256'])
    (output/'root-entry.sh').write_bytes(runner)
    runtime_entry(output/'enter.py',ref(runner)['sha256'],runtime_wrapper)
    close=body(held/'readback.py','2bc376d321305e91448e04af9d7eecd9f2b3366796ffc5271c973e7df376e342')
    (output/'held-readback.py').write_bytes(close)
    (output/'readback.py').write_bytes((HERE/'readback.py').read_bytes())
    return dict(status='EXACT_UNSIGNED_ONBOARDING_CAPSULE_DATA_ONLY',handoff=ref(raw),source_files=len(work),
                fixture_commit=selected['fixture_commit'],tools=versions,archive_operands=len(operands),output=str(output))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--held',type=Path,required=True,help='exact accepted base controller capsule')
    parser.add_argument('--runtime-wrapper',type=Path,required=True,help='exact held Runtime44 wrapper')
    args=parser.parse_args()
    print(json.dumps(prepare(args.output,args.held,args.runtime_wrapper),sort_keys=True,indent=2))
