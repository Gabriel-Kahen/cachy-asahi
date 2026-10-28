# SPDX-License-Identifier: MIT
"""One additional owned consumer, same image/signing policy, original consumer untouched."""
import json
from pathlib import Path
import re
import shutil
import sys
import types
import policy as P

CONTEXT=None
STAGED=None


def replace(raw,before,after):
    P.need(raw.count(before)==1,'exact original host anchor differs: '+before[:80]);return raw.replace(before,after)


def packet_snapshot(root):
    rows={};total=0
    for path in sorted(root.rglob('*')):
        info=path.lstat();P.need(not path.is_symlink() and (path.is_file() or path.is_dir()),'ordinary borrowed packet required')
        if path.is_file():
            total+=info.st_size;P.need(len(rows)<150 and info.st_size<=2*1024**2 and total<=2*1024**2,'bounded borrowed Setup5 packet')
            rows[str(path.relative_to(root))]=dict(bytes=info.st_size,sha256=P.sha(path),mode=info.st_mode,
                uid=info.st_uid,gid=info.st_gid,mtime_ns=info.st_mtime_ns)
    return rows


def original_namespace(code):
    base=code/'scripts/ci/expanded-development-composition';sys.path.insert(0,str(base))
    for name in ('contract','inputs','bang','owned'):sys.modules.pop(name,None)
    raw=(base/'run.py').read_text()
    raw=replace(raw,"        signer=api.sign(addons,out,sign);plan['test_signer']=signer",
        "        setup5_host.stage_pair(args,addons,out,sign)\n        signer=api.sign(addons,out,sign);plan['test_signer']=signer")
    raw=replace(raw,"        verifier.close();verifier=None\n        planroot=", "        setup5_host.verify_signature(verifier,addons,signer)\n        verifier.close();verifier=None\n        planroot=")
    raw=replace(raw,"        resultdir=out/'container';resultdir.mkdir()",
        "        setup5_ref=setup5_host.consume(args,owned,execute,ready,addons,planroot,image,out,plan,after_payload)\n        report['setup5_integration']=setup5_ref\n        report['integration_source']=setup5_host.CONTEXT['source']\n        resultdir=out/'container';resultdir.mkdir()")
    raw=replace(raw,"C.need(len(owned.rows)==3,'two builders and one installed consumer required')",
        "C.need(len(owned.rows)==4,'two builders, one separate Setup5 consumer and one unchanged original consumer required')")
    raw=replace(raw,"    total=0;refs={}\n", "    names += ['setup5/'+n for n in setup5_host.P.PUBLIC]+['setup5-lifecycle.log']\n    total=0;refs={}\n")
    namespace=dict(__name__='held_expanded600_with_separate_setup5',__file__=str(base/'run.py'),setup5_host=sys.modules[__name__])
    exec(compile(raw,str(base/'run.py'),'exec'),namespace);return namespace,raw


def stage_pair(args,addons,out,sign):
    global STAGED
    roots=CONTEXT;native=P.load('setup5_expanded_native_contract',roots['probe']/'scripts/ci/setup5-native-real-modules/contract.py')
    native.verify_source(roots['probe'])
    H=P.load('setup5_expanded_pair_gate',roots['probe']/'scripts/ci/setup5-real-modules/run.py')
    check=out/'setup5-pair-check';check.mkdir(mode=0o700);H.accepted_cli(roots['setup5'],check)
    sys.path.insert(0,str(args.code/'scripts/ci/expanded-development-composition'))
    import inputs
    checks,bind=inputs.tools(args.code)
    recipe=P.load('setup5_expanded_recipe',roots['probe']/'scripts/ci/setup5-native/contract.py')
    pair=[roots['setup5']/'packages'/('cachy-asahi-setup-'+side)/'cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz' for side in ('a','b')]
    inspected=[checks.package(p) for p in pair]
    payload=[recipe.payload(r,roots['probe']) for r in inspected]
    source=recipe.recipe(roots['probe'])
    P.need(payload[0]==payload[1] and inspected[0]['metadata']==inspected[1]['metadata'] and
        all(P.sha(p)==P.ARCHIVE for p in pair) and
        not bind.bind_artifact(source['metadata'],inspected[0],source['input_sha256']['PKGBUILD']),
        'original accepted Setup5 pair/BUILDINFO/source binding differs')
    P.need(not any(inspected[0]['metadata']['.PKGINFO'].get(k) for k in ('install','conflict','replaces','backup')) and
        all(not n.endswith('.hook') for n in payload[0]),'Setup5 scriptlet/hook/replacement refused')
    dest=addons/pair[0].name;P.need(not dest.exists(),'fresh separate Setup5 archive required');shutil.copyfile(pair[0],dest)
    sign.append(dest)  # Existing original TEST key only; original fourteen selection rows stay unchanged.
    public=out/'setup5';public.mkdir(mode=0o700)
    for side,path in zip(('a','b'),pair):shutil.copyfile(path,public/('setup5-pair-'+side+'.pkg.tar.xz'))
    shutil.copyfile(roots['setup5']/'index.json',public/'accepted-setup5-index.json')
    STAGED=dict(name=P.SETUP,version='0.1.0-5',archive=dest.name,sha256=P.ARCHIVE,
        size=dest.stat().st_size,payload=payload[0],metadata=inspected[0]['metadata']['.PKGINFO'])


def verify_signature(verifier,addons,signer):
    P.need(STAGED is not None and re.fullmatch('[0-9A-F]{40}',signer),'original TEST signer required')
    path=addons/STAGED['archive'];signature=addons/(path.name+'.sig')
    verifier(path,signature,signer)
    STAGED.update(signer=signer,signature=P.ref(signature))


def consume(args,owned,execute,ready,addons,planroot,image,out,plan,after_payload):
    P.expected(plan['after'],'0.1.0-3')
    P.need(STAGED is not None and STAGED['signer']==plan['test_signer'] and after_payload['packages']==plan['after'],
        'separate Setup5/signature/full600 plan join required')
    private=dict(schema_version=1,product=STAGED,baseline600_sha256=P.AFTER,source=CONTEXT['source'],
        probe_source=P.PROBE,pair_source=P.PAIR,baseline_source=args.code_revision,original_consumer_modified=False)
    (planroot/'setup5-integration.json').write_bytes(P.encoded(private))
    (planroot/'full600-payload.json').write_bytes(P.encoded(after_payload))
    result=out/'setup5';shutil.copyfile(planroot/'setup5-integration.json',result/'integration-plan.json')
    shutil.copyfile(addons/(STAGED['archive']+'.sig'),result/'setup5-signature.sig')
    name='cachy-asahi-setup5-expanded600-'+__import__('os').urandom(16).hex()
    argv=['docker','run','--name',name,'--pull=never','--platform=linux/arm64','--network=none','--cap-drop=ALL',
        '--security-opt=no-new-privileges','--pids-limit=512','--memory=8g','--cpus=4','--user=0:0',
        '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=2g','--env=CACHY_ASAHI_EXPANDED600='+owned.token]
    argv+=['--cap-add='+c for c in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID')]
    for source,dest,readonly in ((ready,'/original',True),(addons,'/addons',True),(planroot,'/plan',True),
        (args.code,'/code',True),(CONTEXT['probe'],'/real-source',True),(P.HERE,'/integration',True),(result,'/out',False)):
        argv+=['--mount','type=bind,src='+str(source)+',dst='+dest+(',readonly' if readonly else '')]
    execute(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/integration/lifecycle.py'],out/'setup5-lifecycle.log',1800)
    native=P.load('setup5_expanded_result_contract',CONTEXT['probe']/'scripts/ci/setup5-native-real-modules/contract.py')
    value=P.read(result/'lifecycle.json');P.validate(value,native)
    P.need(P.read(result/'real-modules.json',128*1024)==value['real_modules'],'raw real-RC receipt differs from lifecycle')
    for row in value['ldconfig']:
        P.need(P.sha(result/('ld-'+row['phase']+'.json'))==row['state_sha256'] and
            P.sha(result/('aux-'+row['phase']+'.bin'))==row['aux_sha256'],'raw setup-stage ldconfig/aux receipt differs')
    meta=P.load('setup5_expanded_rollback_metadata',P.HERE/'lifecycle.py')
    dates=value['setup3_database_install_date']['interval']
    meta.restored_desc((result/'setup3-before.desc').read_bytes(),(result/'setup3-after.desc').read_bytes(),*dates)
    P.need(all(P.sha(result/('setup5-pair-'+side+'.pkg.tar.xz'))==P.ARCHIVE for side in ('a','b')),
        'retained original Setup5 pair differs')
    return dict(status=value['status'],container=name,receipt=P.ref(result/'lifecycle.json','setup5/lifecycle.json'),
        real_receipt=P.ref(result/'real-modules.json','setup5/real-modules.json'),
        original_consumer_modified=False,hardware='NOT_RUN',release='NOT_ADMITTED')
