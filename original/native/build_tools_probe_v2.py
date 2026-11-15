# SPDX-License-Identifier: MIT
"""Six installed offline commands with nine caller-owned observations; no actors on import."""
import hashlib
import json
import os
from pathlib import Path
import stat

NAME='cachy-asahi-build-tools'
VERSION='0.2.0-1'
STEPS=('cache-init','import-local','cache-verify','recipe-check','preflight-baseline','preflight-lto','consistency-match','consistency-mismatch','consistency-unsupported')
MATCH_RECIPE=b"pkgname=sample\npkgver=1\npkgrel=1\narch=('any')\npackage() {\n    touch SHOULD_NOT_RUN\n}\n"
UNSUPPORTED_RECIPE=MATCH_RECIPE.replace(b'pkgver=1',b'pkgver="$(touch SHOULD_NOT_RUN)"')
MATCH_INFO=b'pkgbase = sample\npkgver = 1\npkgrel = 1\narch = any\npkgname = sample\n'
MISMATCH_INFO=MATCH_INFO.replace(b'pkgver = 1',b'pkgver = 0')

def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def data_pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=4*1024**2):
    p=Path(path);need(p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary fixed probe operand')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded regular probe operand')
        with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(cap+1)
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(p.lstat()),'stable whole probe operand');return raw
    finally:os.close(fd)

def requests(cli,fixtures,work,policy):
    """Pure DATA argv grammar shared with the separately trusted matching reader."""
    f,w=Path(fixtures),Path(work);catalog=f/'inputs/source-inputs.json';cache=w/'cache';pins=policy['fixture_files']
    common=['--cache',str(cache),'--inputs',str(catalog),'--inputs-sha256',pins['inputs/source-inputs.json']['sha256'],'--id','zlib-1.3.2']
    rows=[('cache-init',['cache-init','--cache',str(cache)],0),('import-local',['import-local',*common,'--local-archive',str(f/'zlib-1.3.2.tar.gz')],0),('cache-verify',['cache-verify',*common],0),('recipe-check',['recipe-check',str(f/'recipes/baseline/PKGBUILD')],0)]
    for variant in('baseline','lto'):
        rows.append(('preflight-'+variant,['source-preflight','--recipe',str(f/'recipes'/variant),'--source-plan',str(f/(variant+'-source-plan.json')),'--source-plan-sha256',pins[variant+'-source-plan.json']['sha256'],'--source-catalog',str(catalog),'--source-cache',str(cache)],0))
    for case,code in(('match',0),('mismatch',1),('unsupported',2)):
        rows.append(('consistency-'+case,['recipe-consistency',str(w/(case+'.PKGBUILD')),'--srcinfo',str(w/(case+'.SRCINFO'))],code))
    need(tuple(r[0]for r in rows)==STEPS,'exact nine-observation grammar');return rows

def validate_result(key,value,policy,work):
    need(type(value)is dict,'actual CLI JSON object required')
    pins=policy['fixture_files'];material=pins['zlib-1.3.2.tar.gz']
    if key=='cache-init':need(value.get('status')=='initialized'and value.get('cache')==str(Path(work)/'cache'),'actual private cache init')
    elif key=='import-local':need(value.get('status')=='IMPORTED_VERIFIED_LOCAL_SOURCE'and value.get('source_kind')=='local_archive'and value.get('network_fetches')==0,'actual local import without network')
    elif key=='cache-verify':
        rows=value.get('sources');need(type(rows)is list and len(rows)==1 and rows[0].get('status')=='verified'and rows[0].get('id')=='zlib-1.3.2'and all(rows[0].get(k)==material[k]for k in('bytes','sha256')),'exact retained real-source cache verification')
    elif key=='recipe-check':
        rows=value.get('recipes');need(type(rows)is list and len(rows)==1 and rows[0].get('errors')==[]and rows[0].get('input_sha256',{}).get('PKGBUILD')==pins['recipes/baseline/PKGBUILD']['sha256'],'same pinned baseline literal recipe check')
    elif key.startswith('preflight-'):
        variant=key[len('preflight-'):];need(value.get('status')=='VERIFIED_OFFLINE_SOURCE_BINDING_ONLY'and value.get('plan_sha256')==pins[variant+'-source-plan.json']['sha256']and value.get('catalog_sha256')==pins['inputs/source-inputs.json']['sha256']and value.get('network_fetches')==0 and value.get('cache_writes')is value.get('extraction')is value.get('source_execution')is value.get('builder_started')is False and value.get('legal_acceptance')is value.get('source_completeness_accepted')is False,'exact offline preflight without builder or legal acceptance')
    else:
        case=key[len('consistency-'):];need(case in('match','mismatch','unsupported')and value.get('status')=={'match':'MATCH_MODELED_LITERAL_DECLARATIONS','mismatch':'MISMATCH','unsupported':'UNSUPPORTED'}[case]and value.get('shell_evaluation')is False,'metadata statuses remain distinct')
        recipe=UNSUPPORTED_RECIPE if case=='unsupported'else MATCH_RECIPE;info=MISMATCH_INFO if case=='mismatch'else MATCH_INFO
        need(value.get('inputs')==dict(PKGBUILD=data_pin(recipe),SRCINFO=data_pin(info)),'exact inert literal metadata operands')
        if case=='mismatch':need(value.get('mismatches')==[dict(field='pkgver',PKGBUILD=['1'],SRCINFO=['0'])],'actual stale version diagnosis')
        if case=='unsupported':need(value.get('unsupported')and not value.get('mismatches'),'unsupported must not become agreement')
    return value

def validate_cli(cli,policy):
    cli=Path(cli);need(cli.name==NAME and cli.parent.name=='bin'and cli.parent.parent.name=='usr','fixed installed or whole moved prefix')
    prefix=cli.parents[2];expected=policy['recipe']['payload_files']
    for name,row in expected.items():
        path=prefix/name;need(data_pin(read(path,1024**2))=={k:row[k]for k in('bytes','sha256')}and stat.S_IMODE(path.stat().st_mode)==row['mode'],'every exact12 installed/moved payload byte/mode')
    need(len(expected)==12,'exact12 package payload');return dict(files=12,payload=expected)

def validate_fixtures(fixtures,policy):
    fixtures=Path(fixtures);expected=policy['fixture_files'];actual={p.relative_to(fixtures).as_posix()for p in fixtures.rglob('*')if p.is_file()}
    need(actual==set(expected)|{'files.json'},'complete14-file retained fixture namespace')
    for name,row in expected.items():need(data_pin(read(fixtures/name))==row,'exact retained inert fixture source')
    need(json.loads(read(fixtures/'files.json'))==expected,'fixture manifest full pin map');return dict(files=14,archive={k:policy['trusted_fixture'][k]for k in('bytes','sha256')})

def probe(cli,fixtures,work,command,policy):
    cli,fixtures,work=map(Path,(cli,fixtures,work));installed=validate_cli(cli,policy);fixture=validate_fixtures(fixtures,policy)
    need(work.is_dir()and not any(work.iterdir())and stat.S_IMODE(work.stat().st_mode)==0o700,'fresh empty private alarm work')
    for case in('match','mismatch','unsupported'):
        for suffix,body in(('PKGBUILD',UNSUPPORTED_RECIPE if case=='unsupported'else MATCH_RECIPE),('SRCINFO',MISMATCH_INFO if case=='mismatch'else MATCH_INFO)):
            target=work/(case+'.'+suffix);target.write_bytes(body);target.chmod(0o644)
    records=[]
    for key,arguments,expected in requests(cli,fixtures,work,policy):
        argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(work),'PATH=/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1',str(cli),*arguments]
        raw=command(key,argv,expected,cwd=work);need(type(raw)is bytes and len(raw)<=1024**2,'actual supervised bounded CLI bytes')
        value=json.loads(raw);validate_result(key,value,policy,work);records.append(dict(step=key,argv=argv,expected=expected,stdout=data_pin(raw)))
    need(not(work/'SHOULD_NOT_RUN').exists()and not list(work.rglob('__pycache__')),'no recipe execution or generated code cache')
    need(validate_cli(cli,policy)==installed and validate_fixtures(fixtures,policy)==fixture,'installed bytes and inert fixtures remain held')
    return dict(status='PASS_BUILD_TOOLS_FINITE_INSTALLED_PROBE',version=VERSION,scope='system'if cli==Path('/usr/bin/'+NAME)else'moved',cli=str(cli),installed=installed,fixture=fixture,controls=9,commands_covered=6,commands=records,reports={r['step']:r['stdout']for r in records},steps={k:k for k in STEPS},source_execution='FORBIDDEN',namespace_acceptance='NOT_ESTABLISHED',native_build='NOT_ESTABLISHED_BY_PROBE',alpm_installation='NOT_ESTABLISHED_BY_PROBE',hardware='NOT_RUN',release='NOT_ADMITTED')
