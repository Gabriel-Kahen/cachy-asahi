# SPDX-License-Identifier: MIT
"""Closed signed606 cache and offline image context; no mirror or package waiver."""
import hashlib,importlib.util,json,re,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent
M=1024**2

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path,cap=256*M):
    need(not any(p.is_symlink()for p in(path,*path.parents))and path.is_file()and path.stat().st_nlink==1 and path.stat().st_size<=cap,'ordinary bounded singlelink cache input');return path.read_bytes()
def obj(path):return json.loads(read(path,2*M))
def checked(root,name,size,sha):
    need(type(name)is str and name and Path(name).as_posix()==name and not Path(name).is_absolute()and not{'.','..'}&set(name.split('/')),'contained cache member');p=root/name;need(pin(read(p))==dict(bytes=size,sha256=sha),'whole signed cache member '+name);return p

def verify(root,source,profile):
    manifest=obj(root/'manifest.json');lock=read(root/'expected-installed.lock',65536);expected=dict(line.split()for line in lock.decode().splitlines());need(pin(lock)==profile['expected606']and len(expected)==606,'complete exact606 lock')
    rows=manifest['packages'];need(manifest['status']=='READY_SIGNED_CURRENT606_WELCOME8'and len(rows)==len({r['name']for r in rows})==606 and {r['name']:r['version']for r in rows}==expected,'complete fixed606 manifest')
    base=obj(source/'scripts/ci/maintained-desktop574-inputs.json');need(len(base['packages'])==574 and {r['name']for r in base['packages']} - set(expected)=={'libfdk-aac'} and all(expected.get(r['name'])==r['version']for r in base['packages']if r['name']!='libfdk-aac') and expected['cachy-asahi-fdk-aac']=='3.0.0-1','exact573 held and sole native FDK replacement')
    roles=manifest['preparation']['signer_roles'];need(set(roles)=={'upstream_ALARM','ephemeral_TEST'}and len(set(roles.values()))==2 and all(re.fullmatch('[A-F0-9]{40}',v)for v in roles.values()),'two distinct exact signer roles')
    need(len(manifest['keyrings'])==2 and{r['path']for r in manifest['keyrings']}=={'keys/TEST-public.asc','keys/archlinuxarm.gpg'},'original exact two public keys')
    allowed={'manifest.json','expected-installed.lock','builder-packages.lock'};total=0
    for r in rows:
        total+=r['size'];need(total<=4*1024**3 and r['signature']==r['archive']+'.sig'and r['signer']in roles.values(),'bounded original signed archive shape')
        archive=checked(root,r['archive'],r['size'],r['sha256']);checked(root,r['signature'],r['signature_size'],r['signature_sha256']);allowed.update((r['archive'],r['signature']))
        if r['name']in profile['native_archives']:need(pin(read(archive))==profile['native_archives'][r['name']],'exact accepted selected product archive bytes')
    for r in manifest['keyrings']:checked(root,r['path'],r['size'],r['sha256']);allowed.add(r['path'])
    origins=manifest['original_input_pins'];need(set(origins)=={'original604-manifest.json','original-tools606-products.json','original-latest-input-plan.json'},'whole three original signed input contexts')
    for name,w in origins.items():need(pin(read(root/name,16*M if name=='original-latest-input-plan.json'else 2*M))==w,'whole original input context '+name);allowed.add(name)
    builder=read(root/'builder-packages.lock',65536);need(hashlib.sha256(builder).hexdigest()=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'and len(builder.splitlines())==574,'exact original574 builder lock')
    need({p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()}==allowed,'closed exact signed606 cache')
    return manifest

def stage(ready,source,out,manifest,profile):
    base={r['name']for r in obj(source/'scripts/ci/maintained-desktop574-inputs.json')['packages']};incoming=[r for r in manifest['packages']if r['name']not in base];need(len(incoming)==33 and {r['name']for r in incoming}==set(dict(line.split()for line in read(HERE/'expected606.lock').decode().splitlines()))-base,'exact33 incoming, sole FDK replacement, net32 additions')
    provenance=out/'input-provenance';provenance.mkdir()
    for name in manifest['original_input_pins']:shutil.copyfile(ready/name,provenance/name)
    context=out/'install-context606';(context/'bundle/packages').mkdir(parents=True);(context/'bundle/keys').mkdir();checks_path=source/'scripts/checks/package_checks.py';s=importlib.util.spec_from_file_location('_gui606_package_checks',checks_path);checks=importlib.util.module_from_spec(s);s.loader.exec_module(checks)
    for n in('manifest.json','expected-installed.lock','builder-packages.lock'):shutil.copyfile(ready/n,context/'bundle'/n)
    for r in manifest['keyrings']:shutil.copyfile(ready/r['path'],context/'bundle'/r['path'])
    payload=[]
    for r in incoming:
        for field in('archive','signature'):shutil.copyfile(ready/r[field],context/'bundle'/r[field])
        report=checks.package(ready/r['archive']);need(report['sha256']==r['sha256']and report['metadata']['.PKGINFO']['pkgname']==[r['name']]and report['metadata']['.PKGINFO']['pkgver']==[r['version']]and report['metadata']['.PKGINFO']['arch'][0]in('any','aarch64'),'whole actual incoming package identity/architecture')
        need(r['name']not in profile['native_archives']or not report['errors'],'selected actual project archive policy')
        payload.append(dict(name=r['name'],version=r['version'],metadata=report['metadata']['.PKGINFO'],project_policy_diagnostics=report['errors'],payload={n:v for n,v in report['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}))
    (context/'incoming.json').write_bytes(enc(payload));shutil.copyfile(HERE/'install606.py',context/'install606.py');shutil.copyfile(HERE/'build_scope.py',context/'build_scope.py')
    for n in('contract604.py','lifecycle604.py','alpm_reader.py'):shutil.copyfile(HERE/'support'/n,context/n)
    products=obj(out/'candidates/products.json');byname={r['name']:r for r in incoming}
    for name,row in products.items():
        actual=byname[name];archive=ready/actual['archive'];report=checks.package(archive);row.update(version=actual['version'],archive=archive.name,sha256=actual['sha256'],payload={n:v for n,v in report['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')})
        shutil.copyfile(archive,out/'candidates'/archive.name);shutil.copyfile(ready/actual['signature'],out/'candidates'/(archive.name+'.sig'))
    (out/'candidates/products.json').write_bytes(enc(products));shutil.copyfile(ready/'keys/TEST-public.asc',out/'candidates/TEST-public.asc');control=obj(out/'candidates/control.json');control['signer']=manifest['preparation']['signer_roles']['ephemeral_TEST'];(out/'candidates/control.json').write_bytes(enc(control))
    lock=obj(out/'candidate-lock.json');lock['products']=products
    for n,r in products.items():lock['policy']['products'][n]=dict(version=r['version'],sha256=r['sha256'])
    lock['producer_lifecycle']='FRESH_ORIGINAL574_WITH_SIGNED606_INPUTS_GUI_NOT_RUN';(out/'candidate-lock.json').write_bytes(enc(lock));(out/'candidates/candidate-lock.json').write_bytes(enc(lock))
    desktop=byname['cachy-asahi-hyprland-settings'];shutil.copyfile(ready/desktop['archive'],out/Path(desktop['archive']).name)
    table={p.relative_to(context).as_posix():pin(read(p))for p in sorted(context.rglob('*'))if p.is_file()};receipt=dict(files=table,expected=profile['expected606'],desktop=Path(desktop['archive']).name,desktop_pin=pin(read(ready/desktop['archive'])))
    (out/'context606.json').write_bytes(enc(receipt))

def authorize_runner(runner):
    proof=obj(runner/'current606-proof.json')
    need(proof['status']=='EMITTED_CURRENT606_WELCOME8_GUI_SOURCE_ONLY'and proof['packages']==606 and proof['optional_absent']==604 and proof['actual_run']is None,'ready source-owned606 context required before actors')
    actual={p.relative_to(runner).as_posix():pin(read(p))for p in sorted(runner.rglob('*'))if p.is_file()and p.name!='current606-proof.json'}
    need(actual==proof['files'],'whole emitted606 source/input closure drift')
    need(not any(p.is_symlink()for p in runner.rglob('*')),'ordinary entire emitted606 runner')
    return proof

def build(runner,image,out,execute,text_command,bind,images,report):
    receipt=obj(runner/'context606.json');context=runner/'install-context606';need({p.relative_to(context).as_posix()for p in context.rglob('*')if p.is_file()}==set(receipt['files']),'whole offline606 install context')
    for n,r in receipt['files'].items():need(pin(read(context/n))==r,'offline context drift '+n)
    expected=dict(line.split()for line in read(runner/'expected606.lock').decode().splitlines());need(len(expected)==606 and pin(read(runner/'expected606.lock'))==receipt['expected'],'runtime exact606 selection')
    archive=runner/receipt['desktop'];need(pin(read(archive))==receipt['desktop_pin'],'whole desktop configuration archive')
    base_reference='cachy-asahi-desktop574-base:'+__import__('os').urandom(16).hex();report.update(base_image=image,base_reference=base_reference);bind(image,base_reference,execute,text_command)
    # BuildKit secret mount is separate from the source-owned immutable context.
    spec=importlib.util.spec_from_file_location('_gui_owned_build_scope',HERE/'build_scope.py');scope=importlib.util.module_from_spec(spec);spec.loader.exec_module(scope)
    build_context=out/'context';shutil.copytree(context,build_context);flags,build_proof=scope.prepare(build_context,'runtime606',image,base_reference,out/'runtime606-build-proof.json');report['image_build_proofs']={'runtime606':build_proof}
    iid=out/'runtime-image-id';execute(['docker','build','--network=none','--pull=false','--iidfile',str(iid),*flags,str(build_context)],'runtime-image',300);derived=iid.read_text().strip();need(re.fullmatch('sha256:[a-f0-9]{64}',derived)and derived!=image,'new owned606 image identity');images.append(derived);report.update(base_image=image,runtime_image=derived,runtime_package_count=606,workflow_scope='current606-welcome8-new-gui-pair-required')
    tooling=runner/'qemu-context';need(tooling.is_dir(),'separate exact590 controller context required');qctx=out/'qemu-context';shutil.copytree(tooling,qctx);flags,build_proof=scope.prepare(qctx,'controller590',image,base_reference,out/'controller590-build-proof.json');report['image_build_proofs']['controller590']=build_proof;qid=out/'qemu-image-id';execute(['docker','build','--network=none','--pull=false','--iidfile',str(qid),*flags,str(qctx)],'qemu-image',300);qemu=qid.read_text().strip();need(re.fullmatch('sha256:[a-f0-9]{64}',qemu)and qemu not in(image,derived),'owned separate controller image');images.append(qemu);report.update(controller_image=qemu,controller_packages=590,guest_packages=606)
    return derived,[archive],expected,qemu
