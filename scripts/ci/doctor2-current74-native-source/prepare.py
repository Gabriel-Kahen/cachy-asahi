#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact installed-comparison74 through unchanged current70 machinery; source only."""
import argparse,hashlib,json,os,stat,tempfile,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':260317,'sha256':'1889193d75d08a6576d2b3e5a1f3d13aba7269d2554429182cc9e5c35bf17e49'}
CARRIER='705c5a095f9cabbfd2f3cd137127f4bbc7665f52'
SLICE='scripts/ci/welcome-native/'
POLICY_STAMPS={SLICE+'doctor2-policy.json',SLICE+'source-pins.json',SLICE+'ci/source-manifest.json',
    '.github/workflows/native-arm-build.yml','.github/workflows/native-arm-welcome-doctor-products.yml'}


def need(ok,message):
    if not ok:raise ValueError(message)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name and
         Path(name).as_posix()==name and all(p not in ('','.','..') for p in name.split('/')),'contained source path required')
    return Path(name)


def ordinary(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts,'ordinary absolute source required')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=16*1024**2,'bounded ordinary single-link source required')
            raw=bytearray()
            while len(raw)<=before.st_size:
                part=os.read(fd,min(65536,before.st_size-len(raw)+1))
                if not part:break
                raw.extend(part)
            identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            need(identity(before)==identity(os.fstat(fd))==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) and len(raw)==before.st_size,'source changed while reading')
            return bytes(raw)
        finally:os.close(fd)
    finally:os.close(parent)


def files(root):
    root=Path(root)
    need(root.is_absolute() and root.is_dir() and not any(p.is_symlink() for p in (root,*root.parents)),'ordinary source root required')
    result={}
    for base,dirs,names in os.walk(root):
        if Path(base)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
        need(not any((Path(base)/n).is_symlink() for n in dirs),'source directory alias refused')
        for name in names:
            path=Path(base)/name;result[path.relative_to(root).as_posix()]=ordinary(path)
    return result


def profile():
    raw=ordinary(HERE/'source.json');need(pin(raw)==PROFILE,'exact current74 factory profile required')
    value=json.loads(raw)
    need(value['schema_version']==1 and value['carrier_source']==CARRIER and
         value['authority_predecessor_source']=='88997143a593f2de82fb41ae0224a943a1f99930',
         'exact qualified70 predecessor authority required')
    need(all(value[name] is None for name in ('actual_source','actual_ref','actual_run')),'actual selectors must remain NULL')
    return value


def fresh(output,roots):
    need(output.is_absolute() and '..' not in output.parts and not any(c in str(output) for c in ',\r\n') and output.parent.is_dir() and not output.exists() and
         not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output required')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in roots),'disjoint output required')


def validate(result,before,value,selected):
    view=value['views']['selected' if selected else 'default']
    need(len(result)==74 and {n:pin(b) for n,b in result.items()}==view['files'],'complete exact source74 required')
    need(set(before)<=set(result) and {n for n,b in result.items() if b!=before.get(n)}==set(view['changed_vs70']) and
         set(result)-set(before)==set(view['added_vs70']),'exact source74/current70 delta required')
    inverse=dict(result)
    for name in set(result)-set(before):del inverse[name]
    for name,body in before.items():
        if inverse[name]!=body:inverse[name]=body
    need(inverse==before,'whole current70 predecessor inverse differs')
    need(all(result[name]==before[name] and pin(result[name])==wanted
             for name,wanted in value['unchanged70'].items()),'held current70 actors/security/budgets differ')
    if not selected:
        approved=value['views']['selected']['files']
        need(set(result)==set(approved) and {n for n,b in result.items() if pin(b)!=approved[n]}==POLICY_STAMPS,
             'default may change only policy and its four stamps')
    recipe=value['recipe'];package={n:pin(b) for n,b in result.items() if n.startswith(recipe+'/')}
    need(len(package)==9 and package==value['current_inputs'],'exact comparison-enabled Doctor2 nine inputs required')
    helpers={n:pin(b) for n,b in result.items() if n.startswith('scripts/ci/setup6-retained-helpers/')}
    need(len(helpers)==6 and helpers==value['approved_helpers'],'six approved retained helper/license bodies required')
    policy=json.loads(result[SLICE+'doctor2-policy.json'])
    need(all(policy[n] is None for n in ('actual_source','actual_ref','actual_run')),'emitted actual selectors must remain NULL')
    if selected:
        need(policy['status']=='ROOT_SELECTED_DOCTOR2_NATIVE_PAIR' and policy['version']==value['version'] and
             policy['recipe']==recipe and policy['input_sha256']=={Path(n).name:p['sha256'] for n,p in package.items()},
             'exact selected current74 package policy required')
    else:
        need(policy['status']=='UNBOUND' and all(policy[n] is None for n in ('recipe','version','input_sha256')),
             'default current74 package selection must remain NULL')
    pins=json.loads(result[SLICE+'source-pins.json']);manifest=json.loads(result[SLICE+'ci/source-manifest.json'])
    need(len(pins)==50 and all(pin(result[n])['sha256']==wanted for n,wanted in pins.items()),'all50 source pins required')
    excluded={SLICE+'ci/source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-welcome-doctor-products.yml'}
    need(set(manifest['files'])==set(result)-excluded and len(manifest['files'])==71 and
         all(pin(result[n])==wanted for n,wanted in manifest['files'].items()),'complete manifest71/source74 correspondence required')
    workflow=result['.github/workflows/native-arm-build.yml']
    need(workflow==result['.github/workflows/native-arm-welcome-doctor-products.yml'],'identical workflow aliases required')
    need(workflow.count(pin(result[SLICE+'ci/source-manifest.json'])['sha256'].encode())==1 and
         workflow.count(pin(result[SLICE+'ci/caller.py'])['sha256'].encode())==2,'exact source/caller workflow stamps required')
    proof=workflow.index(b'caller.py" proof');credential=workflow.index(b'using existing secrets only')
    need(all(proof<workflow.index(marker)<credential for marker in
             (b'producer.py" --help',b'installed_comparison.py" --help')),'isolated help must precede credentials')


def prepare(current,native,historical_factory,comparison_factory,current70_factory,output,*,selected=False):
    need(type(selected) is bool,'explicit selected view required');value=profile()
    need(current is not None,'explicit maintained current-root required')
    captured=files(current70_factory)
    need(set(captured)=={'prepare.py','source.json','test_prepare.py','README.md'} and
         {n:pin(b) for n,b in captured.items()}==value['current70_factory'],'exact unchanged current70 factory required')
    prior=json.loads(captured['source.json'])
    need(prior['carrier_source']==CARRIER and prior['authority_source']==value['authority_predecessor_source'] and
         prior['current_inputs']==value['current_inputs'],'unchanged current70 authority/package correspondence required')
    operands={native:files(native),historical_factory:files(historical_factory),comparison_factory:files(comparison_factory)}
    recipe_root=current/relative(value['recipe']);package=files(recipe_root)
    need({p.name for p in recipe_root.iterdir()}=={Path(n).name for n in value['current_inputs']} and
         {value['recipe']+'/'+n:pin(b) for n,b in package.items()}==value['current_inputs'],'exact maintained nine-entry recipe required')
    roots=[current,native,historical_factory,comparison_factory,current70_factory,HERE]
    fresh(output,roots)
    with tempfile.TemporaryDirectory(prefix='doctor2-current74-predecessor-') as temporary:
        private=Path(temporary);snapshot=private/'factory';snapshot.mkdir(mode=0o700)
        for name,body in captured.items():
            path=snapshot/relative(name)
            with path.open('xb') as stream:stream.write(body)
            path.chmod(0o644)
        need(files(snapshot)==captured,'exact private current70 authority snapshot required')
        legacy=types.ModuleType('unchanged_doctor2_current70_factory');legacy.__file__=str(snapshot/'prepare.py')
        exec(compile(captured['prepare.py'],legacy.__file__,'exec'),legacy.__dict__)
        predecessor=private/'source70'
        receipt=legacy.prepare(current,native,historical_factory,comparison_factory,predecessor,selected=selected)
        before=files(predecessor)
        need(receipt['files']==70 and {n:pin(b) for n,b in before.items()}==prior['views']['selected' if selected else 'default']['files'],
             'complete unchanged source70 predecessor emission required')
    view=value['views']['selected' if selected else 'default'];result=dict(before)
    for name,text in view['generated'].items():
        relative(name);need(not name.startswith(value['recipe']+'/'),'generated contexts must not substitute package bytes')
        need(type(text) is str,'generated source body required');result[name]=text.encode()
    validate(result,before,value,selected)
    # Captured code uses private HERE; mutable originals are rechecked before output.
    fresh(output,roots)
    need(profile()==value and files(current70_factory)==captured and files(recipe_root)==package,
         'current74 authority/current package changed before emission')
    need(all(files(root)==raw for root,raw in operands.items()),'predecessor operands changed before emission')
    output.mkdir(mode=0o700)
    for name,body in result.items():
        path=output/relative(name);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(body)
        path.chmod(0o644)
    validate(files(output),before,value,selected)
    return dict(status='SOURCE_ONLY_DOCTOR2_CURRENT74_NOT_NATIVE',view='selected' if selected else 'default',files=74,
        predecessor_source=value['authority_predecessor_source'],version=value['version'],actual_source=None,actual_ref=None,
        actual_run=None,installed_compare='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',acceptance='NOT_GRANTED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('current-root','native-root','historical-factory-root','comparison-factory-root','current70-factory-root','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--selected',action='store_true');args=parser.parse_args()
    result=prepare(*(getattr(args,name).absolute() for name in
        ('current_root','native_root','historical_factory_root','comparison_factory_root','current70_factory_root','output')),selected=args.selected)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
