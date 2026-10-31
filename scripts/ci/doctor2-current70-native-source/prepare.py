#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the closed retained574 Doctor2 route70 or exact historical70562; source only."""
import argparse,hashlib,json,os,stat,tempfile,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 678354, 'sha256': '613c9000106e0224944f5372eaad54d5dad186009e311fc0fda1a63e0c18affc'}
CARRIER='705c5a095f9cabbfd2f3cd137127f4bbc7665f52'
SLICE='scripts/ci/welcome-native/'


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
    raw=ordinary(HERE/'source.json');need(pin(raw)==PROFILE,'exact current70 factory profile required')
    value=json.loads(raw)
    need(value['carrier_source']==CARRIER and all(value[n] is None for n in ('actual_source','actual_ref','actual_run')),'historical carrier and NULL actual selectors required')
    need(value['authority_source']=='88997143a593f2de82fb41ae0224a943a1f99930' and value['authority_ref']=='codex/doctor2-retained574-isolated-entry-v2','exact source70 authority required')
    return value


def fresh(output,roots):
    need(output.is_absolute() and '..' not in output.parts and not any(c in str(output) for c in ',\r\n') and output.parent.is_dir() and not output.exists() and
         not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output required')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in roots),'disjoint output required')


def comparison(base,package,prior,selected):
    view=prior['views']['selected' if selected else 'default'];result=dict(base);result.update(package)
    result.update({name:text.encode() for name,text in view['generated'].items()})
    need({n:pin(b) for n,b in result.items()}==view['files'],'unchanged complete comparison63 context required')
    return result


def validate(result,base,package,lock,prior,value,selected):
    view=value['views']['selected' if selected else 'default']
    need(len(result)==70 and {n:pin(b) for n,b in result.items()}==view['files'],'complete exact source70 required')
    need({n for n,b in result.items() if b!=base.get(n)}==set(view['changed_vs_705']) and
         set(result)-set(base)==set(view['added_vs_705']),'exact source70/705 change set required')
    need(all(pin(result[n])==p for n,p in value['unchanged_705'].items()),'historical actors/security/budgets changed')
    if not selected:
        allowed={SLICE+'doctor2-policy.json',SLICE+'source-pins.json',SLICE+'ci/source-manifest.json',
                 '.github/workflows/native-arm-build.yml','.github/workflows/native-arm-welcome-doctor-products.yml'}
        approved=value['views']['selected']['files']
        need(set(result)==set(approved) and {n for n,b in result.items() if pin(b)!=approved[n]}==allowed,
             'default may change only selection policy and its four source stamps')

    old63=comparison(base,package,prior,selected)
    need({n for n,b in result.items() if b!=old63.get(n)}==set(view['changed_vs_63']) and
         set(result)-set(old63)==set(view['added_vs_63']),'exact source70/comparison63 change set required')
    for old,wanted in ((base,lock['selected_files']),(old63,prior['views']['selected' if selected else 'default']['files'])):
        inverse=dict(result)
        for n in set(result)-set(old):del inverse[n]
        for n,b in old.items():
            if result.get(n)!=b:inverse[n]=b
        need({n:pin(b) for n,b in inverse.items()}==wanted,'complete predecessor inverse differs')
    helpers={n:pin(b) for n,b in result.items() if n.startswith('scripts/ci/setup6-retained-helpers/')}
    need(len(helpers)==6 and helpers==value['approved_helpers'],'six exact approved helper/license bodies required')
    policy=json.loads(result[SLICE+'doctor2-policy.json'])
    need(all(policy[n] is None for n in ('actual_source','actual_ref','actual_run')),'actual source/ref/run must remain NULL')
    if selected:
        need(policy['status']=='ROOT_SELECTED_DOCTOR2_NATIVE_PAIR' and policy['version']==value['version'] and
             policy['recipe']==value['recipe'] and policy['input_sha256']=={Path(n).name:pin(b)['sha256'] for n,b in package.items()},'exact selected nine-input recipe required')
    else:
        need(policy['status']=='UNBOUND' and all(policy[n] is None for n in ('recipe','version','input_sha256')),'default recipe selection must remain NULL')
    pins=json.loads(result[SLICE+'source-pins.json']);manifest=json.loads(result[SLICE+'ci/source-manifest.json'])
    need(len(pins)==50 and all(pin(result[n])['sha256']==p for n,p in pins.items()),'all50 source pins required')
    excluded={SLICE+'ci/source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-welcome-doctor-products.yml'}
    need(set(manifest['files'])==set(result)-excluded and len(manifest['files'])==67 and
         all(pin(result[n])==p for n,p in manifest['files'].items()),'complete manifest67/source70 correspondence required')
    workflow=result['.github/workflows/native-arm-build.yml']
    need(workflow==result['.github/workflows/native-arm-welcome-doctor-products.yml'],'identical workflow aliases required')
    need(workflow.count(pin(result[SLICE+'ci/source-manifest.json'])['sha256'].encode())==1 and
         workflow.count(pin(result[SLICE+'ci/caller.py'])['sha256'].encode())==2,'exact source/caller workflow stamps required')
    need(workflow.index(b'caller.py" proof')<workflow.index(b'producer.py" --help')<workflow.index(b'using existing secrets only'),'isolated help must precede credentials')


def prepare(current,native,historical_factory,comparison_factory,output,*,selected=False,historical=False):
    need(type(selected) is bool and type(historical) is bool,'explicit source views required')
    value=profile();factories={}
    for root,key in ((historical_factory,'historical_factory'),(comparison_factory,'comparison_factory')):
        raw=files(root);need({n:pin(b) for n,b in raw.items()}==value[key],'exact unchanged '+key+' required');factories[key]=raw
    lock=json.loads(factories['historical_factory']['source.json']);prior=json.loads(factories['comparison_factory']['source.json'])
    need(lock['carrier_source']==CARRIER and len(lock['selected_files'])==len(lock['default_files'])==62,'exact historical70562 authority required')
    base=files(native);need({n:pin(b) for n,b in base.items()}==lock['selected_files'],'complete genuine70562 source required')
    roots=[native,historical_factory,comparison_factory]
    if historical:
        need(current is None,'historical emission must omit mutable current-root');fresh(output,roots)
        need(profile()==value and files(native)==base,'historical source changed before emission')
        for source,key in ((historical_factory,'historical_factory'),(comparison_factory,'comparison_factory')):
            need(files(source)==factories[key],'constructor authority changed before historical emission')
        # Execute captured verified code; its untouched HERE reads use a private exact snapshot.
        with tempfile.TemporaryDirectory(prefix='doctor2-historical-authority-') as temporary:
            snapshot=Path(temporary)
            for name,body in factories['historical_factory'].items():
                path=snapshot/relative(name)
                with path.open('xb') as stream:stream.write(body)
                path.chmod(0o644)
            need(files(snapshot)==factories['historical_factory'],'exact historical authority snapshot required')
            legacy=types.ModuleType('unchanged_doctor2_historical_factory');legacy.__file__=str(snapshot/'prepare.py')
            exec(compile(factories['historical_factory']['prepare.py'],legacy.__file__,'exec'),legacy.__dict__)
            result=legacy.prepare(native,native,output,selected)
        need({n:pin(b) for n,b in files(output).items()}==lock['selected_files' if selected else 'default_files'],
             'complete unchanged historical62 emission required')
        return result|dict(view='historical-selected' if selected else 'historical-default',acceptance='NOT_GRANTED')
    need(current is not None,'explicit maintained current-root required');root=current/relative(value['recipe']);raw=files(root)
    need({p.name for p in root.iterdir()}=={Path(n).name for n in value['current_inputs']},'exact nine-entry Doctor2 recipe directory required')
    package={value['recipe']+'/'+n:b for n,b in raw.items()}
    need(len(package)==9 and {n:pin(b) for n,b in package.items()}==value['current_inputs'],'exact maintained nine-input Doctor2 recipe required')
    view=value['views']['selected' if selected else 'default'];result=dict(base);result.update(package)
    for n,text in view['generated'].items():
        relative(n);need(n not in package,'generated transport must not substitute current recipe bytes');result[n]=text.encode()
    validate(result,base,package,lock,prior,value,selected)
    roots.append(current);fresh(output,roots)
    need(profile()==value and files(native)==base and files(root)==raw,'source changed before emission')
    for source,key in ((historical_factory,'historical_factory'),(comparison_factory,'comparison_factory')):
        need(files(source)==factories[key],'constructor authority changed before emission')
    output.mkdir(mode=0o700)
    for n,b in result.items():
        path=output/relative(n);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(b)
        path.chmod(0o644)
    emitted=files(output);validate(emitted,base,package,lock,prior,value,selected)
    return dict(status='SOURCE_ONLY_DOCTOR2_CURRENT70_NOT_NATIVE',view='selected' if selected else 'default',files=70,
                historical_carrier=CARRIER,version=value['version'],actual_source=None,actual_ref=None,actual_run=None,
                hardware='NOT_RUN',release='NOT_ADMITTED',acceptance='NOT_GRANTED')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--current-root',type=Path)
    for name in ('native-root','historical-factory-root','comparison-factory-root','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--selected',action='store_true');parser.add_argument('--historical',action='store_true')
    args=parser.parse_args()
    result=prepare(args.current_root.absolute() if args.current_root else None,args.native_root.absolute(),
                   args.historical_factory_root.absolute(),args.comparison_factory_root.absolute(),args.output.absolute(),
                   selected=args.selected,historical=args.historical)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
