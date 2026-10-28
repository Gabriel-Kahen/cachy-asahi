#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact Doctor2 comparison63 or explicit historical70562; source only."""
import argparse,hashlib,importlib.util,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':196917,'sha256':'f482d9ab910cb15846ebd7f5d500662894f13d8410cda295d63d18fff6bc11f1'}
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
    raw=ordinary(HERE/'source.json');need(pin(raw)==PROFILE,'exact comparison factory profile required')
    value=json.loads(raw)
    need(value['carrier_source']==CARRIER and all(value[n] is None for n in ('actual_source','actual_ref','actual_run')),'historical carrier and NULL actual selectors required')
    return value


def fresh(output,roots):
    need(output.is_absolute() and '..' not in output.parts and not any(c in str(output) for c in ',\r\n') and output.parent.is_dir() and not output.exists() and
         not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output required')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in roots),'disjoint output required')


def prepare(current,native,historical_factory,output,*,selected=False,historical=False):
    need(type(selected) is bool and type(historical) is bool,'explicit source views required')
    value=profile();historical_files=files(historical_factory)
    need({n:pin(b) for n,b in historical_files.items()}==value['historical_factory'],'exact unchanged historical constructor required')
    lock=json.loads(historical_files['source.json'])
    need(lock['carrier_source']==CARRIER and len(lock['selected_files'])==len(lock['default_files'])==62 and len(lock['doctor_files'])==8,'exact historical70562 authority required')
    before=files(native)
    need({n:pin(b) for n,b in before.items()}==lock['selected_files'],'complete genuine70562 source required')
    roots=[native,historical_factory]
    if historical:
        need(current is None,'historical current-root is explicitly the verified705 source; omit --current-root')
        fresh(output,roots)
        spec=importlib.util.spec_from_file_location('exact_historical_doctor2_factory',historical_factory/'prepare.py')
        legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        # Keep every old equality/policy guard; mutable canonical inputs are never substituted.
        result=legacy.prepare(native,native,output,selected)
        return result|dict(view='historical-selected' if selected else 'historical-default',acceptance='NOT_GRANTED')
    need(current is not None,'explicit maintained current-root required')
    recipe_root=current/relative(value['recipe']);current_files=files(recipe_root)
    need({p.name for p in recipe_root.iterdir()}=={Path(n).name for n in value['current_inputs']},'exact maintained nine-entry recipe directory required')
    package={value['recipe']+'/'+n:b for n,b in current_files.items()}
    need(len(package)==9 and {n:pin(b) for n,b in package.items()}==value['current_inputs'],'exact maintained Doctor2 nine-input recipe required')
    view=value['views']['selected' if selected else 'default'];result=dict(before);result.update(package)
    for name,text in view['generated'].items():
        relative(name);need(name in before and name not in package,'generated context may only replace exact historical context leaves')
        result[name]=text.encode('utf-8')
    need(len(result)==63 and {n:pin(b) for n,b in result.items()}==view['files'],'complete new63 source before output required')
    need({n for n in result if result[n]!=before.get(n)}==set(view['changed']),'exact new-source change set required')
    need(all(pin(result[n])==p for n,p in value['unchanged_actors'].items()),'historical actor/security/budget source changed')
    policy=json.loads(result[SLICE+'doctor2-policy.json'])
    need(all(policy[n] is None for n in ('actual_source','actual_ref','actual_run')),'actual source/ref/run must remain NULL')
    need(policy['status']==('ROOT_SELECTED_DOCTOR2_NATIVE_PAIR' if selected else 'UNBOUND'),'explicit new policy view required')
    if selected:
        need(policy['version']==value['version'] and policy['recipe']==value['recipe'] and
             policy['input_sha256']=={Path(n).name:pin(b)['sha256'] for n,b in package.items()},'new selected recipe correspondence required')
    else:need(all(policy[n] is None for n in ('version','recipe','input_sha256')),'default recipe selection must remain NULL')
    roots.append(current);fresh(output,roots);output.mkdir(mode=0o700)
    for name,raw in result.items():
        path=output/relative(name);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
        path.chmod(0o644)
    need({n:pin(b) for n,b in files(output).items()}==view['files'],'whole emitted63 source equality required')
    return dict(status='SOURCE_ONLY_DOCTOR2_COMPARISON63_NOT_NATIVE',view='selected' if selected else 'default',files=63,
                historical_carrier=CARRIER,version=value['version'],actual_source=None,actual_ref=None,actual_run=None,
                hardware='NOT_RUN',release='NOT_ADMITTED',acceptance='NOT_GRANTED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current-root',type=Path)
    for name in ('native-root','historical-factory-root','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--selected',action='store_true')
    parser.add_argument('--historical',action='store_true',help='emit exact old70562; --current-root must be omitted')
    args=parser.parse_args()
    result=prepare(args.current_root.absolute() if args.current_root else None,args.native_root.absolute(),
                   args.historical_factory_root.absolute(),args.output.absolute(),selected=args.selected,historical=args.historical)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
