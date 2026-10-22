#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Offline signed development application catalog and readonly transaction plans."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from types import ModuleType

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
DEFAULT_REPOSITORY_SOURCE=Path(__file__).absolute().parents[2]/'share/cachy-asahi/repository-runtime'
META=('name','version','arch','depend','provides','conflict','replaces','files')
MAX_PACKAGES=4096
MAX_INSTALLED_JSON=16*1024**2
MAX_MATCHES=65536


class Refusal(ValueError):
    def __init__(self,message,issues=()):super().__init__(message);self.issues=list(issues)


def need(ok,message,issues=()):
    if not ok:raise Refusal(message,issues)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()


def ordinary(path,limit=4*1024**2):
    path=Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary canonical source path required')
    st=path.stat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<=limit,'bounded regular source required')
    raw=path.read_bytes();need(len(raw)==st.st_size,'source changed while reading');return raw


def helpers(source):
    pins=json.loads(ordinary(HERE/'helper-pins.json'))['files'];modules={};blobs={}
    for name,pin in pins.items():
        path=Path(source).absolute()/name;raw=ordinary(path)
        need(dict(bytes=len(raw),sha256=digest(raw))==pin,'repository helper differs from package pin: '+name)
        blobs[name]=(path,raw)
    need(set(blobs)=={'scripts/client/client.py','scripts/release/release.py','scripts/release/source_delivery.py'},'exact three repository helpers required')
    for name,(path,raw) in blobs.items():
        module=ModuleType('apps_'+path.stem);module.__file__=str(path)
        exec(compile(raw,str(path),'exec'),module.__dict__);modules[path.stem]=module
    c,r=modules['client'],modules['release']
    # Preserve original association checks, with the already hash-checked Source.
    c.source_delivery_helper=lambda:modules['source_delivery']
    r.source_delivery_module=lambda:modules['source_delivery']
    return c,r,pins


def inventory_reader():
    path=HERE/'inventory.py';module=ModuleType('apps_inventory');module.__file__=str(path)
    exec(compile(ordinary(path),str(path),'exec'),module.__dict__);return module


def allowed(value):
    return (type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,127}',value) is not None and
            not re.search('(^|[-_.])(aur|multilib|x86|x86_64|i[3-6]86)([-_.]|$)',value,re.I) and
            not value.lower().startswith('lib32-'))


def package(row,r):
    need(type(row) is dict and allowed(row.get('name')) and row.get('arch') in ('aarch64','any'),'unsupported package name/architecture')
    need(type(row.get('version')) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}',row['version']) is not None,'invalid package version')
    value={k:row[k] for k in META if k in row};value.setdefault('replaces',[])
    for key in ('depend','provides','conflict','replaces','files'):
        entries=value.get(key);need(type(entries) is list and len(entries)<=(32768 if key=='files' else 256) and all(type(v) is str for v in entries) and len(set(entries))==len(entries),'invalid package '+key)
        for item in entries:
            need(type(item) is str and 0<len(item)<=512,'bounded package metadata required')
            if key=='files':need(all(part not in ('','.','..') for part in item.split('/')),'unsafe payload path')
            else:
                name,op,version=r.relation(item)
                # Native packages may declare foreign-named compatibility aliases.
                # These are metadata, not selected package/dependency identities.
                need(allowed(name) or key in ('provides','conflict','replaces') and
                     re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,127}',name) is not None,'x86/multilib/AUR relation refused')
                if key=='provides':need(op in (None,'='),'unsupported provider relation')
        value[key]=sorted(entries)
    if 'repository' in row:need(allowed(row['repository']),'x86/multilib/AUR installed repository refused')
    if 'sha256' in row:need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'invalid declared archive SHA256')
    return value


def indexed(rows,r):
    need(type(rows) is list and 0<len(rows)<=MAX_PACKAGES,'complete bounded package inventory required')
    result={}
    for row in rows:
        value=package(row,r);need(value['name'] not in result,'duplicate package: '+value['name']);result[value['name']]=value
    return result


def catalog_check(value,release,spec,release_sha,r):
    need(type(value) is dict and set(value)=={'schema_version','kind','target_arch','release_sha256','repository','applications'} and
         type(value['schema_version']) is int and value['schema_version']==1 and value['kind']=='development-application-catalog' and
         value['target_arch']=='aarch64' and value['release_sha256']==release_sha and
         allowed(value['repository']) and value['repository']==spec['repo_name'],'signed catalog/release/repository mismatch')
    available=indexed(release['packages'],r);base=indexed(spec['_base']['packages'],r)
    need(not set(available)&set(base),'application release may not replace any signed base package')
    apps=value['applications'];need(type(apps) is list and 0<len(apps)<=128,'finite nonempty application catalog required')
    result={}
    for app in apps:
        need(type(app) is dict and set(app)=={'id','title','description','packages'} and allowed(app.get('id')),'invalid application entry')
        need(app['id'] not in result,'duplicate application ID')
        for key in ('title','description'):
            need(type(app[key]) is str and 0<len(app[key])<=1024 and all(ord(v)>=32 for v in app[key]),'invalid application text')
        names=app['packages'];need(type(names) is list and 0<len(names)<=64 and len(set(names))==len(names) and
            all(n in available for n in names),'application contains an unavailable/nonrelease package')
        result[app['id']]=app
    return result,available,base


@contextmanager
def authenticated(args,c,r):
    signer=c.fingerprint(args.signer);root=c.directory(Path(args.release).absolute())
    try:
        with tempfile.TemporaryDirectory(prefix='cachy-asahi-apps-') as temporary:
            temp=Path(temporary);keyring=c.read_path(Path(args.keyring).absolute(),c.MAX_KEYRING)
            verifier=c.Verifier(temp,keyring,signer,datetime.now(timezone.utc))
            raw=c.read_member(root,'release.json');need(digest(raw)==args.release_sha256,'release SHA256 differs from caller pin')
            signature=c.read_member(root,'release.json.sig',c.MAX_SIGNATURE)
            signed=temp/'signed-release.json';signed.write_bytes(raw);verifier.verify(signed,signature)
            description,release,current=c.describe(root);need(current==raw,'release changed during authentication')
            snapshot=temp/'bundle';snapshot.mkdir()
            (snapshot/'release.json').write_bytes(raw);(snapshot/'release.json.sig').write_bytes(signature)
            # All semantic/archive readers consume these exact authenticated bytes.
            for name,expected in release['files'].items():
                c.relative(name);target=snapshot/name;target.parent.mkdir(parents=True,exist_ok=True)
                actual,_=c.hash_member(root,name,snapshot=target);need(actual==expected,'release payload changed: '+name)
            for name,target in release['symlinks'].items():
                c.relative(name);need(type(target) is str and '/' not in target and target not in ('.','..') and
                    (Path(name).parent/target).as_posix() in release['files'],'unsafe repository alias')
                (snapshot/name).symlink_to(target)
            def verify(path,key,env):
                need(key==signer,'semantic signer differs from external pin')
                return verifier.verify(path,c.read_path(Path(str(path)+'.sig'),c.MAX_SIGNATURE))
            r.verify_signature=verify
            def command(argv,*,env=None):
                need(str(argv[0]) in ('bsdtar','vercmp'),'unexpected semantic helper command')
                executable=shutil.which(str(argv[0]),path='/usr/bin:/bin');need(executable,'preinstalled semantic tool missing')
                result=subprocess.run([executable,*map(str,argv[1:])],capture_output=True,timeout=30,
                    env=dict(PATH='/usr/bin:/bin',HOME=str(verifier.home),LC_ALL='C'))
                need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=16*1024**2,'semantic helper failed or exceeded output bound')
                return result.stdout
            r.run=command
            checked,spec=r.verify_release(snapshot,signer,{})
            need(checked==release and spec['target_arch']=='aarch64' and type(spec.get('synthetic')) is bool,'semantic release differs')
            spec['_base']=c.decode((snapshot/'base.json').read_bytes())
            catalog_raw=c.read_path(Path(args.catalog).absolute(),c.MAX_JSON)
            need(digest(catalog_raw)==args.catalog_sha256,'catalog SHA256 differs from caller pin')
            catalog_sig=c.read_path(Path(args.catalog_signature).absolute(),c.MAX_SIGNATURE)
            path=temp/'catalog.json';path.write_bytes(catalog_raw);verifier.verify(path,catalog_sig)
            catalog=c.decode(catalog_raw)
            apps,available,base=catalog_check(catalog,release,spec,args.release_sha256,r)
            for row in release['packages']:
                provenance=c.decode((snapshot/row['provenance']).read_bytes())
                need(spec['synthetic'] or (provenance['build']['execution']=='native' and provenance['build']['architecture']=='aarch64'),
                     'application release lacks signed native aarch64 build provenance')
            binding=dict(release_sha256=args.release_sha256,catalog_sha256=args.catalog_sha256,
                catalog_signature_sha256=digest(catalog_sig),signer=signer,keyring_sha256=digest(keyring),
                spec_sha256=release['files']['spec.json'],base_sha256=release['files']['base.json'])
            yield dict(apps=apps,available=available,base=base,spec=spec,release=release,binding=binding)
            need(c.read_member(root,'release.json')==raw and c.read_path(Path(args.catalog).absolute(),c.MAX_JSON)==catalog_raw,
                 'release/catalog changed while planning')
    finally:os.close(root)


class Relations:
    def __init__(self,r):self.r=r;self.probes=0;self.work=0;self.indexes={}
    @lru_cache(maxsize=MAX_MATCHES)
    def matches(self,dep,name,version,provides):
        self.probes+=1;need(self.probes<=MAX_MATCHES,'dependency check exceeds bounded work')
        return self.r.satisfies(dep,dict(name=name,version=version,provides=provides))
    def providers(self,dep,rows):
        name=self.r.relation(dep)[0]
        if id(rows) not in self.indexes:
            offers={}
            for n,p in sorted(rows.items()):
                for offered in {n,*(self.r.relation(v)[0] for v in p['provides'])}:
                    offers.setdefault(offered,[]).append(n)
            self.indexes[id(rows)]=(rows,offers)
        choices=self.indexes[id(rows)][1].get(name,[]);self.work+=1+len(choices)
        need(self.work<=262144,'dependency traversal exceeds bounded work')
        return [n for n in choices if self.matches(dep,n,rows[n]['version'],tuple(rows[n]['provides']))]
    def issues(self,rows):
        result=[];owners={}
        for name,p in sorted(rows.items()):
            for dep in p['depend']:
                if not self.providers(dep,rows):result.append(dict(kind='unsatisfied-dependency',package=name,dependency=dep))
            for conflict in p['conflict']:
                for other in self.providers(conflict,rows):
                    if other!=name:result.append(dict(kind='package-conflict',package=name,other=other,relation=conflict))
            for path in p['files']:
                if path in owners:result.append(dict(kind='file-conflict',path=path,package=name,other=owners[path]))
                owners[path]=name
            need(len(result)<=1024,'too many inconsistent inventory records')
        for path,name in sorted(owners.items()):
            for parent in Path(path).parents:
                if parent.as_posix() in owners:
                    result.append(dict(kind='file-directory-conflict',path=path,package=name,other=owners[parent.as_posix()]))
            need(len(result)<=1024,'too many inconsistent inventory records')
        return result


def plan(context,installed,operation,requested,r):
    observed='observation' in installed
    need(set(installed)==({'schema_version','kind','target_arch','snapshot_id','packages'}|({'observation'} if observed else set())) and
         type(installed['schema_version']) is int and installed['schema_version']==1 and
         installed['kind']=='complete-installed-inventory' and installed['target_arch']=='aarch64' and
         type(installed['snapshot_id']) is str and 0<len(installed['snapshot_id'])<=128,'complete ARM installed inventory required')
    qualifier='CALLER_DECLARED_METADATA_NOT_HOST_ATTESTED'
    if observed:qualifier=inventory_reader().validate(installed,lambda row:package(row,r))
    before=indexed(installed['packages'],r);base=context['base'];available=context['available'];apps=context['apps']
    need(all(before.get(n)==row for n,row in base.items()),'installed base differs from signed base; base redesign refused')
    need(requested and len(set(requested))==len(requested) and all(n in apps for n in requested),'choose distinct signed catalog application IDs')
    names=sorted({p for app in requested for p in apps[app]['packages']})
    protected=set(base)|set(context['spec']['policy']['protected_packages'])
    need(not set(names)&protected,'protected Asahi/base package cannot be selected for mutation')
    relations=Relations(r);issues=relations.issues(before);need(not issues,'installed inventory is inconsistent',issues)
    after=dict(before);selected=set();dependencies=[]
    def add(name,reason):
        row=available[name]
        need(name not in protected and not row['replaces'] and
             not any(r.relation(v)[0] in protected for v in row['provides']+row['conflict']),
             'candidate targets protected base or requires unsupported replacement')
        old=after.get(name)
        if old==row:return
        if old:
            order=int(r.run(['vercmp',row['version'],old['version']]).strip())
            need(order>0,'downgrade/equivalent-version metadata replacement refused: '+name)
        need(name not in selected,'dependency provider requires incompatible selection: '+name)
        after[name]=row;selected.add(name);relations.indexes.pop(id(after),None)
        if reason:dependencies.append(dict(package=name,required_by=reason[0],dependency=reason[1]))
    if operation=='install':
        for name in names:add(name,None)
        while True:
            missing=[(name,dep) for name,p in sorted(after.items()) for dep in p['depend'] if not relations.providers(dep,after)]
            if not missing:break
            name,dep=missing[0];choices=relations.providers(dep,available)
            need(len(choices)==1,'unresolved or ambiguous dependency', [dict(package=name,dependency=dep,candidates=choices)])
            add(choices[0],(name,dep));need(len(after)<=MAX_PACKAGES,'planned inventory exceeds bound')
    elif operation=='reinstall':
        for name in names:
            need(before.get(name)==available[name],'reinstall requires already-installed exact signed version and metadata: '+name)
            add(name,None)
    else:
        need(operation=='remove','install, remove or explicit reinstall only')
        for name in names:after.pop(name,None)
        relations.indexes.pop(id(after),None)
    issues=relations.issues(after);need(not issues,'plan would break dependencies or introduce conflicts',issues)
    declared={p['name']:p.get('sha256') for p in installed['packages']}
    for name in names:
        if operation=='install' and before.get(name)==available[name] and declared.get(name):
            expected=next(p['sha256'] for p in context['release']['packages'] if p['name']==name)
            need(declared[name]==expected,'same-version installed archive differs; implicit reinstall refused')
    def record(name,rows,release_source=False):
        value=dict(rows[name],metadata_sha256=digest(encoded(rows[name])))
        value['source']='signed-release' if release_source else 'caller-installed-inventory'
        if not release_source and declared.get(name):value['declared_archive_sha256']=declared[name]
        if release_source:
            value['release_archive_sha256']=next(p['sha256'] for p in context['release']['packages'] if p['name']==name)
        return value
    changed=[n for n in sorted(after) if before.get(n)!=after[n]]
    result=dict(operation=operation,requested_applications=sorted(requested),requested_packages=names,
        additions=[record(n,after,True) for n in changed if n not in before],
        upgrades=[dict(before=record(n,before),after=record(n,after,True)) for n in changed if n in before],
        removals=[record(n,before) for n in sorted(before.keys()-after.keys())],dependencies=dependencies,conflicts=[],
        unchanged_selected=[n for n in names if operation!='reinstall' and before.get(n)==after.get(n)],
        before_inventory_sha256=digest(encoded([before[n] for n in sorted(before)])),
        after_inventory_sha256=digest(encoded([after[n] for n in sorted(after)])),
        protection='ALL_SIGNED_BASE_PACKAGES',dependency_policy='unique signed-release provider; no orphan/autoremove',
        installed_inventory=qualifier,inventory_reobserved_by_planner=False)
    if operation=='reinstall':
        result['reinstalls']=[dict(before=record(n,before),after=record(n,after,True)) for n in names]
        result['repair_policy']='EXPLICIT_SELECTED_SAME_VERSION_AND_METADATA_ONLY_NO_DEPENDENCY_EXPANSION'
        result['installed_payload']='NOT_OBSERVED_BY_PLANNER_REPAIR_NOT_APPLIED'
    return result


def execute(args):
    c,r,pins=helpers(args.repository_source)
    if args.command=='inventory':
        reader=inventory_reader();publish=reader.publish_diagnostic if getattr(args,'diagnostic_stage',False) else reader.publish
        return publish(args.dbpath,args.output,c,lambda row:package(row,r))
    with authenticated(args,c,r) as context:
        result=dict(schema_version=1,status='READONLY',applied='NOT_APPLIED',scope='development',
            synthetic=context['spec']['synthetic'],stable_accepted=False,freshness='NOT_ESTABLISHED',
            installer_authority=False,binding=context['binding'],helper_pins=pins)
        def app(row):return dict(row,packages=[dict(context['available'][n],release_archive_sha256=next(p['sha256'] for p in context['release']['packages'] if p['name']==n)) for n in row['packages']])
        if args.command=='plan':
            need(args.installed and args.installed_sha256,'explicit installed inventory and SHA256 required for plans')
            raw=c.read_path(Path(args.installed).absolute(),MAX_INSTALLED_JSON);need(digest(raw)==args.installed_sha256,'installed inventory SHA256 mismatch')
            result['plan']=plan(context,c.decode(raw),args.operation,args.applications,r)
            result['binding']['installed_sha256']=args.installed_sha256
            need(c.read_path(Path(args.installed).absolute(),MAX_INSTALLED_JSON)==raw,'installed inventory changed while planning')
            result['status']='PLANNED'
        else:
            rows=[context['apps'][n] for n in sorted(context['apps'])]
            if args.command=='show':
                need(args.application in context['apps'],'unknown application ID');rows=[context['apps'][args.application]]
            if args.command=='search':
                query=args.query.casefold();rows=[p for p in rows if query in (' '.join((p['id'],p['title'],p['description'],*p['packages']))).casefold()]
            result['applications']=[app(row) for row in rows]
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository-source',default=str(DEFAULT_REPOSITORY_SOURCE),
                        help='exact runtime helper tree; defaults to the installed companion package')
    for name in ('release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer'):
        parser.add_argument('--'+name)
    parser.add_argument('--installed');parser.add_argument('--installed-sha256')
    sub=parser.add_subparsers(dest='command',required=True);sub.add_parser('list')
    sub.add_parser('search').add_argument('query');sub.add_parser('show').add_argument('application')
    command=sub.add_parser('plan');command.add_argument('operation',choices=('install','remove','reinstall'));command.add_argument('applications',nargs='+')
    inventory=sub.add_parser('inventory',help='readonly local ALPM9 metadata snapshot, no release credentials')
    inventory.add_argument('--dbpath',type=Path,required=True);inventory.add_argument('--output',type=Path,required=True)
    inventory.add_argument('--diagnostic-stage',action='store_true',help='explicit fresh0600 sibling stage JSON with finite phases/timing only; never acceptance')
    args=parser.parse_args()
    if args.command!='inventory':
        missing=[name for name in ('release','release_sha256','catalog','catalog_sha256','catalog_signature','keyring','signer') if not getattr(args,name)]
        if missing:parser.error('required for signed catalog commands: '+', '.join('--'+n.replace('_','-') for n in missing))
    try:print(encoded(execute(args)).decode(),end='');return 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(encoded(dict(status='REFUSED',applied='NOT_APPLIED',error=str(error),issues=getattr(error,'issues',[]))).decode(),end='');return 1
    except Exception as error:
        # Existing helper Error types intentionally remain their original classes.
        print(encoded(dict(status='REFUSED',applied='NOT_APPLIED',error=str(error))).decode(),end='');return 1

if __name__=='__main__':raise SystemExit(main())
