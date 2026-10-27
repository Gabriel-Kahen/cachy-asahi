#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real original341/C01 planner inputs; missing baseline recipe pins remain held.

No actor, acquisition, synthetic metadata or guessed provider selection. The caller
owns qualification of the immutable image and any native planner transport.
"""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import stat
import tarfile

LANE = 'scripts/ci/offline-source-builder-native'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
LOCK_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
NAMES = ('cachy-asahi-zlib-baseline', 'cachy-asahi-zlib-lto')
HEX = re.compile(r'[0-9a-f]{64}\Z')
QUERIES = (('curl','depend','ca-certificates'),('systemd','depend','dbus-units'))
RETAINED_READER_SHA = '559ff8554b9c93f237ddebec8f6c8ac09749ed93b6a179c06fcf513dfffe3292'
MAX_JSON = 16*1024**2
OWNER = 'Root finite original341 C01 offline batch'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def ordinary(path, limit=MAX_JSON):
    path=Path(path).absolute()
    info=path.lstat()
    need(path==path.resolve() and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=limit,
         'bounded ordinary source/cache file required: '+str(path))
    return path


def raw(path):
    return ordinary(path).read_bytes()


def digest(path):
    with ordinary(path,512*1024**2).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def decode(body):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    def invalid(value):
        raise ValueError('noninteger JSON number')
    value=json.loads(body,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
    need(type(value) is dict,'JSON object required')
    return value


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def merge(inputs):
    """Exactly the producer's rootfs-then-transaction replacement, with full relations."""
    result={}
    for rows,rootfs in ((inputs['rootfs_packages'],True),(inputs['packages'],False)):
        need(type(rows) is list and len(rows)<=4096,'finite installed metadata required')
        seen=set()
        for source in rows:
            row={}
            for key,target in (('name','name'),('version','version'),('arch','arch'),('depends','depend'),('provides','provides')):
                need(key in source,'incomplete installed metadata: '+key)
                value=source[key]
                if key in ('name','version','arch'):
                    if rootfs:
                        need(type(value) is list and len(value)==1,'single installed identity required');value=value[0]
                    need(type(value) is str and value and not any(c.isspace() for c in value),'installed identity text required')
                else:
                    need(type(value) is list and all(type(v) is str and v for v in value),'complete installed relation list required')
                    value=list(value)
                row[target]=value
            need(row['name'] not in seen,'duplicate installed package');seen.add(row['name'])
            need(row['arch'] in ('aarch64','any'),'installed architecture mismatch')
            result[row['name']]=row
    return result


def inventory(rows):
    return ''.join(name+' '+row['version']+'\n' for name,row in sorted(rows.items())).encode()


def closure(packages, roots, relation):
    """Same conservative candidate edges as rebuild_plan, including rejected offers."""
    offers={}
    for name,row in packages.items():
        for offered in [name,*[relation(v)[0] for v in row['provides']]]:
            offers.setdefault(offered,set()).add(name)
    seen=set();pending=list(roots);ambiguous=[];missing=[]
    while pending:
        name=pending.pop()
        if name in seen:
            continue
        need(name in packages,'dependency root absent from original341: '+name);seen.add(name)
        for dependency in packages[name]['depend']:
            candidates=sorted(offers.get(relation(dependency)[0],set()))
            if len(candidates)>1:
                ambiguous.append(dict(package=name,field='depend',dependency=dependency,candidates=candidates))
            if not candidates:
                missing.append(dict(package=name,dependency=dependency))
            pending.extend(set(candidates)-seen)
    return sorted(seen),sorted(ambiguous,key=lambda r:(r['package'],r['dependency'])),missing


def archive_recipe_pin(path,row):
    """Existing batch archive-pin method: fixed bytes, leading PKGINFO/BUILDINFO."""
    path=ordinary(path,512*1024**2)
    need(path.stat().st_size==row['size'] and digest(path)==row['sha256'],'selected archive SHA/size differs: '+row['name'])
    bodies={}
    with tarfile.open(path,'r|xz') as archive:
        for index,member in enumerate(archive):
            need(index<32,'archive metadata not in bounded leading members')
            name=member.name.removeprefix('./')
            if name in ('.PKGINFO','.BUILDINFO'):
                need(name not in bodies and member.isfile() and member.size<=1024**2,'ordinary bounded archive metadata required')
                bodies[name]=archive.extractfile(member).read()
            if len(bodies)==2:
                break
    need(set(bodies)=={'.PKGINFO','.BUILDINFO'},'archive PKGINFO/BUILDINFO unavailable: '+row['name'])
    def metadata(body):
        result={}
        for line in body.decode().splitlines():
            if line and not line.startswith('#'):
                need(' = ' in line,'malformed archive metadata')
                key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
        return result
    package,build=metadata(bodies['.PKGINFO']),metadata(bodies['.BUILDINFO'])
    expected=dict(pkgname=[row['name']],pkgver=[row['version']],arch=[row['arch']],depend=sorted(row['depends']),provides=sorted(row['provides']))
    need(all(sorted(package.get(k,[]))==v for k,v in expected.items()),'archive metadata differs from original341: '+row['name'])
    pins=build.get('pkgbuild_sha256sum',[])
    need(len(pins)==1 and HEX.fullmatch(pins[0]),'archive recipe hash unavailable: '+row['name'])
    need(digest(path)==row['sha256'],'archive changed during recipe-pin inspection')
    return pins[0]


def selected_source(root, relative, source_map):
    path=Path(relative)
    need(type(relative) is str and not path.is_absolute() and '..' not in path.parts and path.as_posix()==relative,'relative reviewed source path required')
    body=raw(root/path);row=source_map[relative]
    need(sha(body)==row['sha256'] and len(body)==row['bytes'] and stat.S_IMODE((root/path).stat().st_mode)==row['mode'],'reviewed source-map mismatch: '+relative)
    return body


def rootfs_provenance(root, inputs, installed, source_map, planner=None):
    relative=LANE+'/baseline-source-provenance.json'
    if not (root/relative).exists() and not (root/relative).is_symlink():
        return {}
    value=decode(selected_source(root,relative,source_map))
    if value==dict(schema_version=1,actual=None,status='UNBOUND_INPUT_HOLD') and type(value['schema_version']) is int:
        return {}
    need(set(value)=={'schema_version','purpose','inputs_sha256','inventory_sha256','rootfs_sha256','packages'} and
         type(value['schema_version']) is int and value['schema_version']==1 and value['purpose']=='original341-rootfs-source-provenance' and
         value['inputs_sha256']==INPUTS_SHA and value['inventory_sha256']==LOCK_SHA and value['rootfs_sha256']==inputs['rootfs']['sha256'],
         'exact reviewed rootfs source-provenance binding required')
    need(type(value['packages']) is list and len(value['packages'])<=165,'bounded rootfs provenance package list required')
    selected={r['name'] for r in inputs['packages']};result={}
    for row in value['packages']:
        need(type(row) is dict and set(row)=={'name','version','arch','recipe_sha256','sources','evidence'},'rootfs provenance package fields')
        name=row['name'];need(name in installed and name not in selected and name not in result,'unique original rootfs-only source identity required')
        need((row['version'],row['arch'])==(installed[name]['version'],installed[name]['arch']),'reviewed rootfs provenance identity differs')
        need(type(row['recipe_sha256']) is str and HEX.fullmatch(row['recipe_sha256']) and type(row['sources']) is list and 0<len(row['sources'])<=128,'reviewed rootfs source pins required')
        for item in row['sources']:
            need(type(item) is dict and type(item.get('url')) is str and 0<len(item['url'])<=512 and
                 (type(item.get('sha256')) is str and HEX.fullmatch(item['sha256']) or type(item.get('commit')) is str and re.fullmatch('[0-9a-f]{40}',item['commit'])),'reviewed rootfs source descriptor pin required')
        if planner is not None:
            planner.pins.project(dict(package={k:row[k] for k in ('name','version','arch')},recipe_sha256=row['recipe_sha256'],sources=row['sources']))
        evidence=row['evidence'];need(type(evidence) is dict and set(evidence)=={'path','sha256'},'retained BUILDINFO evidence fields')
        body=selected_source(root,LANE+'/'+evidence['path'],source_map);need(sha(body)==evidence['sha256'],'retained BUILDINFO evidence checksum differs')
        fields={}
        for line in body.decode().splitlines():
            if line and not line.startswith('#'):
                need(' = ' in line,'malformed retained BUILDINFO')
                key,item=line.split(' = ',1);fields.setdefault(key,[]).append(item)
        need(all(fields.get(k)==[v] for k,v in (('pkgname',name),('pkgver',row['version']),('pkgarch',row['arch']),('pkgbuild_sha256sum',row['recipe_sha256']))),
             'retained BUILDINFO identity/recipe SHA differs')
        result[name]=row
    return result


def topology(installed, recipes, archive_rows, recipe_pins, rootfs_sources=None):
    rootfs_sources=rootfs_sources or {}
    packages=list(installed.values());sources=[];builds=[]
    for name in sorted(installed):
        pin=recipe_pins.get(name);source_id='baseline-'+name if pin is not None else None
        if pin is not None:
            need(HEX.fullmatch(pin) and name in archive_rows,'actual cached BUILDINFO source pin required')
            row=archive_rows[name]
            sources.append(dict(id=source_id,recipe_sha256=pin,sources=[dict(url=row['url'],sha256=row['sha256'])]))
        if name in rootfs_sources:
            need(pin is None and name not in archive_rows,'conflicting rootfs source provenance')
            row=rootfs_sources[name];source_id='rootfs-'+name
            sources.append(dict(id=source_id,recipe_sha256=row['recipe_sha256'],sources=row['sources']))
        builds.append(dict(package=name,source_id=source_id,makedepend=[],checkdepend=[],toolchain=[],
            disposition='external',owner='original341 frozen upstream binary-input owner',hold_reason=None))
    for name in NAMES:
        recipe=recipes[name];metadata=recipe['metadata']
        need(name not in installed,'C01 project package already in baseline')
        packages.append(dict(name=name,version='1.3.2-1',arch='aarch64',depend=metadata['depends'],provides=metadata['provides']))
        sources.append(dict(id=name,recipe_sha256=recipe['report']['input_sha256']['PKGBUILD'],
            sources=[dict(url=url.split('::',1)[-1],sha256=pin) for url,pin in zip(metadata['source'],metadata['sha256sums'])]))
        builds.append(dict(package=name,source_id=name,makedepend=metadata['makedepends'],checkdepend=metadata['checkdepends'],
            toolchain=['base-devel'],disposition='build',owner=OWNER,hold_reason=None))
    return dict(schema_version=1,metadata_role='pre-change-release',release_id='FINITE_ORIGINAL341_C01_BASELINE_LTO_BATCH',
        snapshot_id='source38-original341-'+INPUTS_SHA,packages=packages,sources=sources,build_dependencies=builds,
        changed=dict(sources=list(NAMES),toolchains=[],advisories=[]),
        capacity=dict(native_aarch64_slots=2,owner=OWNER,reference='Finite 8CPU/8GiB hosted job budget; sustainable capacity NOT_MEASURED'))



def provider_request(source_root,image):
    root=Path(source_root).absolute();body=raw(root/'scripts/ci/inputs.lock.json')
    need(sha(body)==INPUTS_SHA,'original341 provider request inputs differ')
    installed=merge(decode(body));need(len(installed)==341 and sha(inventory(installed))==LOCK_SHA,'original341 provider request lock differs')
    need(type(image) is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'provider image ID required')
    packages=[dict(installed[n],depend=sorted(installed[n]['depend']),provides=sorted(installed[n]['provides'])) for n in sorted(installed)]
    return dict(schema_version=1,image=image,inventory_sha256=LOCK_SHA,packages=packages,queries=[list(q) for q in QUERIES])


def graph_review(source_root):
    """Pure presecret rootfs-pin review, using the retained recipe inspector only."""
    root=Path(source_root).absolute();body=raw(root/'scripts/ci/inputs.lock.json')
    need(sha(body)==INPUTS_SHA,'original source38 input lock differs')
    inputs=decode(body);installed=merge(inputs)
    need(len(installed)==341 and inventory(installed)==raw(root/LANE/'expected-packages.lock') and sha(inventory(installed))==LOCK_SHA,'original341 static review lock differs')
    source_map=decode(raw(root/LANE/'source-map.json'))['files']
    selected_source(root,'scripts/checks/package_checks.py',source_map)
    checks=load('c01_presecret_recipe_checks',root/'scripts/checks/package_checks.py')
    def relation(value):
        match=re.fullmatch(r'([A-Za-z0-9@._+-]+)(?:(>=|<=|=|>|<)([^\s]+))?',value)
        need(match is not None,'unsupported static ALPM relation');return match.groups()
    roots={'base-devel'}
    for name in NAMES:
        directory=root/'packages/experiments'/name;report=checks.recipe(directory/'PKGBUILD')
        need(not report['errors'],'C01 presecret recipe inspection failed')
        for relative,pin in report['input_sha256'].items():
            need(sha(selected_source(root,(directory/relative).relative_to(root).as_posix(),source_map))==pin,'reviewed presecret recipe differs')
        for field in ('depends','makedepends','checkdepends'):
            roots.update(relation(dep)[0] for dep in report['metadata'].get(field,[])+report['metadata'].get(field+'_aarch64',[]))
    required,ambiguities,missing=closure(installed,roots,relation)
    sources=rootfs_provenance(root,inputs,installed,source_map)
    unknown=sorted(set(required)-{r['name'] for r in inputs['packages']}-sources.keys())
    return dict(status='ROOTFS_SOURCE_PINS_UNAVAILABLE_INPUT_HOLD' if unknown else 'ROOTFS_SOURCE_PINS_REVIEWED_NATIVE_METADATA_STILL_REQUIRED',
        inventory_sha256=LOCK_SHA,inputs_sha256=INPUTS_SHA,required_baseline_packages=required,
        missing_rootfs_source_provenance=[{k:installed[n][k] for k in ('name','version','arch')} for n in unknown],
        reviewed_rootfs_source_packages=sorted(sources),candidate_provider_ambiguities=ambiguities,unavailable_named_inputs=missing,
        runtime_provider_selection='REQUIRES_ACTUAL_READONLY_QUALIFIED_IMAGE_CAPTURE',native='NOT_RUN',builds='NOT_RUN')


def provider_selections(source_root,work,image,graph,planner):
    """Join actual captured bytes; never infer which ALPM candidate was selected."""
    source_root,work=Path(source_root),Path(work)
    capture_path=work/'installed-provider-capture.json';receipt_path=work/'installed-provider-capture-result.json'
    if not capture_path.exists() and not capture_path.is_symlink() and not receipt_path.exists() and not receipt_path.is_symlink():
        return []
    body=raw(capture_path);need(len(body)<=4*1024**2,'provider capture byte bound')
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate provider capture key');result[key]=value
        return result
    value=json.loads(body,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite provider capture'))
    need(type(value) is dict and set(value)=={'schema_version','status','image','inventory_sha256','inventory_lock','packages','cache_order','queries','db_before','db_after','raw_descriptions','architecture','uid','page_size','collector_sha256','retained_reader_sha256','libalpm','elapsed_seconds','hardware','release'},'closed original341 capture shape required')
    expected=provider_request(source_root,image);packages=expected['packages'];rows={p['name']:p for p in packages}
    need(type(value['schema_version']) is int and value['schema_version']==1 and value['status']=='CAPTURED_INSTALLED_ALPM_SELECTIONS_ONLY' and
         value['image']==image and value['inventory_sha256']==LOCK_SHA and encoded(value['packages'])==encoded(packages) and
         value['inventory_lock']==inventory(rows).decode(),'original341 captured metadata/image/lock differs')
    order=value['cache_order'];need(type(order) is list and len(order)==341 and all(type(n) is str for n in order) and len(set(order))==341 and set(order)==set(rows),'complete original341 actual cache order required')
    need(value['architecture'] in ('aarch64','arm64') and type(value['uid']) is int and 0<value['uid']<=2**32-1 and type(value['page_size']) is int and 4096<=value['page_size']<=65536 and value['page_size']&(value['page_size']-1)==0,'ordinary native capture identity required')
    need(type(value['elapsed_seconds']) in (int,float) and math.isfinite(value['elapsed_seconds']) and 0<=value['elapsed_seconds']<=90 and value['hardware']=='NOT_RUN' and value['release']=='NOT_ADMITTED','bounded capture scope required')
    source_map=decode(raw(source_root/LANE/'source-map.json'))['files']
    collector_sha=sha(selected_source(source_root,LANE+'/capture_installed.py',source_map))
    helper_sha=sha(selected_source(source_root,LANE+'/retained-orphans-reader',source_map))
    need(helper_sha==RETAINED_READER_SHA and value['collector_sha256']==collector_sha and value['retained_reader_sha256']==helper_sha,'exact captured collector/helper differs')
    library=value['libalpm'];need(type(library) is dict and set(library)=={'path','sha256','version'} and type(library['path']) is str and
         re.fullmatch(r'/usr/lib/libalpm\.so\.16(?:\.[0-9]+)*',library['path']) and type(library['sha256']) is str and HEX.fullmatch(library['sha256']) and
         type(library['version']) is str and re.fullmatch(r'16\.[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9_.-]+)?',library['version']),'captured ALPM16 identity differs')
    before,after=value['db_before'],value['db_after']
    for snapshot in (before,after):
        need(type(snapshot) is dict and set(snapshot)=={'nodes','sha256'} and type(snapshot['nodes']) is dict and 0<len(snapshot['nodes'])<=20000 and snapshot['sha256']==sha(encoded(snapshot['nodes'])),'complete DB snapshot digest differs')
        for path,node in snapshot['nodes'].items():
            need(type(path) is str and len(path)<=512 and (path=='.' or path==Path(path).as_posix() and not Path(path).is_absolute() and not any(p in ('.','..') for p in path.split('/'))) and '\\' not in path,'relative DB node required')
            need(type(node) is dict and node.get('kind') in ('file','directory') and set(node)=={'kind','dev','ino','mode','uid','gid','links','bytes','mtime_ns','ctime_ns'}|({'sha256'} if node['kind']=='file' else set()),'closed typed DB node required')
            need(all(type(node[k]) is int and 0<=node[k]<=2**64-1 for k in ('dev','ino','mode','uid','gid','links','bytes','mtime_ns','ctime_ns')) and node['mode']<=0o7777 and node['links']>=1,'typed DB identity differs')
            if node['kind']=='file':need(node['bytes']<=128*1024**2 and node['links']==1 and type(node['sha256']) is str and HEX.fullmatch(node['sha256']),'ordinary DB file digest required')
            if path!='.':need(snapshot['nodes'].get(str(Path(path).parent),{}).get('kind')=='directory','DB parent missing')
        need(sum(n['bytes'] for n in snapshot['nodes'].values() if n['kind']=='file')<=512*1024**2,'DB aggregate byte bound')
    need(encoded(before)==encoded(after),'installed DB changed during capture')
    nodes=before['nodes'];need(nodes.get('.',{}).get('kind')=='directory' and nodes.get('local',{}).get('kind')=='directory' and nodes.get('local/ALPM_DB_VERSION',{}).get('sha256')==sha(b'9\n'),'initialized local DB9 snapshot required')
    need({p for p,n in nodes.items() if p.startswith('local/') and p.count('/')==1 and n['kind']=='file'}=={'local/ALPM_DB_VERSION'} and nodes['local/ALPM_DB_VERSION']['bytes']==2,'local DB file namespace differs')
    descriptions=value['raw_descriptions'];paths={'local/'+p['name']+'-'+p['version']+'/desc' for p in packages}
    need(type(descriptions) is dict and set(descriptions)==paths,'complete raw341 description set required')
    need({p for p,n in nodes.items() if p.startswith('local/') and p.count('/')==1 and n['kind']=='directory'}=={p.rsplit('/',1)[0] for p in paths},'local DB package namespace differs')
    for package in packages:
        path='local/'+package['name']+'-'+package['version']+'/desc';text=descriptions[path]
        need(type(text) is str and len(text.encode())<=65536 and nodes.get(path,{}).get('kind')=='file' and nodes[path]['sha256']==sha(text.encode()) and nodes[path]['bytes']==len(text.encode()) and nodes.get(path[:-4]+'files',{}).get('kind')=='file','raw desc hash/bytes/files differs')
        fields={};key=None
        for line in text.splitlines():
            if line.startswith('%') and line.endswith('%'):
                need(re.fullmatch('%[A-Z][A-Z0-9_]*%',line) and line not in fields,'duplicate raw description field');key=line;fields[key]=[]
            elif line:need(key is not None and len(line)<=4096,'typed bounded raw description required');fields[key].append(line)
        need(all(sorted(fields.get(k,[]))==sorted(v) for k,v in {'%NAME%':[package['name']],'%VERSION%':[package['version']],'%ARCH%':[package['arch']],'%DEPENDS%':package['depend'],'%PROVIDES%':package['provides']}.items()),'raw description and ALPM metadata differ')
    request_body=raw(work/'installed-provider-capture-request.json');need(encoded(decode(request_body))==encoded(expected),'retained provider request differs')
    receipt=decode(raw(receipt_path))
    need(set(receipt)=={'schema_version','status','image','inventory_sha256','returncode','stdout_sha256','collector_sha256','retained_reader_sha256','request_sha256','source_map_sha256'} and type(receipt['schema_version']) is int and receipt['schema_version']==1 and
         receipt['status']=='ACTUAL_OWNED_CONTAINER_STDOUT_CAPTURED' and receipt['image']==image and receipt['inventory_sha256']==LOCK_SHA and type(receipt['returncode']) is int and receipt['returncode']==0 and
         receipt['stdout_sha256']==sha(body) and receipt['collector_sha256']==collector_sha and receipt['retained_reader_sha256']==helper_sha and receipt['request_sha256']==sha(request_body) and receipt['source_map_sha256']==digest(source_root/LANE/'source-map.json'),'actual provider capture receipt differs')
    need(type(value['queries']) is list and len(value['queries'])==2,'two exact provider query observations required')
    supplied={p['name']:p for p in graph['packages']};selections=[]
    for observed,(consumer,field,dependency) in zip(value['queries'],QUERIES):
        need(type(observed) is dict and set(observed)=={'package','field','dependency','candidates','selected','method'} and
             (observed['package'],observed['field'],observed['dependency'])==(consumer,field,dependency) and observed['method']=='alpm_find_satisfier(actual_local_cache_order)' and dependency in rows[consumer]['depend'],'exact installed provider query differs')
        matching=[n for n in order if planner.r.satisfies(dependency,supplied[n])]
        candidates=[dict(package=n,version=rows[n]['version'],cache_index=order.index(n)) for n in matching]
        need(len(matching)>1 and encoded(observed['candidates'])==encoded(candidates) and all(type(c['cache_index']) is int for c in observed['candidates']),'complete actual ordered candidate set differs')
        selected=observed['selected'];need(type(selected) is dict and set(selected)=={'name','version'} and selected['name'] in matching and selected['version']==rows[selected['name']]['version'],'observed selected provider membership/version differs')
        context=planner.provider_context(consumer,field,dependency,matching,supplied)
        selections.append(dict(package=consumer,field=field,dependency=dependency,provider=selected['name'],evidence=dict(kind='INSTALLED_ALPM_CACHE_QUERY_V1',image=image,inventory_sha256=LOCK_SHA,capture_sha256=sha(body),metadata_sha256=sha(encoded(context)))))
    return selections


def prepare(source_root,feature_root,work,image,cache):
    """Emit reviewable real inputs; UNKNOWN_SOURCE_PINS/provider holds stay in graph.

    cache is the producer's flat alarm-cache. The already seeded opaque-source
    cache is work/source-cache. No original input, recipe or cache bytes change.
    """
    source_root,feature_root,work,cache=map(lambda p:Path(p).absolute(),(source_root,feature_root,work,cache))
    need(all(p==p.resolve() and p.is_dir() for p in (source_root,feature_root,work,cache)),'canonical existing input/work directories required')
    need(all(not work.is_relative_to(p) and not p.is_relative_to(work) for p in (source_root,feature_root,cache)),'graph work must be disjoint from reviewed sources/cache')
    need(type(image) is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'qualified immutable image ID required')
    body=raw(source_root/'scripts/ci/inputs.lock.json');need(sha(body)==INPUTS_SHA,'original source38 input lock differs')
    inputs=decode(body);installed=merge(inputs)
    need(len(inputs['rootfs_packages'])==165 and len(inputs['packages'])==248 and len(installed)==341,'exact original165+248=>341 metadata required')
    lock=raw(source_root/LANE/'expected-packages.lock')
    need(sha(lock)==LOCK_SHA and inventory(installed)==lock,'exact original341 package lock differs')
    source_map=decode(raw(source_root/LANE/'source-map.json'))['files']
    build=load('c01_batch_reviewed_build',feature_root/'scripts/build/build_v2.py')
    planner=load('c01_batch_reviewed_planner',feature_root/'scripts/maintenance/rebuild_plan.py')
    recipes={};roots={'base-devel'}
    for name in NAMES:
        directory=source_root/'packages/experiments'/name
        report=build.recipe(directory/'PKGBUILD');need(not report['errors'],'reviewed C01 recipe inspection failed')
        for relative,checksum in report['input_sha256'].items():
            path=directory/relative;key=path.relative_to(source_root).as_posix();data=raw(path);row=source_map[key]
            need(sha(data)==checksum==row['sha256'] and len(data)==row['bytes'] and stat.S_IMODE(path.stat().st_mode)==row['mode'],'reviewed recipe source-map mismatch: '+key)
        metadata=build.normalize_metadata(report['metadata'])
        need(metadata['pkgname']==[name] and metadata['pkgver']==['1.3.2'] and metadata['pkgrel']==['1'] and metadata['epoch']==['0'] and metadata['arch']==['aarch64'],'exact C01 recipe identity required')
        roots.update(planner.r.relation(v)[0] for field in ('depends','makedepends','checkdepends') for v in metadata[field])
        recipes[name]=dict(directory=directory,report=report,metadata=metadata)
    required,ambiguous,missing=closure(installed,roots,planner.r.relation)
    archive_rows={r['name']:r for r in inputs['packages']};pins={}
    for name in required:
        if name in archive_rows:
            row=archive_rows[name];path=cache/row['filename']
            need(Path(row['filename']).name==row['filename'],'flat selected archive filename required')
            if path.exists() or path.is_symlink():
                pins[name]=archive_recipe_pin(path,row)
    rootfs_sources=rootfs_provenance(source_root,inputs,installed,source_map,planner)
    graph=topology(installed,recipes,archive_rows,pins,rootfs_sources)
    selections=provider_selections(source_root,work,image,graph,planner)
    if selections:
        graph['provider_selections']=selections
        ambiguous=[]
    target=work/'batch-graph';need(not target.exists(),'fresh batch-graph output required');target.mkdir(mode=0o700)
    def save(name,value):
        path=target/name;path.write_bytes(encoded(value));return str(path),digest(path)
    input_path,input_sha=save('input.json',graph)
    (target/'image-packages.lock').write_bytes(lock)
    original_plan=decode(selected_source(source_root,LANE+'/source-plan.json',source_map))
    need(original_plan['recipe_inputs']==recipes[NAMES[0]]['report']['input_sha256'],'reviewed baseline source plan recipe differs')
    catalog=source_root/LANE/'source-inputs.json'
    need(sha(selected_source(source_root,LANE+'/source-inputs.json',source_map))==original_plan['catalog_sha256'],'reviewed source catalog differs')
    tasks=[];bindings={}
    for name,recipe in recipes.items():
        reviewed,reviewed_sha=save(name+'.reviewed.json',recipe['report']['input_sha256'])
        plan=dict(original_plan,recipe_inputs=recipe['report']['input_sha256'])
        plan_path,plan_sha=save(name+'.source-plan.json',plan)
        bindings[name]=dict(source_plan=plan_path,source_plan_sha256=plan_sha,source_catalog=str(catalog),source_cache=str(work/'source-cache'))
        tasks.append(dict(package=name,owner=OWNER,recipe=str(recipe['directory']),reviewed_inputs=reviewed,reviewed_inputs_sha256=reviewed_sha,
            expected_packages=str(target/'image-packages.lock'),expected_packages_sha256=LOCK_SHA,image=image,mode='native',
            source_date_epoch=inputs['source_date_epoch'],timeout=240,prerequisite_artifacts={},
            image_dependency_review='Exact original341 lock and full conservative base-devel/C01 dependency graph; unresolved source/provider metadata remains held'))
    config_path,config_sha=save('config.json',dict(schema_version=1,owner=OWNER,review='Finite real C01 baseline/LTO recipes; original341 immutable builder inputs',
        max_parallel=2,cpu_budget=8,memory_gib_budget=8,max_wall_seconds=600,max_attempts=2,tasks=tasks))
    sources_path,sources_sha=save('sources.json',dict(schema_version=1,builder_interface='offline-build-v2',tasks=bindings))
    unknown=set(required)-pins.keys()-rootfs_sources.keys()
    diagnostic=dict(status='INPUT_METADATA_HOLDS_NO_EXECUTION' if unknown or ambiguous or missing else 'INPUTS_READY_FOR_PLANNER_REVIEW',
        baseline_packages=341,required_baseline_packages=required,rootfs_only_recipe_pins_unknown=sorted(set(required)-archive_rows.keys()-rootfs_sources.keys()),
        rootfs_source_provenance_missing=[{k:installed[name][k] for k in ('name','version','arch')} for name in sorted(set(required)-archive_rows.keys()-rootfs_sources.keys())],
        recipe_pins_unknown=sorted(unknown),missing_source_provenance=[{k:installed[name][k] for k in ('name','version','arch')} for name in sorted(unknown)],
        reviewed_rootfs_source_packages=sorted(rootfs_sources),rootfs_provenance_path=LANE+'/baseline-source-provenance.json',
        rootfs_provenance_schema=dict(schema_version=1,purpose='original341-rootfs-source-provenance',inputs_sha256=INPUTS_SHA,inventory_sha256=LOCK_SHA,rootfs_sha256=inputs['rootfs']['sha256'],packages=[]),candidate_provider_ambiguities=ambiguous,unavailable_named_inputs=missing,
        provider_policy='OBSERVED_ALPM_SELECTIONS_ONLY_ALL_CANDIDATE_EDGES_RETAINED',provider_selections=selections,source_pin_scope='Actual cached package BUILDINFO recipe identity plus pinned binary archive descriptor; no rootfs recipe inference',
        image=image,inventory_sha256=LOCK_SHA,builds='NOT_RUN',hardware='NOT_RUN',source_task_admission='NOT_CHECKED')
    save('graph-review.json',diagnostic)
    return dict(input_path=input_path,input_sha=input_sha,config_path=config_path,config_sha=config_sha,sources_path=sources_path,sources_sha=sources_sha,
        planner_path=str(feature_root/'scripts/maintenance/rebuild_plan.py'),planner_sha=digest(feature_root/'scripts/maintenance/rebuild_plan.py'),review=diagnostic)
