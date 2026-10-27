# SPDX-License-Identifier: MIT
"""Verify native installed-cache observations before making explicit planner bindings."""
import hashlib
import json
import math
from pathlib import Path
import contract as C
import capture_providers as A

KIND='INSTALLED_ALPM_CACHE_QUERY_V1'


def projection(row):
    return dict(name=row['name'],version=row['version'],arch=row['arch'],
                depend=sorted(row['depends']),provides=sorted(row['provides']))


def request(source,image):
    packages=[projection(p)for p in sorted(C.baseline(source)['packages'],key=lambda p:p['name'])]
    lock=''.join(p['name']+' '+p['version']+'\n'for p in packages)
    return dict(schema_version=1,image=image,inventory_sha256=hashlib.sha256(lock.encode()).hexdigest(),
                packages=packages,queries=[list(row)for row in A.QUERIES])


def database(snapshot):
    C.need(type(snapshot)is dict and set(snapshot)=={'nodes','sha256'}and type(snapshot['nodes'])is dict,'typed DB snapshot required')
    C.need(0<len(snapshot['nodes'])<=20000 and snapshot['sha256']==hashlib.sha256(C.encoded(snapshot['nodes'])).hexdigest(),'DB snapshot digest differs')
    for path,row in snapshot['nodes'].items():
        C.need(type(path)is str and len(path)<=512 and not Path(path).is_absolute()and'..'not in Path(path).parts,'DB snapshot path differs')
        C.need(type(row)is dict and row.get('kind')in('file','directory'),'typed DB node required')
        for key in ('dev','ino','mode','uid','gid','links','bytes','mtime_ns','ctime_ns'):
            C.need(type(row.get(key))is int and row[key]>=0,'typed DB identity required')
        if row['kind']=='file':C.need(type(row.get('sha256'))is str and C.HEX.fullmatch(row['sha256']),'DB file digest required')


def receipt(source,runtime,image):
    value=C.read(runtime/'provider-capture-result.json')
    C.need(value['status']=='ACTUAL_OWNED_CONTAINER_STDOUT_CAPTURED'and type(value['returncode'])is int and value['returncode']==0 and
        value['image']==image and value['stdout_sha256']==C.digest(runtime/'provider-capture.json')and
        value['stderr_sha256']==C.digest(runtime/'provider-capture.stderr')and value['command_sha256']==C.digest(runtime/'provider-capture-command.json')and
        value['source_manifest_sha256']==C.digest(source/'scripts/ci/build-batch-native/source-manifest.json'),'provider capture receipt differs')
    return value


def verify(source,image,raw,input_value):
    """Input bytes remain untrusted observations until Root joins actual execution."""
    C.need(type(raw)is bytes and len(raw)<=4*1024**2,'bounded provider capture bytes required')
    def pairs(items):
        result={}
        for key,item in items:
            C.need(key not in result,'duplicate provider capture key');result[key]=item
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:C.need(False,'nonfinite provider capture'))
    C.need(type(value)is dict and set(value)=={'schema_version','status','image','inventory_sha256','inventory_lock',
        'packages','cache_order','queries','db_before','db_after','raw_descriptions','architecture','uid','page_size',
        'collector_sha256','retained_reader_sha256','libalpm','elapsed_seconds','hardware','release'},'closed provider capture shape required')
    expected=request(source,image)
    C.need(type(value)is dict and type(value.get('schema_version'))is int and value['schema_version']==1 and
           value.get('status')=='CAPTURED_INSTALLED_ALPM_SELECTIONS_ONLY','typed installed capture required')
    C.need(value['image']==image and value['inventory_sha256']==expected['inventory_sha256']and
           value['packages']==expected['packages'],'installed capture image/inventory/metadata differs')
    C.need(type(value['cache_order'])is list and len(value['cache_order'])==574 and
           len(set(value['cache_order']))==574 and set(value['cache_order'])=={p['name']for p in expected['packages']},'complete typed ALPM cache order required')
    lock=''.join(p['name']+' '+p['version']+'\n'for p in expected['packages'])
    C.need(value['inventory_lock']==lock and value['architecture']in('aarch64','arm64')and
           type(value['uid'])is int and value['uid']>0 and type(value['page_size'])is int and value['page_size']>0,'native ordinary installed identity differs')
    C.need(value['collector_sha256']==C.digest(source/'scripts/ci/build-batch-native/capture_providers.py')and
           value['retained_reader_sha256']==C.digest(source/'scripts/ci/build-batch-native/retained-orphans-reader'),'installed collector/helper source differs')
    lib=value['libalpm'];C.need(type(lib)is dict and set(lib)=={'path','sha256','version'}and
           type(lib['path'])is str and Path(lib['path']).parent==Path('/usr/lib')and
           Path(lib['path']).name.startswith('libalpm.so.16')and type(lib['version'])is str and lib['version'].startswith('16.')and
           type(lib['sha256'])is str and C.HEX.fullmatch(lib['sha256']),'installed libalpm identity differs')
    C.need(type(value['elapsed_seconds'])in(int,float)and math.isfinite(value['elapsed_seconds'])and value['elapsed_seconds']>=0,'typed capture elapsed bound')
    database(value['db_before']);database(value['db_after']);C.need(value['db_before']==value['db_after'],'installed DB changed')
    descriptions=value['raw_descriptions']
    C.need(type(descriptions)is dict and len(descriptions)==574,'complete raw installed desc set required')
    expected_paths=set()
    for package in value['packages']:
        path='local/'+package['name']+'-'+package['version']+'/desc';expected_paths.add(path)
        C.need(path in value['db_before']['nodes'] and type(descriptions.get(path))is str and
               hashlib.sha256(descriptions[path].encode()).hexdigest()==value['db_before']['nodes'][path]['sha256'],'raw installed desc digest differs')
        fields={};key=None
        for line in descriptions[path].splitlines():
            if line.startswith('%')and line.endswith('%'):
                C.need(line not in fields,'duplicate raw desc field');key=line;fields[key]=[]
            elif line:
                C.need(key is not None,'untyped raw desc field');fields[key].append(line)
        expected_fields={'%NAME%':[package['name']],'%VERSION%':[package['version']],'%ARCH%':[package['arch']],
                         '%DEPENDS%':package['depend'],'%PROVIDES%':package['provides']}
        C.need(all(sorted(fields.get(k,[]))==sorted(v)for k,v in expected_fields.items()),'raw desc and actual ALPM metadata differ')
    C.need(set(descriptions)==expected_paths,'mixed raw desc set')
    C.need(value['hardware']=='NOT_RUN'and value['release']=='NOT_ADMITTED','capture scope differs')
    C.need(type(value['queries'])is list and len(value['queries'])==len(A.QUERIES),'exact provider observations required')
    planner=C.load('native_bound_provider_planner',source/'scripts/maintenance/rebuild_plan.py')
    packages={p['name']:p for p in input_value['packages']};rows={p['name']:p for p in value['packages']};selections=[]
    for observed,key in zip(value['queries'],A.QUERIES):
        C.need(type(observed)is dict and set(observed)=={'package','field','dependency','candidates','selected','method'},'typed provider observation required')
        C.need((observed['package'],observed['field'],observed['dependency'])==key and
               observed['method']=='alpm_find_satisfier(actual_local_cache_order)','exact queried consumer relation differs')
        package,field,dependency=key
        C.need(dependency in packages[package]['depend'],'queried dependency absent from planner input')
        # Both fixed native queries are unversioned; no host vercmp or solver is substituted.
        matching=[name for name in value['cache_order']if planner.r.satisfies(dependency,packages[name])]
        candidates=[dict(package=name,version=rows[name]['version'],cache_index=value['cache_order'].index(name))for name in matching]
        C.need(len(matching)>1 and type(observed['candidates'])is list and observed['candidates']==candidates,'all matching provider candidates must remain visible')
        C.need(all(type(p['cache_index'])is int for p in observed['candidates']),'typed provider cache index required')
        selected=observed['selected'];C.need(type(selected)is dict and set(selected)=={'name','version'}and
            selected['name']in matching and selected['version']==rows[selected['name']]['version'],'selected installed provider differs')
        context=planner.provider_context(package,field,dependency,matching,packages)
        selections.append(dict(package=package,field=field,dependency=dependency,provider=selected['name'],evidence=dict(
            kind=KIND,image=image,inventory_sha256=expected['inventory_sha256'],capture_sha256=hashlib.sha256(raw).hexdigest(),
            metadata_sha256=hashlib.sha256(C.encoded(context)).hexdigest())))
    return selections
