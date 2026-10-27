# SPDX-License-Identifier: MIT
"""Pure original341 producer/current-image/ALPM runtime joins; no actor or file I/O."""
import hashlib
import json
import math
from pathlib import PurePosixPath
import re

INPUTS_SHA='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
LOCK_SHA='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
LABEL='org.cachy-asahi.offline-source-builder-owner'
LANE='scripts/ci/offline-source-builder-native/'
HELPER_SHA='559ff8554b9c93f237ddebec8f6c8ac09749ed93b6a179c06fcf513dfffe3292'
QUERIES=(('curl','depend','ca-certificates'),('systemd','depend','dbus-units'))
MEMBERS=('bootstrap-owner.json','bootstrap/image-inspect.json','bootstrap/packages.lock',
    'current-image-inspect.json','installed-provider-capture.json','installed-provider-capture-request.json',
    'installed-provider-capture-result.json','installed-provider-capture-origin.json','source-map.json','scripts/ci/inputs.lock.json')
HEX=re.compile(r'[0-9a-f]{64}\Z')


def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def fields(value,names,message):
    need(type(value)is dict and set(value)==set(names.split()),message)


def same(left,right,message):
    def exact(a,b):
        if type(a)is not type(b):return False
        if type(a)is dict:return a.keys()==b.keys()and all(exact(a[k],b[k])for k in a)
        if type(a)is list:return len(a)==len(b)and all(exact(x,y)for x,y in zip(a,b))
        return a==b
    need(exact(left,right),message)


def integer(value,low=0,high=2**64-1):
    need(type(value)is int and low<=value<=high,'typed bounded integer required');return value


def checksum(value):
    need(type(value)is str and HEX.fullmatch(value),'SHA256 field required');return value


def decode(raw):
    def pairs(rows):
        result={}
        for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
        return result
    def number(raw):
        value=float(raw);need(math.isfinite(value),'nonfinite JSON number');return value
    value=json.loads(raw,object_pairs_hook=pairs,parse_float=number,
        parse_constant=lambda _:need(False,'nonfinite JSON number'))
    need(type(value)is dict,'single JSON object required');return value


def identity_check(identity):
    fields(identity,'source_sha run_id attempt workflow_ref token tag probe consumer feature_code_sha','closed owned execution identity required')
    for key in('source_sha','feature_code_sha'):
        need(type(identity[key])is str and re.fullmatch('[0-9a-f]{40}',identity[key]),'exact source revision required')
    need(type(identity['run_id'])is str and re.fullmatch('[1-9][0-9]*',identity['run_id']),'exact hosted run ID required')
    same(identity['attempt'],1,'first hosted attempt required')
    token=sha((identity['source_sha']+':'+identity['run_id']+':1').encode())[:24]
    same({k:identity[k]for k in('token','tag','probe','consumer')},dict(token=token,tag='cachy-asahi-offline-source:'+token,
        probe='offline-source-lock-'+token,consumer='offline-source-'+token),'derived owned image/name identity differs')
    ref=identity['workflow_ref']
    need(type(ref)is str and len(ref)<=1024 and any(ref.startswith('Gabriel-Kahen/cachy-asahi/.github/workflows/'+p+'@')
        and len(ref)>len('Gabriel-Kahen/cachy-asahi/.github/workflows/'+p+'@')for p in
        ('native-arm-build.yml','native-arm-offline-build-batch-v2.yml')),'owned workflow identity differs')


def inventory(original):
    same(original['schema_version'],1,'original inventory schema differs')
    table={}
    for rows,rootfs,count in((original['rootfs_packages'],True,165),(original['packages'],False,248)):
        need(type(rows)is list and len(rows)==count,'original165/248 metadata count differs')
        seen=set()
        for source in rows:
            row={}
            for field in('name','version','arch'):
                value=source[field]
                if rootfs:
                    need(type(value)is list and len(value)==1,'single rootfs identity required');value=value[0]
                need(type(value)is str and value and len(value)<=256 and not any(c.isspace()for c in value),'installed identity text required')
                row[field]=value
            need(re.fullmatch('[A-Za-z0-9@_+][A-Za-z0-9@_.+-]{0,127}',row['name'])and row['arch']in('aarch64','any'),'installed package name/architecture differs')
            for source_key,target in(('depends','depend'),('provides','provides')):
                value=source[source_key]
                need(type(value)is list and len(value)<=256 and all(type(v)is str and 0<len(v)<=4096 for v in value),'complete installed relation metadata required')
                row[target]=list(value)
            need(row['name']not in seen,'duplicate same-layer installed package');seen.add(row['name']);table[row['name']]=row
    need(len(table)==341,'original rootfs/transaction merge is not341')
    lock=''.join(n+' '+table[n]['version']+'\n'for n in sorted(table)).encode()
    need(sha(lock)==LOCK_SHA,'original341 lock identity differs')
    return table,lock


def image_check(row,identity,image):
    allowed=set('Id RepoTags RepoDigests Parent Comment Created DockerVersion Author Config Architecture Variant Os Size GraphDriver RootFS Metadata Descriptor Container ContainerConfig VirtualSize Platform'.split())
    need(type(row)is dict and {'Id','RepoTags','Architecture','Os','Config','RootFS'}<=set(row)<=allowed,'single closed Docker image inspection object required')
    need(row['Id']==image and re.fullmatch('sha256:[0-9a-f]{64}',image)and row['Architecture']=='arm64'and row['Os']=='linux','owned immutable native image differs')
    same(row['RepoTags'],[identity['tag']],'sole owned image tag required');need(not row.get('RepoDigests'),'unexpected published image reference')
    need(type(row['Config'])is dict and type(row['Config'].get('Labels'))is dict,'typed image labels required')
    labels=row['Config']['Labels']
    same({k:labels.get(k)for k in(LABEL,LABEL+'.source',LABEL+'.run')},
        {LABEL:identity['token'],LABEL+'.source':identity['source_sha'],LABEL+'.run':identity['run_id']},'image owner/source/run labels differ')
    fields(row['RootFS'],'Type Layers','closed image layer identity required')
    layers=row['RootFS']['Layers']
    need(row['RootFS']['Type']=='layers'and type(layers)is list and 0<len(layers)<=128 and len(set(layers))==len(layers)
         and all(type(p)is str and re.fullmatch('sha256:[0-9a-f]{64}',p)for p in layers),'immutable image layers differ')


def database(capture,packages):
    before,after=capture['db_before'],capture['db_after']
    same(before,after,'ALPM database changed during capture')
    fields(before,'nodes sha256','closed DB snapshot required')
    nodes=before['nodes'];need(type(nodes)is dict and 0<len(nodes)<=20000,'bounded DB snapshot required')
    same(before['sha256'],sha(encoded(nodes)),'DB snapshot digest differs')
    for path,node in nodes.items():
        need(type(path)is str and len(path)<=512 and '\\'not in path and
             (path=='.'or PurePosixPath(path).as_posix()==path and not path.startswith('/')and not any(p in('.','..')for p in path.split('/'))),'relative DB node required')
        need(type(node)is dict and node.get('kind')in('file','directory'),'typed DB node required')
        keys='kind dev ino mode uid gid links bytes mtime_ns ctime_ns'+(' sha256'if node['kind']=='file'else'')
        fields(node,keys,'closed DB identity required')
        for field in('dev','ino','mode','uid','gid','links','bytes','mtime_ns','ctime_ns'):integer(node[field])
        need(node['mode']<=0o7777 and node['links']>=1,'DB mode/link identity differs')
        if node['kind']=='file':
            checksum(node['sha256']);need(node['links']==1 and node['bytes']<=128*1024**2,'ordinary DB file required')
        if path!='.':need(nodes.get(str(PurePosixPath(path).parent),{}).get('kind')=='directory','DB parent missing')
    need(sum(n['bytes']for n in nodes.values()if n['kind']=='file')<=512*1024**2,'DB aggregate byte cap')
    need(nodes.get('.',{}).get('kind')==nodes.get('local',{}).get('kind')=='directory','initialized DB root/local required')
    version=nodes.get('local/ALPM_DB_VERSION',{})
    need(version.get('kind')=='file'and version['bytes']==2 and version['sha256']==sha(b'9\n'),'initialized local DB9 required')
    descriptions=capture['raw_descriptions']
    paths={'local/'+p['name']+'-'+p['version']+'/desc'for p in packages}
    need(type(descriptions)is dict and set(descriptions)==paths,'complete raw341 descriptions required')
    need({p for p,n in nodes.items()if p.startswith('local/')and p.count('/')==1 and n['kind']=='directory'}=={p.rsplit('/',1)[0]for p in paths},'local DB package namespace differs')
    need({p for p,n in nodes.items()if p.startswith('local/')and p.count('/')==1 and n['kind']=='file'}=={'local/ALPM_DB_VERSION'},'local DB file namespace differs')
    for package in packages:
        path='local/'+package['name']+'-'+package['version']+'/desc';text=descriptions[path]
        need(type(text)is str and len(text.encode())<=65536,'bounded raw description required')
        need(nodes.get(path,{}).get('kind')=='file'and nodes[path]['sha256']==sha(text.encode())and nodes[path]['bytes']==len(text.encode())
             and nodes.get(path[:-4]+'files',{}).get('kind')=='file','raw description digest/bytes/files differs')
        desc_fields={};key=None
        for line in text.splitlines():
            if line.startswith('%')and line.endswith('%'):
                need(re.fullmatch('%[A-Z][A-Z0-9_]*%',line)and line not in desc_fields,'duplicate raw description field');key=line;desc_fields[key]=[]
            elif line:need(key is not None and len(line)<=4096,'bounded typed description field');desc_fields[key].append(line)
        for k,v in {'%NAME%':[package['name']],'%VERSION%':[package['version']],'%ARCH%':[package['arch']],'%DEPENDS%':package['depend'],'%PROVIDES%':package['provides']}.items():
            same(sorted(desc_fields.get(k,[])),sorted(v),'raw description and ALPM metadata differ')


def prove(identity,inputs,validated_provider_selections):
    """Return deterministic runtime receipts only; malformed/missing joins refuse."""
    try:return _prove(identity,inputs,validated_provider_selections)
    except (KeyError,TypeError,IndexError,AttributeError,UnicodeError,OverflowError,RecursionError)as error:
        raise ValueError('malformed runtime proof input: '+type(error).__name__)from None


def _prove(identity,inputs,selections):
    identity_check(identity)
    need(type(inputs)is dict and set(inputs)==set(MEMBERS),'exact ten actual runtime inputs required; no future proof input')
    need(all(type(raw)is bytes and 0<len(raw)<=16*1024**2 for raw in inputs.values())and sum(map(len,inputs.values()))<=64*1024**2,'bounded runtime bytes required')
    obj={n:decode(raw)for n,raw in inputs.items()if n!='bootstrap/packages.lock'}
    source_map=obj['source-map.json'];fields(source_map,'schema purpose actual files','closed qualified source map required')
    same(source_map['schema'],1,'source map schema differs')
    need(source_map['actual']is None and source_map['purpose']=='FINITE_NATIVE_ARM_OFFLINE_BATCH_V2_COMPONENT_ONLY','source map role differs')
    mapped=source_map['files'];need(type(mapped)is dict and 0<len(mapped)<=2048,'bounded source-map files required')
    for path,row in mapped.items():
        need(type(path)is str and 0<len(path)<=512 and PurePosixPath(path).as_posix()==path and not path.startswith('/')
             and '\\'not in path and not any(p in('.','..')for p in path.split('/')),'relative source-map file required')
        fields(row,'bytes mode sha256','closed source file pin required');integer(row['bytes'],0,16*1024**2)
        need(type(row['mode'])is int and row['mode']in(0o644,0o755),'ordinary source file mode required');checksum(row['sha256'])
    same(sha(inputs['scripts/ci/inputs.lock.json']),INPUTS_SHA,'frozen original341 input bytes differ')
    pin=mapped['scripts/ci/inputs.lock.json']
    same([pin['bytes'],pin['sha256']],[len(inputs['scripts/ci/inputs.lock.json']),INPUTS_SHA],'source-map inventory pin differs')
    installed,lock=inventory(obj['scripts/ci/inputs.lock.json'])
    same(inputs['bootstrap/packages.lock'],lock,'actual producer lock differs from complete original341')
    producer=obj['bootstrap-owner.json']
    fields(producer,'status identity manifest_sha256 image packages_sha256 package_count','closed producer receipt required')
    need(producer['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP','producer did not complete original341 bootstrap')
    same(producer['identity'],identity,'producer/source/run identity differs')
    same(producer['manifest_sha256'],sha(inputs['source-map.json']),'producer source-map pin differs')
    same(producer['packages_sha256'],LOCK_SHA,'producer lock pin differs');same(producer['package_count'],341,'producer package count differs')
    image=producer['image'];need(type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'immutable actual producer image ID required')
    first,current=obj['bootstrap/image-inspect.json'],obj['current-image-inspect.json']
    image_check(first,identity,image);image_check(current,identity,image)
    same(current['Config'],first['Config'],'current image configuration differs from owned producer')
    same(current['RootFS'],first['RootFS'],'current immutable image layer identity differs')
    capture=obj['installed-provider-capture.json'];request=obj['installed-provider-capture-request.json']
    packages=[dict(installed[n],depend=sorted(installed[n]['depend']),provides=sorted(installed[n]['provides']))for n in sorted(installed)]
    same(request,dict(schema_version=1,image=image,inventory_sha256=LOCK_SHA,packages=packages,queries=[list(q)for q in QUERIES]),'actual provider request differs from frozen341 metadata')
    fields(capture,'schema_version status image inventory_sha256 inventory_lock packages cache_order queries db_before db_after raw_descriptions architecture uid page_size collector_sha256 retained_reader_sha256 libalpm elapsed_seconds hardware release','closed actual ALPM capture required')
    same(capture['schema_version'],1,'capture schema differs')
    need(capture['status']=='CAPTURED_INSTALLED_ALPM_SELECTIONS_ONLY'and capture['image']==image,'actual installed capture image/status differs')
    same(capture['inventory_sha256'],LOCK_SHA,'capture inventory pin differs');same(capture['inventory_lock'],lock.decode(),'complete captured lock differs')
    same(capture['packages'],packages,'all341 captured package metadata differs')
    order=capture['cache_order']
    need(type(order)is list and len(order)==341 and all(type(n)is str for n in order)and len(set(order))==341 and set(order)==set(installed),'complete unique actual ALPM cache order required')
    need(capture['architecture']in('aarch64','arm64'),'native capture architecture required')
    integer(capture['uid'],1,2**32-1);page=integer(capture['page_size'],4096,65536)
    need(page&(page-1)==0,'power-of-two captured page size required')
    need(type(capture['elapsed_seconds'])in(int,float)and math.isfinite(capture['elapsed_seconds'])and 0<=capture['elapsed_seconds']<=90,'bounded capture elapsed required')
    same(capture['hardware'],'NOT_RUN','capture hardware claim differs');same(capture['release'],'NOT_ADMITTED','capture release claim differs')
    collector=mapped[LANE+'capture_installed.py']['sha256'];helper=mapped[LANE+'retained-orphans-reader']['sha256']
    same(helper,HELPER_SHA,'retained installed-cache reader source pin differs')
    same(capture['collector_sha256'],collector,'captured collector source pin differs');same(capture['retained_reader_sha256'],helper,'captured reader source pin differs')
    library=capture['libalpm'];fields(library,'path sha256 version','closed captured ALPM library identity required')
    need(type(library['path'])is str and re.fullmatch(r'/usr/lib/libalpm\.so\.16(?:\.[0-9]+)*',library['path'])
         and type(library['version'])is str and re.fullmatch(r'16\.[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9_.-]+)?',library['version']),
         'captured ALPM16 identity differs');checksum(library['sha256'])
    database(capture,packages)
    receipt=obj['installed-provider-capture-result.json']
    same(receipt,dict(schema_version=1,status='ACTUAL_OWNED_CONTAINER_STDOUT_CAPTURED',image=image,inventory_sha256=LOCK_SHA,
        returncode=0,stdout_sha256=sha(inputs['installed-provider-capture.json']),collector_sha256=collector,
        retained_reader_sha256=helper,request_sha256=sha(inputs['installed-provider-capture-request.json']),
        source_map_sha256=sha(inputs['source-map.json'])),'actual capture receipt byte/source/image joins differ')
    origin=obj['installed-provider-capture-origin.json']
    fields(origin,'schema_version status supervised_log_path supervised_log_sha256 stream_origin separate_streams_captured acceptance_rule','closed supervised capture origin required')
    same(origin['schema_version'],1,'capture origin schema differs')
    need(origin['status']=='SUPERVISED_MERGED_STREAM_EQUALS_CANONICAL_COLLECTOR_STDOUT'
         and origin['stream_origin']=='owner.Actors.run merges stdout and stderr'
         and origin['separate_streams_captured']is False
         and origin['acceptance_rule']=='Exact byte equality with batch_graph.encoded(parsed collector JSON); any extra bytes are refused',
         'canonical supervised merged-stream qualification required')
    path=origin['supervised_log_path']
    need(type(path)is str and len(path)<=4096 and path.startswith('/')and PurePosixPath(path).as_posix()==path
         and '..'not in PurePosixPath(path).parts and path.endswith('/batch-graph-actors/installed-provider-capture.log'),
         'actual supervised capture log path required')
    same(origin['supervised_log_sha256'],sha(inputs['installed-provider-capture.json']),'supervised log/capture bytes differ')
    same(inputs['installed-provider-capture.json'],encoded(capture),'capture has extra merged-stream bytes')
    need(type(capture['queries'])is list and len(capture['queries'])==2,'two exact installed query observations required')
    need(type(selections)is list and len(selections)==2,'two caller graph-validated provider selections required')
    expected_selections=[]
    def offered(value):
        match=re.fullmatch(r'([A-Za-z0-9@_.+-]+)(?:=[^\s]+)?',value)
        need(match is not None,'bounded provider relation required');return match[1]
    for observed,(consumer,field,dependency)in zip(capture['queries'],QUERIES):
        fields(observed,'package field dependency candidates selected method','closed actual query observation required')
        same([observed['package'],observed['field'],observed['dependency']],[consumer,field,dependency],'actual query identity differs')
        need(observed['method']=='alpm_find_satisfier(actual_local_cache_order)'and dependency in installed[consumer]['depend'],'actual ALPM query method/consumer relation differs')
        matching=[n for n in order if n==dependency or any(offered(v)==dependency for v in installed[n]['provides'])]
        need(len(matching)>1,'all actual provider alternatives must remain visible')
        candidates=[dict(package=n,version=installed[n]['version'],cache_index=order.index(n))for n in matching]
        same(observed['candidates'],candidates,'complete actual ordered provider candidates differ')
        chosen=observed['selected'];fields(chosen,'name version','closed actual selected provider required')
        need(chosen['name']in matching and chosen['version']==installed[chosen['name']]['version'],'actual selected provider identity/version differs')
        context=dict(package=consumer,field=field,dependency=dependency,consumer=installed[consumer],
            candidates=[installed[n]for n in sorted(matching)])
        expected_selections.append(dict(package=consumer,field=field,dependency=dependency,provider=chosen['name'],evidence=dict(
            kind='INSTALLED_ALPM_CACHE_QUERY_V1',image=image,inventory_sha256=LOCK_SHA,
            capture_sha256=sha(inputs['installed-provider-capture.json']),metadata_sha256=sha(encoded(context)))))
    same(selections,expected_selections,'caller graph-validated selection/capture/context joins differ')
    return dict(schema_version=1,status='PASS_OWNED_IMAGE_AND_INSTALLED341_RUNTIME_JOINS',identity=dict(identity),
        authenticated=False,proof_scope='OWNED_PRODUCER_CURRENT_IMAGE_AND_INSTALLED_ALPM_INVENTORY_ONLY',
        image=image,package_count=341,inventory_sha256=LOCK_SHA,inputs_sha256=INPUTS_SHA,
        runtime_inputs={n:dict(bytes=len(inputs[n]),sha256=sha(inputs[n]))for n in MEMBERS},
        validated_provider_selections_sha256=sha(encoded(selections)),provider_selection_count=2,
        provider_selection_validation='CALLER_GRAPH_VALIDATION_JOINED_TO_EXACT_CAPTURE_AND_ORIGINAL_METADATA',
        alpm=dict(library),observed_uid=capture['uid'],observed_page_size=capture['page_size'],
        source_pin_acceptance='NOT_ESTABLISHED',recipe_buildinfo_holds_unchanged=True,
        build_admission='NOT_ESTABLISHED',installed_target='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',
        limitations=['Pure supplied-byte joins; no actor execution or independent live-daemon recheck.',
            'The parent must bind actual supervised observations and their immediate-preconsumer order; bytes alone cannot establish immediacy.',
            'Image/archive/inventory hashes do not supply missing PKGBUILD or BUILDINFO source provenance.',
            'No package-build, installed Asahi, physical M2, reproducibility, performance, capacity or release acceptance.'])
