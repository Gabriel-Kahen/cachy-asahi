# SPDX-License-Identifier: MIT
"""A finite Root-bound four-package packet; never invent native acceptance."""
import hashlib,importlib.util,json,os,re,stat,sys,tarfile,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
VERSIONS={'cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-apps':'0.1.0-5','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-1'}
HELPERS={'scripts/client/client.py': {'bytes': 28669, 'sha256': '48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7'}, 'scripts/release/release.py': {'bytes': 41320, 'sha256': 'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435'}, 'scripts/release/source_delivery.py': {'bytes': 16456, 'sha256': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'}}
SCOPE='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION'
STATUS='PASS_GENERIC16K_MANAGEMENT_CLI_PRIVATE_FIXTURES_ONLY'
TOOLS=('bash','env','uname','getconf','mount','python3','zsh','fish','cmp','mkdir','rm','ln','gpg','gpgv','gpgconf','gpg-agent','vercmp','bsdtar')

def need(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def relative(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name and all(p not in ('','.','..') for p in name.split('/')) and all(32<=ord(c)<127 for c in name),'safe relative path required');return name
def safe(path):
    path=Path(path).absolute();need('..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path
def read(path,cap=16*1024**2):
    path=safe(path);before=path.stat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap,'bounded single-link regular input required')
    with path.open('rb') as stream:raw=stream.read(cap+1)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(len(raw)==before.st_size<=cap and identity(before)==identity(path.stat()),'input drift');return raw
def pairs(rows):
    value={}
    for k,v in rows:need(k not in value,'duplicate JSON key');value[k]=v
    return value
def decode(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'))
def checked(root,ref):
    need(type(ref) is dict and set(ref)=={'path','bytes','sha256'} and type(ref['bytes']) is int and 0<ref['bytes']<=16*1024**2 and re.fullmatch('[0-9a-f]{64}',ref['sha256'] or ''),'bounded byte reference required')
    raw=read(Path(root)/relative(ref['path']));need(len(raw)==ref['bytes'] and sha(raw)==ref['sha256'],'input hash differs: '+ref['path']);return raw
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
def policy():
    need(not sys.flags.optimize,'ordinary unoptimized Python required')
    value=decode(read(HERE/'input-policy.json'))
    need(value.get('schema_version')==1 and value.get('status')=='ROOT_BOUND_NATIVE_INPUT_PACKET' and value.get('versions')==VERSIONS and
         re.fullmatch('[0-9a-f]{40}',value.get('packet_source') or '') and value.get('packet_index') is not None,
         'management16K native archives/decisions remain UNBOUND')
    return value
def verify_source(root):
    value=decode(read(HERE/'source-manifest.json'));need(value['schema_version']==1 and 1<=len(value['files'])<=256,'finite exact source manifest required')
    for name,pin in value['files'].items():checked(root,dict(path=name,**pin))
    return value

def cleanup_proof(value):
    if value.get('status')=='PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY':
        need(value['authority']=='PASS_REMOVED_AFTER_ACTOR_RETIREMENT' and value['borrowed_images_preserved'] is True,'native authority/borrowed image cleanup absent')
        for group in value['consumer_groups'].values():
            need(group['status'] in ('PASS_CONSUMERS_RETIRED','PASS_NO_CONSUMER_ACTORS') and
                all(row['status']=='PASS' and row['absence_verified'] is True for row in group['containers']),'native consumer absence absent')
        for image in value['dependency_images'].values():
            need(image=='NOT_STARTED' or type(image) is dict and (image['status']=='PASS_NO_DEPENDENCY_IMAGE_ACTORS' and image['absence_verified'] is True or
                image['status']=='PASS' and image['image']['absence_verified'] is True and image['probe']['absence_verified'] is True),'native dependency image cleanup absent')
        value=value['producer']
    need(value['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and value['consumer']['status']=='PASS_CONSUMERS_RETIRED' and
        all(row['status']=='PASS' and row['absence_verified'] is True for row in value['consumer']['containers']) and value['producer']['status']=='PASS' and
        value['producer']['image']['absence_verified'] is True and value['producer']['probe']['absence_verified'] is True,'native consumer/producer cleanup absent')

def packet(root):
    binding=policy();raw=checked(root,binding['packet_index']);value=decode(raw)
    need(value.get('schema_version')==1 and value.get('kind')=='ROOT_ACCEPTED_MANAGEMENT16K_NATIVE_INPUTS' and
         value.get('assembly_kind')=='FOUR_ROOT_ACCEPTED_NATIVE_PAIRS_FOR_PRIVATE16K_DATA_STAGE' and 'source' not in value and set(value.get('packages',{}))==set(VERSIONS),'exact native packet identity required')
    references={}
    def refs(node):
        if type(node) is dict:
            if set(node)=={'path','bytes','sha256'}:
                old=references.setdefault(node['path'],node);need(old==node,'conflicting packet references');checked(root,node)
            else:
                for child in node.values():refs(child)
        elif type(node) is list:
            for child in node:refs(child)
    refs(value);need(len(references)<=256,'closed native packet count bound')
    nodes=[]
    for p in Path(root).rglob('*'):
        nodes.append(p);need(len(nodes)<=512,'native packet node bound')
    paths={p.relative_to(root).as_posix() for p in nodes if p.is_file()}
    need(paths==set(references)|{binding['packet_index']['path']} and sum(v['bytes'] for v in references.values())<=64*1024**2,'native packet reference closure differs')
    parents={parent.as_posix() for name in paths for parent in Path(name).parents if parent.as_posix()!='.'}
    need(all(not p.is_symlink() and (p.is_file() or p.is_dir() and p.relative_to(root).as_posix() in parents) for p in nodes),'native packet node type/empty directory refused')
    for name,version in VERSIONS.items():
        row=value['packages'][name]
        need(row['version']==version and re.fullmatch('[0-9a-f]{40}',row['native_source']) and re.fullmatch('[0-9]+',row['native_run']) and
             row['qualification'] in ('NATIVE_PAIR_ONLY','NATIVE_PAIR_AND_DISPOSABLE_LIFECYCLE') and set(row['files'])=={'a','b'},'exact native pair/source/qualification required')
        need(row['files']['a']['sha256']==row['files']['b']['sha256'] and row['files']['a']['bytes']==row['files']['b']['bytes'] and
             row['files']['a']['path']!=row['files']['b']['path'],'two distinct identical native archives required')
        comparison=decode(checked(root,row['comparison']));checked(root,row['collection']);cleanup_proof(decode(checked(root,row['cleanup'])))
        need(comparison['status']=='contents-reproduced' and not comparison['errors'] and len(comparison['packages'])==1 and
            all(all(v.get(k) is True for k in ('bytes_equal','pkginfo_equal','buildinfo_equal','installed_contents_equal')) for v in comparison['packages'].values()),'complete native pair comparison absent')
        decision=decode(checked(root,row['decision']))
        if decision.get('status')=='ROOT_ACCEPTED_APPS_RUNTIME_CACHE_NATIVE_PAIRS_AND_INSTALLED_LIFECYCLE':
            need(name in ('cachy-asahi-apps','cachy-asahi-cache','cachy-asahi-repository-runtime') and row['qualification']=='NATIVE_PAIR_AND_DISPOSABLE_LIFECYCLE' and
                set(decision['products'])=={'cachy-asahi-apps','cachy-asahi-cache','cachy-asahi-repository-runtime'} and decision['source_sha']==row['native_source'] and
                str(decision['run_id'])==row['native_run'] and decision['distinct_native_builds']==6 and decision['cleanup']=='PASS' and decision['hardware']=='NOT_RUN','joint native Root decision identity differs')
            accepted=decision['products'][name];life=decision['lifecycle']
            need(accepted['version']==version and accepted['archive_bytes']==row['files']['a']['bytes'] and accepted['archive_sha256']==row['files']['a']['sha256'] and accepted['comparison']==comparison and
                life['status']=='PASS_APPS_CACHE_INSTALLED_LIFECYCLE' and life['base_count']==574 and life['installed_count']==577 and life['base574_preserved'] is True and life['user_preserved'] is True and
                life['plans_applied']=='NOT_APPLIED' and life['cache_apply']=='PASS_REAL_ALPM16_EMPTY_TRANSACTION','joint native Root pair/lifecycle joins differ')
        elif decision.get('status')=='ROOT_ACCEPTED_RUNTIME_NATIVE_PAIR_ONLY':
            need(name=='cachy-asahi-repository-runtime' and row['qualification']=='NATIVE_PAIR_ONLY' and decision['package']==name and
                decision['version']==version and decision['source_sha']==row['native_source'] and decision['run_id']==row['native_run'] and
                decision['archive']=={k:row['files']['a'][k] for k in ('bytes','sha256')} and decision['mandatory_checks']=='PASS_BOTH' and
                decision['original_comparison']==comparison,'original Runtime pair-only Root decision differs')
        elif decision.get('status')=='ROOT_ACCEPTED_ORPHANS_NATIVE_PAIR_AND_READONLY_LIFECYCLE':
            need(name=='cachy-asahi-orphans' and row['qualification']=='NATIVE_PAIR_AND_DISPOSABLE_LIFECYCLE' and decision['version']==version and
                decision['source_sha']==row['native_source'] and str(decision['run_id'])==row['native_run'] and decision['archive_sha256']==row['files']['a']['sha256'] and
                decision['archive_bytes']==row['files']['a']['bytes'] and decision['comparison']==comparison and decision['cleanup']=='PASS' and decision['native_checks_per_build']==18 and
                decision['lifecycle']['status']=='PASS_ORPHANS_INSTALLED_READONLY_LIFECYCLE' and decision['lifecycle']['base574_preserved'] is True and
                decision['lifecycle']['user_preserved'] is True and decision['hardware']=='NOT_RUN','original Orphans native Root decision differs')
        else:raise ValueError('unsupported original Root native decision')
        need(set(row['checks'])=={'a','b'} and row['checks']['a']['path']!=row['checks']['b']['path'] and row['check_markers'] and set(row['source_files'])>={'PKGBUILD','.SRCINFO','LICENSE','NOTICE'} and row['payload'], 'complete checks/source/license/payload refs required')
        for ref in row['checks'].values():
            text=checked(root,ref).decode('utf8','strict');need('Starting check()' in text and all(marker in text for marker in row['check_markers']) and not re.search(r'\bskipped=[1-9]|\bOK \(skipped=',text),'native check completion absent/skipped')
    return value

def package_payload(root,packet,checks):
    result={};origins={}
    for name,row in packet['packages'].items():
        need(4<=len(row['source_files'])<=64 and all(Path(file).name==file and file not in ('.','..') for file in row['source_files']),'finite ordinary recipe source set required')
        with tempfile.TemporaryDirectory(prefix='management16k-recipe-') as directory:
            staged=Path(directory)
            for file,ref in row['source_files'].items():(staged/file).write_bytes(checked(root,ref))
            recipe=checks.recipe(staged/'PKGBUILD');meta=recipe['metadata']
            need(not recipe['errors'] and meta['pkgname']==[name] and meta['pkgver'][0]+'-'+meta['pkgrel'][0]==row['version'] and
                meta['arch']==['any'] and meta['license']==['MIT'] and all(not meta.get(k) for k in ('install','provides','conflicts','replaces','backup')) and
                recipe['input_sha256']=={n:r['sha256'] for n,r in row['source_files'].items()} and
                all(Path(v).name==v and '://' not in v for v in meta['source']),'native recipe/source/metadata closure differs')
        reports=[]
        for pair in ('a','b'):
            ref=row['files'][pair];checked(root,ref);path=Path(root)/ref['path']
            need(path.name.endswith('.pkg.tar.xz') and ref['bytes']<=2*1024**2,'finite original native xz package required')
            report=checks.package(path);reports.append(report)
            need(not report['errors'] and not report['review'] and not report['elf'] and report['sha256']==ref['sha256'],'native data package inspection failed')
            meta=report['metadata'];need(meta['.PKGINFO']['pkgname']==[name] and meta['.PKGINFO']['pkgver']==[row['version']] and meta['.PKGINFO']['arch']==['any'] and meta['.PKGINFO']['license']==['MIT'] and
                 meta['.BUILDINFO']['pkgbuild_sha256sum']==[row['source_files']['PKGBUILD']['sha256']],'native BUILDINFO/identity/source join differs')
        need(reports[0]['members']==reports[1]['members'] and reports[0]['metadata']==reports[1]['metadata'],'native pair metadata/payload differs')
        members=reports[0]['members'];actual={k:v for k,v in members.items() if v['type']!='5' and k not in ('.PKGINFO','.BUILDINFO','.MTREE')}
        need(set(actual)==set(row['payload']) and 1<=len(actual)<=32,'complete product payload map required')
        parents={str(p) for name in actual for p in Path(name).parents if str(p)!='.'}
        need(all(k in parents for k,v in members.items() if v['type']=='5'),'unexpected package empty directory')
        with tarfile.open(Path(root)/row['files']['a']['path'],'r:xz') as archive:
            for dest,node in actual.items():
                relative(dest);expected=row['payload'][dest];source=expected['source'];need(Path(source).name==source and source in row['source_files'],'payload source association absent')
                raw=checked(root,row['source_files'][source]);info=node
                need(dest not in result and dest.startswith('usr/') and info['type']=='0' and info['mode']==expected['mode'] in (0o644,0o755) and
                     info['uid']==info['gid']==0 and info['size']==len(raw) and info['sha256']==sha(raw),'native source/license payload differs')
                member=next(m for m in archive if checks.clean_name(m.name)==dest);data=archive.extractfile(member).read()
                need(data==raw,'actual native archive payload differs');result[dest]=(info['mode'],data);origins[dest]=name
    helpers=decode(result['usr/lib/cachy-asahi-apps/helper-pins.json'][1])['files'];prefix='usr/share/cachy-asahi/repository-runtime/'
    need({k[len(prefix):]:dict(bytes=len(v[1]),sha256=sha(v[1])) for k,v in result.items() if k.startswith(prefix)}==helpers==HELPERS,'exact three unchanged installed runtime helpers differ')
    return result,origins
