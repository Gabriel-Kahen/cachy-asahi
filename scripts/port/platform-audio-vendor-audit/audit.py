#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Read delivered Cargo materials as data; never build, resolve or fetch code."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import sys
import tarfile
import tomllib
from urllib.parse import parse_qs

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
INTAKE_SHA256='be5be5ba3a47d462b70a821d1f88a54218fbe91c8341f7f03782e9ac9c6d06e8'
PACKAGES={'bankstown':'bankstown-1.1.0.tar.gz','speakersafetyd':'speakersafetyd-2.0.1.tar.gz','triforce-lv2':'triforce-lv2-0.3.2.tar.gz'}
REGISTRY='registry+https://github.com/rust-lang/crates.io-index'
KINDS={'dependencies','dev-dependencies','build-dependencies'}
MAX_FILE=8*1024**2
MAX_EXPANDED=64*1024**2
MAX_MEMBERS=8192


class Refused(ValueError):pass


def need(ok,code):
    if not ok:raise Refused(code)


def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def desc(raw):return dict(bytes=len(raw),sha256=digest(raw))


def relative(name):
    need(type(name)is str and name and '\\'not in name and '\0'not in name,'UNSAFE_MEMBER_PATH')
    p=PurePosixPath(name)
    need(not p.is_absolute()and p.parts and p.as_posix()==name and '..'not in p.parts,'UNSAFE_MEMBER_PATH')
    return name


def tar_data(raw,link_records=None):
    """Bound every header and expanded byte; do not extract or follow links."""
    need(type(raw)is bytes and 0<len(raw)<=32*1024**2,'ARCHIVE_INPUT_BOUND')
    files={};seen=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:*')as archive:
        for m in archive:
            need(len(seen)<MAX_MEMBERS,'ARCHIVE_MEMBER_LIMIT')
            name=relative(m.name.rstrip('/')if m.isdir()else m.name)
            need(name not in seen,'DUPLICATE_MEMBER');seen.add(name)
            if m.issym()and link_records is not None:
                relative(m.linkname)
                link_records[name]=m.linkname
                continue
            need(m.isfile()or m.isdir(),'UNHANDLED_ARCHIVE_LINK_OR_SPECIAL_FILE')
            if m.isdir():continue
            need(0<=m.size<=MAX_FILE,'ARCHIVE_MEMBER_BYTE_LIMIT');total+=m.size
            need(total<=MAX_EXPANDED,'ARCHIVE_EXPANDED_BYTE_LIMIT')
            body=archive.extractfile(m).read(MAX_FILE+1)
            need(len(body)==m.size,'TRUNCATED_MEMBER');files[name]=body
    if link_records is not None:
        need(not any(str(parent)in link_records for name in files for parent in PurePosixPath(name).parents),'FILE_BELOW_SOURCE_SYMLINK')
    need(not any(str(parent)in files for name in files for parent in PurePosixPath(name).parents),'FILE_AS_ARCHIVE_ANCESTOR')
    need(files,'EMPTY_ARCHIVE');return files


def json_data(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'DUPLICATE_CHECKSUM_JSON_KEY');result[key]=value
        return result
    def invalid(_):raise Refused('UNHANDLED_CHECKSUM_JSON_NUMBER')
    return json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)


def toml(raw):
    need(len(raw)<=1024**2,'MANIFEST_BYTE_LIMIT')
    return tomllib.loads(raw.decode('utf-8'))


def identity(document):
    package=document.get('package',{})
    need(type(package)is dict and type(package.get('name'))is str and type(package.get('version'))is str,'UNHANDLED_PACKAGE_IDENTITY')
    return package['name'],package['version']


def license_material(document,files,base):
    package=document['package'];prefix=base+'/'
    def text(raw):
        try:return 'UTF8_TEXT_PRESENT'if raw.decode('utf-8').strip()else 'EMPTY_OR_WHITESPACE'
        except UnicodeDecodeError:return 'NON_UTF8_BYTES'
    candidates={name[len(prefix):]:dict(**desc(raw),text_status=text(raw))for name,raw in sorted(files.items())if name.startswith(prefix)
        and re.match(r'(?i)^(license|copying|copyright|notice|unlicense)(?:[._-]|$)',PurePosixPath(name).name)}
    declared=package.get('license');declared_file=package.get('license-file')
    bound_file=None
    if type(declared_file)is str:
        key=posixpath.normpath(base+'/'+declared_file)
        if key.startswith(prefix)and key in files:bound_file=dict(path=declared_file,**desc(files[key]),text_status=text(files[key]))
    present=any(row['text_status']=='UTF8_TEXT_PRESENT'for row in candidates.values())or bool(bound_file and bound_file['text_status']=='UTF8_TEXT_PRESENT')
    holds=[]
    if declared_file and not bound_file:holds.append('DECLARED_LICENSE_FILE_NOT_BOUND_INSIDE_CRATE')
    if not present:holds.append('NO_NONEMPTY_UTF8_LICENSE_TEXT_CANDIDATE_INSIDE_CRATE')
    if declared is not None and type(declared)is not str:holds.append('UNHANDLED_LICENSE_DECLARATION')
    return dict(declared_expression=declared,declared_license_file=declared_file,bound_declared_file=bound_file,
        text_candidates=candidates,text_presence=present,holds=holds,terms_authenticated=False,legal_acceptance=False)


def vendor_data(raw):
    files=tar_data(raw);roots=set()
    for name in files:
        parts=PurePosixPath(name).parts
        need(len(parts)>=3 and parts[0]=='vendor','UNBOUND_VENDOR_NAMESPACE');roots.add('/'.join(parts[:2]))
    crates={};identities={};count=0
    for root in sorted(roots):
        prefix=root+'/';subset={name[len(prefix):]:body for name,body in files.items()if name.startswith(prefix)}
        need('.cargo-checksum.json'in subset and 'Cargo.toml'in subset,'MISSING_VENDOR_MANIFEST')
        checksum=json_data(subset['.cargo-checksum.json'])
        need(type(checksum)is dict and set(checksum)=={'files','package'}and type(checksum['files'])is dict,'UNHANDLED_CHECKSUM_FORMAT')
        package_checksum=checksum['package']
        need(package_checksum is None or(type(package_checksum)is str and re.fullmatch('[0-9a-f]{64}',package_checksum)),'INVALID_PACKAGE_CHECKSUM')
        for name,pin in checksum['files'].items():
            relative(name);need(type(pin)is str and re.fullmatch('[0-9a-f]{64}',pin),'INVALID_FILE_CHECKSUM')
        need(set(checksum['files'])==set(subset)-{'.cargo-checksum.json'},'VENDOR_MISSING_OR_EXTRA_FILE')
        for name,pin in checksum['files'].items():need(digest(subset[name])==pin,'VENDOR_FILE_CHECKSUM_DIFFERS')
        document=toml(subset['Cargo.toml']);name,version=identity(document)
        need((name,version)not in identities,'DUPLICATE_VENDOR_PACKAGE_IDENTITY');identities[name,version]=root
        count+=len(checksum['files'])
        crates[root]=dict(name=name,version=version,package_checksum=package_checksum,
            files_verified=len(checksum['files']),checksum_manifest=desc(subset['.cargo-checksum.json']),
            manifest=desc(subset['Cargo.toml']),license=license_material(document,files,root))
    return dict(archive=desc(raw),regular_files=len(files),expanded_bytes=sum(map(len,files.values())),
        declared_files_verified=count,crates=crates),files,identities


def version_tuple(value):
    if not(type(value)is str and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value)):return None
    return tuple(map(int,value.split('.')))


def matches(version,requirement):
    """Finite stable-numeric Cargo requirement subset; None means held format."""
    v=version_tuple(version)
    if v is None or type(requirement)is not str:return None
    terms=requirement.strip().split(',');out=[]
    for term in terms:
        match=re.fullmatch(r'\s*(\^|~|>=|<=|>|<|=)?\s*([0-9]+|\*)(?:\.([0-9]+|\*))?(?:\.([0-9]+|\*))?\s*',term)
        if not match:return None
        op=match[1]or '^';parts=[p for p in match.groups()[1:]if p is not None]
        if any(p!='*'and str(int(p))!=p for p in parts):return None
        if '*'in parts:
            n=parts.index('*')
            if op!='^'or any(p!='*'for p in parts[n:]):return None
            out.append(v[:n]==tuple(map(int,parts[:n])));continue
        nums=tuple(map(int,parts));lower=nums+(0,)*(3-len(nums))
        if op=='=':out.append(v[:len(nums)]==nums)
        elif op in ('>=','<'):out.append(v>=lower if op=='>='else v<lower)
        elif op in ('>','<='):out.append(v[:len(nums)]>nums if op=='>'else v[:len(nums)]<=nums)
        else:
            if op=='~':pivot=0 if len(nums)==1 else 1
            else:pivot=next((i for i,n in enumerate(nums)if n),len(nums)-1)
            upper=lower[:pivot]+(lower[pivot]+1,)+(0,)*(2-pivot)
            out.append(lower<=v<upper)
    return all(out)


def declaration_tables(document):
    result=[]
    for kind in sorted(KINDS):
        if kind in document:result.append((kind,document[kind]))
    targets=document.get('target',{});need(type(targets)is dict,'UNHANDLED_TARGET_TABLE')
    for target,body in sorted(targets.items()):
        need(type(body)is dict,'UNHANDLED_TARGET_TABLE')
        for kind in sorted(KINDS):
            if kind in body:result.append(('target.'+target+'.'+kind,body[kind]))
    return result


def declarations(document,manifest,material,crates):
    rows=[];base=posixpath.dirname(manifest);envelope=PurePosixPath(manifest).parts[0]+'/'
    for scope,table in declaration_tables(document):
        need(type(table)is dict,'UNHANDLED_DEPENDENCY_TABLE')
        for alias,original in sorted(table.items()):
            dep=dict(version=original)if type(original)is str else original
            row=dict(manifest=manifest,scope=scope,alias=alias,declaration=original,candidates=[],holds=[])
            if type(dep)is not dict:
                row['holds'].append('UNHANDLED_DEPENDENCY_DECLARATION');rows.append(row);continue
            name=dep.get('package',alias);requirement=dep.get('version','*');row.update(package=name,requirement=requirement)
            allowed={'version','package','features','optional','default-features','default_features','registry','git','rev','tag','branch','path','workspace'}
            if set(dep)-allowed:row['holds'].append('UNHANDLED_DEPENDENCY_KEYS')
            invalid=any(type(dep[k])is not str for k in set(dep)&{'version','package','registry','git','rev','tag','branch','path'})
            invalid|=any(type(dep[k])is not bool for k in set(dep)&{'optional','default-features','default_features'})
            invalid|='features'in dep and not(type(dep['features'])is list and all(type(x)is str for x in dep['features']))
            if invalid:row['holds'].append('UNHANDLED_DEPENDENCY_FIELD_TYPES')
            if len(set(dep)&{'git','path','registry'})>1:row['holds'].append('MULTIPLE_DEPENDENCY_SOURCE_SELECTORS')
            if 'workspace'in dep:row['holds'].append('WORKSPACE_INHERITANCE_NOT_IMPLEMENTED')
            if 'git'in dep:
                row['source_kind']='git';row['holds'].append('GIT_COMMIT_TO_VENDOR_TREE_PROVENANCE_NOT_ESTABLISHED')
                if not(type(dep.get('rev'))is str and re.fullmatch('[0-9a-f]{40}',dep['rev'])):row['holds'].append('GIT_DECLARATION_NOT_EXACT_COMMIT')
            elif 'path'in dep:
                row['source_kind']='path';path=dep['path']
                if type(path)is str and not path.startswith('/')and '\\'not in path and '\0'not in path:
                    key=posixpath.normpath(base+'/'+path)+'/Cargo.toml'
                    if key.startswith(envelope)and key in material:
                        target=toml(material[key]);actual,version=identity(target);match=matches(version,requirement)
                        if actual==name and match is True:row['candidates'].append(key)
                        if match is None:row['holds'].append('UNHANDLED_VERSION_REQUIREMENT')
                if not row['candidates']:row['holds'].append('PATH_DEPENDENCY_NOT_BOUND_TO_SUPPLIED_MANIFEST')
                rows.append(row);continue
            else:row['source_kind']='registry'
            if 'registry'in dep:row['holds'].append('NAMED_REGISTRY_CONFIGURATION_NOT_IMPLEMENTED')
            unsupported=False
            for root,crate in sorted(crates.items()):
                if crate['name']!=name:continue
                match=matches(crate['version'],requirement)
                if match is None:unsupported=True
                if match is True:row['candidates'].append(root)
            if unsupported:row['holds'].append('UNHANDLED_VERSION_REQUIREMENT')
            if not row['candidates']:row['holds'].append('NO_SUPPLIED_VENDOR_MATCH_FOR_DECLARATION')
            if len(row['candidates'])>1:row['holds'].append('MULTIPLE_SUPPLIED_VERSION_CANDIDATES')
            row['activation']='NOT_EVALUATED_FEATURES_TARGETS_DEV_BUILD';rows.append(row)
    return rows


def source_relation(declaration,target,local_manifests):
    """Lexical source join only. None means unresolved rather than a match."""
    original=declaration['declaration'];dep=dict(version=original)if type(original)is str else original
    if declaration['holds']and any(x in declaration['holds']for x in ('WORKSPACE_INHERITANCE_NOT_IMPLEMENTED','MULTIPLE_DEPENDENCY_SOURCE_SELECTORS','UNHANDLED_DEPENDENCY_KEYS','UNHANDLED_DEPENDENCY_FIELD_TYPES')):return None
    origin=target[2];kind=declaration['source_kind']
    if kind=='registry':return None if 'registry'in dep or origin.startswith('registry+')and origin!=REGISTRY else origin==REGISTRY
    if kind=='path':return origin==''and any(p in declaration['candidates']for p in local_manifests.get(target[:2],[]))
    if not origin.startswith('git+'):return False
    body,separator,commit=origin[4:].rpartition('#')
    if not separator or not re.fullmatch('[0-9a-f]{40}',commit):return None
    url,_,query=body.partition('?')
    if dep.get('git')!=url:return False
    selectors=set(dep)&{'rev','branch','tag'}
    if len(selectors)>1:return None
    if 'rev'in dep:
        rev=dep['rev']
        return rev==commit if type(rev)is str and re.fullmatch('[0-9a-f]{40}',rev)else None
    if selectors:
        selector=next(iter(selectors));return parse_qs(query).get(selector)==[dep[selector]]
    return True


def source_data(raw):
    links={};files=tar_data(raw,links);roots={PurePosixPath(name).parts[0]for name in set(files)|set(links)}
    need(len(roots)==1,'UNHANDLED_SOURCE_ARCHIVE_ROOTS')
    root=next(iter(roots));need(root+'/Cargo.toml'in files and root+'/Cargo.lock'in files,'MISSING_ROOT_CARGO_MATERIAL')
    return files,root,links


def lock_data(raw):
    lock=toml(raw);need(type(lock.get('version'))is int and lock['version']in(3,4)and type(lock.get('package'))is list,'UNHANDLED_CARGO_LOCK_FORMAT')
    entries={}
    for row in lock['package']:
        need(type(row)is dict and set(row)<={'name','version','source','checksum','dependencies','replace'},'UNHANDLED_LOCK_PACKAGE_FIELDS')
        key=(row.get('name'),row.get('version'),row.get('source',''))
        need(all(type(x)is str for x in key)and key not in entries,'DUPLICATE_OR_INVALID_LOCK_PACKAGE')
        need(type(row.get('dependencies',[]))is list and all(type(x)is str for x in row.get('dependencies',[])),'UNHANDLED_LOCK_DEPENDENCIES')
        entries[key]=row
    return lock,entries


def lock_reference(reference,entries):
    match=re.fullmatch(r'([^ ()]+)(?: ([^ ()]+))?(?: \(([^()]+)\))?',reference)
    need(match is not None,'UNHANDLED_LOCK_DEPENDENCY_REFERENCE')
    candidates=[key for key in entries if key[0]==match[1]and(match[2]is None or key[1]==match[2])and(match[3]is None or key[2]==match[3])]
    need(len(candidates)==1,'MISSING_OR_AMBIGUOUS_LOCK_DEPENDENCY');return candidates[0]


def audit_project(source_raw,vendor,files,identities,components):
    source,root,links=source_data(source_raw);lock_raw=source[root+'/Cargo.lock'];lock,entries=lock_data(lock_raw)
    need(digest(lock_raw)==components['cargo_lock_sha256'],'RECORDED_LOCK_HASH_DIFFERS')
    bindings=[];edges=[];declared=[];bound=set();holds=[];errors=[]
    local_manifests={}
    for path,raw in source.items():
        if PurePosixPath(path).name=='Cargo.toml':
            document=toml(raw);key=identity(document);local_manifests.setdefault(key,[]).append(path)
    for key,row in sorted(entries.items()):
        name,version,origin=key;manifest=None
        if origin.startswith('registry+'):
            vendor_root=identities.get((name,version))
            if origin!=REGISTRY:holds.append(dict(code='ALTERNATIVE_REGISTRY_NOT_AUTHENTICATED',package=list(key)))
            if vendor_root is None:errors.append(dict(code='LOCKED_REGISTRY_PACKAGE_MISSING',package=list(key)));continue
            crate=vendor['crates'][vendor_root]
            if not(type(row.get('checksum'))is str and re.fullmatch('[0-9a-f]{64}',row['checksum'])and row['checksum']==crate['package_checksum']):
                errors.append(dict(code='LOCK_VENDOR_PACKAGE_CHECKSUM_DIFFERS',package=list(key)));continue
            manifest=vendor_root+'/Cargo.toml';bound.add(vendor_root)
            bindings.append(dict(package=list(key),vendor_root=vendor_root,checksum_join='LOCK_AND_SELF_DECLARED_VENDOR_ONLY',raw_crate_authentication='NOT_ESTABLISHED'))
        elif origin.startswith('git+'):
            candidate=identities.get((name,version));holds.append(dict(code='LOCKED_GIT_PROVENANCE_NOT_ESTABLISHED',package=list(key),candidate=candidate))
            if candidate:manifest=candidate+'/Cargo.toml'
            else:errors.append(dict(code='LOCKED_GIT_MATERIAL_MISSING',package=list(key)))
        elif origin=='':
            candidates=local_manifests.get((name,version),[])
            if len(candidates)==1:manifest=candidates[0]
            else:errors.append(dict(code='LOCKED_PATH_PACKAGE_MISSING_OR_AMBIGUOUS',package=list(key)))
        else:holds.append(dict(code='UNHANDLED_LOCK_SOURCE',package=list(key)))
        if 'replace'in row:holds.append(dict(code='LOCK_REPLACEMENT_NOT_IMPLEMENTED',package=list(key)))
        if manifest is None:continue
        material=source if not manifest.startswith('vendor/')else files;document=toml(material[manifest])
        decl=declarations(document,manifest,material,vendor['crates']);declared.extend(decl)
        if any(k in document for k in ('workspace','patch','replace')):holds.append(dict(code='WORKSPACE_PATCH_REPLACE_RESOLUTION_NOT_IMPLEMENTED',manifest=manifest))
        for reference in row.get('dependencies',[]):
            target=lock_reference(reference,entries);source_match=[];unhandled=False
            for d in decl:
                if d.get('package')!=target[0]:continue
                match=matches(target[1],d.get('requirement'));relation=source_relation(d,target,local_manifests)
                if match is None or relation is None:unhandled=True
                if match is True and relation is True:source_match.append(d)
            if not source_match:
                diagnostic=dict(code='UNHANDLED_LOCK_EDGE_BINDING'if unhandled else 'LOCK_EDGE_WITHOUT_SUPPORTED_MANIFEST_DECLARATION',owner=list(key),target=list(target))
                (holds if unhandled else errors).append(diagnostic)
            edges.append(dict(owner=list(key),target=list(target),declarations=[dict(scope=d['scope'],alias=d['alias'])for d in source_match],activation='NOT_EVALUATED',
                status='LEXICALLY_JOINED'if source_match else 'HELD_UNHANDLED_FORMAT'if unhandled else 'UNBOUND'))
    expected=[dict(file_count=vendor['crates'][r]['files_verified'],license=vendor['crates'][r]['license']['declared_expression'],name=vendor['crates'][r]['name'],
        package_checksum=vendor['crates'][r]['package_checksum'],root=r,version=vendor['crates'][r]['version'])for r in sorted(bound,key=lambda r:(vendor['crates'][r]['name'],vendor['crates'][r]['version']))]
    if expected!=components['locked_components']or len(bound)!=components['registry_crates']:errors.append(dict(code='RECORDED_COMPONENT_JOIN_DIFFERS'))
    license_root=license_material(toml(source[root+'/Cargo.toml']),source,root)
    return dict(source_archive=desc(source_raw),lock=desc(lock_raw),lock_version=lock['version'],registry_packages=len(bound),
        bindings=bindings,lock_edges=edges,declarations=declared,unbound_vendor_roots=sorted(set(vendor['crates'])-bound),
        root_license=license_root,inert_source_symlinks=links,holds=holds,errors=errors),bound


def audit_materials(materials):
    need(set(materials)==set(PACKAGES),'THREE_COMPILED_PACKAGES_REQUIRED')
    vendor_bytes={bodies['cargo-vendor-117.tar.xz']for bodies in materials.values()}
    need(len(vendor_bytes)==1,'SHARED_VENDOR_BYTES_DIFFER');raw=next(iter(vendor_bytes))
    vendor,files,identities=vendor_data(raw);projects={};bound=set()
    for name,bodies in sorted(materials.items()):
        components=json_data(bodies['COMPONENTS.json']);saved=components['vendor']
        need(all(vendor.get(k)==saved[k]for k in ('regular_files','expanded_bytes'))and len(vendor['crates'])==saved['crates']
            and desc(raw)=={k:saved[k]for k in ('bytes','sha256')},'RECORDED_VENDOR_OBSERVATION_DIFFERS')
        projects[name],used=audit_project(bodies[PACKAGES[name]],vendor,files,identities,components);bound.update(used)
    vendor_declarations=[]
    for root in sorted(vendor['crates']):vendor_declarations.extend(declarations(toml(files[root+'/Cargo.toml']),root+'/Cargo.toml',files,vendor['crates']))
    unbound=sorted(set(vendor['crates'])-bound)
    errors=[dict(package=name,**error)for name,p in projects.items()for error in p['errors']]
    if unbound:errors.append(dict(code='VENDOR_MATERIAL_NOT_BOUND_BY_ANY_DELIVERED_LOCK',roots=unbound))
    return dict(schema=1,purpose='platform-audio-delivered-cargo-vendor-integrity-coverage',status='AUDITED_DATA_WITH_HOLDS'if not errors else 'INTEGRITY_OR_COVERAGE_ERRORS',
        vendor=vendor,vendor_declarations=vendor_declarations,packages=projects,union_locked_vendor_roots=sorted(bound),unbound_vendor_roots=unbound,errors=errors,
        holds=['RAW_CRATE_ARCHIVE_AUTHENTICITY_NOT_ESTABLISHED','CARGO_FEATURE_TARGET_CONFIGURATION_RESOLUTION_NOT_IMPLEMENTED',
            'DECLARATIONS_WITHOUT_SUPPLIED_MATCH_ARE_NOT_PROOF_OF_ACTIVATED_BUILD_DEPENDENCY','GIT_COMMIT_TO_VENDOR_TREE_PROVENANCE_NOT_ESTABLISHED',
            'COMPILER_STD_LINKER_RUNTIME_CORRESPONDING_SOURCES_NOT_DELIVERED','LICENSE_DECLARATIONS_AND_TEXT_CANDIDATES_ARE_NOT_LEGAL_ACCEPTANCE'],
        complete_corresponding_source_accepted=False,legal_acceptance=False,raw_crate_authentication='NOT_ESTABLISHED_NO_RAW_CRATE_BYTES',
        code_execution=False,network=False,native_build=False,publication='NOT_RUN')


def intake_module():
    path=ROOT/'scripts/port/platform-audio-sources/intake.py'
    with path.open('rb')as stream:raw=stream.read(65537)
    need(len(raw)<=65536,'FROZEN_INTAKE_API_BYTE_LIMIT')
    need(digest(raw)==INTAKE_SHA256,'FROZEN_INTAKE_API_PIN_DIFFERS')
    spec=importlib.util.spec_from_file_location('cargo_vendor_intake',path);module=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def delivered(handoff,index_sha256,profile_sha256):
    intake=intake_module();intake.verify(handoff,index_sha256,profile_sha256)
    value=intake.profile(intake.ordinary(Path(handoff)/'native-inputs.json'),profile_sha256);api=intake.load_api(value);materials={};bundles={}
    for name in sorted(PACKAGES):
        raw=intake.ordinary(Path(handoff)/'sources'/name/'source.tar');saved,bodies=api.verified(raw,digest(raw))
        materials[name]=bodies;bundles[name]=dict(**desc(raw),archive_binding=saved['archive_binding'],publication_blockers=saved['publication_blockers'])
    report=audit_materials(materials)
    report.update(handoff=dict(index_sha256=index_sha256,native_profile_sha256=profile_sha256),source_bundles=bundles,
        auditor=dict(**desc(intake.ordinary(HERE/'audit.py')),intake_api_sha256=INTAKE_SHA256))
    return report,api


def main():
    if not sys.flags.isolated:
        print('Python isolated mode (-I) is required',file=sys.stderr);return 2
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('handoff','index-sha256','profile-sha256','output'):parser.add_argument('--'+key,required=True)
    args=parser.parse_args()
    try:
        report,api=delivered(Path(args.handoff),args.index_sha256,args.profile_sha256)
        raw=encoded(report);api.write_fresh(Path(args.output),{'vendor-audit.json':raw})
        print(json.dumps(dict(status=report['status'],report=desc(raw),vendor_crates=len(report['vendor']['crates']),
            files_verified=report['vendor']['declared_files_verified'],errors=len(report['errors']),complete_corresponding_source_accepted=False,legal_acceptance=False,code_execution=False)))
        return int(bool(report['errors']))
    except (OSError,ValueError,KeyError,TypeError,tarfile.TarError)as error:
        reason=str(error)if type(error)is Refused else 'MATERIAL_OR_FORMAT_REFUSED'
        print(json.dumps(dict(status='REFUSED_VENDOR_AUDIT',error_type=type(error).__name__,reason=reason,
            format_holds=[reason]if reason.startswith('UNHANDLED_')else [],complete_corresponding_source_accepted=False,legal_acceptance=False,code_execution=False)))
        return 2


if __name__=='__main__':sys.exit(main())
