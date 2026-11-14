#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Intake exact retained audio binaries and export their finite source handoff.

No payload/artifact code execution, package installation, network or publication.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
MAX_FILE=32*1024**2
MAX_TOTAL=64*1024**2
MAX_JSON=4*1024**2
VERSIONS={'alsa-ucm-conf-asahi':'10-2','asahi-audio':'4.1-2','bankstown':'1.1.0-4','speakersafetyd':'2.0.1-3','triforce-lv2':'0.3.2-3'}
API_FILES={'scripts/release/platform_audio_source_delivery.py','scripts/release/platform_audio_source_profiles.json','scripts/release/source_delivery.py','scripts/checks/package_checks.py'}
LEAVES={'source.tar','bundle.json','source-map.json','PKGBUILD','LICENSE.upstream','PACKAGING.LICENSE','REBUILD.txt'}


class Refused(ValueError):pass


def need(value,reason):
    if not value:raise Refused(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def descriptor(raw):return dict(bytes=len(raw),sha256=sha(raw))


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
        return result
    def invalid(_):raise Refused('NONINTEGER_JSON')
    value=json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
    need(type(value)is dict,'JSON_OBJECT_REQUIRED');return value


def relative(name):
    need(type(name)is str and name and '\\'not in name and '\0'not in name,'INVALID_RELATIVE_PATH')
    path=PurePosixPath(name)
    need(not path.is_absolute()and path.parts and path.as_posix()==name and '..'not in path.parts,'INVALID_RELATIVE_PATH')
    return name


def ordinary(path,maximum=MAX_FILE):
    path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents))and '..'not in path.parts,'ALIASED_INPUT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'UNSAFE_OR_OVERSIZED_INPUT')
        chunks=[];count=0
        while block:=os.read(fd,min(65536,maximum-count+1)):
            count+=len(block);need(count<=maximum,'INPUT_LIMIT');chunks.append(block)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
        need(count==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'CHANGED_INPUT')
        return b''.join(chunks)
    finally:os.close(fd)


def profile(raw,checksum):
    need(re.fullmatch('[0-9a-f]{64}',checksum or '')and sha(raw)==checksum,'NATIVE_PROFILE_PIN_MISMATCH')
    value=decode(raw)
    need(set(value)=={'schema','purpose','source_profile_sha256','api_files','packages','association_scope'}and type(value['schema'])is int and value['schema']==1
         and value['purpose']=='platform-audio-native-source-association'and type(value['packages'])is dict and type(value['api_files'])is dict
         and set(value['packages'])==set(VERSIONS)and set(value['api_files'])==API_FILES,'UNSUPPORTED_NATIVE_PROFILE')
    def pin(item,keys):
        need(type(item)is dict and set(item)==keys and type(item['bytes'])is int and 0<item['bytes']<=MAX_FILE
             and type(item['sha256'])is str and re.fullmatch('[0-9a-f]{64}',item['sha256']),'INVALID_NATIVE_PIN')
    for item in value['api_files'].values():pin(item,{'bytes','sha256'})
    for name,row in value['packages'].items():
        need(type(row)is dict and set(row)=={'version','archive','compiled_payloads','native_record','expected_generic_error_count'}
             and type(row['compiled_payloads'])is dict and type(row['expected_generic_error_count'])is int
             and row['expected_generic_error_count']>=0,'INVALID_NATIVE_ROW')
        pin(row['archive'],{'filename','bytes','sha256'})
        need(row['version']==VERSIONS[name]and Path(row['archive']['filename']).name==row['archive']['filename']
             and row['archive']['filename'].startswith(name+'-'+row['version']+'-'),'INVALID_NATIVE_IDENTITY')
        for item in row['compiled_payloads'].values():pin(item,{'bytes','sha256'})
        for path in row['compiled_payloads']:relative(path)
        record=row['native_record'];need(type(record)is dict and set(record)=={'source','run','validation_document'}
            and all(type(v)is str for v in record.values())and re.fullmatch('[0-9a-f]{40}',record['source'])
            and re.fullmatch('[1-9][0-9]*',record['run'])and record['validation_document'].startswith('docs/validation/'),'INVALID_NATIVE_RECORD')
        relative(record['validation_document'])
    return value


def load_api(value):
    for name,row in value['api_files'].items():
        need(descriptor(ordinary(ROOT/name,MAX_JSON))==row,'PROJECT_API_PIN_MISMATCH')
    path=ROOT/'scripts/release/platform_audio_source_delivery.py'
    spec=importlib.util.spec_from_file_location('audio_source_delivery_intake',path);api=importlib.util.module_from_spec(spec)
    exec(compile(ordinary(path,MAX_JSON),str(path),'exec'),api.__dict__)
    need(api.PROFILE_SHA256==value['source_profile_sha256'],'SOURCE_PROFILE_PIN_MISMATCH')
    need({name:p['version']for name,p in api.profiles().items()}==VERSIONS,'SOURCE_PROFILE_VERSIONS_DIFFER')
    return api


def native_archive(raw,row):
    need(descriptor(raw)=={k:row['archive'][k]for k in ('bytes','sha256')},'NATIVE_ARCHIVE_PIN_MISMATCH')
    # The independently pinned bytes are inspected as data, never loaded as ELF.
    found={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:*')as archive:
        for member in archive:
            if member.name in row['compiled_payloads']:
                need(member.name not in found and member.isfile()and member.size<=MAX_FILE,'INVALID_COMPILED_MEMBER')
                body=archive.extractfile(member).read(MAX_FILE+1)
                need(descriptor(body)==row['compiled_payloads'][member.name]and body.startswith(b'\x7fELF'),'NATIVE_COMPILED_PAYLOAD_PIN_MISMATCH')
                found[member.name]=descriptor(body)
    need(found==row['compiled_payloads'],'MISSING_NATIVE_COMPILED_PAYLOAD')
    return found


def files(root):
    """Exact private handoff namespace; links and special files are never read."""
    root=Path(root).absolute();found={};dirs=set();total=0
    need(not any(p.is_symlink()for p in(root,*root.parents)),'ALIASED_HANDOFF')
    for path in [root,*root.rglob('*')]:
        need(len(found)+len(dirs)<=128,'HANDOFF_NODE_LIMIT');info=path.lstat()
        need(info.st_uid==os.getuid(),'FOREIGN_HANDOFF_OWNER')
        if stat.S_ISDIR(info.st_mode):
            need(stat.S_IMODE(info.st_mode)==0o700,'HANDOFF_DIRECTORY_MODE')
            if path!=root:dirs.add(path.relative_to(root).as_posix())
        else:
            need(stat.S_ISREG(info.st_mode)and stat.S_IMODE(info.st_mode)==0o600,'HANDOFF_FILE_TYPE_OR_MODE')
            total+=info.st_size;need(total<=MAX_TOTAL,'HANDOFF_BYTE_LIMIT')
            name=relative(path.relative_to(root).as_posix());found[name]=ordinary(path)
    parents={str(p)for name in found for p in PurePosixPath(name).parents if str(p)!='.'}
    need(dirs==parents,'UNEXPECTED_EMPTY_HANDOFF_DIRECTORY')
    return found


def package_record(name,row,saved,bundle):
    binding=saved['archive_binding']
    need(binding is not None and binding['archive_sha256']==row['archive']['sha256']and binding['archive_bytes']==row['archive']['bytes']
         and len(binding['generic_guard_errors'])==row['expected_generic_error_count'],'BOUND_NATIVE_ASSOCIATION_DIFFERS')
    return dict(version=row['version'],native_record=row['native_record'],archive=dict(path='archives/'+row['archive']['filename'],**{k:row['archive'][k]for k in ('bytes','sha256')}),
        compiled_payloads=row['compiled_payloads'],source_bundle=dict(path='sources/'+name+'/source.tar',**descriptor(bundle)),archive_binding=binding,
        publication_blockers=saved['publication_blockers'],source_input_status=saved['source_input_status'])


def expected_manifest(value,profile_sha256,revision,rows,material):
    need(re.fullmatch('[0-9a-f]{40}',revision or ''),'OBSERVED_REVISION_REQUIRED')
    return dict(schema=1,purpose='native-bound-platform-audio-finite-source-handoff',profile_sha256=profile_sha256,
        observed_checkout_revision=revision,revision_is_not_source_authority=True,association_scope=value['association_scope'],packages=rows,
        files={name:dict(**descriptor(raw),mode=0o600)for name,raw in sorted(material.items())},
        signature_authentication='NOT_PERFORMED',compiled_source_correspondence='NOT_ESTABLISHED',complete_corresponding_source_accepted=False,legal_acceptance=False,
        native_build_replayed=False,payload_execution=False,publication='NOT_RUN',release='NOT_ADMITTED')


def verify(handoff,index_sha256,profile_sha256):
    material=files(handoff);index=material.pop('delivery.json')
    need(sha(index)==index_sha256,'HANDOFF_INDEX_PIN_MISMATCH')
    saved=decode(index);value=profile(material['native-inputs.json'],profile_sha256);api=load_api(value)
    wanted={'native-inputs.json'};rows={}
    for name,row in sorted(value['packages'].items()):
        archive_name='archives/'+row['archive']['filename'];wanted.add(archive_name);native_archive(material[archive_name],row)
        wanted.update('sources/'+name+'/'+leaf for leaf in LEAVES)
        raw=material['sources/'+name+'/source.tar']
        document,bodies=api.verified(raw,sha(raw),Path(handoff)/archive_name)
        need(material['sources/'+name+'/bundle.json']==api.encoded(document),'EXTERNAL_BUNDLE_MANIFEST_DIFFERS')
        need(material['sources/'+name+'/source-map.json']==api.encoded({k:api.s.digest(v)for k,v in sorted(bodies.items())}),'EXTERNAL_SOURCE_MAP_DIFFERS')
        for leaf in ('PKGBUILD','LICENSE.upstream','PACKAGING.LICENSE','REBUILD.txt'):
            need(material['sources/'+name+'/'+leaf]==bodies[leaf],'EXTERNAL_SOURCE_COPY_DIFFERS')
        rows[name]=package_record(name,row,document,raw)
    need(set(material)==wanted,'HANDOFF_MATERIAL_NAMESPACE_DIFFERS')
    expected=expected_manifest(value,profile_sha256,saved.get('observed_checkout_revision'),rows,material)
    need(saved==expected,'HANDOFF_INDEX_CONTENT_DIFFERS')
    return dict(status='VERIFIED_FIVE_NATIVE_BOUND_FINITE_SOURCE_EXPORTS',packages=len(rows),index_sha256=index_sha256,
        signature_authentication='NOT_PERFORMED',complete_corresponding_source_accepted=False,legal_acceptance=False,payload_execution=False,publication='NOT_RUN')


def export(source_root,archives,output,revision,profile_sha256):
    raw_profile=ordinary(HERE/'native-inputs.json',MAX_JSON);value=profile(raw_profile,profile_sha256);api=load_api(value)
    need(re.fullmatch('[0-9a-f]{40}',revision or ''),'OBSERVED_REVISION_REQUIRED')
    material={}
    for name,row in sorted(value['packages'].items()):
        raw=ordinary(Path(archives)/row['archive']['filename']);native_archive(raw,row);material[row['archive']['filename']]=raw
    output=Path(output).absolute();parent=output.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode)and parent.st_uid==os.getuid()and not stat.S_IMODE(parent.st_mode)&0o022,'OWNED_PRIVATE_OUTPUT_PARENT_REQUIRED')
    api.write_fresh(output,{'native-inputs.json':raw_profile});api.write_fresh(output/'archives',material);api.write_fresh(output/'sources',{})
    rows={}
    for name,row in sorted(value['packages'].items()):
        archive=output/'archives'/row['archive']['filename'];destination=output/'sources'/name
        api.pack(source_root,name,revision,destination,archive)
        raw=ordinary(destination/'source.tar');document,_=api.verified(raw,sha(raw),archive)
        rows[name]=package_record(name,row,document,raw)
    material=files(output);manifest=expected_manifest(value,profile_sha256,revision,rows,material);raw=encoded(manifest)
    fd=os.open(output/'delivery.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw)
    return verify(output,sha(raw),profile_sha256)


def main(argv=None):
    if not sys.flags.isolated:
        print('Python isolated mode (-I) is required',file=sys.stderr);return 2
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    build=sub.add_parser('export')
    for name in ('source-root','archives','output'):build.add_argument('--'+name,type=Path,required=True)
    build.add_argument('--source-revision',required=True)
    check=sub.add_parser('verify');check.add_argument('--handoff',type=Path,required=True);check.add_argument('--index-sha256',required=True)
    for command in (build,check):command.add_argument('--profile-sha256',required=True)
    args=parser.parse_args(argv)
    try:
        result=export(args.source_root,args.archives,args.output,args.source_revision,args.profile_sha256)if args.command=='export'else verify(args.handoff,args.index_sha256,args.profile_sha256)
    except (OSError,ValueError,KeyError,TypeError,tarfile.TarError)as error:
        print(json.dumps(dict(status='REFUSED_PLATFORM_AUDIO_SOURCE_HANDOFF',error_type=type(error).__name__,payload_execution=False,complete_corresponding_source_accepted=False)))
        return 2
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':sys.exit(main())
