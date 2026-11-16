#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent DATA-only reader. Root authenticates the binding and artifact externally."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path,PurePosixPath
import re
import stat
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(path,limit=64*1024**2):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=limit,'bounded ordinary DATA file')
    return json.loads(path.read_bytes())


def bounded_info(max_headers):
    state={'headers':0,'ended':False}
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            block=archive.fileobj.read(512)
            if block==bytes(512):state['ended']=True
            else:
                state['headers']+=1;need(state['headers']<=max_headers,'tar raw header count bound')
            item=(cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf') else cls.frombuf(block,archive.encoding,archive.errors))
            item.offset=archive.fileobj.tell()-512
            return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0<=self.size<=65536,'tar PAX metadata bound');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0<=self.size<=65536,'tar long-name bound');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse tar refused')
        _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
    return Info,state


def end_tar(archive,state):
    tail=0
    while block:=archive.fileobj.read(65536):
        tail+=len(block);need(not any(block) and tail<=16*1024**2,'bounded zero-only tar tail required')
    need(state['ended'] and tail>=512 and archive.fileobj.tell()%512==0,'complete tar termination required')


def unpack_export(path,destination,limit=4*1024**3):
    need(path.stat().st_size<=limit and not destination.exists(),'bounded export/fresh private DATA output')
    destination.mkdir(mode=0o700);seen=set();total=0
    info,state=bounded_info(256)
    with tarfile.open(path,'r|',tarinfo=info) as archive:
        for item in archive:
            need(not item.sparse and not any(k.startswith('GNU.sparse') for k in item.pax_headers),'sparse export refused')
            name=item.name.removeprefix('./');parts=PurePosixPath(name).parts
            if item.isdir():
                need(parts==('output',),'only export root directory');continue
            need(len(parts)==2 and parts[0]=='output' and item.isfile() and parts[1] not in seen and re.fullmatch('[A-Za-z0-9._+-]+',parts[1]),'flat regular-only export namespace')
            seen.add(parts[1]);cap=2*1024**3 if parts[1].endswith('.pkg.tar.zst') else 64*1024**2
            total+=item.size;need(len(seen)<=64 and item.size<=cap and total<=limit,'export payload bounds')
            with (destination/parts[1]).open('xb') as output:
                source=archive.extractfile(item)
                while block:=source.read(1024**2):output.write(block)
            (destination/parts[1]).chmod(item.mode & 0o777)
            archive.members.clear()
        end_tar(archive,state)


def package_inventory(path):
    # Python3.14's stdlib zstd, never an external process or installed package.
    need(sys.version_info >= (3,14),'Python>=3.14 with zstd required for package DATA')
    import compression.zstd
    result={};total=0
    info,state=bounded_info(400000)
    with compression.zstd.ZstdFile(path,'rb') as source,tarfile.open(fileobj=source,mode='r|',tarinfo=info) as archive:
        for item in archive:
            need(not item.sparse and not any(k.startswith('GNU.sparse') for k in item.pax_headers),'sparse package refused')
            name=item.name.removeprefix('./').rstrip('/')
            if name in ('','.'):continue
            p=PurePosixPath(name)
            need(not p.is_absolute() and '..' not in p.parts and name not in result,'unique contained package path')
            row=dict(mode=item.mode & 0o777)
            if item.isdir():row['kind']='dir'
            elif item.issym():row.update(kind='link',target=item.linkname)
            else:
                need(item.isfile() and item.size<=2*1024**3,'regular package payload only')
                total+=item.size;need(total<=16*1024**3,'package expanded byte cap')
                h=hashlib.sha256();stream=archive.extractfile(item)
                while block:=stream.read(1024**2):h.update(block)
                row.update(kind='file',bytes=item.size,sha256=h.hexdigest())
            result[name]=row;need(len(result)<=200000,'package entry cap');archive.members.clear()
        end_tar(archive,state)
    return result


def check_volume(evidence,producer,b,domain,actual):
    spec=importlib.util.spec_from_file_location('llvm_reader_volume',ROOT/'hosted/volume.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
    owner=v.owner(dict(b,operation=v.OP));need(producer['volume_owner']==owner and producer['inner_operation']==v.INNER,'explicit v2 owner and unchanged v1 actor delegation')
    need((producer['actor'],producer['init'],producer['volume'])==(owner['actor'],owner['init'],owner['volume']),'same exact owned namespaces')
    base=evidence/'llvm-build';initialized=load(base/'volume-initialization.json');v.receipt(initialized,owner)
    need(initialized==producer['volume_initialization']==load(base/'inputs/volume-initialization.json'),'whole actual initializer receipt joins')
    admission=load(base/'inputs/volume-admission.json');need(admission==v.admission(owner) and sha(base/'inputs/volume-admission.json')==producer['volume_admission_sha256'],'exact nonroot volume pre-entry admission')
    v.volume_identity(load(base/'volume-before.json'),owner)
    v.inspect_init(load(base/'initializer-before.json'),owner,b['image']);finished=load(base/'initializer-after.json');v.inspect_init(finished,owner,b['image'])
    need(finished['State']['Status']=='exited' and finished['State']['ExitCode']==0 and not finished['State']['Running'] and finished['State']['Pid']==0 and not finished['State']['OOMKilled'],'natural bounded initializer exit')
    domain.inspect_actor(actual,producer['actor'],producer['volume'],b['image'],Path(producer['inputs_path']),Path(producer['source_intake']['root']),owner,producer['volume_admission_sha256'])


def read(binding,binding_sha,evidence,output):
    need(sha(binding)==binding_sha and not output.exists(),'external Root binding digest and fresh DATA output required')
    b=load(binding,1024**2)
    need(b['scope']=='ROOT_AUTHENTICATED_LLVM23_DATA_READER_ONLY' and b['operation']=='llvm23-source-reference-native-v2','independent Root Reader scope')
    spec=importlib.util.spec_from_file_location('llvm_reader_source_guards',ROOT/'hosted/common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    c.verify_source(ROOT,b['source_map_sha256'])
    h=load(evidence/'hosted.json');producer=load(evidence/'llvm-build/producer.json')
    for key in ['source','ref','run','job','approval','source_map_sha256']:
        need(h['binding'][key]==producer['binding'][key]==b[key],'same externally authenticated Source/ref/run/job/approval')
    readback=load(evidence/'source-readback.json');job=load(evidence/'job-metadata.json')
    need(all(readback['binding'][k]==b[k] for k in ['source','ref','run','approval','source_map_sha256']) and readback['status']=='PASS_EXACT_HOSTED_SOURCE_READBACK','published Source readback join')
    need(job['total_count']==len(job['jobs'])==1 and str(job['jobs'][0]['id'])==b['job'] and str(job['jobs'][0]['run_id'])==b['run'] and job['jobs'][0]['head_sha']==b['source'] and job['jobs'][0]['name']=='llvm23-native-v2','actual provider job/source join')
    need(h['status']=='LLVM23_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER' and h['cleanup']['image_absent'] and h['cleanup']['gpg_agent_absent'] and not h['cleanup']['errors'],'hosted result/retirement incomplete')
    need(producer['status']=='COMPLETED_EXPORTED_RETIRED' and producer['image']==b['image'] and producer['owned_resources_absent'] and not producer.get('cleanup_errors'),'owned producer result/absence incomplete')
    need(sha(evidence/'llvm-build/export.tar')==producer['export']['sha256']==b['export_sha256'],'whole exported DATA blob differs')
    need(sha(evidence/'bootstrap/packages.lock')=='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453','actual signed349 lock')
    signatures=load(evidence/'bootstrap/signatures.json')
    need(len(signatures)==257,'all 257 signed payload observations required')
    signer='68B3537F39A313B3E574D06777193F152BDBE6A6'
    for row in signatures.values():
        lines=[line.split() for line in row['status'].splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        need(row['exit_code']==0 and len(lines)==1 and signer in (lines[0][2],lines[0][-1]),'approved signer status/exit mismatch')
        need(not any(token in row['status'] for token in ['BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG']),'signature failure status')
    output.mkdir(mode=0o700);data=output/'actor-data';unpack_export(evidence/'llvm-build/export.tar',data)
    result=load(data/'actor-result.json')
    need(result['status']=='PASS_LLVM23_ACTOR_DATA' and result['image']==b['image'] and result['source']=={'sha':b['source'],'ref':b['ref'].removeprefix('refs/heads/')} and result['run']==b['run'] and result['job']==b['job'],'same actual LLVM actor result')
    for name,row in result['output_files'].items():
        need(re.fullmatch('[A-Za-z0-9._+-]{1,128}',name) and name not in ('.','..'),'literal flat actor output name')
        path=data/name;need(path.stat().st_size==row['bytes'] and sha(path)==row['sha256'],'complete actor output byte join')
    need(set(p.name for p in data.iterdir())==set(result['output_files'])|{'actor-result.json'},'complete flat actor output membership')
    runtime=load(data/'runtime.json');spec=importlib.util.spec_from_file_location('llvm_reader_runtime',ROOT/'actor/runtime.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.validate(runtime['entry'],runtime['parent'])
    actual=load(evidence/'llvm-build/actor-inspect.json');finished=load(evidence/'llvm-build/actor-finished.json')
    need(actual['Image']==finished['Image']==b['image'] and finished['State']['ExitCode']==0 and not finished['State']['OOMKilled'],'actual actor image/exit')
    for name in ['makepkg','probe','tools','runtimes','check','pkginfo','buildinfo','tool-owners','packages-unsorted']:
        row=load(data/(name+'.json'));life=row['lifecycle']
        need(row['success'] and row['returncode']==0 and sha(data/row['log'])==row['log_pin']['sha256'] and (data/row['log']).stat().st_size==row['log_pin']['bytes'] and 0<row['timeout_seconds']<=row['requested_seconds']<=13800 and life.get('natural_exit') and life.get('group_absent') and life.get('retirement')=='REAPED' and not life.get('forced_cleanup') and life.get('ownership_lost') is False and life.get('leader_held_until_group_inspection') is True and life.get('exit_observed_via_waitpid') is True and life.get('exit')==0,'natural owned command completion')
        if name in ['probe','tools','runtimes','check']:
            need(row['argv']==['/usr/bin/bash','/inputs/packages/port/llvm23-source-reference/build.sh',name],'exact Source build stage argv')
        elif name=='makepkg':
            need(row['argv']==['/usr/bin/makepkg','--config','/work/makepkg.conf','--cleanbuild','--nosign','--noconfirm','--log'],'ordinary dependency-checked unsiged makepkg argv')
    admission=load(data/'admission.json');contract=load(ROOT/'contract.json')
    need(sha(data/'admission.json')==producer['admission_sha256']==result['admission_sha256']==runtime['admission_sha256'],'same actual actor admission')
    for key in ['run','job','approval','image','source_map_sha256']:
        need(admission[key]==b[key],'actor admission Root tuple differs')
    need(admission['source']==result['source'] and admission['contract_sha256']==sha(ROOT/'contract.json') and admission['input_signature_audit_sha256']==sha(evidence/'bootstrap/signatures.json'),'actor contract/signature/source joins')
    source_input=load(data/'source-input.json')
    need(source_input['candidate_files']==contract['candidate_files'] and source_input['actor_files']==contract['actor_files'] and source_input['owned_child']==contract['owned_child'] and source_input['archive']==contract['source'] and source_input['source_tree_sha256']==admission['source_tree_sha256'],'whole source and helper input joins')
    producer_spec=importlib.util.spec_from_file_location('llvm_reader_domain',ROOT/'hosted/producer.py');domain=importlib.util.module_from_spec(producer_spec);producer_spec.loader.exec_module(domain)
    check_volume(evidence,producer,b,domain,actual)
    original=(data/'PKGBUILD-original').read_bytes();effective=(data/'PKGBUILD-effective').read_bytes();delta=load(data/'recipe-delta.json')
    old='  python -I "$startdir/reference.py" "$1" --work "$srcdir" "${@:2}"'
    new='  python -I -B /inputs/actor/container_mode.py "$1" --work "$srcdir" "${@:2}"'
    need(original==(ROOT/'packages/port/llvm23-source-reference/PKGBUILD').read_bytes() and delta['old']==old and delta['new']==new and delta['count']==1 and original.count(old.encode())==1 and original.replace(old.encode(),new.encode())==effective,'exact Source-bound explicit container-mode recipe inverse')
    package=data/'cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'
    need(sha(package)==result['package']['sha256'],'package whole checksum')
    inventory=package_inventory(package)
    for name,exported in [('.PKGINFO','PKGINFO'),('.BUILDINFO','BUILDINFO')]:need(inventory[name]['sha256']==sha(data/exported),'package metadata byte join')
    pkginfo=(data/'PKGINFO').read_text().splitlines()
    need(all(line in pkginfo for line in ['pkgname = cachy-asahi-llvm23-source-reference','pkgver = 23.1.1-1','arch = aarch64']),'private package metadata identity')
    expected_installed={'installed = '+line.replace(' ','-',1) for line in (ROOT/'expected349.lock').read_text().splitlines()}
    need({line for line in (data/'BUILDINFO').read_text().splitlines() if line.startswith('installed = ')}==expected_installed,'complete349 BUILDINFO join')
    reported=load(data/'packaged-tree.json')['files']
    need(inventory==reported,'complete package/payload/provenance path-mode-byte join')
    report=dict(schema=1,status='PASS_LLVM23_NATIVE_BUILD_DATA_PARITY_ONLY',source=b['source'],run=b['run'],job=b['job'],image=b['image'],package=result['package'],payload_entries=len(inventory),native_acceptance=False,holds='original4/source108/native16K/M2/performance/release remain held',scope='Authenticated Root role observations and complete package DATA parity, not independent machine attestation or release admission')
    (output/'reader.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['binding','evidence','output']:p.add_argument('--'+key,required=True,type=Path)
    p.add_argument('--binding-sha256',required=True);a=p.parse_args();print(json.dumps(read(a.binding,a.binding_sha256,a.evidence,a.output),sort_keys=True))
