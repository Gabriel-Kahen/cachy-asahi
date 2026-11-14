#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite source/tool/artifact checks for the opt-in Bankstown successor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

SOURCES={'bankstown-1.1.0.tar.gz':'e877508b73fe90774d74526d838f75e8ea278bdbcee0a1f92e3eca67ed734675',
 'cargo-vendor-117.tar.xz':'64cd55473b19f104f3a90570409d58c5ab69f63c61396541c4ad1e56e8d6293f',
 'audio-rust-notices-v1.tar.xz':'7cd393018f279ff2a1e71fe85fb5767e3f58398edcd395da4ab6f4eb357ce522'}
LOCK='66887346513dafbdbe171f77890b4e414bd49abfdde7e0d9e35eeb9ebd677f94'
VERSION='1.99.0'
HOST_VERSION='1.96.1'
NATIVE_RUST_PIN='65c0857c6278d82cc30afaff91a424dd753ba4435b6ac60ea377b3a0d6c9c1bc'
TARGETS={'aarch64-unknown-linux-gnu':183,'x86_64-unknown-linux-gnu':62}
TOOLS={'cargo':'/usr/bin/cargo','rustc':'/usr/bin/rustc','cc':'/usr/bin/cc','ld':'/usr/bin/ld'}
EPOCH=1791748800
HOLDS=['RAW_CRATE_AUTHENTICITY_NOT_ESTABLISHED','SELECTED_COMPILER_STD_LINKER_RUNTIME_SOURCES_NOT_DELIVERED',
       'HISTORICAL_COMPILER_NOT_REPRODUCED','WMIDI_LICENSE_TEXT_ASSOCIATION_LIMITED','LEGAL_RELINKING_NATIVE_M2_RELEASE_NOT_ADMITTED']


def need(value,code):
    if not value:raise ValueError(code)


def read(path,limit=256*1024**2):
    path=Path(path).resolve();need(path.is_file()and path.stat().st_size<=limit,'INPUT_REQUIRED_OR_OVERSIZED')
    with path.open('rb')as stream:raw=stream.read(limit+1)
    need(len(raw)<=limit,'INPUT_BOUND');return raw


def sha(raw):return hashlib.sha256(raw).hexdigest()
def desc(raw):return dict(bytes=len(raw),sha256=sha(raw))
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def sources(root):
    for name,pin in SOURCES.items():need(sha(read(Path(root)/name,16*1024**2))==pin,'DECLARED_SOURCE_DIFFERS:'+name)


def neutral_tree(cwd):
    path=Path(cwd).resolve()
    for parent in(path,*path.parents):
        for name in('.cargo/config','.cargo/config.toml'):
            need(not(parent/name).exists(),'INHERITED_CARGO_CONFIGURATION_REFUSED')


def native_tools(path,pin):
    raw=read(path,2*1024**2);need(sha(raw)==pin,'AUDITED_NATIVE_TOOL_CATALOG_PIN_REQUIRED');value=json.loads(raw)
    need(value.get('schema')==1 and value.get('purpose')=='bankstown-1.1.0-5-native-toolchain'
         and value.get('target')=='aarch64-unknown-linux-gnu'and value.get('compiler_version')==VERSION
         and value.get('tools')==TOOLS and type(value.get('files'))is dict,'AUDITED_NATIVE_TOOL_CATALOG_REQUIRED')
    need(len(value['files'])<=4096,'NATIVE_TOOL_CATALOG_BOUND')
    total=0
    for path,row in value['files'].items():
        need(Path(path).is_absolute()and '..'not in Path(path).parts,'NATIVE_SUPPORT_PATH_REQUIRED')
        body=read(path);total+=len(body);need(total<=2*1024**3,'NATIVE_SUPPORT_BYTE_BOUND')
        need(desc(body)==row,'NATIVE_TOOL_OR_SUPPORT_DIFFERS')
    for role,path in TOOLS.items():
        canonical=str(Path(path).resolve());need(canonical in value['files'],'NATIVE_TOOL_NOT_IN_CATALOG')
        body=read(canonical);need(body[:6]==b'\x7fELF\x02\x01'and struct.unpack_from('<H',body,18)[0]==183,'DIRECT_AARCH64_TOOL_ELF_REQUIRED')
    retained=read(Path(__file__).resolve().parent/'native-rust-inputs.json',1024**2)
    need(sha(retained)==NATIVE_RUST_PIN,'RETAINED_NATIVE_RUST_ASSOCIATION_REQUIRED');rust=json.loads(retained)
    for path,row in rust['files'].items():
        if path in('/usr/bin/cargo','/usr/bin/rustc')or path.startswith('/usr/lib/'):
            need(value['files'].get(path)==row,'NATIVE_RUST_PAYLOAD_ASSOCIATION_DIFFERS')
    for name in ('std','core','alloc','compiler_builtins'):
        need(any('/rustlib/aarch64-unknown-linux-gnu/lib/lib'+name+'-'in path and path.endswith('.rlib')for path in value['files']),'NATIVE_TARGET_LIBRARY_REQUIRED:'+name)
    return value


def artifact(raw,target):
    need(target in TARGETS and len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01','SUPPORTED_ARTIFACT_ELF_REQUIRED')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    need(header[1]==3 and header[2]==TARGETS[target]and header[9]==56 and header[11]==64,'ARTIFACT_TARGET_OR_TYPE_DIFFERS')
    need(0<header[10]<128 and 0<header[12]<4096 and header[5]+56*header[10]<=len(raw)and header[6]+64*header[12]<=len(raw),'ARTIFACT_TABLE_BOUND')
    loads=0
    for i in range(header[10]):
        p=struct.unpack_from('<IIQQQQQQ',raw,header[5]+i*56)
        if p[0]!=1:continue
        loads+=1;need(p[5]<=p[6]and p[2]+p[5]<=len(raw)and p[7]>=16384 and not p[7]&(p[7]-1)
            and p[2]%16384==p[3]%16384 and p[2]%p[7]==p[3]%p[7],'ARTIFACT_STRUCTURAL_16K_LOAD_REQUIREMENT')
    need(loads,'ARTIFACT_LOAD_SEGMENTS_REQUIRED')
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,header[6]+i*64)for i in range(header[12])];exports=set()
    for s in sections:
        if s[1]!=11:continue
        need(s[9]==24 and s[4]+s[5]<=len(raw)and s[6]<len(sections),'DYNAMIC_SYMBOL_TABLE_BOUND')
        strings=sections[s[6]];need(strings[4]+strings[5]<=len(raw),'DYNAMIC_STRING_TABLE_BOUND');text=raw[strings[4]:strings[4]+strings[5]]
        for offset in range(s[4],s[4]+s[5],24):
            entry=struct.unpack_from('<IBBHQQ',raw,offset)
            if entry[3]and entry[1]>>4 in(1,2)and entry[1]&15==2 and entry[0]<len(text):exports.add(text[entry[0]:].split(b'\0',1)[0].decode('utf-8'))
    need('lv2_descriptor'in exports,'LV2_DESCRIPTOR_EXPORT_REQUIRED')
    return dict(**desc(raw),target=target,machine=header[2],load_segments=loads,structural_16k=True,lv2_descriptor_export=True,hardware_validation='NOT_RUN')


def receipt(raw,target,tools_pin,mode):
    inspected=artifact(raw,target)
    need(type(tools_pin)is str and len(tools_pin)==64 and all(c in '0123456789abcdef'for c in tools_pin),'TOOL_CATALOG_ASSOCIATION_REQUIRED')
    need(mode==('HOST_DIAGNOSTIC_ONLY'if target.startswith('x86_64')else 'NATIVE_SOURCE_BUILD'),'RECEIPT_MODE_DIFFERS')
    return dict(schema=1,package='bankstown',version='1.1.0-5',mode=mode,artifact=inspected,selected_compiler=HOST_VERSION if mode=='HOST_DIAGNOSTIC_ONLY'else VERSION,
        tool_catalog_sha256=tools_pin,source_sha256=SOURCES,cargo_lock_sha256=LOCK,source_date_epoch=EPOCH,
        command=['cargo','build','--target',target,'--release','--locked','--offline','--jobs','1'],
        release_policy=dict(target_cpu='x86-64'if target.startswith('x86_64')else 'generic',codegen_units=1,
            upstream_opt_level=3,upstream_lto='thin',link_max_page_size=16384,host_diagnostic_lld_threads=1 if mode=='HOST_DIAGNOSTIC_ONLY'else None),
        holds=HOLDS,complete_corresponding_source_accepted=False,legal_acceptance=False,native_component_qualification='NOT_ADMITTED',physical_m2='NOT_RUN')


def check_receipt(raw,target,document):
    need(document==receipt(raw,target,document.get('tool_catalog_sha256'),document.get('mode')),'BUILD_RECEIPT_DIFFERS')


def main():
    if not sys.flags.isolated:
        print('Python isolated mode (-I) is required',file=sys.stderr);return 2
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    check=sub.add_parser('sources');check.add_argument('--root',type=Path,required=True)
    native=sub.add_parser('native-tools');native.add_argument('--profile',type=Path,required=True);native.add_argument('--sha256',required=True)
    neutral=sub.add_parser('neutral-tree');neutral.add_argument('--cwd',type=Path,required=True)
    inspect=sub.add_parser('artifact');inspect.add_argument('--file',type=Path,required=True);inspect.add_argument('--target',choices=TARGETS,required=True);inspect.add_argument('--receipt',type=Path,required=True)
    create=sub.add_parser('receipt');create.add_argument('--file',type=Path,required=True);create.add_argument('--target',choices=TARGETS,required=True)
    create.add_argument('--tools-sha256',required=True);create.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        if args.command=='sources':sources(args.root)
        elif args.command=='native-tools':native_tools(args.profile,args.sha256)
        elif args.command=='neutral-tree':neutral_tree(args.cwd)
        elif args.command=='artifact':check_receipt(read(args.file),args.target,json.loads(read(args.receipt,1024**2)))
        else:
            value=receipt(read(args.file),args.target,args.tools_sha256,'NATIVE_SOURCE_BUILD')
            fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb')as stream:stream.write(encoded(value))
    except (OSError,ValueError,KeyError,TypeError,struct.error):
        print('Bankstown candidate input/tool/artifact requirement not met',file=sys.stderr);return 2
    return 0


if __name__=='__main__':sys.exit(main())
