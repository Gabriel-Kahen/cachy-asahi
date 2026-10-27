#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite rootless ext4 encoder proposal; no installation or boot interface."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
import types

BASE = Path(__file__).resolve().parent
BLOCK = 4096
MAX_BYTES = 512 * 1024**2
MAX_NODES = 20000
SAFE = re.compile(r'[A-Za-z0-9._+@%=:/-]+\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
FEATURES = 'none,extent,filetype,sparse_super,large_file,dir_index,ext_attr,64bit,metadata_csum'
CONFIG = b'''[defaults]
base_features = ""
default_mntopts = ""
enable_periodic_fsck = 0
[fs_types]
ext4 = {
features = ""
}
small = {
features = ""
}
'''
TOOL_NAMES = ('mke2fs','debugfs','e2fsck')
TOOL_INTERFACE = 'e2fsprogs-linux-regular-ext4-v1'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        while raw := stream.read(1024**2):
            h.update(raw)
    return h.hexdigest()


def decode_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result,'duplicate-json-key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def load_json(path):
    p=Path(path);s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and 0<s.st_size<=32*1024**2,'json-file-bound')
    return decode_json(p.read_bytes())


def read_configuration(path,expected):
    path=Path(path).absolute();need(path==path.resolve(),'configuration-symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=1024**2,'configuration-file-bound')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(1024**2+1)
        fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(before,k)==getattr(os.fstat(fd),k)==getattr(path.lstat(),k) for k in fields),'configuration-drift')
        need(len(raw)==before.st_size and digest(raw)==expected,'tool-configuration-pin')
        return decode_json(raw)
    finally:os.close(fd)


OWNED_PROCESS_SHA='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
OWNED_CORE=None
ACTOR_DIRECTORY=None
ACTOR_NUMBER=0


def owned_core():
    global OWNED_CORE
    if OWNED_CORE is None:
        path=BASE.parent/'virtual/owned_process.py'
        raw=path.read_bytes()
        need(len(raw)<=65536 and digest(raw)==OWNED_PROCESS_SHA,'reserved-supervisor-source-pin')
        module=types.ModuleType('_filesystem_owned_process');module.__file__=str(path)
        exec(compile(raw,str(path),'exec'),module.__dict__);OWNED_CORE=module
    return OWNED_CORE


def run_command(command, *, env, cwd=None, timeout=10, capture_output=True, check=True, max_output=1024**2):
    """Transfer exclusive wait ownership; retain raw combined output/receipts."""
    global ACTOR_NUMBER
    need(ACTOR_DIRECTORY is not None and Path(ACTOR_DIRECTORY).is_dir(),'private-actor-log-directory-required')
    core=owned_core();core.prepare()
    child=None
    try:
        child=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        result=core.supervise(child,cap=timeout,retirement=1.0,grace=0.2,group=True,max_output=max_output)
    except BaseException:
        # A pre-transfer interruption leaves the direct child unreaped. Once
        # supervise has transferred/released ownership it suppresses this flag.
        if child is not None and child.returncode is None and getattr(child,'_child_created',False):
            core.supervise(child,cap=3.0,retirement=1.0,grace=0.0,group=True,max_output=max_output)
        raise
    ACTOR_NUMBER+=1;stem=f'actor-{ACTOR_NUMBER:04d}'
    raw=result.pop('output');directory=Path(ACTOR_DIRECTORY)
    (directory/(stem+'.log')).write_bytes(raw)
    receipt=dict(argv=command,cwd=str(cwd) if cwd is not None else None,
                 environment=env,core_sha256=OWNED_PROCESS_SHA,cap_seconds=timeout,
                 max_output_bytes=max_output,raw_output_sha256=digest(raw),raw_output_bytes=len(raw),
                 supervision=result)
    (directory/(stem+'.json')).write_bytes(canonical(receipt))
    if check:need(result['passed'],'reserved-command-failed:'+stem+':'+str(result.get('error')))
    return types.SimpleNamespace(stdout=raw,stderr=b'',returncode=result['exit'],supervision=receipt)


def validate_tool_configuration(config):
    need(type(config)is dict and set(config)=={'interface','ldd','tools'} and
         config['interface']==TOOL_INTERFACE and type(config['tools'])is dict and
         set(config['tools'])==set(TOOL_NAMES),'unsupported-filesystem-tool-interface')
    need(all(type(p)is str and 0<len(p)<=4096 and Path(p).is_absolute() and '..' not in Path(p).parts
             for p in [config['ldd']]+list(config['tools'].values())),'explicit-absolute-tool-paths-required')
    return config


def tool_pins(config):
    """Capture actual host paths/bytes; no Arch/Ubuntu hash substitution."""
    config=validate_tool_configuration(config)
    result = {'schema_version':2,'configuration':config,'tools':{},'python': {
        'executable':str(Path(sys.executable).resolve()),'sha256':file_hash(sys.executable),
        'version':list(sys.version_info[:3])},'ldd':{'path':config['ldd'],'sha256':file_hash(config['ldd'])},
        'qualification':'CAPTURED_IDENTITY_ONLY_REQUIRE_SEPARATE_HOST_COMPONENT_CHECK'}
    env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LC_ALL':'C','TZ':'UTC'}
    for name,path in config['tools'].items():
        version=run_command([path,'-V'],env=env,capture_output=True,timeout=10,check=True)
        text=(version.stdout+version.stderr).decode().strip()
        need(text.startswith(name+' '),'tool-role-version-mismatch')
        ldd=run_command([config['ldd'],path],env=env,capture_output=True,timeout=10,check=True)
        need(b'not found' not in ldd.stdout+ldd.stderr,'dynamic-library-closure-incomplete')
        libs=sorted(set(re.findall(r'(?:=>\s+|^\s*)(/[^\s()]+)',ldd.stdout.decode(),re.M)))
        need(libs,'dynamic-library-identity')
        result['tools'][name]=dict(path=path,realpath=str(Path(path).resolve()),sha256=file_hash(path),
            version=text,libraries={p:file_hash(p) for p in libs})
    return result


def pathname(value):
    need(type(value) is str and len(value) <= 2048 and SAFE.fullmatch(value), 'unsupported-path-characters')
    need(not value.startswith('/') and all(x not in ('', '.', '..') for x in value.split('/')), 'relative-path')
    need(all(len(x.encode()) <= 255 for x in value.split('/')), 'path-component-bound')
    return value


def metadata(value):
    need(type(value) is dict and set(value) == {'acl', 'xattrs'}, 'explicit-acl-xattr-metadata-required')
    need(value['acl'] is None, 'unsupported-posix-acl: ext4 ACL translation unavailable')
    attrs = value['xattrs']
    need(type(attrs) is dict and len(attrs) <= 32, 'xattr-bound')
    result = {}
    for key, encoded in attrs.items():
        need(type(key) is str and re.fullmatch(r'(user|trusted|security)\.[A-Za-z0-9._+-]+', key)
             and len(key) <= 255, 'unsupported-xattr-namespace-or-name')
        need(type(encoded) is str and len(encoded) <= 5500, 'xattr-value-bound')
        raw = base64.b64decode(encoded, validate=True)
        need(len(raw) <= 1024 and base64.b64encode(raw).decode() == encoded, 'xattr-value-encoding')
        result[key] = raw
    need(sum(len(k)+len(v)+32 for k,v in result.items()) <= 2048, 'xattr-storage-bound')
    return result


def validate(manifest, bodies, meta):
    need(type(manifest) is dict and type(manifest.get('schema_version')) is int and manifest['schema_version'] == 1
         and manifest.get('base') == 'FRESH_PRISTINE_PREPARED_PACKAGE_TREE', 'assembler-manifest-required')
    epoch = manifest.get('source_date_epoch')
    need(type(epoch) is int and 0 <= epoch <= 2147483647, 'epoch-bound')
    nodes = manifest.get('output_nodes')
    need(type(nodes) is dict and 0 < len(nodes) <= MAX_NODES and all(type(n) is dict for n in nodes.values()), 'complete-node-map-required')
    need(type(bodies) is dict and set(bodies) == {p for p,n in nodes.items() if n.get('type') == 'file'}, 'body-closure')
    need(type(meta) is dict and set(meta) == {'schema_version', 'complete', 'nodes', 'root'}, 'metadata-schema')
    need(type(meta['schema_version']) is int and meta['schema_version'] == 1 and meta['complete'] is True
         and type(meta['nodes']) is dict and set(meta['nodes']) == set(nodes), 'complete-metadata-required')
    root = meta['root']
    need(type(root) is dict and set(root) == {'mode', 'uid', 'gid', 'acl', 'xattrs'}, 'explicit-root-metadata')
    attrs = {'': metadata({k:root[k] for k in ('acl', 'xattrs')})}
    total = 0
    for name, node in [('', root)] + sorted(nodes.items()):
        if name:
            pathname(name)
            need(node.get('type') in ('file', 'directory', 'hardlink', 'symlink'), 'unsupported-node')
            required = {'type','mode','uid','gid'}
            required |= {'bytes','sha256'} if node['type'] == 'file' else {'target'} if node['type'] in ('hardlink','symlink') else set()
            need(set(node) == required, 'unsupported-node-metadata')
            for i in range(1,len(name.split('/'))):
                parent = '/'.join(name.split('/')[:i])
                need(parent in nodes and nodes[parent]['type'] == 'directory', 'explicit-directory-parent')
            attrs[name] = metadata(meta['nodes'][name])
        for key, maximum in [('mode',0o7777), ('uid',2**32-1), ('gid',2**32-1)]:
            need(type(node[key]) is int and 0 <= node[key] <= maximum, 'numeric-inode-metadata')
        if not name:
            continue
        if node['type'] == 'file':
            raw = bodies[name]
            need(type(raw) is bytes and type(node['bytes']) is int and len(raw) == node['bytes'] <= MAX_BYTES
                 and type(node['sha256']) is str and HEX.fullmatch(node['sha256']) and digest(raw) == node['sha256'], 'body-hash-size')
            total += len(raw)
        elif node['type'] == 'symlink':
            target = node['target']
            need(type(target) is str and 0 < len(target.encode()) <= 4095 and SAFE.fullmatch(target), 'unsupported-link-target')
            need(node['mode'] == 0o777, 'ext4-symlink-mode')
        elif node['type'] == 'hardlink':
            target = pathname(node['target'])
            need(target in nodes and nodes[target]['type'] == 'file', 'direct-hardlink-target')
            need(all(node[k] == nodes[target][k] for k in ('mode','uid','gid')) and meta['nodes'][name] == meta['nodes'][target], 'hardlink-inode-metadata')
    need(total <= MAX_BYTES, 'payload-byte-bound')
    allocated = sum((len(raw)+BLOCK-1)//BLOCK*BLOCK for raw in bodies.values())
    size = max(16*1024**2, ((allocated + len(nodes)*8192 + 8*1024**2 + 1024**2-1)//1024**2)*1024**2)
    need(size <= 4*1024**3, 'image-size-bound')
    root_uuid = manifest.get('platform',{}).get('root_uuid')
    need(type(root_uuid) is str and str(uuid.UUID(root_uuid)) == root_uuid, 'explicit-root-uuid')
    return nodes, attrs, epoch, size, root_uuid


def regular_image(path, size, identity):
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == size and (st.st_dev, st.st_ino) == identity, 'owned-ordinary-image-required')


def run_tool(command, directory, env, label, image, size, identity):
    regular_image(image,size,identity)
    result=run_command(command,cwd=directory,env=env,timeout=60,max_output=16*1024**2,check=True)
    output=directory/(label+'.log')
    with output.open('xb') as stream:stream.write(result.stdout)
    regular_image(image,size,identity)
    return dict(argv=command,exit_code=result.returncode,log_sha256=file_hash(output),
                reserved_supervision=result.supervision)


def readback(image):
    spec = importlib.util.spec_from_file_location('_ext4_readback',BASE/'independent_readback.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    return reader.read_inventory(image, max_file_bytes=MAX_BYTES, max_nodes=MAX_NODES+1)


def check_inventory(inventory,nodes,meta,epoch,root_uuid,size):
    observed = inventory['nodes']
    need(set(observed)==set(nodes)|{'.'},'readback-node-closure')
    for name,node in [('.',meta['root'])]+sorted(nodes.items()):
        got = observed[name]
        want_type = 'directory' if name=='.' else 'file' if node['type']=='hardlink' else node['type']
        need(got['type']==want_type and all(got[k]==node[k] for k in ('mode','uid','gid')), 'readback-node-metadata:'+name)
        need(all(got[k]==epoch and got[k+'_ns']==0 for k in ('atime','mtime','ctime','crtime')), 'readback-timestamps:'+name)
        want_attrs = meta['root']['xattrs'] if name=='.' else meta['nodes'][name]['xattrs']
        need(got['xattrs']==want_attrs, 'readback-xattrs:'+name)
        if name!='.' and node['type']=='file':
            need(got['size']==node['bytes'] and got['sha256']==node['sha256'],'readback-body:'+name)
            count=1+sum(n['type']=='hardlink' and n['target']==name for n in nodes.values())
            need(got['links']==count,'readback-file-nlink:'+name)
        elif name!='.' and node['type']=='symlink':
            need(base64.b64decode(got['target_b64'])==node['target'].encode() and got['links']==1,'readback-symlink:'+name)
        elif name!='.' and node['type']=='hardlink':
            need(got['inode']==observed[node['target']]['inode'],'readback-hardlink:'+name)
    need(inventory['uuid']==root_uuid and inventory['hash_seed']==root_uuid
         and inventory['image_bytes']==size and inventory['created']==epoch, 'readback-superblock')


def encode(manifest, bodies, meta, expected_pins, output_directory):
    """Consume complete assembler node map and regular byte map. Fresh output only."""
    nodes, attrs, epoch, size, root_uuid = validate(manifest, bodies, meta)
    need(type(expected_pins)is dict and expected_pins.get('schema_version')==2,'filesystem-dependency-profile-v2-required')
    need(expected_pins == tool_pins(expected_pins.get('configuration')), 'tool-pin-mismatch')
    tool_paths={name:expected_pins['tools'][name]['path'] for name in TOOL_NAMES}
    out = Path(output_directory).absolute()
    need(out.parent.is_dir() and out.parent.resolve() == out.parent, 'output-parent-must-be-real-directory')
    out.mkdir(mode=0o700)
    image = out / 'root.ext4'
    fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.truncate(size)
        st = os.fstat(stream.fileno())
        image_identity = (st.st_dev, st.st_ino)
    (out/'mke2fs.conf').write_bytes(CONFIG)
    (out/'inputs').mkdir(mode=0o700)
    env = {'PATH':'/usr/bin','LC_ALL':'C','TZ':'UTC','MKE2FS_CONFIG':str(out/'mke2fs.conf'),
           'E2FSPROGS_FAKE_TIME':str(epoch), 'SOURCE_DATE_EPOCH':str(epoch)}
    root = meta['root']
    inode_count = max(128, ((len(nodes)+32+31)//32)*32)
    extended = (f'hash_seed={root_uuid},lazy_itable_init=0,lazy_journal_init=0,nodiscard,'
                f'root_owner={root["uid"]}:{root["gid"]},root_perms={root["mode"]:04o}')
    command = [tool_paths['mke2fs'],'-t','ext4','-F','-b','4096','-I','256','-N',str(inode_count),'-m','0',
               '-U',root_uuid,'-O',FEATURES,'-E',extended,'-L','cachy-root','-M','/',str(image),str(size//BLOCK)]
    calls = [run_tool(command,out,env,'01-mke2fs',image,size,image_identity)]
    commands = ['rmdir /lost+found']
    for name in sorted(nodes, key=lambda x:(x.count('/'), x)):
        if nodes[name]['type'] == 'directory':
            commands.append('mkdir /'+name)
    for index, name in enumerate(sorted(bodies)):
        (out/'inputs'/f'body-{index}').write_bytes(bodies[name])
        commands.append(f'write inputs/body-{index} /{name}')
    for name in sorted(nodes):
        node = nodes[name]
        if node['type'] == 'symlink':
            commands.append(f'symlink /{name} {node["target"]}')
        elif node['type'] == 'hardlink':
            commands.append(f'link /{node["target"]} /{name}')
    for index, (name,node) in enumerate([('',root)] + sorted(nodes.items())):
        path = '/'+name
        if name and node['type'] == 'hardlink':
            continue
        kind = stat.S_IFDIR if not name or node['type'] == 'directory' else stat.S_IFLNK if node['type'] == 'symlink' else stat.S_IFREG
        for key,value in [('mode',kind | node['mode']),('uid',node['uid']),('gid',node['gid']),
                          ('atime',epoch),('ctime',epoch),('mtime',epoch),('crtime',epoch),
                          ('atime_extra',0),('ctime_extra',0),('mtime_extra',0),('crtime_extra',0),('generation',0)]:
            text = '@'+str(value) if key in ('atime','ctime','mtime','crtime') else str(value)
            commands.append(f'set_inode_field {path} {key} {text}')
        if name and node['type'] == 'file':
            count = 1+sum(n['type']=='hardlink' and n['target']==name for n in nodes.values())
            commands.append(f'set_inode_field {path} links_count {count}')
        for number,(key,raw) in enumerate(sorted(attrs[name].items())):
            (out/'inputs'/f'xattr-{index}-{number}').write_bytes(raw)
            commands.append(f'ea_set -f inputs/xattr-{index}-{number} {path} {key}')
    (out/'debugfs.commands').write_text('\n'.join(commands)+'\n')
    calls.append(run_tool([tool_paths['debugfs'],'-w','-f',str(out/'debugfs.commands'),str(image)],out,env,'02-debugfs',image,size,image_identity))
    regular_image(image,size,image_identity)
    before_check = file_hash(image)
    calls.append(run_tool([tool_paths['e2fsck'],'-f','-n',str(image)],out,env,'03-e2fsck',image,size,image_identity))
    need(file_hash(image)==before_check,'readonly-integrity-check-changed-image')
    inventory = readback(image)
    check_inventory(inventory,nodes,meta,epoch,root_uuid,size)
    (out/'inventory.json').write_bytes(canonical(inventory))
    result = dict(schema_version=1,status='HOST_ROOTLESS_EXT4_BUILT_AND_READ_BACK',
        image={'bytes':size,'sha256':file_hash(image),'uuid':root_uuid,'hash_seed':root_uuid},
        source_manifest_sha256=digest(canonical(manifest)), metadata_sha256=digest(canonical(meta)),
        host={'system':os.uname().sysname,'machine':os.uname().machine,'kernel':os.uname().release,'uid':os.getuid()},
        tools=expected_pins, encoder_sha256=file_hash(__file__), reader_sha256=file_hash(BASE/'independent_readback.py'),
        profile={'block_size':BLOCK,'inode_size':256,'inode_count_requested':inode_count,'features':FEATURES,
                 'journal':False,'timestamps':epoch,'size_formula':'ceil_MiB(allocated_payload_blocks + 8192*nodes + 8MiB), minimum16MiB',
                 'config_sha256':digest(CONFIG),'environment':env}, calls=calls,
        inventory_sha256=digest(canonical(inventory)), native_arm_accepted=False, bootability_accepted=False,
        package_authenticity_accepted=False, hardware_accepted=False, release_accepted=False,
        limitations=['POSIX ACLs refused explicitly','No ESP, boot actors, package database, hooks or installation',
                     'Same-host private fresh-file evidence; not two clean native environments'])
    (out/'result.json').write_bytes(canonical(result))
    return result


def staging_bodies(directory, manifest, meta):
    """Immutable body transport; logical UID/GID come from assembler, not host UID."""
    root = Path(directory).absolute()
    need(root.resolve()==root and root.is_dir(), 'real-staging-directory')
    nodes=manifest['output_nodes']
    need(type(nodes) is dict and 0 < len(nodes)<=MAX_NODES, 'staging-node-bound')
    found, bodies = {}, {}
    def walk(path, relative):
        for child in sorted(os.scandir(path), key=lambda x:x.name):
            name = relative+'/'+child.name if relative else child.name
            pathname(name)
            need(len(found)<MAX_NODES,'staging-node-bound')
            found[name]=child.stat(follow_symlinks=False)
            if stat.S_ISDIR(found[name].st_mode):
                walk(Path(child.path),name)
    walk(root,'')
    need(set(found)==set(nodes),'staging-namespace-closure')
    need(sum(s.st_size for p,s in found.items() if nodes[p]['type']=='file')<=MAX_BYTES,'staging-byte-bound')
    def identity(st):
        return (st.st_dev,st.st_ino,st.st_size,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_mtime_ns,st.st_ctime_ns)
    for name,node in nodes.items():
        p=root/name
        st=found[name]
        need(stat.S_IMODE(st.st_mode)==node['mode'],'staging-mode:'+name)
        expected_attrs = meta['nodes'][name]['xattrs']
        actual_attrs={k:base64.b64encode(os.getxattr(p,k,follow_symlinks=False)).decode()
                      for k in os.listxattr(p,follow_symlinks=False)}
        need(actual_attrs==expected_attrs and meta['nodes'][name]['acl'] is None,'staging-attributes:'+name)
        if node['type'] in ('file','hardlink'):
            need(stat.S_ISREG(st.st_mode),'staging-regular:'+name)
            if node['type']=='hardlink':
                target=found[node['target']]
                need((st.st_dev,st.st_ino)==(target.st_dev,target.st_ino),'staging-hardlink:'+name)
            else:
                links=1+sum(n['type']=='hardlink' and n['target']==name for n in nodes.values())
                need(st.st_nlink==links,'staging-extra-hardlink:'+name)
                fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    need(identity(os.fstat(stream.fileno()))==identity(st),'staging-changed-before-read')
                    raw=stream.read(MAX_BYTES+1)
                    need(identity(os.fstat(stream.fileno()))==identity(st),'staging-changed-during-read')
                bodies[name]=raw
        elif node['type']=='directory':
            need(stat.S_ISDIR(st.st_mode),'staging-directory:'+name)
        else:
            need(stat.S_ISLNK(st.st_mode) and os.readlink(p)==node['target'],'staging-link:'+name)
    root_attrs={k:base64.b64encode(os.getxattr(root,k,follow_symlinks=False)).decode()
                for k in os.listxattr(root,follow_symlinks=False)}
    need(root_attrs==meta['root']['xattrs'] and stat.S_IMODE(root.stat().st_mode)==meta['root']['mode'],'staging-root-metadata')
    return bodies


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    sub=ap.add_subparsers(dest='action',required=True)
    p=sub.add_parser('pin-tools');p.add_argument('--output',required=True)
    p.add_argument('--configuration',required=True);p.add_argument('--configuration-sha256',required=True)
    p.add_argument('--actor-directory',required=True)
    p=sub.add_parser('encode')
    for key in ('assembly-manifest','metadata','tool-pins','staging-directory','output-directory'):
        p.add_argument('--'+key,required=True)
    args=ap.parse_args()
    if args.action=='pin-tools':
        global ACTOR_DIRECTORY
        ACTOR_DIRECTORY=Path(args.actor_directory).absolute();ACTOR_DIRECTORY.mkdir(mode=0o700)
        configuration=read_configuration(args.configuration,args.configuration_sha256)
        with open(args.output,'xb') as out:out.write(canonical(tool_pins(configuration)))
        return
    manifest=load_json(args.assembly_manifest)
    meta=load_json(args.metadata)
    result=encode(manifest,staging_bodies(args.staging_directory,manifest,meta),meta,
                  load_json(args.tool_pins),args.output_directory)
    print(json.dumps(result['image'],sort_keys=True))


if __name__=='__main__':
    main()
