#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in static native/script payload leaves with held auxiliary/link state.

No default route or CLI. Dynamic loading, privileged metadata, services/hooks and
target compatibility are outside this candidate. Existing transaction guards run.
"""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sys
import tarfile
from types import SimpleNamespace

import aux_checkpoint as aux
import full_root as roots
import internal_runtime as strict
import prior_aux_runtime as data_only
import root_link_selection as links
import scale_update as scale

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


elf = module('_prior_payload_elf', HERE.parent/'platform/elf_audit.py')
capabilities = module('_prior_payload_xattrs', HERE.parent/'apps/file_capabilities.py')
MAX_NATIVE = 8*1024**2
UNITS = ('.hook', '.service', '.socket', '.target', '.timer', '.path', '.mount',
         '.automount', '.slice', '.scope', '.swap', '.busname', '.desktop')


def static_elf(raw):
    row = elf.parse_elf(raw)
    machine = {'x86_64':62, 'aarch64':183}.get(os.uname().machine)
    strict.need(row is not None and row['class']==64 and row['byte_order']=='little'
        and machine is not None and row['machine']==machine and row['flags']==0
        and row['osabi'] in (0,3) and row['abi_version']==0, 'native ELF profile differs')
    strict.need(row['type']==2 and not row['interpreter'] and not row['dynamic_present']
        and not row['needed'] and row['rpath'] is None and row['runpath'] is None,
        'only static ET_EXEC without loader dependencies supported')
    loads = row['PT_LOAD']
    strict.need(loads and all(p['offset_vaddr_congruent_declared_alignment'] and not p['flags'] & ~7
        and p['flags'] & 3 != 3 for p in loads), 'native load alignment or writable-executable segment refused')
    strict.need(any(p['flags'] & 1 and p['virtual_address'] <= row['entry'] <
        p['virtual_address']+p['file_bytes'] for p in loads), 'native executable entry not file-backed')
    return dict(kind='static-ET_EXEC', machine=machine, entry=row['entry'], load_segments=len(loads),
                loader_dependencies=[], closure_scope='initial ELF loader only; runtime dlopen/process behavior NOT VERIFIED',
                runtime_verified=False, target_acceptance='NOT ESTABLISHED')


def script_header(raw):
    line, separator, _ = raw.partition(b'\n')
    strict.need(separator and line.startswith(b'#!') and len(line[2:])<=253 and b'\r' not in line,
                'bounded direct shebang required')
    try: fields=line[2:].decode('ascii').strip().split()
    except UnicodeError as error: raise ValueError('ASCII shebang required') from error
    strict.need(len(fields)==1 and fields[0].startswith('/') and Path(fields[0]).name!='env',
                'direct absolute interpreter without arguments or env required')
    name=fields[0].removeprefix('/'); roots.installer.relative(name)
    strict.need('/'+name==fields[0] and not any(ord(c)<33 or ord(c)==127 for c in name), 'canonical interpreter required')
    return dict(kind='direct-script', interpreter=fields[0], runtime_verified=False)


class _Members:
    def __init__(self, archive): self.archive=archive
    def __getattr__(self, name): return getattr(self.archive,name)
    def __iter__(self):
        for member in self.archive:
            strict.need(set(member.pax_headers)<= {'path','linkpath','mtime','atime','ctime'},
                        'archive xattr/ACL/capability or unknown PAX metadata refused')
            yield member


@contextmanager
def _ordinary_tar(*args, **kwargs):
    with tarfile.open(*args, **kwargs) as archive: yield _Members(archive)


def parser(formats):
    """Private existing decoder; same budgets, extra format/metadata observation."""
    value=module('_prior_payload_archive_'+str(id(formats)),HERE/'archive_stream.py')
    value.CONTROLS=value.CONTROLS-{'.INSTALL'}
    value.tarfile=SimpleNamespace(**dict(vars(tarfile),open=_ordinary_tar))
    class Digest:
        def __init__(self): self.digest,self.raw,self.kind=hashlib.sha256(),bytearray(),None
        def update(self, block):
            self.digest.update(block)
            if self.kind is None:
                self.raw.extend(block)
                if len(self.raw)>=4:
                    self.kind='elf' if self.raw.startswith(b'\x7fELF') else 'script' if self.raw.startswith(b'#!') else 'data'
                    if self.kind=='data': del self.raw[4:]
            elif self.kind=='elf': self.raw.extend(block)
            elif self.kind=='script' and len(self.raw)<256: self.raw.extend(block[:256-len(self.raw)])
            if self.kind=='script': del self.raw[256:]
            strict.need(len(self.raw)<=MAX_NATIVE,'native inspection byte bound exceeded')
        def hexdigest(self):
            pin=self.digest.hexdigest()
            row=static_elf(self.raw) if self.kind=='elf' else script_header(bytes(self.raw)) if self.kind=='script' else dict(kind='data')
            formats[pin]=row
            return pin
    value.hashlib=SimpleNamespace(sha256=Digest)
    return value


class Runtime(data_only.Runtime):
    def __init__(self,args,config,*,comparator_path):
        super().__init__(args,config,comparator_path=comparator_path)
        self.formats,self.providers={},{}
        self.new_paths=set()
        self.parser=parser(self.formats)
        self.control_limits=self.parser.Limits(**asdict(self.archive_limits))
        selected=getattr(args,'payload_interpreters',{})
        strict.need(type(selected) is dict and len(selected)<=8,'bounded explicit interpreter selection required')
        for name,row in selected.items():
            strict.need(type(name) is str and name.startswith('/') and Path(name).name!='env'
                and type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int
                and 0<row['bytes']<=MAX_NATIVE and type(row['sha256']) is str
                and roots.installer.HEX.fullmatch(row['sha256']), 'exact static interpreter pin required')
            roots.installer.relative(name[1:])
        self.interpreters={name:dict(row) for name,row in selected.items()}

    def selection(self,snapshot,before,desired):
        strict.need(self.baseline is not None,'complete auxiliary baseline required')
        rows=snapshot['release']['packages']
        strict.need(len(rows)==1 and desired=={rows[0]['name']:rows[0]['version']},'one exact authenticated release package required')
        self.selected_package=rows[0]['name']
        strict.Runtime.selection(self,snapshot,before,desired)
        path=snapshot['bundle'].parent.parent/'prior-package/archive'
        audited=self._audit(path)
        strict.need(audited==self.prior['payload'],'prior audit payload differs')
        self._leaves(audited,self.baseline['nodes'],old=True)
        self.recheck_prior()

    def archive_payload(self,path,accounting):
        strict.need(self.prior is not None,'authenticated prior selection required')
        payload=strict.Runtime.archive_payload(self,path,accounting)
        audited=self._audit(path)
        strict.need(audited==payload,'new audit payload differs')
        self.recheck_prior()
        return payload

    def _audit(self,path):
        metadata={}
        payload=self.parser.archive_payload(path,self.control_limits,self.control_accounting,pkginfo=metadata)
        strict.need(not any(line.partition(' = ')[0]=='backup' for line in metadata['raw'].decode('utf8').splitlines()),
                    'new/prior backup semantics unsupported')
        return payload

    def _ordinary(self,name,node):
        """Descriptor-bound xattr/capability refusal using existing observer."""
        with strict.copy._descriptors() as held:
            root=roots._open_root(self.root);held.append(root)
            root_id=roots._identity(os.fstat(root));mount=roots._mount_id(root,self.root_limits)
            with strict.copy._parent(root,name,mount,{},self.root_limits,self.observation['nodes']) as (parent,base):
                flags=os.O_CLOEXEC|os.O_NOFOLLOW
                flags|=os.O_PATH if node['type']=='symlink' else os.O_RDONLY|os.O_NONBLOCK
                if node['type']=='directory':flags|=os.O_DIRECTORY
                fd=os.open(base,flags,dir_fd=parent);held.append(fd)
                before=roots._identity(os.fstat(fd));strict.copy._metadata_equal(os.fstat(fd),node)
                strict.need(roots._mount_id(fd,self.root_limits)==mount,'ordinary metadata mount crossing')
                strict.need(capabilities._attrs(fd,node['type'],self.root_limits,parent,base) is None,
                            'selected/provider capabilities refused')
                strict.need(before==roots._identity(os.fstat(fd))==roots._identity(os.stat(base,dir_fd=parent,follow_symlinks=False)),
                            'ordinary metadata identity drift')
            strict.copy._root_check(self.root,root,root_id,mount,self.root_limits)

    def _provider(self,requested,seed):
        strict.need(requested in self.interpreters,'explicit reviewed static interpreter required')
        name=requested[1:];node=seed.get(name,{})
        strict.need(node.get('type')=='file' and node.get('mode',0)&0o111 and not node['mode']&0o7000
            and node.get('uid')==node.get('gid')==0
            and 'hardlink_group' not in node and self.resolve_nodes(seed,name)==name
            and name in self.prior['foreign'] and name not in self.old_paths,
            'unchanged foreign-owned canonical static interpreter required')
        pin=self.interpreters[requested]
        strict.need(node['bytes']==pin['bytes'] and node['sha256']==pin['sha256'],'interpreter pin differs')
        self._ordinary(name,node);strict.need(self.node(self.root/name)==node,'interpreter drift')
        # Existing descriptor reader joins bytes to the complete live observation.
        captured=aux.Reader(self.root,self.observation,self.root_limits).capture(name,data_limit=MAX_NATIVE)
        inspected=static_elf(captured['data'])
        self.providers[name]=dict(node=node,inspection=inspected)

    def _recheck_providers(self):
        for name,row in self.providers.items():
            self.root_limits.tick();self._ordinary(name,row['node'])
            strict.need(self.node(self.root/name)==row['node'],'interpreter drift')

    def tree(self,root):
        self._recheck_providers()
        nodes=super().tree(root)
        self._recheck_providers();self._recheck_metadata()
        return nodes

    def _recheck_metadata(self):
        if self.observation is None:return
        names=set(self.old_paths)|self.new_paths|set(links.LINK_NODES)|set(links.RESOLVED_ENDPOINTS.values())
        if self.aux_before is not None:names.update(self.aux_before['closure'])
        for name in sorted(names):
            self.root_limits.tick();node=self.observation['nodes'].get(name)
            if node is not None:self._ordinary(name,node)

    def projected_paths(self,seed,payload):
        projected=super().projected_paths(seed,payload)
        self.new_paths=set(payload)
        return projected

    def _allowed(self,name):
        package=self.selected_package
        return (name.startswith('usr/bin/') and name.count('/')==2
                or any(name.startswith(prefix+'/') for prefix in ('usr/libexec/'+package,
                    'usr/share/'+package,'usr/share/doc/'+package,'usr/share/licenses/'+package)))

    def _leaves(self,payload,seed,*,old=False):
        strict.need(self.prior is not None and self.selected_package is not None,'authenticated prior selection required')
        final=dict(seed)
        if not old:
            for name in self.old_paths-payload.keys():final.pop(name,None)
        final.update(payload)
        protected=set(self.aux_before['closure'])|set(links.LINK_NODES)|set(links.RESOLVED_ENDPOINTS.values())|set(links.DATA_ONLY_ENDPOINTS.values())
        directories=set(self.aux_before['scan_directories'])|{p for p in links.RESOLVED_ENDPOINTS.values() if seed.get(p,{}).get('type')=='directory'}
        def endpoint(nodes,name):
            parent,_,leaf=name.rpartition('/');parent=self.resolve_nodes(nodes,parent)
            literal=parent+'/'+leaf if parent else leaf
            return self.resolve_nodes(nodes,literal) if literal in nodes else literal
        foreign=set(self.prior['foreign'])
        for name in self.prior['foreign']:self.root_limits.tick();foreign.add(endpoint(seed,name))
        for name,node in payload.items():
            self.root_limits.tick()
            strict.need(not any(ord(c)<32 or ord(c)==127 for c in name),'ordinary payload path required')
            if node['type']=='directory':
                strict.need(seed.get(name)==node,'directory creation or metadata change unsupported')
                self._ordinary(name,node);continue
            strict.need(node['type'] in ('file','symlink') and 'hardlink_group' not in node
                and seed.get(name,{}).get('type')!='directory','ordinary leaf without directory replacement required')
            strict.need(self._allowed(name) and not name.endswith(UNITS),'unsupported hook/service/platform/payload path')
            strict.need(not node['mode']&0o7000,'privileged payload mode refused')
            parent=name.rpartition('/')[0]
            strict.need(self.resolve_nodes(seed,parent)==parent,'selected leaf parent alias unsupported')
            endpoints={name,endpoint(seed,name),endpoint(final,name)}
            strict.need(not endpoints&protected and not any(e.startswith(p+'/') for e in endpoints for p in directories),
                        'payload touches auxiliary or selected-link closure')
            strict.need(not endpoints&foreign,'selected leaf has foreign ownership')
            if node['type']=='symlink':
                members=set(self.prior['payload'])|set(payload);target=endpoint(final,name)
                strict.need(node['mode']==0o777 and all(self._allowed(e) and e in members for e in endpoints)
                    and final.get(target,{}).get('type')=='file','contained final package file link required')
            else:
                inspected=self.formats.get(node['sha256'])
                strict.need(inspected is not None,'inspected payload bytes required')
                strict.need(not node['mode']&0o111 or inspected['kind']!='data','unrecognized executable format')
                if inspected['kind']=='direct-script':self._provider(inspected['interpreter'],seed)
            if old:
                strict.need(seed.get(name)==node and self.node(self.root/name)==node,'prior leaf modified or hardlinked')
                self._ordinary(name,node)
            elif name in seed:
                strict.need(name in self.old_paths,'new leaf overwrites unselected ownership')
                self._ordinary(name,seed[name])

    def precommit(self):
        self.recheck_prior();self._recheck_providers()
        strict.need(self.prior is not None,'authenticated prior selection required')
        self._leaves(self.prior['payload'],self.baseline['nodes'],old=True)
        scale.Runtime.precommit(self)
        aux.need(self.projected is not None,'complete-projected-root')
        state=aux.checkpoint(self.root,self.observation,self.root_limits)
        joined=aux.live_keys(state,self.comparator)
        check=aux.compare(self.aux_before,state,self.comparator,committed=False)
        self.recheck_prior();self._recheck_providers();self._recheck_metadata()
        self._leaves(self.prior['payload'],self.baseline['nodes'],old=True)
        self.aux_precommit=state
        self.auxiliary_checks.append(dict(checkpoint='precommit',live_cache_keys=joined,**check))
        self.commit_ready=True


def apply(args,*,comparator_path):
    delegated,result,runtime=False,None,None
    try:
        scale.bound.guard(Path(args.root),Path(args.workspace))
        config=scale.configuration(args.scale,args.scale_sha256)
        runtime=Runtime(args,config,comparator_path=comparator_path);delegated=True
        result=scale.bound.apply(args,adapter=runtime)
        result.update(scope='opt-in-static-payload-prior-auxiliary-disposable-root',auxiliary_checks=runtime.auxiliary_checks,
            selected_link_variant=links.variant_report(runtime.baseline['nodes'] if runtime.baseline else None),
            payload_formats=runtime.formats,interpreter_providers=runtime.providers,control_audit_accounting=runtime.control_accounting,
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED',apple_acceptance='NOT ESTABLISHED',
            hardware='NOT RUN',rollback='NOT IMPLEMENTED',native_target_compatibility='NOT ESTABLISHED')
        if runtime.prior is not None:result['prior_archive']=dict(runtime.prior['evidence'])
        return result
    except BaseException as error:
        failure=dict(result) if type(result) is dict else {}
        for field in ('commit_started','packages_committed','checkpoint_changed'):failure.setdefault(field,'UNKNOWN' if delegated else False)
        failure.update(status='FAIL',phase='prior-payload-auxiliary-runtime',error_type=type(error).__name__,error=str(error)[:256],
            auxiliary_exit_status='NOT OBSERVED',full587_composition='NOT ESTABLISHED',rollback='NOT IMPLEMENTED')
        if runtime is not None and runtime.prior is not None:failure['prior_archive']=dict(runtime.prior['evidence'])
        return failure
