#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite Qt612 preparation Source constructor; no operational entry or authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
BASIS_PIN = dict(bytes=4516,sha256='6a38fd9026b10ea7400b69360ce32a9c45205ccfee5f18116fbf694e10905e3d')
POLICY_PIN = dict(bytes=1858,sha256='cc6e7a6daf31827a3ef060cfdbf3d8ab0a8a6dcfdf32e9b2c51ed857fa05b9b3')
RECIPE_PATH = 'packages/port/qt612-source-reference'
PRIVATE = {'.gnupg','.ssh','.aws','.config'}
ACTUAL = ('recipe_commit','provider','Source','ref','Main','run','job','attempt','image','native_pair','Root_admission','Root_runtime')
MISSING = ('F_FROZEN_RECIPE_COMMIT_AND_CLOSED_MAP','SIGNED349_COMPLETE_PROVIDER_AND_CURRENT_TRUST',
           'RECIPE_BUILD_DEPENDENCY_TRANSACTION','QT_SPECIFIC_RUNTIME_PROJECTION_AND_PAIR_FINISHER',
           'ROOT_RESOURCE_CAPACITY_AND_SOURCE85_READONLY_CONFINEMENT_REVIEW','ACTUAL_SOURCE_PUBLICATION_AND_RUNTIME_ADMISSION')


def need(value,why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def identity(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))


def decode(raw):
    def pairs(rows):
        result = {}
        for k,v in rows:
            need(k not in result,'DUPLICATE_JSON_KEY');result[k] = v
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE_JSON'))


def ordinary(value):
    value = str(value);p = Path(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts and len(value) <= 4096
         and all(ord(c) >= 32 and ord(c) != 127 for c in value) and not PRIVATE.intersection(p.parts)
         and not any(q.is_symlink() for q in (p,*p.parents)), 'ORDINARY_PUBLIC_DATA_PATH')
    return p


def member(name):
    need(type(name) is str and 0 < len(name) <= 255 and name == Path(name).as_posix()
         and not Path(name).is_absolute() and not {'.','..'}.intersection(name.split('/'))
         and all(re.fullmatch('[A-Za-z0-9._+@~-]+',part) for part in name.split('/')), 'SAFE_RELATIVE_MEMBER')
    return name


def descriptor(row,cap):
    need(type(row) is dict and set(row) == {'bytes','sha256'} and type(row['bytes']) is int
         and 0 <= row['bytes'] <= cap and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'BOUNDED_WHOLE_PIN')


def stream(path,expected,observed,*,cap=4*1024**2,collect=False,target=None,mode=None):
    if expected is not None:descriptor(expected,cap)
    p = ordinary(path)
    fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0,os.geteuid())
             and not before.st_mode&0o022 and 0 <= before.st_size <= cap
             and (expected is None or before.st_size == expected['bytes'])
             and (mode is None or stat.S_IMODE(before.st_mode) == mode), 'ORDINARY_EXACT_PINNED_LEAF')
        h,size,parts = hashlib.sha256(),0,[]
        while block := os.read(fd,min(1024**2,before.st_size+1-size)):
            size += len(block);need(size <= before.st_size,'WHOLE_STREAM_BYTE_CAP');h.update(block)
            if collect:parts.append(block)
            if target is not None:target.write(block)
        need((expected is None or dict(bytes=size,sha256=h.hexdigest()) == expected)
             and size == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()), 'STABLE_WHOLE_FILE_PIN')
        previous = observed.get(str(p));need(previous is None or previous == identity(before),'OPERAND_REPLACED_BETWEEN_READS')
        observed[str(p)] = identity(before)
        return b''.join(parts) if collect else None
    finally:os.close(fd)


def unchanged(observed):
    need(all(identity(ordinary(p).lstat()) == v for p,v in observed.items()), 'OPERAND_CHANGED_AFTER_READ')


class Writer:
    """Fresh private DATA, with all creations anchored to retained directory fds."""
    def __init__(self,path):
        self.root = ordinary(path);self.dirs = {};self.files = {}
        parent = os.open(self.root.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.mkdir(self.root.name,0o700,dir_fd=parent)
            fd = os.open(self.root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            self.dirs[self.root] = (fd,os.fstat(fd))
        finally:os.close(parent)

    def directory(self,path):
        if path in self.dirs:return self.dirs[path][0]
        parent = self.directory(path.parent)
        os.mkdir(path.name,0o700,dir_fd=parent)
        fd = os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        self.dirs[path] = (fd,os.fstat(fd));return fd

    def put(self,name,*,raw=None,source=None,expected=None,observed=None,cap=4*1024**2,mode=0o644):
        member(name);self.check();p = self.root/name;parent = self.directory(p.parent)
        fd = os.open(p.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
        with os.fdopen(fd,'wb') as target:
            os.fchmod(target.fileno(),mode)
            if raw is not None:target.write(raw);expected = pin(raw)
            else:stream(source,expected,observed,cap=cap,target=target)
            target.flush();opened = os.fstat(target.fileno())
        need(identity(opened) == identity(p.lstat()),'OUTPUT_LEAF_REPLACED')
        self.files[p] = identity(opened);self.check()
        return dict(expected,mode=stat.S_IMODE(opened.st_mode))

    def check(self):
        stable = lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid'))
        for p,(fd,before) in self.dirs.items():
            need(stable(before) == stable(os.fstat(fd)) == stable(ordinary(p).lstat())
                 and before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700,'STABLE_PRIVATE_OUTPUT_DIRECTORY')
        need(all(identity(p.lstat()) == before for p,before in self.files.items()), 'OUTPUT_FILE_CHANGED')

    def close(self):
        for fd,_ in self.dirs.values():os.close(fd)


def load(path,expected,observed):return decode(stream(path,expected,observed,collect=True))


def srcinfo(raw):
    values = {}
    for line in raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):continue
        need(' = ' in line,'FINITE_SRCINFO_ROW');key,value = line.split(' = ',1)
        values.setdefault(key,[]).append(value)
    return values


def recipe_contract(value,root,observed):
    keys = {'schema','kind','recipe_commit','recipe_path','version','files','upstream_commit','sources','licenses',
            'outputs','dependencies','check_required','features','declared_peak_writable_bytes','Root_acceptance','official_0bd04f_correspondence'}
    need(type(value) is dict and set(value) == keys and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == 'QT612_REFERENCE_RECIPE_SELECTION_V1' and value['recipe_path'] == RECIPE_PATH
         and value['version'] == '6.12.0' and re.fullmatch('[0-9a-f]{40}',value['recipe_commit'] or '')
         and re.fullmatch('[0-9a-f]{40}',value['upstream_commit'] or '')
         and value['Root_acceptance'] is None and value['official_0bd04f_correspondence'] == 'HELD', 'FROZEN_INDEPENDENT_RECIPE_REQUIRED')
    need(type(value['files']) is dict and {'PKGBUILD','.SRCINFO','source.json'} <= set(value['files'])
         and 3 <= len(value['files']) <= 128
         and sum(row['bytes'] for row in value['files'].values()) <= 16*1024**2,'CLOSED_COMPLETE_RECIPE_FILE_MAP')
    base = ordinary(root)/RECIPE_PATH
    found,dirs,pending,nodes = set(),set(),[base],0
    while pending:
        parent = pending.pop()
        for p in parent.iterdir():
            nodes += 1;need(nodes <= 512 and not p.is_symlink(),'RECIPE_NAMESPACE_BOUND')
            if p.is_file():found.add(p.relative_to(base).as_posix())
            else:
                need(p.is_dir(),'ORDINARY_RECIPE_NAMESPACE');dirs.add(p.relative_to(base).as_posix());pending.append(p)
    need(found == set(value['files']),'EXACT_COMPLETE_RECIPE_NAMESPACE')
    expected_dirs = {p.as_posix() for n in value['files'] for p in Path(n).parents if p.as_posix() != '.'}
    need(dirs == expected_dirs,'NO_FOREIGN_RECIPE_DIRECTORIES')
    bodies = {}
    for name,row in value['files'].items():
        member(name);need(type(row) is dict and set(row) == {'bytes','sha256','mode'} and row['mode'] in (0o644,0o755), 'EXACT_RECIPE_FILE_MODE')
        bodies[name] = stream(base/name,{k:row[k] for k in ('bytes','sha256')},observed,collect=True,mode=row['mode'])
    md = srcinfo(bodies['.SRCINFO']);deps = value['dependencies']
    need(md.get('pkgver') == ['6.12.0'] and 'aarch64' in md.get('arch',[]) and '!check' not in md.get('options',[])
         and value['check_required'] is True and re.search(rb'(?m)^check\(\)\s*\{',bodies['PKGBUILD'])
         and re.search(rb'''(?m)^PKGEXT=['"]\.pkg\.tar\.xz['"]''',bodies['PKGBUILD']), 'NORMAL_DEPENDENCY_CHECK_AND_XZ_CONTRACT')
    need(type(deps) is dict and set(deps) == {'depends','makedepends','checkdepends'},'EXPLICIT_DEPENDENCY_CLASSES')
    for key,names in deps.items():
        need(type(names) is list and len(names) <= 256 and len(names) == len(set(names))
             and all(type(n) is str and re.fullmatch('[a-z0-9][a-z0-9@._+:-]*(?:[<>=]+[^ /]+)?',n) for n in names)
             and set(names) == set(md.get(key,[])+md.get(key+'_aarch64',[])),'SRCINFO_DEPENDENCY_EQUALITY')
    outputs = value['outputs']
    need(type(outputs) is list and 1 <= len(outputs) <= 8 and len({row['name'] for row in outputs}) == len(outputs)
         and set(md.get('pkgname',[])) == {row['name'] for row in outputs},'EXACT_SPLIT_PACKAGE_OUTPUTS')
    need(len(md.get('pkgrel',[])) == 1 and re.fullmatch(r'[1-9][0-9]*(?:\.[0-9]+)?',md['pkgrel'][0])
         and md.get('epoch',[]) in ([],['0']), 'EXACT_REFERENCE_RELEASE_NO_UNBOUND_EPOCH')
    version = '6.12.0-'+md['pkgrel'][0]
    for row in outputs:
        need(set(row) == {'name','version','arch','filename'} and row['arch'] == 'aarch64'
             and row['version'] == version and row['filename'] == row['name']+'-'+version+'-aarch64.pkg.tar.xz', 'EXACT_XZ_OUTPUT_BASENAME')
    need(not {re.split('[<>=]',n)[0] for names in deps.values() for n in names}&{row['name'] for row in outputs},'NO_SELF_BINARY_BUILD_DEPENDENCY')
    need(type(value['features']) is list and value['features'] and len(value['features']) <= 128
         and type(value['declared_peak_writable_bytes']) is int and 0 < value['declared_peak_writable_bytes'] <= 64*1024**3,'EXPLICIT_QT_FEATURE_AND_STORAGE_DEMAND')
    need(type(value['sources']) is dict and 1 <= len(value['sources']) <= 32 and type(value['licenses']) is dict and value['licenses'], 'EXPLICIT_SOURCE_PATCH_LICENSE_PINS')
    for name,row in value['sources'].items():
        member(name);need('/' not in name and type(row) is dict and set(row) == {'path','bytes','sha256'},'EXPLICIT_ORDINARY_SOURCE_ALIAS')
        descriptor({k:row[k] for k in ('bytes','sha256')},512*1024**2)
        need(row['bytes'] > 0,'NONEMPTY_SOURCE_INPUT')
    source_rows = md.get('source',[])+md.get('source_aarch64',[])
    sums = md.get('sha256sums',[])+md.get('sha256sums_aarch64',[])
    aliases = [row.split('::',1)[0] if '::' in row else row.rsplit('/',1)[-1] for row in source_rows]
    need(len(aliases) == len(set(aliases)) == len(sums) and set(aliases) == set(value['sources'])
         and all(sha == value['sources'][name]['sha256'] for name,sha in zip(aliases,sums)), 'SRCINFO_SOURCE_ALIAS_AND_SHA256_JOIN')
    need(type(decode(bodies['source.json'])) is dict,'SOURCE_PROVENANCE_JSON_DATA')
    need(sum(row['bytes'] for row in value['sources'].values()) <= 2*1024**3,'QT_SOURCE_TOTAL_CAP')
    for name,row in value['licenses'].items():
        need(name in value['files'] and row == {k:value['files'][name][k] for k in ('bytes','sha256')},'EXACT_RECIPE_LICENSE_NOTICE')
    return value,bodies


def signed_input_plan(lock,baseline,recipe):
    expected = dict(line.split(' ',1) for line in baseline.decode().splitlines())
    need(len(expected) == 349,'EXACT349_BASELINE')
    packages = {r['name'][0]:r['version'][0] for r in lock['rootfs_packages']}
    packages.update({r['name']:r['version'] for r in lock['packages']})
    need(len(packages) == 341 and all(expected.get(n) == v for n,v in packages.items()),'ORIGINAL341_IN349')
    rows = []
    for item in [lock['rootfs'],*lock['packages']]:
        for suffix in ('','.sig'):
            rows.append(dict(role='official_base/'+item['filename']+suffix,filename=item['filename']+suffix,
                bytes=item['signature_size'] if suffix else item['size'],sha256=item['signature_sha256'] if suffix else item['sha256'],path=None,status='UNBOUND_PROVIDER'))
    for item in lock['keyring_files']:
        rows.append(dict(role='official_public_keyring/'+item['filename'],filename=item['filename'],bytes=item['size'],sha256=item['sha256'],path=None,status='UNBOUND_PROVIDER'))
    need(len(rows) == 501 and len({r['role'] for r in rows}) == 501,'EXACT501_ORIGINAL_SIGNED_INPUT_ROLES')
    additions = [dict(name=n,version=expected[n],archive=None,signature=None,status='SUPPLEMENTAL_PIN_AND_PROVIDER_REQUIRED') for n in sorted(set(expected)-set(packages))]
    need(len(additions) == 8,'EXACT8_SUPPLEMENTAL_PACKAGES')
    dependency_rows = None if recipe is None else {kind:[dict(requirement=n,
        baseline_candidate_version=expected.get(re.split('[<>=]',n)[0]),
        status='SIGNED_PROVIDER_AND_VERSION_CONSTRAINT_JOIN_REQUIRED' if re.split('[<>=]',n)[0] in expected else 'ADDITIONAL_SIGNED_PROVIDER_REQUIRED')
        for n in names] for kind,names in recipe['dependencies'].items()}
    missing_packages = None if recipe is None else sorted({re.split('[<>=]',n)[0]
        for names in recipe['dependencies'].values() for n in names if re.split('[<>=]',n)[0] not in expected})
    return dict(kind='QT612_SIGNED_BUILD_INPUT_PLAN_DATA_V1',expected_package_count=349,
        existing_metadata_roles=rows,supplemental_packages=additions,required_material_roles=517,
        bound_material_roles=0,provider=None,current_official_public_trust=None,
        recipe_dependencies=dependency_rows,additional_package_names=missing_packages,
        version_constraint_acceptance=None,normal_dependency_checks_required=True,
        unsigned_dependency_install_allowed=False,additional_transaction=None,Root_acceptance=None)


def native_gate(*args,**kwargs):
    if args or not kwargs:
        raise ValueError('QT612_SOURCE_ONLY_NO_OPERATIONAL_RUNTIME_OR_ROOT_AUTHORITY')
    import importlib.util
    spec = importlib.util.spec_from_file_location('qt612_complete_producer',HERE/'producer.py')
    producer = importlib.util.module_from_spec(spec);spec.loader.exec_module(producer)
    return producer.native_gate(**kwargs)


def construct(*,framework,diagnostic_basis,output,recipe_selection=None,recipe_selection_pin=None,recipe_root=None):
    framework,diagnostic_basis,out = map(ordinary,(framework,diagnostic_basis,output));observed = {}
    need(not out.exists() and out.parent.is_dir() and all(not out.is_relative_to(p) and not p.is_relative_to(out)
         for p in (framework,diagnostic_basis)), 'FRESH_DISJOINT_PREPARATION_SOURCE')
    if recipe_root is not None:need(not out.is_relative_to(ordinary(recipe_root)),'DISJOINT_RECIPE_OUTPUT')
    basis = load(HERE/'basis.lock.json',BASIS_PIN,observed);policy = load(HERE/'resource-PROPOSAL.json',POLICY_PIN,observed)
    need(basis['Source85_Root_closure_review'] == 'PENDING' and policy['accepted'] is False and policy['Root_acceptance'] is None and policy['measured'] is False,'SOURCE85_AND_RESOURCE_REVIEW_UNISSUED')
    basis_bodies = {}
    for group,root in (('framework_files',framework),('Source85_files',diagnostic_basis)):
        for name,row in basis[group].items():
            raw = stream(root/name,{k:row[k] for k in ('bytes','sha256')},observed,collect=True,mode=row['mode'])
            basis_bodies['basis/'+group+'/'+name+'.DATA'] = raw
    declaration = decode(basis_bodies['basis/Source85_files/mount-class-diagnostics-v4.json.DATA'])
    need(declaration['Root_closure_review'] == 'PENDING' and declaration['actual87_payload_success'] is False and declaration['native_pair'] == 'NOT RUN','FAILED_ACTUAL_STAYS_FAILED_DIAGNOSTIC_ONLY')
    selected,bodies = None,{}
    if recipe_selection is not None:
        need(recipe_selection_pin is not None and recipe_root is not None,'EXTERNAL_FROZEN_RECIPE_SELECTION_REQUIRED')
        selected,bodies = recipe_contract(load(recipe_selection,recipe_selection_pin,observed),recipe_root,observed)
    else:need(recipe_selection_pin is None and recipe_root is None,'NO_PARTIAL_RECIPE_BINDING')
    lock = decode(basis_bodies['basis/framework_files/scripts/ci/inputs.lock.json.DATA'])
    baseline = basis_bodies['basis/framework_files/scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock.DATA']
    plan = signed_input_plan(lock,baseline,selected)
    missing = list(MISSING)
    if selected is not None:missing.remove(MISSING[0])
    actual = dict.fromkeys(ACTUAL)
    report = dict(schema=1,kind='QT612_REFERENCE_NATIVE_PREPARATION_DATA_ONLY',status='HOLD_UNBOUND_NATIVE_INPUTS',
        recipe_commit=None if selected is None else selected['recipe_commit'],recipe_revision_role='EXTERNALLY_SELECTED_RECIPE_DATA_NOT_NATIVE_OR_GIT_FETCH_PROOF',
        source_file_pins_verified=selected is not None,source_correspondence='UNBOUND_PENDING_F_SOURCE_SCHEMA_AND_ROOT_REVIEW',
        provider='UNBOUND',missing_roles=missing,actual=actual,
        Root_acceptance=None,native_dispatch_ready=False,native_pair='NOT_RUN',GPG='NOT_RUN',
        Source85_closure_review='PENDING_DIAGNOSTIC_ONLY',official_0bd04f_correspondence='HELD',
        normal_signed_dependency_checks=True,clean_attempts=2,check_required_each=True,
        comparison=['archive_bytes','payload','PKGINFO','BUILDINFO'],native16k='NOT_RUN',M2='NOT_RUN',legal='HELD',release=False)
    admission = dict(schema=1,kind='ROOT_QT612_REFERENCE_NATIVE_ADMISSION_V1',issued_by=None,accepted=False,
        source=None,ref=None,source_map_sha256=None,recipe_commit=None,provider=None,owner_program=None,
        resource_policy=None,created_utc=None,expires_utc=None,nonce=None,attempt=None,Root_acceptance=None)
    writer = Writer(out);files = {}
    try:
        for name,raw in basis_bodies.items():files[name] = writer.put(name,raw=raw)
        for name in ('basis.lock.json','resource-PROPOSAL.json','recipe-API.UNBOUND.json','prepare.py'):
            raw = stream(HERE/name,None,observed,collect=True);files['preparation/'+name] = writer.put('preparation/'+name,raw=raw)
        for name,raw in bodies.items():files['recipe/'+name] = writer.put('recipe/'+name,raw=raw,mode=selected['files'][name]['mode'])
        if selected is not None:
            for name,row in selected['sources'].items():
                files['recipe-sources/'+name] = writer.put('recipe-sources/'+name,source=row['path'],expected={k:row[k] for k in ('bytes','sha256')},observed=observed,cap=512*1024**2)
            files['recipe-selection.DATA.json'] = writer.put('recipe-selection.DATA.json',raw=encoded(selected))
        files['signed-input-plan.DATA.json'] = writer.put('signed-input-plan.DATA.json',raw=encoded(plan))
        files['Root-admission.UNISSUED.DATA.json'] = writer.put('Root-admission.UNISSUED.DATA.json',raw=encoded(admission))
        files['Root-runtime.UNISSUED.DATA.json'] = writer.put('Root-runtime.UNISSUED.DATA.json',raw=encoded(dict(admission,kind='ROOT_QT612_REFERENCE_NATIVE_RUNTIME_V1')))
        files['preparation.DATA.json'] = writer.put('preparation.DATA.json',raw=encoded(report))
        mapping = dict(schema=1,kind='QT612_REFERENCE_PREPARATION_SOURCE_ONLY_V1',files=files,actual=actual,
                       operational_entry=None,Root_acceptance=None,native_dispatch_ready=False)
        raw = encoded(mapping);writer.put('source-map.json',raw=raw)
        unchanged(observed)
        admitted_preparation(out,pin(raw)['sha256'])
        return dict(report,source_map=pin(raw),files=len(files)+1,bytes=sum(r['bytes'] for r in files.values())+len(raw))
    finally:writer.close()


def admitted_preparation(root,expected_map_sha256):
    root = ordinary(root);p = root/'source-map.json';observed = {}
    need(type(expected_map_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_map_sha256),'EXTERNAL_SOURCE_MAP_PIN_REQUIRED')
    size = p.lstat().st_size;raw = stream(p,dict(bytes=size,sha256=expected_map_sha256),observed,collect=True)
    value = decode(raw)
    need(raw == encoded(value) and value['kind'] == 'QT612_REFERENCE_PREPARATION_SOURCE_ONLY_V1'
         and value['operational_entry'] is None and value['Root_acceptance'] is None
         and value['native_dispatch_ready'] is False and set(value['actual']) == set(ACTUAL)
         and all(v is None for v in value['actual'].values()), 'UNISSUED_CLOSED_SOURCE_ONLY_MAP')
    rows = value['files'];need(type(rows) is dict and 20 < len(rows) <= 256 and sum(r['bytes'] for r in rows.values()) <= 2*1024**3,'FINITE_SOURCE_CLOSURE')
    found = set();pending = [root];nodes = 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            nodes += 1;need(nodes <= 1024 and not path.is_symlink(),'FINITE_ORDINARY_SOURCE_NAMESPACE')
            if path.is_dir():pending.append(path)
            else:need(path.is_file(),'ORDINARY_SOURCE_ONLY_LEAF');found.add(path.relative_to(root).as_posix())
    need(found == set(rows)|{'source-map.json'},'COMPLETE_PREPARATION_SOURCE_NAMESPACE')
    for name,row in rows.items():
        member(name);need(set(row) == {'bytes','sha256','mode'} and type(row['mode']) is int and row['mode'] in (0o644,0o755),'EXACT_SOURCE_FILE_MODE')
        stream(root/name,{k:row[k] for k in ('bytes','sha256')},observed,cap=512*1024**2,mode=row['mode'])
    unchanged(observed)
    return dict(status='PASS_PREPARATION_SOURCE_DATA_ONLY',native_dispatch_ready=False,Root_acceptance=None,actual=dict.fromkeys(ACTUAL))


def fence(event,args):
    need(not event.startswith(('subprocess.','socket.','ctypes.')) and event not in
         ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit','os.pidfd_open'), 'QT612_DATA_NO_ACTORS_OR_KERNEL_CUSTODY')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('framework','diagnostic-basis','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--recipe-selection',type=Path);parser.add_argument('--recipe-selection-sha256');parser.add_argument('--recipe-root',type=Path)
    args = parser.parse_args();selected = None
    if args.recipe_selection is not None:selected = dict(bytes=args.recipe_selection.lstat().st_size,sha256=args.recipe_selection_sha256)
    sys.addaudithook(fence)
    report = construct(framework=args.framework,diagnostic_basis=args.diagnostic_basis,output=args.output,
        recipe_selection=args.recipe_selection,recipe_selection_pin=selected,recipe_root=args.recipe_root)
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__ == '__main__':main()
