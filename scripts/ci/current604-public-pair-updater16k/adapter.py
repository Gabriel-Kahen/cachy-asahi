# SPDX-License-Identifier: MIT
"""Only outer dispatch and the native-Docker entry predicate change."""
import ast
from pathlib import Path
import contract as C

def change(raw,before,after):
 text=raw.decode();C.need(text.count(before)==1,'one exact16K adapter anchor: '+before[:90]);text=text.replace(before,after);ast.parse(text);return text.encode()

SIGNATURE_DIAGNOSTIC = '_SIGNATURE_FAILURE_DATA = None\n\ndef signature_failure(args, proc):\n    """Existing failed -U capture only. No key contents or acceptance authority."""\n    global _SIGNATURE_FAILURE_DATA\n    if not (args[0] == \'pacman\' and \'-U\' in args and proc.returncode):\n        return\n    import stat, time\n    try:\n        conf = Path(args[args.index(\'--config\') + 1])\n        need(re.fullmatch(r\'/tmp/composition-[a-z0-9_]{8}/pacman\\.conf\', str(conf)), \'owned private signature diagnostic path\')\n        trust = conf.parent / \'trust\'\n        need(not any(p.is_symlink() for p in (trust, *trust.parents)), \'ordinary private trust diagnostic\')\n        st = trust.lstat()\n        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700, \'exact original private keyring lease\')\n        files = {}\n        for name in (\'pubring.gpg\', \'pubring.kbx\', \'trustdb.gpg\', \'common.conf\', \'gpg.conf\'):\n            p = trust / name\n            try:\n                v = p.lstat()\n            except FileNotFoundError:\n                files[name] = {\'present\': False}\n                continue\n            files[name] = dict(present=True, regular=stat.S_ISREG(v.st_mode), symlink=stat.S_ISLNK(v.st_mode), mode=stat.S_IMODE(v.st_mode), uid=v.st_uid, bytes=v.st_size)\n        messages = []\n        for line in (proc.stdout + \'\\n\' + proc.stderr).splitlines():\n            for marker in (\'gpg error: \', \'GPGME version: \', \'signature timestamp is greater than system time.\'):\n                if marker in line:\n                    messages.append((marker + line.split(marker, 1)[1])[:160])\n        _SIGNATURE_FAILURE_DATA = dict(schema_version=1, status=\'FAILED_REQUIRED_SIGNATURE_OPERANDS_NOT_ACCEPTANCE\', epoch_ns=time.time_ns(), exit_code=proc.returncode, trust=dict(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid, readonly=bool(os.statvfs(trust).f_flag & os.ST_RDONLY), read=os.access(trust,os.R_OK), write=os.access(trust,os.W_OK), search=os.access(trust,os.X_OK)), files=files, GPGME_messages=messages[-4:], messages_omitted=max(0,len(messages)-4), original_crypto_error=\'UNKNOWN_IF_NOT_IN_CAPTURE\', acceptance_authority=False)\n        need(len(json.dumps(_SIGNATURE_FAILURE_DATA).encode()) <= 2048, \'bounded signature diagnostic\')\n    except Exception as error:\n        _SIGNATURE_FAILURE_DATA = dict(schema_version=1, status=\'SIGNATURE_OPERANDS_UNAVAILABLE_NOT_ACCEPTANCE\', error_type=type(error).__name__, acceptance_authority=False)\n\n\n'

def caller(raw):
 out=change(raw,"and os.geteuid() == 0 and Path('/.dockerenv').is_file()", "and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()")
 out=change(out,'def guard():',SIGNATURE_DIAGNOSTIC+'def guard():')
 out=change(out,"run(pacman + ['--noconfirm', '--noscriptlet', '--ask', '4', '-U', *archives])", "run(pacman + ['--debug', '--noconfirm', '--noscriptlet', '--ask', '4', '-U', *archives])")
 out=change(out,"    if proc.returncode:\n        print(proc.stdout[-8192:], proc.stderr[-8192:], flush=True)","    if proc.returncode:\n        signature_failure(args, proc)\n        print(proc.stdout[-8192:], proc.stderr[-8192:], flush=True)")
 out=change(out,"    print(json.dumps(result, sort_keys=True), flush=True)","    print(json.dumps(result, sort_keys=True), flush=True)\n    if _SIGNATURE_FAILURE_DATA is not None:\n        print('APPS6_KEYRING_FAILURE_DATA '+json.dumps(_SIGNATURE_FAILURE_DATA,sort_keys=True,separators=(',',':')),flush=True)")
 return out

def owner(raw):
 old="old.command(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner.py'],public/'transaction.log',3900)"
 new="vm.run(a,argv,image,public,raw,old,3900)"
 out=change(raw,old,new)
 out=change(out,"'audio-inputs','output')", "'audio-inputs','output','kernel-work','kernel-receipt','updater-decisions')")
 out=change(out,"a=p.parse_args(argv);policy=C.policy()", "a=p.parse_args(argv);vm.authorize(a);policy=C.policy()")
 out=change(out,"scope='GENERIC4K_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY'", "scope='GENERIC16K_VM_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY'")
 out=change(out,"result.update(status='PASS',composition=row)","result.update(status='PASS',composition=row,generic16k=C.read(public/'updater16k-result.json'))")
 # Never alter transaction/case verification or producer/cache/volume disposal bodies.
 out=change(out,"failures=old.retire_outer(actor_owned,result);retired=not failures","failures=vm.retire_outer(old,actor_owned,result,public);retired=not failures")
 funcs=lambda r:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(r).body if isinstance(n,ast.FunctionDef)}
 a,b=funcs(raw),funcs(out);C.need([n for n in a if a[n]!=b[n]]==['main'],'only owner main routing may change')
 return out


PERSISTENT_STAGE_DATA = 'def persistent_stage_failure(before, staged, limits):\n    """Existing map DATA only. Equality and incomplete observation still refuse."""\n    try:\n        import math, time\n        actual = staged[\'nodes\']\n        need(type(before) is dict and type(actual) is dict and max(len(before), len(actual)) <= 200000, \'bounded original stage maps\')\n        need(all(type(n) is str and type(v) is dict for rows in (before,actual) for n,v in rows.items()), \'typed original node maps\')\n        need(type(staged[\'complete\']) is bool and not (staged[\'complete\'] is True and actual == before), \'failed stage predicate only\')\n        common = before.keys() & actual.keys()\n        changed = {n for n in common if before[n] != actual[n]}\n        missing, extra = before.keys() - actual.keys(), actual.keys() - before.keys()\n        examples = []\n        def node_pin(value):\n            raw = json.dumps(value, sort_keys=True, separators=(\',\', \':\'), allow_nan=False).encode()\n            need(len(raw) <= 32768, \'bounded original node metadata\')\n            return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())\n        for name in sorted(changed | missing | extra)[:5]:\n            old, new = before.get(name), actual.get(name)\n            fields = sorted(k for k in (old or {}).keys() | (new or {}).keys() if (old or {}).get(k) != (new or {}).get(k))\n            examples.append(dict(path=name[:256], path_truncated=len(name)>256, path_sha256=hashlib.sha256(name.encode()).hexdigest(), kind=\'changed\' if name in changed else \'missing\' if name in missing else \'extra\', fields=[n[:64] for n in fields[:16]], fields_truncated=len(fields)>16, before=None if old is None else node_pin(old), after=None if new is None else node_pin(new)))\n        reasons = staged[\'unsupported_counts\']\n        need(type(reasons) is dict and len(reasons) <= 64 and all(type(k) is str and type(v) is int and 0 < v <= 200000 for k,v in reasons.items()), \'bounded original observation reasons\')\n        remaining = limits.deadline - time.monotonic()\n        need(math.isfinite(remaining), \'finite original stage clock\')\n        value = dict(schema_version=1, status=\'PERSISTENT_STAGE_FAILURE_DATA_NOT_ACCEPTANCE\', observation_complete=staged[\'complete\'], node_maps_equal=actual==before, comparison_scope=\'COMPLETE_MAPS\' if staged[\'complete\'] else \'PARTIAL_OBSERVATION_NOT_EVIDENCE_OF_SOURCE_DRIFT\', expected_nodes=len(before), observed_nodes=len(actual), missing_nodes=len(missing), extra_nodes=len(extra), changed_nodes=len(changed), examples=examples, omitted_examples=max(0,len(changed|missing|extra)-len(examples)), unsupported_counts={k[:96]:v for k,v in sorted(reasons.items())[:8]}, unsupported_reasons_omitted=max(0,len(reasons)-8), stage_remaining_seconds=remaining, stage_deadline_exhausted=remaining<=0, cleanup_authority=False, acceptance_authority=False)\n        raw = json.dumps(value, sort_keys=True, separators=(\',\', \':\'), allow_nan=False)\n        need(len(raw.encode()) <= 6144, \'bounded persistent stage diagnostic\')\n        print(\'APPS6_PERSISTENT_STAGE_FAILURE \'+raw, file=sys.stderr, flush=True)\n    except Exception:\n        pass  # Diagnostic loss never replaces the unchanged original refusal.\n\n\n'
PERSISTENT_STAGE_GUARD = "    need(staged['complete'] is True and staged['nodes'] == before, 'complete persistent stage differs')"
PERSISTENT_STAGE_WRAPPER = "    try:\n        need(staged['complete'] is True and staged['nodes'] == before, 'complete persistent stage differs')\n    except ValueError:\n        persistent_stage_failure(before, staged, limits)\n        raise"


PERSISTENT_OBSERVATION_API = 'def _mount600(original):\n    import ctypes\n    import errno\n    import os\n    import sys\n    # Linux statx UAPI: mask offset0, mnt_id offset144, fixed256-byte record.\n    # Request ordinary STATX_MNT_ID, never the distinct MNT_ID_UNIQUE namespace.\n    class Statx600(ctypes.Structure):\n        _fields_=[(\'mask\',ctypes.c_uint32),(\'prefix\',ctypes.c_ubyte*140),\n                  (\'mnt_id\',ctypes.c_uint64),(\'reserved\',ctypes.c_ubyte*104)]\n    supported=(sys.platform==\'linux\' and sys.byteorder==\'little\' and ctypes.sizeof(ctypes.c_void_p)==8 and\n               os.uname().machine in (\'aarch64\',\'x86_64\') and ctypes.sizeof(Statx600)==256 and Statx600.mnt_id.offset==144)\n    libc=ctypes.CDLL(None,use_errno=True) if supported else None\n    call=getattr(libc,\'statx\',None)\n    if call is not None:\n        call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Statx600))\n        call.restype=ctypes.c_int\n    checked=False\n    def query(descriptor,limits):\n        nonlocal call,checked\n        limits.tick()\n        if call is None:return original(descriptor,limits)\n        result=Statx600()\n        if call(descriptor,b\'\',0x1000,0x1000,ctypes.byref(result))!=0:\n            error=ctypes.get_errno()\n            if error in (errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP,errno.EPERM):\n                call=None;return original(descriptor,limits)\n            raise OSError(error,\'descriptor statx mount query failed\')\n        if not result.mask&0x1000:\n            call=None;return original(descriptor,limits)\n        if not result.mnt_id:raise ValueError(\'descriptor statx mount identity unavailable\')\n        if not checked:\n            if result.mnt_id!=original(descriptor,limits):raise ValueError(\'descriptor mount identity APIs differ\')\n            checked=True\n        return result.mnt_id\n    return query\n\ndef persistent_apis(roots,copier,resolver,driver):\n    """Private APIs only; held walkers/copy/hash/check code and fresh FDs remain."""\n    import types\n    def held(module,size,digest):\n        raw=Path(module.__file__).read_bytes()\n        if module is roots and b\'max_packages: int = 604\' in raw:\n            # Current604\'s exact selected source changes this sole typed default.\n            # Reverse it before the existing whole original source proof; every\n            # observation/copy/security predicate remains byte held.\n            selected=b\'max_packages: int = 604\'\n            need(raw.count(selected)==1,\'one selected604 root package limit\')\n            raw=raw.replace(selected,b\'max_packages: int = 587\',1)\n        need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,\'whole persistent observation API source\')\n    held(roots,35970,\'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d\')\n    held(copier,25734,\'e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b\')\n    def clone(function,namespace):\n        result=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)\n        result.__kwdefaults__=function.__kwdefaults__\n        return result\n    def relative_api(module,digest):\n        import ast,os\n        text=Path(module.__file__).read_text()\n        nodes=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==\'relative\']\n        need(len(nodes)==1 and hashlib.sha256(ast.get_source_segment(text,nodes[0]).encode()).hexdigest()==digest,\'whole original relative validator source\')\n        original=module.relative\n        if os.name!=\'posix\':return original\n        def relative(value):\n            # No filesystem/graph results or strings are retained. Canonical\n            # positive POSIX components need no pathlib normalization; every\n            # uncertain operand takes the entire unchanged original validator.\n            if type(value)is str and value and \'\\0\'not in value and all(p not in(\'\',\'.\',\'..\')for p in value.split(\'/\')):return value\n            return original(value)\n        return relative\n    private_installer=types.SimpleNamespace(**vars(roots.installer))\n    private_installer.relative=relative_api(roots.installer,\'486c47ebbe2e6cfc392bde908003baf7559fd70d2f6ed17684f2ba34340fac41\')\n    private_roots=types.SimpleNamespace(**vars(roots))\n    private_roots._mount_id=_mount600(roots._mount_id)\n    private_roots.installer=private_installer\n    private_roots.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=private_roots._mount_id,installer=private_installer))\n    from contextlib import contextmanager\n    copy_scope=dict(copier.copy_data.__globals__,roots=private_roots)\n    for name in (\'_parent\',\'_root_check\',\'_source_alias\',\'_copy_internal\',\'copy_data\'):\n        original=getattr(copier,name)\n        copy_scope[name]=(contextmanager(clone(original.__wrapped__,copy_scope))\n                          if name==\'_parent\' else clone(original,copy_scope))\n    private_copier=types.SimpleNamespace(**copy_scope)\n    private_driver=driver\n    if driver is not None:\n        private_driver=types.SimpleNamespace(**vars(driver))\n        private_driver.relative=relative_api(driver,\'382ec23738149e6f6ebb9a35d399f9a7e1366f6352ab7a2a64d734e3244f9ead\')\n        private_driver.database=clone(driver.database,dict(driver.database.__globals__,relative=private_driver.relative))\n    return private_roots,private_copier,resolver,private_driver\n\n\n'
PERSISTENT_API_OLD = '    return full_root, measure_copy, root_path, driver'
PERSISTENT_API_NEW = '    return persistent_apis(full_root, measure_copy, root_path, driver)'

PHASE_LABELS=('PATHS','APIS','PARENT','MOUNTS','SOURCE_BEFORE','SOURCE_DB','SELECTION','OWN_BEFORE','COPY','RESTORE','STAGED_OBSERVE','STAGED_EQUALITY','STAGED_DB','OWN_AFTER','SOURCE_AFTER','SOURCE_EQUALITY','MOUNT_EQUALITY','MANIFEST','SOURCE_WALK','SOURCE_HARDLINKS')
PHASE_HELPER='''_UPDATER_PHASE_BYTES = 4096
_UPDATER_PHASE_LABELS = LABELS_PLACEHOLDER

def _updater_phase_write(state, label):
    global _UPDATER_PHASE_BYTES
    if state not in ('BEGIN','END','FAIL') or label not in _UPDATER_PHASE_LABELS:
        return
    raw = ('UPDATER489_STAGE_PHASE '+state+' '+label+'\\n').encode('ascii')
    if len(raw) > _UPDATER_PHASE_BYTES:
        return
    _UPDATER_PHASE_BYTES -= len(raw)
    try:
        os.write(2, raw)
    except OSError:
        pass

@contextmanager
def _updater_phase(label):
    _updater_phase_write('BEGIN', label)
    try:
        yield
    except BaseException:
        _updater_phase_write('FAIL', label)
        raise
    else:
        _updater_phase_write('END', label)


'''.replace('LABELS_PLACEHOLDER',repr(PHASE_LABELS))

def strip_phase(raw):
 text=raw.decode();assert text.count(PHASE_HELPER)==1,'whole fixed phase helper required';text=text.replace(PHASE_HELPER,'',1);tree=ast.parse(text);lines=text.splitlines(keepends=True);remove=set();depth={}
 for n in ast.walk(tree):
  if not isinstance(n,ast.With):continue
  call=n.items[0].context_expr
  if not(isinstance(call,ast.Call)and isinstance(call.func,ast.Name)and call.func.id=='_updater_phase'):continue
  assert len(n.items)==1 and n.items[0].optional_vars is None and len(call.args)==1 and not call.keywords and ast.literal_eval(call.args[0])in PHASE_LABELS,'fixed phase wrapper only'
  assert lines[n.lineno-1]==' '*n.col_offset+"with _updater_phase("+repr(ast.literal_eval(call.args[0]))+"):\n",'exact phase syntax';remove.add(n.lineno)
  for i in range(n.lineno+1,n.end_lineno+1):depth[i]=depth.get(i,0)+4
 return ''.join(line[depth.get(i,0):]if line.strip()else line for i,line in enumerate(lines,1)if i not in remove).encode()

def phase_scope(raw):
 text=raw.decode();tree=ast.parse(text);functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)};material=functions['materialize'];source=functions['source_manifest'];assert len(material.body)==29 and len(source.body)==13,'whole original phase statement counts'
 groups=[('PATHS',1,6),('APIS',7,7),('PARENT',8,9),('MOUNTS',10,11),('SOURCE_BEFORE',12,12),('SOURCE_DB',13,13),('SELECTION',14,15),('OWN_BEFORE',16,16),('COPY',17,18),('RESTORE',19,19),('STAGED_OBSERVE',20,20),('STAGED_EQUALITY',21,21),('STAGED_DB',22,22),('OWN_AFTER',23,23),('SOURCE_AFTER',24,24),('SOURCE_EQUALITY',25,25),('MOUNT_EQUALITY',26,26),('MANIFEST',27,28)]
 wraps=[(label,material.body[a],material.body[b])for label,a,b in groups]+[('SOURCE_WALK',source.body[6],source.body[7]),('SOURCE_HARDLINKS',source.body[8],source.body[11])];lines=text.splitlines(keepends=True)
 for label,first,last in sorted(wraps,key=lambda r:r[1].lineno,reverse=True):
  a,b=first.lineno-1,last.end_lineno;old=lines[a:b];lines[a:b]=[' '*first.col_offset+"with _updater_phase("+repr(label)+"):\n"]+['    '+line if line.strip()else line for line in old]
 out=''.join(lines);anchor='def materialize(';assert out.count(anchor)==1;out=out.replace(anchor,PHASE_HELPER+anchor,1).encode();assert strip_phase(out)==raw,'complete strip-only source inverse';return out


def persistent_stage(raw):
 """Exact original persistent helper, one failure-only pre-existing guard seam."""
 C.need(C.sha(raw)=='cd1f23bd252b77e9b3a9e907e1c0defd5141025408e92ae5c2500152076b6f3a','whole original persistent helper source')
 text=raw.decode();helper=PERSISTENT_OBSERVATION_API+PERSISTENT_STAGE_DATA
 C.need(text.count('def materialize(')==1 and text.count(PERSISTENT_STAGE_GUARD)==1,'one original persistent-stage guard')
 text=text.replace('def materialize(',helper+'def materialize(',1).replace(PERSISTENT_STAGE_GUARD,PERSISTENT_STAGE_WRAPPER,1)
 C.need(text.count(PERSISTENT_API_OLD)==1,'one private observation API seam');text=text.replace(PERSISTENT_API_OLD,PERSISTENT_API_NEW,1)
 ast.parse(text)
 C.need(text.replace(helper,'',1).replace(PERSISTENT_STAGE_WRAPPER,PERSISTENT_STAGE_GUARD,1).replace(PERSISTENT_API_NEW,PERSISTENT_API_OLD,1).encode()==raw,'whole persistent helper inverse')
 return phase_scope(text.encode())

MATERIALIZATION_PROFILE='MATERIALIZE1200_NONRESERVED_CALLER3900_V1'
MATERIALIZATION_HOOKS={
 'normal':(14121,'43d51c985c3164e6e8d8fb7b62b764580a4a096fbf1b3a02de471cbcefcac2a3'),
 'precommit-exit86':(14745,'b0bb74f125d74521ad488c07fdefe0ab251eaeafda6d7061e11bdeda880bcd8a'),
 'postcommit-exit87':(15123,'b64fbdcad25d9f62d268809067d46ac2e9da4394da1a864eb8ad8851067e1fdb')}
MATERIALIZATION_STAGE_BEFORE="('stage_seconds', 900)"
MATERIALIZATION_STAGE_AFTER="('stage_seconds', 1200)"

def validation_hook(raw,case):
 """Only the private prepared validator's stage ceiling; all bodies held."""
 C.need(case in MATERIALIZATION_HOOKS,'explicit materialization validation case')
 size,digest=MATERIALIZATION_HOOKS[case]
 C.need(len(raw)==size and C.sha(raw)==digest,'whole prepared materialization hook source')
 text=raw.decode();C.need(text.count(MATERIALIZATION_STAGE_BEFORE)==1,'one exact stage capacity ceiling')
 changed=text.replace(MATERIALIZATION_STAGE_BEFORE,MATERIALIZATION_STAGE_AFTER,1)
 C.need(changed.replace(MATERIALIZATION_STAGE_AFTER,MATERIALIZATION_STAGE_BEFORE,1)==text,'whole hook stage-ceiling inverse')
 ast.parse(changed);return changed.encode()

def materialization_validation_profile(value,calling,case):
 """Prospective allowance; caller/worker3900 remain hard enclosing ceilings.

 Failure maxima total4200, previously3900 before setup. Nested allowances are
 NOT reserved time, an additive-fit proof, or a promise of actual completion.
 """
 C.need(case in MATERIALIZATION_HOOKS,'explicit1200 capacity case')
 driver=1860 if case=='normal' else 2400
 C.need({k:value[k] for k in ('stage_seconds','driver_seconds','verify_seconds','copy_seconds')}==dict(stage_seconds=900,driver_seconds=driver,verify_seconds=600,copy_seconds=600),'exact preceding per-case budgets; no product/transaction increase')
 name='scripts/ci/full-root-upgrade-caller/upgrade_hook.py';path=calling/'upgrade_hook.py';before=path.read_bytes()
 C.need(value['code_pins'].get(name)==C.sha(before),'whole original prepared hook pin required')
 after=validation_hook(before,case);path.write_bytes(after)
 value['code_pins'][name]=C.sha(after);value['stage_seconds']=1200
 return dict(profile=MATERIALIZATION_PROFILE,case=case,semantics='NONRESERVED_NESTED_STAGE_ALLOWANCE_HARD3900_ENCLOSING_CEILINGS',stage_before_seconds=900,stage_seconds=1200,driver_seconds=driver,verify_seconds=600,copy_seconds=600,caller_seconds=3900,worker_seconds=3900,nested_stage_driver_verify_sum=1200+driver+600,prior_nested_stage_driver_verify_sum=900+driver+600,additive_composition_fit='NOT_ESTABLISHED',reserved_setup_or_cleanup_seconds=0,old900_fit='NOT_ESTABLISHED',future_case_runtime_fit='REQUIRES_ORIGINAL_ACTUAL_EACH_CASE',original_rereads_security_and_product_limits='HELD',hook_before=dict(bytes=len(before),sha256=C.sha(before)),hook_after=dict(bytes=len(after),sha256=C.sha(after)))


DRIVER_COPY_PROFILE='DRIVER_COLD_COPY1200_NONRESERVED_CALLER3900_V1'
DRIVER_COPY_HOOKS={'normal': {'bytes': 14122, 'sha256': '554f1b434925796de48149b498a2ff26f04ef173bab5d7afc8469bb96f7a0a3a'}, 'postcommit-exit87': {'bytes': 15124, 'sha256': '2322852090e24b97037acce9960ade809ee97b1713968a17a9554ee11df565b8'}, 'precommit-exit86': {'bytes': 14746, 'sha256': 'bfdd6101336e72660cfb6f38c4a640e308c2142e0b9725f84fd2ca5f0ac2dde2'}}
DRIVER_COPY_BEFORE="('copy_seconds', 900)"
DRIVER_COPY_AFTER="('copy_seconds', 1200)"

def driver_copy_hook(raw,case):
 """Only the private selected copy allowance; whole original driver is held."""
 C.need(case in DRIVER_COPY_HOOKS,'exact cold-copy validation case')
 C.need(dict(bytes=len(raw),sha256=C.sha(raw))==DRIVER_COPY_HOOKS[case],'whole materialization1200 private hook source')
 text=raw.decode();C.need(text.count(DRIVER_COPY_BEFORE)==1,'one exact private copy ceiling')
 changed=text.replace(DRIVER_COPY_BEFORE,DRIVER_COPY_AFTER,1)
 C.need(changed.replace(DRIVER_COPY_AFTER,DRIVER_COPY_BEFORE,1)==text,'whole private hook copy-ceiling inverse')
 ast.parse(changed);return changed.encode()

def driver_copy_validation_profile(value,calling,case):
 """Copy1200 is nested, nonreserved time inside unchanged driver/3900 ceilings."""
 C.need(case in DRIVER_COPY_HOOKS,'explicit cold-copy profile case')
 driver=1860 if case=='normal'else 2400
 keys=('stage_seconds','driver_seconds','verify_seconds','copy_seconds')
 C.need(all(type(value[k])is int for k in keys)and {k:value[k]for k in keys}==dict(stage_seconds=1200,driver_seconds=driver,verify_seconds=600,copy_seconds=600),'whole prior stage/driver/verify/copy capacity profile')
 name='scripts/ci/full-root-upgrade-caller/upgrade_hook.py';path=calling/'upgrade_hook.py';before=path.read_bytes()
 C.need(value['code_pins'].get(name)==C.sha(before),'whole preceding hook code pin')
 after=driver_copy_hook(before,case);path.write_bytes(after);value['code_pins'][name]=C.sha(after);value['copy_seconds']=1200
 return dict(profile=DRIVER_COPY_PROFILE,case=case,semantics='NONRESERVED_COPY_ALLOWANCE_WITHIN_UNCHANGED_DRIVER_AND_HARD3900',copy_before_seconds=600,copy_seconds=1200,copy_is_nested_within_driver=True,stage_seconds=1200,driver_seconds=driver,verify_seconds=600,caller_seconds=3900,worker_seconds=3900,nested_stage_driver_verify_sum=1200+driver+600,additive_composition_fit='NOT_ESTABLISHED',reserved_setup_or_cleanup_seconds=0,old600_copy_fit='NOT_ESTABLISHED',future_case_runtime_fit='REQUIRES_ORIGINAL_ACTUAL_EACH_CASE',original_driver_aux_runtime_and_product_defaults='BYTE_HELD',independent_materialization_profile=MATERIALIZATION_PROFILE,hook_before=dict(bytes=len(before),sha256=C.sha(before)),hook_after=dict(bytes=len(after),sha256=C.sha(after)))


def prepare_selected(selected,source,target,case,**options):
 config,calling=selected.prepare(source,target,case,**options)
 q=calling/'container.py';original=q.read_bytes();q.write_bytes(caller(original))
 scope=calling/'persistent_scope.py';scope_before=scope.read_bytes();scope.write_bytes(persistent_stage(scope_before))
 value=C.decode(C.read(config));name='scripts/ci/full-root-upgrade-caller/container.py'
 C.need(value['external_pins'].get('/persistent_scope.py')==C.sha(scope_before),'original persistent helper external pin required');value['external_pins']['/persistent_scope.py']=C.sha(scope.read_bytes());scope_name='scripts/ci/full-root-upgrade-caller/persistent_scope.py';C.need(value['code_pins'].get(scope_name)==C.sha(scope_before),'original persistent helper code pin required');value['code_pins'][scope_name]=C.sha(scope.read_bytes())
 C.need(value['code_pins'].get(name)==C.sha(original),'original caller source pin required');value['code_pins'][name]=C.sha(q.read_bytes());profile=materialization_validation_profile(value,calling,case);copy_profile=driver_copy_validation_profile(value,calling,case);C.save(config,value)
 proof=dict(driver_copy_validation_profile=copy_profile,validation_capacity_profile=profile,status='SOURCE_DERIVED_NOT_EXECUTED',before=C.sha(original),after=C.sha(q.read_bytes()),counted_edits=5,persistent_stage_diagnostic=dict(before=C.sha(scope_before),after=C.sha(scope.read_bytes()),original_guard='UNCHANGED_RERAISED',new_walks=0,acceptance_authority=False),config_sha256=C.sha(config.read_bytes()),unchanged='ALL_TRANSACTION_DECISIONS_GUARDS_AND_REQUIRED_SIGNATURE_POLICY',diagnostic='FAILURE_ONLY_ORIGINAL_LIBALPM_DEBUG_AND_BOUNDED_METADATA')
 C.save(calling/'updater16k-adapter.json',proof)
 receipt=C.decode(C.read(target/'adapter.json'));receipt['config_sha256']=proof['config_sha256'];receipt['updater16k_dispatch']=proof;C.save(target/'adapter.json',receipt)
 return config,calling
