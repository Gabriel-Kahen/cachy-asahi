# SPDX-License-Identifier: MIT
"""Synthetic MODEL ELF/receipt refusals only; no runnable Qt or actor evidence."""
import sys

sys.dont_write_bytecode = True


def no_actors(event, args):
    denied = event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
        'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'fcntl.flock',
        'os.remove', 'os.rename', 'os.mkdir', 'os.rmdir', 'os.chmod', 'os.chown', 'os.link', 'os.symlink')
    if event == 'open':
        mode, flags = args[1:3]
        denied |= bool(mode and any(c in mode for c in 'wxa+')) or bool(flags & (1 | 2 | 64 | 512 | 1024))
    if denied:
        raise RuntimeError('MODEL_RUNTIME_NO_ACTORS_OR_WRITES')


sys.addaudithook(no_actors)

import copy
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('gui18_runtime_model_controls', Path(__file__).with_name('runtime.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)


def model_elf(soname, needed=(), requirement=None, definitions=(), hazard=None, interpreter=None):
    """Deliberately non-executable MODEL bytes with real-format dynamic tables."""
    body = bytearray(4096); body[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', body, 16, 3, 183, 1)
    struct.pack_into('<Q', body, 32, 64)
    struct.pack_into('<HHH', body, 52, 64, 56, 3 if interpreter else 2)
    struct.pack_into('<IIQQQQQQ', body, 64, 1, 5, 0, 0x4000, 0x4000, len(body), len(body), 16384)
    strings = bytearray(b'\0')
    def text(value):
        start = len(strings); strings.extend(value.encode() + b'\0'); return start
    entries = [(14, text(soname))] + [(1, text(name)) for name in needed]
    if requirement:
        filename, name, digest, other, flags = requirement
        struct.pack_into('<HHIII', body, 2048, 1, 1, text(filename), 16, 0)
        struct.pack_into('<IHHII', body, 2064, digest, flags, other, text(name), 0)
        entries += [(0x6ffffffe, 0x4800), (0x6fffffff, 1)]
    if definitions:
        for i, (name, digest, index, flags) in enumerate(definitions):
            start = 2304 + i * 32
            struct.pack_into('<HHHHIII', body, start, 1, flags, index, 1, digest, 20,
                             32 if i + 1 < len(definitions) else 0)
            struct.pack_into('<II', body, start + 20, text(name), 0)
        entries += [(0x6ffffffc, 0x4900), (0x6ffffffd, len(definitions))]
    if hazard:
        entries.append((hazard, text('$ORIGIN/MODEL')))
    entries += [(5, 0x4400), (10, len(strings)), (0, 0)]
    body[1024:1024 + len(strings)] = strings
    struct.pack_into('<IIQQQQQQ', body, 120, 2, 6, 512, 0x4200, 0x4200, len(entries)*16, len(entries)*16, 8)
    for i, pair in enumerate(entries):
        struct.pack_into('<qQ', body, 512 + 16*i, *pair)
    if interpreter:
        data = interpreter.encode() + b'\0'; body[384:384 + len(data)] = data
        struct.pack_into('<IIQQQQQQ', body, 176, 3, 4, 384, 0x4180, 0x4180, len(data), len(data), 1)
    return bytes(body)


class Model:
    def __init__(self):
        self.retained = {}; self.image = 'sha256:' + '1'*64
        self.supervisor = dict(code_pin=self.keep(b'MODEL SUPERVISOR CODE, NOT EXECUTED'),
                               nonce='2'*32, owner_identity=[100, 200, 300])
        refs = {k:self.keep(('MODEL '+k).encode()) for k in
                ('archive_pin','signature_pin','native_provenance_pin','database_pin')}
        self.packages = {R.PACKAGE: dict(version='6.12.0-1',architecture='aarch64', provides=['qt6-base=6.12.0'], **refs),
                         'model-native-provider':dict(version='1-1',architecture='aarch64',provides=[],**refs)}
        self.stage = dict(status='PASS_QT612_GUI_DESTDIR_CONTRACT_ONLY', architecture='aarch64',
                          native_acceptance=None, files={}, symlinks={}, elf={})
        self.snapshot = dict(kind='GUI18_INSTALLED_RUNTIME_SNAPSHOT_V1', image=self.image,
            packages=self.packages, files={}, symlinks={}, loader_policy=dict(
                search_directories=['/usr/lib','/lib'],cache={},ld_library_path=None,
                ld_preload=None,ld_audit=None,ld_so_preload=None))
        for path in R.LIBRARIES:
            soname = path.rsplit('/',1)[1].replace('.6.12.0','.6')
            body = model_elf(soname, ['libMODEL.so.1'], ('libMODEL.so.1','MODEL_ABI_1',0x1234,2,0))
            self.file(path, body, R.PACKAGE, staged=True)
            self.alias('/usr/lib/'+soname, path.rsplit('/',1)[1], path, R.PACKAGE)
        self.file('/usr/lib/libMODEL.so.1.0', model_elf('libMODEL.so.1',
                  definitions=[('MODEL_ABI_1',0x1234,2,0)]), 'model-native-provider')
        self.alias('/usr/lib/libMODEL.so.1','libMODEL.so.1.0','/usr/lib/libMODEL.so.1.0','model-native-provider')
        self.alias('/lib','usr/lib','/usr/lib','model-native-provider')

    def keep(self, raw):
        p = R.pin(raw); self.retained[p['sha256']] = raw; return p

    def file(self, path, raw, package, staged=False):
        view = R.elf(raw); p = self.keep(raw)
        self.snapshot['files'][path] = dict(p, package=package, archive_member=path[1:],
                                           mode=0o755, uid=0,gid=0,elf=view)
        if staged:
            self.stage['files'][path[1:]] = dict(p,mode=0o755)
            self.stage['elf'][path[1:]] = dict(view,geometry_16k=True)

    def alias(self,path,target,resolved,package):
        self.snapshot['symlinks'][path] = dict(R.pin(target.encode()), target=target,
                                               resolved=resolved,package=package,mode=0o777,uid=0,gid=0)

    def callback(self,label,argv,observation,stdout=b'',child=400):
        events = dict(kind='GUI18_ORIGINAL_CALLBACK_EVENTS_V1',supervisor=self.supervisor,label=label,argv=argv,
            child_identity=[child,500,600], events=[dict(event='start',at=10),
            dict(event='natural-exit',at=11,exit_code=0),dict(event='reaped',at=12),dict(event='pidfd-retired',at=13)])
        data = dict(kind='GUI18_OWNED_CALLBACK_RECEIPT_V1',label=label,argv=argv,
            supervisor=self.supervisor,image=self.image,inventory_pin=self.snapshot['inventory_pin'],
            deadline_seconds=60,elapsed_seconds=3,exit_code=0,natural_exit=True,reaped=True,pidfd_retired=True,
            stdout_pin=self.keep(stdout),stderr_pin=self.keep(b''),
            events_pin=self.keep(R.encoded(events)),observation_pin=self.keep(R.encoded(observation)))
        raw = R.encoded(data); return raw,self.keep(raw)

    def inputs(self):
        for name,package in self.packages.items():
            entries = {p:dict(type='file',**{k:r[k] for k in ('bytes','sha256','mode')})
                       for p,r in self.snapshot['files'].items() if r['package']==name}
            entries.update({p:dict(type='symlink',**{k:r[k] for k in ('bytes','sha256','mode','target','resolved')})
                            for p,r in self.snapshot['symlinks'].items() if r['package']==name})
            meta = dict(kind='INSTALLED_PACKAGE_FILE_METADATA_V1',name=name,entries=entries,
                        **{k:package[k] for k in ('version','architecture','provides','archive_pin','signature_pin','native_provenance_pin')})
            package['database_pin'] = self.keep(R.encoded(meta))
        inventory = ''.join(n+' '+r['version']+'\n' for n,r in sorted(self.packages.items())).encode()
        self.snapshot['inventory_pin'] = self.keep(inventory)
        provider = dict(kind='GUI18_SIGNED_INSTALLED_PROVIDER_TUPLE_V1',image=self.image,
                        inventory_pin=self.snapshot['inventory_pin'],packages=self.packages,supervisor=self.supervisor)
        self.snapshot['provider_tuple_pin'] = self.keep(R.encoded(provider))
        stage_raw = R.encoded(self.stage); snapshot_raw = R.encoded(self.snapshot)
        stage_pin, snapshot_pin = self.keep(stage_raw),self.keep(snapshot_raw)
        pacman_raw,pacman_pin = self.callback('normal-package-dependencies',['/usr/bin/pacman','-T']+R.DEPENDS,
                                  dict(kind='PACMAN_T_NORMAL_DEPENDENCIES_V1',depends=R.DEPENDS))
        return dict(stage_raw=stage_raw,stage_pin=stage_pin,snapshot_raw=snapshot_raw,snapshot_pin=snapshot_pin,
            pacman_raw=pacman_raw,pacman_pin=pacman_pin,retained=self.retained,
            selection=dict(scope=R.SCOPE,recipe_commit=R.COMMIT,image=self.image,
                           inventory_pin=self.snapshot['inventory_pin'],snapshot_pin=snapshot_pin,
                           provider_tuple_pin=self.snapshot['provider_tuple_pin'],stage_pin=stage_pin))


class ModelRuntimeControls(unittest.TestCase):
    def test_whole_component_model_join_has_no_actual_credit(self):
        m = Model(); result = R.validate_dependencies(**m.inputs())
        self.assertEqual(len(result['modules']),18)
        self.assertEqual(len(result['files']),19)
        self.assertEqual(len(result['version_joins']),18)
        self.assertFalse(result['native_acceptance'])
        self.assertIsNone(result['Root_acceptance'])
        self.assertEqual(result['other54'],'OUTSIDE_COMPONENT_SCOPE')

    def test_real_b052_runtime_dependency_list_and_scope(self):
        root = Path(__file__).resolve().parents[3]
        contract = R.decoded((root/'packages/port/qt612-gui-source-reference/BUILD-CONTRACT.json').read_bytes())
        self.assertEqual(contract['dependencies']['runtime'],R.DEPENDS)
        self.assertEqual(len(R.DEPENDS),39)
        self.assertEqual(contract['package']['version'],'6.12.0-1')
        self.assertEqual(R.MODULES,sorted(R.MODULES))
        self.assertEqual(set(contract['expected_stage']['private_modules']),R.PRIVATE_MODULES)
        self.assertIn(R.OFFSCREEN_MARKER,(root/'packages/port/qt612-gui-source-reference/smoke.cpp').read_text())

    def test_missing_or_changed_raw_file_never_becomes_provider_success(self):
        for mutation in ('missing','drift'):
            m = Model(); args = m.inputs(); p = m.snapshot['files'][R.LIBRARIES[0]]
            if mutation == 'missing':m.retained.pop(p['sha256'])
            else:m.retained[p['sha256']] += b'DRIFT'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):R.validate_dependencies(**args)

    def test_name_only_unsigned_or_stale_snapshot_refuses(self):
        for mutation in ('missing-signature','wrong-image','mode','owner','snapshot-pin'):
            m = Model()
            if mutation == 'missing-signature':m.packages['model-native-provider']['signature_pin']=m.keep(b'')
            if mutation == 'wrong-image':m.snapshot['image']='sha256:'+'9'*64
            if mutation == 'mode':m.snapshot['files']['/usr/lib/libMODEL.so.1.0']['mode']=0o777
            if mutation == 'owner':m.snapshot['files']['/usr/lib/libMODEL.so.1.0']['package']='MISSING'
            args = m.inputs()
            if mutation == 'snapshot-pin':args['selection']['snapshot_pin']=R.pin(b'MODEL DRIFT')
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,KeyError)):R.validate_dependencies(**args)

    def test_original_pacman_receipt_not_custom_version_resolution(self):
        for field,value in [('argv',['pacman','-T','wayland']),('exit_code',127),('natural_exit',False),
                            ('reaped',False),('image','sha256:'+'8'*64),('deadline_seconds',1)]:
            m = Model();args=m.inputs();r=R.decoded(args['pacman_raw']);r[field]=value
            args['pacman_raw']=R.encoded(r);args['pacman_pin']=m.keep(args['pacman_raw'])
            with self.subTest(field=field),self.assertRaises(ValueError):R.validate_dependencies(**args)

    def test_nonce64_does_not_match_original32_guard(self):
        m=Model();m.supervisor['nonce']='2'*64
        with self.assertRaisesRegex(ValueError,'SUPERVISOR_IDENTITY'):R.validate_dependencies(**m.inputs())

    def test_missing_alias_duplicate_provider_or_cycle_refuses(self):
        for mutation in ('missing','duplicate','cycle'):
            m=Model()
            if mutation=='missing':m.snapshot['symlinks'].pop('/usr/lib/libMODEL.so.1')
            if mutation=='duplicate':
                m.file('/opt/MODEL/libMODEL.so.1',model_elf('libMODEL.so.1',definitions=[('MODEL_ABI_1',0x1234,2,0)]),'model-native-provider')
                m.snapshot['loader_policy']['cache']['libMODEL.so.1']=['/opt/MODEL/libMODEL.so.1']
            if mutation=='cycle':m.alias('/usr/lib/libMODEL.so.1','libMODEL.so.1','/usr/lib/libMODEL.so.1','model-native-provider')
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):R.validate_dependencies(**m.inputs())

    def test_gnu_missing_wrong_hash_hidden_or_duplicate_refuses(self):
        definitions = [[],[('OTHER_MODEL_ABI',0x1234,2,0)],[('MODEL_ABI_1',0x5678,2,0)],
                       [('MODEL_ABI_1',0x1234,0x8002,0)],
                       [('MODEL_ABI_1',0x1234,2,0),('MODEL_ABI_1',0x1234,3,0)]]
        for rows in definitions:
            m=Model();m.file('/usr/lib/libMODEL.so.1.0',model_elf('libMODEL.so.1',definitions=rows),'model-native-provider')
            with self.subTest(rows=rows),self.assertRaises(ValueError):R.validate_dependencies(**m.inputs())

    def test_actual_package_database_and_elf_summary_are_both_required(self):
        for mutation in ('database','elf'):
            m=Model()
            if mutation=='elf':m.snapshot['files']['/usr/lib/libMODEL.so.1.0']['elf']['needed']=['MISSING_MODEL.so']
            args=m.inputs()
            if mutation=='database':
                meta=R.decoded(m.retained[m.packages['model-native-provider']['database_pin']['sha256']])
                meta['entries']['/usr/lib/libMODEL.so.1.0']['sha256']='0'*64
                m.packages['model-native-provider']['database_pin']=m.keep(R.encoded(meta))
                provider=R.decoded(m.retained[m.snapshot['provider_tuple_pin']['sha256']]);provider['packages']=m.packages
                m.snapshot['provider_tuple_pin']=m.keep(R.encoded(provider))
                args['snapshot_raw']=R.encoded(m.snapshot);args['snapshot_pin']=m.keep(args['snapshot_raw'])
                args['selection']['snapshot_pin']=args['snapshot_pin']
                args['selection']['provider_tuple_pin']=m.snapshot['provider_tuple_pin']
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):R.validate_dependencies(**args)

    def test_hidden_requirement_and_loader_token_refuse(self):
        for needed,other in [('libMODEL.so.1',0x8002),('$ORIGIN',2)]:
            m=Model();m.file(R.LIBRARIES[0],model_elf('libQt6Concurrent.so.6',[needed],
                (needed,'MODEL_ABI_1',0x1234,other,0)),R.PACKAGE,staged=True)
            with self.subTest(needed=needed),self.assertRaises(ValueError):R.validate_dependencies(**m.inputs())

    def test_all_loader_override_tags_and_environment_refuse(self):
        for tag in (15,29,0x6ffffefb,0x6ffffefc,0x7ffffffd,0x7fffffff):
            with self.subTest(tag=tag),self.assertRaisesRegex(ValueError,'HAZARD'):
                R.elf(model_elf('libMODEL.so.1',hazard=tag))
        for field in ('ld_preload','ld_audit','ld_library_path','ld_so_preload'):
            m=Model();m.snapshot['loader_policy'][field]='MODEL'
            with self.subTest(field=field),self.assertRaises(ValueError):R.validate_dependencies(**m.inputs())

    def test_interpreter_exact_owned_aarch64_provider(self):
        with self.assertRaisesRegex(ValueError,'INTERPRETER'):
            R.elf(model_elf('MODEL',interpreter='/lib64/ld-linux-x86-64.so.2'))
        m=Model();m.file('/usr/lib/ld-linux-aarch64.so.1',model_elf('ld-linux-aarch64.so.1'),'model-native-provider')
        m.file(R.LIBRARIES[0],model_elf('libQt6Concurrent.so.6',interpreter='/lib/ld-linux-aarch64.so.1'),R.PACKAGE,staged=True)
        result=R.validate_dependencies(**m.inputs())
        self.assertIn('/usr/lib/ld-linux-aarch64.so.1',result['files'])

    def test_finite_whole_retained_smoke_receipts_and_marker(self):
        m=Model();dependency=R.validate_dependencies(**m.inputs());raw=R.encoded(dependency)
        common=dict(dependency_raw=raw,dependency_pin=m.keep(raw),retained=m.retained)
        selection=dependency['selection']
        common['load_raw'],common['load_pin']=m.callback('gui18-rtld-now-local',['gui18-owned-probe','--rtld-now-local']+R.LIBRARIES,
            dict(kind='GUI18_RTLD_NOW_LOCAL_OBSERVATION_V1',flags=2,modules=R.LIBRARIES,
                 loaded_files=dependency['files'],stage_pin=selection['stage_pin']),child=401)
        common['offscreen_raw'],common['offscreen_pin']=m.callback('gui18-offscreen-smoke',['gui18-owned-probe','--offscreen-gui'],
            dict(kind='GUI18_OFFSCREEN_OBSERVATION_V1',platform='offscreen',marker=R.OFFSCREEN_MARKER,
                 stage_pin=selection['stage_pin'],loaded_files=dependency['files']),(R.OFFSCREEN_MARKER+'\n').encode(),child=402)
        common['cmake_raw'],common['cmake_pin']=m.callback('gui18-normal-cmake-discovery',['gui18-owned-probe','--normal-cmake-discovery'],
            dict(kind='GUI18_NORMAL_CMAKE_OBSERVATION_V1',modules=R.MODULES,stage_pin=selection['stage_pin'],
                 package_registry=False,target_library_files=dict(zip(R.MODULES,R.LIBRARIES)),
                 target_names=R.CMAKE_TARGETS,package_names=R.CMAKE_PACKAGES),child=403)
        self.assertFalse(R.validate_smoke(**common)['native_acceptance'])
        broken=copy.copy(common);r=R.decoded(common['offscreen_raw']);r['stdout_pin']=m.keep(b'FAKE MARKER\n')
        broken['offscreen_raw']=R.encoded(r);broken['offscreen_pin']=m.keep(broken['offscreen_raw'])
        with self.assertRaises(ValueError):R.validate_smoke(**broken)
        for mapping in ('target_names','package_names'):
            broken=copy.copy(common);r=R.decoded(common['cmake_raw'])
            observation=R.decoded(m.retained[r['observation_pin']['sha256']])
            observation[mapping]['XcbQpa']='Qt6::XcbQpa' if mapping=='target_names' else 'Qt6XcbQpa'
            r['observation_pin']=m.keep(R.encoded(observation))
            broken['cmake_raw']=R.encoded(r);broken['cmake_pin']=m.keep(broken['cmake_raw'])
            with self.subTest(mapping=mapping),self.assertRaises(ValueError):R.validate_smoke(**broken)
        r=R.decoded(common['offscreen_raw'])
        m.retained.pop(r['events_pin']['sha256'])
        with self.assertRaises(ValueError):R.validate_smoke(**common)

    def test_fence_and_finite_input_limits(self):
        for event,args in [('subprocess.Popen',()),('socket.__new__',()),('ctypes.dlopen',()),('open',('MODEL','w',0))]:
            with self.assertRaisesRegex(RuntimeError,'MODEL_RUNTIME_NO_ACTORS'):sys.audit(event,*args)
        with self.assertRaisesRegex(ValueError,'DUPLICATE_JSON_KEY'):R.decoded(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):R.descriptor(dict(bytes=R.MAX_TOTAL+1,sha256='0'*64))


if __name__ == '__main__':
    unittest.main()
