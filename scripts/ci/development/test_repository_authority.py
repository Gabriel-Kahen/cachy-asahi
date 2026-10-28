#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/custody/callback causal fixtures; no GPG/Docker/native/install actors."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).with_name('repository_authority.py')
spec = importlib.util.spec_from_file_location('repository_authority_tests_source',SOURCE)
a = importlib.util.module_from_spec(spec); sys.modules[spec.name] = a; spec.loader.exec_module(a)


def source_gate():
    """Only actual data constants/case validator; no authenticated gate execution."""
    path = ROOT/a.PHASE/'gate.py'; raw = path.read_bytes()
    assert a.digest(raw) == a.PHASE_GATE
    names = {'ORIGINALS','PROBE','CASES','LABELS','STRICT_CONFIG'}
    nodes = [node for node in ast.parse(raw).body if isinstance(node,ast.Assign) and
             any(isinstance(t,ast.Name) and t.id in names for t in node.targets)]
    nodes += [node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef) and node.name == 'case_rows']
    scope = {'need':a.need}; exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),scope)
    return types.SimpleNamespace(**scope)


class GrantFixture:
    def __init__(self, root):
        self.root = root
        initial = ROOT/'scripts/ci/integration.lock.json'
        assert a.digest(initial.read_bytes()) == a.INITIAL
        names = set(json.loads(initial.read_bytes())['source_files']) | {a.OWN,a.HANDOFF,'scripts/ci/integration.lock.json','LICENSE'}
        prefixes = {'runtime':a.RUNTIME,'collector':'scripts/port/repository-client-native','phase':a.PHASE}
        for prefix in prefixes.values():
            names.add(prefix+'/source-map.json')
            names.update(prefix+'/'+name for name in json.loads((ROOT/prefix/'source-map.json').read_bytes()))
        self.rows = {}
        for name in sorted(names):
            source = ROOT/name
            data = source.read_bytes(); mode = source.stat().st_mode & 0o777
            target = root/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data); target.chmod(mode)
            self.rows[name] = {'sha256':a.digest(data),'mode':mode}
        self.actor = {'cli_sha256':'b'*64,'endpoint_identity':{'fixture':'NO ACTOR'},'env':{}}
        self.grant = {'schema_version':2,'purpose':'reviewed-same-job-handoff-execution',
            'source_peer_preflight':'PASS','development_only':True,'added_seconds':1200,
            'source_commit':'a'*40,'recipe_source_commit':'c'*40,'run_id':'123','run_attempt':'2',
            'source_files':self.rows,'maps':{},'callbacks':{},
            'policy_path':'SYNTHETIC-policy.json',
            'license_path':'LICENSE','actor_contract_sha256':a.digest(a.encoded(self.actor))}
        original=json.loads(initial.read_bytes())
        self.grant['original_view']={'schema_version':1,'purpose':'original-159-copy-view',
            'full_source_root':str(root),'root':str(root/'output'/'original-view'),
            'integration_lock_sha256':a.INITIAL,'source_rows_sha256':a.digest(a.encoded(original['source_files'])),
            'file_count':160,'argv_mode':'absolute-view-metadata'}
        self.grant['initial_invocation_sha256'] = a.digest(a.encoded({'argv':['integration','SYNTHETIC-NO-ACTOR'],
                                                                    'output':str(root/'output')}))
        # Test-only coherent runtime ledger follows actual current source bytes.
        # It is not the coordinator's admitted map and is never executed here.
        runtime_rows = {name:{'sha256':self.rows[a.RUNTIME+'/'+name]['sha256'],'mode':0o644}
                        for name in json.loads((root/a.RUNTIME/'source-map.json').read_bytes())}
        data = a.encoded(runtime_rows); (root/a.RUNTIME/'source-map.json').write_bytes(data)
        self.rows[a.RUNTIME+'/source-map.json'] = {'sha256':a.digest(data),'mode':0o644}
        policy = {'coordinated_sets':[{'name':'generic-Hyprland-builder','versions':{'aquamarine':'0.15.1-1',
            'hyprgraphics':'0.5.1-4','hyprland':'0.56.2-4','hyprlang':'0.6.8-5','hyprutils':'0.14.2-1'}}],
            'platform_scope':'generic-builder-only','protected_packages':['pacman','glibc','bash','filesystem'],
            'purpose':'reviewed-generic-restage-policy','review_status':'ACCEPTED',
            'selected_packages':['cachy-asahi-fish-config','cachy-asahi-hyprland-settings','cachy-asahi-setup','cachy-asahi-zsh-config'],
            'supported_models':[]}
        data = a.encoded(policy); assert a.digest(data) == a.POLICY
        (root/'SYNTHETIC-policy.json').write_bytes(data); self.rows['SYNTHETIC-policy.json'] = {'sha256':a.digest(data),'mode':0o644}
        for index in range(max(0,240-len(self.rows))):
            name = f'SYNTHETIC-source-only-{index}.txt'; data = b'INERT SOURCE-COUNT MODEL\n'
            (root/name).write_bytes(data); self.rows[name] = {'sha256':a.digest(data),'mode':0o644}
        for role,prefix in prefixes.items():
            name = prefix+'/source-map.json'; self.grant['maps'][role] = {'path':name,'sha256':self.rows[name]['sha256']}
        self.module = a.load_module(root,'repository_authority_bound_fixture',a.OWN,self.rows[a.OWN],time.monotonic()+10)
        sys.modules[self.module.__name__] = self.module
        for role in ('public_receiver','authority_provider'):
            self.grant['callbacks'][role] = {'path':a.OWN,'module':self.module.__name__,'qualname':'RootCallbacks.'+role}
        self.grant['callbacks']['existing_consumers'] = {'path':a.HANDOFF,'module':'unused-no-actor','qualname':'main'}
        self.raw = a.encoded(self.grant); self.pin = a.digest(self.raw)

    def construct(self, **options):
        return self.module.RootCallbacks(self.root,self.raw,self.pin,a.encoded(self.actor),self.root/'output',
                                         deadline=time.monotonic()+60,**options)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.fixture = GrantFixture(Path(self.temp.name))
        self.addCleanup(sys.modules.pop,self.fixture.module.__name__,None)
        self.environment = mock.patch.dict(os.environ,{'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'2'})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def test_complete_source_only_binding_has_closed_shape_no_actor(self):
        callback = self.fixture.construct(); binding = callback.handoff_binding()
        self.assertEqual(set(binding),a.BINDING_FIELDS)
        self.assertEqual(binding['execution_grant_sha256'],self.fixture.pin)
        self.assertEqual(binding['supported_models'],[])
        self.assertFalse((self.fixture.root/'output').exists())
        with self.assertRaises((a.Refused,self.fixture.module.Refused)):
            callback.public_receiver(None,{},deadline=time.monotonic()+20)
        self.assertEqual(callback._failure,'public-refused')
        with self.assertRaises(self.fixture.module.Refused):
            callback.authority_provider('/missing','f'*64,'/missing',deadline=time.monotonic()+20)

    def test_immutable_state_and_subclass_refuse(self):
        callback = self.fixture.construct()
        with self.assertRaises(AttributeError): callback._grant_pin = '0'*64
        class Foreign(self.fixture.module.RootCallbacks): pass
        with self.assertRaises(self.fixture.module.Refused):
            Foreign(self.fixture.root,self.fixture.raw,self.fixture.pin,a.encoded(self.fixture.actor),
                    self.fixture.root/'output',deadline=time.monotonic()+30)

    def test_actual_run_actor_contract_and_external_pin_required(self):
        with mock.patch.dict(os.environ,{'GITHUB_RUN_ATTEMPT':'3'}),self.assertRaises(self.fixture.module.Refused):
            self.fixture.construct()
        with self.assertRaises(self.fixture.module.Refused):
            self.fixture.module.RootCallbacks(self.fixture.root,self.fixture.raw,'0'*64,a.encoded(self.fixture.actor),
                                             self.fixture.root/'output',deadline=time.monotonic()+30)
        actor = dict(self.fixture.actor,cli_sha256='d'*64)
        with self.assertRaises(self.fixture.module.Refused):
            self.fixture.module.RootCallbacks(self.fixture.root,self.fixture.raw,self.fixture.pin,a.encoded(actor),
                                             self.fixture.root/'output',deadline=time.monotonic()+30)

    def test_class_descriptor_and_foreign_helper_namespace_refuse(self):
        callback = self.fixture.construct(); cls = type(callback)
        with mock.patch.object(cls,'_modules',lambda *args: {'status':'PASS'}),self.assertRaises(self.fixture.module.Refused):
            callback.handoff_binding()
        with mock.patch.object(cls,'_public_facts',property(lambda self:object())),self.assertRaises(self.fixture.module.Refused):
            callback.handoff_binding()
        getter_calls = []
        with mock.patch.object(cls,'_session',property(lambda self:getter_calls.append(True))),self.assertRaises(self.fixture.module.Refused):
            callback.handoff_binding()
        self.assertEqual(getter_calls,[])
        kwdefaults = cls.__init__.__kwdefaults__
        with mock.patch.object(cls.__init__,'__kwdefaults__',dict(kwdefaults,session='FOREIGN')),self.assertRaises(self.fixture.module.Refused):
            callback.handoff_binding()
        original = self.fixture.module.digest
        function = types.FunctionType(original.__code__,dict(original.__globals__))
        function.__module__ = original.__module__
        with mock.patch.object(self.fixture.module,'digest',function),self.assertRaises(ValueError): callback.handoff_binding()

    def test_exact_class_foreign_session_refuses_before_actor(self):
        with self.assertRaises(self.fixture.module.Refused): self.fixture.construct(session=types.SimpleNamespace())

    def test_source_mode_inode_and_bytes_changes_refuse(self):
        callback = self.fixture.construct(); path = self.fixture.root/a.OWN
        path.chmod(0o755)
        with self.assertRaises(ValueError): callback.handoff_binding()
        path.chmod(0o644); path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(ValueError): callback.handoff_binding()

    def test_changed_phase_gate_pin_cannot_grant_pass_lambda(self):
        path = self.fixture.root/a.PHASE/'gate.py'; path.write_text('def accept(*a,**k):return {"status":"PASS-input-acceptance"}\n')
        with self.assertRaises(ValueError): self.fixture.construct()

    def test_actual_session_contextmanager_cell_and_defaults_are_authenticated(self):
        module = a.load_module(self.fixture.root,'repository_authority_session_fixture',a.HANDOFF,
                              self.fixture.rows[a.HANDOFF],time.monotonic()+10)
        sys.modules[module.__name__] = module; self.addCleanup(sys.modules.pop,module.__name__,None)
        session = module.Session(None,self.fixture.root/'output',job_deadline=time.monotonic()+30)
        raw = (self.fixture.root/a.HANDOFF).read_bytes()
        a.authenticate_class(session,'Session',self.fixture.root/a.HANDOFF,raw)
        original = module.Session.step
        foreign = types.FunctionType(original.__code__,original.__globals__,closure=(
            (lambda value:lambda:value)(lambda:None).__closure__[0],))
        foreign.__wrapped__ = original.__wrapped__
        with mock.patch.object(module.Session,'step',foreign),self.assertRaises(a.Refused):
            a.authenticate_class(session,'Session',self.fixture.root/a.HANDOFF,raw)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.callback = object.__new__(a.RootCallbacks)
        self.end = time.monotonic()+10

    def test_fresh_write_exact_bytes_mode_and_no_overwrite(self):
        path = self.root/'accepted.json'; raw = b'{"status":"PENDING"}\n'
        result = a.write(path,raw,self.end)
        self.assertEqual(result,{'path':str(path),'sha256':a.digest(raw)})
        self.assertEqual(a.read(path,self.end,private=True)[0],raw)
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        with self.assertRaises(a.Refused): a.write(path,b'changed',self.end)
        self.assertEqual(path.read_bytes(),raw)

    def test_symlink_hardlink_fifo_ancestor_alias_and_deadline_refuse(self):
        path = self.root/'file'; path.write_bytes(b'bound'); target = self.root/'alias'; target.symlink_to(path)
        with self.assertRaises(OSError): a.read(target,self.end)
        target.unlink(); os.link(path,target)
        with self.assertRaises(a.Refused): a.read(target,self.end)
        target.unlink(); os.mkfifo(target)
        with self.assertRaises(a.Refused): a.read(target,self.end)
        alias = self.root/'aliasdir'; alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError): a.read(alias/'file',self.end)
        with self.assertRaises(a.Refused): a.read(path,time.monotonic()-1)

    def test_exact_tree_map_once_capture_immutable_stage_and_extra_refusal(self):
        path = self.root/'file'; path.write_bytes(b'bound'); path.chmod(0o600)
        rows = {'file':{'sha256':a.digest(b'bound'),'bytes':5}}
        raw,total = self.callback._capture(self.root,rows,self.end)
        path.write_bytes(b'later'); self.assertEqual(raw['file'],b'bound'); self.assertEqual(total,5)
        path.write_bytes(b'bound'); (self.root/'extra').write_bytes(b'NO')
        with self.assertRaises(a.Refused): self.callback._capture(self.root,rows,self.end)

    def test_fsync_failure_and_control_revoke_named_record(self):
        for failure in (OSError('injected'),KeyboardInterrupt()):
            path = self.root/'accepted.json'
            original = a.os.fsync; fired = []
            def fsync(fd):
                original(fd)
                if not fired: fired.append(True); raise failure
            with mock.patch.object(a.os,'fsync',side_effect=fsync),self.assertRaises(type(failure)):
                a.write(path,b'bound',self.end)
            self.assertFalse(path.exists()); self.assertEqual(list(self.root.iterdir()),[])

    def test_json_duplicate_nonfinite_and_relative_paths_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(a.Refused): a.decode(raw)
        for name in ('../secret','/secret','a//b','a/./b'):
            with self.assertRaises(a.Refused): a.relative(name)

    def test_cleanup_late_control_retains_earlier_business_cause(self):
        original = a.os.close; fired = []
        business = a.Refused('source-refused'); control = KeyboardInterrupt()
        def closing(fd):
            original(fd)
            if not fired: fired.append(True); raise control
        with mock.patch.object(a.os,'close',side_effect=closing):
            with self.assertRaises(KeyboardInterrupt) as caught:
                with a.directory(self.root,self.end): raise business
        self.assertIs(caught.exception,control); self.assertIs(caught.exception.__cause__,business)
        object.__setattr__(self.callback,'_failure',None); object.__setattr__(self.callback,'_cancelled',False)
        self.callback._latch(control,'public-refused')
        self.assertTrue(self.callback._cancelled); self.assertEqual(self.callback._failure,'public-refused')

    def test_revocation_error_preserves_original_control_and_no_clock_renewal(self):
        close, fsync = a.os.close, a.os.fsync; fired = []
        control = KeyboardInterrupt(); path = self.root/'accepted.json'
        def closing(fd):
            is_file = os.readlink(f'/proc/self/fd/{fd}').endswith('.json') or '.pending-' in os.readlink(f'/proc/self/fd/{fd}')
            close(fd)
            if is_file and not fired: fired.append(True); raise control
        def syncing(fd):
            if fired: raise OSError('secondary revocation fault')
            fsync(fd)
        with mock.patch.object(a.os,'close',side_effect=closing),mock.patch.object(a.os,'fsync',side_effect=syncing):
            with self.assertRaises(KeyboardInterrupt) as caught: a.write(path,b'bound',self.end)
        self.assertIs(caught.exception,control); self.assertFalse(path.exists())


class PublicFactsTests(unittest.TestCase):
    def setUp(self):
        self.callback = object.__new__(a.RootCallbacks); self.gate = source_gate()
        self.job = {'source_commit':'a'*40,'recipe_source_commit':'b'*40,'run_id':'123','run_attempt':'2',
                    'nonce':'c'*32,'image_id':'sha256:'+'d'*64}
        self.cases = [{'name':name,'result':'PASS','expected_signature_rejection':negative}
                      for name,negative in self.gate.CASES]
        self.cases[8]['rejection_contract'] = {'kind':'missing-required-local-database-signature',
            'missing':['integration.db.sig','integration.db.tar.gz.sig'],'repository':'/scratch/repos/missing-database-signature-B',
            'reference':'/scratch/repos/updated-B','repository_bytes':{},'reference_bytes':{}}
        self.contract = {key:self.job[key] for key in ('source_commit','nonce','image_id')}
        for role,version in (('baseline','0.1.0-1'),('upgrade','0.1.1-1')):
            self.contract[role] = [{'name':name,'archive':name+'-'+version+'-any.pkg.tar.xz',
                                   'sha256':a.digest(name.encode())} for name in sorted(self.gate.ORIGINALS)]
        self.raw = {}; public = {}
        names = {'TEST-signer-A-public.asc','TEST-signer-B-public.asc','TEST-verifier-public.asc',
                 'TEST-signer-A-revoked-public.asc','TEST-repository-aliases.json','TEST-repository-aliases.json.sig','TEST-pacman.conf'}
        for label in self.gate.LABELS:
            rows = self.contract['baseline' if label == 'baseline-A' else 'upgrade']
            packages = {row['archive'] for row in rows}|{self.gate.PROBE+('-1-1-any.pkg.tar.xz' if label == 'baseline-A' else '-2-1-any.pkg.tar.xz')}
            files = packages|{n+'.sig' for n in packages}|{'integration.db.tar.gz','integration.db.tar.gz.sig',
                'integration.files.tar.gz','integration.files.tar.gz.sig','integration.db','integration.db.sig','integration.files','integration.files.sig'}
            if label == 'missing-package-signature-B': files.remove(self.gate.PROBE+'-2-1-any.pkg.tar.xz.sig')
            if label == 'missing-database-signature-B': files -= {'integration.db.tar.gz.sig','integration.db.sig'}
            names.update('TEST-repositories/'+label+'/'+name for name in files)
        for name in names:
            rows = self.contract['baseline' if '/baseline-A/' in name else 'upgrade']
            matches = [row for row in rows if name.endswith('/'+row['archive'])]
            data = matches[0]['name'].encode() if matches else b'SYNTHETIC public test bytes'
            if name == 'TEST-pacman.conf': data = self.gate.STRICT_CONFIG
            if name.endswith('.asc'): data = b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nSYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----\n'
            if name.endswith('.sig'): data = b'\x89SYNTHETIC signature packet prefix; no real crypto'
            self.raw['public/'+name] = data; public[name] = {'sha256':a.digest(data),'bytes':len(data)}
        aliases = {'active':{'target':'updated-B','kind':'directory'}}
        alias_names = {'integration.db':'integration.db.tar.gz','integration.db.sig':'integration.db.tar.gz.sig',
                       'integration.files':'integration.files.tar.gz','integration.files.sig':'integration.files.tar.gz.sig'}
        for label in self.gate.LABELS:
            for alias,target in alias_names.items():
                first,second = 'TEST-repositories/'+label+'/'+alias,'TEST-repositories/'+label+'/'+target
                if first not in public: continue
                self.raw['public/'+first] = self.raw['public/'+second]; public[first] = dict(public[second])
                aliases[label+'/'+alias] = {'target':label+'/'+target,'kind':'file','regular_copy_sha256':public[first]['sha256']}
        data = a.encoded(aliases); self.raw['public/TEST-repository-aliases.json'] = data
        public['TEST-repository-aliases.json'] = {'sha256':a.digest(data),'bytes':len(data)}
        for role,label in (('reference_bytes','updated-B'),('repository_bytes','missing-database-signature-B')):
            prefix = 'TEST-repositories/'+label+'/'
            for name,row in public.items():
                if not name.startswith(prefix): continue
                base = name[len(prefix):]; record = {'sha256':row['sha256']}
                if base in alias_names: record['alias'] = alias_names[base]
                self.cases[8]['rejection_contract'][role][base] = record
        self.manifest = {'development_only':True,'selected_for_release':False,'production_credentials_used':False,
            'files':public,'source_commit':self.job['source_commit'],'purpose':'TEST-ONLY-offline-repository-case-verification',
            'cases':self.cases,'expected_negative_cases_retained':True}
        self.raw['public/manifest.json'] = a.encoded(self.manifest)
        self.files = {name:{'sha256':a.digest(data),'bytes':len(data)} for name,data in self.raw.items()}
        self.repository = {'status':'PASS','purpose':'disposable-generic-repository-test','source_commit':self.job['source_commit'],
            'cases':self.cases,'evidence_sha256':{name:row['sha256'] for name,row in public.items()}}

    def facts(self):
        return self.callback._public_facts(self.manifest,self.repository,self.contract,self.raw,self.files,
                                          self.job,self.job,self.gate)

    def test_actual_case_validator_and_closed_receipt_no_raw_export(self):
        receipt = self.facts(); self.assertEqual(len(receipt),13)
        self.assertEqual(receipt['manifest_sha256'],a.digest(self.raw['public/manifest.json']))
        self.assertNotIn('files',receipt); self.assertNotIn('cases',receipt)
        self.assertLessEqual(len(a.encoded(receipt)),4096)

    def test_manifest_case_hash_payload_extra_private_and_identity_refuse(self):
        original = copy.deepcopy((self.manifest,self.repository,self.contract,self.raw,self.files))
        def wrong_case(): self.cases[8].pop('rejection_contract')
        actions = [lambda:self.manifest.update(extra='NO'),lambda:self.manifest.update(selected_for_release=True),
            lambda:self.repository.update(source_commit='f'*40),lambda:self.contract.update(nonce='e'*32),
            lambda:self.raw.update({'public/foreign':b'NO'}),lambda:self.raw.update({'public/TEST-signer-A-public.asc':b'PRIVATE KEY'}),
            lambda:self.files['public/TEST-pacman.conf'].update(bytes=0),wrong_case]
        for action in actions:
            self.manifest,self.repository,self.contract,self.raw,self.files = copy.deepcopy(original)
            self.cases = self.manifest['cases']; action()
            with self.subTest(action=action),self.assertRaises(ValueError): self.facts()


if __name__ == '__main__':
    unittest.main()
