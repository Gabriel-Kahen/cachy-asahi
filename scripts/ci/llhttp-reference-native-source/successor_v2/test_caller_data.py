#!/usr/bin/env python3
"""FENCED future-caller DATA controls: real CLI/Source68/dispatcher; modeled Root/custody/transport.

No authority, runtime, lease, PIDFD, network or native actor is exercised. The only
writes are disposable LLHTTP62.MODEL fixtures, never a Root output or receipt.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import patch

HERE = Path(os.environ.get('LLHTTP_VA_CALLER','/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-go-va-canonical-ONCE-DRAFT-20261117-r3'))
PACKET = HERE / 'packet/operator-DRAFT'
BASE = Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-canonical-ONCE-DRAFT-20261117-r1/packet/operator-DRAFT')
PUBLIC = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114')
REGISTRATION = PUBLIC/'Root-llhttp62-registration-r1/registration-readback.ACTUAL.json'
SOURCE48 = Path(os.environ.get('LLHTTP_VA_SOURCE',str(PUBLIC / 'llhttp-go-cli-va-successor-DATA-20261117-r1')))
SOURCE47 = PUBLIC / 'Root-llhttp62-source-r1/closed-source-tree'
CID48 = 'a'*40 # MODEL publication only; actual Source68 CID remains NULL.
TREE48 = 'ff40c38eb5062ace3b46cb2f2c4c8c32fc010a00'
MAP48 = '00a7b3ced2bbf21303734d32cf9dde10e7db5e724b0c1b4857f7ab7e5a685998'
OWNER48 = dict(bytes=4244, sha256='fe6a77db55043037aba41c00ef87aad896402d313281637f38146be8e63abd12')
MODEL = None
DENIED = []
REAL_TRANSPORT_EVENTS = []


def beneath(path, root):
    return path == root or root in path.parents


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.')):
        REAL_TRANSPORT_EVENTS.append(event)
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'resource.setrlimit', 'os.kill', 'os.killpg', 'os.link', 'os.symlink',
    }:
        DENIED.append(event)
        raise RuntimeError('FENCED DATA prohibited ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(args[0])).absolute()
        flags = args[2] or 0
        writing = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        if writing:
            allowed = MODEL is not None and beneath(path, MODEL)
        else:
            allowed = any(beneath(path, root) for root in (HERE, BASE, SOURCE48, SOURCE47, REGISTRATION.parent, Path(sys.base_prefix)))
            allowed |= MODEL is not None and beneath(path, MODEL)
        if not allowed:
            DENIED.append('open:' + str(path))
            raise RuntimeError('FENCED DATA unlisted file ' + str(path))
    if event.startswith(('os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.chmod')):
        paths = [Path(os.fsdecode(value)).absolute() for value in args[:2] if isinstance(value, (str, bytes, os.PathLike))]
        if not all((MODEL is not None and beneath(path, MODEL)) or str(path).startswith('/home/gabe/LLHTTP62.MODEL.') for path in paths):
            DENIED.append(event)
            raise RuntimeError('FENCED DATA mutation ' + event)


sys.addaudithook(fence)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def git_object(kind, body):
    return hashlib.sha1(kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body).digest()


def physical_tree(root):
    """Pure in-memory Git tree calculation; no git or external census import."""
    entries = []
    for path in root.iterdir():
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            entries.append((path.name.encode() + b'/', b'40000 ' + path.name.encode() + b'\0' + bytes.fromhex(physical_tree(path))))
        else:
            if not stat.S_ISREG(mode) or path.is_symlink():
                raise ValueError('MODEL census requires ordinary files')
            git_mode = b'100755' if mode & 0o111 else b'100644'
            entries.append((path.name.encode(), git_mode + b' ' + path.name.encode() + b'\0' + git_object('blob', path.read_bytes())))
    return git_object('tree', b''.join(value for _, value in sorted(entries))).hex()


class ModelCensus:
    """Local data census only. This is not the Root custody module."""
    calls = []

    @classmethod
    def closed_source_declared(cls, unused, root, rows, modes):
        actual = {str(path.relative_to(root)) for path in root.rglob('*') if not path.is_dir()}
        if actual != set(rows):
            raise ValueError('complete physical DATA census')
        for name, expected in rows.items():
            path = root / name
            info = path.lstat()
            raw = path.read_bytes()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != modes[name]:
                raise ValueError('ordinary exact DATA file/mode')
            if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != expected:
                raise ValueError('exact DATA body')
        cls.calls.append(len(rows))
        return physical_tree(root)


def proofs(m, root):
    manifest = json.loads((root / 'source-map.json').read_bytes())
    rows = manifest['files']
    public = dict(issuer='Root', status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY', source=CID48 if root == SOURCE48 else 'a' * 40,
                  ref='refs/heads/' + m.PROPOSED_REF, tree=physical_tree(root), source_map_sha256=hashlib.sha256((root / 'source-map.json').read_bytes()).hexdigest(),
                  files=len(rows) + 1, bytes=sum(row['bytes'] for row in rows.values()) + (root / 'source-map.json').stat().st_size,
                  native='NOT RUN', M2='NOT RUN')
    registration = json.loads(REGISTRATION.read_bytes());registration['observed_utc']=int(time.time()) # modeled freshness, no actual readback/authority
    return public, registration


FIELDS = ('source_root', 'publication', 'publication_sha256', 'registration', 'registration_sha256', 'hosted_runtime', 'hosted_runtime_sha256',
          'source_review', 'source_review_sha256', 'approval', 'approval_sha256', 'authority', 'authority_sha256', 'runtime54_profile', 'runtime54_profile_sha256', 'operational_context', 'operational_context_sha256', 'output')


def arguments(root=SOURCE48, output='/MODELED/NEVER-ROOT-OUTPUT'):
    values = {name: ('e' * 64 if name.endswith('_sha256') else '/MODELED/' + name) for name in FIELDS}
    values.update(source_root=str(root),registration=str(REGISTRATION),registration_sha256=hashlib.sha256(REGISTRATION.read_bytes()).hexdigest(), output=str(output), case=True, fd=987654, owner=876543, owner_start=765432)
    return argparse.Namespace(**values)


def cli(m, a):
    """Execute the actual __main__ argparse AST, using the loaded actual definitions."""
    nodes = ast.parse(Path(m.__file__).read_bytes()).body
    main = next(node for node in nodes if isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__')
    argv = [m.__file__]
    for key in FIELDS:
        argv.extend(['--' + key.replace('_', '-'), str(getattr(a, key))])
    if a.case:
        argv += ['--case', '--fd', str(a.fd), '--owner', str(a.owner), '--owner-start', str(a.owner_start)]
    with patch.object(sys, 'argv', argv), patch.object(os, 'umask', return_value=0o077):
        exec(compile(ast.Module(body=[main], type_ignores=[]), m.__file__, 'exec'), dict(vars(m), __name__='__main__'))


def documents(m, a):
    now = int(time.time())
    common = dict(accepted=True, created_utc=now - 1, expires_utc=now + 60, issued_by='Root', nonce='c' * 32,
                  ref='refs/heads/' + m.REF, resources=copy.deepcopy(m.PAIR_RESOURCES), source=m.SOURCE, source_map_sha256=m.MAP)
    ad = dict(common, kind='ROOT_LLHTTP_REFERENCE_HOSTED_ADMISSION_V1')
    rt = dict(common, kind='ROOT_LLHTTP_REFERENCE_HOSTED_RUNTIME_V1', external_supervision=m.OWNER_PROGRAM_PIN,
              bootstrap_resource_domain=m.POLICY_PIN, host_tools=m.HOST_TOOLS)
    ar, rr = canonical(ad), canonical(rt)
    a.approval_sha256 = hashlib.sha256(ar).hexdigest()
    a.hosted_runtime_sha256 = hashlib.sha256(rr).hexdigest()
    return {a.approval: ar, a.hosted_runtime: rr}


class MockPostBoundary(BaseException):
    """Stops before any real POST; never represents a successful dispatch."""


class Controls(unittest.TestCase):
    def setUp(self):
        if not HERE.exists()or not SOURCE48.exists():self.skipTest('exact successor caller/Source DATA required; no acquisition/fallback')
        global MODEL
        MODEL = Path(tempfile.mkdtemp(prefix='LLHTTP62.MODEL.', dir='/home/gabe'))
        model = MODEL
        def cleanup():
            for path in sorted(model.rglob('*'), key=lambda value: len(value.parts), reverse=True):
                if path.is_dir(): path.rmdir()
                else: path.unlink()
            model.rmdir()
        self.addCleanup(cleanup)
        self.m = module(PACKET / 'llhttp_once.py', 'fenced_go_va_operator')
        self.m.PROPOSED_REF='codex/LLHTTP68.MODEL.UNISSUED'
        self.addCleanup(self.assertEqual, DENIED, [])
        self.addCleanup(self.assertEqual, REAL_TRANSPORT_EVENTS, [], 'actual subprocess/socket calls, including actual POSTs, must be zero')
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(os, 'pidfd_open', create=True, side_effect=AssertionError('NO actual PIDFD')))
        self.stack.enter_context(patch.object(os, 'system', side_effect=AssertionError('NO shell')))

    def configured(self, m=None, root=SOURCE48):
        m = m or self.m
        a = arguments(root)
        p, r = proofs(m, root)
        checked = lambda path, digest: copy.deepcopy(p if path == a.publication else r)
        with patch.object(m, 'checked', side_effect=checked):
            m.configure(a)
        return a

    def test_actual_cli_rejects_cross_source_publications_before_custody(self):
        a=arguments();p,r=proofs(self.m,SOURCE48);p['source']='b36a1a6dba7dd42d55646582f3d1fa2002d78d5f'
        with patch.object(self.m,'checked',side_effect=lambda path,digest:p if path==a.publication else r),patch.object(self.m,'modules',side_effect=AssertionError('no custody')) as boundary:
            with self.assertRaises(ValueError):cli(self.m,a)
            boundary.assert_not_called()

    def test_actual_null_cli_refuses_before_input_role_or_lease(self):
        a = arguments()
        a.case = False
        a.publication_sha256 = a.registration_sha256 = ''
        with patch.object(self.m, 'read', side_effect=AssertionError('NULL CLI read')), \
             patch.object(self.m, 'modules', side_effect=AssertionError('NULL CLI custody')), \
             patch.object(self.m, 'approvals', side_effect=AssertionError('NULL CLI Root boundary')):
            with self.assertRaisesRegex(ValueError, 'registration required'):
                cli(self.m, a)

    def test_actual_source68_closure_map_program_and_physical_git_tree(self):
        a = self.configured()
        ModelCensus.calls = []
        body = self.m.source(ModelCensus, None, a)
        self.assertEqual(ModelCensus.calls, [68, 45])
        self.assertEqual(self.m.TREE, TREE48)
        self.assertEqual(self.m.MAP, MAP48)
        self.assertEqual(self.m.OWNER_PROGRAM_PIN, OWNER48)
        self.assertEqual(self.m.CASE['source_files'], 68)
        self.assertEqual(self.m.CASE['source_bytes'], 980464)
        self.assertEqual(hashlib.sha256(body).hexdigest(), self.m.CANDIDATE_WORKFLOW_SHA)
        self.assertEqual((SOURCE48 / 'source-map.json').stat().st_size, 14771)

    def test_canonical_framework_resources_statuses_and_document_predicates_unchanged(self):
        self.assertEqual(self.m.STATUS, ('in_progress', 'pending', 'queued', 'waiting', 'requested'))
        self.assertEqual(self.m.HOST_TOOLS['package_manager_invocations'],0)
        self.assertEqual(self.m.HOST_TOOLS['host_package_mutations'],0)
        def fn(path, name):
            return ast.dump(next(node for node in ast.parse(path.read_bytes()).body if isinstance(node, ast.FunctionDef) and node.name == name), include_attributes=False)
        for name in ('modules', 'main_guard', 'gate'):
            self.assertEqual(fn(PACKET / 'llhttp_once.py', name), fn(BASE / 'llhttp_once.py', name))
        self.assertEqual(fn(PACKET / 'llhttp_once.py', 'llhttp_documents'), fn(PACKET / 'llhttp_dispatch_once.py', 'llhttp_documents'))
        body = (PACKET / 'llhttp_once.py').read_text()
        for seam in ('for sweep in range(2):', 'for status in STATUS:', "v['total_count']==len(v['workflow_runs'])==0", "intent['prior_run_ids']==[]", "main_guard(direct,g['main'])", 'C.natural(r)', "result['release']='CLOSE_ONLY'", 'os.pidfd_open(pid,0)', 'C.OWNER_START=S._read_stat(pid)[4]', 'fcntl.LOCK_EX|fcntl.LOCK_NB'):
            self.assertIn(seam, body)

    def test_operational_context_unissued_refuses_before_proof_reads(self):
        with patch.object(self.m,'checked',side_effect=AssertionError('no context proof access')):
            with self.assertRaisesRegex(ValueError,'operational context required'):
                self.m.operational_context(argparse.Namespace(operational_context=None,operational_context_sha256=None))

    def test_context_proof_names_statuses_pins_and_signed349_refuse(self):
        m=self.m;a=self.configured();a.operational_context='/MODELED/current-context';a.operational_context_sha256='a'*64
        runtime_raw=b'MODELED runtime profile bytes; no identity attestation';proof_raw=canonical(dict(issuer='Root',status='CLOSED_MODELED_BOUNDARY_ONLY'))
        context=dict(issuer='Root',approved=True,status='ROOT_LLHTTP_CANONICAL_OPERATION_CONTEXT_REVIEWED',case=m.CASE,issued_at=datetime.now(timezone.utc).isoformat(),role_label='MODEL_ONLY_UNISSUED',runtime54_profile=dict(path=str(Path(a.runtime54_profile).resolve()),**m.pin(runtime_raw)),registration_sha256=a.registration_sha256,policy=m.POLICY_PIN,owner_program=m.OWNER_PROGRAM_PIN,source349=dict(inputs_lock_sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',expected_packages_sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'),reviewed={k:True for k in m.CONTEXT_PROOFS},proofs={k:dict(path='/MODELED/'+k,**m.pin(proof_raw)) for k in m.CONTEXT_PROOFS})
        # Deliberately MODEL-marked receipts may never be accepted as actual.
        with patch.object(m,'checked',return_value=context),patch.object(m,'read',side_effect=lambda p,*args:runtime_raw if str(p)==a.runtime54_profile else proof_raw):
            with self.assertRaisesRegex(ValueError,'actual Root context proof status'):m.operational_context(a)
        for mode in ('missing-proof','cache-lock','policy','runtime','unissued-role'):
            wrong=copy.deepcopy(context)
            if mode=='missing-proof':del wrong['proofs']['source349_cache']
            elif mode=='cache-lock':wrong['source349']['expected_packages_sha256']='f'*64
            elif mode=='policy':wrong['policy']={}
            elif mode=='runtime':wrong['runtime54_profile']={}
            else:wrong['role_label']=None
            with self.subTest(mode=mode),patch.object(m,'checked',return_value=wrong),patch.object(m,'read',return_value=runtime_raw),self.assertRaises(ValueError):m.operational_context(a)

    def test_exact_documents_zero_apt_and_unissued_field_refusals(self):
        m=self.m;a=self.configured();raws=documents(m,a);ad=json.loads(raws[a.approval]);rt=json.loads(raws[a.hosted_runtime])
        m.llhttp_documents(raws[a.approval],raws[a.hosted_runtime],m.SOURCE,m.REF,a.approval_sha256,a.hosted_runtime_sha256)
        for mode in ('old-APT-field','host-mutation','expired','wrong-map','unissued','oversize'):
            x,y=copy.deepcopy(ad),copy.deepcopy(rt)
            if mode=='old-APT-field':y['host_prerequisites']={}
            elif mode=='host-mutation':y['host_tools']['package_manager_invocations']=1
            elif mode=='expired':y['expires_utc']=1
            elif mode=='wrong-map':x['source_map_sha256']='f'*64
            elif mode=='unissued':x['accepted']=False
            else:x['nonce']='x'*16385
            ar,rr=canonical(x),canonical(y)
            with self.subTest(mode=mode),self.assertRaises((AssertionError,ValueError)):m.llhttp_documents(ar,rr,m.SOURCE,m.REF,m.pin(ar)['sha256'],m.pin(rr)['sha256'])

    def test_full_file_inverse_and_complete_unissued_templates(self):
        rows=json.loads((HERE/'full-files-inverse.DATA.json').read_bytes())['files']
        for row in rows.values():
            body=Path(row['successor']['path']).read_bytes();self.assertEqual(self.m.pin(body),{k:row['successor'][k]for k in ('bytes','sha256')});text=body.decode()
            for seam in reversed(row['seams']):self.assertEqual(text.count(seam['after']),seam['count']);text=text.replace(seam['after'],seam['before'])
            self.assertEqual(self.m.pin(text.encode()),{k:row['predecessor'][k]for k in ('bytes','sha256')})
        values=json.loads((HERE/'ROOT-INPUTS.UNISSUED.json').read_bytes())
        for k in ('runtime54_profile','role_label','operational_context','nonce','created_utc','expires_utc','output','documents_output','live_domains','custody','resources','source349_cache'):self.assertIsNone(values[k])

    def test_gate_missing_one_pass_wrong_status_refuse(self):
        a = self.configured()
        good = dict(case=self.m.CASE, checked_at_utc=datetime.now(timezone.utc).isoformat(), main='f' * 40,
                    authority_sha256=a.authority_sha256, passes=2, statuses=list(self.m.STATUS), complete_paginated=True, empty=True, metadata_GETs=10)
        path = MODEL / 'MODEL-gate.json'
        with self.assertRaises(FileNotFoundError):
            self.m.gate(path, a)
        for mode in ('one-pass', 'wrong-status', 'one-sweep-count', 'nonempty', 'good'):
            value = copy.deepcopy(good)
            if mode == 'one-pass': value['passes'] = 1
            if mode == 'wrong-status': value['statuses'] = ['completed']
            if mode == 'one-sweep-count': value['metadata_GETs'] = 5
            if mode == 'nonempty': value['empty'] = False
            path.write_bytes(canonical(value))
            with self.subTest(mode=mode):
                if mode == 'good': self.assertEqual(self.m.gate(path, a), good)
                else:
                    with self.assertRaises(ValueError): self.m.gate(path, a)

    def test_repeat_post_and_ref_mismatch_refuse(self):
        a = self.configured()
        value = dict(source_map_sha256=self.m.MAP, admission_sha256='a' * 64, admission_json='MODEL', runtime_sha256='b' * 64, runtime_json='MODEL')
        body = json.dumps(dict(ref=self.m.REF, inputs=value)).encode()
        with patch.object(self.m, 'inputs', return_value=value):
            self.m.post_request(self.m.POST, body, False, a)
            for argv, raw, sent in ((self.m.POST, body, True), (self.m.POST, json.dumps(dict(ref='wrong', inputs=value)).encode(), False), (self.m.POST[:-1] + ['wrong'], body, False)):
                with self.assertRaises(ValueError): self.m.post_request(argv, raw, sent, a)

    def test_actual_case_cli_and_dispatcher_stop_at_mock_post(self):
        m = self.m
        a = arguments(output=MODEL / 'MODEL-output')
        out = Path(a.output)
        out.mkdir(mode=0o700)
        p, r = proofs(m, SOURCE48)
        with patch.object(m, 'checked', side_effect=lambda path, digest: p if path == a.publication else r):
            m.configure(a)
        model_documents = documents(m, a)
        actual_read = m.read
        actual_pin = m.pin
        old_primitive_model = b'MODELED UNREAD EXTERNAL OLD PRIMITIVE SEAL BOUNDARY'
        def modeled_document_read(path, cap=8 * 1024**2):
            if Path(path) == m.OLD_PRIMITIVE:
                return old_primitive_model
            return model_documents[str(path)] if str(path) in model_documents else actual_read(path, cap)
        with patch.object(m, 'read', side_effect=modeled_document_read):
            workflow_inputs = m.inputs(a)
        publication = out / 'publication'
        (publication / 'source/.github/workflows').mkdir(parents=True)
        (publication / 'source' / m.WF).write_bytes((SOURCE48 / m.WF).read_bytes())
        policy = (SOURCE48 / m.PREFIX / 'policy.json').read_bytes()
        (publication / 'policy.json').write_bytes(policy)
        (publication / 'publication.json').write_bytes(canonical(dict(source=m.SOURCE, ref=m.REF, tree=m.TREE, workflow_id=m.WORKFLOW, workflow_path=m.WF,
             workflow_sha256=m.WORKFLOW_SHA, root_admission_sha256=a.approval_sha256, hosted_runtime_sha256=a.hosted_runtime_sha256)))
        (out / 'dispatch-inputs.json').write_bytes(canonical(workflow_inputs))
        (out / 'live-gate.json').write_bytes(canonical(dict(case=m.CASE, checked_at_utc=datetime.now(timezone.utc).isoformat(), main='f' * 40,
             authority_sha256=a.authority_sha256, passes=2, statuses=list(m.STATUS), complete_paginated=True, empty=True, metadata_GETs=10)))
        held, approvals, source_calls, gate_calls, transport = [], [], [], [], []
        class ModeledCustody:
            closed_source_declared = ModelCensus.closed_source_declared
            @staticmethod
            def held(unused_u, unused_l, fd, owner):
                if (fd, owner) != (987654, 876543): raise AssertionError('MODEL FD/owner changed')
                held.append((fd, owner))
                return dict(kind='MODELED_NO_ROOT_CUSTODY', fd=fd, owner=owner)
        custody = types.ModuleType('root_custody_2159')
        custody.__dict__.update(Path=Path, json=json, read=actual_read,
             data=lambda path: json.loads(actual_read(path)), save=lambda path, value: Path(path).write_bytes(canonical(value)))
        def load_boundary(name, path, digest):
            self.assertEqual(name, 'root_custody_2159')
            return custody
        def transport_boundary(argv, *args, **kwargs):
            transport.append(list(argv))
            if '--method' in argv and 'POST' in argv:
                self.assertEqual(argv, m.POST)
                self.assertEqual(json.loads(kwargs['input']), dict(ref=m.REF, inputs=workflow_inputs))
                self.assertEqual(set(workflow_inputs), {'source_map_sha256', 'admission_sha256', 'admission_json', 'runtime_sha256', 'runtime_json'})
                self.assertEqual(approvals, ['MODELED_ROOT_PROOF', 'MODELED_ROOT_PROOF'])
                self.assertEqual(source_calls, [68, 68])
                self.assertEqual(len(gate_calls), 3)
                self.assertGreaterEqual(len(held), 5)
                receipt = json.loads((out / 'at-POST.json').read_bytes())
                self.assertEqual(receipt['lease']['kind'], 'MODELED_NO_ROOT_CUSTODY')
                self.assertEqual(receipt['case'], m.CASE)
                self.assertTrue(receipt['once'])
                self.assertFalse(receipt['retry'])
                raise MockPostBoundary('INTERCEPTED BEFORE REAL POST; MODEL ONLY')
            if argv[0] == '/usr/bin/git':
                if 'symbolic-ref' in argv: raw = b'main\n'
                elif 'status' in argv: raw = b''
                elif 'ls-remote' in argv: raw = ('f' * 40 + '\trefs/heads/main\n').encode()
                else: raw = ('f' * 40 + '\n').encode()
                return subprocess.CompletedProcess(argv, 0, raw, b'')
            self.assertEqual(argv[:2], ['gh', 'api'])
            self.assertNotIn('--method', argv)
            self.assertIn('/runs?', argv[2])
            return subprocess.CompletedProcess(argv, 0, b'{"total_count":0,"workflow_runs":[]}', b'')
        actual_source, actual_gate = m.source, m.gate
        def source_boundary(*args):
            body = actual_source(*args)
            source_calls.append(68)
            return body
        def gate_boundary(*args):
            result = actual_gate(*args)
            gate_calls.append(result)
            return result
        with ExitStack() as stack:
            stack.enter_context(patch.object(m, 'checked', side_effect=lambda path, digest: copy.deepcopy(p if path == a.publication else r)))
            stack.enter_context(patch.object(m, 'read', side_effect=modeled_document_read))
            stack.enter_context(patch.object(m, 'pin', side_effect=lambda raw: dict(bytes=len(raw), sha256=m.OLD_PRIMITIVE_SHA) if raw == old_primitive_model else actual_pin(raw)))
            stack.enter_context(patch.object(m, 'modules', return_value=(ModeledCustody, None, None, None)))
            stack.enter_context(patch.object(m, 'approvals', side_effect=lambda unused: approvals.append('MODELED_ROOT_PROOF')))
            stack.enter_context(patch.object(m, 'source', side_effect=source_boundary))
            stack.enter_context(patch.object(m, 'gate', side_effect=gate_boundary))
            stack.enter_context(patch.object(m, 'load', side_effect=load_boundary))
            stack.enter_context(patch.dict(sys.modules, root_custody_2159=custody))
            stack.enter_context(patch.object(subprocess, 'run', side_effect=transport_boundary))
            stack.enter_context(patch.object(subprocess, 'check_output', return_value=m.SOURCE + '\trefs/heads/' + m.REF + '\n'))
            with self.assertRaisesRegex(MockPostBoundary, 'BEFORE REAL POST'):
                cli(m, a)
        self.assertEqual(sum('--method' in argv and 'POST' in argv for argv in transport), 1)
        self.assertFalse((out / 'actual-native/actual-run.json').exists())
        self.assertFalse((out / 'actual-native/dispatch-status.json').exists())
        self.assertTrue((out / 'actual-native/dispatch-intent.json').exists())


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('Run this DATA control with python -I -B, unoptimized')
    unittest.main(verbosity=2)
