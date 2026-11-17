#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced caller DATA controls. Operational proofs are temporary MODEL data.

No Root issuer function, role, lease, process, network, native or signing actor
is entered. Literal CLI parsers run with their final action intercepted.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREPARER = HERE/('prepare.py' if (HERE/'prepare.py').exists() else 'prepare-carrier.py')
SOURCE_PREPARER = Path(os.environ.get('LLHTTP_V6_SOURCE_PREPARER', '/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-inner-public-retention-v6-20261117/scripts/ci/llhttp-reference-native-source/successor_v6/prepare.py'))
PARENT = Path(os.environ.get('LLHTTP_V6_CALLER_PARENT', '/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v5-20261117/artifacts/development/llhttp93-canonical-v5-20261117-r1/canonical-ONCE-DRAFT'))
SOURCE = Path(os.environ.get('LLHTTP_V6_CALLER_SOURCE', '/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-inner-public-retention-v6-20261117/artifacts/development/llhttp-inner-public-retention-v6-20261117-r1/Source95-DATA'))
MODEL = None
ACTORS = []
TREE = 'b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f'
MAP = 'ab743415f602ba8c5f81a063fc7cc5d25587be0d535601396f2ee617fb4149ce'
PREFIX = 'scripts/ci/llhttp-reference-native-source/owner/'
OPERATOR = 'packet/operator-DRAFT/llhttp_once.py'
PRIMITIVE = 'packet/operator-DRAFT/llhttp_dispatch_once.py'
MODEL_CID = 'd' * 40
MODEL_REF = 'codex/MODEL-unissued-source95'
CANDIDATE_CID = None
CANDIDATE_REF = None


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn',
        'os.kill', 'os.killpg', 'os.pidfd_open', 'resource.setrlimit',
        'os.link', 'os.symlink',
    }:
        ACTORS.append(event)
        raise RuntimeError('FENCED DATA actor: ' + event)
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        flags = args[2] or 0
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            path = Path(os.fsdecode(args[0])).absolute()
            if MODEL is None or not path.is_relative_to(MODEL):
                raise RuntimeError('FENCED DATA write outside temporary MODEL')
    if event.startswith(('os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.chmod')):
        for value in args[:2]:
            if isinstance(value, (str, bytes, os.PathLike)):
                path = Path(os.fsdecode(value)).absolute()
                if not ((MODEL is not None and path.is_relative_to(MODEL)) or
                        path.parent == Path('/home/gabe') and path.name.startswith('LLHTTP95.MODEL.')):
                    raise RuntimeError('FENCED DATA mutation outside temporary MODEL')


sys.addaudithook(fence)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def bodies(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def functions(raw):
    return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(raw).body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


class ActionBoundary(BaseException):
    pass


def cli(m, argv):
    """Run the literal __main__ AST with actual definitions, never a subprocess."""
    node = next(n for n in ast.parse(Path(m.__file__).read_bytes()).body
                if isinstance(n, ast.If) and isinstance(n.test, ast.Compare)
                and isinstance(n.test.left, ast.Name) and n.test.left.id == '__name__')
    with patch.object(sys, 'argv', [m.__file__, *argv]), patch.object(os, 'umask', return_value=0o077):
        exec(compile(ast.Module(body=[node], type_ignores=[]), m.__file__, 'exec'), dict(vars(m), __name__='__main__'))


class Controls(unittest.TestCase):
    def setUp(self):
        global MODEL
        self.assertTrue(PARENT.is_dir(), 'exact parent27 is required; no acquisition/fallback')
        self.assertTrue(SOURCE.is_dir(), 'exact Source95 is required; no acquisition/fallback')
        MODEL = Path(tempfile.mkdtemp(prefix='LLHTTP95.MODEL.', dir='/home/gabe'))
        self.model = MODEL
        self.addCleanup(self.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [], 'zero actual actor calls, including attempted POSTs')
        self.p = module(PREPARER, 'llhttp95_caller_DATA')
        self.output = MODEL/'carrier'
        self.result = self.p.construct(PARENT, SOURCE, self.output)
        self.files = bodies(self.output)
        self.m = module(self.output/OPERATOR, 'llhttp95_operator_MODEL')

    def cleanup(self):
        for path in sorted(self.model.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
        self.model.rmdir()

    def arguments(self):
        names = ('source_root', 'publication', 'registration', 'hosted_runtime', 'source_review',
                 'approval', 'authority', 'runtime54_profile', 'operational_context', 'output')
        values = {n: str(self.model/('MODEL-'+n)) for n in names}
        values.update({n+'_sha256': 'e'*64 for n in names if n not in ('source_root', 'output')})
        values.update(source_root=str(SOURCE), case=False, fd=None, owner=None, owner_start=None)
        return argparse.Namespace(**values)

    def modeled_configuration(self):
        """Ephemeral module constants only; no modeled receipt is saved as actual."""
        m = self.m
        m.CANDIDATE_SOURCE, m.CANDIDATE_REF, m.PROPOSED_REF = MODEL_CID, MODEL_REF, MODEL_REF
        a = self.arguments()
        public = dict(issuer='Root', status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',
                      source=MODEL_CID, ref='refs/heads/'+MODEL_REF, tree=TREE,
                      source_map=dict(bytes=20200,sha256=MAP), files=95, bytes=1318237, native='NOT RUN', M2='NOT RUN')
        registration = dict(kind='CALLER_WORKFLOW_REGISTRATION_READBACK_DATA_V1',
            repository='Gabriel-Kahen/cachy-asahi', workflow_id=420972285, workflow_path=m.WF,
            workflow_sha256=m.CANDIDATE_WORKFLOW_SHA, registered_on_default_branch=True,
            registration_commit='a'*40, state='active', observed_utc=int(time.time()))
        with patch.object(m, 'checked', side_effect=lambda path, digest: copy.deepcopy(public if path == a.publication else registration)):
            m.configure(a)
        return a, public, registration

    def test_complete27_inverse_pins_and_all_successor_leaf_tampering(self):
        old = self.p.parent_bodies(PARENT)
        if isinstance(old, tuple):
            old = old[0]
        self.assertEqual(len(old), 27)
        self.assertEqual(old, bodies(PARENT))
        self.assertEqual(self.p.inverse(self.output), old)
        self.assertEqual(self.p.inverse(self.files), old)
        for name in ('full-files-inverse.DATA.json', 'packet-seal.DATA.json', 'prepare-carrier.py',
                     'test_canonical_cli.DATA.py', 'predecessor-metadata/source76/controls-Python-3.12.13.DATA.log', 'predecessor-metadata/source76/controls-Python-3.14.7.DATA.log'):
            self.assertIn(name, old)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.output.rglob('*') if p.is_file()))
        for name, raw in self.files.items():
            with self.subTest(leaf=name), self.assertRaises((ValueError, KeyError)):
                self.p.inverse(dict(self.files, **{name: raw+b'\n# MODEL altered\n'}))
        for changed in ({k:v for k,v in self.files.items() if k != OPERATOR}, dict(self.files, **{'MODEL-extra': b''})):
            with self.assertRaises((ValueError, KeyError)):
                self.p.inverse(changed)

    def test_physical_parent_and_carrier_modes_namespace_refuse(self):
        copied = self.model/'parent27'
        for name, raw in bodies(PARENT).items():
            path = copied/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(stat.S_IMODE((PARENT/name).stat().st_mode))
        path = copied/'HANDOFF.md'
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.p.parent_bodies(copied)
        (self.output/OPERATOR).chmod(0o644)
        with self.assertRaises(ValueError):
            self.p.inverse(self.output)

    def test_source95_whole_closure_and_full_predecessor_inverse(self):
        self.p.source_binding(SOURCE)
        source = bodies(SOURCE)
        self.assertEqual((len(source), sum(map(len, source.values()))), (95, 1318237))
        self.assertEqual(pin(source['source-map.json'])['sha256'], MAP)
        v4 = module(SOURCE_PREPARER, 'llhttp95_source_inverse_DATA')
        self.assertEqual(v4.P.tree(source), TREE)
        previous93=v4.inverse(source)
        self.assertEqual(len(previous93),93)
        previous85=v4.P5.inverse(previous93)
        previous76=v4.P5.P4.inverse(previous85)
        previous68=v4.P5.P4.P3.inverse(previous76)
        self.assertEqual((len(previous85),len(previous76),len(previous68),len(v4.P.inverse(previous68))),(85,76,68,62))
        self.assertEqual(self.p.source_inverse(source),[93,85,76,68,62])
        copied = self.model/'source95'
        for name, raw in source.items():
            path = copied/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
        for name in ('source-map.json', PREFIX+'payload.py', PREFIX+'hosted_owner.py',
                     PREFIX+'owner-program.json', 'previous-v3/source-map.json', self.m.WF):
            path = copied/name
            path.write_bytes(source[name]+b' ')
            with self.subTest(leaf=name), self.assertRaises(ValueError):
                self.p.source_binding(copied)
            path.write_bytes(source[name])
        (copied/PREFIX/'payload.py').chmod(0o600)
        with self.assertRaises(ValueError):
            self.p.source_binding(copied)

    def test_live_root_selectors_unbound_and_actual_entry_refuses_before_actors(self):
        m = self.m
        for name in ('SOURCE', 'REF', 'WORKFLOW', 'WORKFLOW_SHA', 'POST'):
            self.assertIsNone(getattr(m, name))
        self.assertEqual(m.CANDIDATE_SOURCE,CANDIDATE_CID)
        self.assertEqual(m.CANDIDATE_REF,CANDIDATE_REF)
        self.assertEqual(m.PROPOSED_REF,CANDIDATE_REF)
        for name in ('source', 'ref', 'workflow_id', 'workflow_sha256'):
            self.assertIsNone(m.CASE[name])
        values = json.loads(self.files['ROOT-INPUTS.UNISSUED.json'])
        for name in ('Root_authority', 'runtime54_profile', 'operational_context', 'role_label', 'nonce',
                     'created_utc', 'expires_utc', 'output', 'documents_output', 'custody', 'resources',
                     'publication', 'registration'):
            self.assertIsNone(values[name], name)
        self.assertEqual(values['source_CID'],CANDIDATE_CID)
        self.assertEqual(values['source_ref'],None if CANDIDATE_REF is None else 'refs/heads/'+CANDIDATE_REF)
        binding=json.loads(self.files['binding.DATA.json'])
        self.assertEqual(binding['source_CID'],CANDIDATE_CID)
        self.assertEqual(binding['source_ref'],None if CANDIDATE_REF is None else 'refs/heads/'+CANDIDATE_REF)
        self.assertEqual(binding['delegated_metadata_result'],None if self.p.METADATA_PATH is None else dict(path=str(self.p.METADATA_PATH),**self.p.METADATA_PIN))
        self.assertIsNone(binding['Root_authority'])
        a = self.arguments()
        a.publication_sha256 = a.registration_sha256 = ''
        argv = [part for k,v in vars(a).items() if k not in ('case','fd','owner','owner_start')
                for part in ('--'+k.replace('_','-'), str(v))]
        with patch.object(m, 'read', side_effect=AssertionError('no proof read')), \
             patch.object(m, 'modules', side_effect=AssertionError('no role or lease')), \
             patch.object(m, 'approvals', side_effect=AssertionError('no admission')):
            with self.assertRaises(ValueError):
                cli(m, argv)
        with patch.object(m, 'checked', side_effect=AssertionError('no operational proof read')):
            with self.assertRaises(ValueError):
                m.operational_context(argparse.Namespace(operational_context=None, operational_context_sha256=None))
        joiner = module(self.output/'packet/make_root_config.DRAFT.py', 'llhttp95_joiner_null_DATA')
        with patch.object(joiner.O, 'checked', side_effect=AssertionError('no Root proof read')):
            with self.assertRaises(ValueError):
                joiner.assemble(argparse.Namespace())

    def test_consumed_sources_refs_and_foreign_tuple_refuse_before_custody(self):
        a, public, registration = self.modeled_configuration()
        alterations = [dict(public, source=cid) for cid in self.p.CONSUMED_SOURCES]
        alterations += [dict(public, ref='refs/heads/'+ref) for ref in self.p.CONSUMED_REFS]
        alterations += [dict(public, tree='0'*40), dict(public, files=85), dict(public, source_map=dict(bytes=20200,sha256='f'*64))]
        for altered in alterations:
            m = module(self.output/OPERATOR, 'llhttp95_consumed_publication_MODEL')
            m.CANDIDATE_SOURCE,m.CANDIDATE_REF=MODEL_CID,MODEL_REF
            with patch.object(m, 'checked', side_effect=lambda path,digest: altered if path == a.publication else registration), patch.object(m, 'modules', side_effect=AssertionError('no custody')):
                with self.assertRaises(ValueError):
                    m.configure(a)
            self.assertIsNone(m.SOURCE)
            self.assertIsNone(m.POST)

    def test_inactive_templates_and_active_source95_pins_have_no_old_cid_binding(self):
        self.assertEqual(self.m.CANDIDATE_SOURCE,CANDIDATE_CID)
        self.assertEqual(self.m.CANDIDATE_REF,CANDIDATE_REF)
        self.assertEqual(self.m.CONSUMED_SOURCES, self.p.CONSUMED_SOURCES)
        self.assertEqual(self.m.CONSUMED_REFS, self.p.CONSUMED_REFS)
        self.assertEqual(self.m.POLICY_PIN, pin((SOURCE/PREFIX/'policy.json').read_bytes()))
        self.assertEqual(self.m.OWNER_PROGRAM_PIN, dict(bytes=9673,sha256='b9197a46a6161d6d5fa9c3cf3c8edfe030ba7010b48c0dcb4fbaf68886245d4f'))
        self.assertEqual(self.m.POLICY_PIN['bytes'],21404)
        config=json.loads(self.files['packet/operator-DRAFT/config.TEMPLATE.json'])
        self.assertIs(config.pop('case'),False)
        self.assertTrue(all(value is None for value in config.values()))
        for name in ('admission','runtime'):
            value=json.loads(self.files['packet/operator-DRAFT/'+name+'.TEMPLATE.json'])
            self.assertIs(value['accepted'],False)
            for field in ('source','ref','nonce','created_utc','expires_utc','issued_by','source_map_sha256'):
                self.assertIsNone(value[field])
        value=json.loads(self.files['packet/operator-DRAFT/authority.TEMPLATE.json'])
        self.assertIs(value['once'],True)
        self.assertIs(value['retry'],False)
        self.assertTrue(all(v is None for k,v in value.items() if k not in ('once','retry','reviews')))
        self.assertTrue(all(v is None for v in value['reviews'].values()))

    def test_real_configure_and_source_with_temporary_model_metadata_only(self):
        a, public, registration = self.modeled_configuration()
        joiner = module(self.output/'packet/make_root_config.DRAFT.py', 'llhttp95_model_census_DATA')
        calls = []
        def census(unused, root, rows, modes):
            calls.append(len(rows))
            return joiner.physical(unused, root, rows, modes)
        body = self.m.source(type('MODEL_Census', (), {'closed_source_declared': staticmethod(census)}), None, a)
        self.assertEqual(calls, [95, 45])
        self.assertEqual(pin(body), dict(bytes=6201, sha256='2ba05dea048406382cf0285c1a73f56b8671c8a322ffd2636ae41ddc64d82c99'))
        self.assertEqual((self.m.TREE, self.m.MAP), (TREE, MAP))
        self.assertEqual(self.m.CASE['source_files'], 95)
        self.assertEqual(self.m.CASE['source_bytes'], 1318237)
        for altered in (dict(public, source='invalid'), dict(public, files=85), dict(public, tree='0'*40)):
            fresh = module(self.output/OPERATOR, 'llhttp95_foreign_MODEL')
            fresh.CANDIDATE_SOURCE, fresh.CANDIDATE_REF = MODEL_CID, MODEL_REF
            with patch.object(fresh, 'checked', side_effect=lambda path,digest: altered if path == a.publication else registration):
                with self.assertRaises(ValueError):
                    fresh.configure(a)

    def test_literal_issuer_joiner_operator_cli_surfaces_and_routes(self):
        issuer = module(self.output/'issue_root_packet.DRAFT.py', 'llhttp95_issuer_parser_DATA')
        joiner = module(self.output/'packet/make_root_config.DRAFT.py', 'llhttp95_joiner_parser_DATA')
        for m, names in ((issuer, ('--nonce','--root-reviewed','--documents-output','--operational-context-sha256')),
                         (joiner, ('--config-output','--runtime54-profile','--authority-sha256')),
                         (self.m, ('--case','--fd','--owner-start','--operational-context-sha256'))):
            stream = io.StringIO()
            with redirect_stdout(stream), self.assertRaises(SystemExit) as stopped:
                cli(m, ['--help'])
            self.assertEqual(stopped.exception.code, 0)
            for name in names:
                self.assertIn(name, stream.getvalue())
        issuer_args = []
        for name in ('publication','registration','runtime54_profile','operational_context'):
            issuer_args += ['--'+name.replace('_','-'), str(self.model/('MODEL-'+name)), '--'+name.replace('_','-')+'-sha256', 'e'*64]
        issuer_args += ['--output', str(self.model/'MODEL-output'), '--documents-output', str(self.model/'MODEL-documents'),
                        '--created-utc','1','--expires-utc','2','--nonce','c'*32,'--root-reviewed']
        with patch.object(issuer, 'issue', side_effect=ActionBoundary('issuer never entered')) as boundary:
            with self.assertRaises(ActionBoundary):
                cli(issuer, issuer_args)
            self.assertIs(boundary.call_args.args[0].root_reviewed, True)
        joiner_args = ['--source-root',str(SOURCE),'--output',str(self.model/'MODEL-output'), '--config-output',str(self.model/'MODEL-config')]
        for name in joiner.FIELDS:
            joiner_args += ['--'+name.replace('_','-'),str(self.model/('MODEL-'+name)), '--'+name.replace('_','-')+'-sha256','e'*64]
        with patch.object(joiner, 'assemble', side_effect=ActionBoundary('joiner routed only')) as boundary:
            with self.assertRaises(ActionBoundary):
                cli(joiner, joiner_args)
            self.assertEqual(boundary.call_args.args[0].source_root, SOURCE)
        a = self.arguments()
        operator_args = [part for k,v in vars(a).items() if k not in ('case','fd','owner','owner_start')
                         for part in ('--'+k.replace('_','-'),str(v))]
        for flag, function in (([], 'enter'), (['--case','--fd','987654','--owner','876543','--owner-start','765432'], 'case')):
            with patch.object(self.m, function, side_effect=ActionBoundary('operator routed only')) as boundary:
                with self.assertRaises(ActionBoundary):
                    cli(self.m, operator_args+flag)
                self.assertEqual(boundary.call_args.args[0].case, bool(flag))
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli(issuer, issuer_args[:-3])

    def test_actual_root_publication_nested_map_adapter_metadata_only(self):
        if self.p.METADATA_PATH is None:self.skipTest('Root actual publication unissued; no fake receipt')
        _,_,registration=self.modeled_configuration()
        public=json.loads(self.p.read(self.p.METADATA_PATH))
        self.assertNotIn('source_map_sha256',public)
        self.assertEqual(public['source_map'],dict(bytes=20200,sha256=MAP))
        m=module(self.output/OPERATOR,'llhttp95_actual_metadata_MODEL_registration')
        a=self.arguments()
        with patch.object(m,'checked',side_effect=lambda path,digest: public if path==a.publication else registration):
            m.configure(a)
        self.assertEqual((m.SOURCE,m.REF),(CANDIDATE_CID,CANDIDATE_REF))
        self.assertEqual(m.CASE['source_files'],93)
        self.assertIsNone(json.loads(self.files['ROOT-INPUTS.UNISSUED.json'])['Root_authority'])

    def test_primitive_exact_five_inputs_and_registration_null_contract(self):
        a, _, registration = self.modeled_configuration()
        plan=json.loads(self.files['registration-plan.DATA.json'])
        self.assertEqual(plan['issuer'],'workerDATA')
        for key in ('Root_adoption','registration','Main','initial_final_Main_CAS','secret_name_catalog','Root_authority'):
            self.assertIsNone(plan[key])
        self.assertEqual(plan['required_secret_name_count'],22)
        self.assertFalse(plan['secret_values_read'])
        self.assertEqual(plan['workflow_body'],pin((SOURCE/self.m.WF).read_bytes()))
        for change in ({'state':'disabled_manually'},{'observed_utc':1},{'workflow_id':420972286},{'workflow_sha256':'f'*64},{'registration_commit':None}):
            fresh=module(self.output/OPERATOR,'llhttp95_registration_refusal_MODEL')
            fresh.CANDIDATE_SOURCE,fresh.CANDIDATE_REF=MODEL_CID,MODEL_REF
            public=dict(issuer='Root',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',source=MODEL_CID,ref='refs/heads/'+MODEL_REF,tree=TREE,source_map=dict(bytes=20200,sha256=MAP),files=95,bytes=1318237,native='NOT RUN',M2='NOT RUN')
            with patch.object(fresh,'checked',side_effect=lambda path,digest: public if path==a.publication else dict(registration,**change)):
                with self.assertRaises((ValueError,TypeError)):
                    fresh.configure(a)
        node=next(n for n in ast.parse(self.files[PRIMITIVE]).body if isinstance(n,ast.FunctionDef)and n.name=='validate_inputs')
        scope=dict(vars(self.m));exec(compile(ast.Module(body=[node],type_ignores=[]),'primitive-five-input-MODEL','exec'),scope)
        values=dict(source_map_sha256=MAP,admission_sha256='a'*64,admission_json='MODEL-admission',runtime_sha256='b'*64,runtime_json='MODEL-runtime')
        policy=(SOURCE/PREFIX/'policy.json').read_bytes()
        calls=[];scope['llhttp_documents']=lambda *args:calls.append(args)
        self.assertEqual(scope['validate_inputs'](values,MODEL_CID,MODEL_REF,policy,'a'*64,'b'*64),values)
        self.assertEqual(len(calls),1)
        for bad in ({k:v for k,v in values.items()if k!='runtime_json'},dict(values,extra='MODEL'),dict(values,source_map_sha256='f'*64)):
            with self.assertRaises(AssertionError):scope['validate_inputs'](bad,MODEL_CID,MODEL_REF,policy,'a'*64,'b'*64)

    def test_large_policy_and_authority_fit_unchanged_limits_small_documents_stay_16k(self):
        raw=(SOURCE/PREFIX/'policy.json').read_bytes()
        self.assertEqual(len(raw),21404)
        self.assertGreater(len(raw),16384)
        self.assertEqual(self.m.read(SOURCE/PREFIX/'policy.json'),raw)
        custody=self.m.read(self.m.CUSTODY)
        self.assertEqual(pin(custody)['sha256'],self.m.CUSTODY_SHA)
        nodes=[n for n in ast.parse(custody).body if isinstance(n,ast.FunctionDef)and n.name in ('identity','read')]
        scope=dict(Path=Path,os=os,stat=stat)
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'held-custody-read-only-MODEL','exec'),scope)
        self.assertEqual(scope['read'](SOURCE/PREFIX/'policy.json'),raw)
        self.assertIn('a.st_size < 768 * 1024 ** 2',ast.unparse(nodes[-1]))
        authority=dict(MODEL=True,resources=json.loads(raw),Root_authority=None)
        path=self.model/'MODEL-authority.json';data=canonical(authority);path.write_bytes(data)
        self.assertGreater(len(data),16384)
        self.assertEqual(self.m.checked(path,pin(data)['sha256'])['resources'],json.loads(raw))
        defaults=next(n for n in ast.parse(self.files[OPERATOR]).body if isinstance(n,ast.FunctionDef)and n.name=='read').args.defaults
        self.assertEqual(eval(compile(ast.Expression(defaults[-1]),'literal-read-limit','eval')),8*1024**2)
        oversized=b' '*16385
        with self.assertRaises(AssertionError):self.m.llhttp_documents(oversized,b'{}','a'*40,'codex/MODEL','f'*64,'f'*64)
        self.assertEqual(self.m.PUBLIC_RETENTION_PIN,self.p.PUBLIC_RETENTION_PIN)
        self.assertEqual(self.p.PUBLIC_RETENTION_PIN,pin((SOURCE/PREFIX/'public_evidence.py').read_bytes()))
        self.assertEqual(len(authority['resources']['inner_public_retention']['public_leaves']),526)
        self.assertFalse(authority['resources']['inner_public_retention']['acceptance'])

    def test_protected_functions_runtime_custody_deadlines_resources_unchanged(self):
        for name in ('issue_root_packet.DRAFT.py', 'packet/make_root_config.DRAFT.py', OPERATOR, PRIMITIVE):
            before, after = functions((PARENT/name).read_bytes()), functions(self.files[name])
            ignored = {'configure', 'source'} if name == OPERATOR else set()
            self.assertEqual(set(before), set(after))
            for function in set(before)-ignored:
                self.assertEqual(before[function], after[function], name+':'+function)
        parent = module(PARENT/OPERATOR, 'llhttp85_unentered_constants_DATA')
        for name in ('PAIR_RESOURCES','HOST_TOOLS','STATUS','R_PATH','R_SHA','C_PATH','C_SHA',
                     'CUSTODY','CUSTODY_SHA','OLD_PRIMITIVE','OLD_PRIMITIVE_SHA','CONTEXT_PROOFS'):
            self.assertEqual(getattr(parent,name),getattr(self.m,name),name)
        self.assertEqual(functions(self.files[OPERATOR])['llhttp_documents'], functions(self.files[PRIMITIVE])['llhttp_documents'])
        text = self.files[OPERATOR].decode()
        for seam in ('for sweep in range(2):','for status in STATUS:',"v['total_count']==len(v['workflow_runs'])==0",
                     "intent['prior_run_ids']==[]", "main_guard(direct,g['main'])", 'C.natural(r)',
                     "result['release']='CLOSE_ONLY'", 'os.pidfd_open(pid,0)', 'fcntl.LOCK_EX|fcntl.LOCK_NB',
                     'time.monotonic()+1200','run(command,750)'):
            self.assertIn(seam,text)
        self.assertEqual(self.m.HOST_TOOLS['package_manager_invocations'],0)
        self.assertEqual(self.m.HOST_TOOLS['host_package_mutations'],0)

    def test_real_main_cas_and_two_sweep_gate_refuse_each_missing_property(self):
        a, _, _ = self.modeled_configuration()
        m = self.m
        calls = []
        def git(argv, cap):
            calls.append(argv)
            if 'symbolic-ref' in argv:return b'main\n'
            if 'status' in argv:return b''
            if 'ls-remote' in argv:return ('f'*40+'\trefs/heads/main\n').encode()
            return ('f'*40+'\n').encode()
        self.assertEqual(m.main_guard(git,'f'*40),'f'*40)
        self.assertEqual(len(calls),5)
        with self.assertRaises(ValueError):
            m.main_guard(git,'a'*40)
        path = self.model/'MODEL-gate.json'
        good = dict(case=m.CASE, checked_at_utc=datetime.now(timezone.utc).isoformat(), main='f'*40,
                    authority_sha256=a.authority_sha256, passes=2,statuses=list(m.STATUS),complete_paginated=True,empty=True,metadata_GETs=10)
        path.write_bytes(canonical(good))
        self.assertEqual(m.gate(path,a),good)
        for field,value in (('passes',1),('statuses',['completed']),('metadata_GETs',5),('empty',False),
                            ('complete_paginated',False),('checked_at_utc','2000-01-01T00:00:00+00:00')):
            path.write_bytes(canonical(dict(good,**{field:value})))
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.gate(path,a)

    def test_real_document_predicates_and_once_post_validation_without_transport(self):
        a, _, _ = self.modeled_configuration()
        m = self.m
        now = int(time.time())
        common = dict(accepted=True,created_utc=now-1,expires_utc=now+60,issued_by='Root',nonce='c'*32,
                      ref='refs/heads/'+m.REF,resources=m.PAIR_RESOURCES,source=m.SOURCE,source_map_sha256=m.MAP)
        admission = dict(common,kind='ROOT_LLHTTP_REFERENCE_HOSTED_ADMISSION_V1')
        runtime = dict(common,kind='ROOT_LLHTTP_REFERENCE_HOSTED_RUNTIME_V1',external_supervision=m.OWNER_PROGRAM_PIN,
                       bootstrap_resource_domain=m.POLICY_PIN,host_tools=copy.deepcopy(m.HOST_TOOLS))
        ar, rr = canonical(admission), canonical(runtime)
        m.llhttp_documents(ar,rr,m.SOURCE,m.REF,pin(ar)['sha256'],pin(rr)['sha256'])
        for key,value in (('accepted',False),('source',None),('nonce',None),('expires_utc',1),('source_map_sha256','f'*64)):
            wrong = canonical(dict(admission,**{key:value}))
            with self.subTest(field=key), self.assertRaises((AssertionError,ValueError)):
                m.llhttp_documents(wrong,rr,m.SOURCE,m.REF,pin(wrong)['sha256'],pin(rr)['sha256'])
        runtime['host_tools']['package_manager_invocations']=1
        wrong=canonical(runtime)
        with self.assertRaises(AssertionError):
            m.llhttp_documents(ar,wrong,m.SOURCE,m.REF,pin(ar)['sha256'],pin(wrong)['sha256'])
        values=dict(source_map_sha256=m.MAP,admission_sha256='a'*64,admission_json='MODEL',runtime_sha256='b'*64,runtime_json='MODEL')
        body=json.dumps(dict(ref=m.REF,inputs=values)).encode()
        with patch.object(m,'inputs',return_value=values):
            m.post_request(m.POST,body,False,a)
            for argv,raw,sent in ((m.POST,body,True),(m.POST,json.dumps(dict(ref='wrong',inputs=values)).encode(),False),(m.POST[:-1]+['wrong'],body,False)):
                with self.assertRaises(ValueError):
                    m.post_request(argv,raw,sent,a)


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('Run this DATA control with python -I -B, unoptimized')
    unittest.main(verbosity=2)
