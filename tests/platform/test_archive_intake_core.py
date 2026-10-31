#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused adapter/source-map controls; no retained package archives opened."""
from contextlib import contextmanager
import copy
import io
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

PACKET = Path(__file__).resolve().parents[2]
WORK = PACKET / '.intake-engine-test-work'
SOURCE = PACKET / 'scripts/platform/archive_intake.py'
adapter = types.ModuleType('adapter_under_review')
adapter.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), adapter.__dict__)
portable = adapter


def identity(name='networkmanager', version='1.58.1-1'):
    return dict(name=name, version=version, arch='aarch64')


def reference(size=123):
    return dict(path='/retained/exact.pkg.tar.xz', size=size, sha256='a'*64,
                identity=[1, 2, 33152, 1, 1000, 1000, size, 3, 4])


def selection():
    return dict(schema_version=1, scope='EXACT_SELECTED_ARCHIVE_STAGING_ONLY',
                packages=[dict(identity=identity(), archive=reference(), signature=reference(566))])


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global adapter
        WORK.mkdir(mode=0o700)
        cls.runtime_context = portable.runtime(WORK)
        adapter = cls.runtime_context.__enter__()
        cls.policy = adapter.load(adapter.RUNTIME/'policy.py', adapter.POLICY_SHA)
        with cls.policy.snapshot() as (raws, check):
            cls.modules = cls.policy.sources(raws)
            check()
        cls.core, cls.bridge, cls.assembler = (cls.modules[k] for k in ('core', 'bridge', 'assembler'))

    @classmethod
    def tearDownClass(cls):
        cls.runtime_context.__exit__(None, None, None)
        WORK.rmdir()

    def refused(self, code, action):
        with self.assertRaisesRegex(ValueError, '^'+code+'$'):
            action()

    def test_explicit_authentication_is_separate_from_local_digest(self):
        chosen = selection()
        self.assertEqual(adapter.validate_selection(self.core, chosen, copy.deepcopy(adapter.AUTHENTICATION)), chosen['packages'])
        for auth in (None, {}, dict(archive_sha256='a'*64), dict(adapter.AUTHENTICATION, schema_version=True),
                     dict(adapter.AUTHENTICATION, profile='local-sha256-match')):
            with self.subTest(auth=auth):
                self.refused('authentication-profile-required', lambda: adapter.validate_selection(self.core, chosen, auth))
        changed = copy.deepcopy(adapter.AUTHENTICATION)
        changed['proof_sha256']['proof/actual-receipt.json'] = '0'*64
        self.refused('authentication-profile-required', lambda: adapter.validate_selection(self.core, chosen, changed))

    def test_exact_tuple_duplicate_and_reference_refusals(self):
        cases = []
        chosen = selection(); chosen['packages'][0]['identity']['version'] = '1.58.1-2'
        cases.append((chosen, 'authentication-profile-has-no-proof-for-tuple'))
        chosen = selection(); chosen['packages'] *= 2
        cases.append((chosen, 'duplicate-selection'))
        chosen = selection(); chosen['schema_version'] = True
        cases.append((chosen, 'selection-schema'))
        chosen = selection(); chosen['packages'][0]['archive']['size'] = True
        cases.append((chosen, 'reference-pin'))
        chosen = selection(); chosen['packages'][0]['archive']['identity'][6] += 1
        cases.append((chosen, 'reference-pin'))
        for chosen, code in cases:
            with self.subTest(code=code):
                self.refused(code, lambda: adapter.validate_selection(self.core, chosen, adapter.AUTHENTICATION))

    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='maps-', dir=WORK) as parent:
            budget = self.core.Budget(time.monotonic()+120)
            with self.modules['spool'].Store(Path(parent)/'spool', self.core, budget) as store:
                body = store.put(io.BytesIO(b'abc'), 3)
                control = store.put(io.BytesIO(b'pkgname = networkmanager\n'), 25)
                node = dict(type='file', mode=0o640, uid=123, gid=456, bytes=3, sha256=adapter.sha(b'abc'))
                tree = {'usr':dict(type='directory', mode=0o755, uid=0, gid=0),
                        'usr/bin':dict(type='directory', mode=0o755, uid=0, gid=0),
                        'usr/bin/tool':node,
                        'usr/bin/alias':dict(type='hardlink', mode=0o640, uid=123, gid=456, target='usr/bin/tool'),
                        'usr/bin/current':dict(type='symlink', mode=0o777, uid=0, gid=0, target='tool')}
                package = dict(identity=identity(), archive_sha256='a'*64, source_sha256='b'*64,
                               nodes=tree, bodies={'usr/bin/tool':body},
                               metadata={'.PKGINFO':dict(ref=control, parsed={'fields':{'backup':['usr/bin/tool']}})}, intake={})
                yield package, store, budget

    def prepare(self, packages, expected, store):
        return self.bridge.prepare(self.core, self.assembler, packages, expected, store)

    def test_spooled_real_metadata_shape_and_ownership(self):
        with self.fixture() as (package, store, budget):
            nodes, bodies, pristine = self.prepare([package], [identity()], store)
            self.assertEqual(nodes, package['nodes'])
            self.assertEqual(bodies, package['bodies'])
            self.assertEqual(pristine['owners']['usr/bin/tool'], ['networkmanager'])
            self.assertEqual(nodes['usr/bin/alias']['target'], 'usr/bin/tool')
            self.assertEqual({k:nodes['usr/bin/tool'][k] for k in ('mode','uid','gid')}, dict(mode=0o640, uid=123, gid=456))
            with store.lookup(bodies['usr/bin/tool']) as stream:
                self.assertEqual(stream.read(3), b'abc')

    def test_body_and_tuple_closure_refusals(self):
        with self.fixture() as (package, store, budget):
            for mutation, code in (
                (lambda p:p['bodies'].clear(), 'body-reference-set'),
                (lambda p:p['nodes']['usr/bin/tool'].update(sha256='0'*64), 'spool-payload-binding'),
                (lambda p:p['identity'].update(version='newer'), 'exact-package-tuple'),
                (lambda p:p['nodes'].pop('usr/bin'), 'explicit-directory-parent'),
            ):
                changed=copy.deepcopy(package); mutation(changed)
                with self.subTest(code=code):
                    self.refused(code, lambda:self.prepare([changed], [identity()], store))

    def test_hardlink_metadata_ownership_and_symlink_escape_refusals(self):
        with self.fixture() as (package, store, budget):
            for mutation, code in (
                (lambda p:p['nodes']['usr/bin/alias'].update(uid=0), 'hardlink-metadata'),
                (lambda p:p['nodes']['usr/bin/alias'].update(target='usr/bin/missing'), 'same-package-hardlink'),
                (lambda p:p['nodes']['usr/bin/current'].update(target='../../../outside'), 'virtual-link-root-escape'),
            ):
                changed=copy.deepcopy(package); mutation(changed)
                with self.subTest(code=code):
                    self.refused(code, lambda:self.prepare([changed], [identity()], store))
            second=copy.deepcopy(package); second['identity']=identity('perl', '5.42.2-2')
            self.refused('pristine-path-conflict', lambda:self.prepare([package,second], [identity(),second['identity']], store))

    def test_inert_separation_backup_and_unknown_control(self):
        with self.fixture() as (package, store, budget):
            package['metadata']['.INSTALL'] = copy.deepcopy(package['metadata']['.PKGINFO'])
            package['nodes']['usr/share/libalpm/hooks/10-test.hook'] = dict(package['nodes']['usr/bin/tool'])
            before=copy.deepcopy(package)
            result=adapter.separation(self.core, package)
            self.assertEqual(result['scriptlets'], ['.INSTALL'])
            self.assertEqual(result['hook_and_generated_state_inputs'], ['usr/share/libalpm/hooks/10-test.hook'])
            self.assertEqual(result['backup_paths'], ['usr/bin/tool'])
            self.assertFalse(result['hooks_executed']); self.assertFalse(result['generated_state_created'])
            self.assertEqual(package,before)
            for backup, code in ((['../escape'],'noncanonical-path'), (['usr'],'backup-not-package-file'),
                                 (['missing'],'backup-not-package-file'), (['usr/bin/alias'],'backup-not-package-file'),
                                 (['usr/bin/tool']*2,'duplicate-backup-path')):
                changed=copy.deepcopy(package); changed['metadata']['.PKGINFO']['parsed']['fields']['backup']=backup
                with self.subTest(backup=backup):
                    self.refused(code,lambda:adapter.separation(self.core,changed))
            for dot in ('.CHANGELOG','.Changelog','.UNKNOWN'):
                changed=copy.deepcopy(package);changed['nodes'][dot]=dict(package['nodes']['usr/bin/tool'])
                self.refused('unsupported-root-dot-control',lambda:adapter.separation(self.core,changed))

    def test_context_cleanup_failure_never_publishes_pass_receipt(self):
        @contextmanager
        def failing(*args):
            yield {'packages':[{'identity':identity(),'nodes':{},'bodies':{}}]}
            raise ValueError('injected-source-cleanup-failure')
        with tempfile.TemporaryDirectory(prefix='receipt-',dir=WORK) as parent:
            output=Path(parent)/'run'
            with patch.object(adapter,'prepared',failing), patch.object(adapter,'assemble',return_value={}):
                self.refused('injected-source-cleanup-failure',lambda:adapter.run(selection(),adapter.AUTHENTICATION,output))
            self.assertTrue((output/'INCOMPLETE.json').exists())
            self.assertFalse((output/'receipt.json').exists())


    def test_final_marker_or_publication_failure_never_creates_accepted_name(self):
        @contextmanager
        def healthy(*args):
            yield {'packages':[{'identity':identity(),'nodes':{},'bodies':{}}]}
        result=dict(bundle={'bytes':0,'sha256':'a'*64},manifest_sha256='b'*64,
                    manifest={'archive_authentication':{},'inert_separation':{}},io={})
        original_unlink=Path.unlink
        def marker_failure(path,*args,**kwargs):
            if path.name=='INCOMPLETE.json':
                raise OSError('injected-marker-unlink-failure')
            return original_unlink(path,*args,**kwargs)
        for stage in ('marker','rename'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(prefix='commit-',dir=WORK) as parent:
                output=Path(parent)/'run'
                mutation=(patch.object(Path,'unlink',marker_failure) if stage=='marker' else
                          patch.object(adapter.os,'rename',side_effect=OSError('injected-rename-failure')))
                with patch.object(adapter,'prepared',healthy), patch.object(adapter,'assemble',return_value=result), mutation:
                    with self.assertRaises(OSError):
                        adapter.run(selection(),adapter.AUTHENTICATION,output)
                self.assertFalse((output/'receipt.json').exists())
                self.assertTrue((output/'receipt.pending.json').exists())
                self.assertEqual((output/'INCOMPLETE.json').exists(),stage=='marker')


if __name__=='__main__':
    unittest.main(verbosity=2)
