#!/usr/bin/env python3
"""Inert copy/policy connections; synthetic selection never enables actual paths."""
import copy
import functools
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).absolute().parent
sys.path.insert(0,str(HERE))
import test_auxiliary as fixtures
import aux_checkpoint as aux
import aux_copy
import capacity
import disposable_copy
import full_root as roots
import linked_runtime
import root_link_selection as links
import setup_trial

@unittest.skipUnless(os.geteuid()==0,'mapped root required for held UID0 fixtures')
class Connections(unittest.TestCase):
    setUp=fixtures.Closure.setUp
    limits=fixtures.Closure.limits
    mkdir=fixtures.Closure.mkdir
    write=fixtures.Closure.write
    keys=fixtures.Closure.keys
    config=fixtures.Closure.config
    observation=fixtures.Closure.observation
    state=fixtures.Closure.state

    def setUp(self):
        fixtures.Closure.setUp(self)
        self.copy_work=self.base/'copied-work'
        original,real_statvfs=capacity.check,os.statvfs
        def fixture_space(path):
            value=real_statvfs(path)
            if value.f_files==value.f_favail==0:
                fields=list(value); fields[5]=fields[6]=fields[7]=1000000
                return os.statvfs_result(fields)
            return value
        patched=patch.object(capacity,'check',functools.partial(original,statvfs=fixture_space))
        patched.start(); self.addCleanup(patched.stop)

    def observed(self,path): return roots.observe(path,limits=self.limits(),hardlinks='generic-development-internal')
    def copied(self): return aux_copy.copied_root(self.source,self.copy_work,limits=self.limits())

    def selection(self,observation,names,*,data=()):
        nodes=observation['nodes']; names=tuple(sorted(names)); data=set(data)
        patches=[patch.object(links,'CHAIN_PATHS',names),
                 patch.object(links,'LINK_NODES',{name:dict(nodes[name]) for name in names}),
                 patch.object(links,'RESOLVED_ENDPOINTS',{name:'usr/lib/libfixture-a.so' for name in names if name not in data}),
                 patch.object(links,'DATA_ONLY_ENDPOINTS',{name:'dev/null' for name in data})]
        from contextlib import ExitStack
        stack=ExitStack()
        for item in patches: stack.enter_context(item)
        return stack

    def add_links(self,root):
        directory=root/'usr/share'; directory.mkdir(parents=True,exist_ok=True)
        (directory/'absolute-fixture').symlink_to('/usr/lib/libfixture-a.so')
        (directory/'relative-fixture').symlink_to('absolute-fixture')
        return ('usr/share/absolute-fixture','usr/share/relative-fixture')

    def test_auxiliary_copy_preserves_all_nodes_groups_then_cleans(self):
        (self.source/'usr/share/group-a').write_bytes(b'inert group')
        os.link(self.source/'usr/share/group-a',self.source/'usr/share/group-b')
        before=self.observed(self.source); descriptors=len(os.listdir('/proc/self/fd'))
        with self.copied() as (root,report):
            after=self.observed(root)
            self.assertEqual(after['nodes'],before['nodes']); self.assertEqual(after['hardlink_groups'],before['hardlink_groups'])
            self.assertNotEqual((root/'usr/share/group-a').stat().st_ino,(self.source/'usr/share/group-a').stat().st_ino)
            self.assertFalse(report['copy']['eligible']); self.assertTrue(report['copy']['copy_complete'])
            self.assertTrue(report['copy']['copy_byte_identical_before_initialization'])
        self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed'); self.assertFalse(self.copy_work.exists())
        self.assertEqual(self.observed(self.source)['nodes'],before['nodes']); self.assertEqual(len(os.listdir('/proc/self/fd')),descriptors)

    def test_strict_copier_is_unchanged_before_and_after_opt_in(self):
        original=roots.require_eligible
        for attempt in (0,1):
            with self.assertRaisesRegex(ValueError,'unsupported or incomplete'):
                with disposable_copy.copied_root(self.source,self.base/('strict-'+str(attempt)),limits=self.limits()): self.fail('strict copy must refuse helper')
            if attempt==0:
                with self.copied(): pass
        self.assertIs(roots.require_eligible,original)

    def test_empty_selection_rejects_absolute_before_target_allocation(self):
        self.add_links(self.source)
        with self.assertRaisesRegex(ValueError,'unselected-absolute'):
            with self.copied(): self.fail('unselected links must not copy')
        self.assertFalse(self.copy_work.exists())
        self.assertEqual(links.LINK_NODES,{})

    def test_exact_direct_and_relative_chain_copy_preserves_literal_targets(self):
        names=self.add_links(self.source); observation=self.observed(self.source)
        with self.selection(observation,names):
            links.check(observation,self.limits())
            with self.copied() as (root,report):
                for name in names: self.assertEqual(os.readlink(root/name),observation['nodes'][name]['target'])
                self.assertEqual(self.observed(root)['nodes'],observation['nodes'])
        self.assertFalse(self.copy_work.exists())

    def test_wrong_target_missing_member_or_wrong_endpoint_refused(self):
        names=self.add_links(self.source); original=self.observed(self.source)
        with self.selection(original,names):
            for kind in ('literal','endpoint','chain'):
                value=copy.deepcopy(original)
                if kind=='literal': value['nodes'][names[0]]['target']='/home/user/config'
                elif kind=='endpoint': value['nodes'].pop('usr/lib/libfixture-a.so')
                else:
                    value['nodes']['usr/share/unselected-alias']=dict(value['nodes'][names[1]])
                    value['unsupported_counts']['absolute-symlink']+=1
                with self.subTest(kind=kind),self.assertRaises(ValueError): links.check(value,self.limits())

    def test_data_only_endpoint_is_protection_name_not_filesystem_access(self):
        directory=self.root/'inert-masks'; directory.mkdir()
        (directory/'one.hook').symlink_to('/dev/null')
        name='inert-masks/one.hook'; observation=self.observation()
        with self.selection(observation,(name,),data=(name,)):
            instance=linked_runtime.Runtime(self.args,self.config(),comparator_path=fixtures.COMPARATOR)
            seed=instance.tree(self.root)
            self.assertEqual(instance.resolve_nodes(seed,name),'dev/null')
            self.assertEqual(instance.node(self.root/name)['target'],'/dev/null')
            with self.assertRaises(ValueError): aux.Reader(self.root,observation,self.limits()).resolve(name)
            (self.root/'dev').mkdir(); (self.root/'dev/null').write_bytes(b'inert newly appeared endpoint')
            with self.assertRaisesRegex(ValueError,'data-endpoint-drift'): links.check(self.observation(),self.limits())

    def test_copy_failure_cleanup_keeps_source_and_reports_primary(self):
        before=self.observed(self.source)['nodes']; failure=ValueError('inert failed copy')
        binding=aux_copy._copy_binding(self.limits())
        def failed(fd,data,limits): raise failure
        with patch.object(binding,'_write',side_effect=failed),patch.object(aux_copy,'_copy_binding',return_value=binding):
            with self.assertRaises(ValueError) as caught:
                with self.copied(): self.fail('must not yield')
        self.assertIs(caught.exception,failure); self.assertFalse(self.copy_work.exists())
        self.assertEqual(self.observed(self.source)['nodes'],before)

    def test_selected_link_runtime_projects_raw_literals_and_holds_groups(self):
        names=self.add_links(self.root); observation=self.observation()
        with self.selection(observation,names):
            instance=linked_runtime.Runtime(self.args,self.config(),comparator_path=fixtures.COMPARATOR)
            seed=instance.tree(self.root)
            instance.old_paths=set(fixtures.runtime.FILES)-{'usr/bin/cachy-asahi-repository','usr/share/doc/cachy-asahi-setup/repository-enrollment.md'}
            payload={name:dict(type='file',mode=0o644,uid=0,gid=0,bytes=3,sha256=fixtures.digest(b'new')) for name in fixtures.runtime.FILES}
            projected=instance.projected_paths(seed,payload)
            self.assertEqual(projected[names[0]]['target'],'/usr/lib/libfixture-a.so')
            with patch.object(fixtures.scale_runtime(),'precommit'): instance.precommit()
            for name in fixtures.runtime.FILES: self.write(name,b'new')
            instance.tree(self.root)
            self.assertEqual(len(instance.auxiliary_checks),3)
            self.assertEqual(instance.resolve_nodes(instance.observation['nodes'],names[1]),'usr/lib/libfixture-a.so')

    def test_tampered_copy_dependency_refused_before_copy(self):
        with patch.object(aux_copy,'COPY_SHA256','0'*64):
            with self.assertRaisesRegex(ValueError,'copier-source-pin'):
                with self.copied(): self.fail('must not yield')
        self.assertFalse(self.copy_work.exists())

class TrialGlue(unittest.TestCase):
    def args(self):
        from types import SimpleNamespace
        return SimpleNamespace(root='/owned/work/root',workspace='/owned/work',scale='/inputs/scale',scale_sha256='0'*64)

    def invoke(self,initialization,transaction,cleanup_failure=False):
        from contextlib import contextmanager
        calls=[]; copy_report={'cleanup':'NOT RUN'}
        @contextmanager
        def copied(*args,**kwargs):
            calls.append('copy')
            try: yield Path('/owned/work/root'),copy_report
            finally:
                calls.append('cleanup'); copy_report['cleanup']='FAIL' if cleanup_failure else 'PASS-owned-workspace-removed'
                if cleanup_failure: raise ValueError('owned cleanup failed')
        with patch.object(setup_trial.scale,'configuration',return_value={}), \
             patch.object(setup_trial.aux_initialize,'limits_from',return_value=object()), \
             patch.object(setup_trial.aux_copy,'copied_root',side_effect=copied), \
             patch.object(setup_trial.aux_initialize,'initialize',side_effect=lambda *a,**k:calls.append('initialize') or initialization), \
             patch.object(setup_trial.linked_runtime,'apply',side_effect=lambda *a,**k:calls.append('update') or transaction):
            row=setup_trial.run(self.args(),'/source/root',comparator_path='/selected/audio_aux.py')
        return row,calls

    def test_no_update_after_failed_or_unjoined_initialization(self):
        for initialization in ({'status':'FAIL','root_initialized':'UNKNOWN','source_preserved':True},
                               {'status':'PASS','root_initialized':True,'source_preserved':False}):
            row,calls=self.invoke(initialization,{'status':'PASS'})
            self.assertEqual(calls,['copy','initialize','cleanup']); self.assertEqual(row['status'],'FAIL')
            self.assertFalse(row['transaction']['packages_committed'])

    def test_cleanup_failure_preserves_committed_transaction_truth(self):
        initialization=dict(status='PASS',root_initialized=True,source_preserved=True)
        transaction=dict(status='PASS',commit_started=True,packages_committed=True,checkpoint_changed=True)
        row,calls=self.invoke(initialization,transaction,cleanup_failure=True)
        self.assertEqual(row['status'],'FAIL'); self.assertEqual(row['phase'],'cleanup')
        self.assertTrue(row['transaction']['packages_committed']); self.assertTrue(row['transaction']['checkpoint_changed'])
        self.assertEqual(calls,['copy','initialize','update','cleanup'])

    def test_success_requires_update_and_cleanup_and_retains_no_acceptance_claim(self):
        row,calls=self.invoke(dict(status='PASS',root_initialized=True,source_preserved=True),dict(status='PASS'))
        self.assertEqual(row['status'],'PASS'); self.assertEqual(row['phase'],'completed')
        self.assertEqual(row['full587_composition'],'NOT ESTABLISHED')

if __name__=='__main__': unittest.main()
