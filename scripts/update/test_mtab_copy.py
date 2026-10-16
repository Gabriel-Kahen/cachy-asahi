#!/usr/bin/env python3
"""Real inert mtab literal copying; no helper/proc target execution or reads."""
import functools
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).absolute().parent
REPO=next(parent for parent in HERE.parents if (parent/'scripts/update/full_root.py').is_file())
CANDIDATE=HERE/'proposed/scripts/update' if (HERE/'proposed/scripts/update').is_dir() else HERE
sys.path[:0]=[str(CANDIDATE),str(REPO/'scripts/update')]
import root_link_selection as links
import aux_copy
import linked_runtime
import test_auxiliary as fixtures
import aux_checkpoint as aux
import capacity

@unittest.skipUnless(os.geteuid()==0,'mapped-root UID0 fixture required')
class MtabCopy(unittest.TestCase):
    limits=fixtures.Closure.limits
    mkdir=fixtures.Closure.mkdir
    write=fixtures.Closure.write
    keys=fixtures.Closure.keys
    config=fixtures.Closure.config
    observation=fixtures.Closure.observation
    state=fixtures.Closure.state
    def setUp(self):
        fixtures.Closure.setUp(self)
        expected=dict(type='symlink',mode=0o777,uid=0,gid=0,target='/proc/self/mounts')
        for name,value in (('CHAIN_PATHS',('etc/mtab',)),('LINK_NODES',{'etc/mtab':expected}),
                           ('RESOLVED_ENDPOINTS',{}),('DATA_ONLY_ENDPOINTS',{'etc/mtab':'proc/self/mounts'})):
            selected=patch.object(links,name,value);selected.start();self.addCleanup(selected.stop)
        original,statvfs=capacity.check,os.statvfs
        def fixture_space(path):
            value=statvfs(path)
            if value.f_files==value.f_favail==0:
                fields=list(value);fields[5]=fields[6]=fields[7]=1000000;return os.statvfs_result(fields)
            return value
        selected=patch.object(capacity,'check',functools.partial(original,statvfs=fixture_space));selected.start();self.addCleanup(selected.stop)

    def test_each_supported_raw_variant_is_copied_and_reported_without_traversal(self):
        link=self.source/'etc/mtab'
        for index,target in enumerate(links.MTAB_TARGETS):
            if link.is_symlink():link.unlink()
            link.symlink_to(target);work=self.base/('variant-'+str(index))
            with aux_copy.copied_root(self.source,work,limits=self.limits()) as (root,report):
                self.assertEqual(os.readlink(root/'etc/mtab'),target)
                self.assertEqual(report['copy']['selected_link_variant']['observed_target'],target)
                self.assertFalse(report['copy']['selected_link_variant']['target_followed'])
                observation=aux.roots.observe(root,limits=self.limits(),hardlinks='generic-development-internal')
                with self.assertRaises(ValueError):aux.Reader(root,observation,self.limits()).resolve('etc/mtab')
                with self.assertRaises(ValueError):aux.Reader(root,observation,self.limits()).capture('etc/mtab/child')
            self.assertEqual(report['cleanup'],'PASS-owned-workspace-removed')
            self.assertEqual(os.readlink(link),target)

    def test_switch_between_two_allowed_variants_still_fails_exact_copy(self):
        (self.source/'etc/mtab').symlink_to('/proc/mounts')
        work=self.base/'changed-variant';binding=aux_copy._copy_binding(self.limits());observed=binding.roots.observe
        def changed(path,**kwargs):
            if Path(path)==work/'root':
                link=Path(path)/'etc/mtab';link.unlink();link.symlink_to('/proc/self/mounts')
            return observed(path,**kwargs)
        binding.roots.observe=changed
        with patch.object(aux_copy,'_copy_binding',return_value=binding):
            with self.assertRaisesRegex(ValueError,'copy destination nodes differ'):
                with aux_copy.copied_root(self.source,work,limits=self.limits()):self.fail('must not yield')
        self.assertFalse(work.exists());self.assertEqual(os.readlink(self.source/'etc/mtab'),'/proc/mounts')

    def test_unselected_proc_spelling_fails_before_target_allocation(self):
        (self.source/'etc/mtab').symlink_to('/proc/1/mounts');work=self.base/'unselected-variant'
        with self.assertRaisesRegex(ValueError,'selected-literal-link-drift'):
            with aux_copy.copied_root(self.source,work,limits=self.limits()):self.fail('must not yield')
        self.assertFalse(work.exists())

if __name__=='__main__':unittest.main()
