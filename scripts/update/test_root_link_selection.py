#!/usr/bin/env python3
"""Finite production-table controls with inert node maps, not actual roots."""
import importlib.util
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).absolute().parent
REPO=next(parent for parent in HERE.parents if (parent/'scripts/update/full_root.py').is_file())
CANDIDATE=HERE/'proposed/scripts/update' if (HERE/'proposed/scripts/update').is_dir() else HERE
sys.path[:0]=[str(CANDIDATE),str(REPO/'scripts/update')]
import root_link_selection as links
import full_root as roots
import aux_checkpoint as aux
import linked_runtime
import root_path

class Policy(unittest.TestCase):
    def limits(self):return roots.Limits(deadline=time.monotonic()+20,max_nodes=1000,max_bytes=64*1024**2,max_file_bytes=8*1024**2)
    def observation(self,target='/proc/self/mounts'):
        nodes={}
        def parents(name):
            parts=name.split('/')
            for index in range(1,len(parts)):nodes.setdefault('/'.join(parts[:index]),dict(type='directory',mode=0o755,uid=0,gid=0))
        for name,node in links.LINK_NODES.items():parents(name);nodes[name]=dict(node)
        for endpoint in links.RESOLVED_ENDPOINTS.values():
            parents(endpoint)
            nodes.setdefault(endpoint,dict(type='directory',mode=0o755,uid=0,gid=0) if endpoint in ('usr/share/xkeyboard-config-2','usr/share/licenses/qt6-base') else dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='a'*64))
        # Retained keyutils MTREE chain has this ordinary relative intermediary.
        nodes['usr/lib/libkeyutils.so.1']=dict(type='symlink',mode=0o777,uid=0,gid=0,target='libkeyutils.so.1.10')
        nodes['etc/mtab']['target']=target
        return dict(complete=True,eligible=False,nodes=nodes,footprint={},unsupported_counts={'absolute-symlink':87,'auxiliary-present':3},hardlink_groups={})
    def check(self,value):return links.check(value,self.limits())

    def test_full_measured_set_and_source_partition(self):
        import hashlib
        # Frozen independently from retained actual38854181785's complete87 list.
        measured='29e3696affcb565286672dffa03e5f1dfc7549be2bb2ec23ffc9c057c853bbf2'
        self.assertEqual(hashlib.sha256(('\n'.join(links.CHAIN_PATHS)+'\n').encode()).hexdigest(),measured)
        self.assertEqual(len(links.LINK_NODES),87);self.assertEqual(len(links.RESOLVED_ENDPOINTS),45);self.assertEqual(len(links.DATA_ONLY_ENDPOINTS),42)
        self.assertEqual(sum(name.startswith('builder-disabled-hooks/') for name in links.LINK_NODES),41)
        self.assertEqual(sum(name.startswith('etc/systemd/') for name in links.LINK_NODES),20)


    def test_only_two_mtab_spellings_and_exact_metadata(self):
        for target in ('/proc/mounts','/proc/self/mounts'):
            value=self.observation(target);self.assertEqual(self.check(value),value['nodes'])
            self.assertEqual(links.protection_endpoint(value['nodes'],'etc/mtab',self.limits()),target.lstrip('/'))
            report=links.variant_report(value['nodes']);self.assertEqual(report['observed_target'],target)
            self.assertFalse(report['target_followed']);self.assertFalse(report['prior_actual_literal_exported'])
        for target in ('/proc/1/mounts','/proc/self/mountinfo','/proc/../etc/passwd','../proc/self/mounts','/dev/null'):
            with self.subTest(target=target),self.assertRaises(ValueError):self.check(self.observation(target))
        for key,value in (('uid',1),('gid',1),('mode',0o700),('type','file')):
            observation=self.observation();observation['nodes']['etc/mtab'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.check(observation)

    def test_other86_have_no_compatibility_alternatives(self):
        for name in links.CHAIN_PATHS:
            if name=='etc/mtab':continue
            value=self.observation();value['nodes'][name]['target']='/proc/mounts'
            with self.subTest(name=name),self.assertRaises(ValueError):self.check(value)

    def test_extra_missing_and_changed_endpoint_refused(self):
        value=self.observation();value['nodes']['extra-link']=dict(type='symlink',uid=0,gid=0,mode=0o777,target='/usr/bin/c++')
        value['unsupported_counts']['absolute-symlink']+=1
        with self.assertRaises(ValueError):self.check(value)
        value=self.observation();value['nodes'].pop(links.CHAIN_PATHS[0])
        with self.assertRaises(ValueError):self.check(value)
        value=self.observation();endpoint=next(iter(links.RESOLVED_ENDPOINTS.values()));value['nodes'].pop(endpoint)
        with self.assertRaises(ValueError):self.check(value)

    def test_data_endpoint_appearance_or_parent_file_refused(self):
        for target in links.MTAB_TARGETS:
            value=self.observation(target);value['nodes']['proc']=dict(type='directory',mode=0o755,uid=0,gid=0)
            if target=='/proc/self/mounts':value['nodes']['proc/self']=dict(type='directory',mode=0o755,uid=0,gid=0)
            value['nodes'][target.lstrip('/')]=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='a'*64)
            with self.assertRaises(ValueError):self.check(value)
        value=self.observation();value['nodes']['proc']=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='a'*64)
        with self.assertRaises(ValueError):self.check(value)

    def test_data_names_grant_no_reader_or_node_parent_access(self):
        value=self.observation('/proc/mounts');self.check(value)
        self.assertEqual(links.protection_endpoint(value['nodes'],'etc/mtab',self.limits()),'proc/mounts')
        with self.assertRaises(ValueError):root_path.resolve(value['nodes'],'etc/mtab',limits=self.limits())
        with self.assertRaises(ValueError):root_path.resolve(value['nodes'],'etc/mtab/child',limits=self.limits())

    def test_projection_keeps_selected_raw_variant_and_drift_fails_after_commit(self):
        first=self.observation('/proc/mounts')
        first['nodes']['usr/bin/ldconfig']=dict(type='file',uid=0,gid=0,mode=0o755,bytes=1,sha256='b'*64)
        raw=links.restore_literals(links.view(first,self.limits())['nodes'],first['nodes'])
        self.assertEqual(raw['etc/mtab']['target'],'/proc/mounts')
        changed=self.observation('/proc/self/mounts');changed['nodes']['usr/bin/ldconfig']=first['nodes']['usr/bin/ldconfig'];self.check(changed)
        self.assertNotEqual(first['nodes']['etc/mtab'],changed['nodes']['etc/mtab'])
        instance=linked_runtime.Runtime.__new__(linked_runtime.Runtime)
        instance.root=Path('/inert/root');instance.root_limits=self.limits();instance.footprints=[];instance.old_paths=set();instance.database_changes=()
        instance.baseline=first;instance.projected=first['nodes'];instance.commit_ready=True;instance.comparator=object()
        instance.aux_precommit={};instance.auxiliary_checks=[]
        with patch.object(roots,'observe',return_value=changed),patch.object(aux,'checkpoint',return_value={}), \
             patch.object(aux,'live_keys',return_value={}),patch.object(aux,'compare',return_value={}):
            with self.assertRaisesRegex(ValueError,'unrelated-root-content'):instance.tree(instance.root)

if __name__=='__main__':unittest.main()
