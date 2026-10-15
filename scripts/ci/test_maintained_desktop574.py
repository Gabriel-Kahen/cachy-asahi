#!/usr/bin/env python3
"""Focused mocked finished-image/probe ownership checks; no external actors."""
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned574',HERE/'maintained_desktop574.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
TOKEN='a'*16
IMAGE='sha256:'+'1'*64
OLD='sha256:'+'2'*64
CID='c'*64
TAG,NAME=h.owner_names(TOKEN)


class Daemon:
    def __init__(self):
        self.images={IMAGE:{'Id':IMAGE,'Architecture':'arm64','Os':'linux',
            'Config':{'Labels':{h.OWNER_LABEL:TOKEN}},'RepoTags':[TAG],'RepoDigests':[]}}
        self.containers={}
        self.queries=[];self.mutations=[]

    def probe(self):
        self.containers[CID]={'Id':CID,'Name':'/'+NAME,'Image':IMAGE,'Config':{'Labels':{h.OWNER_LABEL:TOKEN}}}

    def __call__(self,*args):
        self.queries.append(args)
        if args[:2]==('image','ls'):
            rows=list(self.images)
            if '--filter' in args:
                value=args[args.index('--filter')+1]
                if value.startswith('reference='):
                    rows=[k for k in rows if value[10:] in self.images[k]['RepoTags']]
                elif value.startswith('label='):
                    key,value=value[6:].split('=',1)
                    rows=[k for k in rows if self.images[k]['Config'].get('Labels',{}).get(key)==value]
                else:raise AssertionError(args)
            return '\n'.join(rows)
        if args[:2]==('image','inspect'):
            return json.dumps([self.images[args[2]]])
        if args[:2]==('container','inspect'):
            return json.dumps([next(v for v in self.containers.values() if v['Name']=='/'+args[2])])
        if args[:2]==('container','ls'):
            value=args[args.index('--filter')+1]
            if value.startswith('name=^/'):
                rows=[v for v in self.containers.values() if v['Name']==value[6:-1]]
            elif value.startswith('id='):rows=[v for k,v in self.containers.items() if k==value[3:]]
            elif value.startswith('ancestor='):rows=[v for v in self.containers.values() if v['Image']==value[9:]]
            else:raise AssertionError(args)
            return '\n'.join(v['Id'] if args[-1]=='{{.ID}}' else v['Name'][1:] for v in rows)
        raise AssertionError(args)

    def run(self,argv,**kwargs):
        self.mutations.append(argv)
        if argv==['/usr/bin/docker','rm','-f',CID]:self.containers.pop(CID)
        elif argv==['/usr/bin/docker','image','rm','--no-prune',IMAGE]:self.images.pop(IMAGE)
        else:raise AssertionError(argv)
        return SimpleNamespace(returncode=0)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.daemon=Daemon()
        self.owner=dict(token=TOKEN,image_tag=TAG,probe_name=NAME,probe_cidfile='probe-cid',
            before_images=[],build_started=True,build_complete=True,probe_started=True,probe_complete=True,image=IMAGE)
        self.report={'ownership':self.owner,'build_returncode':0}
        (self.root/'image-id').write_text(IMAGE)
        (self.root/'probe-cid').write_text(CID)

    def retire(self):
        with patch.object(h,'docker',side_effect=self.daemon),patch.object(h.subprocess,'run',side_effect=self.daemon.run):
            return h.retire_owned(self.root,TOKEN,self.report)

    def test_normal_finished_image_and_absent_probe_retire(self):
        result=self.retire()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(self.daemon.mutations,[['/usr/bin/docker','image','rm','--no-prune',IMAGE]])
        self.assertTrue(result['probe']['absence_verified']);self.assertTrue(result['image']['absence_verified'])

    def test_inflight_and_partial_build_states_never_query_daemon(self):
        for change in ({'build_complete':False},{'build_started':False},{'build_complete':None}):
            self.report['ownership']=dict(self.owner,**change)
            with patch.object(h,'docker') as query,patch.object(h.subprocess,'run') as mutate:
                self.assertEqual(h.retire_owned(self.root,TOKEN,self.report)['status'],'FAIL')
                query.assert_not_called();mutate.assert_not_called()
        self.report.pop('ownership')
        with patch.object(h,'docker') as query:
            self.assertEqual(h.retire_owned(self.root,TOKEN,self.report)['status'],'FAIL');query.assert_not_called()

    def test_finished_output_recovers_from_tag_without_iid(self):
        (self.root/'image-id').unlink();(self.root/'probe-cid').unlink()
        self.owner.pop('image');self.owner.update(probe_started=False,probe_complete=False)
        self.assertEqual(self.retire()['status'],'PASS')

    def test_known_probe_after_interruption_uses_exact_cid(self):
        self.daemon.probe();self.owner['probe_complete']=False
        result=self.retire();self.assertEqual(result['status'],'PASS')
        self.assertEqual(self.daemon.mutations[0],['/usr/bin/docker','rm','-f',CID])
        self.assertFalse(self.daemon.containers)

    def test_probe_name_recovers_missing_cidfile(self):
        self.daemon.probe();(self.root/'probe-cid').unlink();self.owner['probe_complete']=False
        self.assertEqual(self.retire()['status'],'PASS')
        self.assertEqual(self.daemon.mutations[0],['/usr/bin/docker','rm','-f',CID])

    def test_unknown_probe_creation_preserves_finished_image(self):
        (self.root/'probe-cid').unlink();self.owner['probe_complete']=False
        result=self.retire();self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['probe'],'UNKNOWN');self.assertEqual(self.daemon.mutations,[])
        self.assertIn(IMAGE,self.daemon.images)

    def test_baseline_even_if_dangling_is_never_removed(self):
        self.owner['before_images']=[IMAGE];self.daemon.images[IMAGE]['RepoTags']=[]
        result=self.retire();self.assertEqual(result['status'],'FAIL');self.assertEqual(self.daemon.mutations,[])
        self.assertIn(IMAGE,self.daemon.images)

    def test_tag_label_cid_and_foreign_reference_conflicts_refuse(self):
        original=copy.deepcopy(self.daemon.images[IMAGE])
        for field,value in [('Id',OLD),('RepoTags',[TAG,'foreign:keep']),('RepoDigests',['foreign@sha256:keep']),('Config',{'Labels':None})]:
            self.daemon.images[IMAGE]=dict(original,**{field:value})
            with self.subTest(field=field):
                self.assertEqual(self.retire()['status'],'FAIL');self.assertEqual(self.daemon.mutations,[])
        self.daemon.images[IMAGE]=original;self.daemon.probe();(self.root/'probe-cid').write_text('d'*64)
        self.assertEqual(self.retire()['status'],'FAIL');self.assertEqual(self.daemon.mutations,[])

    def test_foreign_container_is_not_removed_with_owned_probe(self):
        self.daemon.probe();foreign='e'*64
        self.daemon.containers[foreign]={'Id':foreign,'Name':'/foreign','Image':IMAGE}
        result=self.retire();self.assertEqual(result['status'],'FAIL')
        self.assertEqual(self.daemon.mutations,[['/usr/bin/docker','rm','-f',CID]])
        self.assertIn(foreign,self.daemon.containers);self.assertIn(IMAGE,self.daemon.images)

    def test_failed_absence_query_cannot_pass(self):
        def query(*args):
            if not self.daemon.images:raise subprocess.TimeoutExpired('mock-query',20)
            return self.daemon(*args)
        with patch.object(h,'docker',side_effect=query),patch.object(h.subprocess,'run',side_effect=self.daemon.run):
            self.assertEqual(h.retire_owned(self.root,TOKEN,self.report)['status'],'FAIL')

    def test_token_validation_and_collision_checks(self):
        for value in (None,'A'*16,'a'*15,'a/../b','a'*17):
            with self.subTest(value=value),self.assertRaises(ValueError):h.owner_names(value)
        (self.root/'image-id').unlink();(self.root/'probe-cid').unlink()
        with patch.object(h,'docker',side_effect=self.daemon),self.assertRaisesRegex(ValueError,'collision'):
            h.owner_begin(self.root,TOKEN)

    def test_live_helper_directory_lock_refuses_cleanup_without_queries(self):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,fd)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        argv=['helper','cleanup','--inputs',str(self.root/'input.json'),'--output',str(self.root),'--job-token',TOKEN]
        with patch.object(sys,'argv',argv),patch.object(h,'docker') as query,self.assertRaises(BlockingIOError):h.main()
        query.assert_not_called()

    def test_owned_rejections_preserve_existing_ownership_report(self):
        original=json.dumps(self.report).encode();(self.root/'report.json').write_bytes(original)
        (self.root/'input.json').write_text('{}')
        argv=['helper','build','--inputs',str(self.root/'input.json'),'--output',str(self.root),'--job-token',TOKEN]
        for architecture in ('x86_64','aarch64'):
            with self.subTest(architecture=architecture),patch.dict(h.os.environ,{},clear=True), \
                 patch.object(sys,'argv',argv),patch.object(h,'plan',return_value=[]), \
                 patch.object(h.platform,'system',return_value='Linux'),patch.object(h.platform,'machine',return_value=architecture), \
                 patch.object(h.subprocess,'check_output',return_value='aarch64'), \
                 patch.object(h.subprocess,'run') as mutate,patch.object(h,'docker') as query:
                self.assertEqual(h.main(),1)
                mutate.assert_not_called();query.assert_not_called()
            self.assertEqual((self.root/'report.json').read_bytes(),original)

    def main_fixture(self,owned):
        (self.root/'image-id').unlink();(self.root/'probe-cid').unlink()
        (self.root/'input.json').write_text('{}');(self.root/'context').mkdir();(self.root/'home').mkdir()
        (self.root/'context/expected-packages.lock').write_bytes(b'fixture\n')
        argv=['helper','build','--inputs',str(self.root/'input.json'),'--output',str(self.root)]
        if owned:argv+=['--job-token',TOKEN]
        commands=[]
        def build(argv,**kwargs):
            commands.append(argv);self.assertEqual(argv[:3],['/usr/bin/docker','build','--progress=plain'])
            if owned:
                state=json.loads((self.root/'report.json').read_text())['ownership']
                self.assertTrue(state['build_started']);self.assertFalse(state['build_complete'])
                self.assertIn(TAG,argv);self.assertIn(h.OWNER_LABEL+'='+TOKEN,argv)
            else:self.assertNotIn('--tag',argv)
            (self.root/'image-id').write_text(IMAGE);self.daemon=Daemon()
            return SimpleNamespace(returncode=0)
        def output(argv,**kwargs):
            if argv[1]=='info':return 'aarch64\n'
            commands.append(argv);self.assertEqual(argv[-2:],[IMAGE,'/builder-packages.lock'])
            if owned:
                state=json.loads((self.root/'report.json').read_text())['ownership']
                self.assertTrue(state['build_complete']);self.assertTrue(state['probe_started']);self.assertFalse(state['probe_complete'])
                self.assertEqual(state['probe_cidfile'],'probe-cid');self.assertIn(NAME,argv)
                self.assertEqual(argv[argv.index('--cidfile')+1],str(self.root/'probe-cid'))
                (self.root/'probe-cid').write_text(CID)
            else:self.assertNotIn('--name',argv);self.assertNotIn('--cidfile',argv)
            return b'fixture\n'
        self.daemon.images={}
        with patch.dict(h.os.environ,{'INHERITED':'MUST-NOT-LEAK'},clear=True),patch.object(sys,'argv',argv), \
             patch.object(h,'plan',return_value=[]),patch.object(h,'configure'), \
             patch.object(h.platform,'system',return_value='Linux'),patch.object(h.platform,'machine',return_value='aarch64'), \
             patch.object(h,'docker',side_effect=lambda *a:self.daemon(*a)), \
             patch.object(h.subprocess,'run',side_effect=build),patch.object(h.subprocess,'check_output',side_effect=output):
            self.assertEqual(h.main(),0)
        result=json.loads((self.root/'report.json').read_text());self.assertEqual(result['status'],'PASS_NATIVE_OFFLINE_574_TRANSACTION')
        self.assertEqual(len(commands),2)
        return result

    def test_default_path_keeps_legacy_commands_and_report(self):
        self.assertNotIn('ownership',self.main_fixture(False))

    def test_owned_path_persists_intent_before_mutations(self):
        result=self.main_fixture(True);self.assertTrue(result['ownership']['probe_complete'])
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,fd)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)


if __name__=='__main__':unittest.main()
