#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source portability only: models do not authenticate archives or run actors."""
from contextlib import contextmanager
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/'scripts/platform/metadata_gated_ext4.py'

def loaded(path):
    module=types.ModuleType('_portable_gate_test');module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module

bridge=loaded(PATH)


class PortableMetadataEncoder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=ROOT/'.portable-encoder-test-work';cls.work.mkdir(mode=0o700)
    @classmethod
    def tearDownClass(cls):cls.work.rmdir()

    def test_relative_current_canonical_graph_imports_without_actors_or_evidence(self):
        modules=bridge.sources()
        self.assertEqual(set(modules),{'intake','verifier','metadata','encoder','reader','owned_process'})
        self.assertEqual(modules['intake'].BUNDLE_SHA,'8c3838da1bfd6d5e7683d3634ffec9d14a5ff6b07966b15c2b06dde5319c4f0d')
        self.assertTrue(all(Path(m.__file__).parent==PATH.parent for k,m in modules.items() if k!='owned_process'))
        self.assertEqual(Path(modules['owned_process'].__file__),ROOT/'scripts/virtual/owned_process.py')
        self.assertNotIn('artifacts/',PATH.read_text())
        self.assertNotIn('base_bridge',PATH.read_text())
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            with modules['intake'].runtime(parent) as engine:
                self.assertEqual(engine.PROFILE,'retained-two-historical-signatures-v1')
            self.assertEqual(list(Path(parent).iterdir()),[])

    def test_changed_relative_helper_source_refuses_before_import(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            d=Path(parent)/'source/scripts/platform';d.mkdir(parents=True)
            for _,(name,_) in bridge.SOURCE_PINS.items():
                target=d.parents[1]/name if name.startswith('scripts/') else d/name
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(bridge.source_path(name),target)
            leaf=d/'archive_inode_metadata.py';leaf.write_bytes(leaf.read_bytes()+b'\n# altered\n')
            with patch.object(bridge,'BASE',d),self.assertRaisesRegex(ValueError,'pin'):bridge.sources()

    def test_source_symlink_and_hardlink_refusals(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            d=Path(parent);source=d/'source';source.write_bytes(b'text')
            link=d/'alias';link.symlink_to(source)
            with self.assertRaisesRegex(ValueError,'symlink'):bridge.pinned(link,bridge.sha(b'text'))
            import os
            link.unlink();os.link(source,link)
            with self.assertRaisesRegex(ValueError,'ordinary'):bridge.pinned(source,bridge.sha(b'text'))

    def selection(self):
        return {'packages':[dict(identity=dict(name=name,version=version,arch='aarch64'),archive={},signature={})
                            for name,version in (('networkmanager','1.58.1-1'),('perl','5.42.2-2'))]}

    def test_readback_uses_already_pinned_reader_module(self):
        modules=bridge.sources();marker={'model':'pinned-reader-used'}
        with patch.object(modules['reader'],'read_inventory',return_value=marker) as read:
            self.assertIs(modules['encoder'].readback(Path('model-image')),marker)
        read.assert_called_once_with(Path('model-image'),max_file_bytes=modules['encoder'].MAX_BYTES,
                                     max_nodes=modules['encoder'].MAX_NODES+1)

    def test_one_package_never_receives_two_package_status(self):
        selection=self.selection();selection['packages'].pop()
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            out=Path(parent)/'not-created'
            with (patch.object(bridge,'sources',side_effect=AssertionError('source/native dispatch')),
                  self.assertRaisesRegex(ValueError,'exact-two')):
                bridge.run(selection,{}, {}, {}, {},out)
            self.assertFalse(out.exists())

    def fixture(self,out,events,reject=False):
        manifest={'output_nodes':{},'output_ownership':{}}
        body=bridge.encoded(manifest)
        class Intake:
            BUNDLE_SHA='bundle';ENGINE_SHA='engine'
            decode=staticmethod(json.loads)
            def run(self,selection,authentication,directory,epoch,seconds):
                events.append('canonical-portable-intake');directory.mkdir()
                (directory/'assembly.json').write_bytes(body)
                return dict(manifest_sha256=bridge.sha(body),portable_source_inputs=dict(
                    entrypoint_sha256=bridge.SOURCE_PINS['intake'][1],graph_manifest_sha256='bundle',engine_sha256='engine'))
        class Verify:
            def verify(self,directory):events.append('verified-staging');return {'modeled':True}
        class Meta:
            def pins(self,configuration):return {'schema_version':2,'configuration':configuration,'model':True}
            def complete(self,reference,pins):
                events.append('direct-metadata')
                if reject:raise ValueError('model-required-metadata-refusal')
                return {'members':[]}
            def join_metadata(self,manifest,reports,policy):events.append('inode-joins');return {'model':True},{'model':True}
        class Encoder:
            def tool_pins(self,configuration):return {'schema_version':2,'configuration':configuration,'model':True}
            def encode(self,manifest,bodies,metadata,pins,directory):
                events.append('package-image');return dict(image={'model':True},status='MODEL_NO_ACTOR')
            def readback(self,path):return {'nodes':{}}
        return dict(intake=Intake(),verifier=Verify(),metadata=Meta(),encoder=Encoder())

    def test_model_sequence_requires_direct_metadata_before_any_image(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            out=Path(parent);events=[];modules=self.fixture(out,events)
            def proof(*args):events.append('generated-root-proof');return {'model':True}
            def bodies(*args):events.append('verified-bodies');return {}
            with patch.object(bridge,'root_proof',proof),patch.object(bridge,'bundle_bodies',bodies):
                answer=bridge._pipeline(modules,self.selection(),
                    {},{'schema_version':2,'configuration':{'model':True},'model':True},
                    {'schema_version':2,'configuration':{'model':True},'model':True},{},out,1700000000)
            self.assertEqual(events,['canonical-portable-intake','verified-staging','direct-metadata','direct-metadata','inode-joins',
                                     'generated-root-proof','verified-bodies','package-image'])
            self.assertFalse(answer['direct_metadata']['generic_empty_inference_used'])
            self.assertFalse(any(answer['acceptance'].values()))
            self.assertEqual(answer['filesystem']['status'],'MODEL_NO_ACTOR')

    def test_model_rejected_metadata_never_reaches_root_or_image(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            out=Path(parent);events=[];modules=self.fixture(out,events,reject=True)
            with patch.object(bridge,'root_proof',side_effect=AssertionError('root dispatched')),self.assertRaisesRegex(ValueError,'metadata-refusal'):
                bridge._pipeline(modules,self.selection(),
                    {},{'schema_version':2,'configuration':{'model':True},'model':True},
                    {'schema_version':2,'configuration':{'model':True},'model':True},{},out,1700000000)
            self.assertNotIn('package-image',events)
            self.assertNotIn('generated-root-proof',events)

    def test_model_portable_source_pin_mismatch_stops_before_metadata(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            out=Path(parent);events=[];modules=self.fixture(out,events)
            modules['intake'].BUNDLE_SHA='changed'
            with self.assertRaisesRegex(ValueError,'portable-intake-source'):bridge._pipeline(modules,
                self.selection(),{},{'schema_version':2,'configuration':{'model':True},'model':True},
                    {'schema_version':2,'configuration':{'model':True},'model':True},{},out,1700000000)
            self.assertNotIn('direct-metadata',events)

    def test_existing_output_is_preserved_and_failed_model_cannot_publish(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            out=Path(parent)/'output';out.mkdir();(out/'marker').write_bytes(b'keep')
            with patch.object(bridge,'sources',return_value={}),self.assertRaises(FileExistsError):bridge.run(self.selection(), {}, {}, {}, {},out)
            self.assertEqual((out/'marker').read_bytes(),b'keep')
            failed=Path(parent)/'failed'
            with (patch.object(bridge,'sources',return_value={}),
                  patch.object(bridge,'_pipeline',side_effect=ValueError('model-failure')),
                  self.assertRaisesRegex(ValueError,'model-failure')):
                bridge.run(self.selection(), {}, {}, {}, {},failed)
            self.assertFalse((failed/'receipt.json').exists());self.assertTrue((failed/'failure.json').is_file())

    def test_source_drift_prevents_final_pass_commit(self):
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            out=Path(parent)/'failed-drift'
            with (patch.object(bridge,'sources',return_value={}),
                  patch.object(bridge,'_pipeline',return_value={'modeled':True}),
                  patch.object(bridge,'check_sources',side_effect=ValueError('source-drift-control')),
                  self.assertRaisesRegex(ValueError,'source-drift')):
                bridge.run(self.selection(),{}, {}, {}, {},out)
            self.assertFalse((out/'receipt.json').exists())
            self.assertTrue((out/'INCOMPLETE.json').exists())

    def test_host_profiles_are_explicit_and_not_arch_defaults(self):
        modules=bridge.sources();metadata=modules['metadata'];encoder=modules['encoder']
        configuration=dict(interface=metadata.SUPPORTED_INTERFACE,library='/host/lib/libarchive.so.13',
                           ldd='/host/bin/ldd',headers=[])
        self.assertEqual(metadata.validate_configuration(configuration),configuration)
        with self.assertRaises(ValueError):metadata.validate_configuration(None)
        bad=copy.deepcopy(configuration);bad['library']='relative/libarchive'
        with self.assertRaises(ValueError):metadata.validate_configuration(bad)
        self.assertNotIn('/usr/lib/libarchive.so.13.8.9',(PATH.parent/'archive_inode_metadata.py').read_text())
        tools=dict(interface=encoder.TOOL_INTERFACE,ldd='/host/bin/ldd',
                   tools={name:'/host/sbin/'+name for name in encoder.TOOL_NAMES})
        self.assertEqual(encoder.validate_tool_configuration(tools),tools)
        with self.assertRaises(ValueError):encoder.validate_tool_configuration({'tools':{}})
        with self.assertRaisesRegex(ValueError,'profile-v2'):
            metadata.Native({'schema_version':1,'library_sha256':'old-arch-hash'})

    def test_checked_configuration_bytes_are_not_reopened_for_profile_capture(self):
        encoder=bridge.sources()['encoder']
        checked={'interface':'model-checked'}
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            directory=Path(parent);configuration=directory/'configuration.json'
            raw=bridge.encoded(checked);configuration.write_bytes(raw)
            args=['encoder','pin-tools','--output',str(directory/'pins.json'),'--configuration',str(configuration),
                  '--configuration-sha256',bridge.sha(raw),'--actor-directory',str(directory/'actors')]
            import sys
            with (patch.object(sys,'argv',args),
                  patch.object(encoder,'load_json',side_effect=AssertionError('unchecked second read')),
                  patch.object(encoder,'tool_pins',side_effect=lambda selected:{'modeled':selected})):
                encoder.main()
            self.assertEqual(json.loads((directory/'pins.json').read_bytes()),{'modeled':checked})
            configuration.write_bytes(bridge.encoded({'interface':'replacement'}))
            with self.assertRaisesRegex(ValueError,'configuration-pin'):
                encoder.read_configuration(configuration,bridge.sha(raw))

    def test_incomplete_dependency_closure_and_loader_overrides_refuse(self):
        modules=bridge.sources();metadata=modules['metadata'];encoder=modules['encoder']
        config=dict(interface=metadata.SUPPORTED_INTERFACE,library='/host/lib/libarchive.so.13',ldd='/host/bin/ldd',headers=[])
        import os
        with (patch.dict(os.environ,{'LD_PRELOAD':'modeled-override'},clear=True),
              patch.object(metadata,'RUN_COMMAND',side_effect=AssertionError('probe after invalid environment')),
              self.assertRaisesRegex(ValueError,'loader-override')):
            metadata.pins(config)
        output=types.SimpleNamespace(stdout=b'libfoo.so => not found\n',stderr=b'')
        with (patch.dict(os.environ,{},clear=True),patch.object(metadata,'RUN_COMMAND',return_value=output),
              patch.object(metadata.C,'CDLL',side_effect=AssertionError('library after missing dependency')),
              self.assertRaisesRegex(ValueError,'closure-incomplete')):
            metadata.pins(config)
        tools=dict(interface=encoder.TOOL_INTERFACE,ldd='/host/bin/ldd',tools={name:'/host/sbin/'+name for name in encoder.TOOL_NAMES})
        def response(command,**kwargs):
            if command[0]==tools['ldd']:return output
            return types.SimpleNamespace(stdout=b'mke2fs 1.99 modeled\n',stderr=b'')
        with (patch.object(encoder,'file_hash',return_value='modeled'),
              patch.object(encoder,'run_command',side_effect=response),
              self.assertRaisesRegex(ValueError,'closure-incomplete')):
            encoder.tool_pins(tools)

    def test_host_component_checker_defaults_to_not_run_without_dispatch(self):
        checker=loaded(ROOT/'tests/platform/check_host_components.py')
        import sys
        stream=io.StringIO()
        from contextlib import redirect_stdout
        with (patch.object(sys,'argv',['check_host_components']),
              patch.object(checker,'loaded',side_effect=AssertionError('native source load')),
              redirect_stdout(stream)):
            checker.main()
        self.assertEqual(json.loads(stream.getvalue())['status'],'NOT_RUN')


if __name__=='__main__':unittest.main(verbosity=2)
