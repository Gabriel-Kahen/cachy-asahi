# SPDX-License-Identifier: MIT
"""Fenced successor DATA controls, never an actual Original Reader run."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
r=load('xs_v2_reader_controls',HERE/'reader.py')
a=load('xs_v2_adapter_controls',HERE/'adapters.py')
d=r.d


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('actor forbidden in v2 Reader controls: '+event)
sys.addaudithook(fence)


def modeled_binding():
    return dict(source='1'*40,ref='refs/heads/codex/MODELED_V2_NOT_ACTUAL',run='1',job='2',
                approval='3'*64,source_map_sha256=r.MAP,operation=a.OUTER)


class Controls(unittest.TestCase):
    def setUp(self):d.start()

    def test_missing_actual_bindings_refuse(self):
        with self.assertRaises(ValueError):r.binding(d.decode((HERE/'binding.TEMPLATE.json').read_bytes()))

    def test_old_source_and_wrong_outer_operation_refuse(self):
        for key,value in (('source',r.PARENT_SOURCE),('operation',a.INNER),('source_map_sha256','0'*64)):
            b=modeled_binding();b[key]=value
            envelope=dict(schema=1,binding=b,artifact=dict(id='4',bytes=1,sha256='5'*64,metadata_sha256='6'*64))
            with self.assertRaises(ValueError):r.binding(envelope)

    def test_projection_is_exact_and_does_not_change_external_binding(self):
        b=modeled_binding();before=dict(b);out=a.inner_binding(b,dict(operation=a.INNER),d)
        self.assertEqual(b,before);self.assertEqual(out,dict(b,operation=a.INNER))
        for outer,inner in ((a.INNER,a.INNER),(a.OUTER,a.OUTER)):
            with self.assertRaises(ValueError):a.inner_binding(dict(b,operation=outer),dict(operation=inner),d)

    def test_mode_map_mismatch_and_missing_operand_refuse(self):
        source=HERE.parents[1]/'hosted_source_v2'
        body=(source/'runtime-files.json').read_bytes();manifest=d.decode(body)
        inputs=dict(archive_sha256=manifest['archive']['sha256'],files=manifest['files'])
        preparation=dict(files=manifest['files'],runtime_manifest=a.MODE_PIN)
        class IO:
            need=staticmethod(d.need);pin=staticmethod(d.pin);decode=staticmethod(d.decode);tick=staticmethod(d.tick)
            read=staticmethod(lambda root,name,cap:body)
        def get(name):
            return (json.dumps(inputs if name.endswith('xs-inputs.json') else preparation)).encode()
        self.assertEqual(a.mode_map(get,'MODELED_SOURCE',IO)['files'],1870)
        inputs['files']=dict(inputs['files']);name=next(n for n,row in inputs['files'].items() if row['mode']==0o444)
        inputs['files'][name]=dict(inputs['files'][name],mode=0o644)
        with self.assertRaises(ValueError):a.mode_map(get,'MODELED_SOURCE',IO)
        with self.assertRaises(KeyError):a.mode_map(lambda name: (_ for _ in ()).throw(KeyError(name)),'MODELED_SOURCE',IO)

    def test_frozen_passive_module_substitution_refuses(self):
        class IO:
            need=staticmethod(d.need);pin=staticmethod(d.pin)
            read=staticmethod(lambda root,name,cap:b'SUBSTITUTED passive classifier DATA')
        with self.assertRaises(ValueError):a.passive('bootstrap.py','MODELED',IO)


if __name__=='__main__':unittest.main(verbosity=2)
