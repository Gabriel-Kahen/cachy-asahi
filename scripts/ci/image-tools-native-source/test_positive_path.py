#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Positive fabricated lifecycle DATA through real projection/capsule/reader."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
OVERRIDE=os.environ['IMAGE_TOOLS_NATIVE_SOURCE']
OLD=Path(OVERRIDE).resolve()
PARENT=Path(os.environ.get('IMAGE_TOOLS_PARENT',str(OLD))).resolve()
# Authenticate the complete emitted Source before loading any producer code.
factory_spec=importlib.util.spec_from_file_location('positive_source_factory',HERE/'prepare.py')
factory=importlib.util.module_from_spec(factory_spec);factory_spec.loader.exec_module(factory)
profile=factory.profile();source_rows,source_bodies=factory.snapshot(OLD)
assert source_rows==profile['expected']['files']
assert factory.tree_id(source_bodies,{n:r['mode'] for n,r in source_rows.items()})==profile['expected']['tree']
sys.path[:0]=[str(OLD/'native'),str(HERE)]
PINS={'image_reader_v1':'b6a0a4cfc0470061778249a53a62d4f4abf476923cfa577d5e04483508a2eb64','image_projection_v1':'75ab8e5468cdd48b96f7bf66c1ceef64b1d108d2e3c18593d61ce4bec5e7671e'}
def audit(event,args):
    if event.startswith(('subprocess.','socket.')) or event in ('os.fork','os.forkpty','os.posix_spawn','os.kill','os.killpg'):raise AssertionError('SOURCE_ONLY_ACTOR_BAN:'+event)
sys.addaudithook(audit)
def module(name,path=None):
    path=path or OLD/'native'/(name+'.py');raw=path.read_bytes()
    if name in PINS and OVERRIDE is None:assert hashlib.sha256(raw).hexdigest()==PINS[name],name
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
R=module('image_reader_v1');P=module('image_projection_v1')
from positive_fixture import fixture,encoded,pin,PREFIX
class Positive(unittest.TestCase):
    def traverse(self,mutate=None):
        data,guest,binding=fixture(R)
        if mutate is not None:
            mutate(data,guest)
            report=guest['image_alpm']
            data[PREFIX+'result.json']=encoded(report);data['journey/result.json']=encoded(guest)
        with tempfile.TemporaryDirectory(prefix='image-positive-DATA-') as tmp:
            root=Path(tmp);public=root/'public';public.mkdir(mode=0o700)
            for name,raw in data.items():
                path=public/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(raw);path.chmod(0o600)
            projection=P.project(OLD,public,root/'projected')
            capsule=root/'public-tree.tar';P.C.pack(root/'projected',capsule);view=P.C.open_capsule(capsule);manifest=view.load('artifacts.json');view.verify_manifest(manifest)
            R.retained_public_projection(view,manifest['files'],binding,'a'*64)
            result=R.retained_image_alpm(view,manifest['files'],guest,'a'*64)
            self.assertEqual(result['status'],'MATCHED_NATIVE_IMAGE_TOOLS_ALPM_COMPONENT_DATA_ONLY')
            self.assertEqual(result['native'],'NOT_ADMITTED');self.assertEqual(result['physical_M2'],'NOT_RUN')
            self.assertEqual(projection['omitted_private_trees_walked'],False)
            self.assertEqual(result['raw_image_nodes'],8)
            return result
    def test_full_positive_component_projection_capsule_path(self):
        self.traverse()
    def test_rebound_restoration_false_refuses(self):
        def mutate(data,guest):guest['image_alpm']['restore']['alpm_db']['unchanged']=False
        with self.assertRaisesRegex(ValueError,'exact DB/home/trust/config/cache restoration'):self.traverse(mutate)
    def test_rebound_inner_reaping_false_refuses(self):
        def mutate(data,guest):
            leaf='diagnostics/system/control-commands/02-assemble.json'
            value=json.loads(data[PREFIX+leaf]);value['supervision']['reaped']=False;data[PREFIX+leaf]=encoded(value)
            guest['image_alpm']['diagnostic_files'][leaf]=pin(data[PREFIX+leaf])
        with self.assertRaisesRegex(ValueError,'actual installed CLI inner owned/raw evidence'):self.traverse(mutate)
if __name__=='__main__':unittest.main(verbosity=2)

