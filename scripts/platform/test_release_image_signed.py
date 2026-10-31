#!/usr/bin/env python3
"""Recipe hook controls only; native image/GPG actors are forbidden."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import time
import stat
import types
import unittest
from unittest.mock import patch

path=Path(__file__).resolve().with_name('release_image.py')
release=types.ModuleType('_signed_recipe_hook');release.__file__=str(path)
exec(compile(path.read_bytes(),str(path),'exec'),release.__dict__)

class SignedHook(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='signed-hook-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.selection=dict(schema_version=1,scope='EXACT_LOCAL_SIGNED_ARCHIVE_SELECTION_V1',release_set=None,packages=[])
        for i in range(5):
            identity=dict(name='fixture-'+str(i),version='1-1',arch='any')
            refs={name:dict(path='/UNOPENED/fixture-'+str(i)+'.'+name,size=1,sha256='a'*64,
                identity=[1,i+1,stat.S_IFREG|0o600,1,0,0,1,0,0])for name in ('archive','signature')}
            self.selection['packages'].append(dict(identity=identity,**refs,primary_fingerprint='A'*40,
                metadata=dict(identity,depends=[],provides=[],conflicts=[],replaces=[],license=['MIT'])))
        now=int(time.time())
        self.policy=dict(schema_version=1,profile='operator-policy-offline-signed-pristine-v1',
            selection_sha256=release.sha(release.encoded(self.selection)),release_set=None,issued=now-60,expires=now+3600,
            signers=[dict(primary='A'*40,signature_not_before=1,not_after=now+3600)])
        for name in ('gpg','public_keyring','trusted','revoked'):
            self.policy[name]=dict(path='/UNOPENED/'+name,bytes=1,sha256='a'*64)
        self.recipe=dict(schema_version=1,kind=release.SIGNED_KIND,epoch=1700000000,inputs={})
        for name,value in dict(selection=self.selection,authentication=self.policy,tool_pins={'schema_version':2},
            metadata_pins={'schema_version':2},root_policy=dict(mode=493,uid=0,gid=0,acl=None,xattrs={})).items():
            raw=release.encoded(value);target=self.root/(name+'.json');target.write_bytes(raw)
            self.recipe['inputs'][name]=dict(path=str(target),sha256=release.sha(raw))
        self.recipe_path=self.root/'recipe.json';self.save()
        guard=patch.object(subprocess,'Popen',side_effect=AssertionError('hook test actor forbidden'));guard.start();self.addCleanup(guard.stop)
    def save(self):
        raw=release.encoded(self.recipe);self.recipe_path.write_bytes(raw);self.digest=release.sha(raw)
    def test_new_profile_plan_loads_five_packages_without_actor(self):
        result=release.plan(self.recipe_path,self.digest)
        self.assertEqual(result['binding']['sources']['signed_archive_intake']['sha256'],release.SIGNED_SHA)
        self.assertIn('NO_ARCHIVE_OR_NATIVE_ACTOR',result['status'])
    def test_policy_pin_refusal_before_image_dispatch(self):
        self.policy['selection_sha256']='0'*64
        raw=release.encoded(self.policy);target=self.root/'authentication.json';target.write_bytes(raw)
        self.recipe['inputs']['authentication']['sha256']=release.sha(raw);self.save()
        with self.assertRaisesRegex(ValueError,'policy-selection-binding'):release.plan(self.recipe_path,self.digest)
    def test_legacy_profile_keeps_exact_two_guard(self):
        self.recipe['kind']=release.KIND;self.save()
        with self.assertRaisesRegex(ValueError,'exact-two-selection'):release.plan(self.recipe_path,self.digest)
    def test_parent_accepts_only_new_profile_result_and_seals_it(self):
        original=release.load_signed_services
        image=dict(bytes=5,sha256=release.sha(b'DATA!'),uuid='model-only')
        for status in ('PASS_POLICY_SIGNED_DIRECT_METADATA_GATED_EXT4','PASS_EXACT_TWO_DIRECT_METADATA_GATED_EXT4'):
            def services(selection,policy):
                bridge,modules=original(selection,policy)
                def model(*args):
                    output=args[-2];output.mkdir(mode=0o700)
                    (output/'receipt.json').write_bytes(release.encoded(dict(status='MODEL_ONLY')))
                    return dict(status=status,acceptance={'release':False},filesystem={'image':copy.deepcopy(image)})
                bridge.run=model;return bridge,modules
            output=self.root/('new'if status.startswith('PASS_POLICY')else'wrong')
            with patch.object(release,'load_signed_services',side_effect=services),patch.object(release,'readback',return_value=image):
                if status.startswith('PASS_POLICY'):
                    result=release.run(self.recipe_path,self.digest,output)
                    self.assertEqual(result['status'],'PASS_RECIPE_BOUND_PRISTINE_PAYLOAD_IMAGE')
                else:
                    with self.assertRaisesRegex(ValueError,'pipeline-result-boundary'):release.run(self.recipe_path,self.digest,output)
                    self.assertTrue((output/'INCOMPLETE.json').exists())

if __name__=='__main__':unittest.main(verbosity=2)
