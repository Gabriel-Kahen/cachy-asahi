# SPDX-License-Identifier: MIT
"""Pure actor proof-path projection controls; no actor gate or candidate import."""
import importlib.util
import json
import tempfile
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
support_spec=importlib.util.spec_from_file_location('v7_test_support_DATA',HERE/'test_support.py');support=importlib.util.module_from_spec(support_spec);support_spec.loader.exec_module(support);PAYLOAD=support.assembled()
s=importlib.util.spec_from_file_location('v7_actor_projection_DATA',PAYLOAD/'actor/entry.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)


def fixture():
    row=lambda name:dict(path='/inputs/'+name,local_path='/FENCED/'+name,bytes=1,sha256='a'*64)
    return dict(FENCED='NOT_AN_ADMITTED_OPERATIONAL_FIXTURE',proofs=[row('proof-'+str(n)+'.json')for n in range(13)],authorization={k:row(name)for k,name in (('dispatch','dispatch-admission.json'),('provider','provider-binding.json'),('qualification','native-qualification.json'))},materials=[dict(name='FENCED-'+str(n),local_path='/FENCED/material')for n in range(5)])


class Controls(unittest.TestCase):
    def snapshot_fixture(self,root):
        spec=importlib.util.spec_from_file_location('FENCED_v7_binding',root/'notice_binding.py')
        binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)
        return dict(FENCED='NOT_A_ROOT_OPERATIONAL_ADMISSION',candidate=dict(notice_binding=binding.BINDING),
                    candidate_admission=dict(path='/inputs/candidate-admission.json',sha256='a'*64),
                    stage0_tree_sha256='b'*64,image=dict(id='FENCED_NO_IMAGE',rootfs_tree_sha256='c'*64,qualified_llvm_tree_sha256='d'*64),
                    image_root='/FENCED_NO_IMAGE_ROOT',materials=[],source=dict(map_sha256='e'*64))
    def test_producer_snapshot_copies_all_eleven_candidate_leaves_without_roles(self):
        root=support.assembled();value=self.snapshot_fixture(root)
        spec=importlib.util.spec_from_file_location('FENCED_v7_snapshot',root/'hosted/producer.py')
        producer=importlib.util.module_from_spec(spec);spec.loader.exec_module(producer)
        with tempfile.TemporaryDirectory(prefix='FENCED-v7-snapshot-') as directory:
            inputs=Path(directory);env=producer.snapshot(root,inputs,value)
            expected=json.loads((root/'candidate-map.json').read_bytes())['files']
            self.assertEqual({p.name for p in (inputs/'candidate').iterdir()},set(expected))
            self.assertEqual(len(expected),11)
            for name in expected:self.assertEqual((inputs/'candidate'/name).read_bytes(),(root/'packages/port/rust199-source-reference'/name).read_bytes())
            self.assertEqual(json.loads((inputs/'root-admission.json').read_bytes())['candidate']['notice_binding'],value['candidate']['notice_binding'])
            self.assertEqual(env['SOURCE_MAP_SHA256'],'e'*64)
    def test_missing_notice_file_stale_map_or_changed_binding_refuses_before_snapshot(self):
        for mutation in ('missing','old_count','binding'):
            root=support.assembled();value=self.snapshot_fixture(root)
            spec=importlib.util.spec_from_file_location('FENCED_v7_refused_snapshot',root/'hosted/producer.py')
            producer=importlib.util.module_from_spec(spec);spec.loader.exec_module(producer)
            if mutation=='missing':(root/'packages/port/rust199-source-reference/notice-catalogue.DATA.json').unlink()
            elif mutation=='old_count':
                raw=json.loads((root/'candidate-map.json').read_bytes());raw['files'].pop('notice_preservation.py');raw['files'].pop('notice-catalogue.DATA.json');(root/'candidate-map.json').write_bytes(producer.encode(raw))
            else:value['candidate']['notice_binding']=dict(value['candidate']['notice_binding'],tree='0'*40)
            with tempfile.TemporaryDirectory(prefix='FENCED-v7-refusal-') as directory:
                inputs=Path(directory)
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):producer.snapshot(root,inputs,value)
                self.assertFalse((inputs/'candidate').exists())
    def test_exact_sixteen_proofs_remap_including_three_authorization_files(self):
        value=fixture();result=a.actor_projection(value)
        rows=list(a.descriptors(result));self.assertEqual(len(rows),16)
        self.assertTrue(all(row['local_path']==row['path']for row in rows))
        self.assertEqual(result['authorization']['dispatch']['local_path'],'/inputs/dispatch-admission.json')
        self.assertEqual(value['authorization']['dispatch']['local_path'],'/FENCED/dispatch-admission.json')
    def test_missing_extra_or_alias_authorization_cannot_pass_namespace(self):
        for mode in ('missing','extra','alias'):
            value=fixture()
            if mode=='missing':value['authorization'].pop('dispatch')
            elif mode=='extra':value['proofs'].append(dict(value['proofs'][0],path='/inputs/EXTRA'))
            else:value['authorization']['dispatch']['path']=value['proofs'][0]['path']
            with self.subTest(mode=mode),self.assertRaises(ValueError):a.actor_projection(value)


if __name__=='__main__':unittest.main()
