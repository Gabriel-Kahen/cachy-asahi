# SPDX-License-Identifier: MIT
"""Pure actor proof-path projection controls; no actor gate or candidate import."""
import importlib.util
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('v4_actor_projection_DATA',HERE/'payload/actor/entry.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)


def fixture():
    row=lambda name:dict(path='/inputs/'+name,local_path='/FENCED/'+name,bytes=1,sha256='a'*64)
    return dict(FENCED='NOT_AN_ADMITTED_OPERATIONAL_FIXTURE',proofs=[row('proof-'+str(n)+'.json')for n in range(13)],authorization={k:row(name)for k,name in (('dispatch','dispatch-admission.json'),('provider','provider-binding.json'),('qualification','native-qualification.json'))},materials=[dict(name='FENCED-'+str(n),local_path='/FENCED/material')for n in range(5)])


class Controls(unittest.TestCase):
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
