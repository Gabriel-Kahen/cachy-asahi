"""The held filesystem link is comparison data, never traversal authority."""
import copy
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import full_root as roots
import root_link_selection as links
import root_path


class Controls(unittest.TestCase):
    def setUp(self):
        self.nodes={name:dict(type='directory',mode=0o755,uid=0,gid=0) for name in ('var','run')}
        # Independent literal from the held filesystem archive, not the rule.
        self.nodes['var/lock']=dict(type='symlink',mode=0o777,uid=0,gid=0,target='../run/lock')
    def limits(self):
        return roots.Limits(deadline=time.monotonic()+10,max_nodes=100,max_bytes=1024,max_file_bytes=1024)
    def test_exact_inert_endpoint_and_original_resolver_stays_strict(self):
        before=copy.deepcopy(self.nodes)
        self.assertEqual(links.protection_endpoint(self.nodes,'var/lock',self.limits()),'run/lock')
        self.assertEqual(self.nodes,before)
        with self.assertRaisesRegex(ValueError,'missing or unsupported: run/lock'):
            root_path.resolve(self.nodes,'var/lock',limits=self.limits())
    def test_literal_type_metadata_and_missing_link_refuse(self):
        for key,value in (('target','/run/lock'),('target','../run/other'),('mode',0o700),('uid',1),('gid',1),('type','file')):
            nodes=copy.deepcopy(self.nodes);nodes['var/lock'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                links.protection_endpoint(nodes,'var/lock',self.limits())
        del self.nodes['var/lock']
        with self.assertRaises(ValueError):links.protection_endpoint(self.nodes,'var/lock',self.limits())
    def test_live_endpoint_or_different_parent_shape_refuses(self):
        variants=[dict(self.nodes,**{'run/lock':dict(type='directory',mode=0o755,uid=0,gid=0)})]
        for name in ('run','var'):
            for field,value in (('type','symlink'),('mode',0o777),('uid',1),('gid',1)):
                nodes=copy.deepcopy(self.nodes);nodes[name][field]=value;variants.append(nodes)
            nodes=copy.deepcopy(self.nodes);del nodes[name];variants.append(nodes)
        for nodes in variants:
            with self.assertRaises(ValueError):links.protection_endpoint(nodes,'var/lock',self.limits())
    def test_child_other_alias_and_other_missing_paths_gain_no_authority(self):
        self.nodes['var/other']=dict(self.nodes['var/lock'])
        for name in ('var/lock/child','var/other','run/lock','absent'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                links.protection_endpoint(self.nodes,name,self.limits())
    def test_original_measured_set_unchanged(self):
        self.assertEqual(len(links.CHAIN_PATHS),87)
        self.assertNotIn('var/lock',links.LINK_NODES)
        self.assertNotIn('var/lock',links.DATA_ONLY_ENDPOINTS)


if __name__=='__main__':unittest.main()
