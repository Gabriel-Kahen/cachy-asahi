# SPDX-License-Identifier: MIT
"""Real disposable native-known-graph mechanics; no synthetic native acceptance."""
import importlib.util
import copy
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('boot607_graph',HERE/'package_graph.py')
G=importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

def row(name,files,version='1-1'):
    return dict(name=name,version=version,arch='any',depend=[],provides=[],conflict=[],files=files)

class Graph(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='boot607-package-graph-control-',dir=HERE if os.environ.get('BOOT607_GRAPH_FS') == 'btrfs' else '/tmp')
        self.root=Path(self.temp.name)
        self.rows=[row('retained',['usr/bin/retained'])]
        for name in ('usr/bin','usr/share/doc','usr/share/licenses','var/lib/pacman/local/retained-1-1','etc','home','root'):
            (self.root/name).mkdir(parents=True,exist_ok=True)
        for name,data in (('usr/bin/retained',b'original\n'),('etc/sentinel',b'keep\n'),('var/lib/pacman/local/retained-1-1/desc',b'complete original record\n'),('var/lib/pacman/local/retained-1-1/files',b'usr/bin/retained\n'),('var/lib/pacman/local/ALPM_DB_VERSION',b'9\n')):
            (self.root/name).write_bytes(data)
        self.before=self.capture()
    def tearDown(self):
        self.temp.cleanup()
    def capture(self,rows=None):
        return G.capture(self.root,self.rows if rows is None else rows,deadline=time.monotonic()+10)
    def lock(self,operation):
        parent=self.root/'var/lib/pacman'
        before=G.key(parent.stat())
        names=sorted(os.listdir(parent))
        (parent/'db.lck').write_bytes(b'')
        operation()
        (parent/'db.lck').unlink()
        return dict(path='var/lib/pacman',lock_created=True,lock_removed=True,names=names,before=before,after=G.key(parent.stat()))
    def install(self):
        for name in G.SELECTED_FILES:
            p=self.root/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(('selected '+name+'\n').encode())
        p=self.root/G.SELECTED_DB
        p.mkdir()
        (p/'desc').write_bytes(b'Boot explicit record\n')
        (p/'files').write_text('\n'.join(sorted(G.SELECTED_FILES)))
    def candidate_rows(self):
        return self.rows+[row(G.NAME,sorted(G.SELECTED_FILES),'0.1.0-1')]
    def test_same_real_graph_and_fd_retirement(self):
        count=len(os.listdir('/proc/self/fd'))
        for _ in range(4):
            self.assertTrue(G.protected(self.before,self.capture(),lock_witness=None))
        self.assertEqual(len(os.listdir('/proc/self/fd')),count)
    def test_exact_selected_addition_and_lock_witness(self):
        witness=self.lock(self.install)
        self.assertTrue(G.protected(self.before,self.capture(self.candidate_rows()),lock_witness=witness))
    def test_selected_same_names_replacement_and_removal(self):
        witness=self.lock(self.install)
        rows=self.candidate_rows()
        first=self.capture(rows)
        self.assertTrue(G.protected(self.before,first,lock_witness=witness))
        def replace():
            for name in G.SELECTED_FILES:
                p=self.root/name
                raw=p.read_bytes()
                p.unlink()
                p.write_bytes(raw)
        witness=self.lock(replace)
        second=self.capture(rows)
        self.assertTrue(G.protected(first,second,lock_witness=witness))
        def remove():
            for name in G.SELECTED_FILES:
                (self.root/name).unlink()
            for name in G.SELECTED_DIRS:
                (self.root/name).rmdir()
            p=self.root/G.SELECTED_DB
            for f in p.iterdir():f.unlink()
            p.rmdir()
        witness=self.lock(remove)
        self.assertTrue(G.protected(second,self.capture(),lock_witness=witness))
    def test_real_filesystem_counter_mode_reported(self):
        witness=self.lock(self.install)
        after=self.capture(self.candidate_rows())
        result=G.protected(self.before,after,lock_witness=witness)
        for parent,mode in result['directory_counter_modes'].items():
            before_nlink=self.before['nodes'][parent]['identity'][5]
            after_nlink=after['nodes'][parent]['identity'][5]
            self.assertEqual(mode,'CONSTANT_ONE_WITH_COMPLETE_INDEPENDENT_CHILD_PROOF' if before_nlink==after_nlink==1 else 'ARITHMETIC_CHILD_DIRECTORY_DELTA')
        self.assertTrue(result['directory_counter_modes'])
    def test_child_proof_type_inode_mount_capability_alias_counter_tampering_refused(self):
        witness=self.lock(self.install)
        after=self.capture(self.candidate_rows())
        for kind in ('identity','kind','mount_id','capability','link','counter'):
            bad=copy.deepcopy(after)
            parent=bad['nodes']['usr/bin']
            child=parent['children_detail']['retained']
            if kind=='identity':child['identity'][1]+=1
            elif kind=='kind':child['kind']='symlink'
            elif kind=='mount_id':child['mount_id']+=1
            elif kind=='capability':child['capability']='01000002'
            elif kind=='link':child['link']='outside'
            else:parent['identity'][5]+=7
            with self.assertRaises(ValueError,msg=kind):
                G.protected(self.before,bad,lock_witness=witness)
    def test_missing_complete_child_proof_refused(self):
        witness=self.lock(self.install)
        after=self.capture(self.candidate_rows())
        del after['nodes']['usr/bin']['children_detail']['retained']
        with self.assertRaises(ValueError):G.protected(self.before,after,lock_witness=witness)
    def test_unknown_existing_child_identity_not_hidden_by_constant_counter(self):
        p=self.root/'usr/bin/unowned'
        p.write_bytes(b'unowned original')
        baseline=self.capture()
        witness=self.lock(self.install)
        p.write_bytes(b'unowned changed!')
        with self.assertRaises(ValueError):G.protected(baseline,self.capture(self.candidate_rows()),lock_witness=witness)
    def test_lock_metadata_change_without_witness_refused(self):
        self.lock(lambda:None)
        with self.assertRaises(ValueError):
            G.protected(self.before,self.capture(),lock_witness=None)
    def test_protected_bytes_and_rawdb_mutations_refused(self):
        for name in ('usr/bin/retained','var/lib/pacman/local/retained-1-1/desc','etc/sentinel'):
            p=self.root/name
            original=p.read_bytes()
            p.write_bytes(b'changed\n')
            with self.assertRaises(ValueError):
                G.protected(self.before,self.capture(),lock_witness=None)
            p.write_bytes(original)
    def test_protected_inode_replaced_even_same_bytes_refused(self):
        p=self.root/'usr/bin/retained'
        raw=p.read_bytes();p.unlink();p.write_bytes(raw)
        with self.assertRaises(ValueError):
            G.protected(self.before,self.capture(),lock_witness=None)
    def test_unknown_child_of_known_parent_refused(self):
        (self.root/'usr/bin/unknown').write_bytes(b'unknown\n')
        with self.assertRaises(ValueError):
            G.protected(self.before,self.capture(),lock_witness=None)
    def test_hardlink_escape_refused(self):
        os.link(self.root/'usr/bin/retained',self.root/'outside-package-graph')
        with self.assertRaises(ValueError):self.capture()
    def test_cross_selected_protected_hardlink_refused(self):
        self.install()
        p=self.root/'usr/bin'/G.NAME
        p.unlink();os.link(self.root/'usr/bin/retained',p)
        with self.assertRaisesRegex(ValueError,'selected/protected hardlink'):self.capture(self.candidate_rows())
    def test_symlink_ancestor_refused(self):
        p=self.root/'usr/bin'
        p.rename(self.root/'usr/original-bin')
        p.symlink_to('original-bin',target_is_directory=True)
        with self.assertRaises(OSError):self.capture()
    def test_rawdb_and_user_tree_growth_during_capture_refused(self):
        for name in ('var/lib/pacman/local/retained-1-1/late-member','etc/late-member'):
            original=G.os.getxattr
            added=[]
            def changed(*args,**kwargs):
                if not added:
                    (self.root/name).write_bytes(b'unobserved member must refuse')
                    added.append(True)
                return original(*args,**kwargs)
            try:
                with patch.object(G.os,'getxattr',side_effect=changed):
                    with self.assertRaisesRegex(ValueError,'complete declared DB/user/config tree'):self.capture()
            finally:
                (self.root/name).unlink()
    def test_deadline_refused(self):
        with self.assertRaises(ValueError):G.capture(self.root,self.rows,deadline=time.monotonic()-1)

if __name__=='__main__':unittest.main(verbosity=2)
