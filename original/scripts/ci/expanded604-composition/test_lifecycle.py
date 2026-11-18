# SPDX-License-Identifier: MIT
"""Inert lifecycle checks: no native actor, package mutation, key or network use."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


# Standalone development tests can use the unchanged generic contract helpers.
contract_path=HERE/'contract.py'
if not contract_path.exists():
    contract_path=Path.cwd()/'scripts/ci/expanded-development-composition/contract.py'
C=load('lifecycle_test_contract604',contract_path)
prior=sys.modules.get('contract');sys.modules['contract']=C
try:L=load('lifecycle_under_test604',HERE/'lifecycle.py')
finally:
    if prior is None:sys.modules.pop('contract',None)
    else:sys.modules['contract']=prior


class Lifecycle(unittest.TestCase):
    def test_fixed_signature_primary_and_subkey(self):
        primary='A'*40;sub='B'*40
        for signing in (primary,sub):
            status='[GNUPG:] VALIDSIG '+signing+' 2026-10-16 1 0 4 0 1 10 00 '+primary+'\n'
            with patch.object(L,'run',return_value=status) as execute:
                L.verify_signature(['gpg'],'archive','signature',primary)
                self.assertEqual(execute.call_args.args[0],['gpg','--status-fd','1','--verify','signature','archive'])

    def test_bad_expired_revoked_and_ambiguous_signatures_refused(self):
        signer='A'*40;valid='[GNUPG:] VALIDSIG '+signer+' 2026-10-16 1 0 4 0 1 10 00 '+signer+'\n'
        values=['',valid+valid,valid.replace(signer,'B'*40)]
        values += [valid+'[GNUPG:] '+token+' details\n' for token in
                   ('BADSIG','ERRSIG','EXPKEYSIG','KEYEXPIRED','KEYREVOKED','REVKEYSIG','SIGEXPIRED','EXPSIG','FAILURE','NO_PUBKEY')]
        for value in values:
            with self.subTest(value=value[-60:]),patch.object(L,'run',return_value=value),self.assertRaises(ValueError):
                L.verify_signature(['gpg'],'archive','signature',signer)

    def test_signing_roles_cannot_add_third_key_or_resign_alarm(self):
        test='A'*40;alarm='B'*40
        def row(name,signer):return dict(name=name,signer=signer,archive=name+'.xz',size=1,sha256='a'*64,
            signature=name+'.xz.sig',signature_size=1,signature_sha256='b'*64)
        original=dict(keyrings=[dict(path='test.asc',size=1,sha256='a'*64),dict(path='alarm.asc',size=1,sha256='b'*64)],
            packages=[row('base',alarm),row('project',test)],
            preparation=dict(signer_roles={'upstream_ALARM':alarm,'ephemeral_TEST':test}))
        for name,signer in (('lsp-plugins-lv2',test),('cachy-asahi-apps',alarm),('cachy-asahi-apps','C'*40)):
            with self.subTest(name=name,signer=signer),tempfile.TemporaryDirectory() as temporary,\
                 patch.object(C,'checked',side_effect=lambda root,ref,*_:root/ref['path']),\
                 patch.object(L,'input_paths',side_effect=lambda root,rows:[root/r['archive'] for r in rows]),\
                 patch.object(L,'run'),patch.object(L,'verify_signature'):
                with self.assertRaises(ValueError):L.trust(Path(temporary),dict(incoming=[row(name,signer)]),original)

    def test_transaction_budget_and_failed_output(self):
        with patch.object(L.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout='ok',stderr='')) as execute:
            self.assertEqual(L.run(['pacman','-Dk']),'ok')
            self.assertEqual(execute.call_args.kwargs['timeout'],180)
        for result in (types.SimpleNamespace(returncode=1,stdout='',stderr='failed'),
                       types.SimpleNamespace(returncode=0,stdout='x'*(4*1024**2+1),stderr='')):
            with patch.object(L.subprocess,'run',return_value=result),self.assertRaises(ValueError):L.run(['pacman'])

    def test_no_host_actor_outside_guard(self):
        with tempfile.TemporaryDirectory() as temporary,patch.object(L,'OUT',Path(temporary)),\
             patch.object(L.platform,'machine',return_value='x86_64'),patch.object(L,'run') as execute:
            self.assertEqual(L.main(),1)
            result=C.read(Path(temporary)/'lifecycle.json')
            self.assertEqual(result['status'],'FAIL');self.assertEqual(result['events'],[])
            self.assertEqual(result['apps_plan'],'NOT_APPLIED');self.assertEqual(result['cache_removal'],'NOT_APPLIED')
            execute.assert_not_called()

    def test_real_tree_preserves_links_hashes_and_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);file=root/'content';file.write_bytes(b'actual bytes');file.chmod(0o640)
            (root/'link').symlink_to('content')
            snapshot=L.tree(root)
            self.assertEqual(snapshot[str(file)]['sha256'],C.sha(file))
            self.assertEqual(snapshot[str(file)]['mode'],0o640)
            self.assertEqual(snapshot[str(root/'link')]['link'],'content')
            self.assertEqual(L.node(root/'absent'),{'type':'absent'})

    def test_archive_node_forms_and_special_rejection(self):
        common=dict(mode=0o644,uid=0,gid=0)
        self.assertEqual(L.expected_node(dict(common,type='0',size=4,sha256='a')),
                         dict(common,type='file',size=4,sha256='a'))
        self.assertEqual(L.expected_node(dict(common,type='2',link='../literal')),
                         dict(common,type='symlink',link='../literal'))
        with self.assertRaises(ValueError):L.expected_node(dict(common,type='1'))

    def test_installed_payload_owner_and_database_mismatch_reject(self):
        member=dict(mode=0o644,uid=0,gid=0,type='0',size=4,sha256='a')
        rows=[dict(name='package',version='1',payload={'usr/file':member})]
        db={'package':dict(version='1',files=['usr/file'])}
        with patch.object(L,'node',return_value=L.expected_node(member)):
            L.check_incoming(rows,{'package':'1'},db)
            for changed in ({'package':'2'},{}):
                with self.assertRaises(ValueError):L.check_incoming(rows,changed,db)
            with self.assertRaises(ValueError):L.check_incoming(rows,{'package':'1'},dict(db,other=dict(files=['usr/file'])))
        with patch.object(L,'node',return_value={'type':'absent'}),self.assertRaises(ValueError):
            L.check_incoming(rows,{'package':'1'},db)

    def test_explicit604_database_limit_without_shared_patch(self):
        rows=[dict(name='p'+str(i),version='1') for i in range(604)]
        helper=types.SimpleNamespace(database=lambda root,**kwargs:(self.assertEqual(kwargs,{'max_packages':604}) or rows))
        with patch.object(C,'load',return_value=helper),patch.object(L,'tree',return_value={}):
            db,_=L.database();self.assertEqual(len(db),604)
            rows.pop()
            with self.assertRaises(ValueError):L.database()

    def test_payload_caps_unchanged_and_special_nodes_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo=Path(temporary)/'pipe';os.mkfifo(fifo)
            with self.assertRaises(ValueError):L.node(fifo)
        huge=types.SimpleNamespace(st_mode=0o100644,st_uid=0,st_gid=0,st_size=1024**3+1)
        with patch.object(Path,'lstat',return_value=huge),self.assertRaises(ValueError):L.node(Path('/unread'))

    def test_metadata_repeats_preserved(self):
        with patch.object(L,'run',return_value='# package\nname = p\ndepend = x\ndepend = y\n'):
            self.assertEqual(L.metadata('input'),{'name':['p'],'depend':['x','y']})


if __name__=='__main__':unittest.main()
