# SPDX-License-Identifier: MIT
"""Disposable real-GPG component controls; never VM/native acceptance fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
HERE=Path(__file__).resolve().parent
REPO=HERE.parent
sys.path.insert(0,str(HERE))
import accepted_inputs as A
import prepare_inputs as P
PACKET=Path(os.environ['BOOT607_INPUT_PACKET']).absolute()
OLD=REPO/'held606'

def load(name,path,aliases=None):
    aliases=aliases or {};missing=object();saved={k:sys.modules.get(k,missing) for k in aliases}
    try:
        sys.modules.update(aliases)
        spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
    finally:
        for k,v in saved.items():
            if v is missing:sys.modules.pop(k,None)
            else:sys.modules[k]=v

class Prepare(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='signing-component-control-',dir='/tmp')
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.producer=self.root/'producer';self.home=self.producer/'private/test-signing';self.home.mkdir(parents=True,mode=0o700)
        self.argv=['gpg','--batch','--no-options','--homedir',str(self.home),'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','']
        self.command(['--quick-gen-key','Boot607 disposable source control <boot607-control@example.invalid>','ed25519','sign','1d'])
        listing=self.command(['--with-colons','--list-secret-keys']).stdout.decode()
        self.signer=next(r.split(':')[9] for r in listing.splitlines() if r.startswith('fpr:'))
        self.public=self.command(['--armor','--export',self.signer]).stdout
        self.ready=self.root/'ready604';(self.ready/'keys').mkdir(parents=True)
        (self.ready/'keys/TEST-public.asc').write_bytes(self.public)
        (self.ready/'keys/archlinuxarm.gpg').write_bytes(b'LOCAL_CONTROL_UPSTREAM_ROLE_NOT_REAL_NATIVE_INPUT')
        manifest=dict(preparation=dict(signer_roles=dict(ephemeral_TEST=self.signer,upstream_ALARM='F'*40)),
            keyrings=[dict(path='keys/TEST-public.asc',size=len(self.public),sha256=A.pin(self.public)['sha256']),
                      dict(path='keys/archlinuxarm.gpg',size=len((self.ready/'keys/archlinuxarm.gpg').read_bytes()),sha256=A.pin((self.ready/'keys/archlinuxarm.gpg').read_bytes())['sha256'])])
        (self.ready/'manifest.json').write_text(json.dumps(manifest))
        def safe(p):
            A.need(p.is_absolute() and p.is_relative_to(self.root) and not any(q.is_symlink() for q in (p,*p.parents)), 'owned local control path')
            return p
        self.C=types.SimpleNamespace(need=A.need,safe=safe,read=lambda p:A.decode(A.read(p)),load=load,scoped_load=load,encoded=lambda d:(json.dumps(d,sort_keys=True,indent=2)+'\n').encode())
        self.checks=load('boot607_real_package_checks',OLD/'held-tools/scripts/checks/package_checks.py')
    def tearDown(self):
        try:subprocess.run(['gpgconf','--homedir',str(self.home),'--kill','all'],check=True,capture_output=True,timeout=15)
        finally:self.temp.cleanup()
    def command(self,args):
        return subprocess.run(self.argv+args,stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=30)
    def make(self):
        return P.make(packet=PACKET,original606_root=OLD,producer=self.producer,ready604=self.ready,output=self.root/'boot607',C=self.C,checks=self.checks,nonce='1'*32)
    def test_real_sign_public_only_verify_archive_held_and_verifier_retired(self):
        result=self.make()
        self.assertEqual(result['sha256'],A.ARCHIVE['sha256'])
        self.assertEqual(result['signer'],self.signer)
        self.assertTrue(all(result[k] is None for k in ('actual_source','actual_ref','actual_run')))
        self.assertEqual(result['new_builds'],'NOT_RUN_REUSED_ACCEPTED_PAIR')
        self.assertFalse((self.producer/'private/boot607-public-verifier').exists())
        self.assertEqual(A.pin(A.read(self.root/'boot607'/result['archive'])),A.ARCHIVE)
        signature=self.root/'boot607'/result['signature']['path']
        status=self.command(['--status-fd=1','--verify',str(signature),str(signature).removesuffix('.sig')]).stdout.decode()
        self.assertIn('[GNUPG:] VALIDSIG '+self.signer+' ',status)
        self.assertNotIn('EXPKEYSIG',status)
    def test_wrong_original_secret_fingerprint_refused(self):
        f=self.ready/'manifest.json';m=json.loads(f.read_bytes());m['preparation']['signer_roles']['ephemeral_TEST']='E'*40;f.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,'secret-key role differs'):self.make()
    def test_multiple_original_secret_certificates_refused(self):
        self.command(['--quick-gen-key','Second disposable source control <second-control@example.invalid>','ed25519','sign','1d'])
        with self.assertRaisesRegex(ValueError,'secret-key role differs'):self.make()

if __name__=='__main__':unittest.main(verbosity=2)
