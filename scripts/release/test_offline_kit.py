#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real fresh TEST signatures and original fixture packages; inspect never installs."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

k = load('offline_kit', HERE / 'offline_kit.py')
t = load('release_fixtures', HERE / 'test_release.py')


class KitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t.ReleaseTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        t.ReleaseTests.tearDownClass()

    def setUp(self):
        self.f = t.ReleaseTests(methodName='runTest')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.f.put('integration.lock.json', {'schema_version': 1, 'fixture': 'original TEST lock'})
        self.f.release_spec['evidence'] = [dict(self.f.ref('integration.lock.json'), id='integration.lock.json')]
        self.bundle = Path(self.f.stage()['path'])
        self.state = self.f.base / 'state'; self.state.mkdir(mode=0o700)
        self.metadata = self.f.base / 'development.json'
        self.public = self.f.base / 'public.gpg'
        self.public.write_bytes(t.r.run(['gpg', '--batch', '--export', self.f.key], env=self.f.env))
        self.make_metadata()
        self.output = self.f.base / 'kit'
        self.args = argparse.Namespace(bundle=str(self.bundle), metadata=str(self.metadata),
            signature=str(self.metadata) + '.sig', public_keyring=str(self.public), signer=self.f.key,
            namespace='dev.original-fixture', minimum_sequence=1, state_dir=str(self.state),
            lock_evidence='integration.lock.json', output=str(self.output))

    def make_metadata(self):
        now = datetime.now(timezone.utc)
        self.metadata.unlink(missing_ok=True)
        k.c.build(argparse.Namespace(bundle=str(self.bundle), output=str(self.metadata), namespace='dev.original-fixture',
            sequence=1, issued_utc=k.c.utc(now-timedelta(minutes=1)), expires_utc=k.c.utc(now+timedelta(hours=1)), signer=self.f.key))
        Path(str(self.metadata)+'.sig').unlink(missing_ok=True)
        t.r.sign(self.metadata, self.f.key, self.f.env)

    def assemble(self):
        result = k.assemble(self.args)
        self.inspect_args = argparse.Namespace(kit=str(self.output), kit_sha256=result['kit_sha256'],
            signer=self.f.key, namespace=self.args.namespace, minimum_sequence=1, state_dir=str(self.state))
        return result

    def refused(self, action):
        before = {p.name:p.read_bytes() for p in self.state.iterdir()}
        with self.assertRaises((k.c.Error, OSError, ValueError, KeyError, TypeError)):
            action()
        self.assertEqual(before, {p.name:p.read_bytes() for p in self.state.iterdir()})

    def resign_metadata(self, **changes):
        value = k.c.decode(self.metadata.read_bytes()); value.update(changes)
        self.metadata.write_bytes(k.c.encoded(value))
        Path(str(self.metadata)+'.sig').unlink(); t.r.sign(self.metadata, self.f.key, self.f.env)

    def test_relocated_standalone_receiver_after_producer_removed(self):
        result = self.assemble()
        unrelated = self.f.base / 'unrelated-receiver'; unrelated.mkdir()
        relocated = unrelated / 'media'; shutil.move(self.output, relocated)
        shutil.rmtree(self.f.root); shutil.rmtree(self.f.inputs)
        self.metadata.unlink(); Path(str(self.metadata)+'.sig').unlink(); self.public.unlink()
        before = k.inventory(relocated)
        command = [sys.executable, '-I', '-B', str(relocated/'scripts/release/offline_kit.py'), 'inspect',
            '--kit', str(relocated), '--kit-sha256', result['kit_sha256'], '--namespace', self.args.namespace,
            '--signer', self.f.key, '--minimum-sequence', '1', '--state-dir', str(self.state)]
        run = subprocess.run(command, cwd=unrelated, capture_output=True, timeout=60,
                             env={'PATH':os.environ['PATH'], 'HOME':str(unrelated)})
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        receipt = json.loads(run.stdout)
        self.assertEqual(receipt['status'], 'inspected-portable-development-kit')
        self.assertTrue(receipt['source_delivery_gap'])
        for field in ('state_changed', 'packages_installed', 'transaction_authorized', 'stable_accepted',
                      'native_validation', 'hardware_validation', 'source_completeness_accepted'):
            self.assertIs(receipt[field], False)
        self.assertEqual(k.inventory(relocated), before); self.assertEqual(list(self.state.iterdir()), [])
        raw = (relocated/'kit.json').read_bytes()
        self.assertNotIn(str(self.f.base).encode(), raw)
        self.assertEqual(receipt['lock']['sha256'], t.r.sha(relocated/'release/evidence/integration.lock.json'))

    def test_exact_signed_payload_db_alias_and_project_license_carried(self):
        self.assemble()
        for name in k.RUNTIME:
            self.assertEqual((self.output/name).read_bytes(), (k.ROOT/name).read_bytes())
        self.assertEqual((self.output/'receiver-license.txt').read_bytes(), (k.ROOT/'LICENSE').read_bytes())
        release = t.r.load(self.bundle/'release.json')
        for name, pin in release['files'].items():
            self.assertEqual(t.r.sha(self.output/'release'/name), pin)
        self.assertTrue((self.output/'release/repo/fixture.db').is_symlink())
        self.assertEqual((self.output/'release/project-license.txt').read_bytes(),
                         (self.bundle/'project-license.txt').read_bytes())

    def test_tampered_and_incomplete_transport_refused(self):
        self.assemble()
        package = self.output/'release/repo'/self.f.archive.name
        original = package.read_bytes(); package.chmod(0o600); package.write_bytes(b'tamper')
        self.refused(lambda:k.inspect(self.inspect_args)); package.write_bytes(original)
        (self.output/'development.json.sig').unlink()
        self.refused(lambda:k.inspect(self.inspect_args))

    def test_updated_transport_receipt_does_not_replace_signed_payload_trust(self):
        self.assemble()
        package = self.output/'release/repo'/self.f.archive.name
        package.chmod(0o600); package.write_bytes(b'tamper')
        path = self.output/'kit.json'; value = k.c.decode(path.read_bytes())
        value['files']['release/repo/'+self.f.archive.name] = t.r.sha(package)
        raw = k.c.encoded(value); path.chmod(0o600); path.write_bytes(raw)
        self.inspect_args.kit_sha256 = k.c.digest(raw)
        self.refused(lambda:k.inspect(self.inspect_args))

    def test_expired_freshly_signed_metadata_refused_before_assembly(self):
        self.resign_metadata(expires_utc=k.c.utc(datetime.now(timezone.utc)-timedelta(seconds=1)))
        self.refused(lambda:k.assemble(self.args)); self.assertFalse(self.output.exists())

    def test_receiver_rechecks_expiry_after_transfer(self):
        self.assemble()
        path = self.output/'development.json'
        value = k.c.decode(path.read_bytes()); value['expires_utc']=k.c.utc(datetime.now(timezone.utc)-timedelta(seconds=1))
        path.chmod(0o600); path.write_bytes(k.c.encoded(value))
        sig=Path(str(path)+'.sig'); sig.unlink(); t.r.sign(path,self.f.key,self.f.env)
        manifest=self.output/'kit.json'; receipt=k.c.decode(manifest.read_bytes())
        for name in ('development.json','development.json.sig'):receipt['files'][name]=t.r.sha(self.output/name)
        raw=k.c.encoded(receipt);manifest.chmod(0o600);manifest.write_bytes(raw);self.inspect_args.kit_sha256=k.c.digest(raw)
        self.refused(lambda:k.inspect(self.inspect_args))

    def test_external_namespace_signer_floor_and_receipt_pin_required(self):
        self.assemble()
        for field, value in (('namespace','other.example'), ('signer','F'*40), ('minimum_sequence',2), ('kit_sha256','0'*64)):
            args=argparse.Namespace(**{**vars(self.inspect_args),field:value})
            with self.subTest(field=field):self.refused(lambda:k.inspect(args))

    def test_existing_checkpoint_retained_and_rollback_refused(self):
        apply=argparse.Namespace(**{**vars(self.args),'apply':True})
        k.c.verify(apply)
        before=(self.state/k.c.CHECKPOINT).read_bytes();self.assemble();k.inspect(self.inspect_args)
        self.assertEqual((self.state/k.c.CHECKPOINT).read_bytes(),before)
        saved=k.c.decode(before);saved['sequence']=2
        path=self.state/k.c.CHECKPOINT;path.write_bytes(k.c.encoded(saved));path.chmod(0o600)
        self.refused(lambda:k.inspect(self.inspect_args))

    def test_unsigned_missing_lock_and_bad_signature_refused(self):
        self.args.lock_evidence='missing-lock.json';self.refused(lambda:k.assemble(self.args))
        self.args.lock_evidence='integration.lock.json'
        Path(self.args.signature).write_bytes(b'bad TEST signature');self.refused(lambda:k.assemble(self.args))
        self.assertFalse(self.output.exists())

    def test_private_key_material_never_copied(self):
        secret=t.r.run(['gpg','--batch','--pinentry-mode','loopback','--passphrase','','--export-secret-keys',self.f.key],env=self.f.env)
        self.public.write_bytes(secret);self.refused(lambda:k.assemble(self.args));self.assertFalse(self.output.exists())
        for raw in (b'',b'-----BEGIN PGP PRIVATE KEY BLOCK-----',b'\xc6\xff',b'\xc6\xe0',b'\x94\x01x'):
            with self.subTest(raw=raw),self.assertRaises(k.c.Error):k.public_packets(raw)

    def test_foreign_file_hardlink_and_escaping_alias_refused(self):
        self.assemble()
        extra=self.output/'secret';extra.write_bytes(b'foreign');self.refused(lambda:k.inspect(self.inspect_args));extra.unlink()
        link=self.output/'release/repo/fixture.db';link.unlink();link.symlink_to('../../../../outside')
        self.refused(lambda:k.inspect(self.inspect_args));link.unlink()
        target=self.output/'release/project-license.txt';os.link(target,self.f.base/'foreign-hardlink')
        self.refused(lambda:k.inspect(self.inspect_args))

    def test_unreadable_or_unrecorded_empty_directory_refused(self):
        self.assemble()
        foreign=self.output/'foreign-empty';foreign.mkdir()
        self.refused(lambda:k.inspect(self.inspect_args));foreign.rmdir()
        original=k.os.scandir
        def denied(path):
            if Path(path)==self.output:raise PermissionError('TEST scan denied')
            return original(path)
        with mock.patch.object(k.os,'scandir',side_effect=denied):
            self.refused(lambda:k.inspect(self.inspect_args))

    def test_output_overlap_or_existing_destination_preserved(self):
        self.args.output=str(self.bundle/'kit');self.refused(lambda:k.assemble(self.args))
        self.args.output=str(self.output);self.output.mkdir();(self.output/'keep').write_bytes(b'keep')
        self.refused(lambda:k.assemble(self.args));self.assertEqual((self.output/'keep').read_bytes(),b'keep')

    def test_concurrent_output_alias_never_redirects_publication(self):
        victim=self.f.base/'victim';victim.mkdir();(victim/'keep').write_bytes(b'keep')
        original=k.publish
        def race(staging,parent,output,inspected_inode):
            output.symlink_to(victim,target_is_directory=True)
            return original(staging,parent,output,inspected_inode)
        with mock.patch.object(k,'publish',side_effect=race):
            self.refused(lambda:k.assemble(self.args))
        self.assertEqual({p.name:p.read_bytes() for p in victim.iterdir()},{'keep':b'keep'})
        self.assertTrue(self.output.is_symlink())

    def test_changed_staging_identity_never_publishes_symlink_kit(self):
        victim=self.f.base/'victim';victim.mkdir();(victim/'keep').write_bytes(b'keep')
        original=k.publish
        def race(staging,parent,output,inspected_inode):
            staging.rename(staging.with_name('held-original'))
            staging.symlink_to(victim,target_is_directory=True)
            return original(staging,parent,output,inspected_inode)
        with mock.patch.object(k,'publish',side_effect=race):
            self.refused(lambda:k.assemble(self.args))
        self.assertFalse(self.output.exists())
        self.assertEqual({p.name:p.read_bytes() for p in victim.iterdir()},{'keep':b'keep'})

    def test_prepublication_io_failure_leaves_no_partial_destination(self):
        with mock.patch.object(k,'publish',side_effect=OSError('TEST prepublication I/O failure')):
            self.refused(lambda:k.assemble(self.args))
        self.assertFalse(self.output.exists())
        self.assertFalse(any(p.name.startswith('.offline-kit-') for p in self.f.base.iterdir()))

    def test_real_available_source_delivery_retained_without_acceptance(self):
        self.f.release_spec['release_id']='fixture-2'
        record=dict(package=dict(name='fixture',version='1.0-1',arch='any',sha256=self.f.digest),
                    recipe_key='PKGBUILD',review_status='INCOMPLETE original synthetic test review')
        def material(name,raw):
            path=self.f.inputs/name;path.write_bytes(raw)
            return dict(id=name,path=name,sha256=t.r.sha(path),bytes=len(raw))
        record['bundle']=material('source.tar',b'original opaque TEST source payload')
        record['notices']=[material('NOTICE',b'original TEST notice MIT')]
        record['recipe']=material('PKGBUILD',b'# original fixture recipe; not executed\n')
        record['source_map']=material('source-map.json',k.c.encoded({'PKGBUILD':record['recipe']['sha256']}))
        record['authorization']=material('existing-review.txt',b'INCOMPLETE test review; no approval')
        self.f.put('source-index.json',dict(schema_version=1,purpose='release-source-delivery',synthetic=True,packages=[record]))
        self.f.release_spec['source_delivery']=dict(schema_version=1,index=dict(self.f.ref('source-index.json'),id='source-index.json'))
        provenance=t.r.load(self.f.inputs/'provenance.json');provenance['recipe_sha256']=record['recipe']['sha256']
        self.f.put('provenance.json',provenance);self.f.release_spec['packages'][0]['provenance']=self.f.ref('provenance.json')
        self.bundle=Path(self.f.stage()['path']);self.args.bundle=str(self.bundle);self.make_metadata()
        self.assemble();result=k.inspect(self.inspect_args)
        self.assertEqual(result['source_delivery'],'CHECKED_DECLARED_ASSOCIATIONS');self.assertFalse(result['source_delivery_gap'])
        self.assertFalse(result['source_completeness_accepted']);self.assertFalse(result['legal_acceptance'])
        self.assertEqual((self.output/'release/evidence/source.tar').read_bytes(),b'original opaque TEST source payload')


if __name__=='__main__':
    unittest.main(verbosity=2)
