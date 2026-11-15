# SPDX-License-Identifier: MIT
"""Synthetic bootstrap receipt joins only; never invoke review(), GPG or an actor."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle_reader_pure_data_test', HERE/'payload/hosted/reader.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def put(path, raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(raw)


def read(path, cap):
    # Only tiny regular files created inside this test's private temporary root.
    data = path.read_bytes()
    if len(data)>cap:
        raise ValueError('synthetic DATA cap')
    return data


class BootstrapFixture:
    """248+8 fake declarations, 257 fake GPG receipts, zero package/archive bytes."""
    def __init__(self, directory):
        self.root,self.evidence = directory/'source',directory/'evidence'
        self.root.mkdir();self.evidence.mkdir()
        self.c = SimpleNamespace(read=read,pin=pin)
        self.base = dict(source='1'*40,ref='refs/heads/codex/synthetic-receipt-data',run='123',job='456',approval='2'*64,source_map_sha256='3'*64,component_map_sha256='4'*64,operation='perl5423-installed-lifecycle-native-v1')
        self.binding = dict(self.base,image='sha256:'+'5'*64)
        self.hosted = dict(binding=copy.deepcopy(self.base),bootstrap={'image':self.binding['image']})
        def declaration(name):
            return dict(filename=name,size=1,sha256=hashlib.sha256(('FAKE DECLARATION '+name).encode()).hexdigest(),signature_size=1,signature_sha256=hashlib.sha256(('FAKE SIG DECLARATION '+name).encode()).hexdigest())
        self.original = dict(rootfs=declaration('rootfs.synthetic'),packages=[declaration('original%03d.pkg.tar.xz'%i) for i in range(248)],keyring_files=[dict(filename='public-keyring-%d.data'%i,size=1,sha256=str(i+6)*64) for i in range(3)],signer_fingerprint=SIGNER)
        self.profile = dict(additions={'rows':[declaration('extra%02d.pkg.tar.xz'%i) for i in range(8)]})
        combined = dict(self.original,packages=self.original['packages']+self.profile['additions']['rows'])
        put(self.root/'original/bootstrap/scripts/ci/inputs.lock.json',encoded(self.original))
        put(self.root/'original/native/input-profile.json',encoded(self.profile))
        put(self.evidence/'bootstrap/inputs.lock.json',encoded(combined))
        signed = [combined['rootfs'],*combined['packages']]
        self.first = signed[0]['filename']
        items = list(combined['keyring_files'])
        for item in signed:
            items.extend([item,dict(filename=item['filename']+'.sig',size=item['signature_size'],sha256=item['signature_sha256'])])
        self.acquisition = dict(acquisition='PASS',counts={'total':517,'pass':517,'fail':0,'pending':0},inputs={item['filename']:dict(status='PASS',expected_bytes=item['size'],expected_sha256=item['sha256']) for item in items})
        self.signatures,self.operations = {},[]
        status = '[GNUPG:] VALIDSIG '+SIGNER+' 2026-11-15 1794700000 0 4 0 1 8 00 '+SIGNER+'\n'
        diagnostic = 'SYNTHETIC STATUS DATA; NO SIGNATURE WAS CREATED OR VERIFIED\n'
        for index,item in enumerate(signed):
            name = item['filename']
            argv = ['gpg','--batch','--no-options','--homedir','/synthetic-runner/perl-lifecycle-hosted/bootstrap/gpg','--no-auto-key-retrieve','--status-fd','1','--verify','/synthetic-runner/alarm-cache/'+name+'.sig','/synthetic-runner/alarm-cache/'+name]
            self.signatures[name] = dict(exit_code=0,status=status,diagnostic=diagnostic,command=argv)
            life = dict(exit=0,natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True)
            operation = dict(argv=argv,returncode=0,lifecycle=life)
            for channel,body in (('stdout',status.encode()),('stderr',diagnostic.encode())):
                relative = 'bootstrap/operations/%03d.%s'%(index,channel)
                operation[channel],operation[channel+'_pin'] = relative,pin(body)
                put(self.evidence/relative,body)
            self.operations.append(operation)
        token = hashlib.sha256((self.base['source']+':'+self.base['ref']+':'+self.base['run']).encode()).hexdigest()[:24]
        self.image = dict(Id=self.binding['image'],Architecture='arm64',Os='linux',Config={'Labels':{'cachy-asahi.hosted-perl-lifecycle':token,'cachy-asahi.hosted-perl-lifecycle.source':self.base['source']}},RepoTags=['perl-lifecycle-native-base:'+token])
        put(self.evidence/'bootstrap/image-inspect.json',encoded(self.image))
        for name in ('input-data-preparation.json','fixed-eight-cache.json'):
            put(self.evidence/'bootstrap'/name,encoded({'fixture':'PASSIVE METADATA ONLY'}))
        self.proof = dict(status='PASS_FRESH_SIGNED349_BOOTSTRAP',binding=copy.deepcopy(self.base),image=self.binding['image'])
        self.save()

    def save(self):
        put(self.evidence/'bootstrap/acquisition.json',encoded(self.acquisition))
        put(self.evidence/'bootstrap/signatures.json',encoded(self.signatures))
        put(self.evidence/'bootstrap/operations.json',encoded(self.operations))
        for name,key in [('inputs.lock.json','inputs_sha256'),('acquisition.json','acquisition_sha256'),('signatures.json','signatures_sha256'),('image-inspect.json','image_inspect_sha256'),('input-data-preparation.json','preparation_sha256'),('fixed-eight-cache.json','cache_additions_sha256')]:
            value = hashlib.sha256((self.evidence/'bootstrap'/name).read_bytes()).hexdigest()
            self.proof[key] = self.hosted['bootstrap'][key] = value
        put(self.evidence/'bootstrap/proof.json',encoded(self.proof))

    def check(self):
        return r.bootstrap_data(self.root,self.evidence,self.binding,self.hosted,self.c)


class ReaderDataTests(unittest.TestCase):
    def test_positive_closed_synthetic_bootstrap_receipt_join(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = BootstrapFixture(Path(directory))
            self.assertIsNone(fixture.check())

    def test_wrong_signed_filename_refuses_even_with_exact_count(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = BootstrapFixture(Path(directory))
            fixture.signatures['unrelated.synthetic'] = fixture.signatures.pop(fixture.first)
            fixture.save()
            with self.assertRaisesRegex(ValueError,'filenames'):
                fixture.check()

    def test_both_primary_endpoints_must_match_the_pinned_primary(self):
        for endpoint in (1,10):
            with self.subTest(endpoint=endpoint),tempfile.TemporaryDirectory() as directory:
                fixture = BootstrapFixture(Path(directory))
                row = fixture.signatures[fixture.first]
                fields = row['status'].split()
                fields[endpoint+1] = '0'*40
                row['status'] = ' '.join(fields)+'\n'
                put(fixture.evidence/fixture.operations[0]['stdout'],row['status'].encode())
                fixture.operations[0]['stdout_pin'] = pin(row['status'].encode())
                fixture.save()
                with self.assertRaisesRegex(ValueError,'primary'):
                    fixture.check()

    def test_foreign_image_refuses_in_proof_or_inspect(self):
        for channel in ('binding','proof','labels'):
            with self.subTest(channel=channel),tempfile.TemporaryDirectory() as directory:
                fixture = BootstrapFixture(Path(directory))
                if channel=='binding':
                    fixture.binding['image'] = 'sha256:'+'9'*64
                elif channel=='proof':
                    fixture.proof['image'] = 'sha256:'+'9'*64
                    fixture.save()
                else:
                    fixture.image['Config']['Labels']['cachy-asahi.hosted-perl-lifecycle.source'] = '9'*40
                    put(fixture.evidence/'bootstrap/image-inspect.json',encoded(fixture.image))
                    fixture.save()
                with self.assertRaisesRegex(ValueError,'image'):
                    fixture.check()

    def test_original_stdout_and_stderr_must_join_status_and_diagnostic(self):
        for channel in ('stdout','stderr'):
            with self.subTest(channel=channel),tempfile.TemporaryDirectory() as directory:
                fixture = BootstrapFixture(Path(directory))
                changed = b'CHANGED PASSIVE CHANNEL DATA\n'
                put(fixture.evidence/fixture.operations[0][channel],changed)
                fixture.operations[0][channel+'_pin'] = pin(changed)
                fixture.save()
                with self.assertRaisesRegex(ValueError,'raw public signature channel'):
                    fixture.check()

    def test_raw_channel_pin_and_containment_are_required(self):
        for mutation in ('pin','path'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                fixture = BootstrapFixture(Path(directory))
                if mutation=='pin':
                    fixture.operations[0]['stdout_pin']['sha256'] = '0'*64
                else:
                    fixture.operations[0]['stdout'] = '../outside'
                fixture.save()
                with self.assertRaises(ValueError):
                    fixture.check()

    def test_unique_original_gpg_command_receipt_required(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = BootstrapFixture(Path(directory))
            fixture.operations.append(copy.deepcopy(fixture.operations[0]))
            fixture.save()
            with self.assertRaisesRegex(ValueError,'unique original'):
                fixture.check()

    def test_uncertain_gpg_retirement_refuses(self):
        for key,value in (('ownership_lost',True),('leader_held_until_group_inspection',False),('exit_observed_via_waitpid',False),('forced_cleanup',True)):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as directory:
                fixture = BootstrapFixture(Path(directory))
                fixture.operations[0]['lifecycle'][key] = value
                fixture.save()
                with self.assertRaisesRegex(ValueError,'retirement'):
                    fixture.check()

    def test_changed_acquisition_declaration_or_source_lock_refuses(self):
        for mutation in ('acquisition','source'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                fixture = BootstrapFixture(Path(directory))
                if mutation=='acquisition':
                    fixture.acquisition['inputs'][fixture.first]['expected_bytes'] += 1
                    fixture.save()
                else:
                    original = copy.deepcopy(fixture.original)
                    original['packages'][0]['size'] += 1
                    put(fixture.root/'original/bootstrap/scripts/ci/inputs.lock.json',encoded(original))
                with self.assertRaises(ValueError):
                    fixture.check()

    def test_changed_bootstrap_proof_channel_hash_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = BootstrapFixture(Path(directory))
            put(fixture.evidence/'bootstrap/input-data-preparation.json',b'CHANGED PASSIVE DATA\n')
            with self.assertRaisesRegex(ValueError,'channel hash'):
                fixture.check()


if __name__=='__main__':
    unittest.main()
