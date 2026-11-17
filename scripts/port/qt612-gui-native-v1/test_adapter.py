# SPDX-License-Identifier: MIT
"""Genuine recipe pins plus MODEL component-boundary joins; no native artifacts."""
import sys


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn',
            'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
        raise RuntimeError('GUI18_MODEL_NO_ACTORS')


sys.addaudithook(fence)
import copy
import importlib.util
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gui_adapter', HERE/'adapter.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
C = A.C
ROOT = HERE.parents[2]


class Components(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='GUI18-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.inputs, self.work = self.base/'retained', self.base/'private-work'
        self.inputs.mkdir(); self.work.mkdir()
        self.archive = b'MODEL_ONLY_NOT_A_PACKAGE'
        self.supervisor = dict(code_pin=C.pin(b'MODEL_SUPERVISOR'),nonce='a'*32,owner_identity=[100,200,300])
        self.stage = dict(MODEL_ONLY_NOT_A_STAGE=True)
        self.observed = dict(archive=C.pin(self.archive),stage=self.stage,
            archive_inventory={'usr':dict(type='directory',mode=0o755,uid=0,gid=0),
                'usr/lib/MODEL':dict(type='file',mode=0o644,uid=0,gid=0,**C.pin(b'MODEL_PAYLOAD'))})
        self.bodies = {name:C.encode(dict(MODEL_ONLY=name)) for name in A.REFERENCES}
        self.bodies.update(original_archive=self.archive,signature=b'MODEL_SIGNATURE',public_key=b'MODEL_PUBLIC',
                           tampered_archive=b'X'+self.archive[1:],stage=C.encode(self.stage))
        self.value = A.template()
        for name in A.REFERENCES:
            path = ('signed/'+C.FILENAME if name=='original_archive' else
                    'signed/'+C.FILENAME+'.sig' if name=='signature' else
                    'first/provenance.json' if name=='first_provenance' else
                    'second/provenance.json' if name=='second_provenance' else
                    'first/artifacts/qt612-stage-contract.json' if name=='stage' else 'MODEL/'+name+'.DATA')
            self.value['references'][name] = dict(path=path,**C.pin(self.bodies[name]))
        self.value.update(official_fingerprints=['F'*40],official_key_sha256=['f'*64],
            runtime_selection=dict(image='sha256:'+'1'*64,stage_pin=C.pin(self.bodies['stage']),
                snapshot_pin=None), lifecycle_selection=dict(image='sha256:'+'1'*64,
                supervisor=self.supervisor,execution_id='2'*64,negative_execution_ids={}))
        package = dict(archive_pin=C.pin(self.archive),signature_pin=C.pin(self.bodies['signature']),
                       native_provenance_pin=C.pin(self.bodies['first_provenance']))
        self.bodies['installed_snapshot'] = C.encode(dict(packages={C.PACKAGE:package}))
        self.value['runtime_selection']['snapshot_pin'] = C.pin(self.bodies['installed_snapshot'])
        deps = C.inspect_recipe(ROOT)['contract']['dependencies']['runtime']
        plan = dict(gui_package=dict(pin=C.pin(self.archive),payload=A.payload(self.observed),depends=sorted(deps)),
                    pacman=['/usr/bin/pacman','--config','/work/project-test.conf','--gpgdir','/work/public-test'])
        self.bodies['lifecycle_plan'] = C.encode(plan)
        self.bodies['actual_pacman_config'] = (b'[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
            b'LocalFileSigLevel = Required TrustedOnly\nGPGDir = /work/public-test\n')
        self.pair = dict(archive_pin=C.pin(self.archive),
            first_provenance_pin=C.pin(self.bodies['first_provenance']),
            second_provenance_pin=C.pin(self.bodies['second_provenance']),
            comparison_pin=C.pin(self.bodies['comparison']),native_acceptance=False)
        self.modules = {
            'trust':types.SimpleNamespace(verify=lambda **kw:dict(status='MODEL_NOT_CRYPTO',overall_admission=False)),
            'archive':types.SimpleNamespace(inspect_archive=lambda *args:copy.deepcopy(self.observed)),
            'native':types.SimpleNamespace(validate_pair=lambda **kw:copy.deepcopy(self.pair)),
            'runtime':types.SimpleNamespace(validate_dependencies=lambda **kw:dict(supervisor=self.supervisor),
                encoded=C.encode,pin=C.pin,validate_smoke=lambda **kw:dict(MODEL_ONLY=True)),
            'lifecycle':types.SimpleNamespace(validate_evidence=lambda *args,**kw:dict(MODEL_ONLY=True))}

    def request(self):
        for name,raw in self.bodies.items():
            row = self.value['references'][name]
            row.update(C.pin(raw))
            path = self.inputs/row['path']; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw);path.chmod(0o644)
        return C.encode(self.value)

    def review(self):
        raw = self.request()
        with patch.object(A,'module',side_effect=lambda name:self.modules[name]):
            return A.review_components(recipe_root=ROOT,inputs_root=self.inputs,request_raw=raw,
                request_sha256=C.pin(raw)['sha256'],work=self.work,call=None,now=1000,retained={})

    def test_MODEL_components_join_without_native_or_Root_credit(self):
        result = self.review()
        self.assertFalse(result['native_acceptance'])
        self.assertFalse(result['full72_claim'])
        self.assertIsNone(result['Root_grant'])
        self.assertEqual(result['signature_component']['status'],'MODEL_NOT_CRYPTO')
        with self.assertRaisesRegex(ValueError,'HOLD'):
            A.native_entry(result)

    def test_unbound_or_old_recipe_request_refuses(self):
        raw = C.encode(A.template())
        with self.assertRaises(ValueError):
            A.selection(raw,C.pin(raw)['sha256'])
        self.value['recipe_commit'] = '69a02851b87ca29daf2e197101b66bf75ff61889'
        with self.assertRaises(ValueError):self.review()

    def test_whole_archive_and_original_receipt_cross_pins_required(self):
        for key in ('archive_pin','first_provenance_pin','second_provenance_pin','comparison_pin'):
            original = self.pair[key];self.pair[key] = C.pin(b'OTHER_MODEL_OPERAND')
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'same whole signed archive'):
                self.review()
            self.pair[key] = original

    def test_current_stage_and_installed_signature_must_join(self):
        self.observed['stage'] = dict(OTHER_MODEL_STAGE=True)
        with self.assertRaisesRegex(ValueError,'original stage receipt'):
            self.review()
        self.observed['stage'] = self.stage
        value = C.decode(self.bodies['installed_snapshot'])
        value['packages'][C.PACKAGE]['signature_pin'] = C.pin(b'FOREIGN_MODEL_SIG')
        self.bodies['installed_snapshot'] = C.encode(value)
        self.value['runtime_selection']['snapshot_pin'] = C.pin(self.bodies['installed_snapshot'])
        with self.assertRaisesRegex(ValueError,'runtime installed package'):
            self.review()

    def test_lifecycle_payload_and_selected_supervisor_cannot_substitute(self):
        plan = C.decode(self.bodies['lifecycle_plan']);plan['gui_package']['payload']['files'].pop('usr',None)
        plan['gui_package']['payload']['files'].pop('/usr')
        self.bodies['lifecycle_plan'] = C.encode(plan)
        with self.assertRaisesRegex(ValueError,'lifecycle package descriptor'):
            self.review()

    def test_actual_config_never_allows_signature_or_include_exception(self):
        for tail in (b'SigLevel = Never\n',b'Include = /etc/pacman.conf\n',b'[unreviewed]\n'):
            raw = self.bodies['actual_pacman_config'];self.bodies['actual_pacman_config'] = raw+tail
            with self.subTest(tail=tail),self.assertRaises(ValueError):self.review()
            self.bodies['actual_pacman_config'] = raw

    def test_different_lifecycle_execution_supervisor_refuses(self):
        self.value['lifecycle_selection']['supervisor'] = dict(self.supervisor,nonce='b'*32)
        with self.assertRaisesRegex(ValueError,'same externally selected image/supervisor'):
            self.review()


class SourceCustody(unittest.TestCase):
    def test_genuine_b052_recipe_and_complete_physical_namespace(self):
        result = C.inspect_recipe(ROOT)
        self.assertEqual(result['recipe_commit'],C.RECIPE_COMMIT)
        self.assertFalse(result['native_acceptance'])
        with tempfile.TemporaryDirectory(prefix='GUI18_RECIPE_COPY_') as d:
            root = Path(d).resolve();destination = root/C.RECIPE_PATH
            destination.parent.mkdir(parents=True)
            shutil.copytree(ROOT/C.RECIPE_PATH,destination)
            self.assertEqual(C.inspect_recipe(root)['recipe_map'],C.MAP_PIN)
            (destination/'EXTRA').write_bytes(b'MODEL_EXTRA')
            with self.assertRaises(ValueError):C.inspect_recipe(root)

    def test_hardlink_symlink_tamper_and_external_pin_refuse(self):
        with tempfile.TemporaryDirectory(prefix='GUI18_CUSTODY_MODEL_') as d:
            root = Path(d).resolve();f=root/'data';f.write_bytes(b'MODEL')
            ref=dict(path='data',**C.pin(b'MODEL'))
            self.assertEqual(C.read_ref(root,ref),b'MODEL')
            (root/'alias').hardlink_to(f)
            with self.assertRaises(ValueError):C.read_ref(root,ref)
            (root/'alias').unlink();f.write_bytes(b'OTHER')
            with self.assertRaises(ValueError):C.read_ref(root,ref)
            f.unlink();f.symlink_to(root/'missing')
            with self.assertRaises(OSError):C.read_ref(root,ref)


if __name__ == '__main__':
    unittest.main()
