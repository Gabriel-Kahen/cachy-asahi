# SPDX-License-Identifier: MIT
"""Actor-fenced MODEL/refusal controls; no Qt build or authentic recipe claim."""
import copy
import importlib.util
import os
import sys
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qt612_data_controls',HERE/'prepare.py')
M = importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
sys.addaudithook(M.fence)


class Controls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='qt612-native-MODEL-')
        self.addCleanup(tmp.cleanup);self.root = Path(tmp.name)

    def recipe(self):
        repo = self.root/'recipe-checkout';base = repo/M.RECIPE_PATH;base.mkdir(parents=True)
        archive = self.root/'src.tar.xz';archive.write_bytes(b'MODEL_SOURCE_NOT_A_QT_ARCHIVE');archive.chmod(0o600)
        source_pin = M.pin(archive.read_bytes())
        name = 'cachy-asahi-qt612-model'
        bodies = {'PKGBUILD':b"PKGEXT='.pkg.tar.xz'\ncheck() {\n :\n}\n",
            '.SRCINFO':('pkgbase = '+name+'\npkgver = 6.12.0\npkgrel = 1\narch = aarch64\ndepends = glibc\nmakedepends = cmake\ncheckdepends = python\nsource = src.tar.xz::https://example.invalid/MODEL\nsha256sums = '+source_pin['sha256']+'\npkgname = '+name+'\n').encode(),
            'source.json':M.encoded(dict(kind='MODEL_NO_UPSTREAM_OR_ROOT_ACCEPTANCE')),
            'LICENSE-MODEL':b'MODEL_NOTICE_NOT_REAL_QT_LICENSE'}
        files = {}
        for member,raw in bodies.items():
            p = base/member;p.write_bytes(raw);p.chmod(0o644);files[member] = dict(M.pin(raw),mode=0o644)
        value = dict(schema=1,kind='QT612_REFERENCE_RECIPE_SELECTION_V1',recipe_commit='b'*40,recipe_path=M.RECIPE_PATH,
            version='6.12.0',files=files,upstream_commit='a'*40,
            sources={'src.tar.xz':dict(path=str(archive),**source_pin)},licenses={'LICENSE-MODEL':M.pin(bodies['LICENSE-MODEL'])},
            outputs=[dict(name=name,version='6.12.0-1',arch='aarch64',filename=name+'-6.12.0-1-aarch64.pkg.tar.xz')],
            dependencies=dict(depends=['glibc'],makedepends=['cmake'],checkdepends=['python']),check_required=True,
            features=['MODEL'],declared_peak_writable_bytes=1024,Root_acceptance=None,official_0bd04f_correspondence='HELD')
        return repo,base,value

    def preparation_model(self):
        out = self.root/'Source';writer = M.Writer(out);rows = {}
        try:
            for i in range(21):rows['MODEL-'+str(i)] = writer.put('MODEL-'+str(i),raw=b'MODEL_ONLY')
            mapping = dict(schema=1,kind='QT612_REFERENCE_PREPARATION_SOURCE_ONLY_V1',files=rows,
                actual=dict.fromkeys(M.ACTUAL),operational_entry=None,Root_acceptance=None,native_dispatch_ready=False)
            raw = M.encoded(mapping);writer.put('source-map.json',raw=raw)
        finally:writer.close()
        return out,mapping,M.pin(raw)['sha256']

    def test_recipe_pins_and_srcinfo_are_data_not_native_acceptance(self):
        repo,_,value = self.recipe();checked,bodies = M.recipe_contract(value,repo,{})
        self.assertEqual(checked,value);self.assertIn('PKGBUILD',bodies)
        self.assertIsNone(checked['Root_acceptance'])

    def test_unfrozen_recipe_revision_refuses(self):
        repo,_,value = self.recipe();value['recipe_commit'] = None
        with self.assertRaisesRegex(ValueError,'FROZEN_INDEPENDENT'):M.recipe_contract(value,repo,{})

    def test_old_official_correspondence_cannot_be_claimed(self):
        repo,_,value = self.recipe();value['official_0bd04f_correspondence'] = 'PASS'
        with self.assertRaisesRegex(ValueError,'FROZEN_INDEPENDENT'):M.recipe_contract(value,repo,{})

    def test_changed_recipe_body_and_mode_refuse(self):
        repo,base,value = self.recipe();p = base/'PKGBUILD';raw = p.read_bytes();p.write_bytes(b'X'+raw[1:])
        with self.assertRaisesRegex(ValueError,'STABLE_WHOLE'):M.recipe_contract(value,repo,{})
        p.write_bytes(raw);p.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'EXACT_PINNED_LEAF'):M.recipe_contract(value,repo,{})

    def test_unknown_recipe_file_and_directory_refuse(self):
        repo,base,value = self.recipe();p = base/'foreign';p.write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError,'EXACT_COMPLETE_RECIPE_NAMESPACE'):M.recipe_contract(value,repo,{})
        p.unlink();p.mkdir()
        with self.assertRaisesRegex(ValueError,'FOREIGN_RECIPE_DIRECTORIES'):M.recipe_contract(value,repo,{})

    def test_empty_directory_fanout_is_bounded(self):
        repo,base,value = self.recipe()
        for i in range(513):(base/('empty'+str(i))).mkdir()
        with self.assertRaisesRegex(ValueError,'RECIPE_NAMESPACE_BOUND'):M.recipe_contract(value,repo,{})

    def test_source_alias_and_checksum_must_join_srcinfo(self):
        repo,_,value = self.recipe();value['sources']['src.tar.xz']['sha256'] = 'f'*64
        with self.assertRaisesRegex(ValueError,'SOURCE_ALIAS_AND_SHA256'):M.recipe_contract(value,repo,{})

    def test_output_version_cannot_drift_from_pkgrel(self):
        repo,_,value = self.recipe();row = value['outputs'][0];row['version'] = '6.12.0-999';row['filename'] = row['name']+'-6.12.0-999-aarch64.pkg.tar.xz'
        with self.assertRaisesRegex(ValueError,'EXACT_XZ_OUTPUT'):M.recipe_contract(value,repo,{})

    def test_arch_specific_dependencies_cannot_be_omitted(self):
        repo,base,value = self.recipe();p = base/'.SRCINFO';raw = p.read_bytes()+b'makedepends_aarch64 = MODEL-missing\n';p.write_bytes(raw);value['files']['.SRCINFO'] = dict(M.pin(raw),mode=0o644)
        with self.assertRaisesRegex(ValueError,'DEPENDENCY_EQUALITY'):M.recipe_contract(value,repo,{})

    def test_check_and_xz_contract_cannot_be_dropped(self):
        repo,_,value = self.recipe();value['check_required'] = False
        with self.assertRaisesRegex(ValueError,'CHECK_AND_XZ'):M.recipe_contract(value,repo,{})

    def test_unsigned_or_self_binary_dependency_is_not_accepted(self):
        repo,base,value = self.recipe();name = value['outputs'][0]['name'];p = base/'.SRCINFO';raw = p.read_bytes()+('depends = '+name+'\n').encode();p.write_bytes(raw);value['files']['.SRCINFO'] = dict(M.pin(raw),mode=0o644);value['dependencies']['depends'].append(name)
        with self.assertRaisesRegex(ValueError,'SELF_BINARY'):M.recipe_contract(value,repo,{})

    def test_license_notice_pin_is_part_of_exact_recipe(self):
        repo,_,value = self.recipe();value['licenses']['LICENSE-MODEL']['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError,'LICENSE_NOTICE'):M.recipe_contract(value,repo,{})

    def test_positive_preparation_source_always_denies_native(self):
        root,_,sha = self.preparation_model();result = M.admitted_preparation(root,sha)
        self.assertFalse(result['native_dispatch_ready']);self.assertIsNone(result['Root_acceptance'])
        with self.assertRaisesRegex(ValueError,'NO_OPERATIONAL_RUNTIME'):M.native_gate(result)

    def test_source_pin_and_extra_file_refuse(self):
        root,_,sha = self.preparation_model()
        with self.assertRaisesRegex(ValueError,'STABLE_WHOLE'):M.admitted_preparation(root,'0'*64)
        (root/'foreign').write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError,'COMPLETE_PREPARATION_SOURCE_NAMESPACE'):M.admitted_preparation(root,sha)

    def test_source_actual_or_operational_entry_cannot_be_promoted(self):
        root,mapping,_ = self.preparation_model();mapping['actual']['run'] = '123';raw = M.encoded(mapping);(root/'source-map.json').write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'UNISSUED_CLOSED'):M.admitted_preparation(root,M.pin(raw)['sha256'])

    def test_source_mode_refuses(self):
        root,_,sha = self.preparation_model();(root/'MODEL-0').chmod(0o600)
        with self.assertRaisesRegex(ValueError,'EXACT_PINNED_LEAF'):M.admitted_preparation(root,sha)

    def test_symlink_hardlink_and_private_home_refuse(self):
        p = self.root/'input';p.write_bytes(b'MODEL');p.chmod(0o600);ref = M.pin(b'MODEL')
        link = self.root/'link';link.symlink_to(p)
        with self.assertRaisesRegex(ValueError,'ORDINARY_PUBLIC'):M.stream(link,ref,{})
        link.unlink();os.link(p,link)
        with self.assertRaisesRegex(ValueError,'EXACT_PINNED_LEAF'):M.stream(p,ref,{})
        with self.assertRaisesRegex(ValueError,'ORDINARY_PUBLIC'):M.ordinary(self.root/'.gnupg'/'private')

    def test_private_umask_does_not_drift_source_modes(self):
        previous = os.umask(0o077)
        try:
            root,_,sha = self.preparation_model()
            self.assertEqual((root/'MODEL-0').stat().st_mode&0o777,0o644)
            M.admitted_preparation(root,sha)
        finally:os.umask(previous)

    def test_retained_basis_policy_and_signed_role_plan(self):
        repo = HERE.parents[2];observed = {};basis = M.load(HERE/'basis.lock.json',M.BASIS_PIN,observed)
        policy = M.load(HERE/'resource-PROPOSAL.json',M.POLICY_PIN,observed)
        self.assertIsNone(policy['Root_acceptance']);self.assertFalse(policy['accepted']);self.assertFalse(policy['measured'])
        self.assertEqual(basis['Source85_Root_closure_review'],'PENDING')
        def body(member):
            row = basis['framework_files'][member]
            return M.stream(repo/member,{k:row[k] for k in ('bytes','sha256')},observed,collect=True)
        lock = M.decode(body('scripts/ci/inputs.lock.json'));baseline = body('scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock')
        plan = M.signed_input_plan(lock,baseline,None)
        self.assertEqual(len(plan['existing_metadata_roles']),501);self.assertEqual(len(plan['supplemental_packages']),8)
        self.assertEqual(plan['required_material_roles'],517);self.assertEqual(plan['bound_material_roles'],0)
        self.assertFalse(plan['unsigned_dependency_install_allowed']);self.assertIsNone(plan['recipe_dependencies'])
        self.assertEqual(policy['docker_cli']['normal_AS_bytes'],512*1024**2)
        self.assertEqual(policy['docker_cli']['canonical_observed_docker_AS_bytes'],2*1024**3)

    def test_actor_and_kernel_custody_calls_are_refused(self):
        for event in ('subprocess.Popen','socket.connect','ctypes.dlopen','resource.setrlimit','os.pidfd_open','fcntl.flock'):
            with self.assertRaisesRegex(ValueError,'NO_ACTORS_OR_KERNEL_CUSTODY'):M.fence(event,())

    def test_duplicate_or_nonfinite_selection_refuses(self):
        for raw in (b'{"accepted":false,"accepted":true}',b'{"limit":NaN}'):
            with self.assertRaises(ValueError):M.decode(raw)


if __name__ == '__main__':unittest.main()
