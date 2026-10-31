# SPDX-License-Identifier: MIT
"""Focused inert controls, actual disposable metadata/files; no native/VM/container actors."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import contract as C
import adapter as A
import installed604 as I
import ci
ROOT=Path(os.environ.get('EXPANDED604_MANAGED_SOURCE',Path.cwd()))

class Lane(unittest.TestCase):
    def test_unbound_first_before_source_or_output(self):
        with patch.object(C,'revision',side_effect=AssertionError('observed source')):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):ci.preflight(type('Args',(),{})())
    def test_duplicate_nonfinite_and_unsafe_refs_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'x'
            for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
                p.write_bytes(raw)
                with self.assertRaises(ValueError):C.json_read(p)
            with self.assertRaises(ValueError):C.checked(root,dict(path='../outside',bytes=1,sha256='a'*64))
    def test_copy_of_protected_modes_is_exact_and_not_reentrant(self):
        for name in ('management_root.py','management_phase.py','management_contract.py'):
            before=(ROOT/'scripts/ci/welcome-management-native'/name).read_text();after=A.transform_counts(before,name)
            ast.parse(after);self.assertNotIn('==594',after);self.assertNotIn('==592',after)
            with self.assertRaises(ValueError):A.transform_counts(after,name)
            for guard in ('signal.pidfd_send_signal','alpm_trans_release','base.guard(True)'):
                self.assertEqual(before.count(guard),after.count(guard))
    def generated(self,path):
        native=C.load(ROOT,'scripts/ci/welcome-management-native/prepare.py');N=native.C;candidate=native.candidates
        UI=N.policy(False)['ui']
        def stage(source,assets,output):
            output.mkdir();lock=dict(status='SYNTHETIC_TEMPLATE_CONTROL_ONLY',eligibility='PRIVATE_GUI_TRIAL_ONLY',products={},policy=dict(ui=UI));(output/'candidate-lock.json').write_bytes(C.encoded(lock));return lock
        ready=path/'ready';ready.mkdir();(ready/'manifest.json').write_text('{"packages":[]}')
        with patch.object(C,'check_source'),patch.object(N,'verify_source'),patch.object(candidate,'verify_source'),patch.object(N,'policy',return_value=dict(ui=UI)),patch.object(candidate,'stage',side_effect=stage):
            A.prepare(ROOT,path/'runner',path/'assets',ready)
        return path/'runner'
    def test_complete_current_generator_16k_and_original_budgets(self):
        with tempfile.TemporaryDirectory() as d:
            runner=self.generated(Path(d))
            for path in runner.glob('*.py'):ast.parse(path.read_text(),filename=path.name)
            subprocess.run(['/bin/bash','-n',str(runner/'desktop574_fixture.sh')],check=True,capture_output=True)
            raw=(runner/'desktop574_runtime.py').read_text();guest=(runner/'base_guest.py').read_text();fixture=(runner/'desktop574_fixture.sh').read_text()
            self.assertIn('time.monotonic() + 1300',raw);self.assertIn('signal.ITIMER_REAL, 1750',raw)
            self.assertIn('TimeoutStartSec=1200',fixture);self.assertIn("management_root.serve(managed_base, session, env, logs, DL.service_lease()['deadline_ns'])",guest)
            self.assertLess(guest.index('    DL.service()'),guest.index('    EVENTS = wait_event_port()'))
            self.assertIn('os.sysconf(\'SC_PAGE_SIZE\')==16384',guest);self.assertIn('elf_audit.py --root',fixture)
            self.assertNotIn('hosted.fetch',raw);self.assertNotIn('LocalFileSigLevel = Optional',raw);self.assertNotIn("'package-build'",raw)
            self.assertIn('installed604_preserved',guest);self.assertIn('managed_session.SETPRIV',guest)
            self.assertEqual((runner/'doctor_lifetime.py').read_bytes(),(ROOT/'scripts/ci/welcome-management-native/doctor_lifetime.py').read_bytes())
            self.assertEqual((runner/'file_capabilities.py').read_bytes(),(ROOT/'scripts/apps/file_capabilities.py').read_bytes())
            self.assertIn('/runner/doctor_lifetime.py',fixture);self.assertIn('/runner/file_capabilities.py',fixture)
            self.assertIn('DL.service()',guest);self.assertNotIn('DL.parent()',guest);self.assertIn("supervise(main)",(runner/'doctor_worker.py').read_text())
            self.assertIn("DL.validate(finals[0]",(runner/'contract.py').read_text())
            self.assertEqual(raw.count("'minimal-management-closing'"),2)
            self.assertEqual((runner/'a11y_driver.c').read_bytes(),(ROOT/'scripts/ci/welcome-management-native/a11y_driver.c').read_bytes())
            with self.assertRaises(ValueError):A.runtime604(raw)
            code="""import sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root));import contract
assert Path(contract.M.__file__)==root/'management_contract.py'
assert 604 in contract.M.verify_result.__code__.co_consts
assert 594 not in contract.M.verify_result.__code__.co_consts
"""
            subprocess.run([sys.executable,'-I','-B','-c',code,str(runner)],check=True,capture_output=True,timeout=20)

    def test_retirement_does_not_infer_absence_from_failure(self):
        raw=dict(cleanup=[{}]*13+[dict(guest_disk_removed=True)],base_reference_cleanup=dict(ok=True))
        actor=dict(natural_exit=True,group_absent=True)
        self.assertTrue(ci.retired(raw,actor))
        for bad in (None,dict(natural_exit=False,group_absent=True),dict(natural_exit=True,group_absent=False)):self.assertFalse(ci.retired(raw,bad))
        raw['cleanup'][0]=dict(exit=1);self.assertFalse(ci.retired(raw,actor))
    def fixture(self,root):
        db=root/'var/lib/pacman/local';db.mkdir(parents=True);(db/'ALPM_DB_VERSION').write_text('9\n')
        packages={('fixture-'+str(i)):'1-1' for i in range(604)}
        for n,v in packages.items():
            p=db/(n+'-'+v);p.mkdir();(p/'desc').write_text('%NAME%\n'+n+'\n\n%VERSION%\n'+v+'\n\n%ARCH%\naarch64\n\n');(p/'files').write_bytes(b'')
        payload=root/'usr/file';payload.parent.mkdir();payload.write_bytes(b'actual bounded bytes')
        (db/'fixture-0-1-1/files').write_text('%FILES%\nusr/file\n\n')
        return packages
    def helper(self):return I.load_db(ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
    def test_real_alpm604_fileless_and_complete_payload_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);helper=self.helper();actual=I.observe(root,helper,packages)
            self.assertEqual(len(actual['packages']),604);self.assertTrue(I.verify(actual,copy.deepcopy(actual)))
            (root/'usr/file').write_bytes(b'drift')
            with self.assertRaises(ValueError):I.verify(I.observe(root,helper,packages),actual)
            with self.assertRaises(ValueError):I.observe(root,helper,packages,deadline=-1)
    def test_real_lock_symlink_hardlink_and_foreign_inventory_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);helper=self.helper();lock=root/'var/lib/pacman/db.lck';lock.touch()
            with self.assertRaises(ValueError):I.observe(root,helper,packages)
            lock.unlink();os.link(root/'usr/file',root/'outside')
            with self.assertRaisesRegex(ValueError,'hardlink'):I.observe(root,helper,packages)
            (root/'outside').unlink();packages.pop('fixture-1')
            with self.assertRaises(ValueError):I.observe(root,helper,packages)
    def test_real_complete_hardlinks_are_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);os.link(root/'usr/file',root/'usr/alias')
            (root/'var/lib/pacman/local/fixture-0-1-1/files').write_text('%FILES%\nusr/file\nusr/alias\n\n')
            observed=I.observe(root,self.helper(),packages);self.assertEqual(observed['hardlinks'],[['usr/alias','usr/file']])
    def test_complete_read_refuses_database_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);helper=self.helper();original=helper.database;calls=0
            def drifting(*args,**kwargs):
                nonlocal calls
                rows=original(*args,**kwargs);calls+=1
                if calls==2:
                    p=root/'var/lib/pacman/local/fixture-0-1-1/desc';p.write_bytes(p.read_bytes()+b'\n')
                return rows
            with patch.object(helper,'database',side_effect=drifting),self.assertRaisesRegex(ValueError,'database/root drift'):I.observe(root,helper,packages)
    def test_real_mode_and_symlinked_parent_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);helper=self.helper();before=I.observe(root,helper,packages)
            (root/'usr/file').chmod(0o600)
            with self.assertRaises(ValueError):I.verify(I.observe(root,helper,packages),before)
            (root/'usr').rename(root/'other');(root/'usr').symlink_to('other')
            with self.assertRaises((OSError,ValueError)):I.observe(root,helper,packages)
    def test_actual_root_level_package_symlink_is_retained_literally(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);(root/'bin').symlink_to('usr')
            (root/'var/lib/pacman/local/fixture-1-1-1/files').write_text('%FILES%\nbin\n\n')
            result=I.observe(root,self.helper(),packages)
            self.assertEqual(result['nodes']['bin']['type'],'symlink');self.assertEqual(result['nodes']['bin']['target'],'usr')
    def test_current604_has_only_Welcome4_Orphans2_changes(self):
        old=dict(line.split() for line in (ROOT/'scripts/ci/expanded604-composition/expected604.lock').read_text().splitlines())
        current=dict(line.split() for line in (ROOT/'scripts/ci/expanded604-current-management/expected604.lock').read_text().splitlines())
        self.assertEqual(set(old),set(current));self.assertEqual(len(current),604)
        self.assertEqual({n:current[n] for n in current if old[n]!=current[n]},dict(zip(('cachy-asahi-welcome','cachy-asahi-orphans'),('0.1.0-4','0.1.0-2'))))
        self.assertEqual(__import__('hashlib').sha256((ROOT/'scripts/ci/expanded604-current-management/expected604.lock').read_bytes()).hexdigest(),C.TARGET)
    def test_current_decisions_reject_historical_and_pair_CLI_only(self):
        # Synthetic documents exercise only the finite readonly gate; no actual receipt is issued.
        native=dict(status='ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION',source_sha='1'*40,run_id='1',cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',package_count=604,expected604_sha256=C.TARGET,installed_lifecycle='PASS',installed_six_modules='PASS',source_manifest_sha256='a'*64,input_policy_sha256='b'*64)
        gui=dict(status='ROOT_ACCEPTED_NATIVE_WELCOME4_MANAGEMENT_GUI',source_sha='2'*40,run_id='2',cleanup='PASS',hardware='NOT_RUN',release='NOT_ADMITTED',frames=24,management_operations_per_profile=17,profiles=['minimal','overlay'],welcome_version='0.1.0-4',orphans_version='0.1.0-2',candidate_source='0b74d8ecea4f152bda4adfbd9bee488890db4363',doctor_lifetime='PASS_ACTUAL_CHILD_WAIT_RELEASE_AND_FIXED_PARENT',gui_contract='PASS',source_manifest_sha256='c'*64)
        value={k:dict(source_sha=d['source_sha'],run_id=d['run_id'],carrier_source='3'*40,decision=dict(path='decision.json',bytes=1,sha256='d'*64),source_manifest_sha256=d['source_manifest_sha256'],**({'input_policy_sha256':d['input_policy_sha256']} if k=='native604' else {})) for k,d in (('native604',native),('welcome4_gui',gui))}
        with patch.object(C,'revision',return_value='3'*40),patch.object(C,'checked',side_effect=lambda root,row,cap:root):
            with patch.object(C,'json_read',side_effect=[native,gui]):self.assertEqual(C.decisions(Path('/native'),Path('/gui'),value)['welcome4_gui'],gui)
            for field,bad in (('status','ROOT_ACCEPTED_WELCOME4_NATIVE_PAIR_AND_SIGNED_INSTALLED_CLI_ONLY'),('welcome_version','0.1.0-2'),('doctor_lifetime','UNKNOWN'),('frames',12)):
                changed=dict(gui);changed[field]=bad
                with self.subTest(field=field),patch.object(C,'json_read',side_effect=[native,changed]),self.assertRaises(ValueError):C.decisions(Path('/native'),Path('/gui'),value)
            with patch.object(C,'json_read',side_effect=[dict(native,status='ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION'),gui]),self.assertRaises(ValueError):C.decisions(Path('/native'),Path('/gui'),value)
    def test_complete_owned_capability_map_and_unknown_xattr_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);packages=self.fixture(root);helper=self.helper();before=I.observe(root,helper,packages)
            self.assertEqual(before['capabilities'],{})
            # Real ordinary tempfile xattr refusal, without privileged capability mutation.
            os.setxattr(root/'usr/file','user.caa-fixture',b'refuse')
            with self.assertRaisesRegex(ValueError,'unknown xattr'):I.observe(root,helper,packages)
            os.removexattr(root/'usr/file','user.caa-fixture')
            caps=I.capabilities();raw=bytes.fromhex('0100000240000000000000000000000000000000');caps.validate(raw)
            # Exact retained Linux layout; this injected read is a host source control, not actual capability evidence.
            original=caps._attrs
            def observed(fd,kind,limits,*args):return raw.hex() if kind=='file' else original(fd,kind,limits,*args)
            with patch.object(I,'capabilities',return_value=caps),patch.object(caps,'_attrs',side_effect=observed):after=I.observe(root,helper,packages)
            self.assertEqual(after['capabilities'],{'usr/file':raw.hex()})
            with self.assertRaises(ValueError):I.verify(after,before)

    def test_workflow_authority_order_and_all_shells_parse(self):
        workflow=C.HERE.parents[2]/'.github/workflows/native-arm-expanded604-current-management-managed16k.yml'
        text=workflow.read_text();self.assertLess(text.index('--preflight'),text.index('--decisions-only'))
        self.assertLess(text.index('--decisions-only'),text.index('Retrieve only the six'))
        self.assertLess(text.index('Verify actual Root decisions and accepted archive bytes before secrets'),text.index('secrets.CACHY'))
        self.assertNotIn('expanded604-current-management-managed16k-vm',text)
        self.assertIn('3700s',text);self.assertIn('15600s',text);self.assertIn('timeout-minutes: 350',text)
        import textwrap
        lines=text.splitlines();count=0
        for i,line in enumerate(lines):
            if line.strip()!='run: |':continue
            end=i+1
            while end<len(lines) and (not lines[end].strip() or len(lines[end])-len(lines[end].lstrip())>8):end+=1
            block=textwrap.dedent('\n'.join(lines[i+1:end]))
            subprocess.run(['/bin/bash','-n'],input=block,text=True,check=True,capture_output=True);count+=1
        self.assertGreaterEqual(count,15)
if __name__=='__main__':unittest.main()
