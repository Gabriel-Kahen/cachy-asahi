# SPDX-License-Identifier: MIT
"""End-to-end controller and guest evidence controls without a VM actor."""

from base64 import b64decode
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_controller as controller_checks
import test_trial as trial_checks

C = controller_checks.C
T = trial_checks.T
G = T.first_login_module(T.read(T.first_login_sources()['guest.py'], collect=False))
NONCE = '4'*32
SIGNER = 'A9'*20
REHEARSAL = dict(fingerprint=SIGNER,created=1794701213,expires=1794787613,test_only=True)


class FirstLoginIntegration(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='overlay583-first-login-fenced-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.packet, receipt, self.before = trial_checks.model_inputs()
        raw = T.encoded(receipt)
        self.packet = T.admit(self.packet,raw,T.pin(raw))
        self.after = T.sorted_rows(self.before+b'cachy-asahi-first-login 0.1.0-2\n')
        guest = T.read(T.first_login_sources()['guest.py'],collect=False)
        self.supplement = dict(receipt=T.pin(b'fixture manifest'),files={'guest.py':guest},
                               after=T.pin(self.after),rehearsal=REHEARSAL)
        self.plan = T.selected_plan(self.packet,NONCE,first_login=self.supplement)

    def test_plan_reuses_fresh_phases_and_refuses_every_combined_operation(self):
        original = T.guest_plan(self.packet,NONCE)
        self.assertEqual(self.plan,dict(original,kind=T.FIRST_LOGIN_KIND,first_login=self.supplement))
        self.assertEqual(T.evidence_names(self.plan),T.evidence_names(original)|{T.FIRST_LOGIN_EVIDENCE})
        for mode in ({'lifecycle':True},{'signature_recovery':True},{'predecessor':self.work},
                     {'predecessor_pin':{'sha256':'a'*64}}):
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'only one Overlay583 operation'):
                T.selected_plan(self.packet,NONCE,first_login=self.supplement,**mode)
        with self.assertRaisesRegex(ValueError,'add exactly one package'):
            T.selected_plan(self.packet,NONCE,first_login=dict(self.supplement,after=T.pin(self.before)))

    def test_controller_bound_first_login_media_are_readonly_and_separate(self):
        staging,worker = self.work/'staging',self.work/'trial.py'
        staging.mkdir()
        (staging/'target.lock').write_bytes(self.before)
        worker.write_bytes(b'fixture worker')
        supplement=self.work/'supplement'
        supplement.mkdir()
        (supplement/'supplement.json').write_bytes(b'fixture manifest')
        (supplement/'guest.py').write_bytes(T.first_login_sources()['guest.py'].read_bytes())
        packet=dict(self.packet,files={},trust={},aliases={})
        pack=self.work/'packed'
        with (
            patch.object(C,'runtime_payload',return_value={}),
            patch.object(C.T,'first_login_selection',return_value=self.supplement) as checked,
        ):
            selected=T.encoded(dict(self.plan,packet=packet))
            files,_,_=C.input_tree(staging,worker,T.pin(worker.read_bytes()),selected,pack,first_login=supplement)
            checked.assert_called_once_with(supplement,self.supplement['receipt']['sha256'])
        self.assertEqual({k for k in files if k.startswith('inputs/')},{'inputs/target.lock'})
        self.assertEqual(files['code/first-login/supplement.json'],self.supplement['receipt'])
        self.assertEqual(files['code/first-login/guest.py'],self.supplement['files']['guest.py'])
        self.assertEqual((pack/'code/first-login/guest.py').stat().st_mode&0o777,0o444)

    def execute(self, *, refusal=False, journey_failure=False):
        inputs=self.work/'inputs'
        work=self.work/'work'
        work.mkdir()
        trust={}
        for name in T.GPG_PATHS:
            path=inputs/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(name.encode())
            trust[name]=T.pin(name.encode())
        plan=dict(self.plan,packet=dict(self.packet,trust=trust,files={},aliases={}))
        output=work/'evidence'
        self.argv=G.command_plan(work,work/'target',work/'pacman.conf',NONCE)
        report=self.journey()
        addon=dict(status=G.PASS,before=T.pin(self.before),installed=T.pin(self.after),after_removal=T.pin(self.before),
                   journey=report,provenance=dict(package_arch='any',host_build='x86_64',native_arm_build='NOT RUN',
                                                original_test_signer=G.SIGNER),rehearsal=REHEARSAL,native_arm_build='NOT RUN',M2='NOT RUN',Root_acceptance=None)
        def run_addon(_trial, **data):
            self.assertEqual(data['nonce'],NONCE)
            self.assertEqual(data['supplement_sha256'],self.supplement['receipt']['sha256'])
            for role,args in self.argv.items():
                data['command'](role,args,20)
            return addon
        shim=SimpleNamespace(ROLES=G.ROLES,evidence=G.evidence,run=run_addon)
        plan['operations']=[[
            role,[str(work/'target') if word==str(T.TARGET) else word for word in argv],seconds
        ] for role,argv,seconds in plan['operations']]

        def command(argv,**kwargs):
            if argv[0]=='/usr/bin/gpgconf':
                return SimpleNamespace(returncode=0)
            role=Path(kwargs['stdout'].name).name.removesuffix('.stdout')
            data={
                'resolve':T.pacman_plan(plan['packet']),'query':self.before,'first-login-base':self.before,
                'first-login-installed':self.after,'first-login-removed':self.before,
                'first-login-verify-signature':(f'[GNUPG:] GOODSIG {SIGNER[-16:]} fixture\n'
                                                 f'[GNUPG:] VALIDSIG {SIGNER} 2026-11-15 1794701213 0 4 0 1 10 00 {SIGNER}\n').encode(),
                'first-login-installed-journey':T.encoded(report),
            }
            kwargs['stdout'].write(data.get(role,b''))
            if role=='install':
                (output/'pacman.log').write_bytes(b'fixture base pacman log\n')
            if journey_failure and role=='first-login-installed-journey':
                kwargs['stderr'].write(b'bounded failed fixture command diagnostic\n')
                return SimpleNamespace(returncode=2)
            return SimpleNamespace(returncode=7 if refusal and role=='first-login-verify-signature' else 0)

        with (
            patch.multiple(T,WORK=work,IN=inputs,TARGET=work/'target',CONFIG=work/'pacman.conf',OUTPUT=output),
            patch.object(T,'check_repos'), patch.object(T,'target_api_mounts'),
            patch.object(T.subprocess,'run',side_effect=command), patch.dict(sys.modules,{T.__name__:T}),
        ):
            rc=T.execute_guest(plan,self.before,{},time.monotonic()+10,first_login=shim)
        return rc,output,plan

    def journey(self):
        steps=['first-login-overlay583-'+value for value in (
            'identity','fish-version','zsh-version','inspect','preview','apply','workspace-marker',
            'first-fish','first-zsh','user-edits','repeat-after-edit','edited-fish','edited-zsh',
            'deactivate-preview','deactivate','removed-fish','removed-zsh','interrupted-setup',
            'pending-inspect','pending-new-selection-refused','recover-preview','recover',
            'recovered-fish','recovered-zsh','final-deactivate','final-fish','final-zsh')]
        actor=[]
        for name in steps:
            code=75 if name.endswith('interrupted-setup') else 2 if any(name.endswith(x) for x in (
                'pending-inspect','pending-new-selection-refused','recover-preview')) else 0
            actor.append(dict(step=name,expected=code,receipt=dict(exit=code,reaped=True,ownership='REAPED',
                group_census='EMPTY_TWICE',output_complete=True,timeout=False,signals=[],error=None)))
        return dict(status='PASS',template_profile='fish0.1.0-1-zsh0.1.0-1',uid=G.UID,user=G.ACCOUNT,
                    command_count=27,shell_startups=10,ordered_steps=steps,actor_commands=actor,
                    recovery_confirmed=True,final_components_deactivated=True,template_and_program_preservation=True,
                    pty='NOT RUN',graphical_login='NOT RUN',
                    user_edit_preservation={'.config/fish/config.fish':'a'*64,'.zshrc':'b'*64})

    def read_fixture(self, output, plan, *, held=False):
        with patch.object(G,'command_plan',return_value=self.argv),patch.object(T,'first_login_module',return_value=G):
            return T.read_result(output,plan,held=held)

    def test_raw_guest_completion_and_readback_refuse_resealed_wrong_argv(self):
        rc,output,plan=self.execute()
        self.assertEqual(rc,0)
        observed=self.read_fixture(output,plan)
        self.assertEqual(observed['status'],'MATCHED_DISPOSABLE_OVERLAY583_FIRST_LOGIN_EVIDENCE')
        self.assertEqual(observed['first_login']['installed'],T.pin(self.after))
        body=output/T.FIRST_LOGIN_EVIDENCE
        value=T.decode(body.read_bytes())
        command=next(row for row in value['commands'] if row['role']=='first-login-install')
        command['argv'][-1]+='.foreign'
        body.write_bytes(T.encoded(value))
        root=output/'result.json'
        result=T.decode(root.read_bytes())
        result['first_login']=T.pin(body.read_bytes())
        root.write_bytes(T.encoded(result))
        with self.assertRaisesRegex(ValueError,'original command or exit differs'):
            self.read_fixture(output,plan)

    def test_actor_refusal_exports_only_received_first_login_command_prefix(self):
        rc,output,plan=self.execute(refusal=True)
        self.assertEqual(rc,T.LIFECYCLE_HOLD_EXIT)
        result=self.read_fixture(output,plan,held=True)
        self.assertEqual(result['status'],T.FIRST_LOGIN_HOLD)
        self.assertIsNone(result['first_login'])
        commands=T.decode((output/T.FIRST_LOGIN_EVIDENCE).read_bytes())['commands']
        self.assertEqual(commands[-1]['role'],'first-login-verify-signature')
        self.assertEqual(commands[-1]['exit'],7)
        self.assertNotIn('first-login-install',[row['role'] for row in commands])

    def test_journey_hold_exports_its_diagnostic_in_the_addon_stderr(self):
        rc,output,plan=self.execute(journey_failure=True)
        self.assertEqual(rc,T.LIFECYCLE_HOLD_EXIT)
        result=self.read_fixture(output,plan,held=True)
        self.assertEqual(result['status'],T.FIRST_LOGIN_HOLD)
        self.assertEqual(result['phase'],'first-login-installed-journey')
        self.assertIsNone(result['first_login'])
        commands=T.decode((output/T.FIRST_LOGIN_EVIDENCE).read_bytes())['commands']
        self.assertEqual(commands[-1]['role'],'first-login-installed-journey')
        self.assertEqual(commands[-1]['exit'],2)
        self.assertEqual(b64decode(commands[-1]['stderr'],validate=True),b'bounded failed fixture command diagnostic\n')
        self.assertNotIn('first-login-uninstall',[row['role'] for row in commands])


if __name__=='__main__':
    unittest.main(verbosity=2)
