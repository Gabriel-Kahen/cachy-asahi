#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure generic policy input maps, never platform/hardware observations."""
from copy import deepcopy
import unittest
import generic_policy as policy


class GenericPolicy(unittest.TestCase):
    def setUp(self):
        self.before={'glibc':'1-1','pacman':'1-1','linux-aarch64':'1-1','fixture':'0-1',
                     **{f'held-{i:03d}':'1-1' for i in range(583)}}
        self.after=dict(self.before,fixture='1-1')
        names=['glibc','linux-aarch64','pacman']
        self.policy=dict(schema_version=1,purpose='cachy-asahi-generic-development-update-policy',release_id='fixture-1',
            protected_packages=names,protected_versions={name:self.before[name] for name in names},
            platform_roles={'kernel':['linux-aarch64']},
            protected_units={scope:sorted(units) for scope,units in policy.asahi.REQUIRED_UNITS.items()},
            before_lock_sha256=policy.lock_sha(self.before),after_lock_sha256=policy.lock_sha(self.after))
        self.settings=dict(purpose='disposable-generic-bound-update',model='generic-development-only',release_id='fixture-1')
        self.snapshot={'release':{'release_id':'fixture-1'},'spec':{'policy':{'protected_packages':names}}}
        self.files={'linux-aarch64':['/usr/lib/modules/6.99.synthetic/kernel/fixture.ko']}
        self.after_files=deepcopy(self.files)

    def authorize(self):
        return policy.authorize(self.policy,self.settings,self.snapshot,self.before,self.after,self.files,self.after_files)

    def test_explicit_generic_acceptance_makes_no_apple_claim(self):
        row=self.authorize()
        self.assertEqual(row['decision'],'generic-development-transaction-allowed')
        self.assertEqual(row['apple_acceptance'],'NOT ESTABLISHED')
        self.assertNotIn('speakersafetyd',self.before)

    def test_wrong_model_purpose_and_phase_refuse(self):
        for key,value in (('model','apple,j413'),('purpose','production')):
            with self.subTest(key=key):
                old=self.settings[key];self.settings[key]=value
                with self.assertRaisesRegex(ValueError,'explicit generic'):self.authorize()
                self.settings[key]=old
        with self.assertRaisesRegex(ValueError,'phase'):
            policy.authorize(self.policy,self.settings,self.snapshot,self.before,self.after,self.files,self.files,phase='services')

    def test_any_held_version_drift_refuses_exact_locks(self):
        self.after['held-001']='2-1'
        with self.assertRaisesRegex(ValueError,'locks'):self.authorize()

    def test_protected_change_refuses_even_when_new_lock_is_supplied(self):
        self.after['glibc']='2-1';self.policy['after_lock_sha256']=policy.lock_sha(self.after)
        with self.assertRaisesRegex(ValueError,'protected package versions'):self.authorize()

    def test_actual_kernel_ownership_change_refuses(self):
        self.after_files['linux-aarch64']=['/usr/lib/modules/6.99.synthetic/kernel/changed.ko']
        with self.assertRaisesRegex(ValueError,'kernel ownership'):self.authorize()

    def test_signed_protected_selection_and_policy_purpose_must_match(self):
        self.snapshot['spec']['policy']['protected_packages']=['glibc','pacman']
        with self.assertRaisesRegex(ValueError,'authenticated release'):self.authorize()
        self.policy['purpose']='cachy-asahi-apple-update-policy'
        with self.assertRaisesRegex(ValueError,'generic development policy'):policy.protected_names(self.policy)


if __name__=='__main__':unittest.main(verbosity=2)
