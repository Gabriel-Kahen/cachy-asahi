#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert exact574 tooling selection; no network, GPG, package or VM actors."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())


def load(name,path):
    spec=importlib.util.spec_from_file_location('tooling_selection_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


prepare=load('prepare',HERE/'prepare.py')
ci=load('ci',HERE/'ci.py')
accepted=load('accepted',ROOT/'scripts/ci/desktop574_runtime.py')
INPUTS=json.loads((ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
LOCK=json.loads((ROOT/'scripts/virtual/tooling.lock.json').read_bytes())
BASE={r['name']:r['version'] for r in INPUTS['packages']}
BASE_BYTES=''.join(n+' '+v+'\n' for n,v in sorted(BASE.items())).encode()


def signature(row):
    return dict(filename=row['filename']+'.sig',sha256=row['signature_sha256'],size=row['signature_size'])


class SelectionControls(unittest.TestCase):
    def test_exact574_known_tuple_preserved_and_accepted_additions_match(self):
        self.assertEqual(hashlib.sha256(BASE_BYTES).hexdigest(),prepare.BUILDER_LOCK)
        extra=prepare.tooling_additions(BASE,LOCK['packages'])
        self.assertEqual(extra,accepted.additions(BASE,LOCK));self.assertEqual(len(extra),16)
        union=prepare.union_inventory(BASE,LOCK['packages'])
        self.assertEqual(len(union),590);self.assertEqual({n:union[n] for n in BASE},BASE)
        self.assertEqual(union['snappy'],'1.3.1-1')
        self.assertNotIn('snappy',{r['name'] for r in extra})
    def test_only_the_declared_snappy_versions_are_exempt(self):
        for name,new_version in (('snappy','1.2.2-4'),('fuse3','999-1'),('numactl','999-1')):
            rows=copy.deepcopy(LOCK['packages']);next(r for r in rows if r['name']==name)['version']=new_version
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'replacement'):prepare.tooling_additions(BASE,rows)
    def test_exception_cannot_authorize_another574_inventory(self):
        for change in (dict(snappy='1.3.1-2'),dict(glibc='other')):
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'replacement'):
                prepare.tooling_additions(dict(BASE,**change),LOCK['packages'])
    def test_wrong_count_or_duplicate_still_refuses(self):
        rows=copy.deepcopy(LOCK['packages']);rows[-1]=rows[0]
        for base,tooling in (({k:v for k,v in BASE.items() if k!='snappy'},LOCK['packages']),
                             (BASE,rows),(BASE,LOCK['packages'][:-1])):
            with self.assertRaises(ValueError):prepare.tooling_additions(base,tooling)
    def test_only16_archives_signatures_and_public_keyring_rows_selected(self):
        selected=prepare.tooling_inputs(BASE,LOCK,signature)
        extra=accepted.additions(BASE,LOCK)
        self.assertEqual(selected,LOCK['keyring_files']+[x for row in extra for x in (row,signature(row))])
        self.assertEqual(len(selected),35)
        names={r['filename'] for r in selected}
        for row in LOCK['packages']:
            self.assertEqual(row['filename'] in names,row['name'] not in BASE)
            self.assertEqual(row['filename']+'.sig' in names,row['name'] not in BASE)
    def test_ci_uses_same_exact_builder_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            ready=Path(temp);(ready/'builder-packages.lock').write_bytes(BASE_BYTES)
            (ready/'manifest.json').write_text(json.dumps(dict(builder_lock=dict(path='builder-packages.lock',sha256=prepare.BUILDER_LOCK))))
            self.assertEqual(ci.selected_tooling_inputs(ready,LOCK,prepare,SimpleNamespace(signature=signature)),
                             prepare.tooling_inputs(BASE,LOCK,signature))
            (ready/'builder-packages.lock').write_bytes(BASE_BYTES+b'other 1\n')
            with self.assertRaisesRegex(ValueError,'exact original574'):ci.selected_tooling_inputs(ready,LOCK,prepare,SimpleNamespace(signature=signature))


class ToolingBoundaryControls(unittest.TestCase):
    def invoke(self,failure=None):
        extra=accepted.additions(BASE,LOCK)
        auditor=SimpleNamespace(validate_lock=Mock(),signature=signature,verify=Mock(),inspect=Mock(return_value={'hooks':{}}))
        if failure=='signature':auditor.verify.side_effect=ValueError('INERT bad signature')
        if failure=='hooks':auditor.inspect.return_value={'hooks':{'bad.hook':'INERT'}}
        command=Mock(return_value={'stdout':'INERT verifier output'}); report={}
        c=dict(builder_inventory=BASE,tooling_inventory=prepare.union_inventory(BASE,LOCK['packages']))
        with patch.dict(sys.modules,{'audit_tooling':auditor}),patch.object(prepare,'installed') as installed,\
             patch.object(prepare,'checked_file') as checked,patch.object(Path,'glob',return_value=[]):
            if failure:
                with self.assertRaises(ValueError):prepare.tooling(c,LOCK,object(),command,report)
                self.assertNotIn('status',report)
            else:prepare.tooling(c,LOCK,object(),command,report)
            return extra,auditor,command,report,installed,checked
    def test_verifies_only_missing_inputs_and_installs_exact16_then_exact_inventory(self):
        extra,auditor,command,report,installed,checked=self.invoke()
        self.assertEqual(auditor.verify.call_count,16);self.assertEqual(auditor.inspect.call_count,16)
        self.assertEqual(checked.call_count,35)
        selected=prepare.tooling_inputs(BASE,LOCK,signature)
        self.assertEqual({call.args[1]:call.args[2] for call in checked.call_args_list},
                         {r['filename']:dict(sha256=r['sha256'],bytes=r['size']) for r in selected})
        self.assertTrue(all(call.args[1]==LOCK['signer_fingerprint'] for call in auditor.verify.call_args_list))
        self.assertEqual([call.args[1] for call in auditor.inspect.call_args_list],extra)
        argv=[call.args[0] for call in command.call_args_list]
        install=next(row for row in argv if row[0]=='/usr/bin/pacman')
        self.assertIn('--noscriptlet',install)
        self.assertEqual(install[install.index('-U')+1:],['/tooling-cache/'+r['filename'] for r in extra])
        self.assertEqual([call.args[1] for call in installed.call_args_list],
                         [BASE,prepare.union_inventory(BASE,LOCK['packages'])])
        self.assertEqual(report['preserved_tooling']['snappy'],'1.3.1-1')
        self.assertEqual(report['added_tooling'],[r['name'] for r in extra]);self.assertEqual(report['status'],'TOOLING_READY')
        self.assertIn(['/usr/bin/ldconfig'],argv)
    def test_bad_signature_refuses_installation_and_still_requests_owned_key_cleanup(self):
        _,auditor,command,_,_,_=self.invoke('signature')
        self.assertEqual(auditor.verify.call_count,1);self.assertEqual(auditor.inspect.call_count,0)
        argv=[call.args[0] for call in command.call_args_list]
        self.assertFalse(any(row[0]=='/usr/bin/pacman' for row in argv));self.assertEqual(argv[-1][0],'/usr/bin/gpgconf')
    def test_hook_refusal_keeps_installation_disabled(self):
        _,auditor,command,_,_,_=self.invoke('hooks')
        self.assertEqual(auditor.verify.call_count,1);self.assertEqual(auditor.inspect.call_count,1)
        self.assertFalse(any(call.args[0][0]=='/usr/bin/pacman' for call in command.call_args_list))


if __name__=='__main__':unittest.main()
