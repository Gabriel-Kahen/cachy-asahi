# SPDX-License-Identifier: MIT
"""Finite604 selection and private materialization controls; never native evidence."""
import ast
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contract as C
import materializer as M


class Core(unittest.TestCase):
    def test_exact604_lock_and_only_two_predecessors(self):
        before,after=C.locks();incoming={n:after[n] for n in C.ADDITIONS|C.UPGRADES.keys()}
        self.assertEqual(C.selected(before,incoming),after)
        self.assertEqual((len(before),len(after),len(incoming)),(587,604,19))
        for name in ('cachy-asahi-doctor','cachy-asahi-update','glibc'):
            bad=dict(incoming);bad[name]='changed'
            with self.subTest(name=name),self.assertRaises(ValueError):C.selected(before,bad)
        for name in C.UPGRADES:
            bad=dict(incoming);bad[name]=before[name]
            with self.subTest(name=name),self.assertRaises(ValueError):C.selected(before,bad)

    def test_unbound_policy_is_first_gate(self):
        pending=C.policy(bound=False);pending['status']='UNBOUND_FIXTURE';pending['welcome'].update(status='UNBOUND',carrier_source=None,source=None,index=None)
        with patch.object(C,'read',return_value=pending),patch.object(C,'revision',side_effect=AssertionError('Git reached')):
            with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
            with self.assertRaisesRegex(ValueError,'UNBOUND'):C.verify_source(Path('/absent'))
            with self.assertRaisesRegex(ValueError,'UNBOUND'):M.accepted(*([Path('/absent')]*8),C.policy(bound=False))

    def test_no_final_source_freeze_can_be_inferred_from_policy(self):
        value=C.policy(bound=False);value['status']='ROOT_BOUND_FINAL604_ACCEPTED_INPUTS';value['welcome'].update(
            status='ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE',source='a'*40,carrier_source='b'*40,index=dict(path='index.json',bytes=1,sha256='c'*64))
        actual=C.read
        def read(path,*a,**kw):
            if Path(path).name=='input-policy.json':return value
            result=actual(path,*a,**kw)
            if Path(path).name=='source-manifest.json':result=dict(result,status='UNBOUND_FIXTURE')
            return result
        with patch.object(C,'read',side_effect=read):
            C.policy()
            with self.assertRaisesRegex(ValueError,'UNBOUND'):C.verify_source(Path('/absent'))

    def test_shared_six_shell_validator_keeps_exact_function_ast(self):
        import os
        source=Path(os.environ.get('EXPANDED604_SOURCE',Path.cwd()))
        def function(path):return next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='validate_combined')
        self.assertEqual(ast.dump(function(C.HERE/'contract.py'),include_attributes=False),ast.dump(function(source/'scripts/ci/expanded-development-composition/contract.py'),include_attributes=False))

    def test_unbound_materialization_creates_no_target_or_signing(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'target'
            pending=C.policy(bound=False);pending['status']='UNBOUND_FIXTURE'
            with patch.object(C,'read',return_value=pending),self.assertRaisesRegex(ValueError,'UNBOUND'):M.prepare(*([Path('/absent')]*6),target,pending,*([Path('/absent')]*4))
            self.assertFalse(target.exists())


class Materialization(unittest.TestCase):
    def test_complete604_preserves585_signed_inputs_and_signs_only18(self):
        before,after=C.locks();incoming_names=C.ADDITIONS|C.UPGRADES.keys();signed=[];verified=[]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);ready=root/'original';producer=root/'producer';target=root/'target';assets=root/'assets'
            for p in (ready/'packages',ready/'keys',producer/'private/test-signing',assets):p.mkdir(parents=True)
            roles=dict(ephemeral_TEST='A'*40,upstream_ALARM='B'*40);original=[]
            for name,version in sorted(before.items()):
                archive='packages/'+name+'.original';path=ready/archive;path.write_bytes(b'original archive '+name.encode());sig=ready/(archive+'.sig');sig.write_bytes(b'original signature '+name.encode())
                original.append(dict(name=name,version=version,archive=archive,size=path.stat().st_size,sha256=C.sha(path),signature=archive+'.sig',signature_size=sig.stat().st_size,signature_sha256=C.sha(sig),signer=roles['ephemeral_TEST']))
            keys=[]
            for n in ('alarm','test'):
                p=ready/'keys'/n;p.write_bytes(b'public fixture '+n.encode());keys.append(dict(path='keys/'+n,size=p.stat().st_size,sha256=C.sha(p)))
            projects=[dict(name=n,version=before[n]) for n in list(C.UPGRADES)+sorted(set(before)-C.UPGRADES.keys())[:8]]
            source=Path(os.environ.get('EXPANDED604_SOURCE',Path.cwd()));selected=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
            builder=C.inventory_bytes({r['name']:r['version'] for r in selected['packages']});self.assertEqual(__import__('hashlib').sha256(builder).hexdigest(),C.BUILDER)
            original_manifest=dict(schema_version=1,packages=original,projects=projects,keyrings=keys,preparation=dict(signer_roles=roles),builder_lock=dict(path='builder-packages.lock',size=len(builder),sha256=C.BUILDER))
            (ready/'manifest.json').write_bytes(C.encoded(original_manifest));(ready/'builder-packages.lock').write_bytes(builder)
            incoming={}
            for name in sorted(incoming_names):
                path=assets/(name+'.accepted');path.write_bytes(b'accepted fixture '+name.encode());node=dict(type='0',mode=0o644,uid=0,gid=0,size=1,sha256='0'*64,link='',mtime=0)
                report=dict(sha256=C.sha(path),metadata={'.PKGINFO':{'pkgname':[name],'pkgver':[after[name]]}},members={'usr/share/'+name:node})
                incoming[name]=dict(name=name,version=after[name],archive=str(path),inspected=report)
                if name=='lsp-plugins-lv2':
                    sig=path.with_name(path.name+'.sig');sig.write_bytes(b'original official fixture signature');incoming[name].update(signature_size=sig.stat().st_size,signature_sha256=C.sha(sig))
            def copy_archive(source,destination,row):
                C.need(C.sha(source)==row['sha256'] and source.stat().st_size==row['size'] and not destination.exists(),'exact copy guard');destination.write_bytes(source.read_bytes());destination.chmod(0o444)
            def sign(home,paths,signer):
                self.assertEqual((home,signer),(producer/'private/test-signing',roles['ephemeral_TEST']))
                signed.extend(paths)
                for path in paths:path.with_name(path.name+'.sig').write_bytes(b'synthetic signature control')
            class Verifier:
                def __init__(self,*a):pass
                def __call__(self,archive,signature,signer):verified.append((archive,signature,signer))
                def close(self):pass
            helper=SimpleNamespace(copy_archive=copy_archive,sign=sign)
            def load(name,path):
                if path.name=='profile.py':return SimpleNamespace(manifest=lambda ready:(original_manifest,{},before))
                if path.name=='producer.py':return SimpleNamespace(PublicVerifier=Verifier)
                return SimpleNamespace(payload=lambda report:{n:r for n,r in report['members'].items()})
            with patch.object(M,'accepted',return_value=(dict(summary=dict(status='SYNTHETIC_CONTROL_ONLY')),incoming)),patch.object(C,'prerequisites'),patch.object(C,'load',side_effect=load),patch.object(C,'scoped_load',return_value=helper):
                self.assertEqual(M.prepare(ready,producer,*([root]*4),target,{},*([root]*4)),target)
            value,_,actual=C.target_manifest(target);self.assertEqual(actual,after)
            self.assertEqual(len(signed),18);self.assertEqual(len(verified),604)
            self.assertNotIn('lsp-plugins-lv2.accepted',{p.name for p in signed})
            for row in original:
                if row['name'] not in C.UPGRADES:
                    self.assertEqual((target/row['archive']).read_bytes(),(ready/row['archive']).read_bytes())
                    self.assertEqual((target/row['signature']).read_bytes(),(ready/row['signature']).read_bytes())
                else:self.assertFalse((target/row['archive']).exists())
            self.assertEqual(value['expanded604']['copied_original_archive_signatures'],585)
            self.assertEqual(len(value['projects']),21)


if __name__=='__main__':unittest.main()
