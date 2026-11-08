"""New integration controls only: DATA, AST and disposable fake-adapter root.

Never calls a capsule Reader, GPG, pacman, compiler or native execution actor.
"""
import ast
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(P/'overlay/native'),str(P/'tests')]
V=importlib.import_module('security_recovery_reader')
N=importlib.import_module('security_recovery_native')
A=importlib.import_module('test_native_adapter')
R=A.R;F=A.F;S=A.S
M=importlib.import_module('security_recovery_metadata')

def journal(binding,events=None):
    previous='0'*64;lines=[]
    for i,event in enumerate(events or V.PHASES):
        row=dict(schema=1,sequence=i,binding=binding,previous=previous,event=event,data={})
        row['sha256']=V.pin(V.encoded(row))['sha256'];previous=row['sha256'];lines.append(V.encoded(row))
    return b'\n'.join(lines).decode()+'\n'

class PassiveControls(unittest.TestCase):
    binding=dict(source='c'*40,ref='refs/heads/codex/unbound-data',run='9000000000041',attempt=1,map_sha256='b'*64,token='d'*24)
    def test_complete_passive_journal_data_no_resume(self):
        value=V.journal_data(journal(self.binding),self.binding)
        self.assertEqual(tuple(value['phases']),V.PHASES);self.assertFalse(value['resume_allowed'])
    def test_tampered_journal_hash_refused(self):
        with self.assertRaises(ValueError):V.journal_data(journal(self.binding).replace('BASELINE_RECORDED','BASELINE_CHANGED'),self.binding)
    def test_wrong_binding_refused(self):
        with self.assertRaises(ValueError):V.journal_data(journal(self.binding),dict(self.binding,run='9000000000042'))
    def test_partial_or_reordered_or_failed_journal_refused(self):
        for raw in (journal(self.binding)[:-1],journal(self.binding,list(V.PHASES[:4])+['FAILED']),journal(self.binding,list(V.PHASES[:3])+[V.PHASES[4]])):
            with self.subTest(raw=raw[-80:]),self.assertRaises(ValueError):V.journal_data(raw,self.binding)
    def test_duplicate_and_nonfinite_json_refused(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError):V.parse(raw,100)
    def test_passive_reader_imports_no_mutator(self):
        tree=ast.parse((P/'overlay/native/security_recovery_reader.py').read_bytes())
        imports={n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}
        imports|={v.name for n in ast.walk(tree) if isinstance(n,ast.Import) for v in n.names}
        self.assertFalse(imports&{'os','pathlib','subprocess','security_recovery','security_recovery_fs','security_recovery_adapter','security_recovery_journal','security_interruption_owner'})
    def test_public_armor_crc_decode_and_reject(self):
        import base64
        body=b'public DATA fixture';crc=0xB704CE
        for byte in body:
            crc^=byte<<16
            for _ in range(8):
                crc<<=1
                if crc&0x1000000:crc^=0x1864CFB
        raw=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'+base64.b64encode(body)+b'\n='+base64.b64encode((crc&0xFFFFFF).to_bytes(3,'big'))+b'\n-----END PGP PUBLIC KEY BLOCK-----\n'
        self.assertEqual(N.decode_public_armor(raw),body)
        with self.assertRaises(ValueError):N.decode_public_armor(raw.replace(b'=','=AAAA\n='.encode(),1))
    def test_overlay_keeps_normal_observer_and_closed_new_operation(self):
        contract=json.loads((P/'overlay/native/security-contract-v1.json').read_bytes())
        self.assertEqual(contract['operation'],V.OP)
        self.assertIn('recovery_block',contract['recovery']['observation']['source'])
        self.assertNotIn('recovery_block',contract['upgrade']['observation']['source'])
        helper=(P/'overlay/native/security_native_v1.py').read_text()
        self.assertLess(helper.index('recovery_context=prepare_recovery'),helper.index("c.run('prior-required-install'"))
        self.assertLess(helper.index("current=inventory('repeated-inventory')"),helper.index("recovery_context.episode"))
        self.assertLess(helper.index('recovery_context.episode'),helper.index("current=inventory('removed-inventory')"))
        for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml'):
            text=(P/'overlay'/name).read_text();self.assertIn('options: ['+V.OP+']',text)

class DriverNormalizerControls(unittest.TestCase):
    def setUp(self):self.f=A.Fixture()
    def tearDown(self):self.f.close()
    def exercise(self,drift=False):
        f=self.f;ref=f.adapter.capture_reference(('bin/security',),f.baseline)
        policy=S.RecoveryPolicy(f.binding['source'],f.binding['ref'],f.binding['run'],('bin/security',),os.geteuid(),os.getegid())
        directory=f.local/S.NEW;directory.mkdir();directory.chmod(0o755);lock=f.root/'var/lib/pacman/db.lck';lock.write_bytes(b'');lock.chmod(0)
        snap=F.snapshot(f.fd,policy.payload_names,owner_uid=os.geteuid(),owner_gid=os.getegid())
        cp=dict(type='FIRST_UPGRADE_ZERO',phase=S.PHASE,package=S.NAME,pid=81234,ppid=81233,starttime=123456,
            event=1,percent=0,howmany=1,current=1,prepared_directory=snap['db'][S.NEW],lock=snap['lock'])
        retired=dict(pid=cp['pid'],starttime=cp['starttime'],method='OWNED_PIDFD_INTERRUPT',signal=9,
            reaped=True,group_absent=True,descendants_absent=True,pid_reserved_until_retirement=True,checkpoint_blocked_until_interrupt=True)
        evidence=dict(protocol=S.PROTOCOL,binding=policy.binding(),baseline_sha256=F.snapshot_sha256(f.baseline),checkpoint=cp,retirement=retired)
        original=f.fake.run
        def run(argv,**kwargs):
            value=original(argv,**kwargs)
            if argv==list(A.A.CMD_INSTALL):
                body=A.desc(A.NOW+1)
                if drift:body+=b'%UNAUTHORIZED%\nchange\n\n'
                f.write('var/lib/pacman/local/'+S.NEW+'/desc',body,0o644)
                value['retirement']['wall_finished']=A.NOW+1
            elif argv==list(A.A.CMD_QUERY):
                value['stdout']=b''.join(sorted([('base%03d 1-1\n'%i).encode()for i in range(349)]+[(S.NAME+' 0.1.0-2\n').encode()]))
            return value
        f.fake.run=run
        # Full new core normalizer hook executes against only disposable files.
        return R.recover(f.fd,f.baseline,policy,evidence,f.inputs,ref['candidate_db'],ref['candidate_payload'],f.adapter,
            metadata_normalizer=M.MetadataNormalizer(ref['reference']))
    def test_driver_normalizes_only_timestamp_before_verify(self):
        result=self.exercise();self.assertEqual(result['normalization']['field'],'INSTALLDATE')
        row=result['normalization']['file_evidence'][S.NEW+'/desc']
        self.assertEqual(row['actual_installdate']-row['reference_installdate'],1)
        self.assertEqual(result['completed'],['verify-signature','orphan-cleanup','signed-candidate-install','verify-recovered'])
    def test_driver_refuses_non_timestamp_drift_without_retry(self):
        with self.assertRaises(R.RecoveryFailure) as caught:self.exercise(True)
        self.assertEqual(caught.exception.phase,'verify-recovered')
        self.assertEqual(sum('-U' in argv for argv,kwargs in self.f.fake.calls),2)

if __name__=='__main__':unittest.main()
