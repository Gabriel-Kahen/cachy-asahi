#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed private-parser refusal diagnostics; no actors or native acceptance."""
import sys

def deny(event,args):
 if event.startswith(('socket.','subprocess.','ctypes.','pty.'))or event in('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn'):raise RuntimeError('actor forbidden: '+event)
sys.addaudithook(deny)
import argparse,copy,json
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_owner_data as controls
from test_kernel_audit_data import event,WINDOW

class KernelRefusalV5Data(unittest.TestCase):
 def setUp(self):
  self.work=tempfile.TemporaryDirectory(prefix='kernel-refusal-v5-new-DATA-');self.addCleanup(self.work.cleanup);self.f=controls.ports.Fixture(Path(self.work.name)/'owner')
 def run_owner(self,mode='schema'):
  f=self.f;original=f.respond
  def respond(argv):
   if argv[0]!='/usr/bin/journalctl':return original(argv)
   if mode=='permission':return b'PRIVATE_COMMAND_ERROR_SENTINEL',1
   return controls.ports.encoded(dict(event(),UNEXPECTED_PRIVATE_FIELD='PRIVATE_JOURNAL_SENTINEL')),0
  with patch.object(f,'respond',respond):f.diagnostic=f.module.owner_matrix_kernel_refusals_v5(f.actor,f.root,f.args,f.own,f.context,f.dockerfile,f.ledger,f.verify_base,f.source_proof)
  f.owner=controls.ports.load(f.work/'public/namespace-policy/owner.json');f.result=controls.ports.load(f.work/'public/namespace-policy/result.json');return controls.ports.load(f.work/'public/namespace-policy/kernel-audit-refusals-v5.json')
 def test_distinct_refusal_counterexamples_keep_original_refusal(self):
  with self.f.ports():
   m=self.f.module
   samples=[(b'not-json PRIVATE_ERROR_SENTINEL','JSON','JSON_DECODE_OR_VALUE'),(b'{"MESSAGE":"x","MESSAGE":"y"}','JSON','DUPLICATE_JSON_FIELD'),(controls.ports.encoded(dict(event(),UNEXPECTED_FIELD='PRIVATE_FIELD_SENTINEL')),'RECORD_FIELDS','RECORD_SCHEMA_OR_MESSAGE_LIMIT'),(controls.ports.encoded(event(__REALTIME_TIMESTAMP=True)),'RECORD_FIELDS','TIMESTAMP_OR_BOOT_ID_SHAPE'),(controls.ports.encoded(event(MESSAGE=event()['MESSAGE'].replace('capability=12','capability=21'))),'AVC_FIELDS','CAPABILITY_NAME_NUMBER_MISMATCH'),(b'\n'.join(controls.ports.encoded(event()).strip()for _ in range(9)),'MATCH_COUNT','MATCH_LIMIT'),(b'x'*16385,'OUTPUT_BOUNDS','LINE_SET_LIMIT')]
   for raw,phase,code in samples:
    with self.subTest(code=code):
     old=m.kernel_audit_parse_v4(raw,WINDOW,0);d=m.kernel_refusal_diagnostic_v5(raw,WINDOW,0);self.assertEqual(old['status'],'UNKNOWN_MALFORMED_OR_EXCESS_OUTPUT');self.assertEqual((d['phase'],d['code']),(phase,code));self.assertEqual(d['v4_status'],old['status']);self.assertFalse(d['private_reason_recomputed']);self.assertNotIn(b'SENTINEL',controls.ports.encoded(d))
     if d['line']is not None:self.assertEqual(d['line']['sha256'],m.pin(raw.splitlines()[d['line']['number']])['sha256'])
 def test_valid_empty_unmatched_nonzero_views_preserve_v4(self):
  with self.f.ports():
   m=self.f.module
   for raw,rc in[(controls.ports.encoded(event()),0),(b'',0),(controls.ports.encoded(event(MESSAGE='unmatched PRIVATE_SENTINEL')),0),(b'PRIVATE_PERMISSION_SENTINEL',1)]:
    old=m.kernel_audit_parse_v4(raw,WINDOW,rc);d=m.kernel_refusal_diagnostic_v5(raw,WINDOW,rc);self.assertEqual(d['v4_status'],old['status']);self.assertIsNone(d['line']);self.assertFalse(d['acceptance']);self.assertNotIn(b'SENTINEL',controls.ports.encoded(d));self.assertEqual(d['namespace_effect'],'UNKNOWN')
 def test_full_owner_projection_matching_reader_reports_unrecomputed_reason(self):
  f=self.f
  with f.ports():
   d=self.run_owner();self.assertEqual(len(d['captures']),4);self.assertEqual(len([c for c in f.calls if c['argv'][0]=='/usr/bin/journalctl']),4)
   _,payloads=controls.project(f);self.assertTrue(f.module.KERNEL_REFUSAL_V5_LEAF in payloads,'required v5 leaf refused by unchanged projection');self.assertFalse(any('private/'in n for n in payloads));self.assertNotIn(b'PRIVATE_JOURNAL_SENTINEL',b''.join(payloads.values()))
   returned=controls.read(f,payloads);q=returned['kernel_refusals_v5'];self.assertEqual(q['status'],'VALIDATED_PRIVATE_REFUSAL_ENVELOPE_RAW_REASON_NOT_RECOMPUTED');self.assertFalse(q['private_reason_recomputed']);self.assertFalse(q['independent_owned_process_proof']);self.assertTrue(all(r['qualification']=='REPORTED_PRIVATE_REASON_NOT_RECOMPUTED'for r in q['reports']));self.assertEqual(returned['kernel_audit_v4']['summary']['candidate_records'],0)
 def test_reader_refuses_forged_claims_unbounded_fields_and_selector_changes(self):
  f=self.f
  with f.ports():
   original=self.run_owner();audit=f.owner['kernel_audit_v4']
   for key in('cause','extra','phase','line','CID','proof','type'):
    value=copy.deepcopy(original);r=value['captures'][0];d=r['diagnostic']
    if key=='cause':d['namespace_effect']='APPARMOR_CAUSED'
    elif key=='extra':d['raw_message']='PRIVATE_SENTINEL'
    elif key=='phase':d.update(phase='COMMAND',code='COMMAND_EXIT_NONZERO')
    elif key=='line':d['line']['number']=True
    elif key=='CID':r['container']='f'*64
    elif key=='proof':d['private_reason_recomputed']=True
    elif key=='type':d['phase']=[]
    owner=copy.deepcopy(f.owner);owner['kernel_refusals_v5']=value
    with self.subTest(key=key),self.assertRaises(f.module.MatrixGuard):f.module.validate_kernel_refusals_v5(value,audit,owner,controls.expected(f))
 def test_nonzero_command_is_not_a_parse_or_permission_cause_claim(self):
  f=self.f
  with f.ports():
   value=self.run_owner('permission');q=f.module.validate_kernel_refusals_v5(value,f.owner['kernel_audit_v4'],f.owner,controls.expected(f));self.assertTrue(all(v['code']=='COMMAND_EXIT_NONZERO'for v in q['reports']));self.assertNotIn(b'PRIVATE_COMMAND_ERROR_SENTINEL',controls.ports.encoded(value));self.assertEqual(len([c for c in f.calls if c['argv'][0]=='/usr/bin/journalctl']),4)
 def test_unstarted_capture_cannot_invent_line_or_parser_refusal(self):
  f=self.f
  with f.ports():
   value=f.module.kernel_refusal_capture_v5(dict(private_raw_pin=None),f.work);self.assertEqual(value['code'],'CAPTURE_NOT_STARTED');self.assertIsNone(value['line']);self.assertEqual(value['v4_status'],'UNKNOWN_NOT_STARTED')

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--basis',required=True,type=Path);args,rest=p.parse_known_args();controls.ports.configure_basis(args.basis.resolve(strict=True));unittest.main(argv=[sys.argv[0],*rest])
