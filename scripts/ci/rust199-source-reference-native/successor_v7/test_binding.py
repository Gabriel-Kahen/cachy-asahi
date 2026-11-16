# SPDX-License-Identifier: MIT
"""FENCED provider metadata controls; no request, process, daemon or actor."""
import copy
import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
support_spec=importlib.util.spec_from_file_location('v7_test_support_DATA',HERE/'test_support.py');support=importlib.util.module_from_spec(support_spec);support_spec.loader.exec_module(support);PAYLOAD=support.assembled()
s=importlib.util.spec_from_file_location('v7_admission_binding_DATA',PAYLOAD/'admission.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)
s=importlib.util.spec_from_file_location('v7_entry_binding_DATA',PAYLOAD/'hosted/entry.py');e=importlib.util.module_from_spec(s);s.loader.exec_module(e)


def fixture():
    source=dict(sha='a'*40,ref='refs/heads/codex/FENCED-DATA',map_sha256='b'*64,approval='c'*64,run=None,job=None)
    dispatch=dict(source=source,FENCED='COMPONENT_ONLY_NOT_A_ROOT_GRANT')
    env=dict(GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_SHA=source['sha'],GITHUB_REF=source['ref'],GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='123',GITHUB_JOB='bootstrap',RUST199_OPERATION=g.OPERATION,GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@'+source['ref'],GH_TOKEN='FENCED_NOT_A_CREDENTIAL')
    jobs=dict(total_count=2,jobs=[dict(id=11,run_id=123,head_sha=source['sha'],name='rust199-bootstrap-v4',status='in_progress',conclusion=None),dict(id=12,run_id=123,head_sha=source['sha'],name='rust199-build-v4',status='in_progress',conclusion=None)])
    return dispatch,env,jobs


class Controls(unittest.TestCase):
    def test_predispatch_null_ids_actual_metadata_binds_unique_phase(self):
        dispatch,env,jobs=fixture()
        for phase,job in (('bootstrap','11'),('build','12')):
            value=g.provider_binding(dispatch,'d'*64,{**env,'GITHUB_JOB':phase},jobs,phase)
            self.assertEqual(value['source']['run'],'123');self.assertEqual(value['source']['job'],job)
        self.assertIsNone(dispatch['source']['run']);self.assertIsNone(dispatch['source']['job'])
    def test_predispatch_cannot_invent_ids(self):
        dispatch,env,jobs=fixture();dispatch['source']['run']='1'
        with self.assertRaises(ValueError):g.provider_binding(dispatch,'d'*64,env,jobs,'bootstrap')
    def test_manual_repo_ref_attempt_workflow_and_operation_guards(self):
        dispatch,env,jobs=fixture()
        for key,value in (('GITHUB_REPOSITORY','OTHER/repo'),('GITHUB_EVENT_NAME','push'),('GITHUB_SHA','0'*40),('GITHUB_REF','refs/heads/main'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_RUN_ID',''),('GITHUB_WORKFLOW_REF','OTHER'),('RUST199_OPERATION','other'),('GITHUB_JOB','build')):
            with self.subTest(key=key),self.assertRaises(ValueError):g.provider_binding(dispatch,'d'*64,{**env,key:value},jobs,'bootstrap')
    def test_ambiguous_extra_job_wrong_source_run_or_phase_refuses(self):
        dispatch,env,jobs=fixture()
        for mode in ('duplicate','extra','source','run','missing','attempt','completed','conclusion'):
            bad=copy.deepcopy(jobs)
            if mode=='duplicate':bad['jobs'][1]['name']='rust199-bootstrap-v4'
            elif mode=='extra':bad['jobs'][1]['name']='unreviewed-job'
            elif mode=='source':bad['jobs'][0]['head_sha']='0'*40
            elif mode=='run':bad['jobs'][0]['run_id']=999
            elif mode=='attempt':bad['jobs'][0]['run_attempt']=2
            elif mode=='completed':bad['jobs'][0]['status']='completed'
            elif mode=='conclusion':bad['jobs'][0]['conclusion']='success'
            else:bad['jobs']=bad['jobs'][1:];bad['total_count']=1
            with self.subTest(mode=mode),self.assertRaises(ValueError):g.provider_binding(dispatch,'d'*64,env,bad,'bootstrap')
    def test_actual_job_client_is_bounded_injected_exact_attempt_endpoint(self):
        dispatch,env,jobs=fixture();calls=[]
        def fetch(url,token):calls.append((url,token));return g.encode(jobs)
        env['GITHUB_JOB']='build';provider,raw=e.actual_provider(g,dispatch,'d'*64,env,'build',fetch)
        self.assertEqual(len(calls),1);self.assertTrue(calls[0][0].endswith('/runs/123/attempts/1/jobs?per_page=10'))
        self.assertEqual(provider['source']['job'],'12')
        with self.assertRaises(ValueError):e.actual_provider(g,dispatch,'d'*64,env,'build',lambda *a:b'x'*(1024**2+1))
    def test_checkonly_code_precedes_work_or_operational_phase(self):
        text=(PAYLOAD/'hosted/entry.py').read_text();run=text[text.index('def run(args):'):]
        self.assertLess(text.index('if args.check_only:return 0'),text.index('work.mkdir('))
        self.assertLess(run.index('dispatch_gate(args,os.environ)'),run.index('actual_provider(gate,dispatch,'))
        self.assertIn('len(raw)<=16384',text);self.assertIn('0<len(v)<=200',text)
        self.assertNotIn('GH_TOKEN',g.encode(fixture()[0]).decode())


if __name__=='__main__':unittest.main()
