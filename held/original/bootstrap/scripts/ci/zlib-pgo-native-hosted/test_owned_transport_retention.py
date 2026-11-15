# SPDX-License-Identifier: MIT
"""Transport DATA reader controls; every process/network entry point is forbidden."""
import copy,importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];PACKET=ROOT.parent
spec=importlib.util.spec_from_file_location('_pgo_transport_retention_controls',HERE/'retention.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
OWNER=SimpleNamespace(MAP='scripts/ci/zlib-pgo-native-hosted/source-map.json')
TEMP='/home/runner/work/_temp';ORIGINAL_SOURCE='/home/runner/work/cachy-asahi/cachy-asahi'

def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes)else(json.dumps(value,indent=2,sort_keys=True)+'\n').encode())

def fixture(work,own):
    carrier=TEMP+'/pgo-hosted-retained'
    row=dict(status='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY',identity=own,role=R.PHASE_ROLES['input-transport'],
        manifest_sha256=R.sha(R.read(ROOT/OWNER.MAP)),runtime_temp=TEMP,source_root=ORIGINAL_SOURCE,carrier_path=carrier,
        carrier_source=R.CARRIER_SOURCE,carrier_head=R.CARRIER_SOURCE,profile_sha256=R.CARRIER_PROFILE,
        expected_carrier_files=1154,expected_carrier_bytes=1046432165,budget_seconds=480,retry=False,
        partial_data_retained=True,native='NOT_RUN',acceptance=False)
    write(work/'input-transport-owner.json',row)
    write(work/'input-transport.stdout',b'');write(work/'input-transport.stderr',b'');write(work/'input-transport.exit-code',b'0\n')
    git=['git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true',
         '-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always']
    commands=[[*git,'init','--template=',carrier],
        [*git,'-C',carrier,'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60',
         'fetch','--depth=1','--no-tags','--no-recurse-submodules','https://github.com/Gabriel-Kahen/cachy-asahi.git',R.CARRIER_SOURCE],
        [*git,'-C',carrier,'rev-parse','--verify','FETCH_HEAD'],
        [*git,'-C',carrier,'checkout','--detach',R.CARRIER_SOURCE],
        [*git,'-C',carrier,'rev-parse','--verify','HEAD']]
    actors=[]
    for number,command in enumerate(commands):
        actors.append(dict(argv=command,log=TEMP+f'/pgo-hosted-work/input-transport-actors/{number:04d}.log',
            status='PASS',exit=0,natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,
            exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',forced_cleanup=False,elapsed_seconds=.01))
        write(work/'input-transport-actors'/f'{number:04d}.log',b'DATA-only fixture\n')
    write(work/'input-transport-actors/actors.json',actors)
    prepared=dict(status='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY',source=R.CARRIER_SOURCE,
        carrier=dict(source=R.CARRIER_SOURCE,files=1154,blob_joins=1154),mode='native248',actual=None)
    write(work/'bootstrap/retained-preparation.json',prepared)
    return row,actors,prepared


class OwnedTransportRetentionControls(unittest.TestCase):
    def setUp(self):
        path=PACKET/'evidence/tmp';path.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='transport-reader-',dir=path);self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
        self.own=dict(source_sha='a'*40,run_id='123',attempt=1)
        self.enterContext(patch.object(subprocess,'Popen',side_effect=AssertionError('child forbidden')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))
        for name in('waitid','waitpid','kill','killpg'):self.enterContext(patch.object(os,name,side_effect=AssertionError('numeric child operation forbidden')))

    def test_complete_full1154_data_join_is_not_native_or_cleanup_credit(self):
        fixture(self.work,self.own)
        with patch.dict(os.environ,{'RUNNER_TEMP':'/different-reader-host'}):
            record=R.transport_record(self.work,ROOT,self.own,OWNER,runtime_temp=TEMP)
        self.assertEqual((record['carrier_files'],record['carrier_bytes'],record['fetches']),(1154,1046432165,1))
        self.assertEqual(record['role'],'RETAINED_INPUT_TRANSPORT_DATA');self.assertEqual(record['native'],'NOT_RUN')
        self.assertEqual(record['native_cleanup'],'NOT_ESTABLISHED');self.assertIs(record['acceptance'],False)
        with self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER,runtime_temp='/wrong-temp')
        self.assertEqual(R.PHASE_ROLES['cleanup'],'PRODUCER_RETIREMENT_AFTER_CONSUMERS')

    def test_wrong_source_identity_volume_role_or_path_refuses(self):
        row,_,_=fixture(self.work,self.own)
        variants=[('identity',{}),('carrier_head','b'*40),('profile_sha256','c'*64),('expected_carrier_files',496),('expected_carrier_bytes',703396421),('role','NATIVE_PRODUCER'),('retry',True),('budget_seconds',None),('acceptance',True),('carrier_path',ORIGINAL_SOURCE+'/source-retained')]
        for key,value in variants:
            bad=copy.deepcopy(row);bad[key]=value;write(self.work/'input-transport-owner.json',bad)
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):R.transport_record(self.work,ROOT,self.own,OWNER)

    def test_failed_missing_or_nonzero_outer_stream_never_qualifies(self):
        row,_,_=fixture(self.work,self.own)
        for code in(b'1\n',b'',b'0',b'124\n'):
            write(self.work/'input-transport.exit-code',code)
            with self.subTest(code=code),self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER)
        write(self.work/'input-transport.exit-code',b'0\n');(self.work/'input-transport.stderr').unlink()
        with self.assertRaises(FileNotFoundError):R.transport_record(self.work,ROOT,self.own,OWNER)
        write(self.work/'input-transport.stderr',b'partial diagnostic');row['status']='FAIL_RETAINED_INPUT_TRANSPORT_DATA';write(self.work/'input-transport-owner.json',row)
        with self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER)

    def test_missing_owned_exit_second_fetch_or_incomplete_blob_proof_refuses(self):
        _,actors,prepared=fixture(self.work,self.own)
        for key,value in [('exit_observed_via_waitpid',False),('ownership_lost',True),('forced_cleanup',True),('exit',None)]:
            bad=copy.deepcopy(actors);bad[1][key]=value;write(self.work/'input-transport-actors/actors.json',bad)
            with self.subTest(key=key),self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER)
        bad=copy.deepcopy(actors);bad[2]['argv']=bad[1]['argv'];write(self.work/'input-transport-actors/actors.json',bad)
        with self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER)
        for corruption in('init-target','checkout-target','revparse-target','credential-qualifier','aggregate-elapsed'):
            bad=copy.deepcopy(actors)
            if corruption=='init-target':bad[0]['argv'][-1]=TEMP+'/unselected-carrier'
            elif corruption in('checkout-target','revparse-target'):
                index=3 if corruption=='checkout-target'else 2
                target=bad[index]['argv'].index('-C')+1;bad[index]['argv'][target]=TEMP+'/unselected-carrier'
            elif corruption=='credential-qualifier':
                target=bad[1]['argv'].index('credential.helper=');bad[1]['argv'][target]='credential.helper=store'
            else:
                for actor in bad:actor['elapsed_seconds']=100
            write(self.work/'input-transport-actors/actors.json',bad)
            with self.subTest(corruption=corruption),self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER)
        write(self.work/'input-transport-actors/actors.json',actors);prepared['carrier']['blob_joins']=496;write(self.work/'bootstrap/retained-preparation.json',prepared)
        with self.assertRaises(ValueError):R.transport_record(self.work,ROOT,self.own,OWNER)

    def test_transport_only_failure_retains_partial_streams_without_private_cache(self):
        source=self.work/'source';source.mkdir();work=self.work/'work';work.mkdir();public=self.work/'public'
        for name in('only-source','map','alias1','alias2'):write(source/name,b'held source')
        (source/'pgo-source'/R.RECIPE).mkdir(parents=True)
        proof=self.work/'proof.json';write(proof,b'presecret DATA proof')
        write(work/'input-transport-owner.json',dict(status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',identity=self.own,runtime_temp=TEMP,source_root=ORIGINAL_SOURCE,carrier_path=TEMP+'/pgo-hosted-retained'))
        write(work/'input-transport.stdout',b'partial stdout');write(work/'input-transport.stderr',b'bounded failure DATA');write(work/'input-transport.exit-code',b'124\n')
        write(work/'input-transport-actors/actors.json',[dict(status='FAIL',exit=None)]);write(work/'input-transport-actors/0000.log',b'partial actor log')
        def fresh(path):Path(path).mkdir();return Path(path)
        owner=SimpleNamespace(ROOT=source,MAP='map',ALIASES=('alias1','alias2'),fresh=fresh,save=write,binding=lambda *a,**kw:({'files':{'only-source':{}}},self.own))
        args=SimpleNamespace(work=work,public=public,proof=proof,manifest_sha256='d'*64)
        with patch.object(R,'producer',side_effect=AssertionError('producer must not be reached')):
            self.assertEqual(R.retain(args,owner),1)
        receipt=R.j(public/'receipt.json');self.assertEqual(receipt['status'],'PARTIAL_OR_FAILED_PGO_HOSTED_DATA')
        self.assertEqual(receipt['construction'],'NOT QUALIFIED');self.assertEqual(receipt['cleanup_credit'],'NONE')
        self.assertIs(receipt['acceptance'],False);self.assertEqual(receipt['phase_roles']['input-transport'],'RETAINED_INPUT_TRANSPORT_DATA')
        self.assertEqual(R.read(public/'input-transport.stderr'),b'bounded failure DATA')
        self.assertEqual(R.read(public/'input-transport-actors/0000.log'),b'partial actor log')
        self.assertFalse((self.work/'alarm-cache').exists())

if __name__=='__main__':unittest.main()
