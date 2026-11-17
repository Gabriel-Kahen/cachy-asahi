# SPDX-License-Identifier: MIT
"""Reader-only closed transport DATA controls; no producer execution or actors."""
import argparse
import copy
import importlib.util
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
READER=HERE.parent/'payload/native/reader_current_v3.py'
ACTORS=[]

def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn','os.fork')) or event in ('os.system','fcntl.flock','resource.setrlimit'):
        ACTORS.append(event);raise AssertionError('Reader DATA controls forbid actor: '+event)

sys.addaudithook(fence)
spec=importlib.util.spec_from_file_location('FENCED_transport_v7_reader',READER)
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
CANARY='FENCED_SECRET_https://private.invalid/token'


def nested():
    return dict(schema=1,kind='CURRENT_RETAINED_TRANSPORT_FAILURE_V1',phase='REQUIRED_BLOBS_FETCH',
        operation='GIT_FETCH_BLOBS',error_class='VALIDATION',errno=None,command_ordinal=7,
        git_exit=128,git_timeout=False,http_status=None)


def packet():
    return dict(schema=2,kind='CURRENT_MATERIAL_STAGE_FAILURE_V2',phase='TRANSPORT_NATIVE248',
        reason='COMMAND_FAILED',command_ordinal=2,transport=nested())


def record():
    value=packet()
    return dict(schema=1,kind='CURRENT_MATERIAL_STAGE_FAILURE_RECORD_V1',status='DIAGNOSTIC_ONLY',
        availability='AVAILABLE',packet=value,request_pin=R.pin(b'request'),context_pin=R.pin(b'context'),
        stdout_pin=R.pin(b''),stderr_pin=R.pin(R.encoded(value)),retirement_pin=R.pin(b'retired'),**R.DIAGNOSTIC_FINAL)


class Controls(unittest.TestCase):
    def tearDown(self):self.assertEqual(ACTORS,[])
    def test_historical_packet_and_no_nested_v2_remain_data_only(self):
        old=dict(schema=1,kind='CURRENT_MATERIAL_STAGE_FAILURE_V1',phase='TRANSPORT_NATIVE248',reason='COMMAND_FAILED',command_ordinal=2)
        self.assertEqual(R.diagnostic_packet(old),old)
        current=packet();current['transport']=None;self.assertEqual(R.diagnostic_packet(current),current)
        R.delegated_public_body(R.encoded(current));R.delegated_public_body(R.encoded(packet()))
    def test_all_finite_nested_domains_and_integer_boundaries(self):
        for field,values in dict(phase=R.TRANSPORT_PHASES,operation=R.TRANSPORT_OPERATIONS,error_class=R.TRANSPORT_ERRORS,
            errno=(None,*R.TRANSPORT_ERRNOS),command_ordinal=(None,0,1169),git_exit=(None,-255,0,255),git_timeout=(None,True,False)).items():
            for value in values:
                row=packet();row['transport'][field]=value
                with self.subTest(field=field,value=value):self.assertEqual(R.diagnostic_packet(row),row)
    def test_unknown_strings_extra_keys_boolean_numbers_and_http_status_refuse(self):
        values=dict(schema=(True,2),kind=(CANARY,),phase=(CANARY,),operation=(CANARY,),error_class=(CANARY,),
            errno=(True,0,-1,4095,CANARY),command_ordinal=(True,-1,1170,CANARY),git_exit=(True,-256,256,CANARY),
            git_timeout=(0,1,CANARY),http_status=(200,404,CANARY),stderr=(CANARY,))
        for field,changes in values.items():
            for value in changes:
                row=packet();row['transport'][field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):R.diagnostic_packet(row)
        for field in nested():
            row=packet();row['transport'].pop(field)
            with self.subTest(missing=field),self.assertRaises(ValueError):R.diagnostic_packet(row)
    def test_nested_record_is_bound_to_transport_phase_and_exact_parent_schema(self):
        for phase in R.DIAGNOSTIC_PHASES:
            row=packet();row['phase']=phase
            if phase in ('CHILD','TRANSPORT_PUBLIC14','TRANSPORT_NATIVE248'):R.diagnostic_packet(row)
            else:
                with self.subTest(phase=phase),self.assertRaises(ValueError):R.diagnostic_packet(row)
        for change in ({'schema':True},{'schema':1},{'kind':'CURRENT_MATERIAL_STAGE_FAILURE_V1'},{'extra':CANARY},{'command_ordinal':True}):
            row=packet();row.update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):R.diagnostic_packet(row)
    def test_retained_record_requires_canonical_complete_packet_pin_and_no_acceptance(self):
        row=record();checked=R.diagnostic_failure_record(R.encoded(row))
        self.assertFalse(checked['Root_authentication']);self.assertFalse(checked['native_acceptance']);self.assertIsNone(checked['Root_acceptance'])
        for change in ('stderr','retirement','unsafe','acceptance','padding','duplicate'):
            value=record()
            if change=='stderr':value['stderr_pin']=R.pin(b'raw child stderr')
            elif change=='retirement':value['retirement_pin']=None
            elif change=='unsafe':value['packet']['transport']['exception']=CANARY;value['stderr_pin']=R.pin(R.encoded(value['packet']))
            elif change=='acceptance':value['release_acceptance']=True
            raw=R.encoded(value)
            if change=='padding':raw+=b' '
            elif change=='duplicate':raw=b'{"schema":1,"schema":1}\n'
            with self.subTest(change=change),self.assertRaises(ValueError):R.diagnostic_failure_record(raw)
    def test_unsealed_prospective_source_never_admits_or_executes(self):
        with patch.object(R,'TRANSPORT_SOURCE',None),self.assertRaisesRegex(ValueError,'PROFILE_NOT_SEALED'):
            R.transport_source_data({}, {},delegated=True)
        with self.assertRaisesRegex(ValueError,'DELEGATED_ONLY'):R.transport_source_data({}, {},delegated=False)
    def contract(self):
        members={role:('scripts/ci/first-login-enrollment-native-source/payload/native/'+name) for role,name in dict(
            materials_stager='stage_materials_current_v3_python_v1.py',material_domain_executor='material_domain_current_v3.py',hosted_launcher='hosted_current_v3.py').items()}
        operands=dict(materials_stager='stager.py',material_domain_executor='material_domain.py',hosted_launcher='hosted.py')
        files={member:(HERE/'payload'/operands[role]).read_bytes() for role,member in members.items()}
        rows={role:dict(member=member,**R.pin(files[member])) for role,member in members.items()}
        return files,rows
    def test_new_contract_preserves_five_capture_bodies_and_closed_declarations(self):
        files,rows=self.contract()
        with patch.object(R,'TRANSPORT_REPLACEMENTS',rows):
            value=R.transport_source_contract(files,dict(roles=rows));self.assertFalse(value['Root_authentication']);self.assertIsNone(value['Root_acceptance'])
            for role,mode in (('material_domain_executor','capture'),('materials_stager','enum'),('hosted_launcher','pin')):
                altered=dict(files);member=rows[role]['member']
                if mode=='capture':altered[member]=altered[member].replace(b'def stderr_identity(',b'def changed_stderr_identity(',1)
                elif mode=='enum':altered[member]=altered[member].replace(b"'ADMISSION','SETUP'",b"'FOREIGN','SETUP'",1)
                else:altered[member]=altered[member].replace(rows['material_domain_executor']['sha256'].encode(),b'0'*64,1)
                with self.subTest(mode=mode),self.assertRaises(ValueError):R.transport_source_contract(altered,dict(roles=rows))


def read_source(root,wanted):
    root=Path(root)
    if root!=root.resolve() or not root.is_absolute():raise ValueError('canonical public Source root')
    raw=(root/'source.lock.json').read_bytes()
    if R.pin(raw)!=wanted['source_map']:raise ValueError('exact public Source map')
    lock=R.receipt(raw);rows=dict(lock['files'])
    rows.update({name:dict(mode=0o644,**R.pin(raw)) for name in ('source.lock.json','source-map.json')})
    files={}
    for name,row in rows.items():
        R.relative(name);path=root/name;info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=row['mode'] or path.resolve()!=path:raise ValueError('ordinary public Source leaf')
        body=path.read_bytes()
        if R.pin(body)!=R.whole(row):raise ValueError('whole public Source leaf')
        files[name]=body
    if (len(files),sum(map(len,files.values())),R.source_git_tree(files,rows))!=(wanted['files'],wanted['bytes'],wanted['tree']):raise ValueError('complete public Source tuple')
    return files


def selection(files,prefix):
    program=R.receipt(files[prefix+'program.json'])
    family='scripts/ci/first-login-enrollment-native-source/'
    paths=dict(profile=family+'successor_v2/profile.json',program=prefix+'program.json',
        **{role:program['roles'][role]['member'] for role in ('policy','retention','encoder')})
    return dict(source_lock_pin=R.pin(files['source.lock.json']),binding=dict(source_lock=R.pin(files['source.lock.json'])),
        source={role:dict(path=name,**R.pin(files[name])) for role,name in paths.items()},
        fingerprint=R.SELECTED_TEST_FINGERPRINT,resources=dict(build_seconds=180,builder_cpus=4,
            builder_memory_bytes=4294967296,builder_pids=512,total_seconds=1800,command_rows=512),
        reader_pin=R.pin(READER.read_bytes()),stage='backend')


def inverse(files,prefix,map_name):
    value=R.receipt(files[prefix+'inverse.json'])
    restored={name:raw for name,raw in files.items() if name not in set(value['remove'])|{'source.lock.json','source-map.json'}}
    for name,backup in value.get('restore',{}).items():restored[name]=files[backup]
    restored['source.lock.json']=restored['source-map.json']=files[map_name]
    return restored


def genuine_cases(root):
    class GenuineTransportSource(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            if type(R.TRANSPORT_SOURCE) is not dict:raise ValueError('Reader profile not sealed')
            cls.files=read_source(root,R.TRANSPORT_SOURCE);cls.expected=selection(cls.files,R.TRANSPORT_PREFIX)
        def parse(self,files,expected=None):
            with patch.object(Path,'read_bytes',side_effect=AssertionError('Reader consumes supplied opaque Source bytes only')):
                return R.source_data(self.expected if expected is None else expected,files,delegated=True)
        def test_complete_source205_registry_and_all_historical_inverse_tuples(self):
            profile,program,policy=self.parse(self.files)
            self.assertEqual(program,R.receipt(self.files[R.TRANSPORT_PREFIX+'program.json']))
            self.assertEqual((program['schema'],len(program['roles']),len(program['delegation_programs']),len(program['staging_materials'])),(7,27,25,5))
            source196=inverse(self.files,R.TRANSPORT_PREFIX,'provenance/v7/source196-map.json')
            source188=inverse(source196,R.CAPTURE_PREFIX,'provenance/v6/source188-map.json')
            source179=inverse(source188,R.DIAGNOSTIC_PREFIX,'provenance/v5/source179-map.json')
            source139=inverse(source179,'scripts/ci/first-login-enrollment-native-source/successor_v4_source/','provenance/v4/v3-source-map.json')
            for basis,wanted in ((source196,R.CAPTURE_SOURCE),(source188,R.DIAGNOSTIC_SOURCE),(source179,R.DIAGNOSTIC_BASIS),
                (source139,dict(files=139,bytes=43544563,tree='dcab30972b74d62df099d8ae12997dc0e557ff00'))):
                lock=R.receipt(basis['source.lock.json']);rows=dict(lock['files']);rows.update({name:dict(mode=0o644,**R.pin(basis['source.lock.json'])) for name in ('source.lock.json','source-map.json')})
                self.assertEqual((len(basis),sum(map(len,basis.values())),R.source_git_tree(basis,rows)),(wanted['files'],wanted['bytes'],wanted['tree']))
                self.assertTrue(all(R.pin(raw)==R.whole(rows[name]) for name,raw in basis.items()))
            historical_selection=selection(source196,R.CAPTURE_PREFIX)
            with patch.object(Path,'read_bytes',side_effect=AssertionError('no external source reads')):
                R.source_data(historical_selection,source196,delegated=True)
            self.assertEqual(profile['operation'],R.OP);self.assertIsNone(policy['material_domain_executor_current_v3']['Root_issuance'])
            self.assertEqual(ACTORS,[])
        def test_rehashed_outer_claims_do_not_bypass_complete_inverse_or_registry(self):
            for mode in ('backup','basis-map','inverse','provenance','constructor','old-registry','mapping','issued','mode'):
                files=dict(self.files);lock=R.receipt(files['source.lock.json']);expected=copy.deepcopy(self.expected)
                if mode=='backup':name=next(n for n in files if n.startswith('provenance/v7/original/'));files[name]+=b' '
                elif mode=='basis-map':name='provenance/v7/source196-map.json';files[name]+=b' '
                elif mode=='inverse':
                    name=R.TRANSPORT_PREFIX+'inverse.json';value=R.receipt(files[name]);value['remove'].pop();files[name]=R.encoded(value)
                elif mode=='provenance':
                    name='provenance/v7/rebind.json';value=R.receipt(files[name]);value['transport_commit']='0'*40;files[name]=R.encoded(value)
                elif mode=='constructor':name=R.TRANSPORT_PREFIX+'prepare.py';files[name]+=b' '
                elif mode=='old-registry':name=R.CAPTURE_PREFIX+'program.json';files[name]+=b' '
                elif mode=='mapping':
                    name=R.TRANSPORT_PREFIX+'program.json';value=R.receipt(files[name]);value['delegation_programs']['hosted_launcher']=value['delegation_programs']['material_domain_executor'];files[name]=R.encoded(value)
                elif mode=='issued':name=None;lock['actual']['publication']={}
                else:name=next(n for n in files if n.startswith('provenance/v7/original/'));lock['files'][name]['mode']=0o755
                if name is not None:lock['files'][name].update(R.pin(files[name]))
                files['source.lock.json']=files['source-map.json']=R.encoded(lock)
                expected['source_lock_pin']=expected['binding']['source_lock']=R.pin(files['source.lock.json'])
                program_pin=R.pin(files[R.TRANSPORT_PREFIX+'program.json']);expected['source']['program'].update(program_pin)
                rows=dict(lock['files']);rows.update({n:dict(mode=0o644,**R.pin(files['source.lock.json'])) for n in ('source.lock.json','source-map.json')})
                claimed=dict(files=len(files),bytes=sum(map(len,files.values())),tree=R.source_git_tree(files,rows),source_map=R.pin(files['source.lock.json']))
                with self.subTest(mode=mode),patch.object(R,'TRANSPORT_SOURCE',claimed),patch.object(R,'TRANSPORT_PROGRAM_PIN',program_pin),self.assertRaises(ValueError):self.parse(files,expected)
        def test_v7_delegation_and_fixed_source_qualification_are_mandatory(self):
            with self.assertRaises(ValueError):R.source_data(self.expected,self.files,delegated=False)
            files=dict(self.files);files['source-map.json']+=b' '
            with self.assertRaises(ValueError):self.parse(files)
            files=dict(self.files);files['FENCED_extra.data']=b'FENCED'
            with self.assertRaises(ValueError):self.parse(files)
            self.assertEqual(ACTORS,[])
    return GenuineTransportSource


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--genuine-source',type=Path)
    chosen,remaining=parser.parse_known_args()
    if sys.argv.count('--genuine-source')>1:parser.error('select at most one genuine Source')
    if chosen.genuine_source is not None:globals()['GenuineTransportSource']=genuine_cases(chosen.genuine_source)
    unittest.main(argv=[sys.argv[0],*remaining])
