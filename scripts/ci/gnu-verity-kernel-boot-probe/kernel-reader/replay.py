#!/usr/bin/env python3
"""Pure original GNU verity kernel build evidence replay. No artifact code execution."""
import argparse,copy,hashlib,importlib.util,io,json,os,re,shutil,stat,subprocess,sys,zipfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SOURCE=None
REF=None
RUN = None
LANE='scripts/ci/gnu-verity-kernel-native'
MAX_TOTAL=384*1024**2+65536
MAX_ZIP=400*1024**2
AUTH='0b7759de4418d3b9d4d751ba20ab33a81bc1c52f2051aa04f8e2c3ed26fc4d87'

def need(ok, message):
    if not ok:
        raise ValueError(message)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))

def safe(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name and
         all(p not in ('', '.', '..') for p in name.split('/')), 'ordinary relative path')
    return name

def ordinary(path, cap):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap, 'bounded single-link input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(cap + 1)
        identity = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'input drift')
        return raw
    finally:
        os.close(fd)

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def selected(binding, selection, archive=True):
    import custody;custody.check(HERE/'source')
    fields = {'source_sha','ref','run_id','run_attempt'}
    need(set(selection) == fields and set(binding) == fields|{'artifact_sha256'}, 'exact Root selection/binding fields')
    need(all(type(v) is str and v for v in selection.values()) and
         all(type(binding[k]) is str and binding[k] for k in fields), 'NULL/unselected actual refused')
    need(selection == dict(source_sha=SOURCE,ref=REF,run_id=RUN,run_attempt='1') and
         {k:binding[k] for k in fields} == selection, 'exact Root-selected original run/source/ref/attempt')
    digest = binding['artifact_sha256']
    need((not archive and digest is None) or (type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest)), 'original archive digest required')

def run_identity(run, binding, success=True):
    need(type(run.get('id')) is int and str(run['id']) == binding['run_id'] and
         type(run.get('run_attempt')) is int and str(run['run_attempt']) == binding['run_attempt'] and
         run.get('head_sha') == SOURCE and run.get('head_branch') == REF and
         run.get('workflow_id') == 381664314 and run.get('path') == '.github/workflows/native-arm-build.yml' and
         run.get('name') == 'native-arm-gnu-verity-kernel-build-only' and run.get('event') == 'workflow_dispatch' and
         run.get('repository',{}).get('full_name') == 'Gabriel-Kahen/cachy-asahi' and
         run.get('status') == 'completed', 'original terminal workflow identity')
    if success:
        need(run.get('conclusion') == 'success', 'original workflow did not succeed')

def read(path):
    return decode(ordinary(path,4*1024**2))

def collection_join(archive,metadata,binding):
    """Join original transport bytes/API identity without acquiring anything."""
    root=archive.parent;outcome=read(root/'collection-outcome.json')
    need(outcome['status']=='ORIGINALS_COLLECTED_ONCE_NOT_ACCEPTED' and outcome['source']==SOURCE and outcome['run']==RUN and outcome['retry']is False and outcome['acceptance_authority']is False and outcome['cleanup_authority']is False,'once-only complete original collection outcome')
    raw=ordinary(archive,MAX_ZIP);logs=ordinary(root/'logs.zip',64*1024**2);run=ordinary(metadata,1024**2);api=ordinary(root/'artifacts.json',2*1024**2)
    need(outcome['artifact']==pin(raw) and pin(raw)['sha256']==binding['artifact_sha256'] and outcome['logs']==pin(logs) and outcome['metadata']==pin(run) and ordinary(root/'run.json',1024**2)==run and outcome['artifact_metadata']==pin(api),'complete original transport byte identities')
    transport=load('ksm_kernel_passive_original_transport',HERE/'collect.py');item=transport.artifact_row(decode(api),binding)
    need(outcome['artifact_id']==item['id'] and item['size_in_bytes']==len(raw) and (item.get('digest')is None or item['digest']=='sha256:'+pin(raw)['sha256']),'original artifact API size/digest join')
    with zipfile.ZipFile(io.BytesIO(logs))as z:
        rows=z.infolist();need(len(rows)<256 and len({r.filename for r in rows})==len(rows) and sum(r.file_size for r in rows)<=MAX_TOTAL and not any(r.flag_bits&1 for r in rows) and z.testzip()is None,'complete bounded original logs ZIP')
    return dict(artifact=pin(raw),logs=pin(logs),metadata=pin(run),artifact_metadata=pin(api))

def preflight(source):
 import custody;custody.check(source)
 source=Path(source).absolute();raw=ordinary(HERE/'source-authorization.json',1024**2)
 need(pin(raw)['sha256']==AUTH,'frozen20 authorization');rows=decode(raw)['files']
 need(len(rows)==20 and {p.relative_to(source).as_posix()for p in source.rglob('*')if p.is_file()}==set(rows),'exact closed20 source')
 for n,v in rows.items():need(pin(ordinary(source/safe(n),1024**2))==v,'source differs: '+n)
 for n in('lane','runtime','verity_profile','domain'):sys.modules.pop(n,None)
 sys.path.insert(0,str(source/LANE));L=load('ksm_kernel_trusted_lane',source/LANE/'lane.py')
 proof=L.preflight(source);need(proof['source_files']==20 and proof['actual_source']is None and proof['actual_run']is None,'pure build-only source gate')
 return L

FILES={'Image','Image.header','config','kernel-profile.json','build-receipt.json','build_kernel.py','kernel.fragment','diagnostic.fragment','source-proof.json','source-manifest.json','acquisition.json','archive-header.bin','baseline.config','baseline-build-receipt.json','configuration-delta.json','baseline-controller.json','baseline-controller.stdout','baseline-controller.stderr','candidate-controller.json','candidate-controller.stdout','candidate-controller.stderr','controller.json','configure.log','build.log','ordered-cleanup.json'}
DIAGNOSTIC_FILES={'candidate-unvalidated.config','candidate-unvalidated.Image.header','candidate-unvalidated-build-receipt.json','candidate-unvalidated.json'}
FILES=FILES|DIAGNOSTIC_FILES
def unvalidated_data(files,positive=False):
 need(DIAGNOSTIC_FILES<=set(files),'complete prevalidation DATA required')
 d=decode(files['candidate-unvalidated.json'])
 need(set(d)=={'schema_version','status','files','unavailable','acceptance_authority','boot','configuration_delta','image'}and type(d['schema_version'])is int and d['schema_version']==1 and d['status']=='UNVALIDATED_CANDIDATE_DATA'and d['unavailable']=={}and d['acceptance_authority']is False and d['boot']=='NOT_RUN'and d['configuration_delta']=='NOT_YET_VALIDATED'and d['image']=='HEADER_ONLY_NOT_COMPLETE_IMAGE','exact nonaccepting prevalidation descriptor')
 names=DIAGNOSTIC_FILES-{'candidate-unvalidated.json'}
 need(set(d['files'])==names and all(pin(files[n])==d['files'][n]for n in names),'complete prevalidation original member pins')
 need(len(files['candidate-unvalidated.config'])<=262144 and len(files['candidate-unvalidated.Image.header'])==64 and len(files['candidate-unvalidated-build-receipt.json'])<=65536,'prevalidation DATA caps')
 decode(files['candidate-unvalidated-build-receipt.json'])
 if positive:
  for diagnostic,original in(('candidate-unvalidated.config','config'),('candidate-unvalidated.Image.header','Image.header'),('candidate-unvalidated-build-receipt.json','build-receipt.json')):
   need(files[diagnostic]==files[original],'prevalidation/validated original byte join: '+original)
 return d

def archive_files(raw):
 files={};total=0;names=set()
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  for row in z.infolist():
   safe(row.filename);need(row.filename not in names,'duplicate ZIP member');names.add(row.filename)
   need(not row.is_dir()and row.filename in FILES|{'kernel-artifacts.json'}and stat.S_IFMT(row.external_attr>>16)in(0,stat.S_IFREG)and not row.flag_bits&1,'closed original kernel ZIP files; no aliases/directories/encryption')
   cap=256*1024**2 if row.filename=='Image'else 16*1024**2 if row.filename.endswith(('.stdout','.stderr','.log'))else 1024**2 if row.filename=='source-manifest.json'else 262144 if row.filename in('config','baseline.config','candidate-unvalidated.config')else 65536
   total+=row.file_size;need(0<=row.file_size<=cap and total<=MAX_TOTAL and len(files)<30,'source-matched kernel ZIP byte/file caps');files[row.filename]=z.read(row)
 need(set(files)==FILES|{'kernel-artifacts.json'},'complete exact kernel export required')
 d=decode(files['kernel-artifacts.json']);need(type(d)is dict and type(d.get('schema_version'))is int and d['schema_version']==1 and d.get('status')=='BUILT_ONLY_GNU_VERITY_DIAGNOSTIC16K_NOT_BOOTED','original complete build-only descriptor')
 need(set(d['files'])==FILES and all(pin(files[n])==v for n,v in d['files'].items())and type(d['total_bytes'])is int and d['total_bytes']==sum(len(files[n])for n in FILES)<=384*1024**2,'complete original descriptor byte index')
 return files,d

def command(row,files,kind,work):
 need(set(row)=={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'},'original exact controller fields')
 need(type(row['exit_code'])is int and row['exit_code']==0 and row['group_absence_verified']is True and type(row['time_limit'])is int and 0<row['time_limit']<=(300 if kind=='baseline'else 3700)and type(row['seconds'])in(int,float)and 0<=row['seconds']<=row['time_limit']+6 and type(row['output_limit'])is int and row['output_limit']==16*1024**2,'natural bounded kernel helper/group retirement')
 name='baseline'if kind=='baseline'else'helper';directory=work+'/'+name
 expected=['/usr/bin/python3','-I','-B',directory+'/build_kernel.py','--archive',work+'/inputs/kernel.tar.gz','--output',directory+'/built','--configure-only'if kind=='baseline'else'--build','--boot-diagnostics']
 need(row['argv']==expected,'exact original baseline/candidate command')
 for stream in('stdout','stderr'):
  raw=files[kind+'-controller.'+stream];need(type(row[stream+'_bytes'])is int and row[stream+'_bytes']==len(raw)and row[stream+'_sha256']==pin(raw)['sha256'],'complete original helper command streams')
 need(row['stdout_bytes']+row['stderr_bytes']<=16*1024**2,'combined original helper stream bound')

def validate_data(files,d,L,source,public):
 need(set(d)=={'schema_version','status','profile','source','archive','files','total_bytes','cleanup','receipt_paths','native_package_acceptance','boot','VM','live_kernel_write','hardware','performance','release'},'exact build-only descriptor fields')
 for k in('boot','VM','live_kernel_write','hardware','performance'):need(d[k]=='NOT_RUN','no runtime/boot authority')
 need(d['release']=='NOT_ADMITTED'and d['native_package_acceptance']=='NOT_REQUIRED_NOT_GRANTED'and d['receipt_paths']=='ORIGINAL_BUILD_PROVENANCE_NOT_VALID_AT_IMPORT','strict build-only authority scope')
 proof=decode(files['source-proof.json']);need(d['source']==proof and set(proof)=={'status','source_sha','workflow_sha','ref','run_id','run_attempt','manifest','profile'}and proof['status']=='SOURCE_PROOF_PASS_BUILD_ONLY'and proof['source_sha']==proof['workflow_sha']==SOURCE and proof['ref']==REF and proof['run_id']==RUN and proof['run_attempt']=='1'and proof['profile']==L.KP.PROFILE and proof['manifest']==pin(files['source-manifest.json']),'actual source/workflow/run/manifest join')
 need(files['source-manifest.json']==ordinary(source/LANE/'source-manifest.json',1024**2),'whole original implementation manifest')
 KP=L.KP;K=KP.contract(source);H=KP.helper(source)
 need(files['build_kernel.py']==KP.build_helper(KP.held(source,'build_kernel.py'))and files['kernel.fragment']==KP.fragment(KP.held(source,'kernel.fragment'))and files['diagnostic.fragment']==files['kernel.fragment']+H.DIAGNOSTIC_FRAGMENT.encode(),'source-owned exact derived helper/fragments; no exported code import')
 profile=K.validate(decode(files['kernel-profile.json']));need(profile==d['profile']and profile['Image']==pin(files['Image'])and profile['config']==pin(files['config']),'exact fresh GNU verity Image/config profile')
 need(files['Image.header']==files['Image'][:64]and len(files['Image.header'])==64,'whole actual Image/header join');KP.check_config(public/'config');H.HERE=public;H.config_check(public/'config',True);H.image_check(public/'Image')
 receipt=decode(files['build-receipt.json']);original=copy.deepcopy(receipt)
 work=str(Path(receipt['helper']['path']).parent.parent);need(Path(work).is_absolute()and Path(work).name=='gnu-verity-kernel-work'and not any(x in('..','.')for x in Path(work).parts)and '\n'not in work and '\r'not in work,'ordinary original build provenance root')
 expected={'helper':work+'/helper/build_kernel.py','fragment':work+'/helper/kernel.fragment','diagnostic_fragment':work+'/helper/built/diagnostic.fragment','image':work+'/helper/built/build/arch/arm64/boot/Image','config':work+'/helper/built/build/.config','archive':work+'/inputs/kernel.tar.gz','system_map':work+'/helper/built/build/System.map'}
 for key,path in expected.items():need(receipt[key]['path']==path,'exact original receipt path provenance')
 for key,name in(('helper','build_kernel.py'),('fragment','kernel.fragment'),('diagnostic_fragment','diagnostic.fragment'),('image','Image'),('config','config')):need({k:receipt[key][k]for k in('bytes','sha256')}==pin(files[name]),'original receipt file pin '+key)
 # Explicit DATA-only projection into owned replay files. Original bytes remain unchanged.
 projected=copy.deepcopy(receipt);projected['image']['path']=str(public/'Image');projected['config']['path']=str(public/'config')
 checked,_,_=K.from_receipt(projected,H,files['kernel.fragment'],pin(files['build_kernel.py'])['sha256'],pin(files['kernel.fragment'])['sha256']);need(checked==profile and receipt==original,'unchanged contract under declared DATA path projection only')
 archive=dict(bytes=262965559,sha256='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad',source_revision='94fb23346d522edf53722357c426a3e58030beea',retained='HEADER_ONLY_ARCHIVE_REACQUIRE_REQUIRES_FULL_ORIGINAL_HASH')
 need(receipt['missing_tools']==[] and set(receipt['tools'])==set(H.TOOLS)and all(v is not None for v in receipt['tools'].values())and receipt['guest_boot']==receipt['hardware']==receipt['performance']=='NOT RUN','complete original tool set and no boot/hardware/performance claim')
 need(d['archive']==archive and receipt['archive']['bytes']==archive['bytes']and receipt['archive']['sha256']==archive['sha256']and len(files['archive-header.bin'])==64 and files['archive-header.bin'][:3]==b'\x1f\x8b\x08','exact archive provenance/header, full archive source-enforced')
 acquire=decode(files['acquisition.json']);fetch=load('ksm_kernel_trusted_fetch',source/'scripts/virtual/generic16k/fetch_inputs.py');manifest,msha=fetch.load_manifest(source/'scripts/virtual/generic16k/inputs.json')
 need(acquire['status']=='FETCHED_HASH_VERIFIED'and acquire['original_input']==manifest['inputs'][0]and acquire['historical_manifest_sha256']==msha and acquire['transport_policy']=='TWO_DIRECT_TAG_URLS_NO_REDIRECT_300S'and acquire['total_deadline_seconds']==300 and acquire['partial_absent']is True and acquire['bytes']==archive['bytes']and acquire['sha256']==archive['sha256']and acquire['source_revision']==archive['source_revision'],'exact source-selected direct archive acquisition')
 need(1<=len(acquire['attempts'])<=2 and acquire['attempts'][-1]['status']=='PASS'and acquire['result']['bytes']==archive['bytes']and acquire['result']['sha256']==archive['sha256']and acquire['result']['path']==work+'/inputs/kernel.tar.gz'and acquire['result']['final_url']==acquire['attempts'][-1]['requested_url'],'complete acquired original source identity')
 for index,row in enumerate(acquire['attempts']):need(row['requested_url']==('https://codeload.github.com/AsahiLinux/linux/tar.gz/refs/tags/asahi-7.1.13-3','https://codeload.github.com/AsahiLinux/linux/tar.gz/asahi-7.1.13-3')[index],'exact finite source transport attempts')
 baseline=decode(files['baseline-build-receipt.json']);need(baseline['status']=='CONFIGURED_ONLY'and baseline['kernel_build']=='NOT RUN'and baseline['profile']==KP.OLD and baseline['boot_diagnostics']is True and baseline['source_commit']==archive['source_revision']and baseline['archive']==receipt['archive']and baseline['tools']==receipt['tools']and baseline['build_environment']==receipt['build_environment'],'same native baseline/candidate tools/environment/archive')
 need(baseline['helper']['path']==work+'/baseline/build_kernel.py'and baseline['helper']['sha256']==KP.PINS['build_kernel.py']['sha256']and baseline['fragment']['sha256']==KP.PINS['kernel.fragment']['sha256']and baseline['config']['path']==work+'/baseline/built/build/.config'and {k:baseline['config'][k]for k in('bytes','sha256')}==pin(files['baseline.config']),'source original baseline/config identity')
 env=receipt['build_environment'];need(env['jobs']==2 and env['build_seconds']==3600 and env['workspace_limit_bytes']==16*1024**3 and env['per_file_limit_bytes']==2*1024**3 and len(env['host_uname'])==5 and env['host_uname'][0]=='Linux'and env['host_uname'][4]=='aarch64','original native finite kernel build profile')
 need(decode(files['configuration-delta.json'])==L.delta(files['baseline.config'],files['config']),'complete same-environment configuration delta replay')
 rows=[]
 for kind in('baseline','candidate'):
  row=decode(files[kind+'-controller.json']);command(row,files,kind,work);rows.append(row)
 controller=decode(files['controller.json']);need(set(controller)=={'status','commands','seconds','controller_seconds','baseline_retired_before_candidate'}and controller['status']=='PASS_NATURAL_KERNEL_HELPERS'and controller['commands']==rows and type(controller['seconds'])in(int,float)and sum(r['seconds']for r in rows)<=controller['seconds']<=3700 and controller['controller_seconds']==3700 and controller['baseline_retired_before_candidate']is True,'shared original3700 controller and ordered baseline retirement')
 for n,keys in(('baseline', ['allnoconfig']),('candidate',['allnoconfig','-j2'])):
  rec=baseline if n=='baseline'else receipt;directory=work+('/baseline'if n=='baseline'else'/helper')+'/built'
  expected_cmd=['/usr/bin/make','-C',directory+'/linux-asahi-7.1.13-3','O='+directory+'/build','ARCH=arm64','LLVM=1']
  need(len(rec['commands'])==(1 if n=='baseline'else 2),'complete original helper build command count')
  for i,c in enumerate(rec['commands']):
   need(c['argv']==expected_cmd+(['allnoconfig']if i==0 else['-j2','Image'])and type(c['returncode'])is int and c['returncode']==0,'actual original configuration/Image commands')
   if n=='candidate':need(c['log']==directory+('/configure.log'if i==0 else'/build.log')and c['log_bytes']==len(files['configure.log'if i==0 else'build.log'])and c['log_sha256']==pin(files['configure.log'if i==0 else'build.log'])['sha256'],'original complete make log identity')
 cleanup=decode(files['ordered-cleanup.json']);need(d['cleanup']==cleanup and set(cleanup)=={'status','identity','absence_verified'}and cleanup['status']=='PASS_OWNED_BUILD_WORK_REMOVED'and cleanup['absence_verified']is True and type(cleanup['identity'])is list and len(cleanup['identity'])==3 and all(type(x)is int and x>=0 for x in cleanup['identity'])and cleanup['identity'][2]>0,'source-enforced owned workspace identity/removal receipt')
 return dict(profile=profile,original_receipt=pin(files['build-receipt.json']),original_path_provenance=expected,DATA_projection='ONLY_IMAGE_CONFIG_PATHS_FOR_UNCHANGED_SOURCE_CONTRACT_NOT_SAME_JOB_GATE',cleanup=cleanup)

def replay(source,archive,metadata,binding,selection,output):
 selected(binding,selection);run_identity(decode(ordinary(metadata,1024**2)),binding);transport=collection_join(archive,metadata,binding);L=preflight(source)
 raw=ordinary(archive,MAX_ZIP);need(pin(raw)['sha256']==binding['artifact_sha256'],'whole original artifact hash');files,d=archive_files(raw)
 need(output.is_absolute()and not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in output.parents)and not(output.is_relative_to(source)or source.is_relative_to(output)),'fresh ordinary separate replay output');output.mkdir(mode=0o700);public=output/'original-public';public.mkdir()
 for n,data in files.items():(public/n).write_bytes(data)
 unvalidated_data(files,positive=True)
 checked=validate_data(files,d,L,source,public)
 projection=dict(status=None,source=SOURCE,run=int(RUN),descriptor=pin(files['kernel-artifacts.json']),source_manifest=pin(files['source-manifest.json']),profile=L.KP.PROFILE,archive={k:d['archive'][k]for k in('bytes','sha256','source_revision')},configuration_delta=pin(files['configuration-delta.json']),Image=pin(files['Image']),config=pin(files['config']),original_transport=None,build_receipt=pin(files['build-receipt.json']),cleanup='PASS_OWNED_BUILD_WORK_REMOVED',boot='NOT_RUN',VM='NOT_RUN',live_kernel_write='NOT_RUN',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED',limits=['NO_BOOT_OR_SYSFS_EXECUTION_CREDIT','ORIGINAL_ABSOLUTE_RECEIPT_PATHS_ARE_PROVENANCE_NOT_LATER_JOB_PATHS','NO_INDEPENDENT_MACHINE_ATTESTATION'])
 return dict(status='PASS_ORIGINAL_GNU_VERITY_DIAGNOSTIC16K_BUILD_ONLY_REPLAY',source=SOURCE,ref=REF,run=RUN,original_transport=transport,Root_decision_inputs=projection,Root_decision='NOT_ISSUED_STATUS_AND_TRANSPORT_RECEIPT_PIN_REQUIRE_ROOT',artifact_index=pin(files['kernel-artifacts.json']),files=d['files'],checked=checked,scope='NATIVE_BUILD_CONFIG_HEADER_AND_SOURCE_ENFORCED_OWNED_WORK_REMOVAL_ONLY',limits=['FULL_SOURCE_ARCHIVE_BODY_UNEXPORTED_HEADER_DOES_NOT_REPLACE_HASH','WORKSPACE_ABSENCE_SOURCE_ENFORCED_NOT_INDEPENDENT_HOST_INSPECTION','ORIGINAL_RECEIPT_PATHS_PROVENANCE_ONLY_DATA_PROJECTION_EXPLICIT','NO_BOOT_OR_VM_OR_KERNEL_WRITE_OR_PACKAGE_ACCEPTANCE'],boot='NOT_RUN',VM='NOT_RUN',live_kernel_write='NOT_RUN',native_package_acceptance='NOT_GRANTED',hardware='NOT_RUN',performance='NOT_RUN',release='NOT_ADMITTED')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=HERE/'source');p.add_argument('--source-preflight',action='store_true')
 for n in('archive','metadata','binding','selection','output'):p.add_argument('--'+n,type=Path)
 a=p.parse_args()
 from unittest.mock import patch
 with patch.object(subprocess,'Popen',side_effect=AssertionError('PASSIVE_NO_PROCESS')),patch.object(subprocess,'run',side_effect=AssertionError('PASSIVE_NO_PROCESS')):
  if a.source_preflight:preflight(a.source.absolute());print('PASS_SOURCE_ONLY20_NO_BUILD_OR_BOOT')
  else:print(json.dumps(replay(a.source.absolute(),a.archive.absolute(),a.metadata.absolute(),decode(a.binding.read_bytes()),decode(a.selection.read_bytes()),a.output.absolute()),sort_keys=True))
