# SPDX-License-Identifier: MIT
"""Fixed privacy rule IDs and source-whitelisted context; never expose values."""
import hashlib,json,re
from pathlib import Path
CAP=16*1024**2
PRIVATE_MARKER=re.compile(br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY|BEGIN PGP PRIVATE|ssh-(?:rsa|ed25519)|ecdsa-sha2-|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+|authorization\s*:\s*(?:bearer|token)|(?:access[_-]?token|password|secret)\s*[=:]|CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)|PRIVATE_KEY|(?:_TOKEN|_SECRET|_PASSWORD)\b',re.I)
RULES=tuple((f'PRIVACY_{i:02d}',re.compile(pattern,re.I)) for i,pattern in enumerate((
 br'-----BEGIN[^\r\n]{0,100}PRIVATE KEY',br'BEGIN PGP PRIVATE',br'ssh-(?:rsa|ed25519)',br'ecdsa-sha2-',
 br'(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+',br'authorization\s*:\s*(?:bearer|token)',
 br'(?:access[_-]?token|password|secret)\s*[=:]',br'CACHY_(?:OLD_FOUR|RETAINED_BUBBLEWRAP)',br'PRIVATE_KEY',br'(?:_TOKEN|_SECRET|_PASSWORD)\b'),1))
ROOT_FIELDS={('status',),('phase',),('error',),('failure','phase'),('failure','type'),('failure','message')}
PYTHON_FIELDS={('status',),('error',),('build_protocol',),('project','status'),('project','build'),('project','install'),('project','unchanged'),('project','edit'),('project','failure_recovery')}
EXTENSION_FIELDS={('status',),('error',),('project','status')}
BUILD_FIELDS={('status',),('error',),('project_workflows','cmake','status'),('project_workflows','meson','status')}
SUMMARY_FIELDS={('status',),('aggregate',),('projects','cmake','status'),('projects','meson','status')}|{('tools',t) for t in ('cmake','ctest','meson','ninja','cc','c++')}
FIELDS={
 'journey/result.json':ROOT_FIELDS|{('python',)+p for p in PYTHON_FIELDS}|{('extension',)+p for p in EXTENSION_FIELDS}|{('build_systems',)+p for p in BUILD_FIELDS},
 'journey/python/result.json':PYTHON_FIELDS,'journey/extension/result.json':EXTENSION_FIELDS,
 'journey/build-systems/result.json':BUILD_FIELDS,'journey/build-summary.json':SUMMARY_FIELDS,
 'build-summary.json':{('status',)}|{('guest_summary',)+p for p in SUMMARY_FIELDS},
 'receipt.json':{('status',),('error',),('bootstrap','status')},'consumer-diagnostic.json':{('status',),('phase',)},
 'cleanup.json':{('status',)},'provision-diagnostic.json':{('status',)}}


# New contexts identify only fixed Source vocabulary, never the matched value.
# List positions are canonicalized; the hash cannot print arbitrary field names.
def _label_registry():
 result={}
 def add(file,label,path):result.setdefault(file,{}).setdefault(label,set()).add(tuple(path))
 for feature,label in (('python','PYTHON'),('extension','EXTENSION'),('build_systems','BUILD')):
  folder='build-systems' if feature=='build_systems' else feature
  for file,prefix in (('journey/result.json',(feature,)),('journey/'+folder+'/result.json',())):
   for leaf,name in (('status','REPORT_STATUS'),('error','REPORT_ERROR')):add(file,label+'_'+name,prefix+(leaf,))
   for leaf,name in (('argv','ARGUMENT'),('cwd','LOCATION'),('step','STEP'),('launch_error','LAUNCH_ERROR')):
    path=prefix+('commands','*',leaf)+(('*',) if leaf=='argv' else ())
    add(file,label+'_COMMAND_'+name,path)
   for leaf in ('error','ownership','group_census'):
    add(file,label+'_COMMAND_SUPERVISION',prefix+('commands','*','supervision',leaf))
   add(file,label+'_COMMAND_SUPERVISION',prefix+('commands','*','supervision','signals','*'))
   if feature=='build_systems':
    for backend in ('cmake','meson'):
     add(file,'BUILD_PROJECT_STATUS',prefix+('project_workflows',backend,'status'))
     add(file,'BUILD_PROJECT_MISSING_TOOL',prefix+('project_workflows',backend,'missing','*'))
    for tool in ('cmake','ctest','meson','ninja','cc','c++'):
     for leaf in ('status','path','resolved'):
      add(file,'BUILD_TOOL_METADATA',prefix+('tools',tool,leaf))
     add(file,'BUILD_TOOL_METADATA',prefix+('tools',tool,'version','*'))
 for file,prefix in (('journey/build-systems/commands.json',()),('journey/python/commands.json',()),('journey/extension/commands.json',())):
  label='BUILD' if 'build-systems' in file else 'PYTHON' if '/python/' in file else 'EXTENSION'
  add(file,label+'_COMMAND_ARGUMENT',('*','argv','*'))
  add(file,label+'_COMMAND_LOCATION',('*','cwd'))
  add(file,label+'_COMMAND_STEP',('*','step'))
  for leaf in ('error','ownership','group_census'):add(file,label+'_COMMAND_SUPERVISION',('*','supervision',leaf))
 return result
LABEL_PATHS=_label_registry()

HEADER_PROFILE_SHA256='2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c'
_HEADER_PATHS=None

def _pinned_header_paths():
 global _HEADER_PATHS
 if _HEADER_PATHS is None:
  from capsule import _ordinary
  raw=_ordinary(Path(__file__).resolve().parent/'input-profile.json',256*1024)
  if hashlib.sha256(raw).hexdigest()!=HEADER_PROFILE_SHA256:raise ValueError('PINNED_HEADER_CONTEXT_PROFILE_REFUSED')
  files=json.loads(raw)['python_headers']['files']
  if type(files) is not dict or len(files)!=283:raise ValueError('PINNED_HEADER_CONTEXT_PROFILE_REFUSED')
  names=[]
  for name,row in files.items():
   if type(name) is not str or not name.startswith('usr/include/python3.14/') or type(row) is not dict:
    raise ValueError('PINNED_HEADER_CONTEXT_PROFILE_REFUSED')
   names.append(name.removeprefix('usr/include/python3.14/'))
  _HEADER_PATHS={
   'journey/result.json':{prefix+(name,) for prefix in (('headers','files'),('extension','headers','files')) for name in names},
   'journey/extension/result.json':{('headers','files',name) for name in names}}
 return _HEADER_PATHS

def _fixed_context(path,relative_path,is_key):
 if is_key:
  header_shape=(relative_path=='journey/result.json' and
   (len(path)==3 and path[:2]==('headers','files') or len(path)==4 and path[:3]==('extension','headers','files'))
   or relative_path=='journey/extension/result.json' and len(path)==3 and path[:2]==('headers','files'))
  if header_shape and tuple(path) in _pinned_header_paths().get(relative_path,set()):
   return 'PINNED_PYTHON_HEADER_MAP_KEY',hashlib.sha256(_canonical(list(path))).hexdigest(),'EXTENSION_HEADER_REPORT'
  return None
 canonical=tuple('*' if type(part) is int else part for part in path)
 for label,known in LABEL_PATHS.get(relative_path,{}).items():
  if canonical in known:return label,hashlib.sha256(_canonical(list(canonical))).hexdigest(),None
 return None


def _pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def _canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')

def _rule(raw):
 hit=PRIVATE_MARKER.search(raw)
 if hit is None:return None
 for identifier,pattern in RULES:
  candidate=pattern.match(raw,hit.start())
  if candidate is not None and candidate.end()==hit.end():return identifier
 return 'PRIVACY_00'

def _parse(raw):
 def pairs(items):
  value={}
  for key,item in items:
   if key in value:raise ValueError('duplicate')
   value[key]=item
  return value
 return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))

def _field(value,identifier):
 stack=[(value,(),False)];seen=0
 while stack:
  current,path,key=stack.pop();seen+=1
  if seen>100000 or len(path)>64:return None
  if type(current) is str:
   if _rule(current.encode('utf-8'))==identifier:return path,current,key
  elif type(current) is dict:
   if len(current)>100000:return None
   for name,item in reversed(list(current.items())):
    stack.append((item,path+(name,),False));stack.append((name,path+(name,),True))
  elif type(current) is list:
   if len(current)>100000:return None
   for index,item in reversed(list(enumerate(current))):stack.append((item,path+(index,),False))
 return None

def inspect_privacy(raw,relative_path):
 """Return fixed metadata or None; never marker, value, arbitrary field or span."""
 if type(raw) is not bytes or len(raw)>CAP:raise ValueError('PRIVACY_INPUT_REFUSED')
 identifier=_rule(raw)
 if identifier is None:return None
 result=dict(schema=1,rule_id=identifier,logical_field='UNCLASSIFIED',field_path_sha256=None,field_sha256=None,whole_file=_pin(raw))
 if type(relative_path) is not str or not relative_path.endswith('.json'):return result
 try:
  found=_field(_parse(raw),identifier)
  if found is None:return result
  path,value,is_key=found;result['field_path_sha256']=hashlib.sha256(_canonical(list(path))).hexdigest()
  fixed=_fixed_context(path,relative_path,is_key)
  if fixed is not None:
   result.update(logical_field=fixed[0],field_path_sha256=fixed[1],field_sha256=None)
   if fixed[2] is not None:result['scope']=fixed[2]
   return result
  if not is_key and path in FIELDS.get(relative_path,set()):
   value_hash=hashlib.sha256(_canonical(value)).hexdigest()
   result.update(logical_field='.'.join(path),field_sha256=value_hash)
 except (ValueError,UnicodeError,RecursionError,TypeError,OverflowError):pass
 return result

HOST={'transport-diagnostic.json','transport-proof.json','receipt.json','cleanup.json','source-proof.json','consumer-inspect.json','consumer-after.json','consumer-diagnostic.json',
 'image-ledger.json','image-retirement.json','bootstrap-failure-retention.json','provision-diagnostic.json','build-summary.json','meson-diagnostic.json'}
REPORTS={'python':{'result.json','commands.json','project.json'},'extension':{'result.json','commands.json','project.json'},
 'build-systems':{'result.json','commands.json','project-cmake.json','project-meson.json','installed-cmake.json','installed-meson.json'}}
PRODUCERS={'native/python_backend.py','native/uv-inputs.json','scripts/workflows/python_development.py','scripts/workflows/python_extension.py',
 'scripts/workflows/developer_build_systems.py','scripts/workflows/developer_workflow.py'}
PROOFS={phase+'-'+name for phase in ('bootstrap','overlay') for name in ('packages.lock','signatures.json','bootstrap.json','cache-checksums.json','Dockerfile','runner.json')}|{'bootstrap-acquisition.json','bootstrap-key-import.log','bootstrap-bootstrap.log'}
SITE='lib/python3.14/site-packages/';DIST='uv_build-0.11.28.dist-info/'
BACKEND={'bin/uv-build'}|{SITE+'uv_build/'+n for n in ('__init__.py','__main__.py','py.typed')}|{SITE+DIST+n for n in ('METADATA','WHEEL','RECORD','INSTALLER','REQUESTED','direct_url.json','uv_cache.json','licenses/LICENSE-APACHE','licenses/LICENSE-MIT','sboms/uv-build.cyclonedx.json')}
CODES=set('''BOUNDED_DATA_ACCESS_OR_STRUCTURE_REFUSED BOUNDED_UNALIASED_ORDINARY_DATA_REQUIRED CAPSULE_COUNT_CAP CAPSULE_INDEX_BYTE_CAP CAPSULE_OUTPUT_MUST_BE_OUTSIDE_PUBLIC_ROOT CAPSULE_WRITE_MADE_NO_PROGRESS CAPTURED_PAYLOAD_BINDING COMMAND_LOG_WITHOUT_SOURCE_REPORT_REFUSED DATA_BYTE_CAP DATA_CHANGED_BEFORE_OPEN DATA_CHANGED_DURING_READ DIRECTORY_CHANGED_BEFORE_OPEN DIRECTORY_CHANGED_DURING_DATA_ACCESS DUPLICATE_JSON_KEY FEATURE_REPORT_OBJECT_REQUIRED FINITE_INSTALLED_BACKEND_FILE_MAP_REQUIRED FINITE_SOURCE_COMMAND_RECORDS_REQUIRED FINITE_UNIQUE_SOURCE_COMMAND_LOG_REQUIRED FRESH_DISJOINT_PROJECTION_REQUIRED HARDLINKED_PUBLIC_DATA_REFUSED HOST_PATH_ALIASES_REFUSED INCLUSIVE_CAPSULE_BYTE_CAP INSTALLED_BACKEND_OBJECT_REQUIRED INVALID_DATA_PATH NONCANONICAL_DATA_PATH ORDINARY_PERMISSION_MODE_REQUIRED PRIVATE_MATERIAL_MARKER_IN_SELECTED_PUBLIC_DATA_REFUSED PRIVATE_MATERIAL_PATH_REFUSED PROJECTION_AGGREGATE_CAP PROJECTION_AUTHORITY_BINDING_REFUSED PROJECTION_AUTHORITY_OBJECT_REQUIRED PROJECTION_AUTHORITY_RECEIPT_REQUIRED PROJECTION_COPY_DIFFERS PROJECTION_DIRECTORY_COUNT_CAP PROJECTION_DUPLICATE_LEAF_DIFFERS PROJECTION_FINAL_AGGREGATE_CAP PROJECTION_PRODUCER_SOURCE_PIN_DIFFERS PROJECTION_RETAINED_SOURCE_PIN_DIFFERS PROJECTION_TYPED_SOURCE_PIN_REQUIRED PUBLIC_DIRECTORY_CHANGED_DURING_CAPTURE PUBLIC_PAYLOAD_AGGREGATE_CAP PUBLIC_TREE_CHANGED_BEFORE_CAPSULE_PUBLICATION PUBLIC_TREE_COUNT_CAP PUBLISHED_CAPSULE_CHANGED REGULAR_ARTIFACT_MANIFEST_REQUIRED SELECTED_SOURCE_LEAF_CHANGED_BEFORE_PROJECTION SOURCE_COMMAND_LOG_NAMESPACE_DIFFERS SOURCE_PINNED_BACKEND_MEMBER_MISSING_OR_CHANGED UNKNOWN_FEATURE_ROOT_ENTRY_REFUSED UNKNOWN_JOURNEY_ENTRY_REFUSED UNKNOWN_PUBLIC_PROOF_LEAF_REFUSED UNKNOWN_PUBLIC_ROOT_ENTRY_REFUSED AMBIGUOUS_PROJECTION_AUTHORITY_REFUSED BACKEND_LEAF_OUTSIDE_SOURCE_WHEEL_LAYOUT_REFUSED BACKEND_PATH_PREFIX_REFUSED'''.split())
PHASES={'guard','pack','capture','validate','manifest','encode','publish','projection','projection-source','projection-read','projection-select','projection-copy'}

def _need(value):
 if not value:raise ValueError('UNSAFE_REFUSAL_METADATA')

def _sha(value,nullable=False):return value is None and nullable or type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def _path(value):
 if type(value) is not str or len(value.encode('utf-8'))>4096 or PRIVATE_MARKER.search(value.encode()):return False
 if value in HOST|PRODUCERS|{'journey/result.json','journey/build-summary.json','journey/meson-diagnostic.json','artifacts.json','public-projection.json'}:return True
 if value.startswith('transport-proof/'):
  return value.removeprefix('transport-proof/')=='receipt.json' or re.fullmatch(r'[0-9]{4}\.(stdout|stderr)',value.removeprefix('transport-proof/')) is not None
 if value.startswith('bootstrap-proof/'):return value.removeprefix('bootstrap-proof/') in PROOFS
 if re.fullmatch(r'actor-logs/[0-9]{4}\.log|provision-logs/(?:proof\.json|input-transport-owner\.json|input-cache-owner\.json)-[0-9]{3}\.log',value):return True
 for feature,names in REPORTS.items():
  prefix='journey/'+feature+'/'
  if value.startswith(prefix):
   suffix=value.removeprefix(prefix)
   if suffix in names or re.fullmatch(r'[0-9]{3}-[A-Za-z0-9][A-Za-z0-9_+.-]{0,127}\.log',suffix):return True
 return value.startswith('journey/python/venv/') and value.removeprefix('journey/python/venv/') in BACKEND

def validate_context(value,path):
 keys={'schema','rule_id','logical_field','field_path_sha256','field_sha256','whole_file'}
 _need(type(value) is dict and (set(value)==keys or set(value)==keys|{'scope'}))
 _need(type(value['schema']) is int and value['schema']==1 and value['rule_id'] in {'PRIVACY_00',*(r[0] for r in RULES)})
 whole=value['whole_file'];_need(type(whole) is dict and set(whole)=={'bytes','sha256'} and type(whole['bytes']) is int and 0<whole['bytes']<=CAP and _sha(whole['sha256']))
 _need(_sha(value['field_path_sha256'],True) and _sha(value['field_sha256'],True))
 if value['logical_field']=='PINNED_PYTHON_HEADER_MAP_KEY':
  _need(set(value)==keys|{'scope'} and value['scope']=='EXTENSION_HEADER_REPORT' and value['field_sha256'] is None
   and value['field_path_sha256'] in {hashlib.sha256(_canonical(list(parts))).hexdigest() for parts in _pinned_header_paths().get(path,set())})
  return True
 _need(set(value)==keys)
 if value['logical_field']=='UNCLASSIFIED':_need(value['field_sha256'] is None)
 elif type(value['logical_field']) is str and value['logical_field'] in LABEL_PATHS.get(path,{}):
  _need(value['field_sha256'] is None and value['field_path_sha256'] in
   {hashlib.sha256(_canonical(list(parts))).hexdigest() for parts in LABEL_PATHS[path][value['logical_field']]})
 else:
  known={'.'.join(parts):parts for parts in FIELDS.get(path,set())};_need(type(value['logical_field']) is str and value['logical_field'] in known)
  _need(_sha(value['field_sha256']) and value['field_path_sha256']==hashlib.sha256(_canonical(list(known[value['logical_field']]))).hexdigest())
 return True

def validate_refusal(value):
 """Shared strict validator for owner persistence and safe DATA fallback."""
 try:
  keys={'schema','status','phase','code','path','path_sha256','member'}
  _need(type(value) is dict and (set(value)==keys or set(value)==keys|{'privacy_context'}))
  _need(type(value['schema']) is int and value['schema']==1 and value['status']=='REFUSED_PUBLIC_DATA'
   and type(value['code']) is str and value['code'] in CODES and type(value['phase']) is str and value['phase'] in PHASES)
  _need(_sha(value['path_sha256'],True) and (value['path'] is None or _path(value['path'])))
  _need(value['path'] is None or value['path_sha256'] is None)
  _need(value['member'] is None or type(value['member']) is str and re.fullmatch(r'index\.json|data/[0-9]{6}',value['member']))
  if value['code']=='PRIVATE_MATERIAL_MARKER_IN_SELECTED_PUBLIC_DATA_REFUSED':
   _need(value['phase']=='projection-select' and value['path'] is not None and value['member'] is None and 'privacy_context' in value)
   validate_context(value['privacy_context'],value['path'])
  else:_need('privacy_context' not in value)
  _need(len(_canonical(value))<=4096)
  return True
 except (ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):raise ValueError('UNSAFE_REFUSAL_METADATA') from None
