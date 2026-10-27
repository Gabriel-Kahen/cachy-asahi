# SPDX-License-Identifier: MIT
"""Finite source-only578 reuse and separately unbound current607 route.

Reads only explicitly supplied source contracts and the exact qualified DATA
scope receipt. No source execution, root acquisition, actor or acceptance API.
"""
import argparse,copy,hashlib,json,os,re,stat
from pathlib import Path
SOURCE='0ab7177026b02f813125b2b843f51b7650c35774'
RUN=40417662010
CAPSULE=dict(bytes=47033,sha256='bb772e76d94fed2b5342efbb4b9623740310b3d724bc62e2120ca8ad68dbff87')
QUALIFIED=dict(bytes=1313,sha256='85682bff8896c968486b2889040277b729c9a96d2eadd524dc65ffe825291231')
CURRENT607_PROFILE=dict(bytes=18898,sha256='28d209ed1be8d5a2e79524cd542be896b40b203d2429bc68e5f8476e7b781ebd')
CURRENT607_POLICY=dict(bytes=3840,sha256='2cf9c6980e509d88e3baab2355ada32aa8395042dfe2995da87a40ea61e178fa')
TOOLING_PROFILE=dict(bytes=1486,sha256='ab6f28ec8d5a3f637729c4f5fbf7ca3c0846d705967650f60c072b5468baa156')
MATERIALIZER_MAP=dict(bytes=230902,sha256='497fe59f6615388c56366affa749d2f7cb25ccf6432f506770a718e1ed2c8850')
APPS_ARCHIVE=dict(bytes=29664,sha256='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af')
CURRENT607_ROOT_AUTHORITY=None
REQUIREMENTS=(
 'Independent Root admission of a freshly owned607 root; accepted prerequisite receipts alone are insufficient.',
 'Complete exact607 inventory/lock, Apps16 version and archive pin, and the unchanged other606 lock; never count-only admission.',
 'Explicit native-generic4k producer/consumer architecture, page, kernel and ownership context; a prior QEMU readback is not a native stopped-image handoff.',
 'Fresh root/archive identity and complete node, capability, hardlink, user/config/trust/base maps; no retired source or workspace reuse.',
 'Source/run/attempt/token-bound607 policy and lease plus exclusive source/copy ownership; no inherited574 or578 count relabeling.',
 'Reviewed finite source and reader inverses for all574-base/578-install assumptions, candidate set, snapshot, budgets and ordered disposal.',
 'Original authenticated same-version Apps16 plan, pending/lock checks, original rejection gates and all deadlines remain mandatory.',
 'New raw failure/repair receipts and independent replay; qualified interruption DATA keeps UNKNOWN commit and grants no rollback or repair-success credit.',
)


def need(ok,why):
    if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
    def pairs(rows):
        out={}
        for k,v in rows:need(k not in out,'duplicate route JSON key');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite route JSON'))
def relative(name):
    need(type(name)is str and name and not name.startswith('/')and '\\'not in name and '\0'not in name and all(n not in('','.','..')for n in name.split('/')),'ordinary source contract member');return name

def ordinary(value):
    text=os.fspath(value);need(type(text)is str and os.path.isabs(text)and text==os.path.normpath(text)and not text.startswith('//'),'explicit absolute normalized source-only input')
    path=Path(text);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source-only ancestry');return path

def read(path,cap=16*1024**2):
    path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        first=os.fstat(fd);need(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<=first.st_size<=cap,'bounded ordinary singlelink source-only input');parts=[];size=0
        while raw:=os.read(fd,65536):parts.append(raw);size+=len(raw);need(size<=first.st_size,'source-only input growth')
        identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        need(size==first.st_size and identity(first)==identity(os.fstat(fd))==identity(path.lstat()),'stable source-only FD/path identity');return b''.join(parts)
    finally:os.close(fd)

def checked(raw,want):
    need(type(want)is dict and set(want)=={'bytes','sha256'}and type(want['bytes'])is int and want['bytes']>=0 and type(want['sha256'])is str and re.fullmatch('[0-9a-f]{64}',want['sha256'])and pin(raw)==want,'exact source-only input pin');return raw


def qualified_scope(raw):
    checked(raw,QUALIFIED);v=decode(raw)
    need(v['status']=='ROOT_QUALIFIED_NATIVE_GENERIC4K_RETAINED_INTERRUPTION_DATA_ONLY'and v['source']==SOURCE and v['run']==RUN and v['attempt']==1,'exact qualified interruption DATA scope')
    need(v['protected_base_packages']==574 and v['healthy_installed_packages']==578 and v['full_current607_acceptance']=='NOT_GRANTED'and v['repair_success']is False and v['commit_started']==v['packages_committed']=='UNKNOWN'and v['rollback']=='NOT_CLAIMED'and v['hardware']=='NOT_RUN'and v['release']=='NOT_ADMITTED','574/578 DATA cannot grant607, repair, rollback or hardware credit')
    return v


def source_contract(root):
    root=ordinary(root);need(root.is_dir(),'explicit full256 source directory')
    raw=checked(read(root/'capsule.json'),CAPSULE);v=decode(raw)
    need(v['schema_version']==1 and v['status']=='SOURCE_ONLY_NATIVE_ARM_OPERATION_CAPSULE'and v['actual']is None and v['Root_acceptance']is None and len(v['files'])==255,'exact source-only255 nonself capsule')
    expected=dict(v['files'],**{'capsule.json':CAPSULE});actual={};directories=set();total=0
    for path in sorted(root.rglob('*')):
        name=relative(path.relative_to(root).as_posix());need(not path.is_symlink(),'source capsule alias')
        if path.is_dir():directories.add(name)
        else:
            need(name in expected,'foreign source capsule member');body=checked(read(path),expected[name]);total+=len(body);need(total<=64*1024**2,'bounded full256 source bytes');actual[name]=pin(body)
    parents={p.as_posix()for name in expected for p in Path(name).parents if str(p)!='.'}
    need(actual==expected and directories==parents and len(actual)==256,'entire exact256 source closure')
    snippets={
      'repair-source/scripts/ci/apps-full574-native/job.py':("PASS_NATIVE_OFFLINE_574_TRANSACTION","maintained_desktop574.py"),
      'repair-source/scripts/ci/apps-full574-native/snapshot.py':('len(rows)==574','C.sha(lock)==C.BASE'),
      'repair-source/scripts/apps/full574_closure.py':("PURPOSE='APPS_ORIGINAL574_READONLY_CLOSURE'",),
      'operation/lifecycle.py':('base_count=574,installed_count=578',),
    }
    for name,values in snippets.items():
        text=read(root/name).decode();need(all(value in text for value in values),'original574/578 source route predicate: '+name)
    return dict(source=SOURCE,capsule=CAPSULE,files=256,existing_base=574,existing_installed=578,source_only=True,source_trust_waivers=False)


def audit(source_root,qualified_data,prerequisite_profile,prerequisite_policy,tooling_profile,materializer_map):
    source=source_contract(source_root);scope=qualified_scope(read(qualified_data))
    raw_profile=checked(read(prerequisite_profile),CURRENT607_PROFILE);p=decode(raw_profile)
    policy=checked(read(prerequisite_policy),CURRENT607_POLICY).decode()
    tool=decode(checked(read(tooling_profile),TOOLING_PROFILE));material=decode(checked(read(materializer_map),MATERIALIZER_MAP))
    need(tool['sources']['fresh']==material['source']=='b9976eea34eaed4b6e56af3be21d4d652fa971d6'and material['actual']is None and len(material['files'])==1197,'whole pinned1197 fresh materializer source map, not an installed root')
    expected={'fresh607':('5a0789405ded23f759f4a3aa545cf737c4ec3bde','codex/latest607-fresh-accepted-v1',24),'baseline607':('95d86b53df796b1b309fa5f37d04587adac5cbf8','codex/latest607-apps6-baseline-accepted-v1',24),'carrier':('bbfb088d5707c986617989fa572a751bae6c25ae','codex/latest607-updater-prerequisites-v1',50)}
    records={}
    for kind,(sha,ref,count)in expected.items():
        row=p['inputs'][kind];need((row['source'],row['ref'],len(row['files']))==(sha,ref,count),'exact accepted607 source prerequisite role')
        records[kind]=dict(source=sha,ref=ref,files=count,whole_map_sha256=hashlib.sha256(json.dumps(row['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest())
        if kind!='carrier':records[kind]['decision']=row['files']['decision.json']
    need("RETAINED_SOURCE_BOUND_ROOT_REPORT_NOT_FRESH_FD_OBSERVATION"in policy and "SOURCE_BOUND_RETAINED_RECEIPTS_NOT_LIVE_REOBSERVATION"in policy and "ONE_INSTALLED_PREREQUISITE_NOT_UPDATER_ACCEPTANCE"in policy and "row.get('qemu_natural_exit')is True"in policy,'607 records retain their exact QEMU/prerequisite limitations')
    return dict(schema_version=1,status='PASS_SOURCE_CONTRACT_AUDIT_DATA_ONLY',source=source,qualified_data_pin=QUALIFIED,qualified_data_status=scope['status'],qualified_full_current607=scope['full_current607_acceptance'],current607_prerequisites=records,fresh_materializer=dict(source=material['source'],files=1197,map_pin=MATERIALIZER_MAP),current607_root_authority=None,current607_available=False,reason='NO_ADMITTED607_ROOT_PROVIDER_IN_AUDITED_SOURCE_CONTRACTS',actual_root=None,native='NOT_RUN',Root_acceptance=None,hardware='NOT_RUN',release='NOT_ADMITTED')


def pending607_request():
    return dict(schema_version=1,route='current607',expected_packages=607,protected_other_packages=606,Apps_version='0.1.0-16',Apps_archive=copy.deepcopy(APPS_ARCHIVE),execution_profile='native-generic4k',source=None,run_id=None,attempt=None,root_snapshot=None,inventory=None,expected607_lock=None,other606_lock=None,node_map=None,capability_map=None,policy=None,lease=None,producer_token=None,root_admission=None,Root_acceptance=None)


def validate_pending607(value):
    expected=pending607_request();need(type(value)is dict and set(value)==set(expected)and type(value['schema_version'])is int and type(value['expected_packages'])is int and type(value['protected_other_packages'])is int and value==expected,'closed explicitly UNBOUND607 request; no invented root or authority')
    return copy.deepcopy(value)


def admit607(value):
    need(CURRENT607_ROOT_AUTHORITY is not None,'current607 admission is UNBOUND; prerequisite DATA and a607 count cannot admit a live root')
    raise ValueError('no607 admission implementation is issued by this source-only audit')


def select_route(requested,audited,request607=None):
    need(requested in('prefer607','native578','current607'),'finite requested source route')
    need(audited['status']=='PASS_SOURCE_CONTRACT_AUDIT_DATA_ONLY'and audited['source']==dict(source=SOURCE,capsule=CAPSULE,files=256,existing_base=574,existing_installed=578,source_only=True,source_trust_waivers=False)and audited['qualified_data_pin']==QUALIFIED and audited['current607_root_authority']is None and audited['current607_available']is False,'source-audited exact574/578 and unbound607 contracts')
    pending=validate_pending607(pending607_request()if request607 is None else request607)
    route=None if requested=='current607'else'native578'
    return dict(schema_version=1,status='PENDING_INDEPENDENT607_ROOT_ADMISSION'if route is None else'SOURCE_ROUTE578_REUSE_NO_REPAIR_OUTCOME',requested_route=requested,selected_route=route,source=SOURCE,protected_base_packages=574 if route else None,healthy_installed_packages=578 if route else None,selected_native_archive=APPS_ARCHIVE,source_only=True,actual_root=None,root_ready=False,current607=dict(status='PENDING_SEPARATE_ROUTE',request=pending,authority=None,requirements=list(REQUIREMENTS)),reason=audited['reason'],runtime='NOT_RUN',repair_success=False,commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',Root_acceptance=None,hardware='NOT_RUN',release='NOT_ADMITTED')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in('source-root','qualified-data','prerequisite-profile','prerequisite-policy','tooling-profile','materializer-map'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--route',choices=('prefer607','native578','current607'),default='prefer607');p.add_argument('--pending-request',type=Path);a=p.parse_args()
    report=audit(a.source_root,a.qualified_data,a.prerequisite_profile,a.prerequisite_policy,a.tooling_profile,a.materializer_map)
    request=decode(read(a.pending_request))if a.pending_request is not None else None
    print(encoded(dict(audit=report,selection=select_route(a.route,report,request))).decode(),end='')
    return 0
if __name__=='__main__':raise SystemExit(main())
