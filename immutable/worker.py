"""New-purpose worker entry; original lifecycle bodies run through explicit API."""
import ast,hashlib,os,re,socket,sys
from pathlib import Path
import inputs,worker_api
P,C,client,B=inputs.broker()

def lifecycle(raw):
 before="report['proc_preflight']['status']=='PASS_READONLY_PROC_PREFLIGHT' and report['proc_preflight']['cleanup']=='PASS_OWNED_EMPTY_PROBE_REMOVED'"
 after="report['proc_preflight']['status']=='PASS_PID1_READONLY_PROC_PREFLIGHT' and report['proc_preflight']['cleanup']=='PASS_PID1_OWNED_PROBE_REMOVED'"
 text=raw.decode();P.need(text.count(before)==1,'one explicit new-purpose preflight receipt guard');text=text.replace(before,after);P.need(text.replace(after,before).encode()==raw,'whole lifecycle inverse');return text

def run(fd,nonce,bootstrap):
 P.need(os.getpid()!=1 and os.getppid()==1,'actual direct child only');sock=socket.socket(fileno=fd);P.channel(sock);P.need(P.peer(sock)==(1,0,0),'real PID1-created channel')
 B.close_except({0,1,2,fd});bootstrap.install_worker_fences();bootstrap.drop_worker();channel=client.Client(sock,nonce)
 # Guest/contract source is pinned, never read from an artifact or worker plan.
 guest=inputs.original('_gnu_immutable_original_guest','scripts/ci/glibc-gnu-provider-installed16k/guest.py');G=guest.C
 selection=G.decode(G.read('/installed16k/selection.json'));P.need(selection['nonce']==nonce and os.uname().release==selection['kernel']['release']and os.sysconf('SC_PAGE_SIZE')==16384,'actual original kernel/nonce/16K join')
 original=G.read('/installed16k/container16k.py');P.need(G.sha(original)==selection['adapter_sha256'],'original exact generated16K lifecycle')
 text=lifecycle(original);module=G.load('_immutable_lifecycle','/installed16k/container16k.py');namespace=vars(module);exec(compile(text,'<explicit-pid1-mount-lifecycle>','exec'),namespace)
 helpers=module.C.helpers
 def bound_helpers(root):return worker_api.bind(helpers(root),channel,guest)
 module.C.helpers=bound_helpers
 os.environ.update(CACHY_GNU_PROVIDER_LIFECYCLE='1',INPUT_INDEX_SHA256=selection['input_index_sha256'],OUTPUT_UID='0',OUTPUT_GID='0',PYTHONDONTWRITEBYTECODE='1')
 G.save('/out/isolation.json',dict(purpose='GNU_IMMUTABLE_RUNTIME_V1',worker_mask=P.WORKER_MASK,raw_devices='ABSENT_ACTUAL_CLIENT_GUARD',syscall_filters='WHOLE_ORIGINAL_HELD',authority='NOT_OLD_NATIVE10_OR_LEGACY8_PURPOSE'))
 code=module.main();P.need(code==0,'unchanged complete two-case574 provider lifecycle')
 # A new purpose result, not old three-record kernel/lifecycle acceptance.
 report=G.decode(G.read('/out/result.json',8*1024**2));P.need(report['status']=='PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE'and not any(Path('/work').iterdir()),'full original lifecycle/clone cleanup')
 native=module.C;index,_,_,_=native.configuration(Path('/inputs'),selection['input_index_sha256']);api=native.helpers(Path('/source'));stages=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after');caps=api['capabilities'].records(index,report['cases'],stages)
 for case in native.CASES:
  row=report['cases'][case];P.need(row['status']=='PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE'and row['source_before']==row['source_after']==index['source_nodes_sha256']and row['copy_lifetime']['cleanup']=='PASS-owned-workspace-removed','original full574/source/copy guards')
  for name in('before_runtime','provider_runtime','reinstalled_runtime','held_runtime'):P.need(row[name]['result']['page_size']==16384 and row[name]['normal_parent_and_child']is True,'all eight real normal runtime observations')
 files={};total=0
 for path in sorted(Path('/out').iterdir()):
  P.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',path.name),'whole original closed evidence filename');raw=G.read(path,64*1024**2);files[path.name]=P.pin(raw);total+=len(raw)
 P.need(len(files)<=256 and total<=512*1024**2 and sum(n.endswith('-root.json.gz')for n in files)==16,'all16 fullmaps and original export limits')
 print(P.encode(dict(files=files,bytes=total,purpose='GNU_IMMUTABLE_RUNTIME_V1',status='SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT',nonce=nonce,source_nodes_sha256=index['source_nodes_sha256'],capabilities=caps,worker_mask=P.WORKER_MASK,boot='ACTUAL16K_OBSERVED_NOT_ROOT_ACCEPTED',hardware='NOT_RUN',release='NOT_ADMITTED')).decode(),end='',flush=True)
