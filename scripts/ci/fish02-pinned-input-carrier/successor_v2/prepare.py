#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Bound Fish exact501, inner512/cadence and strict public HOLD preservation."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('frozen_fish_carrier',HERE.parent/'prepare.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)
P=A.P;PREFIX=A.PREFIX;MARKER=A.MARKER
PARENT=dict(files=62,bytes=1431202,tree='9db85398af8cd52b43adcf5925568b7bcf54cbc7',map=dict(bytes=13276,sha256='44a5c63ae729a9eb0fb83280659e987fc29dee0b105e5125ab12975a6a1d2507'))
EXPORTER_PIN=dict(bytes=10144,sha256='9fb780b222a10cddbd4b74518e53d42b15690da981cefeb15add5b767296d2cd')
BINDING=dict(repository='Gabriel-Kahen/cachy-asahi-ci-inputs',branch='native349-r1',commit='9d9e1ab7ce694e33238ec1152bef72270d4bf91f',tree='cc6298d8dbbb5b0dd522de76b7140306d83bfe7a',manifest=dict(bytes=99724,sha256='d831cf894377deb4a90f6b8fd69eca08263318273a58061936f00b7ad82ba18e'),ssh_host_keys=['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'],deploy_key_fingerprint='SHA256:6gnCZBWA+I9mccJV/YzywHoefkGrpuKBHU0dVcgqn7k',Root_receipt=dict(bytes=1545,sha256='8fc5e5af70725a9e58db957885cdcbbb0a7694edb55694d059d882c0a41e41ac'),readonly_repository_scope='Gabriel-Kahen/cachy-asahi-ci-inputs')


def validate_parent(old):
    P.need(len(old)==62 and sum(map(len,old.values()))==PARENT['bytes']and P.pin(old['source-map.json'])==PARENT['map'],'whole immutable carrier62 map/census')
    rows=json.loads(old['source-map.json']);P.need(set(old)==set(rows['files'])|{'source-map.json'}and all(dict(P.pin(old[n]),mode=0o644)==r for n,r in rows['files'].items())and all(v is None for v in rows['actual'].values()),'whole carrier62 closure/NULL fields')
    P.need(A.data(old).git_tree(old)==PARENT['tree'],'whole carrier62 tree');A.inverse(old)


def exporter():
    raw=P.read(HERE/'public_evidence.FROZEN.py');P.need(P.pin(raw)==EXPORTER_PIN,'whole frozen strict512 exporter');text=raw.decode()
    seams=(('cachy-asahi-llhttp-reference-9.3.1-1-aarch64','cachy-asahi-fish-config-0.1.0-2-any'),('llhttp-reference-native','fish02-native'),('PASS_CURRENT_LLHTTP_REFERENCE_NATIVE_PAIR_ONLY','PASS_CURRENT_FISH02_NATIVE_PAIR_ONLY'))
    for before,after in seams:P.need(before in text and after not in text,'literal Fish public operand');text=text.replace(before,after)
    reverse=text
    for before,after in reversed(seams):reverse=reverse.replace(after,before)
    P.need(reverse.encode()==raw,'whole strict public exporter inverse');return text.encode()


def assemble(old):
    validate_parent(old);new=dict(old);seams={}
    def change(name,before,after):
        text=new[name].decode();P.need(text.count(before)==1 and after not in text,'one bound512/HOLD seam');new[name]=text.replace(before,after).encode();seams.setdefault(name,[]).append(dict(before=before,after=after))
    helper=A.HELPER;host=PREFIX+'hosted_owner.py';d=PREFIX+'data.py';program=PREFIX+'owner-program.json';public=PREFIX+'public_evidence.py'
    change(helper,'project_entry=N.project_entry','''_ORIGINAL_PROJECT_ENTRY=N.project_entry
N.BINDING='''+repr(BINDING)+'''

def project_entry(raw):
    prior=_ORIGINAL_PROJECT_ENTRY(raw)
    before=b'len(self.rows)<160';after=b'len(self.rows)<512'
    N.need(prior.count(before)==1 and after not in prior,'one finite512 held-command seam')
    result=prior.replace(before,after)
    N.need(result.replace(after,before)==prior,'whole original held command guard inverse')
    return result''')
    anchor="s=importlib.util.spec_from_file_location('fish02_exact_carrier',HERE/'native349_carrier_case.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)"
    change(host,anchor,anchor+"\ns=importlib.util.spec_from_file_location('fish02_strict_public_HOLD',HERE/'public_evidence.py');E=importlib.util.module_from_spec(s);s.loader.exec_module(E)")
    change(host,"            time.sleep(.1)\n        raise TimeoutError('owned service startup deadline')","            time.sleep(min(1.0,max(0.0,until-time.monotonic())))\n        raise TimeoutError('owned service startup deadline')")
    change(host,"            time.sleep(.2)\n        evidence=work/","            time.sleep(min(10.0,max(0.0,owner.end-time.monotonic())))\n        evidence=work/")
    before="""        # Copy only original finite public evidence, never cache/keyring/config or Docker data.
        total=0;public=a.output/'evidence';public.mkdir(mode=0o700)
        for path in evidence.rglob('*'):
            D.need(not path.is_symlink(),'ordinary inherited evidence')
            if path.is_file():
                raw=D.read(path,16*1024**2,empty=True);total+=len(raw);D.need(total<=16*1024**2,'same complete public evidence cap')
                target=public/path.relative_to(evidence);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
"""
    change(host,before,'        # Exact public outputs are snapshotted in finally before cleanup.\n')
    anchor="    finally:\n        report['host_preflight']=owner.host_facts"
    change(host,anchor,"""    finally:
        E.preserve(report,a.output/'volume/work/fish02-native',a.output/'evidence',
                   dict(source=actual['source'],ref=actual['ref'],source_map_sha256=a.source_map_sha256,
                        run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ['GITHUB_JOB'],nonce=actual['nonce']),a.runner_uid)
        report['host_preflight']=owner.host_facts""")
    change(d,"value['kind']=='FISH02_EXACT_PINNED_INPUT_CARRIER_SOURCE_V1' and len(rows)==61","value['kind']=='FISH02_BOUND512_PUBLIC_HOLD_SOURCE_V2' and len(rows)==62")
    change(d,'inverse_source60(inverse_source62(bodies))','inverse_source60(inverse_source62(inverse_carrier_source62(bodies)))')
    for name,parts in seams.items():
        reverse=new[name].decode()
        for part in reversed(parts):reverse=reverse.replace(part['after'],part['before'])
        P.need(reverse.encode()==old[name],'whole original Fish program inverse');ast.parse(new[name])
    new[d]+=b'\n'+P.read(HERE/'inverse.py');new[public]=exporter();ns=dict(__name__='inert_fish_public',__file__=str(HERE/'MODEL-E.py'));exec(compile(new[public],ns['__file__'],'exec'),ns)
    policy=json.loads(old[PREFIX+'policy.json']);policy['private_pinned_input_carrier']['carrier_actual_commit']=BINDING['commit'];policy['private_pinned_input_carrier']['binding']=BINDING
    policy['inner_public_retention']=ns['DECLARATION'];policy['finite_command_case']=dict(kind='FISH02_EXACT501_INNER512_OUTER_CADENCE_V2',inner_limit=512,outer_limit_unchanged=512,startup_status_seconds=1,running_status_seconds=10,maximum_added_poll_wait_seconds=10,inherited_status_query_seconds=30,conservative_query_plus_wait_seconds=40,cleanup_reserve_seconds_unchanged=90,ledger=json.loads(P.read(HERE/'command-ledger.DATA.json')),CPU_RSS_PID_swap_and_deadlines_unchanged=True)
    new[PREFIX+'policy.json']=P.encode(policy)
    changed={n:raw.decode()for n,raw in old.items()if n not in new or new[n]!=raw};changed['source-map.json']=old['source-map.json'].decode();changed[program]=old[program].decode();changed[MARKER]=old[MARKER].decode()
    added=sorted(set(new)-set(old));excluded={'source-map.json',program,MARKER}
    new[MARKER]=P.encode(dict(kind='FISH02_COMPLETE_CARRIER62_BOUND512_HOLD_INVERSE_V2',origin=PARENT,before_utf8=changed,after={n:dict(P.pin(raw),mode=0o644)for n,raw in new.items()if n not in excluded and(n in changed or n in added)},added=added,actual=None))
    p=json.loads(old[program]);p['files']={n:dict(P.pin(raw),mode=0o644)for n,raw in sorted(new.items())if not n.startswith('held-source32/')and n not in('source-map.json',program)};new[program]=P.encode(p)
    new['source-map.json']=P.encode(dict(json.loads(old['source-map.json']),kind='FISH02_BOUND512_PUBLIC_HOLD_SOURCE_V2',files={n:dict(P.pin(raw),mode=0o644)for n,raw in sorted(new.items())if n!='source-map.json'}))
    return new


def inverse(new):
    proof=json.loads(new[MARKER]);P.need(proof['origin']==PARENT,'complete bound carrier62 domain');before=proof['before_utf8'];raw=before['source-map.json'].encode();P.need(P.pin(raw)==PARENT['map'],'whole fixed carrier62 map')
    rows=dict(json.loads(raw)['files'],**{'source-map.json':dict(PARENT['map'],mode=0o644)});old={n:before[n].encode()if n in before else new[n]for n in rows};validate_parent(old);P.need(new==assemble(old),'whole literal bound512 Fish successor');return old


def physical(root):
    root=Path(root);b={}
    for p in root.rglob('*'):
        P.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary complete carrier62')
        if p.is_file():P.need(p.stat().st_mode&0o777==0o644,'whole parent modes');b[str(p.relative_to(root))]=P.read(p)
    validate_parent(b);return b


def construct(parent,output):
    parent,output=map(Path,(parent,output));P.need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint Source')
    old=physical(parent);new=assemble(old);inverse(new);P.need(len(new)==63 and sum(map(len,new.values()))<2*1024**2,'strict finite Source63/2MiB')
    output.mkdir(mode=0o700)
    for n,raw in new.items():
        p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
    D=A.data(new);D.source(output,P.pin(new['source-map.json'])['sha256'])
    return dict(status='FISH02_BOUND512_CADENCE_STRICT_HOLD_SOURCE_UNISSUED',files=len(new),bytes=sum(map(len,new.values())),tree=D.git_tree(new),source_map=P.pin(new['source-map.json']),policy=P.pin(new[PREFIX+'policy.json']),program=P.pin(new[PREFIX+'owner-program.json']),helper=P.pin(new[A.HELPER]),public_exporter=P.pin(new[PREFIX+'public_evidence.py']),workflow=P.pin(new[A.NEW_WF]),full_carrier62_inverse=True,source_inverse_counts=[62,62,60,57,53,50,48],actual=json.loads(new['source-map.json'])['actual'],Root_registration=None,Root_authority=None,private_fetch='NOT RUN',native_pair='NOT RUN')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in('parent','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.parent,a.output),sort_keys=True,indent=2))
