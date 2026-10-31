#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Default-null source/emission controls, with all process creation prohibited."""
import argparse,ast,json,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import candidates as C
import derive as D
import dns_contract as DNS
import emit
import job
import run

def refusal(operation):
    try:operation()
    except ValueError:return
    raise ValueError('required refusal missing')
def functions(text):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}

def check(source,out):
    with patch('subprocess.Popen',side_effect=AssertionError('actor prohibited')),patch('subprocess.run',side_effect=AssertionError('actor prohibited')):
        C.verify_source(source);policy=C.read(C.HERE/'input-policy.json')
        C.need(policy==C.read(C.HERE/'null-policy.json')and policy['status']=='UNBOUND','canonical default input policy must remain exact NULL fixture')
        for row in policy['inputs'].values():C.need(all(row[k]is None for k in ('carrier_source','carrier_ref','index_path','index_pin','decision_pin','decision_status')),'public packet approval/selection not supplied')
        for operation in (lambda:C.selection(source),lambda:job.prove(source,'minimal',{}),lambda:run.execute(source,source,source,out,'minimal')):refusal(operation)
        for name,derive,changed in [('management_phase.py',D.phase,{'exercise','report_command'}),('management_root.py',D.root_fixture,{'serve','find'}),('management_contract.py',D.management,{'verify_result','visible_control','action'})]:
            old=functions((source/'scripts/ci/welcome-management-native'/name).read_text());new=functions(derive(source))
            C.need(set(old)==set(new)and {k:v for k,v in old.items()if k not in changed}=={k:v for k,v in new.items()if k not in changed},'unaffected original function changed')
        for path in C.HERE.glob('*.py'):ast.parse(path.read_text(),filename=str(path))
        raw=DNS.encoded(dict(status='STORED_CONNECTION_PROFILES',profiles=[DNS.PROFILE],live_dns='NOT_REAPPLIED_STORED_PROFILE_ONLY'));DNS.report(raw)
        refusal(lambda:DNS.report(raw.replace(b'STORED_CONNECTION_PROFILES',b'UNKNOWN')))
        result=emit.emit(source,out);expected=emit.closed(out)
        # Both real .git forms are metadata only, never a generic dotfile bypass.
        meta=out/'.git';meta.write_text('gitdir: /source-control-only\n');C.need(emit.closed(out)==expected,'Git worktree metadata mishandled');meta.unlink()
        meta.mkdir();(meta/'HEAD').write_text('source-control-only\n');C.need(emit.closed(out)==expected,'Git checkout subtree mishandled');(meta/'HEAD').unlink();meta.rmdir()
        extra=out/'.unexpected';extra.write_text('must refuse\n');refusal(lambda:emit.closed(out));extra.unlink()
        C.need(emit.closed(out)==expected,'closed source not restored after refusal control')
    return dict(status='PASS_DEFAULT_NULL_SOURCE_AND_EMISSION_NO_ACTORS',source_files=result['files'],public_selection='NULL',GUI='NOT_RUN',hardware='NOT_RUN')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(check(a.source.absolute(),a.output.absolute()),sort_keys=True))
