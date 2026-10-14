# SPDX-License-Identifier: MIT
"""Concrete packet/pin preparation, normal artifact IO only. Issues no grant."""
import hashlib
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent

def row(path, sources):
    # Source custody performs each filesystem operation under the same originalE.
    path=Path(path);relative=path.relative_to(sources.root).as_posix()
    raw=sources.file(relative);sources.verify_node(relative)
    expected=sources.rows[relative]
    return {'path':str(path),**expected}

def make_packet(value,native,*,sources,capacity_path=None):
    """Root provides actual current native rows and separately admitted flags.

    The caller must authenticate Source/270, this closure, original clock and
    guardian before launch. This function cannot promote or invent that state.
    """
    value=json.loads(json.dumps(value,allow_nan=False));native=json.loads(json.dumps(native,allow_nan=False))
    assert set(native)=={'execution_granted','dependencies','interpreter','stdlib','mapping_grant','checker_root'}
    selected=lambda path:row(path,sources)
    bootstrap=selected(HERE/'bootstrap.py')
    value['schema']=1;value['lane']='native-topmem-fish-zsh-integrated-pairs-v3'
    value['helper_bundle']={k:bootstrap[k] for k in ('path','sha256')}|{'api':'integrated-pairs-v3'}
    integration={'core':{p.name:selected(p) for p in [HERE/'selected/core'/name for name in ('authority.py','artifact_custody.py','zstd_owner.py','checker.py','pair_archive.py','pair_compare.py')]},
        'adapter':{p.name:selected(p) for p in [HERE/'selected/adapter'/name for name in ('admission.py','descriptor_ops.py','source_library_loader.py')]},
        'bridge':selected(HERE/'checker_bridge.py'),'capabilities':selected(HERE/'capabilities.py'),
        'capacity':selected(capacity_path or HERE/'capacity/boundary-followup/capacity_plan.py'),'native':native}
    pins={'contract':{k:v for k,v in selected(HERE/'pair_contract.py').items() if k in ('path','sha256')},
        'recipes':{k:v for k,v in selected(HERE/'recipe_rows.json').items() if k in ('path','sha256')},
        'entry':{k:v for k,v in selected(HERE/'selected/entry.sh').items() if k in ('path','sha256')},
        'helper_admission':dict(value['helper_bundle']),'integration':integration,'bootstrap_bytes':bootstrap['bytes']}
    return {'value':value,'pins':pins}

def native_grant_fields(job,*,inspector_sha,library_sha,dependencies,interpreter_sha,ABI):
    """Fill exact bindings only; Root must separately issue the three flags."""
    def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    return {'job_binding':digest(job),'inspector_source_sha256':inspector_sha,'library_sha256':library_sha,
        'dependencies_binding':digest(dependencies),'interpreter_sha256':interpreter_sha,'abi_binding':digest(ABI),
        'enabled':False,'initialization_admitted':False,'confinement_admitted':False}

if __name__=='__main__':raise SystemExit('REFUSED: call make_packet with Root-selected current native rows; no input/actor admission is issued')
