# SPDX-License-Identifier: MIT
"""One reversible BUILDINFO predicate successor; held Readers stay byte-exact."""
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent/'v6/base.py'
PARENT_SHA = '381586ed2c175d7c950c54e4c8bd10eedcc68a54dd0b4275e8cda4bcb916cfc9'
HELPER_SHA = '1e86fbac17b2cf5dad23f59c12a6b39be60d8cbecc9288a071077a338c6ca37b'
for path, sha in ((PARENT,PARENT_SHA),(HERE/'buildinfo.py',HELPER_SHA)):
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != sha:
        raise ValueError('whole trusted passive Reader7 dependency')
spec = importlib.util.spec_from_file_location('llvm7_held_base6',PARENT)
held = importlib.util.module_from_spec(spec);spec.loader.exec_module(held)
spec = importlib.util.spec_from_file_location('llvm7_buildinfo',HERE/'buildinfo.py')
buildinfo = importlib.util.module_from_spec(spec);spec.loader.exec_module(buildinfo)
v, old, parent_pins = held.v, held.old, held.parent_pins
projection_proof = dict(held.projection_proof,buildinfo_helper_sha256=HELPER_SHA)
BEFORE = b"    expected = {'installed = '+s.replace(' ','-',1) for s in read(source/'expected349.lock').decode().splitlines()}\n    need({s for s in metadata['.BUILDINFO'].decode().splitlines() if s.startswith('installed = ')} == expected, 'complete349 package BUILDINFO')"
AFTER = b"    buildinfo349(metadata['.BUILDINFO'],source,evidence)"


def install(specification, namespace):
    proof = held.install(specification,namespace)
    # held.install recreates replay: apply the BUILDINFO seam afterwards.
    frozen = old.B.function_bytes(old.B._closure['v2/reader.py'],'replay')
    runtime, runtime_proof = old.B.projected(frozen,[(
        b"observed = load(data/'runtime.json');runtime(observed)",
        b"verified_namespace(data,result);observed = load(data/fact_names['runtime']);runtime(observed)")],'runtime facts')
    v.need(runtime_proof == proof['replay'],'unchanged inherited runtime namespace projection')
    replay, buildinfo_proof = old.B.projected(runtime,[(BEFORE,AFTER)],'BUILDINFO installed encoding')
    profile = v.load(HERE/'architecture-profile.json')
    v.buildinfo349 = lambda raw,source,evidence: buildinfo.check(raw,source,evidence,v,profile)
    exec(compile(replay,'<trusted-Reader7-BUILDINFO-encoding-only>','exec'),v.__dict__)
    v.need(v.replay.__globals__ is v.__dict__ and v.replay.__globals__['commands'] is v.commands and
           v.replay.__globals__['retirement'] is v.retirement and v.retirement is held.v.retirement,
           'new replay retains strict receipt namespace and Reader6 retirement')
    return dict(proof,buildinfo=buildinfo_proof,architecture_basis=profile['kind'])
