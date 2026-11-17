# SPDX-License-Identifier: MIT
"""Source339 two-leaf correction and new derived TSV; never execute a guest."""
import hashlib,importlib.util,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('strict_cache_transition',HERE/'transition.py');T=importlib.util.module_from_spec(s);s.loader.exec_module(T)
def verify():
 lock=json.loads((HERE/'source.lock.json').read_bytes());names={p.relative_to(HERE).as_posix()for p in HERE.rglob('*')if p.is_file()and p.relative_to(HERE).as_posix()!='source.lock.json'};T.C.need(names==set(lock['files'])and not any(p.is_symlink()for p in HERE.rglob('*')),'closed physical proposal')
 for name,row in lock['files'].items():
  p=HERE/name;T.C.need(dict(**T.C.pin(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode))==row,'whole proposal bytes/modes')

def manifest(baseline):
 verify()
 p=json.loads((HERE/'providers.DATA.json').read_bytes());v,expected=T.derive(baseline,p['baseline_nodes'],p['db_nodes'],p['db_elf_sonames'])
 lines=['PERL5423_DB53_CACHE_TRANSITION_V1']+[tag+' '+str(v[key]['bytes'])+' '+v[key]['sha256']for tag,key in(('BASELINE','baseline'),('INSTALLED','installed'),('RESTORED','restored'))];return ('\n'.join(lines)+'\n').encode(),v,expected

def apply(initialized,root,baseline):
 p=json.loads((HERE/'provenance.DATA.json').read_bytes())
 for name,body in(('initialized-state.sh',initialized),('root.sh',root)):T.C.need(T.C.pin(body)==p['predecessor'][name],'exact unchanged Source339 operational leaves')
 text,v,expected=manifest(baseline);guard=initialized.decode();body=root.decode();old='  [[ $(_initialized_view "$i") == "${initialized_expected[$i]}" ]] || { _ig_diagnostic R21 "${i:-14}";return 2; }'
 new='  current=$(_initialized_view "$i") || return\n  if [[ ( $i == 5 || $i == 9 ) && ( ${initialized_cache_phase:-} == INSTALLED || ${initialized_cache_phase:-} == RESTORED ) ]];then\n   _initialized_cache_phase_view "$i" "$current" "${initialized_expected[$i]}" || { _ig_diagnostic R21 "${i:-14}";return 2; }\n  else [[ $current == "${initialized_expected[$i]}" ]] || { _ig_diagnostic R21 "${i:-14}";return 2; };fi'
 T.C.need(guard.count(old)==1 and guard.count(' local i path before attrs\n')==1,'one exact view comparison and local declaration');guard=guard.replace(old,new).replace(' local i path before attrs\n',' local i path before attrs current\n')
 helper=(HERE/'guest-cache-transition.sh').read_text();T.C.need(helper.count('@CACHE_TRANSITION_MANIFEST_SHA256@')==1,'one constructor-bound manifest pin');guard+='\n'+helper.replace('@CACHE_TRANSITION_MANIFEST_SHA256@',hashlib.sha256(text).hexdigest())
 changes=[(' bounded "$install_seconds" "$S/dependency-install.log"',' initialized_cache_transaction_begin\n bounded "$install_seconds" "$S/dependency-install.log"'),('_ig_substage REMOVE_DONE\n_ig_substage ASSERT_USERS_ENTER','_ig_substage REMOVE_DONE\ninitialized_cache_transaction_installed\n_ig_substage ASSERT_USERS_ENTER'),('checkpoint_phase cache_restoration\ninitialized_guard','checkpoint_phase cache_restoration\ninitialized_cache_transaction_restored\ninitialized_guard')]
 for a,b in changes:T.C.need(body.count(a)==1,'one exact fixed lifecycle phase insertion');body=body.replace(a,b)
 return dict(initialized=guard.encode(),root=body.encode(),manifest=text,derivation=v,expected_installed=expected)

def inverse(value,baseline):
 a=(HERE/'predecessor-initialized-state.sh').read_bytes();b=(HERE/'predecessor-root.sh').read_bytes();T.C.need(value==apply(a,b,baseline),'exact emitted successor before inverse');return a,b
