# SPDX-License-Identifier: MIT
"""Finite insertion into the unchanged genuine native606 owner and sequence."""
import hashlib
from pathlib import Path
import shutil
import accepted_inputs as A
import prepare_inputs

SEQUENCE=" checkpoint('baseline604',base);install('install606');install('same-version606');remove('remove604');install('reinstall606');remove('final604')"
WITH_BOOT=" checkpoint('baseline604',base);install('install606');install('same-version606')\n import sys\n sys.path.insert(0,'/runner/boot607')\n import boot607\n previous_ld,previous_aux=boot607.exercise(g,locals())\n remove('remove604');install('reinstall606');remove('final604')"

def one(raw,before,after):
    A.need(raw.count(before)==1,'one exact genuine606-to-Boot insertion seam')
    return raw.replace(before,after)

def consumer(raw):
    result=one(raw,SEQUENCE,WITH_BOOT)
    A.need(one(result,WITH_BOOT,SEQUENCE)==raw,'entire original native606 sequence held outside one insertion')
    compile(result,'<native606-plus-Boot>','exec')
    return result

OWNER_EDITS=(
 ("    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))","    save(out/'input-summary.json',dict(summary=summary['summary'],retention=summary['retention']))\n    Y.prepare_nonce(out)"),
 ("    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates.","    Y.authorize()\n    policy,summary=verify(args)  # No output, secrets, Docker or producer module before all input gates."),
 ("        X.validate(life.get('tools606'))","        X.validate(life.get('tools606'))\n        Y.validate_boot(life.get('boot607'))"),
 ("status='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'","status='PASS_NATIVE606_TO607_BOOT_SYNTHETIC_COMPONENT_REQUIRES_REPLAY'"),
 ("    home=producer_root/'private/expanded604-verifier'", "    C.need(not (producer_root/'private/boot607-public-verifier').exists()and not (producer_root/'private/boot607-public-verifier').is_symlink(),'Boot public verifier agent absence uncertain; preserve original producer')\n    home=producer_root/'private/expanded604-verifier'"),
)

def owner(raw):
    result=raw
    for before,after in OWNER_EDITS:result=one(result,before,after)
    restored=result
    for before,after in reversed(OWNER_EDITS):restored=one(restored,after,before)
    A.need(restored==raw and 'active.process.wait(timeout=1800)' in result and
           'signal.setitimer(signal.ITIMER_REAL,6600)' in result,'whole native606 owner inverse/clocks held')
    compile(result,'<native606-plus-Boot-owner>','exec')
    return result

class Integration:
    """Original native606 prepare/validation/export, with bounded Boot additions."""
    def __init__(self,root,prior,source,packet,authorize):
        self.root,self.prior,self.source,self.packet,self._authorize=root,prior,source,packet,authorize
        self.nonce=None
    def __getattr__(self,name):return getattr(self.prior,name)
    def authorize(self):
        # Constructor supplies the mandatory whole Apps350 held-native263 source,
        # original accepted606 Root decision, new NULL/bound policy and carrier
        # commit/index gates. Never derive original606 authority from Apps350 copy.
        return self._authorize()
    def prepare_nonce(self,out):
        import os,json
        self.nonce=os.urandom(16).hex()
        path=out/'boot607-selection.json'
        A.need(not path.exists() and not path.is_symlink(),'fresh source-owned native Boot nonce receipt')
        path.write_text(json.dumps(dict(purpose='SOURCE_OWNED_NATIVE606_BOOT607_CONTEXT',nonce=self.nonce,authority='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',actual_source=None,actual_ref=None,actual_run=None),sort_keys=True)+'\n');path.chmod(0o600)
    def prepare(self,root,producer,out,owned,ready,C):
        tools,runner=self.prior.prepare(root,producer,out,owned,ready,C)
        checks=C.load('boot607_held_package_checks',root/'held-tools/scripts/checks/package_checks.py')
        plan=prepare_inputs.make(packet=self.packet,original606_root=root,producer=producer,ready604=out/'ready604',output=tools/'boot607',C=C,checks=checks,nonce=self.nonce)
        target=runner/'boot607';target.mkdir()
        for name in ('accepted_inputs.py','native_contract.py','package_graph.py','transaction_adapter.py','step_entry.py','boot607.py'):
            shutil.copyfile(self.source/name,target/name)
        for name in ('lifecycle.py','boot_fixture.py','installed_fixture.py'):
            shutil.copyfile(self.source/'accepted-boot79'/name,target/('accepted-lifecycle.py' if name=='lifecycle.py' else name))
        shutil.copytree(self.source/'accepted-boot79/boot-fixture',target/'boot-fixture')
        shutil.copytree(self.root/'copyworker',target/'copyworker')
        shutil.copyfile(self.root/'copyworker/scripts/ci/current606-apps7-copy/alpm_step.py',target/'held-alpm-step.py')
        program=runner/'tools606.py';before=program.read_bytes();program.write_text(consumer(before.decode()))
        self.ledger=dict(status='SOURCE_ONLY_NATIVE606_TO607_BOOT_FINITE_DERIVATION',original606=A.pin(before),derived606=A.pin(program.read_bytes()),native606_sequence='FULL_ORIGINAL_BEFORE_AND_AFTER_INSERTION',consumer_seconds=1800,owner_seconds=6600,accepted_boot=plan,files={p.relative_to(target).as_posix():A.pin(p.read_bytes()) for p in sorted(target.rglob('*')) if p.is_file()})
        (tools/'boot607-runner-derivation.json').write_bytes(C.encoded(self.ledger))
        for p in (target,*target.rglob('*')):
            A.need(not p.is_symlink(),'ordinary source-owned native runner')
            p.chmod(0o755 if p.is_dir() else 0o644)
        return tools,runner
    def validate_boot(self,result):
        A.need(type(result) is dict and result.get('status')=='PASS_NATIVE606_TO607_ACCEPTED_BOOT_SYNTHETIC_LIFECYCLE_REQUIRES_REPLAY' and
               (result.get('base_count'),result.get('installed_count'),result.get('restored_count'))==(606,607,606) and
               result.get('scope')=='COMPLETE_PACKAGE_PAYLOAD_RAW_DB_KNOWN_ANCESTRY_PLUS_ETC_HOME_ROOT_NOT_WHOLE_ROOT' and
               result.get('new_boot_builds')=='NOT_RUN_ACCEPTED_PAIR_REUSED' and result.get('chroot_copy607')=='NOT_ISSUED' and
               result.get('hardware')==result.get('GUI')=='NOT_RUN' and result.get('real_journal')==result.get('live_pstore')=='NOT_READ' and result.get('release')=='NOT_ADMITTED', 'strict finite Boot native component result')
        import importlib.util
        spec=importlib.util.spec_from_file_location('_boot607_original15_validator',self.source/'accepted-boot79/boot_fixture.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        A.need(result.get('source_owned_nonce')==self.nonce and result.get('nonce_authority')=='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION','native result/source-owned transport nonce join')
        events=result['events']
        A.need([e['phase'] for e in events]==['install607','same-version607','remove606','reinstall607','final606'] and
               [e['count'] for e in events]==[607,607,606,607,606], 'five exact native607/606 transitions')
        for e in events:
            A.need(e['other606']['status']=='PROTECTED_KNOWN606_GRAPH_HELD' and e['other606']['whole_root'] is False and
                   e['signature']=='REQUIRED_ORIGINAL_EPHEMERAL_TEST' and e['fixture_graph_unchanged'] is True and
                   e['user_config_preserved'] is True and e['prior_reports_preserved'] is True, 'whole stated606 preservation/security scope')
            wanted=2 if e['count']==607 else 0
            A.need(len(e['observations'])==wanted,'both ordinary homes on every installed phase')
            if wanted:
                A.need({o['home'] for o in e['observations']}=={'boot607-home-fresh','boot607-home-existing'},'exact ordinary homes')
                for o in e['observations']:
                    fixture.validate(o['boot'],'77c326d908442852de51e66c660153d4c6051390b14466e48fa9c037cc1c573e')
        A.need([r['phase'] for r in result['ldconfig']]==['baseline606',*(e['phase'] for e in events)] and
               all(r['helper_exit']=='NOT_OBSERVED' and r['transition']['kind']=='RAW_EQUAL' for r in result['ldconfig']), 'six fresh exact raw auxiliary observations')
        return result
    def prepare_export(self,out,report):
        view=dict(report)
        if report.get('status')=='PASS_NATIVE606_TO607_BOOT_SYNTHETIC_COMPONENT_REQUIRES_REPLAY':
            self.validate_boot(report['lifecycle'].get('boot607'))
            view['status']='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'
        self.prior.prepare_export(out,view)
        report['tools606_scope']=view['tools606_scope']
        report['scope']='NATIVE_CURRENT606_PLUS_ACCEPTED_BOOT_SYNTHETIC_COMPONENT_ONLY'
        report['ordinary_copy607']='NOT_ISSUED'
        report['native_acceptance']='REQUIRES_FULL_RETAINED_ORIGINAL_REPLAY_AND_ROOT_DECISION'
    def export_names(self,out):
        names=self.prior.export_names(out)
        if (out/'boot607-selection.json').is_file():names.append('boot607-selection.json')
        home=out/'container'
        if home.exists():names.extend(str(p.relative_to(out)) for p in sorted(home.iterdir()) if p.is_file() and p.name.startswith('boot607'))
        return names
