# SPDX-License-Identifier: MIT
"""Focused DATA/refusal controls; never run GPG or any selected verifier."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('stateless206',HERE/'verify.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)
A=V.load()
NOW=1794950000


def key():
    return '\n'.join(['pub:-:4096:1:'+A['SIGNER'][-16:]+':1390085363:::q:::scESC:', 'fpr:::::::::'+A['SIGNER']+':', 'uid:-::::1390085363::MODEL::'+A['UID']+':', 'sub:-:4096:1:'+A['SUBKEY'][-16:]+':1390085363::::::e:', 'fpr:::::::::'+A['SUBKEY']+':'])+'\n'


class Controls(unittest.TestCase):
    def test_exact_projection_full_inverse_and_all_other_guards_unchanged(self):
        raw=V.frozen();new=V.project(raw);self.assertEqual(new.decode().replace(V.AFTER,V.BEFORE).replace(V.NEW_ROOT,V.OLD_ROOT).encode(),raw)
        oldtree,newtree=ast.parse(raw),ast.parse(new)
        functions=lambda tree:{n.name:ast.dump(n,include_attributes=False)for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        old,now=functions(oldtree),functions(newtree)
        for name in old:
            if name!='verify':self.assertEqual(old[name],now[name],name)
        def normalized(tree):
            verify=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='verify')
            for n in ast.walk(verify):
                if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='common':n.value=ast.Constant(value='FIXED_PUBLIC_INSPECTION_FLAGS_ONLY')
            return ast.dump(verify,include_attributes=False)
        self.assertEqual(normalized(oldtree),normalized(newtree))
        for rawbad in(raw+b'\n',raw.replace(b'207',b'206',1)):self.assertRaises(ValueError,V.project,rawbad)
        self.assertIn("len(report['actors']) == 208",new.decode());self.assertIn("not any(home.iterdir())",new.decode())
    def test_unissued_default_and_old_selected_entry_refuse_before_actor(self):
        with patch.dict(A,read_pinned=lambda *a,**k:(_ for _ in()).throw(AssertionError('no input')),validate_selection=lambda *a:(_ for _ in()).throw(AssertionError('no selection'))),patch.object(A['subprocess'],'Popen',side_effect=AssertionError('no actor')):
            report,code=A['verify'](None,None);self.assertEqual(code,2);self.assertEqual(report['actors'],[])
        template=HERE/'SELECTION.TEMPLATE.json'
        with patch.object(A['subprocess'],'Popen',side_effect=AssertionError('no actor')):
            self.assertRaisesRegex(ValueError,'UNISSUED',A['verify'],template,A['pin'](template.read_bytes()),execute=True)
        selection=json.loads(template.read_bytes());selection.update(schema=1,issuer='Root',status='ROOT_SELECTED_MINIMAL206_PUBLIC_INPUT_VERIFICATION_ONLY',accepted=True);selection['entry']['path']=str(V.FROZEN)
        self.assertRaisesRegex(ValueError,'exact selected entry',A['validate_selection'],selection,NOW)
    def test_current_official_key_checks_still_refuse_unusable_or_foreign(self):
        good=key();A['key_status'](good,NOW)
        for bad in(good.replace('pub:-:','pub:r:'),good.replace('uid:-:','uid:i:'),good.replace('sub:-:','sub:e:'),good.replace(':scESC:',':scESCD:'),good.replace(A['SIGNER'],'0'*40),good.replace(A['UID'],'MODEL FOREIGN'),good.replace(':1390085363::',':1390085363:'+str(NOW-1)+':')):self.assertRaises(ValueError,A['key_status'],bad,NOW)
    def test_whole422_207_and_original_signature_algorithm_pins_retained(self):
        self.assertEqual(A['pin']((A['SOURCE']/'source.lock.json').read_bytes()),A['SOURCE_LOCK'])
        d=json.loads((A['SOURCE']/'builder.lock.json').read_bytes());self.assertEqual(A['pin']((A['SOURCE']/'builder.lock.json').read_bytes()),A['BUILDER']);rows,signed=A['inputs'](d);self.assertEqual((len(rows),len(signed),sum(x['bytes']for x in rows.values())),(422,207,1473694724))
        bad=copy.deepcopy(d);bad['packages']=bad['packages'][:-1];self.assertRaises(ValueError,A['inputs'],bad)
        self.assertEqual(A['RUN_CAP'],900);self.assertEqual(A['ACTOR_CAP'],60)
    def test_retirement_trust_and_actor_fences_unchanged_fail_closed(self):
        row=dict(passed=True,reaped=True,ownership='REAPED',exit=0,timeout=False,signals=[],error=None,output_complete=True,group_census='EMPTY_TWICE',seconds=.1);A['natural'](row)
        for field,value in(('signals',['SIGTERM']),('exit',1),('ownership','UNKNOWN'),('group_census','EMPTY_ONCE'),('timeout',True)):self.assertRaises(ValueError,A['natural'],dict(row,**{field:value}))
        fence=A['ActorFence']()
        for event in('subprocess.Popen','socket.connect','ctypes.dlopen','os.fork'):self.assertRaises(ValueError,fence,event,('MODEL',))


if __name__=='__main__':
    with patch.object(A['subprocess'],'Popen',side_effect=AssertionError('DATA controls never run actors')):unittest.main(verbosity=2)
