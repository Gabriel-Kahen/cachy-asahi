"""Exact environment semantics across Docker image/CLI ordering; no actors."""
import copy
import itertools
from pathlib import Path
import types
import unittest
from unittest.mock import patch
import test_native_preflight as existing

P, R = existing.P, existing.R
ROOT = existing.ROOT


def command_environment(trial):
    """Use the actual pure CLI constructor, with only host architecture modeled."""
    with patch.object(R.os, 'uname', return_value=types.SimpleNamespace(machine='aarch64')):
        command=R.docker_command(trial,Path('/model/source'),Path('/model/inputs'),Path('/model/output'))
    user=[command[i+1] for i,value in enumerate(command) if value=='--env']
    # Moby v28.0.4 daemon/commit.go merge: missing image keys append after user entries.
    merged=list(user)
    for value in P.CONFIG['Env']:
        if value.partition('=')[0] not in {item.partition('=')[0] for item in merged}:merged.append(value)
    return user,merged


class EnvironmentOrderTests(unittest.TestCase):
    def setUp(self):
        self.control=existing.ContainerControls();self.control.setUp()
        self.expected=self.control.row['Config']['Env']

    def check(self, environment, **config):
        row=copy.deepcopy(self.control.row);row['Config'].update(Env=environment,**config)
        before=copy.deepcopy(row)
        self.control.check(row)
        self.assertEqual(row,before)

    def test_real_command_plus_image_merge_reproduces_old_order_contradiction(self):
        data=existing.CurrentDataControls();data.setUp()
        sources=types.SimpleNamespace(raw={name:(ROOT/name).read_bytes() for name in P.SOURCE_PATHS})
        trial=P.selection(sources,data.controller,R,data.handoff(),'b'*32,input_successor=data.selector)
        user,merged=command_environment(trial)
        expected=P.CONFIG['Env']+user
        self.assertEqual([item.partition('=')[0] for item in user],
                         ['CACHY_ASAHI_INSTALL_NONCE','CACHY_ASAHI_INSTALL_IMAGE'])
        self.assertNotEqual(merged,expected,'old list equality must reject this standard merge order')
        self.assertEqual(set(merged),set(expected))
        row=copy.deepcopy(self.control.row);row['Image']=trial['image_id'];row['Config']['Env']=merged
        self.control.trial=trial;row['Config']['Cmd'][-1]=P.sha(P.encoded(trial))
        self.control.check(row)

    def test_all_permutations_accept_without_changing_inspection(self):
        for values in itertools.permutations(self.expected):
            with self.subTest(order=values):self.check(list(values))

    def test_duplicate_missing_extra_wrong_keys_and_values_refuse(self):
        cases=[[],self.expected[:-1],self.expected+['FOREIGN=value'],self.expected+[self.expected[0]],
               [self.expected[0],self.expected[0],self.expected[2]],
               ['PATH=/foreign',*self.expected[1:]],
               [self.expected[0],'CACHY_ASAHI_INSTALL_NONCE='+'d'*32,self.expected[2]],
               [self.expected[0],self.expected[1],'CACHY_ASAHI_INSTALL_IMAGE=sha256:'+'d'*64],
               [self.expected[0],self.expected[1],'CACHY_ASAHI_INSTALL_IMAGE'],
               [self.expected[0],self.expected[1],'CACHY_ASAHI_INSTALL_IMAGE='+self.control.trial['image_id']+'=foreign']]
        for values in cases:
            with self.subTest(environment=values),self.assertRaisesRegex(ValueError,'^CONTAINER_ENV$'):self.check(values)

    def test_wrong_types_and_foreign_hooks_refuse_without_hook_execution(self):
        calls=[]
        class ForeignString(str):
            def __hash__(self):calls.append('hash');raise AssertionError('foreign hash')
            def __eq__(self,other):calls.append('eq');raise AssertionError('foreign eq')
        class ForeignList(list):
            def __len__(self):calls.append('length');raise AssertionError('foreign length')
            def __iter__(self):calls.append('iteration');raise AssertionError('foreign iteration')
        for values in (None,tuple(self.expected),{},'PATH=value',[None,*self.expected[1:]],
                       [ForeignString(self.expected[0]),*self.expected[1:]],ForeignList(self.expected)):
            with self.subTest(kind=type(values).__name__):
                self.assertIs(P.environment_matches(values,self.expected),False)
        self.assertEqual(calls,[])

    def test_volumes_and_healthcheck_still_refuse_with_correct_unordered_env(self):
        for config in ({'Volumes':{'/foreign':{}}},{'Healthcheck':{'Test':['CMD','foreign']}}):
            with self.subTest(config=config),self.assertRaisesRegex(ValueError,'^CONTAINER_ENV$'):
                self.check(list(reversed(self.expected)),**config)

    def test_modeled_pipeline_reordered_env_starts_then_cleans_and_wrong_value_refuses(self):
        for wrong in (False,True):
            with self.subTest(wrong=wrong):
                model=existing.CurrentPipelineModels();model.setUp()
                try:
                    transport=model.session.source_graph['runtime']['transport'];supervise=transport.supervise
                    def reordered(argv,**kwargs):
                        result,observation=supervise(argv,**kwargs)
                        if argv[1:3]==['container','inspect']:
                            rows=P.strict(result['stdout']);values=rows[0]['Config']['Env']
                            rows[0]['Config']['Env']=values[1:]+values[:1]
                            if wrong:rows[0]['Config']['Env'][0]='CACHY_ASAHI_INSTALL_NONCE=foreign'
                            result['stdout']=P.encoded(rows)
                        return result,observation
                    transport.supervise=reordered
                    if wrong:
                        with self.assertRaisesRegex(ValueError,'^CONTAINER_ENV$'):model.run_model()
                        self.assertNotIn('start',[row[0][0] for row in model.commands])
                    else:
                        result=model.run_model();self.assertEqual(result['status'],'PASS')
                        self.assertEqual(result['cleanup'],{'remove_exit':0,'absent':True})
                        self.assertIn('start',[row[0][0] for row in model.commands])
                    self.assertEqual(model.commands[-2][0],['rm','-f','a'*64]);self.assertTrue(model.closed)
                finally:model.doCleanups()


if __name__=='__main__':unittest.main()
