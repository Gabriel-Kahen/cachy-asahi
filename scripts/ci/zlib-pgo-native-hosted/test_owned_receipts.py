# SPDX-License-Identifier: MIT
"""Focused receipt/output-limit controls; no real child or package process."""
import copy,importlib.util,subprocess,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('_owned_retention_controls','retention.py');O=load('_owned_output_controls','owned_child.py')


class OwnedReceiptControls(unittest.TestCase):
    def test_false_zero_missing_witness_or_lost_retirement_refuses(self):
        row=dict(exit=0,exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',natural_exit=True,forced_cleanup=False,group_absent=True,leader_held_until_group_inspection=True)
        R.owned_status(row,0)
        for key,value in [('exit',None),('exit_observed_via_waitpid',False),('ownership_lost',True),('retirement','UNKNOWN'),('forced_cleanup',True),('natural_exit',False)]:
            bad=copy.deepcopy(row);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):R.owned_status(bad,0)
        del row['exit_observed_via_waitpid']
        with self.assertRaises(ValueError):R.owned_status(row,0)

    def test_explicit_output_caps_refuse_before_any_child(self):
        with patch.object(subprocess,'Popen')as launch:
            for limit in (0,-1,True,float('nan'),513*1024**2):
                with self.subTest(limit=limit),self.assertRaises(ValueError):O.run(['not-launched'],stdout_limit=limit)
            launch.assert_not_called()

    def test_large_file_cap_changes_only_bounds_not_owned_exit_evidence(self):
        class State:
            def __init__(self,process,row,uids):self.row=row;self.reaped=False;row.update(exit=None,ownership_lost=False)
            def witness(self):return SimpleNamespace(si_pid=123)
            def retire(self,force=False):
                self.reaped=True;self.row.update(exit=7,exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED')
        def launch(*args,**kwargs):kwargs['stdout'].write(b'fixture');return SimpleNamespace(pid=123,returncode=None)
        with patch.object(O,'_OwnedState',State),patch.object(subprocess,'Popen',side_effect=launch),patch.object(O.os,'waitid',side_effect=AssertionError('not a real child')),patch.object(O.os,'waitpid',side_effect=AssertionError('not a real child')):
            result=O.run(['synthetic'],capture_output=True,stdout_limit=512*1024**2)
        self.assertEqual((result.returncode,result.stdout),(7,b'fixture'))


if __name__=='__main__':unittest.main()
