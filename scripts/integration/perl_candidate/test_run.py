#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refusal controls for the fixed host-side Docker contract; no actors."""
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('perl_candidate_run',Path(__file__).with_name('run.py'))
RUN=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(RUN)


def model():
    return {'Image':RUN.BASE,'Mounts':[],'Config':{'User':'0:0','Volumes':None},'HostConfig':{
        'NetworkMode':'none','Privileged':False,'Binds':None,'Devices':[],
        'NanoCpus':2000000000,'Memory':4294967296,'PidsLimit':256,'CapDrop':['ALL'],
        'CapAdd':['CAP_'+name for name in ('CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID','SYS_CHROOT')],
        'SecurityOpt':['no-new-privileges']}}


class ContractTests(unittest.TestCase):
    def test_exact_contract(self):
        RUN.validate_inspection(model(),RUN.BASE)

    def test_image_user_and_volume_differences_refuse(self):
        for field,value in [('Image','sha256:'+'0'*64),('Mounts',[{'Source':'/home'}])]:
            row=model();row[field]=value
            with self.subTest(field=field),self.assertRaises(RUN.PROCESS.Error):RUN.validate_inspection(row,RUN.BASE)
        for field,value in [('User','1000:1000'),('Volumes',{'/caller':{}})]:
            row=model();row['Config'][field]=value
            with self.subTest(field=field),self.assertRaises(RUN.PROCESS.Error):RUN.validate_inspection(row,RUN.BASE)

    def test_network_privilege_binds_devices_and_caps_refuse(self):
        for field,value in [('NetworkMode','host'),('Privileged',True),('Binds',['/home:/home:ro']),
            ('Devices',[{'PathOnHost':'/dev/sda'}]),('CapDrop',[]),('CapAdd',['ALL']),('SecurityOpt',[])]:
            row=model();row['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(RUN.PROCESS.Error):RUN.validate_inspection(row,RUN.BASE)

    def test_changed_resource_limits_refuse(self):
        for field in ('NanoCpus','Memory','PidsLimit'):
            row=model();row['HostConfig'][field]+=1
            with self.subTest(field=field),self.assertRaises(RUN.PROCESS.Error):RUN.validate_inspection(row,RUN.BASE)

    def test_operational_checks_survive_python_optimization(self):
        import ast
        tree=ast.parse(Path(RUN.__file__).read_text())
        self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))


if __name__=='__main__':unittest.main()
