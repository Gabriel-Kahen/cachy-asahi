# SPDX-License-Identifier: MIT
"""Explicit trusted source loaders and bounded published revision check."""
import importlib.util,re,subprocess,sys
import common as C

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def revision(root,expected):
 C.need(re.fullmatch('[0-9a-f]{40}',expected or'')and subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True,timeout=15).strip()==expected,'exact immutable published input revision')
