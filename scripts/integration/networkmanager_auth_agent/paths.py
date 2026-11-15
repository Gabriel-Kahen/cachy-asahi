#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import importlib.util,json,os
from pathlib import Path
if not(os.geteuid()==0 and os.environ.get('CACHY_ASAHI_PAM_ACTOR')=='1'):raise RuntimeError('owned root fixture only')
s=importlib.util.spec_from_file_location('pam_environment',Path('/opt/nm-private-bus/previous_guest.py'));g=importlib.util.module_from_spec(s);s.loader.exec_module(g);env=g.clean_env(os.environ);os.environ.clear();os.environ.update(env)
import gi
gi.require_version('NM','1.0')
from gi.repository import NM
c=NM.Client.new(None)
print(json.dumps({k:c.get_connection_by_uuid(v).get_path()for k,v in {'system':'e3140000-0000-4000-8000-000000000011','foreign':'e3140000-0000-4000-8000-000000000014'}.items()}))
