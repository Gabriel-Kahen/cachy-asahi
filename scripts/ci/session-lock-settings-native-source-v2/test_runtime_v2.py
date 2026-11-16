#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New inert-control custody refusals; reuse all24 coupled MODEL controls."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location('coupled_v2_data',Path(__file__).with_name('test_data.py'));M=importlib.util.module_from_spec(s);s.loader.exec_module(M)

class InstalledCustody(unittest.TestCase):
 def test_every_installed_or_moved_count_payload_and_scope_is_joined(self):
  for phase in('installed','reinstalled'):
   for change in('missing','missing-moved','wrong-count','wrong-payload','wrong-package','claimed-compositor','changed-diagnostic'):
    with self.subTest(phase=phase,change=change):
     view,files,guest,report,data,refresh=M.modeled_component()
     if change=='missing':
      report['business'][phase].pop('installed-controls');refresh()
     else:
      row=next(v for v in report['commands']if v['step']==phase+'-installed-controls');name='journey/'+M.OPERATION+'/'+row['log'];value=json.loads(data[name])
      if change=='missing-moved':value['locations'].pop()
      elif change=='wrong-count':value['locations'][1]['tests']=23
      elif change=='wrong-payload':value['payload'][0]['sha256']='0'*64
      elif change=='wrong-package':value['package']['name']='unselected'
      elif change=='claimed-compositor':value['compositor']=True
      else:value['locations'][0]['diagnostics_pin']['sha256']='invalid'
      raw=M.encoded(value);data[name]=raw;row['log_pin']=M.pin(raw);files[name].update(M.pin(raw))
      report['business'][phase]['installed-controls']=dict(argv=row['argv'],output=M.pin(raw),result=value);refresh()
     with self.assertRaises(ValueError):M.check_modeled(view,files,guest)

 def test_old_help_parser_and_both_packages_stay_mandatory(self):
  for change in('helper-help','screenshot-help','config-verify','settings-build'):
   with self.subTest(change=change):
    view,files,guest,report,data,refresh=M.modeled_component()
    if change=='settings-build':report['builds'].pop('a-settings')
    else:report['business']['installed'].pop(change)
    refresh()
    with self.assertRaises(ValueError):M.check_modeled(view,files,guest)

if __name__=='__main__':unittest.main()
