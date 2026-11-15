#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only invocation adapter; preserves exact seat/custody/login mechanics."""
import argparse, importlib.util, json, os, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;SEAT=HERE.parent/'systemd_tcg_seat_guest'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-ui-seat-reference-boot',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--tool-image',required=True);p.add_argument('--tool-image-id',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not(a.allow_first_ui_seat_reference_boot and __debug__ and os.geteuid()!=0):p.error('explicit Root-reviewed first boot and ordinary host user required')
    from intake import exact
    for name,ref in json.loads((HERE/'references.json').read_text()).items():exact(HERE.parents[2]/name,ref['bytes'],ref['sha256'])
    controller=load('fixed_UI_seat_controller',SEAT/'boot.py');accept=load('UI_result',HERE/'result.py').accept;original_parse=controller.parse
    # Explicit parser extension only: original seat proof remains mandatory.
    def parse(data,nonce):
        result=original_parse(data,nonce);ui=result['ui_journey'];accept(ui)
        assert result['installed_gate']==ui['root']['installation_receipt'] and result['installed_gate']['nonce']==nonce
        session=ui['root']['client_session_corroboration'];assert session['process_session']==result['user']['process_session'] and session['login1']['Id']==result['user']['logind']['Id']
        return result
    controller.parse=parse
    original=sys.argv;sys.argv=[str(SEAT/'boot.py'),'--allow-first-real-seat-reference-boot','--prepared',str(a.prepared),'--prepared-sha256',a.prepared_sha256,'--tool-image',a.tool_image,'--tool-image-id',a.tool_image_id,'--output',str(a.output)]
    try:code=controller.main()
    finally:sys.argv=original
    foundation=json.loads((a.output/'report.json').read_text());report={'schema_version':1,'status':'HOLD','scope':'real installed GTK in owned x86 real PAM/tty1/seat0 session only','ARM_M2_release':'NOT RUN','foundation_report':str(a.output/'report.json')}
    if code==0 and foundation['status']=='PASS_X86_REAL_SEAT_REFERENCE_ONLY':
        report['ui_journey']=foundation['seat']['ui_journey'];accept(report['ui_journey']);report['status']='PASS_X86_REAL_SEAT_FIRST_LOGIN_UI_LIFECYCLE_ONLY'
    else:report['failure']=foundation.get('failure',{'category':'HeldFoundation','message':foundation['status']})
    (a.output/'journey.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({'status':report['status'],'report':str(a.output/'journey.json')}));return 0 if report['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())
