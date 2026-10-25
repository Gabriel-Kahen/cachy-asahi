# SPDX-License-Identifier: MIT
"""Copy exact finite past Root decisions as DATA; default activation stays NULL."""
import base64,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;DEV=HERE.parents[1]
SPECS={
 'apps':('current606-apps-renewed-signer-native-actual-20261019/Root-component-acceptance.json','3660e6cb87b4cb5591b1d295c62c8b02cca4b7e6',39320580643,'ROOT_ACCEPTED_FINITE_CURRENT606_APPS7_NATIVE_ARTIFACT_PRESERVATION'),
 'welcome5':('current606-welcome-artifact-native-actual-20261019/Root-component-acceptance.json','deaf5d618fbc7be87b4e0296481beb7e336a9155',39308892579,'ROOT_ACCEPTED_FINITE_CURRENT606_WELCOME5_NATIVE_ARTIFACT_PRESERVATION'),
 'doctor':('doctor2-current606-native-actual-20261019/Root-component-acceptance.json','6f824cac64cd44f765e54fd3b5a853689ea0ce7b',39335483055,'ROOT_ACCEPTED_FINITE_CURRENT606_DOCTOR2_NATIVE_ARTIFACT_PRESERVATION'),
 'ksm':('ksm606-budget-native-actual-20261019/Root-component-acceptance-v2.json','a69921a214a9db4df8be6772bf1b3da344cd0eb4',39337741854,'ROOT_ACCEPTED_FINITE_CURRENT606_KSM2_NATIVE_ARTIFACT_PRESERVATION'),
 'welcome6':('welcome6-native-build-pair-actual-20261019/Root-component-acceptance.json','f14cfdf82280c22ba644b971d6bb26b75bad4bb2',39344263189,'ROOT_ACCEPTED_FINITE_NATIVE_WELCOME6_BUILD_PAIR_ONLY'),
 'boot':('boot79-native-products-actual-20261019/Root-component-acceptance.json','2c524830adb007e3b49392ceb54dd4cc5236c77d',39323942218,'ROOT_ACCEPTED_FINITE_NATIVE_BOOT_REPORT_PAIR_AND_SYNTHETIC_INSTALLED_CLI_LIFECYCLE')}
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def main():
 out=HERE/'accepted';out.mkdir();records={}
 for role,(path,source,run,status)in SPECS.items():
  body=(DEV/path).read_bytes();v=json.loads(body);assert(v['source'],v.get('run',v.get('run_id')),v['status'],v['release'])==(source,run,status,'NOT_ADMITTED')
  (out/(role+'.json')).write_bytes(body);records[role]=dict(path=role+'.json',**pin(body),source=source,run=run,status=status,authority='HISTORICAL_FINITE_COMPONENT_INPUT_ONLY_NO_COMBINED_CREDIT')
 (HERE/'accepted-component-pins.json').write_bytes(enc(records))
 policy=dict(schema_version=1,purpose='CURRENT607_LATEST_FIVE_TOOLS_NATIVE_COMPOSITION',status='UNBOUND_SOURCE_ONLY',current606=None,component_inputs=None,packet_checkouts=None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None)
 (HERE/'default-policy.json').write_bytes(enc(policy));print('ROOT_COMPONENT_DATA_ONLY',len(records))
if __name__=='__main__':main()
