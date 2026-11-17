# SPDX-License-Identifier: MIT
"""Pure operand projection for maintained native_arm audit/bootstrap, never entry."""
import argparse,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def encoded(v):return(json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def project(d):
 raw=encoded(d);expected=json.loads((HERE/'profile.DATA.json').read_bytes())['builder_lock']
 if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=expected:raise ValueError('fixed separate builder manifest only')
 if d['kind']!='SEPARATE_MINIMAL_NATIVE_LIBRARY_BUILDER_INPUTS_V1'or d['metadata_graph_status']!='PASS'or d['graph_blockers']or d['rootfs_reconciliation']['missing']:raise ValueError('complete separate builder closure required')
 packages=[]
 for r in d['packages']:
  a=r['archive'];packages.append(dict(name=r['name'],version=r['version'],arch=r['arch'],filename=a['filename'],size=a['bytes'],sha256=a['sha256'],signature_size=a['signature_bytes'],signature_sha256=a['signature_sha256'],url=r['url'],repo=r['repo'],license=r['licenses_declared'],depends=r['depends'],provides=r['provides'],conflicts=r['conflicts'],replaces=r['replaces']))
 return dict(schema_version=1,snapshot_id='SEPARATE-MINIMAL-NATIVE-LIBRARY-BUILDER-20261117',status='UNISSUED_BUILD_ONLY_INPUTS',rootfs=d['rootfs'],rootfs_packages=d['rootfs_original_inventory'],packages=packages,keyring_files=d['keyring_files'],signer_fingerprint=d['signer_fingerprint'],repository_databases=d['catalogs'],source_date_epoch=1791748800,native_build='NOT RUN',hardware_validation='NOT RUN',installation='NOT RUN',resolver_transaction='METADATA_ONLY_REQUIRES_ACTUAL_NORMAL_DEPENDENCY_TRANSACTION')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--lock',type=Path,required=True);p.add_argument('--lock-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();raw=a.lock.read_bytes();assert hashlib.sha256(raw).hexdigest()==a.lock_sha256 and not a.output.exists();d=json.loads(raw);a.output.mkdir(mode=0o700);(a.output/'native-inputs.lock.json').write_bytes(encoded(project(d)));(a.output/'expected206.lock').write_text(''.join(r['name']+' '+r['version']+'\n'for r in d['packages']))
