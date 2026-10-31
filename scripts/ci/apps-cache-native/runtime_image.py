#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install only the accepted, signed runtime pair into the owned dependency-image container."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I


def main():
    L,driver=I.apis();I.guard(L,'runtime-dependency-image')
    base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
    L.need(len(base)==574 and L.inventory()==base and set(products)=={'cachy-asahi-repository-runtime'},'exact574/runtime-only image preparation required')
    state=I.base_state(L,driver);control=json.loads(Path('/inputs/control.json').read_bytes());pacman=I.pacman(L,control['signer'])
    query=pacman[:-2]  # Keep the same config; transaction flags stay on -U/-R only.
    row=products['cachy-asahi-repository-runtime'];archive=Path('/inputs')/row['archive']
    L.need(archive.parent==Path('/inputs') and L.sha(archive)==row['sha256'],'accepted runtime pair bytes differ')
    L.command(pacman+['-U',str(archive)],timeout=90);L.command(query+['-Dk'])
    L.command(query+['-T',*control['apps_dependencies']])
    expected=base|{'cachy-asahi-repository-runtime':row['version']};L.need(L.inventory()==expected,'exact575 dependency inventory differs')
    I.payloads(L,products);preserved=I.preserve_base(L,state)
    lock=''.join(n+' '+v+'\n' for n,v in sorted(expected.items()))
    Path('/out/runtime575.lock').write_text(lock)
    Path('/out/runtime-image.json').write_text(json.dumps(dict(status='PASS_SIGNED_RUNTIME_DEPENDENCY_INSTALL',
        package_count=575,base574_preserved=True,base_manifest_sha256=preserved,runtime_sha256=row['sha256'],
        expected_lock_sha256=__import__('hashlib').sha256(lock.encode()).hexdigest(),signatures='REQUIRED_TEST_ONLY',
        dependencies='PASS_PACMAN_T_NO_WAIVERS',hardware='NOT_RUN'),sort_keys=True)+'\n')
    L.command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])


if __name__=='__main__':main()
