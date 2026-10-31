#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive the accepted full GUI runner; no build, package, service or VM actors."""
import argparse
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s


def replace(text,old,new):
    s.need(text.count(old)==1,'managed16K adapter anchor differs: '+old[:100]);return text.replace(old,new)


def prepare(source,output,assets):
    s.check_source(source)
    candidates=s.load(source,'scripts/ci/welcome-managed-gui/candidates.py');sys.modules['candidates']=candidates
    shared=s.load(source,'scripts/ci/welcome-managed-gui/prepare.py');shared.prepare(source,output,assets)
    for name in ('elf_audit.py','kernel_contract.py'):shutil.copyfile(s.HERE/name,output/name)
    shutil.copyfile(source/'scripts/virtual/generic16k/fixture.py',output/'elf_reader.py')
    guest=(output/'base_guest.py').read_text()
    guest=replace(guest,"    need(os.geteuid() == (0 if root else 23001), 'wrong guest identity')", "    need('cachy_asahi_managed_gui16k=1' in words and os.sysconf('SC_PAGE_SIZE')==16384 and\n         platform.release()=='7.1.13-generic16k-managed-gui','explicit diagnostic16K guest required')\n    need(os.geteuid() == (0 if root else 23001), 'wrong guest identity')")
    guest=replace(guest,"emit('boot', architecture=platform.machine(), kernel=kernel, page_size=page_size, hardware='NOT_RUN')",
        "emit('boot', architecture=platform.machine(), kernel=kernel, page_size=page_size, hardware='NOT_RUN',\n             kernel_profile_sha256=hashlib.sha256((SHARE/'kernel-profile.json').read_bytes()).hexdigest())")
    guest=replace(guest,"need(kernel == '7.2.10-1-aarch64-ARCH' and page_size == 4096, 'expected generic 4K guest kernel required')",
        "need(kernel == '7.1.13-generic16k-managed-gui' and page_size == 16384, 'expected diagnostic16K guest kernel required')")
    guest=replace(guest,"        command(['/usr/bin/modprobe', 'virtio_gpu'], env, logs, 'virtio-gpu')\n",'        # Exact diagnostic receipt requires built-in virtio GPU and CONFIG_MODULES=n.\n')
    (output/'base_guest.py').write_text(guest)
    contract=(output/'gui_contract.py').read_text();contract=replace(contract,"platform['page_size_bytes']==4096","platform['page_size_bytes']==16384")
    (output/'gui_contract.py').write_text(contract)
    contract=(output/'contract.py').read_text()
    contract=replace(contract,'import managed_contract as M','import managed_contract as M\nK=C.load("managed16k_kernel_contract","kernel_contract.py")')
    contract=replace(contract,'    managed=M.verify_result(events)','    managed=M.verify_result(events)\n    kernel_profile=K.boot(events,Path(__file__).with_name("kernel-profile.json"))')
    contract=replace(contract,"return dict(managed_session=managed,compositor_logs=compositor_logs,producer_lifecycle=lock['producer_lifecycle'],",
        "return dict(managed_session=managed,compositor_logs=compositor_logs,producer_lifecycle=lock['producer_lifecycle'],\n                diagnostic_kernel=kernel_profile,")
    (output/'contract.py').write_text(contract)
    fixture=(output/'desktop574_fixture.sh').read_text()
    fixture=replace(fixture,'ExecStartPre=/usr/bin/modprobe virtio_console','# Built-in virtio-console; guest verifies the exact owned event port before use.')
    fixture=replace(fixture,'depmod -b "$root" 7.2.10-1-aarch64-ARCH\ncp /boot/Image /out/Image\nprintf \'%s\\n\' \'92445dac35421e6cba8ccf7b3e7de8fe8ca8914b69db26fce4a5162352f5dc0a  /out/Image\' | sha256sum -c -',
        'cp /runner/diagnostic.Image /out/Image\ncp /runner/kernel-profile.json "$root/usr/local/share/desktop574/kernel-profile.json"\n'
        'python3 -I -B -c \'import hashlib,json; from pathlib import Path; v=json.loads(Path("/runner/kernel-profile.json").read_text()); p=Path("/out/Image"); assert p.stat().st_size==v["Image"]["bytes"] and hashlib.sha256(p.read_bytes()).hexdigest()==v["Image"]["sha256"]\'')
    fixture=replace(fixture,'cc -std=c11 -O2 -Wall -Wextra -Werror /source/scripts/virtual/gbm_probe.c',
        'cc -std=c11 -O2 -Wall -Wextra -Werror -Wl,-z,max-page-size=16384 /source/scripts/virtual/gbm_probe.c')
    fixture=replace(fixture,'cc -std=c11 -O2 -Wall -Wextra -Werror /runner/a11y_driver.c',
        'cc -std=c11 -O2 -Wall -Wextra -Werror -Wl,-z,max-page-size=16384 /runner/a11y_driver.c')
    fixture=replace(fixture,'allocated=$(du -sx --block-size=1 "$root" | cut -f1)',
        'python3 -I -B /runner/elf_audit.py --root "$root" --reader /runner/elf_reader.py --output /out/elf16k.json\n'
        'allocated=$(du -sx --block-size=1 "$root" | cut -f1)')
    (output/'desktop574_fixture.sh').write_text(fixture)
    runtime=(output/'desktop574_runtime.py').read_text()
    runtime=replace(runtime,'cachy_asahi_welcome_gui=1','cachy_asahi_welcome_gui=1 cachy_asahi_managed_gui16k=1')
    runtime=replace(runtime,"        name = 'desktop574-vm-' + os.urandom(8).hex(); containers.append(name)",
        "        elf_source=fixture/'elf16k.json'\n        require(elf_source.stat().st_size<=16*1024**2,'ELF receipt bound')\n"
        "        elf_report=json.loads(elf_source.read_text())\n        require(elf_report['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT','actual full-tree16K ELF gate failed')\n"
        "        shutil.copyfile(elf_source,out/'elf16k.json')\n        report['elf16k']=dict(sha256=hashlib.sha256(elf_source.read_bytes()).hexdigest(),ELFs=len(elf_report['ELF']))\n"
        "        report['diagnostic_kernel']=json.loads((runner/'kernel-profile.json').read_text())\n"
        "        name = 'desktop574-vm-' + os.urandom(8).hex(); containers.append(name)")
    runtime=runtime.replace('PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_METADATA','PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_GENERIC16K_METADATA')
    (output/'desktop574_runtime.py').write_text(runtime)
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','assets'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(prepare(args.source.resolve(),args.output.resolve(),args.assets.resolve()))
