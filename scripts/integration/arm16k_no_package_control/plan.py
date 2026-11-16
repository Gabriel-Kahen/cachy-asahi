#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Render an unissued diagnostic plan; rendering never executes its control."""
import base64,hashlib,json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE65=dict(author_commit='57c0aa8ad61b8128cc7a224030bebbc759a41df3',author_tree='09bd4c22062ca3b4c23019ff3564bd51c860d355',author_lock=dict(bytes=10598,sha256='9324c8e79374ba95e5b2ce37e389b3e5732cf6c079ca6857b35205932ad5a61a'),tree='7ad0d52fdeeeba3314d29201bd28f41766639625',files=65,bytes=742532,lock=dict(bytes=10598,sha256='f787650b1dcd78c4081b544719cd4f1d8d7c67c46da09c495e6c185917c542ac'),production_bytes_unchanged=True,test_only_amendment=['test_controls.py','test_probe_readiness.py','source.lock.json'])
BASELINE=dict(certificate=dict(bytes=3870,sha256='569d9373d0af561def524d8a573f67c50e7556886b59047ceac4804dfb239d61'),raw=dict(bytes=1610612736,sha256='f69d74fbb0043793c96424d0f91ad2f6fb2d8cf3a72fb94024ea9cc40dae4cd3'),prepared=dict(bytes=58179,sha256='f7b3073f58acce8ab5e21ff61f2182779d24046e1582cda6adb0a3db66b7036e'))


def guest_command(stage,nonce):
 if stage not in ('after_login','before_logout')or type(nonce)is not str or len(nonce)!=32 or any(c not in '0123456789abcdef'for c in nonce):raise ValueError('fixed diagnostic stage and nonce required')
 # Root may send these literal bytes through its reviewed Serial primitive.
 # No probe is installed into the image, no secret is an argument.
 body=(HERE/'guest-metadata.sh').read_text()
 if not body.isascii()or len(body)>4096:raise ValueError('bounded ASCII public probe required')
 encoded=base64.b64encode(body.encode()).decode()
 # One line avoids multiline tty prompts; encoded echo cannot spoof frame tags.
 return "/usr/bin/printf '%s' '"+encoded+"' | /usr/bin/base64 --decode | /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC0 /bin/bash --noprofile --norc -s -- "+stage+' '+nonce+'\n'


def plan():
 body=(HERE/'guest-metadata.sh').read_bytes()
 return dict(schema=1,kind='ARM16K_NO_PACKAGE_CONTROL_DRAFT_V1',status='IMPLEMENTED_CONTROL_SOURCE_NOT_EXECUTED',
  comparison_source=SOURCE65,original_baseline=BASELINE,
  required_native_host_api='os.pidfd_open; missing API refuses after public grants and before private inputs or transport',
  metadata_reader=dict(file='metadata_raw_reader.py',author_commit='c9ac118ec3308dbf042c15e2af216772a48d9525',bytes=12810,sha256='94a755ab24b940a809f53a78faf90a851ded9f14d28c0fdb9cf75f5e01c59f23',per_scan_seconds=120,boot_budget_addition_seconds=240,launch_epoch='qemu-epoch.json'),
  objective='Separate boot/login/logout-class drift from effects requiring the package lifecycle; observation only, no restoration or acceptance waiver',
  reuse=dict(session='scripts/integration/arm16k_systemd_tcg_guest/boot.py: parse_session and normal PAM exchange; do not invoke its consumed first-boot entry',proof='/usr/local/libexec/arm16k-login-proof',custody='scripts/integration/arm16k_perl5423_vm/controller.py: QMPPeer, authority review and exact Scope validation',resources='scripts/integration/arm16k_perl5423_vm/runtime.py and budget.py: current explicit CLI, owner guards, natural retirement',qemu='scripts/integration/arm16k_perl5423_vm/actor.py: qemu_argv geometry and RTC policy; new operation must omit Perl case tokens and use the ORIGINAL baseline overlay'),
  guest_probe=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),stages=['after_login','before_logout'],transport='single-line base64 DATA via printf/base64/bash; no guest file staging; output bounded to 64KiB',private_contents=False),
  phases=['Root metadata-only offline_before of original raw; no file inventory or body hashes','Fresh private qcow2 overlay backed by exact read-only original raw; same case14 qualified Image/config and RTC/TCG geometry','Normal builder PAM login; unchanged original login proof; after_login metadata frame','No package operation or lifecycle service; fixed reviewed idle interval; before_logout metadata frame','Normal PAM logout and original-peer QMP quit; natural QEMU/actor reap; empty process group; container absence','Root metadata-only offline_after of disposable merged view; never write original raw; compare every selected public row'],
  forbidden=['consume original first-boot marker','reuse case14 output, image, nonce or actor','Perl-prepared raw or package lifecycle service','ALPM transaction, package archive mount, GPG, dependency install, package query in the control workload','timestamp touch, absence cleanup, root/.ssh enumeration or body reads','use image.scan or whole inventory for metadata-only observation','equate observation completion with preservation PASS'],
  required_fresh_Root_bindings=['independent once-only diagnostic authority and marker outside baseline','same original baseline raw/prepared/certificate and original private PAM credential pins','same actual case14 Image/config pins and QEMU tool image; no original-kernel fallback','new source lock, case/nonce, output, explicit Docker endpoint/CLI, actor/tool pins','independently admitted finite quota, memory, CPU, PID, overlay/readback, output and deadline budgets','pin original namespace/ownership metadata; enumerate only fixed public path metadata; no recursive private traversal','bounded serial frame joins and exact original QMP peer custody through retirement'],
  causal_limits=['after_login combines boot and login; there is no early-boot checkpoint','shared changed path in control and package run supports a boot/session-class explanation, not creator identity','package-only change is not proof of ALPM causation: timing, service races and different fixture staging remain confounders','original-to-final package metadata includes preparation effects; future Root comparison needs a separately pinned prepared-before-VM public projection to isolate staging','single unmatched control cannot justify normalization; optional matched-duration/repeated control needs separate fresh Root grants','unknown residues or differences outside public projection stay unreviewed; no complete namespace or byte preservation is claimed'],
  decisions=dict(Root_authority=None,actual_actor=None,actual_VM=None,source_publication=None,next_case=None,baseline_refresh=None,preservation_waiver=None))


if __name__=='__main__':print(json.dumps(plan(),sort_keys=True,indent=2))
