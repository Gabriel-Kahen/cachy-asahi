# SPDX-License-Identifier: MIT
"""Finite fresh v3 component receipts, never a version-upgrade or hardware claim."""
import base64
import hashlib
import json
def validate(C, value):
    C.need(value.get('status') == 'PASS_RUNTIME_CLIENT_V3_FRESH_LIFECYCLE' and value.get('base_count') == 574 and
           value.get('installed_count') == 576 and value.get('architecture') == 'aarch64' and value.get('page_size') == 4096,
           'exact native4K two-product component required')
    C.need(all(value.get(k) is True for k in ('base574_preserved', 'user_preserved')) and
           value.get('hardware') == 'NOT_RUN' and value.get('release') == 'NOT_ADMITTED' and value.get('version_upgrade') == 'NOT_RUN',
           'preservation and component-only limits required')
    C.need(value.get('removal_order') == [C.ROLES['client'], C.ROLES['runtime']], 'leaf-before-Runtime removal order required')
    events = value.get('events')
    C.need(type(events) is list and len(events) == 5, 'five exact fresh/reinstall/remove phases required')
    for event, (phase, count) in zip(events, [('install', 576), ('same-version-reinstall', 576), ('remove', 574), ('reinstall-after-removal', 576), ('final-remove', 574)]):
        C.need(event.get('phase') == phase and event.get('count') == count and event.get('base574_preserved') is True and
               event.get('user_preserved') is True, 'exact inventory/preservation phase required')
        if count == 574:
            C.need(event.get('payloads_absent') is True, 'all owned payload files must be absent after removal')
            continue
        rows = event.get('observations')
        C.need(type(rows) is list and len(rows) == 2 and {r.get('home') for r in rows} == {'client-v3-home-fresh', 'client-v3-home-existing'},
               'both ordinary-user home cases required')
        for row in rows:
            result = row.get('client_v3', {})
            C.need(result.get('status') == 'PASS_INSTALLED_V3_REAL_SIGNED_APPLY_AND_REBIND' and
                   all(result.get(k) is True for k in ('actual_cli_readonly', 'actual_cli_apply', 'idempotent_readonly',
                       'rename_after_real_verification', 'refused_before_checkpoint_write', 'checkpoint_preserved', 'private_agent_retired')) and
                   result.get('real_signature_checks_before_rebind') == 5 and result.get('crypto_success_mocks') == 0 and
                   result.get('collected_code_imports') == 0 and result.get('installed_source') is True,
                   'complete actual installed CLI/GPG/checkpoint/refusal/retirement evidence required')
            C.need(C.re.fullmatch('[a-f0-9]{64}', result.get('transcript_sha256') or '') and
                   type(result.get('transcript_bytes')) is int and 0 < result['transcript_bytes'] <= 65536,
                   'whole bounded genuine command transcript binding required')
            transcript = result.get('transcript')
            C.need(type(transcript) is list and transcript, 'complete command transcript required')
            raw = (json.dumps(transcript, sort_keys=True, separators=(',', ':')) + '\n').encode()
            C.need(len(raw) == result['transcript_bytes'] and hashlib.sha256(raw).hexdigest() == result['transcript_sha256'],
                   'whole command transcript hash/length differs')
            witnesses = [r['real_rebind_verifier'] for r in transcript if type(r) is dict and 'real_rebind_verifier' in r]
            C.need(len(witnesses) == 1, 'one complete post-verification rename witness required')
            witness = witnesses[0]
            C.need(witness.get('completed_bundle_targets') == 3 and witness.get('state_renamed_after_all_real_signatures') is True and
                   witness.get('crypto_success_mocks') == 0 and len(witness.get('actual_verified_signatures', [])) == 5,
                   'five real signatures and three bundle targets required before rename')
            commands = witness.get('actual_GPG_commands')
            C.need(type(commands) is list and len(commands) == 5, 'five complete actual GPG commands required')
            for command in commands:
                C.need(command.get('exit') == 0, 'real GPG command failed')
                for role in ('stdout', 'stderr'):
                    stream = command[role]
                    decoded = base64.b64decode(stream['base64'], validate=True)
                    C.need(len(decoded) == stream['bytes'] and hashlib.sha256(decoded).hexdigest() == stream['sha256'],
                           'complete raw GPG stream hash/length differs')
                    if role == 'stdout':
                        C.need(decoded.count(b'[GNUPG:] VALIDSIG ') == 1, 'one complete real signature status per command required')
