# SPDX-License-Identifier: MIT
"""Narrow Setup8 dependency splice into the exact audited native bootstrap."""

import ast


def bind(native, source, dependency, certificate, contract):
    """Install a projected build() in an already admission-fenced native module.

    The selected certificate and archive are read only when the admitted
    bootstrap reaches its private Docker context. Import and bind do not run
    tools or authenticate a signer.
    """
    contract.need(contract.digest(source) == contract.BOOTSTRAP_SHA,
                  'exact proven signed-input native_arm.py required')
    text = source.decode('utf-8')
    node, = (node for node in ast.parse(text).body
             if isinstance(node, ast.FunctionDef) and node.name == 'build')
    original = ast.get_source_segment(text, node)
    setup = contract.SETUP
    signer = contract.PINS['setup8']['test_signer']
    transaction = (
        '&& gpgv --status-fd 1 --keyring /tmp/setup8/public.gpg '
        f'/tmp/setup8/{setup}.sig /tmp/setup8/{setup} > /tmp/setup8/validsig '
        f'''&& awk '$1 == "[GNUPG:]" && $2 ~ /^(EXPSIG|EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY)$/ {{ bad=1 }} $1 == "[GNUPG:]" && $2 == "VALIDSIG" {{ rows++; if (NF == 12 && $3 == "{signer}" && $12 == "{signer}") good++ }} END {{ exit bad || rows != 1 || good != 1 }}' /tmp/setup8/validsig '''
        '&& pacman-key --add /tmp/setup8/public.gpg '
        f'&& pacman-key --lsign-key {signer} '
        f'&& pacman -U --noconfirm --noscriptlet /tmp/setup8/{setup} '
        f'&& pacman-key --delete {signer} '
        '&& rm -rf /tmp/setup8 '
    )
    edits = (
        ("                  'COPY disabled-hooks.txt /tmp/disabled-hooks.txt\\n'",
         "                  'COPY disabled-hooks.txt /tmp/disabled-hooks.txt\\n'\n"
         "                  'COPY setup8/ /tmp/setup8/\\n'"),
        ("                  '&& gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent '",
         f"                  {transaction!r}\n"
         "                  '&& gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent '"),
        ("    (context / 'Dockerfile').write_text(dockerfile)",
         "    _stage_exact_setup8(context)\n"
         "    (context / 'Dockerfile').write_text(dockerfile)"),
        ("    if lock != ''.join(f'{name} {version}\\n' for name, version in sorted(expected.items())):",
         "    if 'cachy-asahi-setup' in expected:\n"
         "        raise ValueError('Setup8 must be the one supplemental dependency')\n"
         "    expected['cachy-asahi-setup'] = '0.3.0-1'\n"
         "    if lock != ''.join(f'{name} {version}\\n' for name, version in sorted(expected.items())):"),
    )
    projected = original
    for before, after in edits:
        contract.need(projected.count(before) == 1 and after not in projected,
                      'unique Setup8 native bootstrap seam required')
        projected = projected.replace(before, after, 1)
    inverse = projected
    for before, after in reversed(edits):
        inverse = inverse.replace(after, before, 1)
    contract.need(inverse == original, 'complete original native build inverse required')

    def stage(context):
        rows = {}
        for role, name, path in (('archive', setup, dependency / setup),
                                 ('signature', setup + '.sig', dependency / (setup + '.sig')),
                                 ('certificate', 'public.gpg', certificate)):
            expected = contract.PINS['setup8'][role]
            raw = contract.read(path, expected['bytes'])
            if {'bytes': len(raw), 'sha256': contract.digest(raw)} != expected:
                raise ValueError('exact Setup8 ' + role + ' required')
            rows[name] = raw
        target = context / 'setup8'
        target.mkdir(mode=0o700)
        for name, raw in rows.items():
            with (target / name).open('xb') as stream:
                stream.write(raw)
            (target / name).chmod(0o644)

    native.__dict__['_stage_exact_setup8'] = stage
    exec(compile(projected, '<first-login-signed-setup8-bootstrap>', 'exec'), native.__dict__)
    return projected
