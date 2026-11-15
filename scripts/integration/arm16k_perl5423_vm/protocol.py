# SPDX-License-Identifier: MIT
"""Finite serial DATA protocol; acceptance still needs passive output ELF checks."""
import re

PACKAGE = 'perl'
PROBE = dict(STATUS='PASS', ARCH='aarch64', PAGESIZE='16384', UID='1000', GID='1000',
             PERL_VERSION='5.42.3', FUNCTIONAL='PASS', COMMANDS='PASS', ELF_GEOMETRY='HOST_CHECK_REQUIRED')
INSTALLED = dict(STATUS='PASS', PACKAGE=PACKAGE, VERSION='5.42.3-1.3')
RESTORED = dict(STATUS='PASS', ARCH='aarch64', PAGESIZE='16384', PACKAGE=PACKAGE,
                VERSION='5.42.3-1.3', BASE_PAYLOAD='RESTORED', BASE_METADATA='RESTORED', BASE_XATTR='RESTORED',
                LOCAL_DB='RESTORED', USERS='RESTORED', UNOWNED_LDCACHE='RESTORED', PERL_BASELINE='RESTORED', PRIVATE_TRUST='REMOVED',
                HOOKS_SCRIPTLETS='UNSUPPRESSED', GUEST_SYNC='PASS', ELF_GEOMETRY='HOST_CHECK_REQUIRED', RTC_PRESENT='yes',
                RTC_DRIVER='pl031', RTC_HCTOSYS='1', RTC_CLOCK_ADVANCED='yes', CLOCK_SETTING='none')
EPOCHS = {'HOST_BOOT_UTC', 'GUEST_BEFORE_CRYPTO_UTC', 'RTC_BEFORE_CRYPTO_UTC'}
HASHES = {'BASE_SHA256', 'FINAL_SHA256', 'FUNCTIONAL_SHA256', 'ELF_MANIFEST_SHA256'}


def _nonce(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('literal nonce required')


def frame(data, nonce, kind='PROBE'):
    _nonce(nonce)
    if kind not in {'INSTALLED', 'PROBE', 'RESTORED'}:
        raise ValueError('fixed Perl phase required')
    if not isinstance(data, bytes) or len(data) > 8 * 1024 * 1024:
        raise ValueError('bounded serial bytes required')
    text = data.decode('utf-8', errors='strict').replace('\r\n', '\n')
    begin = 'PERL5423_' + kind + '_BEGIN ' + nonce
    end = 'PERL5423_' + kind + '_END ' + nonce
    lines = text.split('\n')
    if lines.count(begin) != 1 or lines.count(end) != 1:
        raise ValueError('one exact complete Perl phase frame required')
    first, last = lines.index(begin), lines.index(end)
    if last <= first or last - first > 65:
        raise ValueError('ordered bounded Perl phase frame required')
    fields = {}
    for line in lines[first + 1:last]:
        if '=' not in line or len(line) > 321:
            raise ValueError('bounded scalar frame field required')
        key, value = line.split('=', 1)
        if (not re.fullmatch('[A-Z][A-Z0-9_]{0,63}', key) or key in fields
                or not re.fullmatch('[ -~]{1,256}', value)):
            raise ValueError('unique ASCII frame fields required')
        fields[key] = value
    return fields


def _exact(fields, expected):
    if fields != expected:
        raise ValueError('exact Perl phase fields differ')
    return fields


def validate_probe(fields):
    return _exact(fields, PROBE)


def validate(fields, expected_base, epoch, now):
    """Validate Root receipt DATA; this does not grant ELF or runtime authority."""
    if not isinstance(expected_base, str) or not re.fullmatch('[0-9a-f]{64}', expected_base):
        raise ValueError('exact expected baseline hash required')
    if set(fields) != set(RESTORED) | HASHES | EPOCHS:
        raise ValueError('complete exact Root restoration fields required')
    for key, value in RESTORED.items():
        if fields[key] != value:
            raise ValueError('Root restoration result differs: ' + key)
    if any(not re.fullmatch('[0-9a-f]{64}', fields[k]) for k in HASHES):
        raise ValueError('actual receipt/output hashes required')
    if fields['BASE_SHA256'] != expected_base or fields['FINAL_SHA256'] != expected_base:
        raise ValueError('exact baseline restoration hash required')
    if any(not re.fullmatch('[1-9][0-9]{8,11}', fields[k]) for k in EPOCHS):
        raise ValueError('bounded actual RTC epochs required')
    if type(epoch) is not int or type(now) is not int:
        raise ValueError('actual integer host clock observations required')
    host, guest, rtc = (int(fields[k]) for k in
                        ('HOST_BOOT_UTC', 'GUEST_BEFORE_CRYPTO_UTC', 'RTC_BEFORE_CRYPTO_UTC'))
    # Match the unchanged reviewed PL031 RTC helper, without setting clocks.
    if not (host == epoch and host - 5 <= guest <= min(host + 485, now + 5)
            and abs(guest - rtc) <= 2):
        raise ValueError('advancing guest RTC/host clock disagreement')
    return fields


def _session(session):
    expected = dict(ARCH='aarch64', PAGESIZE='16384', UID='1000', USERNAME='builder',
                    PID1='systemd', Name='builder', User='1000', Class='user',
                    Type='tty', Service='login', Remote='no', LOGIND='active', DBUS='active')
    if any(session.get(k) != v for k, v in expected.items()):
        raise ValueError('ordinary baseline ARM16K PAM/systemd/logind session required')
    identity = session.get('Id', '')
    if (not re.fullmatch('[A-Za-z0-9_-]{1,64}', identity)
            or session.get('XDG_SESSION_ID') != identity
            or not re.fullmatch('[1-9][0-9]{0,9}', session.get('Leader', ''))
            or session.get('State') not in {'active', 'online'}):
        raise ValueError('actual finite logind identity required')


def journey(serial, password, baseline_nonce, nonce, parse_frame):
    """Use one normal PAM login; all waits inherit the driver's finite deadline."""
    _nonce(baseline_nonce)
    _nonce(nonce)
    if (not isinstance(password, str) or not 1 <= len(password) <= 128
            or any(c in password for c in '\r\n\x00')):
        raise ValueError('bounded single-line baseline password required')
    serial.until(rb'login:\s*')
    serial.send(b'builder\n')
    serial.until(rb'Password:\s*')
    serial.send(password.encode() + b'\n')
    serial.until(('ARM16K_SHELL_READY ' + baseline_nonce).encode())
    # The root snapshot covers the home directories. Interactive Bash history
    # must not add a logout side effect to this deliberately finite case.
    serial.send(b'unset HISTFILE; /usr/local/libexec/arm16k-login-proof\n')
    serial.until(('TCG_LOGIN_END ' + baseline_nonce).encode())
    session = parse_frame(bytes(serial.data), baseline_nonce)
    _session(session)
    command = ('/usr/bin/env -i HOME=/home/builder USER=builder LOGNAME=builder '
               'PATH=/usr/bin:/bin LC_ALL=C TZ=UTC /usr/bin/bash --noprofile --norc '
               '/var/lib/arm16k-perl5423-vm/probe.sh ' + nonce)
    serial.send((command + '\n').encode())
    serial.until(('PERL5423_INSTALLED_END ' + nonce).encode())
    installed = frame(bytes(serial.data), nonce, 'INSTALLED')
    serial.until(('PERL5423_PROBE_END ' + nonce).encode())
    probe = frame(bytes(serial.data), nonce)
    serial.send((command + ' restored\n').encode())
    serial.until(('PERL5423_RESTORED_END ' + nonce).encode())
    restored = frame(bytes(serial.data), nonce, 'RESTORED')
    serial.send(b'exit\n')
    serial.until(rb'login:\s*')
    _exact(installed, INSTALLED)
    validate_probe(probe)
    return dict(session=session, installed=installed, probe=probe, restored=restored,
                normal_PAM_logout_observed=True)
